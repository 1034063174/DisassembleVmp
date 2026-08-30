/*
 * snapshot.cpp — x64dbg 调试上下文快照
 *
 * 职责：从 x64dbg 调试器中读取当前的寄存器和内存状态，
 *       打包成 SnapshotData 结构体供 Unicorn 模拟使用。
 *
 * 抓取内容：
 *   1. 所有通用寄存器（RAX~R15, RIP, RSP, RBP, EFLAGS）
 *   2. 进程所有已提交（MEM_COMMIT）的内存页
 *      — 确保 VMP 跨 handler 间接跳转（push reg; ret）能正确模拟
 *      — 包含主模块、栈、VMP 运行时分配的可执行内存等
 *
 * 内存映射策略（2026-08-13 改进）：
 *   旧方案：只映射 RIP 所在模块 + RSP ± 64KB 栈
 *   问题：VMP handler 之间通过 push reg; ret 间接跳转到模块外的动态分配内存，
 *         旧方案读不到这些内存，hookMemUnmapped 映射空页导致模拟脱轨。
 *         实测 500 步去混淆时前 ~110 步有效（50%检出），#111 后全部无效。
 *   新方案：使用 DbgMemMap() 枚举进程所有已提交的可读内存页，全部映射到 Unicorn。
 *         这样 VMP 运行时分配的可执行内存（handler 代码、解密上下文表等）
 *         都能被 Unicorn 正确读取，间接跳转不再脱轨。
 *   降级：DbgMemMap 失败时回退到旧方案（模块+栈）。
 */
#include "snapshot.h"
#include "../pluginmain.h"
#include "../utils/logger.h"

namespace deobf {

/*
 * readMemoryRegion — 从 x64dbg 读取一段内存区域
 *
 * 使用 x64dbg SDK 的 DbgMemRead() 读取目标进程的内存。
 * 失败时返回 false（例如地址无效或内存不可读）。
 */
bool readMemoryRegion(uint64_t base, size_t size, SnapshotData::MemoryRegion& region)
{
    region.base = base;
    region.data.resize(size);
    return DbgMemRead(base, region.data.data(), size);
}

/*
 * takeSnapshot — 抓取当前调试上下文的完整快照
 *
 * 前置条件：
 *   - x64dbg 必须正在调试（DbgIsDebugging() == true）
 *   - 目标进程必须已暂停（DbgIsRunning() == false）
 *
 * 返回 false 的情况：
 *   - 未在调试状态（snap.is_debugging = false）
 *   - 目标正在运行未暂停（snap.is_paused = false）
 *   - 寄存器读取失败
 */
bool takeSnapshot(SnapshotData& snap)
{
    // 检查调试状态
    if (!DbgIsDebugging()) {
        snap.is_debugging = false;
        return false;
    }
    snap.is_debugging = true;
    snap.is_paused = !DbgIsRunning();

    if (!snap.is_paused)
        return false;

    // 读取所有寄存器（使用 AVX512 结构体以兼容最新版 x64dbg SDK）
    REGDUMP_AVX512 regdump = {};
    if (!DbgGetRegDumpEx(&regdump, sizeof(regdump)))
        return false;

    // 通用寄存器（cip/cax/cbx 等是 x64dbg SDK 的跨平台命名）
    snap.rip = regdump.regcontext.cip;
    snap.rax = regdump.regcontext.cax;
    snap.rbx = regdump.regcontext.cbx;
    snap.rcx = regdump.regcontext.ccx;
    snap.rdx = regdump.regcontext.cdx;
    snap.rsi = regdump.regcontext.csi;
    snap.rdi = regdump.regcontext.cdi;
    snap.rbp = regdump.regcontext.cbp;
    snap.rsp = regdump.regcontext.csp;
    snap.rflags = regdump.regcontext.eflags;

#ifdef _WIN64
    // x64 专有寄存器
    snap.r8  = regdump.regcontext.r8;
    snap.r9  = regdump.regcontext.r9;
    snap.r10 = regdump.regcontext.r10;
    snap.r11 = regdump.regcontext.r11;
    snap.r12 = regdump.regcontext.r12;
    snap.r13 = regdump.regcontext.r13;
    snap.r14 = regdump.regcontext.r14;
    snap.r15 = regdump.regcontext.r15;

    // GS base：Windows x64 中 GS 指向 TEB（Thread Environment Block）
    // regcontext.gs 只是段选择子（0x2B），不是 base address
    // 用 DbgValFromString 获取真正的 GS base（= TEB 地址）
    snap.gs_base = DbgValFromString("teb()");
#endif

    snap.regions.clear();

    // ===== 记录模块名 =====
    char modname[MAX_MODULE_SIZE] = {};
    if (DbgGetModuleAt(snap.rip, modname))
        snap.module_name = modname;

    // ===== 枚举进程所有已提交内存页（2026-08-13 新增） =====
    //
    // 为什么需要映射所有内存：
    //   VMP 保护的代码在运行时会动态分配可执行内存（通过 VirtualAlloc 等），
    //   handler 之间通过 push reg; ret 间接跳转到这些区域。
    //   如果 Unicorn 中没有这些内存，间接跳转的目标地址会因为内存内容错误
    //   而计算出无效值（比如指向 MEM_FREE 的地址），导致模拟脱轨。
    //
    // DbgMemMap() 返回什么：
    //   x64dbg 内部调用 VirtualQueryEx 枚举目标进程的内存布局，
    //   返回 MEMMAP 结构（包含 MEMPAGE 数组），每个 MEMPAGE 含 MEMORY_BASIC_INFORMATION。
    //   注意：返回的 page 指针由 x64dbg 的 BridgeAlloc 分配，用完要 BridgeFree。
    //
    // 过滤策略：
    //   - 只取 MEM_COMMIT 的页（已分配且有物理页的内存）
    //   - 跳过 PAGE_NOACCESS（不可读写执行）
    //   - 跳过 PAGE_GUARD（触发异常的守护页，读取会导致异常）
    //   - 跳过 >256MB 的超大区域（防止内存爆炸）
    //   - DbgMemRead 失败的页静默跳过（可能权限不足或地址已失效）
    //
    MEMMAP memmap = {};
    if (DbgMemMap(&memmap) && memmap.count > 0 && memmap.page) {
        size_t total_bytes = 0;
        int mapped_count = 0;
        int skipped_count = 0;

        for (int i = 0; i < memmap.count; i++) {
            const auto& mbi = memmap.page[i].mbi;

            // 只映射已提交的内存（MEM_COMMIT）
            // MEM_RESERVE 只是保留了地址空间，没有实际物理页，不能读
            // MEM_FREE 是未分配的地址空间
            if (mbi.State != MEM_COMMIT)
                continue;

            // 跳过不可读的页面
            // PAGE_NOACCESS：任何访问都会触发异常
            // PAGE_GUARD：首次访问触发 STATUS_GUARD_PAGE_VIOLATION 异常
            // protect == 0：未知保护属性，不安全
            DWORD protect = mbi.Protect;
            if (protect == 0 || (protect & PAGE_NOACCESS) || (protect & PAGE_GUARD)) {
                skipped_count++;
                continue;
            }

            uint64_t base = (uint64_t)mbi.BaseAddress;
            size_t size = mbi.RegionSize;

            // 安全限制：跳过超大区域（>256MB），避免内存爆炸
            // 正常进程不会有这么大的连续区域，有的话通常是映射文件或保留区
            if (size > 256 * 1024 * 1024) {
                skipped_count++;
                continue;
            }

            // 读取内存内容到 region
            // DbgMemRead 内部使用 ReadProcessMemory，失败时返回 false
            SnapshotData::MemoryRegion region;
            if (readMemoryRegion(base, size, region)) {
                total_bytes += size;
                mapped_count++;
                snap.regions.push_back(std::move(region));
            }
        }

        // DbgMemMap 返回的 page 指针由 BridgeAlloc 分配，必须用 BridgeFree 释放
        BridgeFree(memmap.page);

        logger::info("Snapshot: mapped %d regions, %zu bytes total (%d skipped)",
                     mapped_count, total_bytes, skipped_count);
    } else {
        // ===== DbgMemMap 失败时降级到旧逻辑（模块+栈） =====
        // 正常情况不会走到这里，除非 x64dbg SDK 版本不支持 DbgMemMap
        logger::info("Snapshot: DbgMemMap failed, falling back to module+stack mapping");

        // 映射 RIP 所在模块
        if (snap.module_name.size()) {
            duint mod_base = DbgModBaseFromName(snap.module_name.c_str());
            duint mod_size = DbgFunctions()->ModSizeFromAddr(mod_base);
            if (mod_base && mod_size) {
                SnapshotData::MemoryRegion mod_region;
                if (readMemoryRegion(mod_base, mod_size, mod_region))
                    snap.regions.push_back(std::move(mod_region));
            }
        }

        // 模块映射失败时降级：只映射 RIP 往后 64KB
        if (snap.regions.empty()) {
            SnapshotData::MemoryRegion code_region;
            if (readMemoryRegion(snap.rip, 0x10000, code_region))
                snap.regions.push_back(std::move(code_region));
        }

        // 映射栈内存
        uint64_t stack_base = snap.rsp > 0x10000 ? snap.rsp - 0x10000 : 0;
        SnapshotData::MemoryRegion stack_region;
        if (readMemoryRegion(stack_base, 0x20000, stack_region))
            snap.regions.push_back(std::move(stack_region));
    }

    return true;
}

} // namespace deobf
