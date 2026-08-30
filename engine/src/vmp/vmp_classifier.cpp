// vmp_classifier.cpp — VMP handler 模式识别
// 对应 VmpHelper: VmpBlockBuilder.cpp (tryMatch_*)

#include "vmp_classifier.h"
#include "vmp_context.h"
#include <cstdio>
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
// 内部工具
// ─────────────────────────────────────────────────────────────────────────────

// 在单条 InsnPcode 内找定义某个 unique 变量的 RawOp
static const RawOp* find_def(const InsnPcode& ip, uint64_t unique_off) {
    for (auto& op : ip.ops) {
        if (op.dead || !op.has_out) continue;
        if (op.out.space->getName() == "unique" && op.out.offset == unique_off)
            return &op;
    }
    return nullptr;
}

// 构建 unique → 运行时值 映射（COPY/INT_ADD/INT_SUB）
std::map<uint64_t, uint64_t> build_unique_vals(const InsnPcode& ip) {
    std::map<uint64_t, uint64_t> uv;
    for (auto& op : ip.ops) {
        if (op.dead || !op.has_out) continue;
        if (op.out.space->getName() != "unique") continue;

        if (op.opc == ghidra::CPUI_COPY && !op.ins.empty()) {
            auto& s = op.ins[0];
            if (s.space->getName() == "register") {
                int uid = ghidra_off_to_uc(s.offset);
                if (uid >= 0) uv[op.out.offset] = ip.regs.get(uid);
            }
        } else if ((op.opc == ghidra::CPUI_INT_ADD ||
                    op.opc == ghidra::CPUI_INT_SUB ||
                    op.opc == ghidra::CPUI_INT_MULT) && op.ins.size() == 2) {
            uint64_t a = 0, b = 0; bool ok = true;
            for (int i = 0; i < 2; ++i) {
                auto& v = op.ins[i];
                uint64_t& dst = (i == 0) ? a : b;
                if (v.space->getName() == "register") {
                    int uid = ghidra_off_to_uc(v.offset);
                    if (uid >= 0) dst = ip.regs.get(uid); else ok = false;
                } else if (v.space->getName() == "const") {
                    dst = v.offset;
                } else if (v.space->getName() == "unique") {
                    auto it = uv.find(v.offset);
                    if (it != uv.end()) dst = it->second; else ok = false;
                } else { ok = false; }
            }
            if (ok) uv[op.out.offset] = (op.opc == ghidra::CPUI_INT_ADD) ? a + b
                                      : (op.opc == ghidra::CPUI_INT_MULT) ? a * b
                                      : a - b;
        }
    }
    return uv;
}

// ─────────────────────────────────────────────────────────────────────────────
// 段内 def-use 表（段内 SSA）
// 对应 VmpHelper: PcodeOpTracer::TraceInput 所依赖的 SSA def 链
// ─────────────────────────────────────────────────────────────────────────────

SegDefUse build_seg_defuse(const VmpHandlerSeg& seg,
                           const std::vector<InsnPcode>& insns)
{
    SegDefUse du;
    for (int i = seg.start_idx; i <= seg.end_idx; ++i) {
        for (auto& op : insns[i].ops) {
            if (op.dead || !op.has_out) continue;  // 只收录 live op 的 def，dead 写会污染寄存器溯源链
            VnKey k{ op.out.space->getName(), op.out.offset };
                    du[k] = { &op, i };  // 一律取最后一次写（unique 跨指令复用同一 offset，后写才是实际引用来源）
        }
    }
    return du;
}

// ── 溯源结果（等价 VmpHelper TraceInputResult）────────────────────────────────
struct SrcInfo {
    bool is_vmstack_addr = false; // varnode 本身是 vmStack 地址（INT_ADD(rsp,off)）= bAccessMem=false
    bool is_vmstack_off  = false; // varnode 派生自 vmStack offset 寄存器（如 rsi 及其算术结果）
    bool from_vmstack    = false; // varnode 是 LOAD(vmStack_addr) 的结果          = bAccessMem=true
    bool from_vmcode     = false; // varnode 是 LOAD(vmCode 寄存器) 的结果
};

// 前向声明（两者互递归）
static SrcInfo trace_varnode(const ghidra::VarnodeData& vn,
                              const SegDefUse& du,
                              uint64_t seg_vmcode_off,
                              uint64_t vmstack_off_reg,
                              uint64_t vmstack_direct_reg,
                              int depth);

// 溯源某个 def op 的输出来源
static SrcInfo trace_defentry(const DefEntry& de,
                               const SegDefUse& du,
                               uint64_t seg_vmcode_off,
                               uint64_t vmstack_off_reg,
                               uint64_t vmstack_direct_reg,
                               int depth)
{
    SrcInfo r;
    if (!de.op) return r;
    const RawOp& op = *de.op;

    switch (op.opc) {
    case ghidra::CPUI_LOAD:
        if (op.ins.size() >= 2) {
            SrcInfo addr = trace_varnode(op.ins[1], du, seg_vmcode_off, vmstack_off_reg, vmstack_direct_reg, depth);
            // addr.from_vmstack: 等价 VmpHelper bAccessMem 传播——LOAD[LOAD[vmStack_addr]] 也算 from_vmstack
            if (addr.is_vmstack_addr || addr.from_vmstack) r.from_vmstack = true;
            else if (addr.from_vmcode) r.from_vmcode  = true;
        }
        break;

    case ghidra::CPUI_COPY:
        if (!op.ins.empty())
            r = trace_varnode(op.ins[0], du, seg_vmcode_off, vmstack_off_reg, vmstack_direct_reg, depth);
        // is_vmstack_off 通过 COPY 自动传播（recursive 返回值直接赋给 r）
        break;

    case ghidra::CPUI_INT_ADD: {
        if (op.ins.size() != 2) break;
        bool a_rsp = (op.ins[0].space->getName() == "register" && op.ins[0].offset == 0x20);
        bool b_rsp = (op.ins[1].space->getName() == "register" && op.ins[1].offset == 0x20);
        bool a_vso = (vmstack_off_reg && op.ins[0].space->getName() == "register"
                      && op.ins[0].offset == vmstack_off_reg);
        bool b_vso = (vmstack_off_reg && op.ins[1].space->getName() == "register"
                      && op.ins[1].offset == vmstack_off_reg);
        if ((a_rsp && b_vso) || (b_rsp && a_vso)) {
            r.is_vmstack_addr = true;
        } else {
            SrcInfo a = trace_varnode(op.ins[0], du, seg_vmcode_off, vmstack_off_reg, vmstack_direct_reg, depth);
            SrcInfo b = trace_varnode(op.ins[1], du, seg_vmcode_off, vmstack_off_reg, vmstack_direct_reg, depth);
            if (a.is_vmstack_addr || b.is_vmstack_addr) r.is_vmstack_addr = true;
            // 慢路径：INT_ADD(rsp, COPY(rsi)) — rsi 经 unique 间接传入
            if ((a_rsp && b.is_vmstack_off) || (b_rsp && a.is_vmstack_off))
                r.is_vmstack_addr = true;
            if (a.is_vmstack_off || b.is_vmstack_off) r.is_vmstack_off = true;
            // vmCode 指针做偏移运算（如 LOAD [r11+4]）：INT_ADD(r11, const) 仍属于 from_vmcode
            if (a.from_vmcode || b.from_vmcode) r.from_vmcode = true;
        }
        break;
    }

    case ghidra::CPUI_INT_SUB:
        if (op.ins.size() >= 1) {
            SrcInfo a = trace_varnode(op.ins[0], du, seg_vmcode_off, vmstack_off_reg, vmstack_direct_reg, depth);
            if (a.is_vmstack_addr) r.is_vmstack_addr = true;
            if (a.is_vmstack_off)  r.is_vmstack_off  = true;
        }
        break;

    default:
        // 等价 VmpHelper traceOpCode：任意其他 op 都递归追溯所有输入并合并 flags
        // 解密链（INT_XOR/BSWAP/INT_AND/INT_NEGATE/…）可透明传播 from_vmstack/from_vmcode
        for (auto& in : op.ins) {
            SrcInfo s = trace_varnode(in, du, seg_vmcode_off, vmstack_off_reg, vmstack_direct_reg, depth);
            if (s.is_vmstack_addr) r.is_vmstack_addr = true;
            if (s.is_vmstack_off)  r.is_vmstack_off  = true;
            if (s.from_vmstack)    r.from_vmstack     = true;
            if (s.from_vmcode)     r.from_vmcode      = true;
        }
        break;
    }
    return r;
}

// 溯源一个 varnode 的来源（等价 VmpHelper TraceInput + reg_stack 识别）
// vmstack_off_reg:    rsp + vmstack_off_reg = vmStack 地址（vPushReg/vPopReg 阶段）
// vmstack_direct_reg: 直接作为 vmStack 指针（执行阶段，等价 VmpHelper reg_stack）
static SrcInfo trace_varnode(const ghidra::VarnodeData& vn,
                              const SegDefUse& du,
                              uint64_t seg_vmcode_off,
                              uint64_t vmstack_off_reg,
                              uint64_t vmstack_direct_reg,
                              int depth)
{
    SrcInfo r;
    if (depth > 12) return r;

    const std::string& sp = vn.space->getName();

    if (sp == "register") {
        // vmstack_direct_reg (e.g. rbx=0x18): 执行阶段直接 vmStack 指针
        // 等价 VmpHelper: srcResult[0].name == buildCtx->vmreg.reg_stack
        if (vmstack_direct_reg && vn.offset == vmstack_direct_reg) {
            r.is_vmstack_addr = true;
            return r;
        }
        // vmstack_off_reg (e.g. rsi=0x30): vmStack offset 寄存器，不追溯段内 def
        if (vmstack_off_reg && vn.offset == vmstack_off_reg) {
            r.is_vmstack_off = true;
            return r;
        }
        if (seg_vmcode_off && vn.offset == seg_vmcode_off) { r.from_vmcode = true; return r; }
        VnKey k{ sp, vn.offset };
        auto it = du.find(k);
        if (it != du.end())
            return trace_defentry(it->second, du, seg_vmcode_off, vmstack_off_reg, vmstack_direct_reg, depth + 1);
        return r;
    }

    if (sp == "unique") {
        VnKey k{ sp, vn.offset };
        auto it = du.find(k);
        if (it == du.end()) return r;
        return trace_defentry(it->second, du, seg_vmcode_off, vmstack_off_reg, vmstack_direct_reg, depth + 1);
    }

    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
// 地址判断工具
// ─────────────────────────────────────────────────────────────────────────────

// STORE 目标是 VM 操作数栈（不是 vmRegFile）
// 对应 VmpHelper: tryMatch_vPushReg / tryMatch_vPushImm 中对 dst 的校验
static bool is_vmstack_store(const InsnPcode& ip, const RawOp& op) {
    if (op.ins.size() < 2) return false;
    auto& dst = op.ins[1];

    // Pattern 1: STORE [unique = INT_ADD(rsp, reg/unique)]
    // → mov [rsp+rsi], val
    if (dst.space->getName() == "unique") {
        const RawOp* def = find_def(ip, dst.offset);
        if (def && def->opc == ghidra::CPUI_INT_ADD && def->ins.size() == 2) {
            bool has_rsp = false, has_other = false;
            for (auto& v : def->ins) {
                if (v.space->getName() == "register" && v.offset == 0x20) has_rsp = true;
                else if (v.space->getName() == "register" || v.space->getName() == "unique") has_other = true;
            }
            if (has_rsp && has_other) return true;
        }
    }

    // Pattern 2: STORE [register:X] where X != rsp
    // → 64-bit VMP 用 rbx 作为 vmStack 指针（sub rbx,8; mov [rbx],val）
    if (dst.space->getName() == "register" && dst.offset != 0x20)
        return true;

    return false;
}

// LOAD 来源是 VM 操作数栈（不是 vmCode、不是 host rsp）
// 对应 VmpHelper: tryMatch_vPopReg / tryMatch_vMemAccess 中对 src 的校验
static bool is_vmstack_load(const InsnPcode& ip, const RawOp& op,
                            uint64_t seg_vmcode_off) {
    if (op.ins.size() < 2) return false;
    auto& la = op.ins[1];

    // Pattern 1: LOAD [unique = INT_ADD(rsp, reg/unique)]
    if (la.space->getName() == "unique") {
        const RawOp* def = find_def(ip, la.offset);
        if (def && def->opc == ghidra::CPUI_INT_ADD && def->ins.size() == 2) {
            bool has_rsp = false, has_other = false;
            for (auto& v : def->ins) {
                if (v.space->getName() == "register") {
                    if (v.offset == 0x20) has_rsp = true;
                    else                   has_other = true;
                } else if (v.space->getName() == "unique") {
                    has_other = true;
                }
            }
            if (has_rsp && has_other) return true;
        }
    }

    // Pattern 2: LOAD [register:X] where X != rsp and X != vmCode
    if (la.space->getName() == "register"
            && la.offset != 0x20
            && la.offset != seg_vmcode_off)
        return true;

    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// 段切分
// ─────────────────────────────────────────────────────────────────────────────

std::vector<VmpHandlerSeg> split_handler_segs(const std::vector<InsnPcode>& insns) {
    std::vector<VmpHandlerSeg> segs;
    int seg_start = 0;

    for (int i = 0; i < (int)insns.size(); ++i) {
        bool is_boundary = false;
        for (auto& op : insns[i].ops)
            if (!op.dead && (op.opc == ghidra::CPUI_BRANCHIND ||
                             op.opc == ghidra::CPUI_RETURN))
                is_boundary = true;
        if (!is_boundary) continue;

        int ts = 0, tl = 0;
        for (int j = seg_start; j <= i; ++j)
            for (auto& op : insns[j].ops) {
                if (op.dead) continue;
                if (op.opc == ghidra::CPUI_STORE) ts++;
                if (op.opc == ghidra::CPUI_LOAD)  tl++;
            }
        segs.push_back({seg_start, i, ts, tl});
        seg_start = i + 1;
    }

    // 末尾残余段（trace 被截断）
    if (seg_start < (int)insns.size()) {
        int ts = 0, tl = 0;
        for (int j = seg_start; j < (int)insns.size(); ++j)
            for (auto& op : insns[j].ops) {
                if (op.dead) continue;
                if (op.opc == ghidra::CPUI_STORE) ts++;
                if (op.opc == ghidra::CPUI_LOAD)  tl++;
            }
        segs.push_back({seg_start, (int)insns.size() - 1, ts, tl});
    }

    return segs;
}

// ─────────────────────────────────────────────────────────────────────────────
// 每段 vmCode 寄存器探测
// 对应 VmpHelper: updateVmReg() — 每个 handler block 独立识别 vmCode
// ─────────────────────────────────────────────────────────────────────────────

uint64_t detect_seg_vmcode(const VmpHandlerSeg& seg,
                           const std::vector<InsnPcode>& insns,
                           const VmpCtx& ctx,
                           uint64_t global_vmcode_off)
{
    auto is_mapped = [&](uint64_t addr) -> bool {
        if (!ctx.pages) return false;
        for (auto& pg : *ctx.pages)
            if (addr >= pg.base && addr < pg.base + pg.data.size()) return true;
        return false;
    };

    for (int i = seg.start_idx; i <= seg.end_idx; ++i) {
        auto& ip = insns[i];
        for (auto& op : ip.ops) {
            if (op.dead) continue;
            if (op.opc != ghidra::CPUI_LOAD || op.ins.size() < 2) continue;
            auto& la = op.ins[1];
            if (la.space->getName() != "register") continue;
            if (la.offset == 0x20) continue;  // rsp 排除
            int uid = ghidra_off_to_uc(la.offset);
            if (uid < 0) continue;
            uint64_t ra = ip.regs.get(uid);
            int64_t  sd = (int64_t)(ra - ip.regs.rsp);
            if (is_mapped(ra) && (sd < -0x1000 || sd > 0x1000)
                    && (!ctx.vmRegBase
                        || ra < ctx.vmRegBase
                        || ra >= ctx.vmRegBase + 32 * 8)) {
                return la.offset;
            }
        }
    }

    return global_vmcode_off;  // 探测失败，回退全局值
}

// ─────────────────────────────────────────────────────────────────────────────
// 模式匹配（对应 VmpHelper AnaVmpPattern 调用链）
// ─────────────────────────────────────────────────────────────────────────────

// tryMatch_vPopReg: vmRegFile STORE + vmStack LOAD
// → 从操作数栈弹出值，写回宿主寄存器
static bool tryMatch_vPopReg(const VmpHandlerSeg& seg,
                              const std::vector<InsnPcode>& insns,
                              VmpCtx& ctx,
                              uint64_t seg_vmcode_off,
                              HandlerResult& res)
{
    bool found_vmreg_store  = false;
    bool found_vmstack_load = false;
    uint64_t candidate_vdr  = 0;   // 候选 vmstack_direct_reg，只在 match 成功后提交

    for (int i = seg.start_idx; i <= seg.end_idx; ++i) {
        auto& ip = insns[i];
        auto  uv = build_unique_vals(ip);

        for (auto& op : ip.ops) {
            if (op.dead) continue;

            if (op.opc == ghidra::CPUI_STORE && op.ins.size() >= 3 && ctx.vmRegBase) {
                auto& dst = op.ins[1];
                uint64_t dst_addr = 0;
                if (dst.space->getName() == "register") {
                    int uid = ghidra_off_to_uc(dst.offset);
                    if (uid >= 0) dst_addr = ip.regs.get(uid);
                } else if (dst.space->getName() == "unique") {
                    auto it = uv.find(dst.offset);
                    if (it != uv.end()) dst_addr = it->second;
                }
                if (dst_addr >= ctx.vmRegBase && dst_addr < ctx.vmRegBase + 32 * 8) {
                    int64_t rel = (int64_t)(dst_addr - ctx.vmRegBase);
                    if (rel >= 0 && rel % 8 == 0) {
                        found_vmreg_store = true;
                        res.slot = (int)(rel / 8);
                        auto it = ctx.vmRegSlotMap.find(dst_addr);
                        res.reg_name = (it != ctx.vmRegSlotMap.end()) ? it->second : "?";
                    }
                }
            }

            if (op.opc == ghidra::CPUI_LOAD && !found_vmstack_load) {
                if (is_vmstack_load(ip, op, seg_vmcode_off)) {
                    found_vmstack_load = true;
                    // 记录候选 vmstack_direct_reg（Pattern-2: LOAD [register:X]）
                    // 等价 VmpHelper: buildCtx->vmreg.reg_stack = srcResult[0].name
                    // 注意：只记录，不提交——确认 match 成功后才写入 ctx
                    if (!ctx.vmstack_direct_reg && !candidate_vdr && op.ins.size() >= 2) {
                        auto& la = op.ins[1];
                        if (la.space->getName() == "register"
                                && la.offset != 0x20
                                && la.offset != seg_vmcode_off)
                            candidate_vdr = la.offset;
                    }
                }
            }
        }
    }

    if (found_vmreg_store && found_vmstack_load) {
        // match 确认后才提交 vmstack_direct_reg（防止 vPushReg 段污染）
        if (!ctx.vmstack_direct_reg && candidate_vdr)
            ctx.vmstack_direct_reg = candidate_vdr;
        res.type = "vPopReg";
        return true;
    }
    return false;
}

// tryMatch_vPushReg: vmStack STORE + vmRegFile LOAD
// → 把宿主寄存器值压入操作数栈
static bool tryMatch_vPushReg(const VmpHandlerSeg& seg,
                               const std::vector<InsnPcode>& insns,
                               const VmpCtx& ctx,
                               uint64_t seg_vmcode_off,
                               HandlerResult& res)
{
    bool found_vmstack_store = false;
    bool found_vmreg_load    = false;

    for (int i = seg.start_idx; i <= seg.end_idx; ++i) {
        auto& ip = insns[i];
        auto  uv = build_unique_vals(ip);

        for (auto& op : ip.ops) {
            if (op.dead) continue;

            if (op.opc == ghidra::CPUI_STORE && !found_vmstack_store)
                if (is_vmstack_store(ip, op))
                    found_vmstack_store = true;

            if (op.opc == ghidra::CPUI_LOAD && op.ins.size() >= 2 && ctx.vmRegBase) {
                auto& la = op.ins[1];
                uint64_t load_addr = 0;
                if (la.space->getName() == "register") {
                    int uid = ghidra_off_to_uc(la.offset);
                    if (uid >= 0) load_addr = ip.regs.get(uid);
                } else if (la.space->getName() == "unique") {
                    auto it = uv.find(la.offset);
                    if (it != uv.end()) load_addr = it->second;
                }
                if (load_addr >= ctx.vmRegBase && load_addr < ctx.vmRegBase + 32 * 8) {
                    int64_t rel = (int64_t)(load_addr - ctx.vmRegBase);
                    if (rel >= 0 && rel % 8 == 0 && !found_vmreg_load) {
                        found_vmreg_load = true;
                        res.slot = (int)(rel / 8);
                        auto it = ctx.vmRegSlotMap.find(load_addr);
                        res.reg_name = (it != ctx.vmRegSlotMap.end()) ? it->second : "?";
                    }
                }
            }
        }
    }

    if (found_vmstack_store && found_vmreg_load) {
        res.type = "vPushReg";
        return true;
    }
    return false;
}

// tryMatch_vPushImm: vmStack STORE + vmCode LOAD，无 vmRegFile LOAD
// → 把字节码中的立即数压入操作数栈
static bool tryMatch_vPushImm(const VmpHandlerSeg& seg,
                               const std::vector<InsnPcode>& insns,
                               const VmpCtx& ctx,
                               uint64_t seg_vmcode_off,
                               HandlerResult& res)
{
    bool     found_vmstack_store = false;
    bool     found_vmcode_load   = false;
    bool     found_vmreg_load    = false;
    uint64_t store_val           = 0;

    for (int i = seg.start_idx; i <= seg.end_idx; ++i) {
        auto& ip = insns[i];
        auto  uv = build_unique_vals(ip);

        for (auto& op : ip.ops) {
            if (op.dead) continue;

            if (op.opc == ghidra::CPUI_STORE && op.ins.size() >= 3) {
                bool vmstack = is_vmstack_store(ip, op);
                if (!found_vmstack_store && vmstack) {
                    found_vmstack_store = true;
                    // 提取写入值（= 立即数）
                    auto& val = op.ins[2];
                    if (val.space->getName() == "register") {
                        int uid = ghidra_off_to_uc(val.offset);
                        if (uid >= 0) store_val = ip.regs.get(uid);
                    } else if (val.space->getName() == "unique") {
                        auto it = uv.find(val.offset);
                        if (it != uv.end()) store_val = it->second;
                    } else if (val.space->getName() == "const") {
                        store_val = val.offset;
                    }
                }
                // 检查是否有 vmRegFile STORE（有则不是 vPushImm）
                // 注意：vmStack STORE 的运行时地址可能落在 vmRegBase 窗口内（两者相邻），
                // 必须先排除已识别为 vmStack 的 STORE，否则误判为 vmRegFile STORE。
                if (!vmstack && ctx.vmRegBase) {
                    auto& dst = op.ins[1];
                    uint64_t dst_addr = 0;
                    if (dst.space->getName() == "register") {
                        int uid = ghidra_off_to_uc(dst.offset);
                        if (uid >= 0) dst_addr = ip.regs.get(uid);
                    } else if (dst.space->getName() == "unique") {
                        auto it = uv.find(dst.offset);
                        if (it != uv.end()) dst_addr = it->second;
                    }
                    if (dst_addr >= ctx.vmRegBase && dst_addr < ctx.vmRegBase + 32 * 8)
                        found_vmreg_load = true; // 复用该标志排除
                }
            }

            if (op.opc == ghidra::CPUI_LOAD && op.ins.size() >= 2) {
                auto& la = op.ins[1];
                if (la.space->getName() == "register" && la.offset == seg_vmcode_off)
                    found_vmcode_load = true;
                // 也检查 vmRegFile LOAD
                if (ctx.vmRegBase) {
                    uint64_t load_addr = 0;
                    if (la.space->getName() == "register") {
                        int uid = ghidra_off_to_uc(la.offset);
                        if (uid >= 0) load_addr = ip.regs.get(uid);
                    } else if (la.space->getName() == "unique") {
                        auto it = uv.find(la.offset);
                        if (it != uv.end()) load_addr = it->second;
                    }
                    if (load_addr >= ctx.vmRegBase && load_addr < ctx.vmRegBase + 32 * 8)
                        found_vmreg_load = true;
                }
            }
        }
    }

    if (found_vmstack_store && found_vmcode_load && !found_vmreg_load) {
        res.type    = "vPushImm";
        res.imm_val = store_val;
        return true;
    }
    return false;
}

// tryMatch_vMemAccess
// 对应 VmpHelper tryMatch_vMemAccess（含精确 storeCount/loadCount 门卫）。
//
// VmpHelper 的门卫等价计数：
//   语义 STORE：dst 地址 trace_varnode → is_vmstack_addr 或 from_vmstack
//   语义 LOAD ：addr trace_varnode → is_vmstack_addr 或 from_vmcode
// 有了精确的 vmstack_off_reg 后，INT_ADD(rsp, vmstack_off_reg) 才是 vmStack 地址，
// native push [rsp] 不再误命中，计数与 VmpHelper obank 等价。
static bool tryMatch_vMemAccess(const VmpHandlerSeg& seg,
                                 const std::vector<InsnPcode>& insns,
                                 const VmpCtx& ctx,
                                 uint64_t seg_vmcode_off,
                                 HandlerResult& res)
{
    uint64_t vso = ctx.vmstack_off_reg;
    uint64_t vdr = ctx.vmstack_direct_reg;
    SegDefUse du = build_seg_defuse(seg, insns);

    int          sem_stores = 0;
    const RawOp* the_store  = nullptr;
    int          sem_loads  = 0;

    for (int i = seg.start_idx; i <= seg.end_idx; ++i) {
        for (auto& op : insns[i].ops) {
            if (op.dead) continue;
            if (op.opc == ghidra::CPUI_STORE && op.ins.size() >= 3) {
                SrcInfo dst = trace_varnode(op.ins[1], du, seg_vmcode_off, vso, vdr, 0);
                if (dst.is_vmstack_addr || dst.from_vmstack) {
                    sem_stores++;
                    if (!the_store) the_store = &op;
                }
            }
            if (op.opc == ghidra::CPUI_LOAD && op.ins.size() >= 2) {
                SrcInfo addr = trace_varnode(op.ins[1], du, seg_vmcode_off, vso, vdr, 0);
                if (addr.is_vmstack_addr || addr.from_vmcode || addr.from_vmstack) sem_loads++;
            }
        }
    }

    // vReadMem:  1 store + 3 loads（从宿主内存读，结果压 vmStack）
    // vWriteMem: 2 stores + 2 loads（弹 vmStack，写入宿主内存）
    bool is_write = (sem_stores == 2 && sem_loads == 2);
    bool is_read  = (sem_stores == 1 && sem_loads == 3);
    if (!is_read && !is_write) {
        if (seg.live_stores >= 1 && seg.live_loads >= 2)
            fprintf(stderr, "  [vMemAccess-miss] seg S=%d L=%d sem_s=%d sem_l=%d vso=0x%llx vdr=0x%llx vmcoff=0x%llx\n",
                    seg.live_stores, seg.live_loads, sem_stores, sem_loads,
                    (unsigned long long)vso, (unsigned long long)vdr,
                    (unsigned long long)seg_vmcode_off);
        return false;
    }
    if (!the_store || the_store->ins.size() < 3) return false;

    SrcInfo dst = trace_varnode(the_store->ins[1], du, seg_vmcode_off, vso, vdr, 0);
    SrcInfo src = trace_varnode(the_store->ins[2], du, seg_vmcode_off, vso, vdr, 0);

    if (!dst.is_vmstack_addr && !dst.from_vmstack) return false;
    if (!src.from_vmstack && !src.from_vmcode) return false;  // vWriteMem: src 来自 vmStack；vReadMem: src 来自宿主内存（via vmCode 地址间接）

    if (is_write) res.type = "vWriteMem";
    else          res.type = "vReadMem";
    return true;
}

// tryMatch_vLogicalOp: 无 vmStack 参与，纯 vmRegFile LOAD×2 + vmRegFile STORE
// → ADD/NAND 等二元运算（VmpHelper: tryMatch_vLogicalOp）
static bool tryMatch_vLogicalOp(const VmpHandlerSeg& seg,
                                 const std::vector<InsnPcode>& insns,
                                 const VmpCtx& ctx,
                                 uint64_t /*seg_vmcode_off*/,
                                 HandlerResult& res)
{
    if (!ctx.vmRegBase) return false;

    bool found_vmreg_store = false;
    bool found_vmstack_any = false;
    int  vmreg_load_count  = 0;

    for (int i = seg.start_idx; i <= seg.end_idx; ++i) {
        auto& ip = insns[i];
        auto  uv = build_unique_vals(ip);

        for (auto& op : ip.ops) {
            if (op.dead) continue;

            if (op.opc == ghidra::CPUI_STORE && op.ins.size() >= 3) {
                if (is_vmstack_store(ip, op)) { found_vmstack_any = true; break; }
                auto& dst = op.ins[1];
                uint64_t dst_addr = 0;
                if (dst.space->getName() == "register") {
                    int uid = ghidra_off_to_uc(dst.offset);
                    if (uid >= 0) dst_addr = ip.regs.get(uid);
                } else if (dst.space->getName() == "unique") {
                    auto it = uv.find(dst.offset);
                    if (it != uv.end()) dst_addr = it->second;
                }
                if (dst_addr >= ctx.vmRegBase && dst_addr < ctx.vmRegBase + 32 * 8)
                    found_vmreg_store = true;
            }

            if (op.opc == ghidra::CPUI_LOAD && op.ins.size() >= 2) {
                auto& la = op.ins[1];
                uint64_t load_addr = 0;
                if (la.space->getName() == "register") {
                    int uid = ghidra_off_to_uc(la.offset);
                    if (uid >= 0) load_addr = ip.regs.get(uid);
                } else if (la.space->getName() == "unique") {
                    auto it = uv.find(la.offset);
                    if (it != uv.end()) load_addr = it->second;
                }
                if (load_addr >= ctx.vmRegBase && load_addr < ctx.vmRegBase + 32 * 8)
                    vmreg_load_count++;
            }
        }
        if (found_vmstack_any) break;
    }

    if (!found_vmstack_any && found_vmreg_store && vmreg_load_count >= 2) {
        res.type = "vLogicalOp";
        return true;
    }
    return false;
}

// tryMatch_vExit: 对应 VmpHelper tryMatch_vExit (loadCount >= 7, storeCount == 0)
// vExit = pop 序列，恢复所有 CPU 寄存器后 ret，没有任何 STORE
static bool tryMatch_vExit(const VmpHandlerSeg& seg,
                            const std::vector<InsnPcode>& /*insns*/,
                            const VmpCtx& /*ctx*/,
                            uint64_t /*seg_vmcode_off*/,
                            HandlerResult& res)
{
    if (seg.live_loads >= 7 && seg.live_stores == 0) {
        res.type = "vExit";
        return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// 主分类入口 — 对应 VmpHelper AnaVmpPattern 调用链
// ─────────────────────────────────────────────────────────────────────────────

HandlerResult classify_seg(int seg_idx,
                           const VmpHandlerSeg& seg,
                           const std::vector<InsnPcode>& insns,
                           VmpCtx& ctx,
                           uint64_t seg_vmcode_off)
{
    HandlerResult res;
    res.seg_idx  = seg_idx;
    res.type     = "unknown";
    res.reg_name = "";

    // seg[0] 固定为 init+dispatch
    if (seg_idx == 0) { res.type = "(init+dispatch)"; return res; }

    // 按 VmpHelper AnaVmpPattern 顺序尝试
    if (tryMatch_vPopReg   (seg, insns, ctx, seg_vmcode_off, res)) goto done;
    if (tryMatch_vPushReg  (seg, insns, ctx, seg_vmcode_off, res)) goto done;
    if (tryMatch_vPushImm  (seg, insns, ctx, seg_vmcode_off, res)) goto done;
    if (tryMatch_vMemAccess(seg, insns, ctx, seg_vmcode_off, res)) goto done;
    if (tryMatch_vLogicalOp(seg, insns, ctx, seg_vmcode_off, res)) goto done;
    if (tryMatch_vExit     (seg, insns, ctx, seg_vmcode_off, res)) goto done;

done:
    // slot 名称回退：slot 有效但地址不在 vmRegSlotMap → vmReg[N]
    if ((res.type == "vPushReg" || res.type == "vPopReg")
            && (res.reg_name == "?" || res.reg_name.empty())) {
        char tmp[24];
        snprintf(tmp, sizeof(tmp), "vmReg[%d]", res.slot);
        res.reg_name = tmp;
    }

    return res;
}
