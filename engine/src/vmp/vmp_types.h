#pragma once
// vmp_types.h — 所有模块共享的核心数据结构
// 对应 VmpHelper: VmpInstruction.h

#include <cstdint>
#include <string>
#include <vector>
#include "vmp_context.h"

#ifdef LoadImage
#undef LoadImage
#endif
#include "sleigh.hh"

// 内存页（Unicorn 动态映射 + Sleigh 读取共用）
struct MemPage { uint64_t base; std::vector<uint8_t> data; };

// 单条 PCode 操作（Sleigh 原始输出）
struct RawOp {
    ghidra::OpCode              opc;
    bool                        has_out = false;
    ghidra::VarnodeData         out;
    std::vector<ghidra::VarnodeData> ins;
    bool                        dead = false;   // 死代码消除后标记
};

// 一条 x86 指令对应的 PCode + 执行时寄存器快照 + 栈快照
struct InsnPcode {
    uint64_t            addr     = 0;
    uint32_t            size     = 0;   // 指令字节长度（来自 Unicorn cb_code）
    std::string         asm_text;
    std::string         bytes_str;  // "48 89 D8 "
    std::vector<RawOp>  ops;
    RegCtx              regs = {};  // 该指令执行前的寄存器值（第一次仿真采集）
    // 执行前栈快照，由 Unicorn cb_code 直接读取（非 pages[] 缓存）
    // 布局：[0]=RSP-8*N .. [N]=RSP .. [2N]=RSP+8*N
    static constexpr int NSLOTS = 17; // 2*8+1
    struct StackSlot { int64_t offset; uint64_t addr; uint64_t value; };
    StackSlot stack_slots[NSLOTS] = {};
};

// handler 段：用 BRANCHIND/RETURN 切分后的一段连续 PCode 指令区间
// 对应 VmpHelper: VmpNode
struct VmpHandlerSeg {
    int start_idx, end_idx;     // 在 insns[] 里的下标范围（含两端）
    int live_stores, live_loads; // 死代码消除后存活的 STORE/LOAD 数量
};

// handler 分类结果
// 对应 VmpHelper: VmpInstruction 及其子类
struct HandlerResult {
    int         seg_idx;
    std::string type;       // "vPushReg" / "vPopReg" / "vPushImm" / "vExit" / ...
    int         slot    = -1;
    std::string reg_name;
    uint64_t    imm_val = 0; // vPushImm 的立即数值
};
