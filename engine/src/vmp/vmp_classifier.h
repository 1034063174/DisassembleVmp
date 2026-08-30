#pragma once
// vmp_classifier.h — VMP handler 模式识别
// 对应 VmpHelper: VmpBlockBuilder.cpp (tryMatch_*)

#include <vector>
#include <map>
#include <string>
#include "vmp_types.h"

// ── 段内 def-use 链（段内 SSA 等价）─────────────────────────────────────────
//
// Sleigh unique 变量天然 SSA（每个 unique 只写一次）。
// register 变量取段内最后一次写（handler 短、基本无二次写，足够精确）。

// Varnode 身份键：(space 名, offset)
struct VnKey {
    std::string space;
    uint64_t    offset = 0;
    bool operator<(const VnKey& o) const {
        if (space != o.space) return space < o.space;
        return offset < o.offset;
    }
};

// def-use 条目：产生该 varnode 的 PCode op，及其所在 insns[] 下标
struct DefEntry {
    const RawOp* op       = nullptr;
    int          insn_idx = -1;
};

// 段内 def-use 表
using SegDefUse = std::map<VnKey, DefEntry>;

// 为一个 handler 段构建 def-use 表
SegDefUse build_seg_defuse(const VmpHandlerSeg& seg,
                           const std::vector<InsnPcode>& insns);

// 分类器需要的上下文（vmRegFile 基址、slot→寄存器名映射、已知 vmCode offset）
struct VmpCtx {
    uint64_t                        vmRegBase   = 0;
    std::map<uint64_t, std::string> vmRegSlotMap;  // runtime_addr → reg_name
    std::vector<MemPage>*           pages       = nullptr;
    uint64_t                        rsp_at_entry = 0;

    // 对应 VmpHelper buildCtx->vmreg.reg_stack（64位等价）
    //
    // vmstack_off_reg (e.g. rsi=0x30):
    //   INT_ADD(rsp, vmstack_off_reg) → is_vmstack_addr（vPushReg/vPopReg 阶段）
    //   trace_varnode 对该寄存器直接返回 is_vmstack_off=true，不追溯段内 def
    //
    // vmstack_direct_reg (e.g. rbx=0x18):
    //   执行阶段直接作为 vmStack 指针（等价 VmpHelper reg_stack="EBP"）
    //   从第一个成功的 vPopReg 段学习（only committed after full match confirmed）
    uint64_t                        vmstack_off_reg    = 0;   // 0 = 未检测
    uint64_t                        vmstack_direct_reg = 0;   // 0 = 未检测
};

// 切分 insns → handler 段列表
// 对应 VmpHelper: VmpTraceFlowGraph 按 BRANCHIND/RETURN 切分
std::vector<VmpHandlerSeg> split_handler_segs(const std::vector<InsnPcode>& insns);

// 对单个 handler 段进行模式匹配，填写 HandlerResult
// 对应 VmpHelper: VmpBlockBuilder::AnaVmpPattern
HandlerResult classify_seg(
    int                                   seg_idx,
    const VmpHandlerSeg&                  seg,
    const std::vector<InsnPcode>&         insns,
    VmpCtx&                               ctx,
    uint64_t                              seg_vmcode_off  // 本段探测到的 vmCode ghidra offset
);

// 在单个 handler 段内探测 vmCode 寄存器的 Ghidra offset
// 对应 VmpHelper: updateVmReg()
uint64_t detect_seg_vmcode(
    const VmpHandlerSeg&          seg,
    const std::vector<InsnPcode>& insns,
    const VmpCtx&                 ctx,
    uint64_t                      global_vmcode_off  // 全局已知值，探测失败时回退
);

// 构建单条 InsnPcode 的 unique→运行时值 映射（供 LOAD/STORE 地址求值）
std::map<uint64_t, uint64_t> build_unique_vals(const InsnPcode& ip);
