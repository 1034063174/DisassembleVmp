#pragma once
// vmp_dead.h — 死代码消除
// 对应 VmpHelper: ActionVmpHandlerDeadCode + RuleVmpEarlyRemoval

#include <vector>
#include "vmp_types.h"

// 对单个 handler 段做反向活跃性分析（[start_idx, end_idx] 闭区间）
// ignore_eflag=true 时 CBRANCH 丢弃 flag 输入（默认，等价 VmpHelper）
// ignore_eflag=false 时 CBRANCH 保留 flag 输入（保守模式）
void eliminate_dead_seg(std::vector<InsnPcode>& insns, int start_idx, int end_idx,
                        bool ignore_eflag = true);

// 全 trace 版（仅在 split 之前临时使用，通常不再调用）
void eliminate_dead(std::vector<InsnPcode>& insns);

