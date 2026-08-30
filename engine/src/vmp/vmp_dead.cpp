// vmp_dead.cpp — 死代码消除
// 对应 VmpHelper: ActionVmpHandlerDeadCode + RuleVmpEarlyRemoval
//
// 算法：反向活跃性分析 + 每条 x86 指令后的 RuleVmpEarlyRemoval 正向清理
//
// VnKey 忽略 size，使得 r11b/r11d/r11 都别名到同一个 key，
// 与 Ghidra 的 varnode heritage 保持一致。

#include "vmp_dead.h"
#include <set>
#include <string>

struct VnKey {
    std::string space;
    uint64_t    offset;
    bool operator<(const VnKey& o) const {
        if (space != o.space) return space < o.space;
        return offset < o.offset;
    }
};

static VnKey to_key(const ghidra::VarnodeData& v) {
    return {v.space->getName(), v.offset};
}

static bool vn_eq(const VnKey& a, const VnKey& b) {
    return a.space == b.space && a.offset == b.offset;
}

// x86 flag 寄存器判断：register 空间且 size == 1（ZF/CF/SF/OF/PF/AF/DF 均为 1 字节）
static bool is_flag_varnode(const ghidra::VarnodeData& v) {
    return v.space->getName() == "register" && v.size == 1;
}

static bool has_sideeffect(ghidra::OpCode opc) {
    switch (opc) {
    case ghidra::CPUI_STORE:
    case ghidra::CPUI_BRANCH:    case ghidra::CPUI_CBRANCH:
    case ghidra::CPUI_BRANCHIND: case ghidra::CPUI_CALL:
    case ghidra::CPUI_CALLIND:   case ghidra::CPUI_CALLOTHER:
    case ghidra::CPUI_RETURN:
        return true;
    default:
        return false;
    }
}

// RuleVmpEarlyRemoval: 每条 x86 指令的反向扫描结束后，清理 flag 副作用导致的假活跃。
//
// 问题场景（以 xor r11, rax 为例）:
//   u1 = INT_XOR r11, rax  ← 后续把 u1 加入 live（因为 ZF 需要 u1）
//   r11 = COPY u1           ← dead（r11 在下游已被覆盖）
//   ZF  = INT_EQUAL u1, 0   ← alive（ZF 在 live）
//
// 反向扫描后 INT_XOR 因 u1∈live 而存活，将 r11 加入 live —— 这是错的。
// r11 的 COPY 是 dead 的，说明这条链的唯一"真实"输出已死；
// ZF 的消费是 flag 副作用，不应传播 r11 的活跃性。
//
// 修复：扫描 dead 的 COPY(register = unique)；若该 unique 的所有存活消费者都是 flag op，
// 则将这些 flag op、该 unique 的生产 op 一并标 dead，并撤销其把 r11 加入 live 的操作。
static void rule_early_removal(std::vector<RawOp>& ops, std::set<VnKey>& live) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& dead_op : ops) {
            // 找 dead 的 COPY(register = unique) op
            if (!dead_op.dead || dead_op.opc != ghidra::CPUI_COPY) continue;
            if (!dead_op.has_out) continue;
            if (dead_op.out.space->getName() != "register") continue;
            if (dead_op.ins.empty() || dead_op.ins[0].space->getName() != "unique") continue;

            uint64_t uid = dead_op.ins[0].offset;

            // 检查该 unique 的所有存活消费者是否全是 flag op（size=1 寄存器写）
            bool found_alive_consumer = false;
            bool all_flag = true;
            for (auto& op2 : ops) {
                if (op2.dead) continue;
                for (auto& v : op2.ins) {
                    if (v.space->getName() == "unique" && v.offset == uid) {
                        found_alive_consumer = true;
                        if (!op2.has_out || !is_flag_varnode(op2.out))
                            all_flag = false;
                        break;
                    }
                }
                if (!all_flag) break;
            }

            if (!found_alive_consumer || !all_flag) continue;

            // 所有存活消费者都是 flag op —— 执行 EarlyRemoval
            // 1. 标记 flag 消费 op dead，撤销它们向 live 加入的 flag 寄存器
            for (auto& op2 : ops) {
                if (op2.dead) continue;
                bool reads_uid = false;
                for (auto& v : op2.ins) {
                    if (v.space->getName() == "unique" && v.offset == uid) {
                        reads_uid = true; break;
                    }
                }
                if (!reads_uid) continue;
                op2.dead = true;
                changed = true;
                if (op2.has_out) live.erase(to_key(op2.out));
            }

            // 2. 标记 unique 的生产 op dead，撤销其把寄存器加入 live 的操作
            for (auto& op2 : ops) {
                if (op2.dead || !op2.has_out) continue;
                if (op2.out.space->getName() != "unique" || op2.out.offset != uid) continue;

                op2.dead = true;
                changed = true;
                live.erase(to_key(op2.out)); // 撤销 u1 在 live 中的存在

                // 撤销该 op 的寄存器/unique 输入（如果无其他存活 op 依赖）
                for (auto& v : op2.ins) {
                    if (v.space->getName() == "const") continue;
                    VnKey vk = to_key(v);
                    bool still_needed = false;
                    for (auto& op3 : ops) {
                        if (op3.dead || &op3 == &op2) continue;
                        for (auto& v3 : op3.ins) {
                            if (vn_eq(to_key(v3), vk)) { still_needed = true; break; }
                        }
                        if (still_needed) break;
                    }
                    if (!still_needed) live.erase(vk);
                }
            }
        }
    }
}

void eliminate_dead_seg(std::vector<InsnPcode>& insns, int start_idx, int end_idx,
                        bool ignore_eflag) {
    std::set<VnKey> live;

    // handler 出口处所有 GPR 视为 live：
    // 去混淆前后必须保证所有通用寄存器一致，不论后续是否使用。
    // EFLAGS 各位不预设——只有被后续 live 指令读取的标志位才算活跃。
    static const uint64_t gpr_offsets[] = {
        0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, // rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi
        0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8  // r8-r15
    };
    for (auto off : gpr_offsets)
        live.insert({"register", off});

    for (int ii = end_idx; ii >= start_idx; --ii) {
        // Phase 1: 反向活跃性扫描
        for (int ji = (int)insns[ii].ops.size() - 1; ji >= 0; --ji) {
            RawOp& op = insns[ii].ops[ji];

            if (op.opc == ghidra::CPUI_CBRANCH) {
                if (ignore_eflag) {
                    // Unicorn trace 已确定路径，CBRANCH 退化为无条件跳转。
                    // 不传播 flag 输入——flag 的活跃性由其他 live 指令
                    // （adc/rcl/cmove/setcc 等）自然传播。
                    if (!op.ins.empty() && op.ins[0].space->getName() != "const")
                        live.insert(to_key(op.ins[0]));
                    continue;
                }
                // 不忽略时走通用 has_sideeffect 路径，所有输入（含 flag）加入 live
            }

            if (has_sideeffect(op.opc)) {
                for (auto& v : op.ins)
                    if (v.space->getName() != "const")
                        live.insert(to_key(v));
                continue;
            }

            if (!op.has_out) continue;

            const std::string& spc = op.out.space->getName();
            if (spc == "ram") {
                for (auto& v : op.ins)
                    if (v.space->getName() != "const")
                        live.insert(to_key(v));
                continue;
            }

            VnKey k = to_key(op.out);
            if (live.count(k)) {
                live.erase(k);
                for (auto& v : op.ins)
                    if (v.space->getName() != "const")
                        live.insert(to_key(v));
            } else {
                op.dead = true;
            }
        }

        // Phase 2: RuleVmpEarlyRemoval —— 清理 flag 副作用导致的假活跃
        rule_early_removal(insns[ii].ops, live);
    }
}

void eliminate_dead(std::vector<InsnPcode>& insns) {
    if (!insns.empty())
        eliminate_dead_seg(insns, 0, (int)insns.size() - 1);
}


