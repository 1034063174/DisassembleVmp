#pragma once
// vmp_analyzer.h — VMP handler 分析引擎公开接口（供 UI 使用）
// 内部逻辑与 pcode_demo/main.cpp 完全一致

#include <cstdint>
#include <string>
#include <vector>
#include "../ipc/ipc_client.h"

// 寄存器快照（UI 可见，不含 Unicorn/Sleigh 类型）
struct VmpRegCtx {
    bool     valid  = false;
    uint64_t rax=0, rbx=0, rcx=0, rdx=0;
    uint64_t rsi=0, rdi=0, rbp=0, rsp=0;
    uint64_t r8=0,  r9=0,  r10=0, r11=0;
    uint64_t r12=0, r13=0, r14=0, r15=0;
    uint64_t rflags=0;
};

// 栈槽（单条汇编行对应的栈快照条目）
struct VmpStackEntry {
    int64_t  offset;   // 距 RSP 的字节偏移（0 = RSP 处）
    uint64_t addr;
    uint64_t value;    // 读取失败时为 0
    bool     is_rsp;
};

// 轻量 varnode（不持有 Ghidra 指针）
struct VmpVarnode {
    std::string space;      // "register", "unique", "const", "ram"
    uint64_t    offset = 0;
    uint32_t    size   = 0;
    std::string reg_name;   // register 空间时填充寄存器名（如 "rax", "CF"），否则空
};

// Capstone x86 操作数（结构化）
struct VmpX86Operand {
    std::string type;         // "reg", "mem", "imm"
    std::string reg;          // type=="reg" 时的寄存器名
    int64_t     imm = 0;      // type=="imm" 时的立即数
    // type=="mem" 时的内存操作数分量
    std::string mem_base;     // 基址寄存器 ("RSP", "" 表示无)
    std::string mem_index;    // 变址寄存器 ("RCX", "" 表示无)
    int         mem_scale = 0;// 变址比例 (1/2/4/8)
    int64_t     mem_disp  = 0;// 位移
    int         size      = 0;// 操作数字节大小 (1/2/4/8)
};

// 轻量 PCode op（不持有 Ghidra 指针）
struct VmpPcodeOp {
    int         opc      = 0;   // ghidra::OpCode 数值
    std::string opc_name;       // "COPY", "INT_ADD", "STORE" 等
    bool        has_out  = false;
    VmpVarnode  out;
    std::vector<VmpVarnode> ins;
    bool        dead     = false;
};

// 单条汇编行（跨所有 handler 段展开）
struct VmpAsmRow {
    uint64_t    addr        = 0;
    int         seg_idx     = -1;   // 所属 handler 段
    int         global_idx  = -1;   // 在全局 insns[] 中的下标
    std::string asm_text;           // "mov rax, rbx"
    std::string bytes_str;          // "48 89 D8 "
    bool        is_junk     = false;// 所有 PCode op 均为 dead
    VmpRegCtx   regs;               // 该指令执行前的寄存器快照
    VmpRegCtx   regs_deobf;         // 同段内下一条 live 指令的寄存器（去混淆后对比用）
    bool        has_deobf   = false;
    std::vector<VmpStackEntry> stack;       // 执行前栈快照（RSP 上下各若干个 qword）
    std::vector<VmpStackEntry> stack_deobf; // 下一条 live 指令的栈快照（对比用）
    std::string analysis;           // 分析标注（由 vmp_annotate 填充）
    std::vector<VmpPcodeOp> pcode;  // 该指令的 PCode 操作列表
    std::string mnemonic;            // Capstone 助记符 ("mov", "push", "xor" 等)
    std::vector<VmpX86Operand> operands; // Capstone 结构化操作数
};

// 单个 handler 段的摘要
struct VmpHandlerSummary {
    int         seg_idx     = 0;
    std::string type;       // "vPushReg" / "vPopReg" / "vPushImm" / "unknown" / ...
    std::string detail;     // "(slot=0, r9)" / "(0xDEADBEEF)" / ""
    uint64_t    addr_start  = 0;
    uint64_t    addr_end    = 0;
    int         live_stores = 0;
    int         live_loads  = 0;
    std::vector<int> row_indices;  // 在 VmpAnalysisResult::rows[] 中的下标
    std::string summary;           // Lua 可写的简介文本（显示在 Handler简介 面板）
};

// 完整分析结果
struct VmpAnalysisResult {
    bool        ok    = false;
    std::string error;
    std::string vmCode_reg;   // "r11"
    std::string vmStack_reg;  // "rsi"
    uint64_t    vmRegBase = 0;
    int         total_insns  = 0;
    int         junk_insns   = 0;
    std::vector<VmpAsmRow>         rows;
    std::vector<VmpHandlerSummary> handlers;
    std::string dump_path;    // 落盘 JSON 路径，空表示未落盘
};

// 主入口：连接 x64dbg → Unicorn 仿真 → Sleigh PCode → 死代码消除 → handler 分类
VmpAnalysisResult vmp_analyze(IpcClient& ipc,
                               const std::string& sla_path,
                               int steps,
                               bool ignore_eflag = true);
