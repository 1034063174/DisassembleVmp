// ui_vmp.cpp — VMP分析 tab
#include "ui_main.h"
#include "../vmp/vmp_analyzer.h"
#include "../vmp/vmp_lua.h"
#include "imgui.h"
#include <cstdio>
#include <cstring>
#include <unordered_map>

// ── 颜色映射 ─────────────────────────────────────────────────────────────────

static ImVec4 handler_color(const std::string& t)
{
    // unknown → 红色
    if (t == "unknown")    return ImVec4(1.0f, 0.3f, 0.3f, 1);
    // vPushVSP → 黄色
    if (t == "vPushVSP")   return ImVec4(1.0f, 0.85f, 0.2f, 1);
    // vPush 系列（vPushReg, vPushImm64, vPushImm32, vPushImm16 等）→ 绿色
    if (t.rfind("vPush", 0) == 0) return ImVec4(0.4f, 0.9f, 0.4f, 1);
    // vPop → 白色
    if (t == "vPop")       return ImVec4(1.0f, 1.0f, 1.0f, 1);
    // vStore 系列 → 橙色
    if (t.rfind("vStore", 0) == 0) return ImVec4(1.0f, 0.5f, 0.2f, 1);
    // vLoad 系列 → 青色
    if (t.rfind("vLoad", 0) == 0) return ImVec4(0.3f, 0.85f, 0.9f, 1);
    // vExit → 红色偏亮
    if (t == "vExit")      return ImVec4(1.0f, 0.4f, 0.4f, 1);
    // 算术/逻辑 (vAdd, vSub, vAnd, vOr, vXor, vNot, vNeg, vShr, vShl, vOp 等) → 紫色
    if (t.rfind("v", 0) == 0) return ImVec4(0.9f, 0.5f, 0.9f, 1);
    // 默认灰色
    return ImVec4(0.65f, 0.65f, 0.65f, 1);
}

// ── 寄存器行渲染 ─────────────────────────────────────────────────────────────

static void reg_row(const char* name, uint64_t vbefore, uint64_t vafter,
                    bool has_deobf, int ei)
{
    bool differ = has_deobf && (vbefore != vafter);

    ImGui::TableNextRow();
    if (differ)
        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, IM_COL32(120,20,20,200));

    char sb[24], sa[24];
    snprintf(sb, sizeof(sb), "%016llX", (unsigned long long)vbefore);
    snprintf(sa, sizeof(sa), "%016llX", (unsigned long long)vafter);

    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(name);

    ImGui::TableSetColumnIndex(1);
    {
        char pid[32]; snprintf(pid, sizeof(pid), "##vb%d", ei);
        ImGui::TextUnformatted(sb);
        if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
            ImGui::OpenPopup(pid);
        if (ImGui::BeginPopup(pid)) {
            if (ImGui::MenuItem("复制")) ImGui::SetClipboardText(sb);
            ImGui::EndPopup();
        }
    }

    if (has_deobf) {
        ImGui::TableSetColumnIndex(2);
        char pid[32]; snprintf(pid, sizeof(pid), "##va%d", ei);
        ImGui::TextColored(differ ? ImVec4(1,0.3f,0.3f,1) : ImVec4(0.3f,0.9f,0.3f,1),
                           "%s", sa);
        if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
            ImGui::OpenPopup(pid);
        if (ImGui::BeginPopup(pid)) {
            if (ImGui::MenuItem("复制")) ImGui::SetClipboardText(sa);
            ImGui::EndPopup();
        }
    }
}

// jmp 固定地址判断：asm 以 "jmp" 开头且操作数首字符为数字或 '-'（立即数/绝对地址）
// "jmp      0x7FF6..."  → true（隐藏）
// "jmp      rax"        → false（保留）
static bool is_jmp_imm(const std::string& asm_text) {
    const char* p = asm_text.c_str();
    if (p[0]!='j'||p[1]!='m'||p[2]!='p') return false;
    // 跳过 "jmp" 后的空格
    p += 3;
    while (*p == ' ' || *p == '\t') ++p;
    // 操作数以数字或 '-' 开头 → 固定地址；以字母开头 → 寄存器/符号
    return (*p >= '0' && *p <= '9') || *p == '-';
}

// ── Lua 说明文档（单一数据源）──────────────────────────────────────────────
// 行首标记: # 标题 | @name\ttype\tdesc 字段 | // 注释 | > 代码 | $ 蓝段头 | ^ 橙段头 | (空)间距
static const char* const lua_doc[] = {
    "#全局变量",
    "@vmCode_reg\tstring\tvmCode 寄存器名",
    "@vmStack_reg\tstring\tvmStack 寄存器名",
    "@vmRegBase\tinteger\tvmRegFile 基址",
    "@total_insns\tinteger\t总指令数",
    "@junk_insns\tinteger\t垃圾指令数",
    "",
    "#全局函数",
    "@log(...)\tvoid\t输出到日志面板 (支持 string/number/boolean/nil, 多参数)",
    "//前缀 \"[error]\" 红色, \"[warn]\" 黄色, \"[ok]\" 绿色",
    "@read_mem(addr,size)\tstring\t从 x64dbg 读内存, 返回 hex 或 nil (size<=65536)",
    "@read_u64(addr)\tinteger\t读 8 字节小端, 返回 integer 或 nil",
    "",
    "#rows[]  每条指令 (1-based)",
    "@.addr\tinteger\t地址",
    "@.seg_idx\tinteger\t所属 handler 段索引 (1-based)",
    "@.step\tinteger\t全局步数",
    "@.asm\tstring\t汇编文本",
    "@.bytes\tstring\t字节码十六进制",
    "@.is_junk\tboolean\t是否垃圾指令 (writeback 可写)",
    "@.has_deobf\tboolean\t是否有去混淆对比",
    "@.analysis\tstring\t分析标注 (默认可写)",
    "",
    "#rows[].mnemonic / .operands[]  Capstone 结构化操作数",
    "//Capstone 将汇编指令拆成 助记符 + 操作数列表, 方便结构化匹配",
    "//例: \"mov r11, qword ptr [rsp+0x90]\"",
    "//  mnemonic = \"mov\"",
    "//  operands[1] = {type=\"reg\", reg=\"r11\", size=8}           -- 目标",
    "//  operands[2] = {type=\"mem\", mem_base=\"rsp\", mem_disp=144, size=8} -- 源",
    "",
    "@.mnemonic\tstring\t助记符 (\"mov\", \"push\", \"xor\", \"lea\" 等)",
    "@.operands[]\ttable\t操作数列表 (1-based, 顺序同汇编: [1]=目标, [2]=源)",
    "@  .type\tstring\t\"reg\" / \"mem\" / \"imm\"",
    "@  .size\tinteger\t字节大小 (1=byte, 2=word, 4=dword, 8=qword)",
    "",
    "$    type=\"reg\" -- 寄存器操作数",
    "//  例: push rax -> {type=\"reg\", reg=\"rax\", size=8}",
    "@    .reg\tstring\t寄存器名, 小写 (\"rax\", \"r11\", \"rsp\", \"eax\", \"al\")",
    "",
    "$    type=\"imm\" -- 立即数操作数",
    "//  例: push 0x1234 -> {type=\"imm\", imm=0x1234, size=8}",
    "@    .imm\tinteger\t立即数值 (十进制, string.format(\"0x%X\", op.imm) 转十六进制)",
    "",
    "$    type=\"mem\" -- 内存操作数",
    "//  地址公式: [mem_base + mem_index * mem_scale + mem_disp]",
    "//  例: [rsp+0x90]   -> mem_base=\"rsp\", mem_index=\"\", mem_scale=1, mem_disp=144",
    "//  例: [rax+rcx*8]  -> mem_base=\"rax\", mem_index=\"rcx\", mem_scale=8, mem_disp=0",
    "//  例: [rip+0x1234] -> mem_base=\"rip\", mem_index=\"\", mem_scale=1, mem_disp=0x1234",
    "//  例: [0x7FF60000] -> mem_base=\"\",    mem_index=\"\", mem_scale=1, mem_disp=0x7FF60000",
    "@    .mem_base\tstring\t基址寄存器 (\"rsp\"/\"rax\"/..., 无则空串)",
    "@    .mem_index\tstring\t变址寄存器 (\"rcx\"/\"rdx\"/..., 无则空串)",
    "@    .mem_scale\tinteger\t变址比例 (1/2/4/8), 无 index 时为 1",
    "@    .mem_disp\tinteger\t位移值 (十进制, 0x90 显示为 144)",
    "",
    "#rows[].regs / .stack  运行时快照",
    "$  .regs / .regs_deobf  寄存器快照 (table)",
    "//.rax .rbx .rcx .rdx .rsi .rdi .rbp .rsp  (integer)",
    "//.r8 .r9 .r10 .r11 .r12 .r13 .r14 .r15    (integer)",
    "//.rflags (integer)  .valid (boolean)",
    "//.regs_deobf: 去混淆后, has_deobf=true 时存在, 字段同 .regs",
    "",
    "$  .stack[] / .stack_deobf[]  栈快照 (table)",
    "@  .offset\tinteger\t相对 RSP 偏移",
    "@  .addr\tinteger\t绝对地址",
    "@  .value\tinteger\t内存值",
    "@  .is_rsp\tboolean\t是否 RSP 指向的槽",
    "",
    "#rows[].pcode[]  Sleigh PCode 语义操作",
    "//Sleigh 将一条 x86 指令拆成多个原子操作 (PCode), 用于语义分析",
    "//例: mov r11,[rsp+0x90] 拆成: INT_ADD tmp=RSP+0x90 -> LOAD tmp2=[tmp] -> COPY R11=tmp2",
    "",
    "@.pcode[]\ttable\tPCode 操作列表 (1-based)",
    "@  .opc\tinteger\t操作码编号",
    "@  .opc_name\tstring\t操作码名 (见下方 PCode 操作码表)",
    "@  .dead\tboolean\t是否被死代码消除",
    "@  .has_out\tboolean\t是否有输出 varnode",
    "@  .out\ttable\t输出 varnode {space, offset, size, reg_name}",
    "@  .ins[]\ttable\t输入 varnode 列表 (字段同 .out)",
    "",
    "$  varnode 字段说明:",
    "@  .space\tstring\t地址空间 (见下)",
    "@  .offset\tinteger\t偏移量 (space=const 时即为常量值)",
    "@  .size\tinteger\t字节大小",
    "@  .reg_name\tstring\t寄存器名 (space=register 时有效)",
    "",
    "$  space 地址空间:",
    "//  \"register\" -- CPU 寄存器 (RAX/RBX/RSP...), reg_name 有效",
    "//  \"const\"    -- 立即数/常量, offset 就是常量值本身 (如 0x90)",
    "//  \"unique\"   -- Sleigh 临时变量, 仅在同一条指令的 PCode 之间传值",
    "//  \"ram\"      -- 内存地址空间, LOAD/STORE 的第一个 input 标识读写空间",
    "",
    "#PCode 操作码表 (opc_name)",
    "",
    "$  控制流:",
    "@  COPY\t\tdst = src  寄存器赋值/传值",
    "@  BRANCH\t\t无条件跳转到常量地址",
    "@  CBRANCH\t\t条件跳转: if(cond) goto addr",
    "@  BRANCHIND\t\t间接跳转: goto [reg]  (VMP handler 分发标志)",
    "@  CALL\t\t直接调用",
    "@  CALLIND\t\t间接调用: call [reg]",
    "@  CALLOTHER\t\t特殊指令 (CPUID/RDTSC 等)",
    "@  RETURN\t\t函数返回",
    "",
    "$  内存:",
    "@  LOAD\t\t从内存读: dst = [addr]  (x86 的 mov reg,[...])",
    "@  STORE\t\t写入内存: [addr] = val  (x86 的 mov [...],reg)",
    "",
    "$  算术:",
    "@  INT_ADD\t\t加法: a + b  (也用于地址计算 RSP+offset)",
    "@  INT_SUB\t\t减法: a - b",
    "@  INT_MULT\t\t无符号乘法",
    "@  INT_DIV\t\t无符号除法",
    "@  INT_SDIV\t\t有符号除法",
    "@  INT_REM\t\t无符号取余",
    "@  INT_SREM\t\t有符号取余",
    "",
    "$  位运算:",
    "@  INT_AND\t\t按位与: a & b",
    "@  INT_OR\t\t按位或: a | b",
    "@  INT_XOR\t\t按位异或: a ^ b",
    "@  INT_NEGATE\t\t按位取反: ~a",
    "@  INT_2COMP\t\t补码取反: -a (二进制补码)",
    "",
    "$  移位:",
    "@  INT_LEFT\t\t逻辑左移: a << b",
    "@  INT_RIGHT\t\t逻辑右移: a >> b (无符号)",
    "@  INT_SRIGHT\t\t算术右移: a >> b (有符号, 保留符号位)",
    "",
    "$  比较:",
    "@  INT_EQUAL\t\t相等: a == b  -> bool",
    "@  INT_NOTEQUAL\t\t不等: a != b  -> bool",
    "@  INT_LESS\t\t无符号小于: a < b  -> bool",
    "@  INT_SLESS\t\t有符号小于",
    "@  INT_LESSEQUAL\t\t无符号小于等于",
    "@  INT_SLESSEQUAL\t\t有符号小于等于",
    "",
    "$  进位/借位:",
    "@  INT_CARRY\t\t无符号加法进位: carry(a+b)  -> bool",
    "@  INT_SCARRY\t\t有符号加法溢出: overflow(a+b)  -> bool",
    "@  INT_SBORROW\t\t有符号减法借位: borrow(a-b)  -> bool",
    "",
    "$  扩展:",
    "@  INT_ZEXT\t\t零扩展: 4字节->8字节, 高位补0",
    "@  INT_SEXT\t\t符号扩展: 4字节->8字节, 高位补符号位",
    "",
    "$  布尔:",
    "@  BOOL_AND\t\t布尔与: a && b  (1-bit)",
    "@  BOOL_OR\t\t布尔或: a || b",
    "@  BOOL_XOR\t\t布尔异或",
    "@  BOOL_NEGATE\t\t布尔取反: !a",
    "",
    "$  拼接/其他:",
    "@  PIECE\t\t拼接: hi:lo -> 合并为更大值",
    "@  SUBPIECE\t\t截取: 从大值中取出子段 (类似强转)",
    "@  POPCOUNT\t\t统计 1 的位数 (popcnt)",
    "@  LZCOUNT\t\t前导零计数 (lzcnt)",
    "",
    "#handlers[]  handler 段列表 (1-based)",
    "@.type\tstring\tvPushReg/vPopReg/vPushImm/vReadMem/vWriteMem/vLogicalOp/vExit/unknown",
    "@.detail\tstring\t细节 (寄存器名/立即数值)",
    "@.seg_idx\tinteger\t段索引",
    "@.addr_start\tinteger\t起始地址",
    "@.addr_end\tinteger\t结束地址",
    "@.live_stores\tinteger\t活跃 STORE 数",
    "@.live_loads\tinteger\t活跃 LOAD 数",
    "@.row_indices[]\ttable\t行下标 (1-based, 对应 rows 索引)",
    "@.summary\tstring\t简介文本 (writeback 可写, 显示在左下角 Handler简介 面板)",
    "",
    "#writeback 回写机制",
    ">writeback = {\"analysis\", \"is_junk\", \"summary\"}",
    "//不声明 writeback 则默认只回写 analysis",
    "//支持的字段: analysis(string)  is_junk(boolean)  summary(string)",
    "//summary 写入 handlers[].summary, 显示在左下角 Handler简介 面板",
    "//回写后 is_junk 会影响 NOP混淆 按钮的行为",
    "",
    "#Demo 1: 标注 LOAD/STORE",
    ">for i, row in ipairs(rows) do",
    ">    if row.is_junk then goto skip end",
    ">    for _, op in ipairs(row.pcode) do",
    ">        if not op.dead and op.opc_name == \"LOAD\" and op.has_out then",
    ">            row.analysis = \"LOAD->\" .. op.out.reg_name",
    ">            log(string.format(\"step %d: LOAD -> %s\", row.step, op.out.reg_name))",
    ">        end",
    ">        if not op.dead and op.opc_name == \"STORE\" then",
    ">            row.analysis = \"STORE\"",
    ">        end",
    ">    end",
    ">    ::skip::",
    ">end",
    "",
    "#Demo 2: 读内存",
    ">local val = read_u64(rows[1].regs.rsp)",
    ">if val then log(string.format(\"栈顶: 0x%X\", val)) end",
    "",
    ">local hex = read_mem(0x7FF6A0001000, 32)",
    ">if hex then log(\"hex: \" .. hex) end",
    "",
    "#Demo 3: 修改 is_junk 并回写",
    ">writeback = {\"analysis\", \"is_junk\"}",
    ">for i, row in ipairs(rows) do",
    ">    if row.step > 500 then",
    ">        row.is_junk = true",
    ">        row.analysis = \"marked_junk\"",
    ">    end",
    ">end",
    "",
    "#Demo 4: 打印 handler 摘要",
    ">for i, h in ipairs(handlers) do",
    ">    log(string.format(\"[%d] %s %s  insns=%d stores=%d loads=%d\",",
    ">        i, h.type, h.detail, #h.row_indices, h.live_stores, h.live_loads))",
    ">end",
    "",
    "#Demo 5: 打印栈快照",
    ">local row = rows[1]",
    ">for _, s in ipairs(row.stack) do",
    ">    local mark = s.is_rsp and \" <-- RSP\" or \"\"",
    ">    log(string.format(\"  [%+d] 0x%X = 0x%X%s\",",
    ">        s.offset, s.addr, s.value, mark))",
    ">end",
    "",
    "#Demo 6: 写入 Handler简介",
    ">writeback = {\"summary\"}",
    ">for i, h in ipairs(handlers) do",
    ">    h.summary = string.format(\"%s %s  %d条指令\", h.type, h.detail, #h.row_indices)",
    ">end",
    "",
    "#Demo 7: 查找 mov reg, [rsp+0x90]  (Capstone 操作数匹配)",
    ">for i, row in ipairs(rows) do",
    ">    if row.mnemonic == \"mov\" and #row.operands == 2 then",
    ">        local dst = row.operands[1]",
    ">        local src = row.operands[2]",
    ">        if dst.type == \"reg\"",
    ">           and src.type == \"mem\"",
    ">           and src.mem_base == \"rsp\"",
    ">           and src.mem_index == \"\"",
    ">           and src.mem_disp == 0x90 then",
    ">            log(string.format(\"step %d: %s -> %s\", row.step, row.asm, dst.reg))",
    ">        end",
    ">    end",
    ">end",
    nullptr
};

static std::string lua_doc_text()
{
    std::string out;
    for (int i = 0; lua_doc[i]; ++i) {
        const char* ln = lua_doc[i];
        if (!ln[0]) { out += '\n'; continue; }
        switch (ln[0]) {
        case '#': out += "=== "; out += (ln+1); out += " ===\n"; break;
        case '@': {
            const char* p=ln+1, *t1=strchr(p,'\t'), *t2=t1?strchr(t1+1,'\t'):nullptr;
            if (t1&&t2) {
                char nb[64]={},tb[32]={};
                int nl=(int)(t1-p); if(nl>63)nl=63; memcpy(nb,p,nl);
                int tl=(int)(t2-t1-1); if(tl>31)tl=31; memcpy(tb,t1+1,tl);
                char buf[512];
                if (tb[0]) snprintf(buf,sizeof(buf),"%-16s %-10s %s\n",nb,tb,t2+1);
                else       snprintf(buf,sizeof(buf),"%-16s %s\n",nb,t2+1);
                out += buf;
            }
            break;
        }
        case '/': out += (ln+2); out += '\n'; break;
        case '>': out += (ln+1); out += '\n'; break;
        case '$': case '^': out += (ln+1); out += '\n'; break;
        }
    }
    return out;
}

static void lua_doc_render()
{
    for (int i = 0; lua_doc[i]; ++i) {
        const char* ln = lua_doc[i];
        if (!ln[0]) { ImGui::Spacing(); continue; }
        switch (ln[0]) {
        case '#':
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(1.0f,0.85f,0.3f,1), "%s", ln+1);
            ImGui::Separator();
            break;
        case '@': {
            const char* p=ln+1, *t1=strchr(p,'\t'), *t2=t1?strchr(t1+1,'\t'):nullptr;
            if (t1&&t2) {
                char nb[64]={},tb[32]={};
                int nl=(int)(t1-p); if(nl>63)nl=63; memcpy(nb,p,nl);
                int tl=(int)(t2-t1-1); if(tl>31)tl=31; memcpy(tb,t1+1,tl);
                ImGui::TextColored(ImVec4(0.4f,0.9f,1.0f,1), "  %-16s", nb);
                ImGui::SameLine(0,0);
                ImGui::TextColored(ImVec4(0.5f,0.8f,0.5f,1), "%-10s", tb);
                ImGui::SameLine(0,0);
                ImGui::TextDisabled("%s", t2+1);
            }
            break;
        }
        case '/':
            ImGui::TextColored(ImVec4(0.5f,0.5f,0.5f,1), "  %s", ln+2);
            break;
        case '>':
            ImGui::TextColored(ImVec4(0.8f,0.8f,0.8f,1), "  %s", ln+1);
            break;
        case '$':
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.6f,0.6f,0.9f,1), "%s", ln+1);
            break;
        case '^':
            ImGui::Spacing();
            ImGui::TextColored(ImVec4(0.9f,0.7f,0.4f,1), "%s", ln+1);
            break;
        }
    }
    ImGui::Spacing();
}

void UiMain::renderVmpTab()
{
    // ═══ 工具栏 ══════════════════════════════════════════════════════════════
    ImGui::SetNextItemWidth(80);
    ImGui::InputInt("步数##vmps", &vmp_step_count_, 0, 0);
    if (vmp_step_count_ < 100)    vmp_step_count_ = 100;
    if (vmp_step_count_ > 100000) vmp_step_count_ = 100000;
    ImGui::SameLine();

    ImGui::Checkbox("忽略eflag##vmpeflag", &vmp_ignore_eflag_);
    ImGui::SameLine();

    if (ImGui::Button("解析", ImVec2(80, 0))) {
        vmp_status_            = "正在分析...";
        vmp_selected_handler_  = -1;
        vmp_selected_row_      = -1;
        vmp_result_            = vmp_analyze(ipc_, std::string(vmp_sla_buf_), vmp_step_count_, vmp_ignore_eflag_);
        if (vmp_result_.ok) {
            char buf[160];
            snprintf(buf, sizeof(buf),
                     "完成: %d 条指令 / %d 个 handler / %d 条垃圾  [vmCode=%s vmStack=%s]",
                     vmp_result_.total_insns,
                     (int)vmp_result_.handlers.size(),
                     vmp_result_.junk_insns,
                     vmp_result_.vmCode_reg.c_str(),
                     vmp_result_.vmStack_reg.c_str());
            vmp_status_ = buf;
        } else {
            vmp_status_ = "错误: " + vmp_result_.error;
        }
    }

    ImGui::SameLine();
    ImGui::Checkbox("隐藏垃圾##vmphide", &vmp_hide_junk_);
    ImGui::SameLine();
    ImGui::Checkbox("隐藏jmp固址##vmphidejmp", &vmp_hide_jmp_imm_);

    // NOP混淆 按钮：弹确认框后才执行
    ImGui::SameLine();
    {
        int junk_cnt = 0;
        for (auto& h : vmp_result_.handlers)
            for (auto& ri : h.row_indices) {
                if (ri >= 0 && ri < (int)vmp_result_.rows.size() && vmp_result_.rows[ri].is_junk)
                    junk_cnt++;
            }
        if (!vmp_result_.ok || junk_cnt == 0) ImGui::BeginDisabled();
        char nop_label[64];
        snprintf(nop_label, sizeof(nop_label), "NOP混淆(%d)##vmpnop", junk_cnt);
        if (ImGui::Button(nop_label, ImVec2(130, 0)))
            ImGui::OpenPopup("##vmp_nop_confirm");
        if (!vmp_result_.ok || junk_cnt == 0) ImGui::EndDisabled();

        if (ImGui::BeginPopupModal("##vmp_nop_confirm", nullptr,
                ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoTitleBar))
        {
            ImGui::Text("确定要 NOP 掉 %d 条垃圾指令吗？", junk_cnt);
            ImGui::Text("此操作会直接修改 x64dbg 中的内存。");
            ImGui::Separator();
            if (ImGui::Button("确定", ImVec2(100, 0))) {
                nlohmann::json arr = nlohmann::json::array();
                for (auto& row : vmp_result_.rows) {
                    if (!row.is_junk) continue;
                    char buf[32];
                    snprintf(buf, sizeof(buf), "%llX", (unsigned long long)row.addr);
                    int sz = 0;
                    for (size_t k = 0; k < row.bytes_str.size(); ++k)
                        if (row.bytes_str[k] == ' ') sz++;
                    if (sz == 0) sz = 1;
                    arr.push_back({{"addr", buf}, {"size", sz}});
                }
                auto nr = ipc_.send("nop_addresses", {{"addresses", arr}});
                if (nr.value("status","") == "ok") {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "NOP'd %d 条垃圾指令",
                             nr["data"].value("patched", 0));
                    vmp_status_ = msg;
                } else {
                    vmp_status_ = "NOP 失败: " + nr["error"].value("message", "unknown");
                }
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("取消", ImVec2(100, 0)))
                ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
    }

    // Lua 脚本按钮（5个可配置槽位）
    for (int si = 0; si < LUA_SLOT_COUNT; ++si) {
        auto& slot = vmp_lua_slots_[si];
        ImGui::SameLine();

        const char* display_name = (slot.name[0] != '\0') ? slot.name : "(空)";
        if (!vmp_result_.ok) ImGui::BeginDisabled();
        char btn_id[96];
        snprintf(btn_id, sizeof(btn_id), "%s##luaslot%d", display_name, si);
        if (ImGui::Button(btn_id)) {
            if (slot.path[0] != '\0') {
                vmp_lua_log_.clear();
                vmp_lua_log_scroll_ = true;
                auto err = vmp_run_lua(std::string(slot.path), vmp_result_, ipc_,
                    [this](const std::string& msg) { vmp_lua_log_.push_back(msg); });
                if (err.empty())
                    vmp_lua_log_.push_back("[ok]");
                else
                    vmp_lua_log_.push_back("[error] " + err);
            }
        }
        if (!vmp_result_.ok) ImGui::EndDisabled();

        char ctx_id[96];
        snprintf(ctx_id, sizeof(ctx_id), "##luactx%d", si);
        if (ImGui::BeginPopupContextItem(ctx_id)) {
            ImGui::Text("Lua #%d", si + 1);
            ImGui::Separator();
            ImGui::SetNextItemWidth(120);
            ImGui::InputText("名称##sn", slot.name, sizeof(slot.name));
            ImGui::SetNextItemWidth(300);
            ImGui::InputText("脚本##sp", slot.path, sizeof(slot.path));
            if (ImGui::Button("确定##sok", ImVec2(80, 0)))
                ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
    }

    // Lua 说明按钮
    ImGui::SameLine();
    if (ImGui::Button("Lua说明"))
        ImGui::OpenPopup("Lua说明##lua_help_popup");
    ImGui::SetNextWindowSize(ImVec2(750, 600), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("Lua说明##lua_help_popup", nullptr, 0)) {

        if (ImGui::Button("复制全部", ImVec2(100, 0))) {
            std::string txt = lua_doc_text();
            ImGui::SetClipboardText(txt.c_str());
        }
        ImGui::SameLine();
        if (ImGui::Button("关闭", ImVec2(100, 0)))
            ImGui::CloseCurrentPopup();
        ImGui::Separator();

        if (ImGui::BeginChild("##lua_help_scroll", ImVec2(0, 0), false)) {
            lua_doc_render();
        }
        ImGui::EndChild();
        ImGui::EndPopup();
    }

    // 状态栏
    if (vmp_result_.ok)
        ImGui::TextColored(ImVec4(0.3f,0.8f,0.3f,1), "%s", vmp_status_.c_str());
    else if (!vmp_result_.error.empty())
        ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "%s", vmp_status_.c_str());
    else
        ImGui::TextDisabled("%s", vmp_status_.c_str());

    ImGui::Separator();

    if (!vmp_result_.ok && vmp_result_.error.empty()) {
        ImGui::TextDisabled("点击「解析」按钮，工具将读取 x64dbg 当前 RIP，");
        ImGui::TextDisabled("通过 Unicorn 仿真追踪所有 handler，并显示在此处。");
        return;
    }
    if (!vmp_result_.ok) return;

    // ═══ 主体布局 ════════════════════════════════════════════════════════════
    float body_w = ImGui::GetContentRegionAvail().x;
    float body_h = ImGui::GetContentRegionAvail().y;
    float left_w = body_w * 0.22f;
    float summary_h = 300.0f;

    // ── 左侧总容器 ────────────────────────────────────────────────────────────
    if (ImGui::BeginChild("##vmp_left", ImVec2(left_w, 0), false)) {

        // ── 左上：Handler 列表 ────────────────────────────────────────────────
        float left_avail = ImGui::GetContentRegionAvail().y;
        if (ImGui::BeginChild("##vmp_handlers", ImVec2(0, left_avail - summary_h - ImGui::GetStyle().ItemSpacing.y), true)) {
            ImGui::Text("Handlers  (%d)", (int)vmp_result_.handlers.size());
            ImGui::Separator();

            for (int hi = 0; hi < (int)vmp_result_.handlers.size(); ++hi) {
                auto& h = vmp_result_.handlers[hi];
                char label[256];
                snprintf(label, sizeof(label), "[%d] %s %s##hitem%d",
                         hi, h.type.c_str(), h.detail.c_str(), hi);

                bool sel = (vmp_selected_handler_ == hi);
                ImGui::PushStyleColor(ImGuiCol_Text, handler_color(h.type));
                if (ImGui::Selectable(label, sel)) {
                    vmp_selected_handler_ = hi;
                    if (!h.row_indices.empty())
                        vmp_selected_row_ = h.row_indices[0];
                    else
                        vmp_selected_row_ = -1;
                }
                ImGui::PopStyleColor();

                if (ImGui::IsItemHovered()) {
                    ImGui::BeginTooltip();
                    ImGui::Text("seg #%d", h.seg_idx);
                    ImGui::Text("0x%llX – 0x%llX",
                                (unsigned long long)h.addr_start,
                                (unsigned long long)h.addr_end);
                    ImGui::Text("%d 条指令  live STORE=%d  LOAD=%d",
                                (int)h.row_indices.size(),
                                h.live_stores, h.live_loads);
                    ImGui::EndTooltip();
                }
            }
        }
        ImGui::EndChild();

        // ── 左下：Handler简介 ─────────────────────────────────────────────────
        if (ImGui::BeginChild("##vmp_handler_summary", ImVec2(0, 0), true)) {
            if (vmp_selected_handler_ < 0 ||
                vmp_selected_handler_ >= (int)vmp_result_.handlers.size()) {
                ImGui::TextDisabled("Handler简介");
            } else {
                auto& h = vmp_result_.handlers[vmp_selected_handler_];
                ImGui::PushStyleColor(ImGuiCol_Text, handler_color(h.type));
                ImGui::Text("[%d] %s %s", vmp_selected_handler_,
                            h.type.c_str(), h.detail.c_str());
                ImGui::PopStyleColor();
                ImGui::Separator();
                if (h.summary.empty()) {
                    ImGui::TextDisabled("(Lua: handlers[i].summary)");
                } else {
                    ImGui::TextWrapped("%s", h.summary.c_str());
                }
            }
        }
        ImGui::EndChild();
    }
    ImGui::EndChild(); // ##vmp_left

    ImGui::SameLine();

    // ── 右侧总容器 ────────────────────────────────────────────────────────────
    if (!ImGui::BeginChild("##vmp_right", ImVec2(0, 0), false)) {
        ImGui::EndChild();
        return;
    }

    float rh = ImGui::GetContentRegionAvail().y;
    float rw = ImGui::GetContentRegionAvail().x;

    // ── 右上：指令表 + 寄存器面板 ────────────────────────────────────────────
    if (ImGui::BeginChild("##vmp_top", ImVec2(0, rh * 0.55f), false)) {
        float tw = ImGui::GetContentRegionAvail().x;
        float reg_w = 335.0f;
        float asm_w = tw - reg_w - ImGui::GetStyle().ItemSpacing.x;
        if (asm_w < 200.0f) asm_w = 200.0f;

        // 指令表
        if (ImGui::BeginChild("##vmp_asm", ImVec2(asm_w, 0), true)) {
            if (vmp_selected_handler_ < 0) {
                ImGui::TextDisabled("← 从左侧选择一个 Handler");
            } else {
                auto& h = vmp_result_.handlers[vmp_selected_handler_];

                int seg_junk = 0;
                for (int ri : h.row_indices)
                    if (vmp_result_.rows[ri].is_junk) ++seg_junk;

                ImGui::PushStyleColor(ImGuiCol_Text, handler_color(h.type));
                ImGui::Text("[%d] %s %s", vmp_selected_handler_,
                            h.type.c_str(), h.detail.c_str());
                ImGui::PopStyleColor();
                ImGui::SameLine();
                ImGui::TextDisabled("(%d 条, %d 垃圾)", (int)h.row_indices.size(), seg_junk);
                ImGui::Separator();

                if (ImGui::BeginTable("##vmp_insn_tbl", 6,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                    ImGuiTableFlags_SizingStretchProp))
                {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("步",   ImGuiTableColumnFlags_WidthFixed,   40);
                    ImGui::TableSetupColumn("地址", ImGuiTableColumnFlags_WidthFixed,  140);
                    ImGui::TableSetupColumn("字节", ImGuiTableColumnFlags_WidthFixed,  110);
                    ImGui::TableSetupColumn("指令", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("状态", ImGuiTableColumnFlags_WidthFixed,   45);
                    ImGui::TableSetupColumn("分析", ImGuiTableColumnFlags_WidthFixed,  120);
                    ImGui::TableHeadersRow();

                    for (int ri : h.row_indices) {
                        const auto& row = vmp_result_.rows[ri];
                        if (vmp_hide_junk_ && row.is_junk) continue;
                        if (vmp_hide_jmp_imm_ && is_jmp_imm(row.asm_text)) continue;

                        ImGui::TableNextRow();

                        bool sel = (vmp_selected_row_ == ri);
                        if (sel)
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                                                   IM_COL32(60,100,180,200));
                        else if (row.is_junk)
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                                                   IM_COL32(100,20,20,180));

                        char addr_s[24];
                        snprintf(addr_s, sizeof(addr_s), "0x%llX",
                                 (unsigned long long)row.addr);

                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%d", row.global_idx);

                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextUnformatted(addr_s);

                        ImGui::TableSetColumnIndex(2);
                        ImGui::TextDisabled("%s", row.bytes_str.c_str());

                        ImGui::TableSetColumnIndex(3);
                        char sel_id[256];
                        snprintf(sel_id, sizeof(sel_id), "%s##ar%d",
                                 row.asm_text.c_str(), ri);
                        if (ImGui::Selectable(sel_id, sel,
                                ImGuiSelectableFlags_SpanAllColumns))
                            vmp_selected_row_ = ri;

                        if (ImGui::BeginPopupContextItem()) {
                            if (ImGui::MenuItem("复制地址"))
                                ImGui::SetClipboardText(addr_s);
                            if (ImGui::MenuItem("复制指令"))
                                ImGui::SetClipboardText(row.asm_text.c_str());
                            if (ImGui::MenuItem("执行 Lua")) {
                                auto err = vmp_run_lua("scripts\\mouse.lua", vmp_result_, ipc_,
                                    [this](const std::string& s){ vmp_lua_log_.push_back(s); }, ri);
                                if (!err.empty())
                                    vmp_lua_log_.push_back("[error] " + err);
                            }
                            ImGui::EndPopup();
                        }

                        ImGui::TableSetColumnIndex(4);
                        if (row.is_junk)
                            ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "垃圾");
                        else
                            ImGui::TextColored(ImVec4(0.3f,1,0.3f,1), "正常");

                        ImGui::TableSetColumnIndex(5);
                        if (!row.analysis.empty())
                            ImGui::TextUnformatted(row.analysis.c_str());
                    }
                    ImGui::EndTable();
                }
            }
        }
        ImGui::EndChild();

        ImGui::SameLine();

        // 寄存器面板（始终显示对比）
        if (ImGui::BeginChild("##vmp_reg", ImVec2(0, 0), true)) {
            if (vmp_selected_row_ < 0 ||
                vmp_selected_row_ >= (int)vmp_result_.rows.size()) {
                ImGui::TextDisabled("点击指令行查看寄存器");
            } else {
                const auto& row = vmp_result_.rows[vmp_selected_row_];
                char addr_h[24];
                snprintf(addr_h, sizeof(addr_h), "0x%llX", (unsigned long long)row.addr);
                ImGui::Text("[%s]", addr_h);
                ImGui::SameLine();
                if (row.is_junk)
                    ImGui::TextColored(ImVec4(1,0.4f,0.4f,1), "%s  [垃圾]",
                                       row.asm_text.c_str());
                else
                    ImGui::TextUnformatted(row.asm_text.c_str());
                ImGui::Separator();

                if (!row.regs.valid) {
                    ImGui::TextDisabled("无寄存器数据");
                } else {
                    bool has_d = row.has_deobf;
                    int  ncols = has_d ? 3 : 2;

                    if (ImGui::BeginTable("##vmp_reg_tbl", ncols,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit))
                    {
                        ImGui::TableSetupScrollFreeze(0, 1);
                        ImGui::TableSetupColumn("寄存器",  ImGuiTableColumnFlags_WidthFixed, 58);
                        ImGui::TableSetupColumn("执行前",  ImGuiTableColumnFlags_WidthStretch);
                        if (has_d)
                            ImGui::TableSetupColumn("去混淆后", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();

                        struct E { const char* n; uint64_t b, a; };
                        const E entries[] = {
                            {"RAX",    row.regs.rax,    row.regs_deobf.rax},
                            {"RBX",    row.regs.rbx,    row.regs_deobf.rbx},
                            {"RCX",    row.regs.rcx,    row.regs_deobf.rcx},
                            {"RDX",    row.regs.rdx,    row.regs_deobf.rdx},
                            {"RSI",    row.regs.rsi,    row.regs_deobf.rsi},
                            {"RDI",    row.regs.rdi,    row.regs_deobf.rdi},
                            {"RBP",    row.regs.rbp,    row.regs_deobf.rbp},
                            {"RSP",    row.regs.rsp,    row.regs_deobf.rsp},
                            {"R8",     row.regs.r8,     row.regs_deobf.r8},
                            {"R9",     row.regs.r9,     row.regs_deobf.r9},
                            {"R10",    row.regs.r10,    row.regs_deobf.r10},
                            {"R11",    row.regs.r11,    row.regs_deobf.r11},
                            {"R12",    row.regs.r12,    row.regs_deobf.r12},
                            {"R13",    row.regs.r13,    row.regs_deobf.r13},
                            {"R14",    row.regs.r14,    row.regs_deobf.r14},
                            {"R15",    row.regs.r15,    row.regs_deobf.r15},
                            {"RFLAGS", row.regs.rflags, row.regs_deobf.rflags},
                        };
                        for (int ei = 0; ei < (int)(sizeof(entries)/sizeof(entries[0])); ++ei)
                            reg_row(entries[ei].n, entries[ei].b, entries[ei].a, has_d, ei);

                        ImGui::EndTable();
                    }

                    if (!row.has_deobf && !row.is_junk)
                        ImGui::TextDisabled("（本段最后一条 live 指令，无后续对比）");
                }
            }
        }
        ImGui::EndChild();
    }
    ImGui::EndChild(); // ##vmp_top

    // ── 右下：Lua 日志 + 栈面板 ─────────────────────────────────────────
    float bottom_w = ImGui::GetContentRegionAvail().x;
    float log_w = bottom_w * 0.55f;
    if (log_w < 200.0f) log_w = 200.0f;

    // Lua 日志面板
    if (ImGui::BeginChild("##vmp_lua_log", ImVec2(log_w, 0), true)) {
        ImGui::Text("Lua Log");
        ImGui::SameLine();
        if (ImGui::SmallButton("清空##lualog"))
            vmp_lua_log_.clear();
        ImGui::Separator();

        if (ImGui::BeginChild("##vmp_lua_log_scroll", ImVec2(0, 0), false)) {
            for (int li = 0; li < (int)vmp_lua_log_.size(); ++li) {
                const char* s = vmp_lua_log_[li].c_str();
                if (strncmp(s, "[error]", 7) == 0)
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1));
                else if (strncmp(s, "[warn]", 6) == 0)
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.8f, 0.2f, 1));
                else if (strncmp(s, "[ok]", 4) == 0)
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 0.9f, 0.3f, 1));
                else
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_Text));
                char sel_label[1024];
                snprintf(sel_label, sizeof(sel_label), "%s##logln%d", s, li);
                ImGui::Selectable(sel_label, false);
                ImGui::PopStyleColor();
                if (ImGui::BeginPopupContextItem()) {
                    if (ImGui::MenuItem("复制")) ImGui::SetClipboardText(s);
                    if (ImGui::MenuItem("复制全部")) {
                        std::string all;
                        for (auto& l : vmp_lua_log_) { all += l; all += '\n'; }
                        ImGui::SetClipboardText(all.c_str());
                    }
                    ImGui::EndPopup();
                }
            }
            if (vmp_lua_log_scroll_) {
                ImGui::SetScrollHereY(1.0f);
                vmp_lua_log_scroll_ = false;
            }
        }
        ImGui::EndChild();
    }
    ImGui::EndChild(); // ##vmp_lua_log

    ImGui::SameLine();

    // 栈面板
    if (ImGui::BeginChild("##vmp_stack", ImVec2(0, 0), true)) {
        if (vmp_selected_row_ < 0 ||
            vmp_selected_row_ >= (int)vmp_result_.rows.size()) {
            ImGui::TextDisabled("点击指令行查看栈快照");
        } else {
            const auto& row = vmp_result_.rows[vmp_selected_row_];
            bool has_sd = row.has_deobf && !row.stack_deobf.empty();

            ImGui::Text("栈快照  —  %s", row.asm_text.c_str());
            ImGui::SameLine(0, 20);
            ImGui::Checkbox("自定义基准", &vmp_stack_custom_base_);
            if (vmp_stack_custom_base_) {
                ImGui::SameLine();
                ImGui::SetNextItemWidth(160);
                ImGui::InputText("##stack_base", vmp_stack_base_buf_, sizeof(vmp_stack_base_buf_));
            }
            ImGui::Separator();

            if (row.stack.empty()) {
                ImGui::TextDisabled("无栈数据");
            } else {
                // 按绝对地址配对 before/after：
                // stack[si].addr == stack_deobf[?].addr → 才算同一块内存的前后对比
                // 若 RSP 发生偏移（push/pop），slot 索引不同，但地址对得上才是真正变化
                std::unordered_map<uint64_t, const VmpStackEntry*> deobf_by_addr;
                if (has_sd) {
                    for (const auto& sd : row.stack_deobf)
                        deobf_by_addr[sd.addr] = &sd;
                }

                // 有对比时 4 列（偏移/地址/执行前值/去混淆后值），否则 3 列
                int ncols = has_sd ? 4 : 3;
                if (ImGui::BeginTable("##vmp_stk_tbl", ncols,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit))
                {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("偏移",   ImGuiTableColumnFlags_WidthFixed,  55);
                    ImGui::TableSetupColumn("地址",   ImGuiTableColumnFlags_WidthFixed, 145);
                    ImGui::TableSetupColumn("执行前", ImGuiTableColumnFlags_WidthStretch);
                    if (has_sd)
                        ImGui::TableSetupColumn("去混淆后", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();

                    int n = (int)row.stack.size();
                    for (int si = 0; si < n; ++si) {
                        const auto& s = row.stack[si];

                        // 按地址找对应的 deobf 槽（而非按 slot 索引）
                        const VmpStackEntry* sd = nullptr;
                        if (has_sd) {
                            auto it = deobf_by_addr.find(s.addr);
                            if (it != deobf_by_addr.end()) sd = it->second;
                        }

                        // 同一地址上值变化 → 真正的内存变化（如 junk 指令写了这个槽）
                        bool val_changed = sd && (s.value != sd->value);
                        // 这条地址在去混淆后不存在（比如被 pop 移走）
                        bool addr_gone   = has_sd && !sd;

                        ImGui::TableNextRow();

                        if (s.is_rsp)
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                                                   IM_COL32(40,120,40,200));
                        else if (val_changed)
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                                                   IM_COL32(120,30,30,180));

                        // 偏移列
                        ImGui::TableSetColumnIndex(0);
                        int64_t disp = s.offset;
                        bool is_base = (s.offset == 0);
                        if (vmp_stack_custom_base_) {
                            uint64_t custom_base = 0;
                            try { custom_base = std::stoull(vmp_stack_base_buf_, nullptr, 16); } catch (...) {}
                            if (custom_base != 0) {
                                disp = (int64_t)(s.addr - custom_base);
                                is_base = (disp == 0);
                            }
                        }
                        if (is_base)
                            ImGui::TextColored(ImVec4(0.3f,1,0.3f,1), "BASE");
                        else if (disp > 0)
                            ImGui::Text("+0x%llX", (unsigned long long)disp);
                        else
                            ImGui::Text("-0x%llX", (unsigned long long)(-disp));

                        char as[24], vs[24];
                        snprintf(as, sizeof(as), "0x%llX", (unsigned long long)s.addr);
                        snprintf(vs, sizeof(vs), "%016llX", (unsigned long long)s.value);

                        // 地址列
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextUnformatted(as);
                        {
                            char pid[48]; snprintf(pid, sizeof(pid), "##ska%d", si);
                            if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
                                ImGui::OpenPopup(pid);
                            if (ImGui::BeginPopup(pid)) {
                                if (ImGui::MenuItem("复制地址")) ImGui::SetClipboardText(as);
                                ImGui::EndPopup();
                            }
                        }

                        // 执行前值列
                        ImGui::TableSetColumnIndex(2);
                        ImGui::TextUnformatted(vs);
                        {
                            char pid[48]; snprintf(pid, sizeof(pid), "##skv%d", si);
                            if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
                                ImGui::OpenPopup(pid);
                            if (ImGui::BeginPopup(pid)) {
                                if (ImGui::MenuItem("复制值")) ImGui::SetClipboardText(vs);
                                ImGui::EndPopup();
                            }
                        }

                        // 去混淆后值列
                        if (has_sd) {
                            ImGui::TableSetColumnIndex(3);
                            if (addr_gone) {
                                // 该地址在去混淆后的快照范围之外（RSP 移动超出窗口）
                                ImGui::TextDisabled("---");
                            } else if (sd) {
                                char vs2[24];
                                snprintf(vs2, sizeof(vs2), "%016llX", (unsigned long long)sd->value);
                                if (val_changed)
                                    ImGui::TextColored(ImVec4(1,0.35f,0.35f,1), "%s", vs2);
                                else
                                    ImGui::TextColored(ImVec4(0.3f,0.9f,0.3f,1), "%s", vs2);
                                {
                                    char pid[48]; snprintf(pid, sizeof(pid), "##skdv%d", si);
                                    if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
                                        ImGui::OpenPopup(pid);
                                    if (ImGui::BeginPopup(pid)) {
                                        if (ImGui::MenuItem("复制值")) ImGui::SetClipboardText(vs2);
                                        ImGui::EndPopup();
                                    }
                                }
                            }
                        }
                    }
                    ImGui::EndTable();
                }

                if (!has_sd && row.has_deobf && row.stack.empty())
                    ImGui::TextDisabled("（无栈数据）");
                else if (!row.has_deobf && !row.is_junk)
                    ImGui::TextDisabled("（本段最后一条 live 指令，无后续对比）");
            }
        }
    }
    ImGui::EndChild(); // ##vmp_stack

    ImGui::EndChild(); // ##vmp_right
}
