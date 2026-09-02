-- annotate.lua — VMP 分析标注脚本示例
-- ═══════════════════════════════════════════════════════════════════
-- 全局变量:
--   vmCode_reg     string  vmCode 寄存器名
--   vmStack_reg    string  vmStack 寄存器名
--   vmRegBase      integer vmRegFile 基址
--   total_insns    integer 总指令数
--   junk_insns     integer 垃圾指令数
--   log(msg)       function 输出到 UI 日志面板
--                  前缀 "[error]" 红色, "[warn]" 黄色, "[ok]" 绿色
--
-- ─── rows[] ────────────────────────────────────────────────────────
-- 每条指令 (1-based)
--   .addr          integer  地址
--   .seg_idx       integer  所属 handler 段索引 (1-based)
--   .step          integer  全局步数
--   .asm           string   汇编文本
--   .bytes         string   字节码十六进制
--   .is_junk       boolean  是否垃圾指令
--   .has_deobf     boolean  是否有去混淆对比数据
--   .analysis      string   分析标注 (可写, 脚本执行后回写到 UI)
--
--   .regs          table    执行前寄存器快照
--     .rax         integer
--     .rbx         integer
--     .rcx         integer
--     .rdx         integer
--     .rsi         integer
--     .rdi         integer
--     .rbp         integer
--     .rsp         integer
--     .r8          integer
--     .r9          integer
--     .r10         integer
--     .r11         integer
--     .r12         integer
--     .r13         integer
--     .r14         integer
--     .r15         integer
--     .rflags      integer
--     .valid       boolean
--
--   .regs_deobf    table    去混淆后寄存器 (has_deobf=true 时存在, 字段同 .regs)
--
--   .stack[]       table    栈快照 (1-based)
--     .offset      integer  相对 RSP 偏移
--     .addr        integer  绝对地址
--     .value       integer  内存值
--     .is_rsp      boolean  是否 RSP 指向的槽
--
--   .stack_deobf[] table    去混淆后栈 (has_deobf=true 时存在, 字段同 .stack)
--
--   .pcode[]       table    PCode 操作列表 (1-based)
--     .opc         integer  操作码编号
--     .opc_name    string   操作码名, 取值:
--                    "COPY"
--                    "LOAD"
--                    "STORE"
--                    "BRANCH"
--                    "CBRANCH"
--                    "BRANCHIND"
--                    "CALL"
--                    "CALLIND"
--                    "CALLOTHER"
--                    "RETURN"
--                    "INT_ADD"
--                    "INT_SUB"
--                    "INT_AND"
--                    "INT_OR"
--                    "INT_XOR"
--                    "INT_NEGATE"
--                    "INT_2COMP"
--                    "INT_LEFT"
--                    "INT_RIGHT"
--                    "INT_SRIGHT"
--                    "INT_MULT"
--                    "INT_DIV"
--                    "INT_SDIV"
--                    "INT_REM"
--                    "INT_SREM"
--                    "INT_EQUAL"
--                    "INT_NOTEQUAL"
--                    "INT_LESS"
--                    "INT_SLESS"
--                    "INT_LESSEQUAL"
--                    "INT_SLESSEQUAL"
--                    "INT_CARRY"
--                    "INT_SCARRY"
--                    "INT_SBORROW"
--                    "INT_ZEXT"
--                    "INT_SEXT"
--                    "BOOL_AND"
--                    "BOOL_OR"
--                    "BOOL_XOR"
--                    "BOOL_NEGATE"
--                    "PIECE"
--                    "SUBPIECE"
--                    "POPCOUNT"
--                    "LZCOUNT"
--                    "?"           (未知操作码)
--     .dead        boolean  是否被死代码消除标记
--     .has_out     boolean  是否有输出 varnode
--     .out         table    输出 varnode (has_out=true 时存在)
--       .space     string   地址空间 ("register", "ram", "const", "unique")
--       .offset    integer  偏移量
--       .size      integer  字节大小
--       .reg_name  string   寄存器名 (space="register" 时有效, 否则为 "")
--     .ins[]       table    输入 varnode 列表 (1-based, 每项字段同 .out)
--
-- ─── handlers[] ────────────────────────────────────────────────────
-- handler 段列表 (1-based)
--   .seg_idx       integer  段索引
--   .type          string   类型, 取值:
--                    "vPushReg"    寄存器压栈
--                    "vPopReg"     寄存器弹栈
--                    "vPushImm"    立即数压栈
--                    "vReadMem"    内存读取
--                    "vWriteMem"   内存写入
--                    "vLogicalOp"  逻辑/算术运算
--                    "vExit"       退出 VM
--                    "unknown"     未识别
--   .detail        string   细节 (如寄存器名、立即数值)
--   .addr_start    integer  起始地址
--   .addr_end      integer  结束地址
--   .live_stores   integer  活跃 STORE 数
--   .live_loads    integer  活跃 LOAD 数
--   .row_indices[] table    行下标列表 (1-based, 对应 rows 索引)
-- ═══════════════════════════════════════════════════════════════════

log("annotate.lua loaded")
log(string.format("total=%d  junk=%d  handlers=%d", total_insns, junk_insns, #handlers))

for i, row in ipairs(rows) do
    if row.is_junk then goto continue end

    for _, op in ipairs(row.pcode) do
        if not op.dead and op.opc_name == "LOAD" and op.has_out then
            local dst = op.out.reg_name
            if dst ~= "" then
                row.analysis = "LOAD->" .. dst
                log(string.format("step %d: LOAD -> %s", row.step, dst))
            end
        end

        if not op.dead and op.opc_name == "STORE" then
            row.analysis = "STORE"
            log(string.format("step %d: STORE", row.step))
        end
    end

    ::continue::
end

log("[ok] done")
