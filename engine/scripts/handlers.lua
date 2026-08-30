-- handlers.lua — 展示 handler 划分结构
-- 输出每个 handler 的类型、地址范围、指令数、以及关键指令摘要

log(string.format("=== Handler 划分 === (共 %d 个 handler, %d 条指令, %d 条垃圾)",
    #handlers, total_insns, junk_insns))
log(string.format("vmCode=%s  vmStack=%s  vmRegBase=0x%X",
    vmCode_reg, vmStack_reg, vmRegBase))
log("")

for hi, h in ipairs(handlers) do
    -- handler 头
    local insn_cnt = #h.row_indices
    local junk_cnt = 0
    for _, ri in ipairs(h.row_indices) do
        if rows[ri].is_junk then junk_cnt = junk_cnt + 1 end
    end
    local clean_cnt = insn_cnt - junk_cnt

    log(string.format("[handler %d]  %s  %s", hi, h.type, h.detail))
    log(string.format("  地址: 0x%X ~ 0x%X", h.addr_start, h.addr_end))
    log(string.format("  指令: %d 条 (有效 %d, 垃圾 %d)", insn_cnt, clean_cnt, junk_cnt))
    log(string.format("  STORE=%d  LOAD=%d", h.live_stores, h.live_loads))

    -- 列出非垃圾指令的汇编和 PCode 摘要
    local shown = 0
    for _, ri in ipairs(h.row_indices) do
        local row = rows[ri]
        if not row.is_junk then
            -- 收集有效 PCode 操作
            local ops = {}
            for _, op in ipairs(row.pcode) do
                if not op.dead then
                    local s = op.opc_name
                    if op.has_out and op.out.reg_name ~= "" then
                        s = s .. "->" .. op.out.reg_name
                    end
                    ops[#ops + 1] = s
                end
            end
            local pcode_str = #ops > 0 and table.concat(ops, ", ") or ""

            log(string.format("    [%d] 0x%X  %-30s  %s",
                row.step, row.addr, row.asm, pcode_str))
            shown = shown + 1
        end
    end

    if junk_cnt > 0 then
        log(string.format("    ... (%d 条垃圾指令已隐藏)", junk_cnt))
    end
    log("")
end

log("[ok] handler 划分展示完毕")
