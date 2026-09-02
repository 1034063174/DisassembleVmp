dofile("scripts\\tools.lua")

for _, idx in ipairs({53}) do
    local h = handlers[idx]
    log(string.format("\n=== handler %d (type: %s) ===", idx - 1, h.type or "nil"))
    for _, ri in ipairs(h.row_indices) do
        local row = rows[ri]
        local junk = row.is_junk and " [JUNK]" or ""
        local ops = {}
        if row.operands then
            for _, op in ipairs(row.operands) do
                if op.type == "reg" then
                    table.insert(ops, op.reg)
                elseif op.type == "imm" then
                    table.insert(ops, string.format("0x%X", op.imm))
                elseif op.type == "mem" then
                    local s = "["
                    if op.mem_base and op.mem_base ~= "" then s = s .. op.mem_base end
                    if op.mem_index and op.mem_index ~= "" then s = s .. "+" .. op.mem_index end
                    if op.mem_disp and op.mem_disp ~= 0 then s = s .. string.format("+0x%X", op.mem_disp) end
                    s = s .. "]"
                    table.insert(ops, s)
                end
            end
        end
        log(string.format("  %d: %-8s %s%s", ri, row.mnemonic, table.concat(ops, ", "), junk))
    end
end
