-- mouse.lua — 右键菜单: 生成当前行的 operands pattern 并复制到剪贴板
if not context_row then
    log("[error] mouse.lua 需要通过右键菜单调用")
    return
end

local row = rows[context_row]
if not row then
    log("[error] context_row 无效: " .. tostring(context_row))
    return
end

log(string.format("step %d: %s  %s", row.step, row.mnemonic, row.asm))

local parts = {}
for i, op in ipairs(row.operands) do
    local fields = {}
    table.insert(fields, string.format('type = "%s"', op.type))

    if op.type == "reg" then
        table.insert(fields, string.format('reg = "%s"', op.reg))

    elseif op.type == "imm" then
        table.insert(fields, string.format("imm = 0x%X", op.imm))

    elseif op.type == "mem" then
        if op.mem_base ~= "" then
            table.insert(fields, string.format('mem_base = "%s"', op.mem_base))
        end
        if op.mem_index ~= "" then
            table.insert(fields, string.format('mem_index = "%s"', op.mem_index))
            table.insert(fields, string.format("mem_scale = %d", op.mem_scale))
        end
        if op.mem_disp ~= 0 then
            table.insert(fields, string.format("mem_disp = 0x%X", op.mem_disp))
        end
    end

    table.insert(parts, "    { " .. table.concat(fields, ", ") .. " }")
end

local code = string.format('---------------------------------------\n if row.mnemonic == "%s" and match(row.operands, {\n%s\n}) then',
    row.mnemonic, table.concat(parts, ",\n"))

log(code)
set_clipboard(code)
log("[ok] 已复制到剪贴板")
