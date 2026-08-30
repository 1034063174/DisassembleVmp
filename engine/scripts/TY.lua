log(string.format("=== Handler 枚举 === (共 %d 个)", #handlers))

writeback = {"summary"}
for i, h in ipairs(handlers) do
    h.summary = string.format("%s %s  %d条指令", h.type, h.detail, #h.row_indices)
end

local VMRegister = {
    VMEIP = "NONE",
    VMStack = "NONE",
    VMJMPBase = "NONE",
    VMDEC = "NONE"
}

function ShowVMRegister()
    local data = ""
    for k, v in pairs(VMRegister) do
        data = data .. string.format("%s     %s\r\n", k, v)
    end
    return data
end

function match(A, B) -- 比较结构体  B中的是否A都有
    if #B > #A then
        return false
    end
    for i, b in ipairs(B) do
        local a = A[i]
        if not a then
            return false
        end
        for k, v in pairs(b) do
            if a[k] ~= v then
                return false
            end
        end
    end
    return true

end
        local summaryData = ""
for hi, h in ipairs(handlers) do

    if hi == 1 then

        for _, ri in ipairs(h.row_indices) do
            local row = rows[ri]
            if not row.is_junk and row.mnemonic ~= "jmp" then
                if row.mnemonic == "mov" and match(row.operands, {{
                    type = "reg"
                    -- reg = "r11"
                }, {
                    type = "mem",
                    mem_base = "rsp",
                    mem_disp = 0x90
                }}) then
                    VMRegister.VMEIP = row.operands[1].reg

                end
                -------------------------------------------------------------------------------------------------------
                if row.mnemonic == "mov" and match(row.operands, {{
                    type = "reg"
                }, -- reg = "rbx" 
                {
                    type = "reg",
                    reg = "rsp"
                }}) then
                    VMRegister.VMStack = row.operands[1].reg

                end
                ---------------------------------------
                if row.mnemonic == "lea" and match(row.operands, {{
                    type = "reg"
                }, -- reg = "r8"
                {
                    type = "mem",
                    mem_base = "rip",
                    mem_disp = 0xFFFFFFFFFFFFFFF9
                }}) then
                    VMRegister.VMJMPBase = row.operands[1].reg
                end

            end
        end

   

    end
         h.summary = ShowVMRegister()
end

log("[ok] done")
