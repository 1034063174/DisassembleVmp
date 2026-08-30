writeback = {"analysis", "is_junk"}
log("annotate.lua loaded")
log(string.format("total=%d  junk=%d  handlers=%d", total_insns, junk_insns, #handlers))

local function vn_str(vn)
    if vn.space == "register" then
        return string.format("%s:%d", vn.reg_name, vn.size)
    elseif vn.space == "const" then
        return string.format("0x%X:%d", vn.offset, vn.size)
    else
        return string.format("%s(0x%X):%d", vn.space, vn.offset, vn.size)
    end
end

local function dump_vn(vn)
    log(
        string.format("  space=%-10s offset=0x%X  size=%d  reg_name=%s", vn.space, vn.offset, vn.size, vn.reg_name or ""))
end

for i, row in ipairs(rows) do
    if row.step == 40 then
        row.analysis = "obcode基地址"
    end

    if row.step == 44 then
        row.analysis = "这是顶层的push"

        log(row.mnemonic)

        for i, op in ipairs(row.operands) do
            for k, v in pairs(op) do
                log(i, k, v)
            end
        end

        if row.mnemonic == "mov" and #row.operands == 2 then
            local dst = row.operands[1]
            local src = row.operands[2]
            if dst.type == "reg" and src.type == "mem" and src.mem_base == "rsp" and src.mem_index == "" and
                src.mem_disp == 0x90 then
                log(string.format("step %d: %s → %s", row.step, row.asm, dst.reg))
            end
        end
    end
    if row.step == 59 then
        row.analysis = "算出来的key + obcode基地址"
    end

    if row.step == 67 then
        row.analysis = "再加上一个偏移"
    end
    if row.step == 68 then
        row.analysis = "VM栈与x86栈保持一致"
    end

    if row.step == 69 then
        row.analysis = "VMcontext"
    end

    if row.step == 82 then
        row.analysis = "这是 jmpBase"
    end

    if row.step == 85 then
        row.analysis = "VEIP+=4"
    end
end
log(vmRegBase);
log("[ok] done")
