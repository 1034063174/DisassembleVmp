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



if row.step == 1066 then
        row.analysis = "减完rdx刚好=0"
    end

end
log(vmRegBase);
log("[ok] done")
