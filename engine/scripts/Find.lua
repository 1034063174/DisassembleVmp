local target = 0x12345678

for i, row in ipairs(rows) do
    if not row.is_junk then
        local r = row.regs
        if r and r.valid then
            for _, name in ipairs({"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
                                   "r8","r9","r10","r11","r12","r13","r14","r15"}) do
                if r[name] == target then
                    log(string.format("step %d: %s = 0x%X  %s", row.step, name, target, row.asm))
                end
            end
        end
    end
end