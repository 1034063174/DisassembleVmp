local h = handlers[1]
if not h then log("[error] no handler"); return end

log(string.format("=== Handler 1: %s %s ===", h.type, h.detail))
log("")

for _, ri in ipairs(h.row_indices) do
    local row = rows[ri]
    if not row.is_junk then
        if (row.mnemonic == "add" or row.mnemonic == "sub") then
            local op1 = row.operands[1]
            if op1 and op1.type == "reg" and op1.reg == "rsp" then
                local rsp_val = (row.regs and row.regs.valid) and row.regs.rsp or 0
                local imm = row.operands[2] and row.operands[2].imm or 0
                log(string.format("  step %3d: %-30s  RSP=0x%X  %s 0x%X, 停止",
                    row.step, row.asm, rsp_val, row.mnemonic, imm))
                break
            end
        end

        local is_push = (row.mnemonic == "push" or row.mnemonic == "pushfq")
        local is_entry_call = (row.step == 1 and row.mnemonic == "call")
        if is_push or is_entry_call then
            local what = row.asm:match("push%s+(.+)") or "?"
            local val = "?"
            local rsp_after = "?"
            if row.regs and row.regs.valid then
                local r = row.regs
                rsp_after = string.format("0x%X", r.rsp - 8)
                local map = {
                    rax=r.rax, rbx=r.rbx, rcx=r.rcx, rdx=r.rdx,
                    rsi=r.rsi, rdi=r.rdi, rbp=r.rbp, rsp=r.rsp,
                    r8=r.r8, r9=r.r9, r10=r.r10, r11=r.r11,
                    r12=r.r12, r13=r.r13, r14=r.r14, r15=r.r15,
                    rflags=r.rflags
                }
                if map[what] then
                    val = string.format("0x%X", map[what])
                elseif row.mnemonic == "pushfq" then
                    what = "rflags"
                    val = string.format("0x%X", r.rflags)
                elseif row.mnemonic == "call" then
                    what = "ret_addr"
                    val = "next_rip"
                else
                    val = what
                end
            end
            log(string.format("  step %3d: %-30s  RSP=%s  %-8s = %s",
                row.step, row.asm, rsp_after, what, val))
        end
    end
end