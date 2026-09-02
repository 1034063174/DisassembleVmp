-- tools.lua — 公共工具函数

-- get_init_pushes()
-- 分析 init handler (handler 1) 的压栈顺序
-- 返回:
--   pushes: 按执行顺序排列的压栈列表，每项 {desc, value, rsp_after, slot}
--           desc: 寄存器名 / "entry_push" / "entry_retaddr" / "rflags"
--           value: 压入的值（十六进制数字）
--           rsp_after: push 执行后的 RSP 值
--           slot: 相对于 vmStack 基址的 slot 号（第一个 push = 最高 slot）
--   vmstack_base: vmStack 基址（sub rsp 之后的 RSP，即所有 push 落地之后的栈顶）
--   rsp_to_name: {[rsp_after] = desc} 查表：给定 rsp 值，查出对应的寄存器名
function get_init_pushes()
    local h1 = handlers[1]
    if not h1 then return {}, 0, {} end

    local pushes = {}

    for _, ri in ipairs(h1.row_indices) do
        local row = rows[ri]
        if row.is_junk then goto continue end

        -- 遇到 add/sub rsp 停止
        if (row.mnemonic == "add" or row.mnemonic == "sub") then
            local op1 = row.operands[1]
            if op1 and op1.type == "reg" and op1.reg == "rsp" then break end
        end

        local r = row.regs
        if not r or not r.valid then goto continue end

        if row.mnemonic == "push" then
            local what = row.asm:match("push%s+(.+)")
            local regs = {
                rax=r.rax, rbx=r.rbx, rcx=r.rcx, rdx=r.rdx,
                rsi=r.rsi, rdi=r.rdi, rbp=r.rbp, rsp=r.rsp,
                r8=r.r8, r9=r.r9, r10=r.r10, r11=r.r11,
                r12=r.r12, r13=r.r13, r14=r.r14, r15=r.r15
            }
            local val = nil
            if regs[what] then
                val = regs[what]
            end
            table.insert(pushes, {
                desc = regs[what] and what or "entry_push",
                value = val,
                rsp_after = r.rsp - 8
            })
        elseif row.mnemonic == "pushfq" then
            table.insert(pushes, {
                desc = "rflags",
                value = r.rflags,
                rsp_after = r.rsp - 8
            })
        elseif row.mnemonic == "call" then
            table.insert(pushes, {
                desc = "entry_retaddr",
                value = nil,
                rsp_after = r.rsp - 8
            })
        end

        ::continue::
    end

    -- 从栈快照补全 entry_push / entry_retaddr 的值
    for _, row in ipairs(rows) do
        if row.step == 1 and row.stack then
            for _, s in ipairs(row.stack) do
                if s.is_rsp then
                    for _, p in ipairs(pushes) do
                        if p.desc == "entry_push" and not p.value then
                            p.value = s.value; break
                        end
                    end
                    break
                end
            end
        elseif row.step == 2 and row.stack then
            for _, s in ipairs(row.stack) do
                if s.is_rsp then
                    for _, p in ipairs(pushes) do
                        if p.desc == "entry_retaddr" and not p.value then
                            p.value = s.value; break
                        end
                    end
                    break
                end
            end
            break
        end
    end

    -- 推算 slot 号（第一个 push → 最高 slot）
    local total = #pushes
    for i, p in ipairs(pushes) do
        p.slot = total - i
    end

    -- vmStack 基址 = 最后一个 push 执行后的 RSP
    local vmstack_base = 0
    if total > 0 then
        vmstack_base = pushes[total].rsp_after
    end

    -- 构建 rsp_after → desc 查找表
    local rsp_to_name = {}
    for _, p in ipairs(pushes) do
        rsp_to_name[p.rsp_after] = p.desc
    end

    return pushes, vmstack_base, rsp_to_name
end

-- get_vmstack_reg()
-- 从 init handler 检测 vmStack 寄存器（特征: mov REG, rsp）
function get_vmstack_reg()
    local h1 = handlers[1]
    if not h1 then return nil end
    for _, ri in ipairs(h1.row_indices) do
        local row = rows[ri]
        if not row.is_junk and row.mnemonic == "mov" and #row.operands >= 2 then
            local dst = row.operands[1]
            local src = row.operands[2]
            if dst.type == "reg" and src.type == "reg" and src.reg == "rsp" then
                return dst.reg
            end
        end
    end
    return nil
end
