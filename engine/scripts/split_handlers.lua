dofile("scripts\\tools.lua")

writeback = {"handler_type"}

local pushes, vmstack_base, rsp_to_name = get_init_pushes()
local vs_reg = get_vmstack_reg()
local vc_reg = vmCode_reg or "r11"

if not vs_reg then
    log("[error] 未找到 vmStack 寄存器")
    return
end

log(string.format("vmStack 寄存器: %s", vs_reg))
log(string.format("vmCode  寄存器: %s", vc_reg))
log(string.format("vmStack 基址: 0x%X", vmstack_base))
log(string.format("\n=== Init: %d 次压栈 ===\n", #pushes))

for _, p in ipairs(pushes) do
    local v = p.value and string.format("0x%X", p.value) or "?"
    log(string.format("  slot %2d  RSP=0x%X  %-14s  %s", p.slot, p.rsp_after, p.desc, v))
end
log("")

local function vmstack_lookup(ptr)
    local name = rsp_to_name[ptr]
    local off = ptr - vmstack_base
    return name, off
end

-- 辅助：检查 mem 操作数是否为 [reg] 无偏移无 index
local function is_bare_mem(op, base)
    return op.type == "mem" and op.mem_base == base
           and (op.mem_index == "" or not op.mem_index)
           and (not op.mem_disp or op.mem_disp == 0)
end

-- 辅助：子寄存器名 → 64 位全名
local subreg_map = {
    eax="rax", ax="rax", al="rax", ah="rax",
    ebx="rbx", bx="rbx", bl="rbx", bh="rbx",
    ecx="rcx", cx="rcx", cl="rcx", ch="rcx",
    edx="rdx", dx="rdx", dl="rdx", dh="rdx",
    esi="rsi", si="rsi", sil="rsi",
    edi="rdi", di="rdi", dil="rdi",
    ebp="rbp", bp="rbp", bpl="rbp",
    esp="rsp", sp="rsp", spl="rsp",
    r8d="r8",  r8w="r8",  r8b="r8",
    r9d="r9",  r9w="r9",  r9b="r9",
    r10d="r10", r10w="r10", r10b="r10",
    r11d="r11", r11w="r11", r11b="r11",
    r12d="r12", r12w="r12", r12b="r12",
    r13d="r13", r13w="r13", r13b="r13",
    r14d="r14", r14w="r14", r14b="r14",
    r15d="r15", r15w="r15", r15b="r15",
}
local function reg64(name)
    return subreg_map[name] or name
end

-- 辅助：从寄存器名推断大小（字节数）
local reg_size_map = {
    al=1, bl=1, cl=1, dl=1, sil=1, dil=1, bpl=1, spl=1,
    ah=1, bh=1, ch=1, dh=1,
    r8b=1, r9b=1, r10b=1, r11b=1, r12b=1, r13b=1, r14b=1, r15b=1,
    ax=2, bx=2, cx=2, dx=2, si=2, di=2, bp=2, sp=2,
    r8w=2, r9w=2, r10w=2, r11w=2, r12w=2, r13w=2, r14w=2, r15w=2,
    eax=4, ebx=4, ecx=4, edx=4, esi=4, edi=4, ebp=4, esp=4,
    r8d=4, r9d=4, r10d=4, r11d=4, r12d=4, r13d=4, r14d=4, r15d=4,
    rax=8, rbx=8, rcx=8, rdx=8, rsi=8, rdi=8, rbp=8, rsp=8,
    r8=8, r9=8, r10=8, r11=8, r12=8, r13=8, r14=8, r15=8,
}
local function reg_size(name)
    return reg_size_map[name] or 8
end

-- 辅助：从 regs 表取寄存器值（自动处理子寄存器）
local function get_reg_val(regs, name)
    if not regs or not regs.valid then return nil end
    return regs[reg64(name)]
end

handlers[1].type = "(init+dispatch)"
handlers[1].detail = ""

-- rsp+offset → 寄存器名 映射表（由 init 后连续 vPop 建立）
local rsp_off_to_reg = {}
local building_reg_map = true  -- 遇到非 vPop 停止建表

log("=== Handler 分类 ===\n")

for hi = 2, #handlers do
    local h = handlers[hi]

    local live = {}
    for _, ri in ipairs(h.row_indices) do
        local row = rows[ri]
        if not row.is_junk then
            table.insert(live, row)
        end
    end

    local typ = "unknown"
    local det = ""

    if #live < 2 then
        h.type = typ; h.detail = det
        goto next_handler
    end

    local i1 = live[1]
    local i2 = live[2]

    -- ══════════════════════════════════════════════════════════
    -- vPop 特征（顺序搜索）:
    --   先找 mov  xxx, [vs_reg]
    --   再往后找 add  vs_reg, 8
    -- ══════════════════════════════════════════════════════════
    local vpop_mov_idx = nil
    local vpop_mov_row = nil
    for j = 1, #live do
        local row = live[j]
        if row.mnemonic == "mov" and #row.operands >= 2
           and is_bare_mem(row.operands[2], vs_reg)
           and row.operands[1].type == "reg" then
            vpop_mov_idx = j
            vpop_mov_row = row
            break
        end
    end

    if vpop_mov_idx then
        for j = vpop_mov_idx + 1, #live do
            local row = live[j]
            if row.mnemonic == "add" and #row.operands >= 2
               and row.operands[1].type == "reg" and row.operands[1].reg == vs_reg
               and row.operands[2].type == "imm" and row.operands[2].imm == 8 then

                typ = "vPop"
                local pop_reg = vpop_mov_row.operands[1].reg
                local vmstack_name = nil
                local pop_target_off = nil

                if building_reg_map and vpop_mov_row.regs and vpop_mov_row.regs.valid then
                    local ptr = vpop_mov_row.regs[vs_reg]
                    if ptr then
                        local name, off = vmstack_lookup(ptr)
                        vmstack_name = name
                        if name then
                            det = string.format("vmStack[+0x%X](%s)", off, name)
                        else
                            det = string.format("vmStack[+0x%X]", off)
                        end
                    end
                end

                -- 查找 mov [rsp + A], pop_reg → 弹出目标位置
                if pop_reg then
                    for k = j + 1, #live do
                        local r = live[k]
                        if r.mnemonic == "mov" and #r.operands >= 2 then
                            local dst = r.operands[1]
                            local src = r.operands[2]
                            if dst.type == "mem" and dst.mem_base == "rsp"
                               and src.type == "reg" and src.reg == pop_reg
                               and r.regs and r.regs.valid then
                                local target_off = 0
                                if dst.mem_index ~= "" and dst.mem_index and r.regs[dst.mem_index] then
                                    target_off = r.regs[dst.mem_index]
                                end
                                if dst.mem_disp and dst.mem_disp ~= 0 then
                                    target_off = target_off + dst.mem_disp
                                end
                                pop_target_off = target_off
                                local reg_name = rsp_off_to_reg[target_off]
                                if reg_name then
                                    det = det .. string.format(" ->rsp+0x%X(%s)", target_off, reg_name)
                                else
                                    det = det .. string.format(" ->rsp+0x%X", target_off)
                                end
                                break
                            end
                        end
                    end
                end

                if building_reg_map and vmstack_name and pop_target_off then
                    rsp_off_to_reg[pop_target_off] = vmstack_name
                end
                break
            end
        end
    end

    -- 非 vPop → 停止建表
    if typ ~= "vPop" and building_reg_map and hi > 2 then
        building_reg_map = false
        log("=== rsp+offset → 寄存器映射 ===")
        local sorted = {}
        for off, name in pairs(rsp_off_to_reg) do
            table.insert(sorted, {off=off, name=name})
        end
        table.sort(sorted, function(a,b) return a.off < b.off end)
        for _, item in ipairs(sorted) do
            log(string.format("  rsp+0x%X = %s", item.off, item.name))
        end
        log("")
    end

    -- ══════════════════════════════════════════════════════════
    -- vPush 系列（全指令搜索）:
    --   在 live 中找 sub vs_reg, 8/4 (或 lea vs_reg, [vs_reg-8/-4])
    --   紧接着找 mov [vs_reg], REG
    --   然后根据 REG 的来源区分:
    --     来自 vs_reg             → vPushVSP
    --     来自 [rsp + offset]    → vPushReg
    --     来自 vmCode 8 字节     → vPushImm64
    --     来自 vmCode 4 字节     → vPushImm32
    -- ══════════════════════════════════════════════════════════
    if typ == "unknown" then
        local sub_idx = nil   -- sub vs_reg, N 的位置
        local sub_size = nil  -- 4 or 8
        local mov_idx = nil   -- mov [vs_reg], REG 的位置
        local store_reg = nil -- 写入 vmStack 的寄存器

        -- 搜索 sub vs_reg, 8/4 或 lea vs_reg, [vs_reg-8/-4]
        for j = 1, #live do
            local row = live[j]
            if row.mnemonic == "sub" and #row.operands >= 2
               and row.operands[1].type == "reg" and row.operands[1].reg == vs_reg
               and row.operands[2].type == "imm"
               and (row.operands[2].imm == 8 or row.operands[2].imm == 4 or row.operands[2].imm == 2) then
                sub_idx = j
                sub_size = row.operands[2].imm
                break
            end
            if row.mnemonic == "lea" and #row.operands >= 2
               and row.operands[1].type == "reg" and row.operands[1].reg == vs_reg
               and row.operands[2].type == "mem" and row.operands[2].mem_base == vs_reg
               and (row.operands[2].mem_disp == -8 or row.operands[2].mem_disp == -4 or row.operands[2].mem_disp == -2) then
                sub_idx = j
                sub_size = -row.operands[2].mem_disp
                break
            end
        end

        -- 在 sub 之后找 mov [vs_reg], REG
        if sub_idx then
            for j = sub_idx + 1, #live do
                local row = live[j]
                if row.mnemonic == "mov" and #row.operands >= 2 then
                    local dst = row.operands[1]
                    if is_bare_mem(dst, vs_reg) then
                        mov_idx = j
                        local src = row.operands[2]
                        if src.type == "reg" then
                            store_reg = src.reg
                        end
                        break
                    end
                end
            end
        end

        if sub_idx and mov_idx and store_reg then

            -- vmStack 写入位置
            local mov_row = live[mov_idx]
            local push_ptr = nil
            if mov_row.regs and mov_row.regs.valid then
                push_ptr = mov_row.regs[vs_reg]
            end

            -- ── 判断数据来源（优先级从高到低） ──

            -- 来源 0: mov REG, vs_reg → vPushVSP (压入 vmStack 指针自身)
            for j = 1, sub_idx - 1 do
                local row = live[j]
                if row.mnemonic == "mov" and #row.operands >= 2 then
                    local dst = row.operands[1]
                    local src = row.operands[2]
                    if dst.type == "reg" and dst.reg == store_reg
                       and src.type == "reg" and src.reg == vs_reg then
                        typ = "vPushVSP"
                        if mov_row.regs and mov_row.regs.valid and get_reg_val(mov_row.regs, store_reg) then
                            det = string.format("(0x%X)", get_reg_val(mov_row.regs, store_reg))
                        end
                        break
                    end
                end
            end

            -- 来源 1: mov REG, [rsp + offset] → vPushReg (从宿主栈读)
            if typ == "unknown" then
                for j = 1, sub_idx - 1 do
                    local row = live[j]
                    if row.mnemonic == "mov" and #row.operands >= 2 then
                        local dst = row.operands[1]
                        local src = row.operands[2]
                        if dst.type == "reg" and dst.reg == store_reg
                           and src.type == "mem" and src.mem_base == "rsp" then
                            if row.regs and row.regs.valid then
                                local off = 0
                                if src.mem_index ~= "" and src.mem_index and row.regs[src.mem_index] then
                                    off = row.regs[src.mem_index]
                                end
                                if src.mem_disp and src.mem_disp ~= 0 then
                                    off = off + src.mem_disp
                                end
                                -- 优先用 vPop 建立的 rsp+offset→寄存器 映射
                                local reg_name = rsp_off_to_reg[off]
                                if not reg_name then
                                    -- 回退：用 init 压栈表查
                                    local rsp_val = row.regs.rsp
                                    if rsp_val then
                                        reg_name = rsp_to_name[rsp_val + off]
                                    end
                                end
                                typ = "vPushReg"
                                if reg_name then
                                    det = string.format("(%s) rsp+0x%X", reg_name, off)
                                else
                                    det = string.format("rsp+0x%X", off)
                                end
                            end
                            break
                        end
                    end
                end
            end

            -- 来源 2: mov REG, [vc_reg] + add vc_reg, N → vPushImm64/vPushImm32/vPushImm16
            if typ == "unknown" then
                for j = 1, sub_idx - 1 do
                    local row = live[j]
                    if (row.mnemonic == "mov" or row.mnemonic == "movzx") and #row.operands >= 2 then
                        local src = row.operands[2]
                        if src.type == "mem" and src.mem_base == vc_reg
                           and (src.mem_index == "" or not src.mem_index)
                           and (not src.mem_disp or src.mem_disp == 0) then
                            -- 往后顺序搜索 add vc_reg, N
                            for k = j + 1, sub_idx - 1 do
                                local nxt = live[k]
                                if nxt.mnemonic == "add" and #nxt.operands >= 2
                                   and nxt.operands[1].type == "reg" and nxt.operands[1].reg == vc_reg
                                   and nxt.operands[2].type == "imm" then
                                    local imm_size = nxt.operands[2].imm
                                    if imm_size == 8 then
                                        typ = "vPushImm64"
                                    elseif imm_size == 4 then
                                        typ = "vPushImm32"
                                    elseif imm_size == 1 then
                                        typ = "vPushImm16"
                                    end
                                    if typ ~= "unknown" then
                                        if mov_row.regs and mov_row.regs.valid and mov_row.regs[store_reg] then
                                            det = string.format("(0x%X)", mov_row.regs[store_reg])
                                        end
                                    end
                                    break
                                end
                            end
                            break
                        end
                    end
                end
            end

            -- 补充写入的值（不再显示 vmStack 偏移）
            if typ ~= "unknown" then
                if mov_row.regs and mov_row.regs.valid and get_reg_val(mov_row.regs, store_reg) then
                    det = det .. string.format(" =0x%X", get_reg_val(mov_row.regs, store_reg))
                end
            end
        end
    end

    -- ══════════════════════════════════════════════════════════
    -- vOp 算术/逻辑运算特征（顺序搜索）:
    --   先找 pushfq，再往后找 pop [vs_reg]
    --   pushfq 之前的算术指令决定具体类型
    -- ══════════════════════════════════════════════════════════
    if typ == "unknown" then
        local pushfq_idx = nil
        local pop_idx = nil

        for j = 1, #live do
            if live[j].mnemonic == "pushfq" then
                pushfq_idx = j
                -- 往后找 pop [vs_reg]
                for k = j + 1, #live do
                    if live[k].mnemonic == "pop" and #live[k].operands >= 1
                       and is_bare_mem(live[k].operands[1], vs_reg) then
                        pop_idx = k
                        break
                    end
                end
                if pop_idx then break end
                pushfq_idx = nil
            end
        end

        if pushfq_idx then
            -- 在 pushfq 之前找算术/逻辑指令
            local arith_ops = {
                add = "vAdd", sub = "vSub",
                ["and"] = "vAnd", ["or"] = "vOr", xor = "vXor",
                ["not"] = "vNot", neg = "vNeg",
                shr = "vShr", shl = "vShl", sar = "vSar",
                imul = "vImul", mul = "vMul",
            }

            for j = pushfq_idx - 1, 1, -1 do
                local row = live[j]
                local vname = arith_ops[row.mnemonic]
                if vname then
                    -- 检查 or/and 前是否有两个 not → vNand/vNor
                    if row.mnemonic == "or" or row.mnemonic == "and" then
                        local not_count = 0
                        for k = j - 1, 1, -1 do
                            if live[k].mnemonic == "not" then
                                not_count = not_count + 1
                            else
                                break
                            end
                        end
                        if not_count >= 2 then
                            if row.mnemonic == "or" then
                                vname = "vNand"
                            else
                                vname = "vNor"
                            end
                        end
                    end
                    typ = vname
                    -- 尝试获取操作数的值
                    if row.regs and row.regs.valid and #row.operands >= 2 then
                        local op1 = row.operands[1]
                        local op2 = row.operands[2]
                        local a = (op1.type == "reg" and row.regs[op1.reg]) and row.regs[op1.reg] or nil
                        local b = (op2.type == "reg" and row.regs[op2.reg]) and row.regs[op2.reg] or nil
                        if a and b then
                            det = string.format("0x%X %s 0x%X", a, row.mnemonic, b)
                        elseif a then
                            det = string.format("0x%X %s ...", a, row.mnemonic)
                        end
                    elseif row.regs and row.regs.valid and #row.operands >= 1 then
                        local op1 = row.operands[1]
                        local a = (op1.type == "reg" and row.regs[op1.reg]) and row.regs[op1.reg] or nil
                        if a then
                            det = string.format("%s 0x%X", row.mnemonic, a)
                        end
                    end
                    break
                end
            end

            -- 找到了 pushfq+pop 但没识别出具体运算，标记为 vOp
            if typ == "unknown" then
                typ = "vOp"
            end
        end
    end

    -- ══════════════════════════════════════════════════════════
    -- vStore 特征（全指令搜索）:
    --   搜索 add vs_reg, M (弹出 vmStack)
    --   在 add 之前找 mov REG1, [vs_reg] (读地址)
    --   在 add 之前找 mov REG2, [vs_reg+8] (读值)
    --   在 add 之后找 mov [REG1], REG2 (写入内存)
    --   根据写入指令的寄存器大小判断 store 宽度
    -- ══════════════════════════════════════════════════════════
    if typ == "unknown" then
        -- 找 add vs_reg, M（vmStack 弹出）
        local add_idx = nil
        local pop_size = nil
        for j = 1, #live do
            local row = live[j]
            if row.mnemonic == "add" and #row.operands >= 2
               and row.operands[1].type == "reg" and row.operands[1].reg == vs_reg
               and row.operands[2].type == "imm" and row.operands[2].imm > 8 then
                add_idx = j
                pop_size = row.operands[2].imm
                break
            end
        end

        if add_idx then
            -- 在 add 之前找 mov REG1, [vs_reg]（读地址）
            local addr_reg = nil
            for j = 1, add_idx - 1 do
                local row = live[j]
                if row.mnemonic == "mov" and #row.operands >= 2
                   and row.operands[1].type == "reg"
                   and is_bare_mem(row.operands[2], vs_reg) then
                    addr_reg = row.operands[1].reg
                    break
                end
            end

            -- 在 add 之后找 mov [addr_reg], REG2（写入内存）
            if addr_reg then
                for j = add_idx + 1, #live do
                    local row = live[j]
                    if row.mnemonic == "mov" and #row.operands >= 2
                       and row.operands[1].type == "mem"
                       and row.operands[2].type == "reg" then
                        local write_reg = row.operands[2].reg
                        local sz = reg_size(write_reg)
                        local size_map = {[1]="vStore8", [2]="vStore16", [4]="vStore32", [8]="vStore64"}
                        typ = size_map[sz] or string.format("vStore%d", sz * 8)

                        -- 地址和值从写入指令时刻取
                        local addr_val = get_reg_val(row.regs, addr_reg)
                        local write_val = get_reg_val(row.regs, write_reg)
                        if addr_val and write_val then
                            det = string.format("[0x%X] = 0x%X", addr_val, write_val)
                        elseif addr_val then
                            det = string.format("[0x%X]", addr_val)
                        end
                        break
                    end
                end
            end
        end
    end

    -- ══════════════════════════════════════════════════════════
    -- vLoad 特征（顺序搜索）:
    --   mov REG1, [vs_reg]         ; 读栈顶（地址）
    --   mov REG2, [REG1]           ; 解引用读内存
    --   mov [vs_reg], REG2         ; 值写回栈顶
    -- ══════════════════════════════════════════════════════════
    if typ == "unknown" then
        -- 找 mov REG1, [vs_reg]
        for j = 1, #live do
            local row = live[j]
            if row.mnemonic == "mov" and #row.operands >= 2
               and row.operands[1].type == "reg"
               and is_bare_mem(row.operands[2], vs_reg) then
                local addr_reg = row.operands[1].reg
                -- 往后找 mov REG2, [REG1] (或 movzx)
                for k = j + 1, #live do
                    local r2 = live[k]
                    if (r2.mnemonic == "mov" or r2.mnemonic == "movzx") and #r2.operands >= 2
                       and r2.operands[1].type == "reg"
                       and r2.operands[2].type == "mem"
                       and r2.operands[2].mem_base == addr_reg
                       and (not r2.operands[2].mem_index or r2.operands[2].mem_index == "")
                       and (not r2.operands[2].mem_disp or r2.operands[2].mem_disp == 0) then
                        local val_reg = r2.operands[1].reg
                        local read_size = reg_size(val_reg)
                        -- 往后找 mov [vs_reg], REG2
                        for m = k + 1, #live do
                            local r3 = live[m]
                            if r3.mnemonic == "mov" and #r3.operands >= 2
                               and is_bare_mem(r3.operands[1], vs_reg)
                               and r3.operands[2].type == "reg"
                               and subreg_map[r3.operands[2].reg] == subreg_map[val_reg] then
                                local sz = read_size * 8
                                typ = string.format("vLoad%d", sz)
                                -- 尝试获取地址值
                                if row.regs and row.regs.valid and row.regs[vs_reg] then
                                    local addr_ptr = row.regs[vs_reg]
                                    -- 读 vmStack 栈顶得到的值
                                    if r2.regs and r2.regs.valid and get_reg_val(r2.regs, val_reg) then
                                        det = string.format("[0x%X] =0x%X", row.regs[addr_reg] or 0, get_reg_val(r2.regs, val_reg))
                                    elseif row.regs[addr_reg] then
                                        det = string.format("[0x%X]", row.regs[addr_reg])
                                    end
                                end
                                break
                            end
                        end
                        break
                    end
                end
                if typ ~= "unknown" then break end
            end
        end
    end

    -- ══════════════════════════════════════════════════════════
    -- vExit 特征:
    --   mov rsp, vs_reg   ← 恢复真实栈指针
    --   连续 pop 寄存器
    --   ret
    -- ══════════════════════════════════════════════════════════
    if typ == "unknown" then
        if live[1].mnemonic == "mov" and #live[1].operands >= 2
           and live[1].operands[1].type == "reg" and live[1].operands[1].reg == "rsp"
           and live[1].operands[2].type == "reg" and live[1].operands[2].reg == vs_reg then
            -- 确认最后一条是 ret
            if live[#live].mnemonic == "ret" then
                typ = "vExit"
            end
        end
    end

    h.type = typ
    h.detail = det
    log(string.format("[handler %2d] %-12s %s", hi - 1, typ, det))

    ::next_handler::
end

log("\n[ok] done")
