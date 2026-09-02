dofile("scripts\\tools.lua")

-- ═══════════════════════════════════════════════════════
-- decompile.lua — 符号栈 + EXIT 寄存器映射，还原原始汇编
-- 前置: 先运行 annotate.lua + split_handlers.lua
-- ═══════════════════════════════════════════════════════

local pushes, vmstack_base, rsp_to_name = get_init_pushes()
local vs_reg = get_vmstack_reg()
if not vs_reg then log("[error] 未找到 vmStack 寄存器"); return end

-- ── 解析 ──

local function parse_reg(detail)
    return detail:match("^%((%a%w*)%)")
end

local function parse_imm(detail)
    local hex = detail:match("^%(0x(%x+)%)")
    if not hex then hex = detail:match("=0x(%x+)") end
    if hex then return tonumber(hex, 16) end
    return nil
end

local function parse_pop_target(detail)
    return detail:match("->rsp%+0x%x+%((%a%w*)%)")
end

local function parse_rsp_offset(detail)
    local hex = detail:match("rsp%+0x(%x+)")
    if hex then return tonumber(hex, 16) end
    return nil
end

-- ── 找 vExit 和恢复序列 ──

local vexit_idx = nil
for hi = 1, #handlers do
    if handlers[hi].type == "vExit" then vexit_idx = hi; break end
end
if not vexit_idx then log("[error] 未找到 vExit"); return end

local exit_restore_start = vexit_idx - 1
while exit_restore_start >= 1 and handlers[exit_restore_start].type == "vPushReg" do
    exit_restore_start = exit_restore_start - 1
end
exit_restore_start = exit_restore_start + 1

-- ── 从 vExit handler 提取 pop 寄存器顺序 ──

local vexit_h = handlers[vexit_idx]
local exit_pop_regs = {}
for _, ri in ipairs(vexit_h.row_indices) do
    local row = rows[ri]
    if not row.is_junk and row.mnemonic == "pop" and #row.operands >= 1
       and row.operands[1].type == "reg" then
        table.insert(exit_pop_regs, row.operands[1].reg)
    elseif not row.is_junk and row.mnemonic == "popfq" then
        table.insert(exit_pop_regs, "rflags")
    end
end

-- ── 从恢复序列提取 push 偏移 ──

local exit_push_offsets = {}
for hi = exit_restore_start, vexit_idx - 1 do
    local off = parse_rsp_offset(handlers[hi].detail or "")
    if off then
        table.insert(exit_push_offsets, off)
    end
end

-- ── LIFO 匹配：构建 EXIT 映射（offset → CPU 寄存器） ──

local off_to_exit = {}
local n_push = #exit_push_offsets
local n_pop  = #exit_pop_regs

if n_push == n_pop then
    for i = 1, n_push do
        local push_off = exit_push_offsets[n_push - i + 1]  -- LIFO: 最后push = 第一个pop
        local pop_reg  = exit_pop_regs[i]
        off_to_exit[push_off] = pop_reg
    end
end

log("=== EXIT 寄存器映射 (slot → CPU register) ===")
local sorted = {}
for off, name in pairs(off_to_exit) do table.insert(sorted, {off=off, name=name}) end
table.sort(sorted, function(a,b) return a.off < b.off end)
for _, item in ipairs(sorted) do
    local init_name = ""
    for _, p in ipairs(pushes) do
        if p.rsp_after then
            -- 找 init 映射的名字做对比
        end
    end
    log(string.format("  rsp+0x%X = %s", item.off, item.name))
end
log("")

-- ── 符号元素 ──

local function sym_reg(name)      return {type="reg", name=name} end
local function sym_imm(val, bits) return {type="imm", value=val, bits=bits or 64} end
local function sym_expr(op, a, b) return {type="expr", op=op, a=a, b=b} end
local function sym_vsp()          return {type="vsp"} end
local function sym_flags()        return {type="flags"} end
local function sym_unknown()      return {type="unknown"} end

local function sym_to_asm(s)
    if not s then return "?" end
    if s.type == "reg" then return s.name end
    if s.type == "imm" then return string.format("0x%X", s.value) end
    if s.type == "vsp" then return "rsp" end
    if s.type == "flags" then return "rflags" end
    if s.type == "expr" then
        if s.op == "add" and s.b and s.b.type == "imm" then
            if s.b.value == 0 then return sym_to_asm(s.a) end
            return string.format("%s + 0x%X", sym_to_asm(s.a), s.b.value)
        elseif s.op == "sub" and s.b and s.b.type == "imm" then
            return string.format("%s - 0x%X", sym_to_asm(s.a), s.b.value)
        end
        return string.format("%s(%s, %s)", s.op, sym_to_asm(s.a), sym_to_asm(s.b or {type="unknown"}))
    end
    return "?"
end

local function mem_operand(addr_sym, size_prefix)
    return string.format("%s ptr [%s]", size_prefix, sym_to_asm(addr_sym))
end

-- ── 初始化 ──

local compute_start = nil
for hi = 2, #handlers do
    if handlers[hi].type ~= "vPop" then compute_start = hi; break end
end
if not compute_start then log("[error] 未找到计算 handler"); return end

local stack = {}
local regfile = {}

-- 先用 INIT 映射初始化（所有 init vPop 的槽位）
local off_to_init = {}
for hi = 2, #handlers do
    local h = handlers[hi]
    if h.type ~= "vPop" then break end
    local det = h.detail or ""
    local m = det:match("%((%a%w*)%)")
    local tgt_off = parse_rsp_offset(det)
    if m and tgt_off and m ~= "entry_push" and m ~= "entry_retaddr" then
        off_to_init[tgt_off] = m
        regfile[tgt_off] = sym_reg(m)
    end
end

-- EXIT 映射覆盖：exit 时槽位对应的才是真正的 CPU 寄存器
for off, name in pairs(off_to_exit) do
    regfile[off] = sym_reg(name)
end

local output = {}
local function emit(asm) table.insert(output, asm) end
local function spush(sym) table.insert(stack, sym) end
local function spop()
    if #stack == 0 then return sym_unknown() end
    return table.remove(stack)
end

local compute_end = exit_restore_start - 1

-- ── 遍历 handler ──

for hi = compute_start, compute_end do
    local h = handlers[hi]
    local typ = h.type
    local det = h.detail or ""

    -- ── vPushReg ──
    if typ == "vPushReg" then
        local off = parse_rsp_offset(det)
        if off and regfile[off] then
            spush(regfile[off])
        else
            spush(sym_unknown())
        end

    -- ── vPushImm ──
    elseif typ == "vPushImm64" then
        spush(parse_imm(det) and sym_imm(parse_imm(det), 64) or sym_unknown())
    elseif typ == "vPushImm32" then
        spush(parse_imm(det) and sym_imm(parse_imm(det), 32) or sym_unknown())
    elseif typ == "vPushImm16" then
        spush(parse_imm(det) and sym_imm(parse_imm(det), 16) or sym_unknown())

    -- ── vPushVSP ──
    elseif typ == "vPushVSP" then
        spush(sym_vsp())

    -- ── vPop ──
    elseif typ == "vPop" then
        local val = spop()
        local tgt_off = parse_rsp_offset(det)

        if tgt_off and off_to_exit[tgt_off] then
            local exit_reg = off_to_exit[tgt_off]

            -- 只有 imm/expr 写入寄存器槽位才输出指令
            -- reg→reg 是 VMP 内部的寄存器洗牌，不输出
            if val.type == "imm" then
                emit(string.format("mov %s, 0x%X", exit_reg, val.value))
            elseif val.type == "expr" then
                -- 检查 dst = dst op src 形式
                if val.a and val.a.type == "reg" and val.a.name == exit_reg and val.b then
                    emit(string.format("%s %s, %s", val.op, exit_reg, sym_to_asm(val.b)))
                else
                    emit(string.format("; %s = %s", exit_reg, sym_to_asm(val)))
                end
            end
            -- reg/vsp/flags/unknown → 不输出（VMP 内部洗牌）

            regfile[tgt_off] = val
        else
            if tgt_off then
                regfile[tgt_off] = val
            end
        end

    -- ── 算术运算 ──
    elseif typ == "vAdd" or typ == "vSub" or typ == "vAnd"
        or typ == "vOr" or typ == "vXor" or typ == "vShr"
        or typ == "vShl" or typ == "vSar" or typ == "vImul"
        or typ == "vMul" then

        local op_map = {
            vAdd="add", vSub="sub", vAnd="and", vOr="or", vXor="xor",
            vShr="shr", vShl="shl", vSar="sar", vImul="imul", vMul="mul"
        }
        local b = spop()
        local a = spop()

        if typ == "vAdd" and b.type == "imm" and b.value == 0 then
            spush(a)
        elseif typ == "vAdd" and a.type == "imm" and a.value == 0 then
            spush(b)
        else
            spush(sym_expr(op_map[typ], a, b))
        end
        spush(sym_flags())

    elseif typ == "vNot" then
        spush(sym_expr("not", spop(), nil))
        spush(sym_flags())

    elseif typ == "vNeg" then
        spush(sym_expr("neg", spop(), nil))
        spush(sym_flags())

    -- ── vStore ──
    elseif typ:match("^vStore") then
        local addr = spop()
        local val  = spop()
        local bits = typ:match("vStore(%d+)")
        local sz_map = {["8"]="byte", ["16"]="word", ["32"]="dword", ["64"]="qword"}
        local sz = sz_map[bits] or "qword"
        emit(string.format("mov %s, %s", mem_operand(addr, sz), sym_to_asm(val)))

    elseif typ == "vExit" then
        emit("ret")
    elseif typ == "vOp" then
        emit(string.format("; [%d] vOp", hi - 1))
    elseif typ == "unknown" then
        emit(string.format("; [%d] unknown", hi - 1))
    end
end

emit("ret")

-- ── 输出 ──

log("=== 还原汇编 ===\n")
for _, line in ipairs(output) do
    log(line)
end
log(string.format("\n[ok] %d 条指令 (符号栈剩余 %d)", #output, #stack))

local f = io.open("vmp_decompiled.asm", "w")
if f then
    f:write("; decompiled by vmp_engine\n\n")
    for _, line in ipairs(output) do f:write(line .. "\n") end
    f:close()
    log("[ok] 已写入 vmp_decompiled.asm")
end
