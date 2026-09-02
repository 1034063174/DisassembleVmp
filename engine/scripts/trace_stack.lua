dofile("scripts\\tools.lua")

local pushes, vmstack_base, rsp_to_name = get_init_pushes()
local vs_reg = get_vmstack_reg()

local function parse_imm(detail)
    local hex = detail:match("^%(0x(%x+)%)")
    if not hex then hex = detail:match("=0x(%x+)") end
    if hex then return tonumber(hex, 16) end
    return nil
end

local function parse_rsp_offset(detail)
    local hex = detail:match("rsp%+0x(%x+)")
    if hex then return tonumber(hex, 16) end
    return nil
end

-- 模拟符号栈
local stack = {}
local slots = {}  -- slot_off → symbolic name

local function spush(val) table.insert(stack, val) end
local function spop()
    if #stack == 0 then return "UNDERFLOW" end
    return table.remove(stack)
end
local function stack_str()
    local s = "["
    for i, v in ipairs(stack) do
        if i > 1 then s = s .. ", " end
        s = s .. tostring(v)
    end
    return s .. "]"
end

local function slot_name(off) return string.format("slot_0x%X", off) end

-- 初始化 slot
for hi = 2, #handlers do
    local h = handlers[hi]
    if h.type ~= "vPop" then break end
    local det = h.detail or ""
    local m = det:match("%((%a%w*)%)")
    local off = parse_rsp_offset(det)
    if m and off then
        slots[off] = m
    elseif off then
        slots[off] = string.format("init_0x%X", off)
    end
end

-- 追踪 handler 20-80
for hi = 21, 81 do
    local h = handlers[hi]
    if not h then break end
    local typ = h.type
    local det = h.detail or ""

    if typ == "vPushReg" then
        local off = parse_rsp_offset(det)
        if off then
            spush(slots[off] or slot_name(off))
        else
            spush("?reg")
        end

    elseif typ == "vPushImm64" or typ == "vPushImm32" or typ == "vPushImm16" then
        local imm = parse_imm(det)
        spush(string.format("0x%X", imm or 0))

    elseif typ == "vPushVSP" then
        spush("__VSP__")

    elseif typ == "vPop" then
        local val = spop()
        local off = parse_rsp_offset(det)
        if off then
            slots[off] = val
        end

    elseif typ == "vAdd" then
        local b, a = spop(), spop()
        local result = string.format("(%s + %s)", a, b)
        spush(result)
        spush("flags")

    elseif typ == "vSub" then
        local b, a = spop(), spop()
        spush(string.format("(%s - %s)", a, b))
        spush("flags")

    elseif typ == "vAnd" then
        local b, a = spop(), spop()
        spush(string.format("(%s & %s)", a, b))
        spush("flags")

    elseif typ == "vOr" then
        local b, a = spop(), spop()
        spush(string.format("(%s | %s)", a, b))
        spush("flags")

    elseif typ == "vXor" then
        local b, a = spop(), spop()
        spush(string.format("(%s ^ %s)", a, b))
        spush("flags")

    elseif typ == "vNot" then
        spush(string.format("NOT(%s)", spop()))
        spush("flags")

    elseif typ:match("^vStore") then
        local addr = spop()
        local val = spop()
        spush(string.format("[%s]=%s", addr, val))

    elseif typ:match("^vLoad") then
        local addr = spop()
        if addr == "__VSP__" then
            if #stack > 0 then
                spush(stack[#stack])
            else
                spush("dup_empty")
            end
        else
            spush(string.format("LOAD[%s]", addr))
        end

    elseif typ == "vExit" then
        break
    end

    log(string.format("[h%2d] %-12s stack=%s", hi-1, typ, stack_str()))
end

-- 输出最终 slot 状态
log("\n=== 关键 slot 最终值 ===")
for _, off in ipairs({0x30, 0x38, 0x58, 0x60, 0x70, 0x80}) do
    if slots[off] then
        log(string.format("  slot 0x%X = %s", off, slots[off]))
    end
end
