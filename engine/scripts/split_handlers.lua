-- split_handlers.lua — 完整版 handler 划分 (1:1 对应 C++ vmp_classifier.cpp)
-- 实现: split_handler_segs, build_seg_defuse, trace_varnode, 全部 tryMatch_*

-- ═══════════════════════════════════════════════════════════════
-- 寄存器名 → Ghidra offset 映射
-- ═══════════════════════════════════════════════════════════════
local reg_to_ghidra = {
    rax=0x00, rcx=0x08, rdx=0x10, rbx=0x18,
    rsp=0x20, rbp=0x28, rsi=0x30, rdi=0x38,
    r8=0x80, r9=0x88, r10=0x90, r11=0x98,
    r12=0xA0, r13=0xA8, r14=0xB0, r15=0xB8,
}
local ghidra_to_reg = {}
for k, v in pairs(reg_to_ghidra) do ghidra_to_reg[v] = k end

local RSP_OFF = 0x20
local vmcode_ghidra_off = reg_to_ghidra[vmCode_reg] or 0
local vmstack_ghidra_off = reg_to_ghidra[vmStack_reg] or 0

-- ═══════════════════════════════════════════════════════════════
-- def-use 表: {space:offset} → {op=, insn_idx=}
-- 对应 C++: build_seg_defuse()
-- ═══════════════════════════════════════════════════════════════
local function vn_key(space, offset)
    return space .. ":" .. offset
end

local function build_seg_defuse(seg_rows)
    local du = {}
    for _, ri in ipairs(seg_rows) do
        local row = rows[ri]
        for _, op in ipairs(row.pcode) do
            if not op.dead and op.has_out then
                local k = vn_key(op.out.space, op.out.offset)
                du[k] = { op = op, row_idx = ri }
            end
        end
    end
    return du
end

-- ═══════════════════════════════════════════════════════════════
-- trace_varnode / trace_defentry (互递归)
-- 对应 C++: trace_varnode() + trace_defentry()
-- 返回: {is_vmstack_addr, is_vmstack_off, from_vmstack, from_vmcode}
-- ═══════════════════════════════════════════════════════════════
local function new_src()
    return { is_vmstack_addr=false, is_vmstack_off=false, from_vmstack=false, from_vmcode=false }
end

local function merge_src(dst, src)
    if src.is_vmstack_addr then dst.is_vmstack_addr = true end
    if src.is_vmstack_off  then dst.is_vmstack_off  = true end
    if src.from_vmstack    then dst.from_vmstack     = true end
    if src.from_vmcode     then dst.from_vmcode      = true end
end

-- 前向声明
local trace_varnode

local function trace_defentry(de, du, seg_vmcode_off, vso, vdr, depth)
    local r = new_src()
    if not de or not de.op then return r end
    local op = de.op

    if op.opc_name == "LOAD" then
        if #op.ins >= 2 then
            local addr = trace_varnode(op.ins[2], du, seg_vmcode_off, vso, vdr, depth)
            if addr.is_vmstack_addr or addr.from_vmstack then
                r.from_vmstack = true
            elseif addr.from_vmcode then
                r.from_vmcode = true
            end
        end

    elseif op.opc_name == "COPY" then
        if #op.ins >= 1 then
            r = trace_varnode(op.ins[1], du, seg_vmcode_off, vso, vdr, depth)
        end

    elseif op.opc_name == "INT_ADD" then
        if #op.ins ~= 2 then return r end
        local a_vn, b_vn = op.ins[1], op.ins[2]
        local a_rsp = (a_vn.space == "register" and a_vn.offset == RSP_OFF)
        local b_rsp = (b_vn.space == "register" and b_vn.offset == RSP_OFF)
        local a_vso = (vso ~= 0 and a_vn.space == "register" and a_vn.offset == vso)
        local b_vso = (vso ~= 0 and b_vn.space == "register" and b_vn.offset == vso)

        if (a_rsp and b_vso) or (b_rsp and a_vso) then
            r.is_vmstack_addr = true
        else
            local a = trace_varnode(a_vn, du, seg_vmcode_off, vso, vdr, depth)
            local b = trace_varnode(b_vn, du, seg_vmcode_off, vso, vdr, depth)
            if a.is_vmstack_addr or b.is_vmstack_addr then r.is_vmstack_addr = true end
            if (a_rsp and b.is_vmstack_off) or (b_rsp and a.is_vmstack_off) then
                r.is_vmstack_addr = true
            end
            if a.is_vmstack_off or b.is_vmstack_off then r.is_vmstack_off = true end
            if a.from_vmcode or b.from_vmcode then r.from_vmcode = true end
        end

    elseif op.opc_name == "INT_SUB" then
        if #op.ins >= 1 then
            local a = trace_varnode(op.ins[1], du, seg_vmcode_off, vso, vdr, depth)
            if a.is_vmstack_addr then r.is_vmstack_addr = true end
            if a.is_vmstack_off  then r.is_vmstack_off  = true end
        end

    else
        -- 所有其他 op: 递归追溯所有输入并合并 (解密链穿透)
        for _, inv in ipairs(op.ins) do
            local s = trace_varnode(inv, du, seg_vmcode_off, vso, vdr, depth)
            merge_src(r, s)
        end
    end
    return r
end

trace_varnode = function(vn, du, seg_vmcode_off, vso, vdr, depth)
    local r = new_src()
    if depth > 12 then return r end

    if vn.space == "register" then
        -- vmstack_direct_reg
        if vdr ~= 0 and vn.offset == vdr then
            r.is_vmstack_addr = true
            return r
        end
        -- vmstack_off_reg
        if vso ~= 0 and vn.offset == vso then
            r.is_vmstack_off = true
            return r
        end
        -- vmCode
        if seg_vmcode_off ~= 0 and vn.offset == seg_vmcode_off then
            r.from_vmcode = true
            return r
        end
        -- 查 def-use 表
        local k = vn_key(vn.space, vn.offset)
        local de = du[k]
        if de then
            return trace_defentry(de, du, seg_vmcode_off, vso, vdr, depth + 1)
        end
        return r
    end

    if vn.space == "unique" then
        local k = vn_key(vn.space, vn.offset)
        local de = du[k]
        if not de then return r end
        return trace_defentry(de, du, seg_vmcode_off, vso, vdr, depth + 1)
    end

    return r
end

-- ═══════════════════════════════════════════════════════════════
-- build_unique_vals: unique → 运行时值 (COPY/INT_ADD/INT_SUB/INT_MULT)
-- 对应 C++: build_unique_vals()
-- ═══════════════════════════════════════════════════════════════
local function build_unique_vals(row)
    local uv = {}
    for _, op in ipairs(row.pcode) do
        if op.dead or not op.has_out then goto next end
        if op.out.space ~= "unique" then goto next end

        if op.opc_name == "COPY" and #op.ins >= 1 then
            local s = op.ins[1]
            if s.space == "register" and s.reg_name ~= "" then
                local v = row.regs[s.reg_name]
                if v then uv[op.out.offset] = v end
            end
        elseif (op.opc_name == "INT_ADD" or op.opc_name == "INT_SUB" or op.opc_name == "INT_MULT")
               and #op.ins == 2 then
            local a, b = nil, nil
            for ii = 1, 2 do
                local v = op.ins[ii]
                if v.space == "register" and v.reg_name ~= "" then
                    local rv = row.regs[v.reg_name]
                    if rv then
                        if ii == 1 then a = rv else b = rv end
                    end
                elseif v.space == "const" then
                    if ii == 1 then a = v.offset else b = v.offset end
                elseif v.space == "unique" then
                    local uval = uv[v.offset]
                    if uval then
                        if ii == 1 then a = uval else b = uval end
                    end
                end
            end
            if a and b then
                if op.opc_name == "INT_ADD" then uv[op.out.offset] = a + b
                elseif op.opc_name == "INT_SUB" then uv[op.out.offset] = a - b
                else uv[op.out.offset] = a * b end
            end
        end
        ::next::
    end
    return uv
end

-- 解析 varnode 的运行时地址
local function resolve_addr(row, vn)
    local uv = build_unique_vals(row)
    if vn.space == "register" and vn.reg_name ~= "" then
        return row.regs[vn.reg_name]
    elseif vn.space == "const" then
        return vn.offset
    elseif vn.space == "unique" then
        return uv[vn.offset]
    end
    return nil
end

-- ═══════════════════════════════════════════════════════════════
-- 地址判定工具
-- ═══════════════════════════════════════════════════════════════
local function is_vmregfile(addr)
    if not addr or vmRegBase == 0 then return false end
    return addr >= vmRegBase and addr < vmRegBase + 256
end

local function find_def_in_row(row, unique_off)
    for _, op in ipairs(row.pcode) do
        if not op.dead and op.has_out
           and op.out.space == "unique" and op.out.offset == unique_off then
            return op
        end
    end
    return nil
end

-- is_vmstack_store: 对应 C++ is_vmstack_store()
local function is_vmstack_store_fn(row, addr_vn)
    if addr_vn.space == "register" and addr_vn.offset ~= RSP_OFF then
        return true
    end
    if addr_vn.space == "unique" then
        local def = find_def_in_row(row, addr_vn.offset)
        if def and def.opc_name == "INT_ADD" and #def.ins == 2 then
            local has_rsp, has_other = false, false
            for _, v in ipairs(def.ins) do
                if v.space == "register" and v.offset == RSP_OFF then has_rsp = true
                elseif v.space == "register" or v.space == "unique" then has_other = true
                end
            end
            if has_rsp and has_other then return true end
        end
    end
    return false
end

-- is_vmstack_load: 对应 C++ is_vmstack_load()
local function is_vmstack_load_fn(row, addr_vn, seg_vmcode_off)
    if addr_vn.space == "register"
       and addr_vn.offset ~= RSP_OFF
       and addr_vn.offset ~= seg_vmcode_off then
        return true
    end
    if addr_vn.space == "unique" then
        local def = find_def_in_row(row, addr_vn.offset)
        if def and def.opc_name == "INT_ADD" and #def.ins == 2 then
            local has_rsp, has_other = false, false
            for _, v in ipairs(def.ins) do
                if v.space == "register" and v.offset == RSP_OFF then has_rsp = true
                elseif v.space == "register" or v.space == "unique" then has_other = true
                end
            end
            if has_rsp and has_other then return true end
        end
    end
    return false
end

-- ═══════════════════════════════════════════════════════════════
-- tryMatch_* 函数 (完整版)
-- ═══════════════════════════════════════════════════════════════

local function tryMatch_vPopReg(seg_rows, seg_vmcode_off, ctx)
    local found_vmreg_store = false
    local found_vmstack_load = false
    local candidate_vdr = 0
    local slot_name = ""

    for _, ri in ipairs(seg_rows) do
        local row = rows[ri]
        local uv = build_unique_vals(row)
        for _, op in ipairs(row.pcode) do
            if op.dead then goto next end

            -- vmRegFile STORE
            if op.opc_name == "STORE" and #op.ins >= 3 and vmRegBase ~= 0 then
                local addr_vn = op.ins[2]
                local dst_addr = resolve_addr(row, addr_vn)
                if is_vmregfile(dst_addr) then
                    local rel = dst_addr - vmRegBase
                    if rel >= 0 and rel % 8 == 0 then
                        found_vmreg_store = true
                        local slot_addr = dst_addr
                        slot_name = ghidra_to_reg[ctx.vmRegSlotMap and ctx.vmRegSlotMap[slot_addr]]
                            or string.format("vmReg[%d]", rel // 8)
                    end
                end
            end

            -- vmStack LOAD
            if op.opc_name == "LOAD" and not found_vmstack_load then
                if is_vmstack_load_fn(row, op.ins[2], seg_vmcode_off) then
                    found_vmstack_load = true
                    if ctx.vmstack_direct_reg == 0 and candidate_vdr == 0 and #op.ins >= 2 then
                        local la = op.ins[2]
                        if la.space == "register" and la.offset ~= RSP_OFF and la.offset ~= seg_vmcode_off then
                            candidate_vdr = la.offset
                        end
                    end
                end
            end

            ::next::
        end
    end

    if found_vmreg_store and found_vmstack_load then
        if ctx.vmstack_direct_reg == 0 and candidate_vdr ~= 0 then
            ctx.vmstack_direct_reg = candidate_vdr
        end
        return true, "vPopReg", slot_name
    end
    return false
end

local function tryMatch_vPushReg(seg_rows, seg_vmcode_off, ctx)
    local found_vmstack_store = false
    local found_vmreg_load = false
    local slot_name = ""

    for _, ri in ipairs(seg_rows) do
        local row = rows[ri]
        for _, op in ipairs(row.pcode) do
            if op.dead then goto next end

            if op.opc_name == "STORE" and not found_vmstack_store then
                if is_vmstack_store_fn(row, op.ins[2]) then
                    found_vmstack_store = true
                end
            end

            if op.opc_name == "LOAD" and #op.ins >= 2 and vmRegBase ~= 0 then
                local dst_addr = resolve_addr(row, op.ins[2])
                if is_vmregfile(dst_addr) then
                    local rel = dst_addr - vmRegBase
                    if rel >= 0 and rel % 8 == 0 and not found_vmreg_load then
                        found_vmreg_load = true
                        slot_name = ghidra_to_reg[ctx.vmRegSlotMap and ctx.vmRegSlotMap[dst_addr]]
                            or string.format("vmReg[%d]", rel // 8)
                    end
                end
            end

            ::next::
        end
    end

    if found_vmstack_store and found_vmreg_load then
        return true, "vPushReg", slot_name
    end
    return false
end

local function tryMatch_vPushImm(seg_rows, seg_vmcode_off, ctx)
    local found_vmstack_store = false
    local found_vmcode_load = false
    local found_vmreg_load = false

    for _, ri in ipairs(seg_rows) do
        local row = rows[ri]
        local uv = build_unique_vals(row)
        for _, op in ipairs(row.pcode) do
            if op.dead then goto next end

            if op.opc_name == "STORE" and #op.ins >= 3 then
                local is_vs = is_vmstack_store_fn(row, op.ins[2])
                if not found_vmstack_store and is_vs then
                    found_vmstack_store = true
                end
                if not is_vs and vmRegBase ~= 0 then
                    local dst_addr = resolve_addr(row, op.ins[2])
                    if is_vmregfile(dst_addr) then found_vmreg_load = true end
                end
            end

            if op.opc_name == "LOAD" and #op.ins >= 2 then
                local la = op.ins[2]
                if la.space == "register" and la.offset == seg_vmcode_off then
                    found_vmcode_load = true
                end
                if vmRegBase ~= 0 then
                    local load_addr = resolve_addr(row, la)
                    if is_vmregfile(load_addr) then found_vmreg_load = true end
                end
            end

            ::next::
        end
    end

    if found_vmstack_store and found_vmcode_load and not found_vmreg_load then
        return true, "vPushImm", ""
    end
    return false
end

local function tryMatch_vMemAccess(seg_rows, seg_vmcode_off, ctx)
    local vso = ctx.vmstack_off_reg
    local vdr = ctx.vmstack_direct_reg
    local du = build_seg_defuse(seg_rows)

    local sem_stores = 0
    local the_store_op = nil
    local sem_loads = 0

    for _, ri in ipairs(seg_rows) do
        local row = rows[ri]
        for _, op in ipairs(row.pcode) do
            if op.dead then goto next end

            if op.opc_name == "STORE" and #op.ins >= 3 then
                local dst = trace_varnode(op.ins[2], du, seg_vmcode_off, vso, vdr, 0)
                if dst.is_vmstack_addr or dst.from_vmstack then
                    sem_stores = sem_stores + 1
                    if not the_store_op then the_store_op = op end
                end
            end

            if op.opc_name == "LOAD" and #op.ins >= 2 then
                local addr = trace_varnode(op.ins[2], du, seg_vmcode_off, vso, vdr, 0)
                if addr.is_vmstack_addr or addr.from_vmcode or addr.from_vmstack then
                    sem_loads = sem_loads + 1
                end
            end

            ::next::
        end
    end

    local is_write = (sem_stores == 2 and sem_loads == 2)
    local is_read  = (sem_stores == 1 and sem_loads == 3)
    if not is_read and not is_write then return false end
    if not the_store_op or #the_store_op.ins < 3 then return false end

    local dst = trace_varnode(the_store_op.ins[2], du, seg_vmcode_off, vso, vdr, 0)
    local src = trace_varnode(the_store_op.ins[3], du, seg_vmcode_off, vso, vdr, 0)
    if not dst.is_vmstack_addr and not dst.from_vmstack then return false end
    if not src.from_vmstack and not src.from_vmcode then return false end

    if is_write then return true, "vWriteMem", string.format("sem S=%d L=%d", sem_stores, sem_loads) end
    return true, "vReadMem", string.format("sem S=%d L=%d", sem_stores, sem_loads)
end

local function tryMatch_vLogicalOp(seg_rows, seg_vmcode_off, ctx)
    if vmRegBase == 0 then return false end

    local found_vmreg_store = false
    local found_vmstack_any = false
    local vmreg_load_count = 0

    for _, ri in ipairs(seg_rows) do
        local row = rows[ri]
        local uv = build_unique_vals(row)
        for _, op in ipairs(row.pcode) do
            if op.dead then goto next end

            if op.opc_name == "STORE" and #op.ins >= 3 then
                if is_vmstack_store_fn(row, op.ins[2]) then
                    found_vmstack_any = true
                    break
                end
                local dst_addr = resolve_addr(row, op.ins[2])
                if is_vmregfile(dst_addr) then found_vmreg_store = true end
            end

            if op.opc_name == "LOAD" and #op.ins >= 2 then
                local load_addr = resolve_addr(row, op.ins[2])
                if is_vmregfile(load_addr) then vmreg_load_count = vmreg_load_count + 1 end
            end

            ::next::
        end
        if found_vmstack_any then break end
    end

    if not found_vmstack_any and found_vmreg_store and vmreg_load_count >= 2 then
        return true, "vLogicalOp", string.format("vmReg LOAD×%d", vmreg_load_count)
    end
    return false
end

local function tryMatch_vExit(seg_rows, live_stores, live_loads)
    if live_loads >= 7 and live_stores == 0 then
        return true, "vExit", string.format("L=%d S=0", live_loads)
    end
    return false
end

-- ═══════════════════════════════════════════════════════════════
-- 主流程
-- ═══════════════════════════════════════════════════════════════

log("=== Handler 划分 (完整版) ===")
log(string.format("vmCode=%s(0x%X)  vmStack=%s(0x%X)  vmRegBase=0x%X",
    vmCode_reg, vmcode_ghidra_off, vmStack_reg, vmstack_ghidra_off, vmRegBase))
log("")

-- ── 第一步: 切段 ──
log("━━━ 切段: 遇到 BRANCHIND/RETURN 切一刀 ━━━")

local segs = {}  -- { {row_indices={}, boundary=string, live_stores=, live_loads=} }
local cur_rows = {}

for i, row in ipairs(rows) do
    cur_rows[#cur_rows + 1] = i
    local is_boundary = false
    local boundary_op = ""
    for _, op in ipairs(row.pcode) do
        if not op.dead and (op.opc_name == "BRANCHIND" or op.opc_name == "RETURN") then
            is_boundary = true
            boundary_op = op.opc_name
            break
        end
    end

    if is_boundary then
        -- 统计 live STORE/LOAD
        local ts, tl = 0, 0
        for _, ri in ipairs(cur_rows) do
            for _, op in ipairs(rows[ri].pcode) do
                if not op.dead then
                    if op.opc_name == "STORE" then ts = ts + 1 end
                    if op.opc_name == "LOAD"  then tl = tl + 1 end
                end
            end
        end
        segs[#segs + 1] = {
            row_indices = cur_rows,
            boundary = boundary_op,
            live_stores = ts,
            live_loads = tl,
        }
        log(string.format("  seg %d: row %d~%d (%d条)  %s  S=%d L=%d  (0x%X: %s)",
            #segs, cur_rows[1], cur_rows[#cur_rows], #cur_rows,
            boundary_op, ts, tl, row.addr, row.asm))
        cur_rows = {}
    end
end

-- 末尾残余
if #cur_rows > 0 then
    local ts, tl = 0, 0
    for _, ri in ipairs(cur_rows) do
        for _, op in ipairs(rows[ri].pcode) do
            if not op.dead then
                if op.opc_name == "STORE" then ts = ts + 1 end
                if op.opc_name == "LOAD"  then tl = tl + 1 end
            end
        end
    end
    segs[#segs + 1] = {
        row_indices = cur_rows,
        boundary = "(truncated)",
        live_stores = ts,
        live_loads = tl,
    }
    log(string.format("  seg %d: row %d~%d (残余)", #segs, cur_rows[1], cur_rows[#cur_rows]))
end

log(string.format("\n切段: %d 个  C++: %d 个\n", #segs, #handlers))

-- ── 第二步: 逐段分类 ──
log("━━━ 逐段分类 (完整 trace_varnode 溯源) ━━━")
log("")

-- 分类上下文 (跨段积累 vmstack_direct_reg)
local ctx = {
    vmstack_off_reg = vmstack_ghidra_off,
    vmstack_direct_reg = 0,
}

for si, seg in ipairs(segs) do
    local sr = seg.row_indices
    local first = rows[sr[1]]
    local last  = rows[sr[#sr]]

    log(string.format("┌─ seg %d: row %d~%d  [0x%X ~ 0x%X]  %d条  S=%d L=%d ─────",
        si, sr[1], sr[#sr], first.addr, last.addr, #sr, seg.live_stores, seg.live_loads))

    if si == 1 then
        log("│  [判定] (init+dispatch) 跳过")
        local cpp = #handlers >= 1 and handlers[1].type or "?"
        log(string.format("│  [C++]  %s", cpp))
        log("└─────────────────────────────────")
        goto next_seg
    end

    -- 每段探测 vmCode 寄存器 (对应 C++ detect_seg_vmcode)
    local seg_vmcode_off = vmcode_ghidra_off

    -- 按 C++ classify_seg 优先级尝试匹配
    local matched, seg_type, detail = false, "unknown", ""
    local reason = ""

    matched, seg_type, detail = tryMatch_vPopReg(sr, seg_vmcode_off, ctx)
    if matched then reason = "vmRegFile STORE + vmStack LOAD (trace确认)" goto classified end

    matched, seg_type, detail = tryMatch_vPushReg(sr, seg_vmcode_off, ctx)
    if matched then reason = "vmStack STORE + vmRegFile LOAD" goto classified end

    matched, seg_type, detail = tryMatch_vPushImm(sr, seg_vmcode_off, ctx)
    if matched then reason = "vmStack STORE + vmCode LOAD, 无vmRegFile" goto classified end

    matched, seg_type, detail = tryMatch_vMemAccess(sr, seg_vmcode_off, ctx)
    if matched then reason = "语义计数匹配 + trace_varnode 溯源确认" goto classified end

    matched, seg_type, detail = tryMatch_vLogicalOp(sr, seg_vmcode_off, ctx)
    if matched then reason = "无vmStack, vmRegFile STORE + LOAD×2+" goto classified end

    matched, seg_type, detail = tryMatch_vExit(sr, seg.live_stores, seg.live_loads)
    if matched then reason = "LOAD≥7, STORE=0 (pop序列恢复寄存器)" goto classified end

    reason = "所有模式均未命中"

    ::classified::

    log(string.format("│  [判定] %-12s %s", seg_type, detail))
    log(string.format("│  [依据] %s", reason))

    -- 对比 C++
    local cpp_type = si <= #handlers and handlers[si].type or "?"
    local cpp_detail = si <= #handlers and handlers[si].detail or ""
    local match_ok = (seg_type == cpp_type)
    if match_ok then
        log(string.format("│  [C++]  %-12s %s", cpp_type, cpp_detail))
    else
        log(string.format("│  [C++]  %-12s %s  ← 不一致!", cpp_type, cpp_detail))
    end

    -- vmstack_direct_reg 状态
    if ctx.vmstack_direct_reg ~= 0 then
        local vdr_name = ghidra_to_reg[ctx.vmstack_direct_reg] or string.format("0x%X", ctx.vmstack_direct_reg)
        log(string.format("│  [ctx]  vmstack_direct_reg = %s", vdr_name))
    end

    log("└─────────────────────────────────")

    ::next_seg::
end

-- 汇总
log("")
log("━━━ 汇总 ━━━")
local match_cnt, mismatch_cnt = 0, 0
local mismatch_list = {}
for si = 1, #segs do
    if si <= #handlers then
        local lua_type = "?"
        -- 重新快速判定 (不打 log)
        if si == 1 then
            lua_type = "(init+dispatch)"
        else
            local sr = segs[si].row_indices
            local seg_vmcode_off = vmcode_ghidra_off
            local m, t, _ = tryMatch_vPopReg(sr, seg_vmcode_off, ctx)
            if m then lua_type = t
            else m, t = tryMatch_vPushReg(sr, seg_vmcode_off, ctx)
                if m then lua_type = t
                else m, t = tryMatch_vPushImm(sr, seg_vmcode_off, ctx)
                    if m then lua_type = t
                    else m, t = tryMatch_vMemAccess(sr, seg_vmcode_off, ctx)
                        if m then lua_type = t
                        else m, t = tryMatch_vLogicalOp(sr, seg_vmcode_off, ctx)
                            if m then lua_type = t
                            else m, t = tryMatch_vExit(sr, segs[si].live_stores, segs[si].live_loads)
                                if m then lua_type = t
                                else lua_type = "unknown" end
                            end
                        end
                    end
                end
            end
        end
        if lua_type == handlers[si].type then
            match_cnt = match_cnt + 1
        else
            mismatch_cnt = mismatch_cnt + 1
            mismatch_list[#mismatch_list + 1] = string.format(
                "  seg %d: Lua=%s  C++=%s", si, lua_type, handlers[si].type)
        end
    end
end

log(string.format("段数: Lua=%d  C++=%d", #segs, #handlers))
log(string.format("一致: %d / %d", match_cnt, math.min(#segs, #handlers)))

if mismatch_cnt > 0 then
    log(string.format("[warn] 不一致: %d 个", mismatch_cnt))
    for _, s in ipairs(mismatch_list) do log(s) end
else
    log("全部一致")
end

log("[ok] done")
