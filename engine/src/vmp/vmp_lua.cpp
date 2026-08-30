// vmp_lua.cpp — Lua 脚本引擎
// 将 VmpAnalysisResult 导出为 Lua table，执行用户脚本，回写 row.analysis。

#include "vmp_lua.h"
#include "../ipc/ipc_client.h"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <cstdio>
#include "imgui.h"

struct LuaCtx {
    VmpAnalysisResult* res;
    IpcClient* ipc;
    std::function<void(const std::string&)> log_fn;
};

static int l_log(lua_State* L)
{
    auto* ctx = (LuaCtx*)lua_touserdata(L, lua_upvalueindex(1));
    if (!ctx || !ctx->log_fn) return 0;
    int nargs = lua_gettop(L);
    std::string msg;
    for (int i = 1; i <= nargs; ++i) {
        if (i > 1) msg += '\t';
        int t = lua_type(L, i);
        if (t == LUA_TSTRING) {
            msg += lua_tostring(L, i);
        } else if (t == LUA_TNUMBER) {
            if (lua_isinteger(L, i)) {
                char buf[32];
                snprintf(buf, sizeof(buf), "%lld", (long long)lua_tointeger(L, i));
                msg += buf;
            } else {
                char buf[32];
                snprintf(buf, sizeof(buf), "%g", lua_tonumber(L, i));
                msg += buf;
            }
        } else if (t == LUA_TBOOLEAN) {
            msg += lua_toboolean(L, i) ? "true" : "false";
        } else if (t == LUA_TNIL) {
            msg += "nil";
        } else {
            char buf[64];
            snprintf(buf, sizeof(buf), "<%s>", lua_typename(L, t));
            msg += buf;
        }
    }
    ctx->log_fn(msg);
    return 0;
}

// read_mem(addr, size) -> string (hex) or nil
static int l_read_mem(lua_State* L)
{
    auto* ctx = (LuaCtx*)lua_touserdata(L, lua_upvalueindex(1));
    if (!ctx || !ctx->ipc) { lua_pushnil(L); return 1; }
    uint64_t addr = (uint64_t)luaL_checkinteger(L, 1);
    int size = (int)luaL_checkinteger(L, 2);
    if (size <= 0 || size > 0x10000) { lua_pushnil(L); return 1; }
    char sa[32];
    snprintf(sa, sizeof(sa), "%llX", (unsigned long long)addr);
    auto r = ctx->ipc->send("read_memory", {{"address", sa}, {"size", size}});
    if (r.value("status", "") != "ok") { lua_pushnil(L); return 1; }
    std::string hex = r["data"].value("hex", "");
    if (hex.empty()) { lua_pushnil(L); return 1; }
    lua_pushstring(L, hex.c_str());
    return 1;
}

// read_u64(addr) -> integer or nil
static int l_read_u64(lua_State* L)
{
    auto* ctx = (LuaCtx*)lua_touserdata(L, lua_upvalueindex(1));
    if (!ctx || !ctx->ipc) { lua_pushnil(L); return 1; }
    uint64_t addr = (uint64_t)luaL_checkinteger(L, 1);
    char sa[32];
    snprintf(sa, sizeof(sa), "%llX", (unsigned long long)addr);
    auto r = ctx->ipc->send("read_memory", {{"address", sa}, {"size", 8}});
    if (r.value("status", "") != "ok") { lua_pushnil(L); return 1; }
    std::string hex = r["data"].value("hex", "");
    // hex format: "AA BB CC DD EE FF 00 11"
    uint64_t val = 0;
    int shift = 0, count = 0;
    for (size_t i = 0; i < hex.size() && count < 8; ++i) {
        if (hex[i] == ' ') continue;
        if (i + 1 >= hex.size()) break;
        unsigned byte = 0;
        if (sscanf(&hex[i], "%02X", &byte) == 1) {
            val |= (uint64_t)byte << shift;
            shift += 8;
            count++;
        }
        i++;
    }
    if (count < 8) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)val);
    return 1;
}

// set_clipboard(text)
static int l_set_clipboard(lua_State* L)
{
    const char* text = luaL_checkstring(L, 1);
    ImGui::SetClipboardText(text);
    return 0;
}

static void push_reg_ctx(lua_State* L, const VmpRegCtx& r)
{
    lua_createtable(L, 0, 18);
    auto set = [&](const char* k, uint64_t v) {
        lua_pushinteger(L, (lua_Integer)v);
        lua_setfield(L, -2, k);
    };
    set("rax", r.rax); set("rbx", r.rbx); set("rcx", r.rcx); set("rdx", r.rdx);
    set("rsi", r.rsi); set("rdi", r.rdi); set("rbp", r.rbp); set("rsp", r.rsp);
    set("r8",  r.r8);  set("r9",  r.r9);  set("r10", r.r10); set("r11", r.r11);
    set("r12", r.r12); set("r13", r.r13); set("r14", r.r14); set("r15", r.r15);
    set("rflags", r.rflags);
    lua_pushboolean(L, r.valid);
    lua_setfield(L, -2, "valid");
}

static void push_varnode(lua_State* L, const VmpVarnode& vn)
{
    lua_createtable(L, 0, 4);
    lua_pushstring(L, vn.space.c_str());     lua_setfield(L, -2, "space");
    lua_pushinteger(L, (lua_Integer)vn.offset); lua_setfield(L, -2, "offset");
    lua_pushinteger(L, vn.size);             lua_setfield(L, -2, "size");
    lua_pushstring(L, vn.reg_name.c_str());  lua_setfield(L, -2, "reg_name");
}

static void push_pcode(lua_State* L, const std::vector<VmpPcodeOp>& ops)
{
    lua_createtable(L, (int)ops.size(), 0);
    for (int i = 0; i < (int)ops.size(); ++i) {
        auto& op = ops[i];
        lua_createtable(L, 0, 6);

        lua_pushinteger(L, op.opc);          lua_setfield(L, -2, "opc");
        lua_pushstring(L, op.opc_name.c_str()); lua_setfield(L, -2, "opc_name");
        lua_pushboolean(L, op.has_out);      lua_setfield(L, -2, "has_out");
        lua_pushboolean(L, op.dead);         lua_setfield(L, -2, "dead");

        if (op.has_out) {
            push_varnode(L, op.out);
            lua_setfield(L, -2, "out");
        }

        lua_createtable(L, (int)op.ins.size(), 0);
        for (int j = 0; j < (int)op.ins.size(); ++j) {
            push_varnode(L, op.ins[j]);
            lua_rawseti(L, -2, j + 1);
        }
        lua_setfield(L, -2, "ins");

        lua_rawseti(L, -2, i + 1);
    }
}

static void push_stack(lua_State* L, const std::vector<VmpStackEntry>& stk)
{
    lua_createtable(L, (int)stk.size(), 0);
    for (int i = 0; i < (int)stk.size(); ++i) {
        lua_createtable(L, 0, 4);
        lua_pushinteger(L, (lua_Integer)stk[i].offset); lua_setfield(L, -2, "offset");
        lua_pushinteger(L, (lua_Integer)stk[i].addr);   lua_setfield(L, -2, "addr");
        lua_pushinteger(L, (lua_Integer)stk[i].value);  lua_setfield(L, -2, "value");
        lua_pushboolean(L, stk[i].is_rsp);              lua_setfield(L, -2, "is_rsp");
        lua_rawseti(L, -2, i + 1);
    }
}

static void push_operands(lua_State* L, const std::vector<VmpX86Operand>& ops)
{
    lua_createtable(L, (int)ops.size(), 0);
    for (int i = 0; i < (int)ops.size(); ++i) {
        auto& op = ops[i];
        lua_createtable(L, 0, 8);
        lua_pushstring(L, op.type.c_str());       lua_setfield(L, -2, "type");
        lua_pushinteger(L, op.size);               lua_setfield(L, -2, "size");
        if (op.type == "reg") {
            lua_pushstring(L, op.reg.c_str());     lua_setfield(L, -2, "reg");
        } else if (op.type == "imm") {
            lua_pushinteger(L, (lua_Integer)op.imm); lua_setfield(L, -2, "imm");
        } else if (op.type == "mem") {
            lua_pushstring(L, op.mem_base.c_str());  lua_setfield(L, -2, "mem_base");
            lua_pushstring(L, op.mem_index.c_str()); lua_setfield(L, -2, "mem_index");
            lua_pushinteger(L, op.mem_scale);        lua_setfield(L, -2, "mem_scale");
            lua_pushinteger(L, (lua_Integer)op.mem_disp); lua_setfield(L, -2, "mem_disp");
        }
        lua_rawseti(L, -2, i + 1);
    }
}

std::string vmp_run_lua(const std::string& script_path,
                        VmpAnalysisResult& res,
                        IpcClient& ipc,
                        const std::function<void(const std::string&)>& log_fn,
                        int context_row)
{
    lua_State* L = luaL_newstate();
    if (!L) return "failed to create Lua state";
    luaL_openlibs(L);

    LuaCtx ctx{&res, &ipc, log_fn};

    // log(msg)
    lua_pushlightuserdata(L, &ctx);
    lua_pushcclosure(L, l_log, 1);
    lua_setglobal(L, "log");

    // read_mem(addr, size) -> hex string or nil
    lua_pushlightuserdata(L, &ctx);
    lua_pushcclosure(L, l_read_mem, 1);
    lua_setglobal(L, "read_mem");

    // read_u64(addr) -> integer or nil
    lua_pushlightuserdata(L, &ctx);
    lua_pushcclosure(L, l_read_u64, 1);
    lua_setglobal(L, "read_u64");

    // set_clipboard(text)
    lua_pushcfunction(L, l_set_clipboard);
    lua_setglobal(L, "set_clipboard");

    // context_row: 1-based index of right-clicked row, or nil
    if (context_row >= 0 && context_row < (int)res.rows.size())
        lua_pushinteger(L, context_row + 1);
    else
        lua_pushnil(L);
    lua_setglobal(L, "context_row");

    // globals: vmCode_reg, vmStack_reg, vmRegBase
    lua_pushstring(L, res.vmCode_reg.c_str());  lua_setglobal(L, "vmCode_reg");
    lua_pushstring(L, res.vmStack_reg.c_str()); lua_setglobal(L, "vmStack_reg");
    lua_pushinteger(L, (lua_Integer)res.vmRegBase); lua_setglobal(L, "vmRegBase");
    lua_pushinteger(L, res.total_insns);        lua_setglobal(L, "total_insns");
    lua_pushinteger(L, res.junk_insns);         lua_setglobal(L, "junk_insns");

    // handlers table
    lua_createtable(L, (int)res.handlers.size(), 0);
    for (int hi = 0; hi < (int)res.handlers.size(); ++hi) {
        auto& h = res.handlers[hi];
        lua_createtable(L, 0, 7);
        lua_pushinteger(L, h.seg_idx);           lua_setfield(L, -2, "seg_idx");
        lua_pushstring(L, h.type.c_str());       lua_setfield(L, -2, "type");
        lua_pushstring(L, h.detail.c_str());     lua_setfield(L, -2, "detail");
        lua_pushinteger(L, (lua_Integer)h.addr_start); lua_setfield(L, -2, "addr_start");
        lua_pushinteger(L, (lua_Integer)h.addr_end);   lua_setfield(L, -2, "addr_end");
        lua_pushinteger(L, h.live_stores);       lua_setfield(L, -2, "live_stores");
        lua_pushinteger(L, h.live_loads);         lua_setfield(L, -2, "live_loads");
        lua_pushstring(L, h.summary.c_str());    lua_setfield(L, -2, "summary");

        lua_createtable(L, (int)h.row_indices.size(), 0);
        for (int ri = 0; ri < (int)h.row_indices.size(); ++ri) {
            lua_pushinteger(L, h.row_indices[ri] + 1);
            lua_rawseti(L, -2, ri + 1);
        }
        lua_setfield(L, -2, "row_indices");

        lua_rawseti(L, -2, hi + 1);
    }
    lua_setglobal(L, "handlers");

    // rows table
    lua_createtable(L, (int)res.rows.size(), 0);
    for (int i = 0; i < (int)res.rows.size(); ++i) {
        auto& row = res.rows[i];
        lua_createtable(L, 0, 14);

        lua_pushinteger(L, (lua_Integer)row.addr);   lua_setfield(L, -2, "addr");
        lua_pushinteger(L, row.seg_idx + 1);         lua_setfield(L, -2, "seg_idx");
        lua_pushinteger(L, row.global_idx);          lua_setfield(L, -2, "step");
        lua_pushstring(L, row.asm_text.c_str());     lua_setfield(L, -2, "asm");
        lua_pushstring(L, row.bytes_str.c_str());    lua_setfield(L, -2, "bytes");
        lua_pushboolean(L, row.is_junk);             lua_setfield(L, -2, "is_junk");
        lua_pushboolean(L, row.has_deobf);           lua_setfield(L, -2, "has_deobf");
        lua_pushstring(L, row.analysis.c_str());     lua_setfield(L, -2, "analysis");

        push_reg_ctx(L, row.regs);                   lua_setfield(L, -2, "regs");
        if (row.has_deobf) {
            push_reg_ctx(L, row.regs_deobf);         lua_setfield(L, -2, "regs_deobf");
        }

        push_stack(L, row.stack);                    lua_setfield(L, -2, "stack");
        if (row.has_deobf && !row.stack_deobf.empty()) {
            push_stack(L, row.stack_deobf);          lua_setfield(L, -2, "stack_deobf");
        }

        push_pcode(L, row.pcode);                    lua_setfield(L, -2, "pcode");

        lua_pushstring(L, row.mnemonic.c_str());     lua_setfield(L, -2, "mnemonic");
        push_operands(L, row.operands);              lua_setfield(L, -2, "operands");

        lua_rawseti(L, -2, i + 1);
    }
    lua_setglobal(L, "rows");

    // execute script
    int err = luaL_dofile(L, script_path.c_str());
    std::string errmsg;
    if (err != LUA_OK) {
        errmsg = lua_tostring(L, -1);
        lua_close(L);
        return errmsg;
    }

    // read back: check global 'writeback' table for field list
    // default: {"analysis"}, supported: analysis, is_junk, summary
    bool wb_analysis = true;
    bool wb_is_junk  = false;
    bool wb_summary  = false;

    lua_getglobal(L, "writeback");
    if (lua_istable(L, -1)) {
        wb_analysis = false;
        int wbn = (int)lua_rawlen(L, -1);
        for (int wi = 1; wi <= wbn; ++wi) {
            lua_rawgeti(L, -1, wi);
            if (lua_isstring(L, -1)) {
                const char* f = lua_tostring(L, -1);
                if (strcmp(f, "analysis") == 0) wb_analysis = true;
                else if (strcmp(f, "is_junk") == 0) wb_is_junk = true;
                else if (strcmp(f, "summary") == 0) wb_summary = true;
                else log_fn(std::string("[warn] [C++] writeback: unknown field '") + f + "', ignored");
            }
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);

    std::string wb_fields;
    if (wb_analysis) { if (!wb_fields.empty()) wb_fields += ", "; wb_fields += "analysis"; }
    if (wb_is_junk)  { if (!wb_fields.empty()) wb_fields += ", "; wb_fields += "is_junk"; }
    if (wb_summary)  { if (!wb_fields.empty()) wb_fields += ", "; wb_fields += "summary"; }
    log_fn("[C++] writeback fields: " + (wb_fields.empty() ? "(none)" : wb_fields));

    lua_getglobal(L, "rows");
    if (lua_istable(L, -1)) {
        for (int i = 0; i < (int)res.rows.size(); ++i) {
            lua_rawgeti(L, -1, i + 1);
            if (lua_istable(L, -1)) {
                if (wb_analysis) {
                    lua_getfield(L, -1, "analysis");
                    if (lua_isstring(L, -1))
                        res.rows[i].analysis = lua_tostring(L, -1);
                    lua_pop(L, 1);
                }
                if (wb_is_junk) {
                    lua_getfield(L, -1, "is_junk");
                    if (lua_isboolean(L, -1))
                        res.rows[i].is_junk = lua_toboolean(L, -1);
                    lua_pop(L, 1);
                }
            }
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);

    // read back handlers[].summary
    if (wb_summary) {
        lua_getglobal(L, "handlers");
        if (lua_istable(L, -1)) {
            for (int i = 0; i < (int)res.handlers.size(); ++i) {
                lua_rawgeti(L, -1, i + 1);
                if (lua_istable(L, -1)) {
                    lua_getfield(L, -1, "summary");
                    if (lua_isstring(L, -1))
                        res.handlers[i].summary = lua_tostring(L, -1);
                    lua_pop(L, 1);
                }
                lua_pop(L, 1);
            }
        }
        lua_pop(L, 1);
    }

    lua_close(L);
    return "";
}
