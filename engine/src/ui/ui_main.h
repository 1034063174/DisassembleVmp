#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../ipc/ipc_client.h"
#include "../vmp/vmp_analyzer.h"
#include "imgui.h"
#include <nlohmann/json.hpp>
#include <vector>
#include <string>

struct ImGuiContext;
struct ImGuiSettingsHandler;
struct ImGuiTextBuffer;

class UiMain {
public:
    void init(HWND hwnd);
    void render();

private:
    friend void SettingsHandler_ReadLine(ImGuiContext*, ImGuiSettingsHandler*, void*, const char*);
    friend void SettingsHandler_WriteAll(ImGuiContext*, ImGuiSettingsHandler*, ImGuiTextBuffer*);

    // ── VMP分析 tab ───────────────────────────────── ui_vmp.cpp
    void renderVmpTab();

    // ── 通用 ─────────────────────────────────────── ui_main.cpp
    void addLog(const char* fmt, ...);

    // ── 连接栏状态（共用）────────────────────────────────────────
    IpcClient ipc_;
    char pipe_buf_[256] = "\\\\.\\pipe\\x64deobf_0";
    std::vector<std::string> available_pipes_;
    HWND hwnd_ = nullptr;
    std::vector<std::string> log_;

    // ── VMP分析 tab 状态 ─────────────────────────────────────────
    VmpAnalysisResult vmp_result_;
    char   vmp_sla_buf_[512]     = "specfiles\\x86-64.sla";
    int    vmp_step_count_       = 2000;
    int    vmp_selected_handler_ = -1;
    int    vmp_selected_row_     = -1;
    bool   vmp_hide_junk_        = false;
    bool   vmp_hide_jmp_imm_     = false;
    bool   vmp_ignore_eflag_     = true;
    std::string vmp_status_      = "就绪";
    struct LuaSlot {
        char name[64]  = "";
        char path[512] = "";
    };
    static constexpr int LUA_SLOT_COUNT = 10;
    LuaSlot vmp_lua_slots_[LUA_SLOT_COUNT] = {
        {"annotate", "scripts\\annotate.lua"},
        {"Lua2", "scripts\\lua2.lua"},
        {"Lua3", "scripts\\lua3.lua"},
        {"Lua4", "scripts\\lua4.lua"},
        {"Lua5", "scripts\\lua5.lua"},
        {"Lua6", "scripts\\lua6.lua"},
        {"Lua7", "scripts\\lua7.lua"},
        {"Lua8", "scripts\\lua8.lua"},
        {"Lua9", "scripts\\lua9.lua"},
        {"Lua10", "scripts\\lua10.lua"},
    };
    int    vmp_lua_edit_slot_   = -1;
    std::vector<std::string> vmp_lua_log_;
    bool   vmp_lua_log_scroll_   = true;

    // ── 栈基准地址 ──────────────────────────────────────────────
    bool   vmp_stack_custom_base_ = false;
    char   vmp_stack_base_buf_[24] = "0";

    // ── 窗口位置/大小持久化 ──────────────────────────────────────
    int  saved_win_x_ = 0, saved_win_y_ = 0;
    int  saved_win_w_ = 0, saved_win_h_ = 0;
    bool has_saved_win_ = false;
};
