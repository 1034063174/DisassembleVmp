// ui_main.cpp — 框架：init / addLog / render / 连接栏 / 自定义设置持久化
#include "ui_main.h"
#include "imgui.h"
#include "imgui_internal.h"
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdlib>

// ── ImGui 自定义设置持久化 ───────────────────────────────────────────────────

static UiMain* g_ui_for_settings = nullptr;

static void* SettingsHandler_ReadOpen(ImGuiContext*, ImGuiSettingsHandler*, const char* name)
{
    if (strcmp(name, "Main") == 0) return (void*)1;
    return nullptr;
}

static void SettingsHandler_ReadLine(ImGuiContext*, ImGuiSettingsHandler*, void* entry, const char* line)
{
    if (!entry || !g_ui_for_settings) return;
    auto* ui = g_ui_for_settings;
    int v;
    if (sscanf(line, "vmp_step_count=%d", &v) == 1)       { ui->vmp_step_count_ = v; return; }
    if (sscanf(line, "vmp_hide_junk=%d", &v) == 1)         { ui->vmp_hide_junk_ = (v != 0); return; }
    if (sscanf(line, "vmp_hide_jmp_imm=%d", &v) == 1)      { ui->vmp_hide_jmp_imm_ = (v != 0); return; }
    if (sscanf(line, "vmp_ignore_eflag=%d", &v) == 1)       { ui->vmp_ignore_eflag_ = (v != 0); return; }
    int si; char nbuf[64], pbuf[512];
    if (sscanf(line, "lua_slot%d_name=%63[^\n]", &si, nbuf) == 2 && si >= 0 && si < 5) {
        snprintf(ui->vmp_lua_slots_[si].name, sizeof(ui->vmp_lua_slots_[si].name), "%s", nbuf);
        return;
    }
    if (sscanf(line, "lua_slot%d_path=%511[^\n]", &si, pbuf) == 2 && si >= 0 && si < 5) {
        snprintf(ui->vmp_lua_slots_[si].path, sizeof(ui->vmp_lua_slots_[si].path), "%s", pbuf);
        return;
    }
    int x, y, w, h;
    if (sscanf(line, "win_rect=%d,%d,%d,%d", &x, &y, &w, &h) == 4) {
        if (w > 100 && w < 8000 && h > 100 && h < 5000) {
            ui->saved_win_x_ = x; ui->saved_win_y_ = y;
            ui->saved_win_w_ = w; ui->saved_win_h_ = h;
            ui->has_saved_win_ = true;
        }
        return;
    }
}

static void SettingsHandler_WriteAll(ImGuiContext* ctx, ImGuiSettingsHandler* handler, ImGuiTextBuffer* buf)
{
    if (!g_ui_for_settings) return;
    auto* ui = g_ui_for_settings;
    buf->appendf("[%s][Main]\n", handler->TypeName);
    buf->appendf("vmp_step_count=%d\n", ui->vmp_step_count_);
    buf->appendf("vmp_hide_junk=%d\n", ui->vmp_hide_junk_ ? 1 : 0);
    buf->appendf("vmp_hide_jmp_imm=%d\n", ui->vmp_hide_jmp_imm_ ? 1 : 0);
    buf->appendf("vmp_ignore_eflag=%d\n", ui->vmp_ignore_eflag_ ? 1 : 0);
    for (int i = 0; i < 5; ++i) {
        if (ui->vmp_lua_slots_[i].name[0])
            buf->appendf("lua_slot%d_name=%s\n", i, ui->vmp_lua_slots_[i].name);
        if (ui->vmp_lua_slots_[i].path[0])
            buf->appendf("lua_slot%d_path=%s\n", i, ui->vmp_lua_slots_[i].path);
    }
    if (ui->has_saved_win_ && ui->saved_win_w_ > 100 && ui->saved_win_h_ > 100)
        buf->appendf("win_rect=%d,%d,%d,%d\n",
                      ui->saved_win_x_, ui->saved_win_y_,
                      ui->saved_win_w_, ui->saved_win_h_);
    buf->appendf("\n");
}

void UiMain::init(HWND hwnd)
{
    hwnd_ = hwnd;

    g_ui_for_settings = this;
    ImGuiSettingsHandler ini_handler;
    memset(&ini_handler, 0, sizeof(ini_handler));
    ini_handler.TypeName = "x64deobf";
    ini_handler.TypeHash = ImHashStr("x64deobf");
    ini_handler.ReadOpenFn = SettingsHandler_ReadOpen;
    ini_handler.ReadLineFn = SettingsHandler_ReadLine;
    ini_handler.WriteAllFn = SettingsHandler_WriteAll;
    ImGui::GetCurrentContext()->SettingsHandlers.push_back(ini_handler);

    ImGui::LoadIniSettingsFromDisk(ImGui::GetIO().IniFilename);

    if (has_saved_win_ && saved_win_w_ > 100 && saved_win_h_ > 100
        && saved_win_w_ < 8000 && saved_win_h_ < 5000)
        SetWindowPos(hwnd, nullptr, saved_win_x_, saved_win_y_,
                     saved_win_w_, saved_win_h_, SWP_NOZORDER);

    ipc_.setPipeName(pipe_buf_);

    addLog("x64去混淆 UI 已启动");
    auto pipes = IpcClient::scanPipes();
    if (pipes.size() == 1) {
        snprintf(pipe_buf_, sizeof(pipe_buf_), "%s", pipes[0].c_str());
        ipc_.setPipeName(pipe_buf_);
        addLog("自动连接: %s", pipe_buf_);
    } else if (pipes.size() > 1) {
        addLog("检测到 %d 个实例，请手动选择:", (int)pipes.size());
        for (auto& p : pipes) addLog("  %s", p.c_str());
        available_pipes_ = std::move(pipes);
    } else {
        addLog("未检测到 x64deobf 插件实例");
    }
}

void UiMain::addLog(const char* fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    log_.push_back(buf);
    if (log_.size() > 500) log_.erase(log_.begin());
}

// 连接栏
static void renderConnectionBar(IpcClient& ipc, char* pipe_buf, int pipe_buf_size,
                                 std::vector<std::string>& available_pipes,
                                 std::function<void(const char*)> log_fn)
{
    ImGui::TextColored(
        ipc.isConnected() ? ImVec4(0.2f,0.9f,0.2f,1) : ImVec4(0.9f,0.3f,0.3f,1),
        ipc.isConnected() ? "[已连接]" : "[未连接]");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(260);
    if (ImGui::InputText("##pipe", pipe_buf, pipe_buf_size, ImGuiInputTextFlags_EnterReturnsTrue)) {
        ipc.setPipeName(pipe_buf);
        if (log_fn) log_fn((std::string("切换 Pipe: ") + pipe_buf).c_str());
    }
    ImGui::SameLine();
    if (ImGui::Button("扫描")) {
        available_pipes = IpcClient::scanPipes();
        if (available_pipes.empty()) {
            if (log_fn) log_fn("未找到 x64deobf 插件实例");
        } else {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "找到 %d 个实例:", (int)available_pipes.size());
            if (log_fn) log_fn(tmp);
            for (auto& p : available_pipes)
                if (log_fn) log_fn(("  " + p).c_str());
        }
        if (!available_pipes.empty())
            ImGui::OpenPopup("##pipelist");
    }
    if (ImGui::BeginPopup("##pipelist")) {
        for (auto& p : available_pipes) {
            if (ImGui::MenuItem(p.c_str())) {
                snprintf(pipe_buf, pipe_buf_size, "%s", p.c_str());
                ipc.setPipeName(pipe_buf);
                if (log_fn) log_fn(("已选择: " + p).c_str());
            }
        }
        ImGui::EndPopup();
    }
}

void UiMain::render()
{
    if (hwnd_ && IsWindow(hwnd_) && !IsIconic(hwnd_)) {
        RECT rc;
        GetWindowRect(hwnd_, &rc);
        int w = (int)(rc.right - rc.left);
        int h = (int)(rc.bottom - rc.top);
        if (w > 100 && w < 8000 && h > 100 && h < 5000) {
            saved_win_x_ = (int)rc.left;
            saved_win_y_ = (int)rc.top;
            saved_win_w_ = w;
            saved_win_h_ = h;
            has_saved_win_ = true;
        }
    }

    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,    ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::Begin("##main", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove     | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus);
    ImGui::PopStyleVar(2);

    // ── 假标题栏：拖动区 + 最小化 + 关闭 ──────────────────────────────────
    {
        extern bool g_titlebar_hovered;

        float bar_h  = 26.0f;
        ImVec2 bar_pos = ImGui::GetCursorScreenPos();
        float  bar_w   = ImGui::GetContentRegionAvail().x;
        float  btn_w   = 36.0f;
        float  drag_w  = bar_w - btn_w * 2 - 4.0f;

        ImGui::InvisibleButton("##titlebar_drag", ImVec2(drag_w, bar_h));
        g_titlebar_hovered = ImGui::IsItemHovered();

        if (g_titlebar_hovered && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            if (IsZoomed(hwnd_)) ShowWindow(hwnd_, SW_RESTORE);
            else                  ShowWindow(hwnd_, SW_MAXIMIZE);
        }

        ImGui::GetWindowDrawList()->AddText(
            ImVec2(bar_pos.x + 8, bar_pos.y + 6),
            IM_COL32(200, 200, 200, 255),
            "x64dbg 去混淆工具");

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0,0,0,0));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f,0.3f,0.3f,1));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.5f,0.5f,0.5f,1));
        if (ImGui::Button("-##min", ImVec2(btn_w, bar_h)))
            ShowWindow(hwnd_, SW_MINIMIZE);
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f,0.15f,0.15f,1));
        if (ImGui::Button("X##close", ImVec2(btn_w, bar_h)))
            PostMessage(hwnd_, WM_CLOSE, 0, 0);
        ImGui::PopStyleColor(4);

        ImGui::Separator();
    }

    renderConnectionBar(ipc_, pipe_buf_, sizeof(pipe_buf_), available_pipes_,
        [this](const char* msg){ addLog("%s", msg); });

    ImGui::Separator();

    renderVmpTab();

    ImGui::End();
}
