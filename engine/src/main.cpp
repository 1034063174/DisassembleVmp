// x64deobf UI - DX11 + ImGui 入口
// 独立进程，通过 Named Pipe 与 x64dbg 插件通信

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include <windowsx.h>
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")
#include "ui/ui_main.h"

static ID3D11Device*           g_pd3dDevice = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*         g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

static void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

static void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

static bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd,
        &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ImGui 每帧更新：鼠标是否悬停在假标题栏拖动区
bool g_titlebar_hovered = false;

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_NCHITTEST: {
        // 手动检测8方向缩放边框（因为 WM_NCCALCSIZE=0 后系统不再识别）
        const int BORDER = 6;
        RECT rc;
        GetWindowRect(hWnd, &rc);
        int x = GET_X_LPARAM(lParam);
        int y = GET_Y_LPARAM(lParam);
        bool left   = x < rc.left   + BORDER;
        bool right  = x >= rc.right  - BORDER;
        bool top    = y < rc.top    + BORDER;
        bool bottom = y >= rc.bottom - BORDER;
        if (left  && top)    return HTTOPLEFT;
        if (right && top)    return HTTOPRIGHT;
        if (left  && bottom) return HTBOTTOMLEFT;
        if (right && bottom) return HTBOTTOMRIGHT;
        if (left)            return HTLEFT;
        if (right)           return HTRIGHT;
        if (top)             return HTTOP;
        if (bottom)          return HTBOTTOM;
        // 标题栏拖动区由 ImGui 决定
        extern bool g_titlebar_hovered;
        if (g_titlebar_hovered) return HTCAPTION;
        return HTCLIENT;
    }
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) return 0;
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"x64deobf_ui";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowW(wc.lpszClassName, L"x64dbg Deobfuscator",
        WS_POPUP,   // 纯 POPUP，无 WS_THICKFRAME，不会有隐式边框占位
        100, 100, 1300, 800, nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.FrameRounding = 3.0f;
    style.GrabRounding = 3.0f;

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // 加载中文字体（微软雅黑），支持中文显示
    ImFontConfig font_cfg;
    font_cfg.OversampleH = 1; font_cfg.OversampleV = 1;
    static const ImWchar ranges[] = {
        0x0020, 0x00FF, // 基本拉丁 + Latin-1
        0x2190, 0x21FF, // 箭头（↑等）
        0x4E00, 0x9FAF, // CJK 常用汉字
        0x3000, 0x303F, // CJK 标点
        0xFF00, 0xFFEF, // 全角字符
        0,
    };
    const char* font_path = "C:\\Windows\\Fonts\\msyh.ttc";
    if (FILE* f = fopen(font_path, "rb")) {
        fclose(f);
        io.Fonts->AddFontFromFileTTF(font_path, 14.0f, &font_cfg, ranges);
    } else {
        io.Fonts->AddFontDefault();
    }

    UiMain ui;
    ui.init(hwnd);

    ImVec4 clear_color = ImVec4(0.06f, 0.06f, 0.09f, 1.00f);
    bool done = false;

    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done) break;

        // 每帧用 GetClientRect 对齐 swap chain，避免 WM_SIZE 尺寸与实际渲染区不一致
        {
            RECT cr;
            GetClientRect(hwnd, &cr);
            UINT cw = cr.right  - cr.left;
            UINT ch = cr.bottom - cr.top;

            DXGI_SWAP_CHAIN_DESC sd;
            g_pSwapChain->GetDesc(&sd);
            if (cw > 0 && ch > 0 && (cw != sd.BufferDesc.Width || ch != sd.BufferDesc.Height)) {
                CleanupRenderTarget();
                g_pSwapChain->ResizeBuffers(0, cw, ch, DXGI_FORMAT_UNKNOWN, 0);
                CreateRenderTarget();
            }
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ui.render();

        ImGui::Render();
        const float clear_color_with_alpha[4] = {
            clear_color.x * clear_color.w, clear_color.y * clear_color.w,
            clear_color.z * clear_color.w, clear_color.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        g_pSwapChain->Present(1, 0); // VSync
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}
