#include "ipc_client.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using json = nlohmann::json;

json IpcClient::send(const std::string& cmd, const json& params)
{
    connected_ = false;

    std::wstring wpipe(pipe_name_.begin(), pipe_name_.end());
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int retry = 0; retry < 8; ++retry) {
        pipe = CreateFileW(wpipe.c_str(), GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY)
            WaitNamedPipeW(wpipe.c_str(), 200);
        else
            Sleep(25); // 管道实例正在重建，稍等
    }
    if (pipe == INVALID_HANDLE_VALUE)
        return {{"status", "error"}, {"error", {{"code", "CONNECT_FAILED"}, {"message", "Cannot connect to plugin pipe"}}}};

    connected_ = true;

    json request = {{"cmd", cmd}};
    if (!params.empty())
        request["params"] = params;

    std::string req_str = request.dump();
    uint32_t len = (uint32_t)req_str.size();
    DWORD written;
    WriteFile(pipe, &len, sizeof(len), &written, nullptr);
    WriteFile(pipe, req_str.data(), len, &written, nullptr);

    // 读响应
    uint32_t resp_len = 0;
    DWORD bytesRead;
    ReadFile(pipe, &resp_len, sizeof(resp_len), &bytesRead, nullptr);
    if (bytesRead != sizeof(resp_len) || resp_len > 10 * 1024 * 1024) {
        CloseHandle(pipe);
        return {{"status", "error"}, {"error", {{"code", "READ_FAILED"}, {"message", "Failed to read response"}}}};
    }

    std::string resp_str(resp_len, '\0');
    ReadFile(pipe, &resp_str[0], resp_len, &bytesRead, nullptr);
    CloseHandle(pipe);

    try {
        return json::parse(resp_str);
    } catch (...) {
        return {{"status", "error"}, {"error", {{"code", "PARSE_FAILED"}, {"message", "Failed to parse response"}}}};
    }
}

json IpcClient::ping() { return send("ping"); }
json IpcClient::getContext() { return send("get_context"); }
json IpcClient::analyze(int count) { return send("analyze", {{"count", count}}); }
json IpcClient::nopAllJunk() { return send("nop_all_junk"); }
json IpcClient::undoAll() { return send("undo_all"); }
json IpcClient::listPasses() { return send("list_passes"); }
json IpcClient::setPass(const std::string& name, bool enabled) {
    return send("set_pass", {{"name", name}, {"enabled", enabled}});
}

std::vector<std::string> IpcClient::scanPipes()
{
    std::vector<std::string> result;
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(L"\\\\.\\pipe\\x64deobf_*", &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return result;
    do {
        char narrow[512];
        WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, narrow, sizeof(narrow), nullptr, nullptr);
        result.push_back(std::string("\\\\.\\pipe\\") + narrow);
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return result;
}
