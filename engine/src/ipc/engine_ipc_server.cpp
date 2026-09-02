#include "engine_ipc_server.h"

using json = nlohmann::json;

void EngineIpcServer::start(const std::string& pipe_name, CmdHandler handler)
{
    if (running_) return;
    pipe_name_ = pipe_name;
    handler_ = handler;
    running_ = true;
    thread_ = std::thread(&EngineIpcServer::serverLoop, this);
}

void EngineIpcServer::stop()
{
    running_ = false;
    // 连一次管道让阻塞的 ConnectNamedPipe 返回
    std::wstring wp(pipe_name_.begin(), pipe_name_.end());
    HANDLE h = CreateFileW(wp.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (thread_.joinable()) thread_.join();
}

void EngineIpcServer::serverLoop()
{
    std::wstring wp(pipe_name_.begin(), pipe_name_.end());

    while (running_) {
        HANDLE pipe = CreateNamedPipeW(wp.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 4096, 4096, 0, nullptr);

        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected || !running_) {
            CloseHandle(pipe);
            continue;
        }

        // 读请求: [4字节长度][JSON]
        uint32_t req_len = 0;
        DWORD bytesRead;
        if (!ReadFile(pipe, &req_len, sizeof(req_len), &bytesRead, nullptr) ||
            bytesRead != sizeof(req_len) || req_len > 10 * 1024 * 1024) {
            CloseHandle(pipe);
            continue;
        }

        std::string req_str(req_len, '\0');
        if (!ReadFile(pipe, &req_str[0], req_len, &bytesRead, nullptr)) {
            CloseHandle(pipe);
            continue;
        }

        // 解析并处理
        json response;
        try {
            json request = json::parse(req_str);
            std::string cmd = request.value("cmd", "");
            json params = request.value("params", json::object());
            response = handler_(cmd, params);
        } catch (const std::exception& e) {
            response = {{"status", "error"}, {"error", e.what()}};
        }

        // 写响应: [4字节长度][JSON]
        std::string resp_str = response.dump();
        uint32_t resp_len = (uint32_t)resp_str.size();
        DWORD written;
        WriteFile(pipe, &resp_len, sizeof(resp_len), &written, nullptr);
        WriteFile(pipe, resp_str.data(), resp_len, &written, nullptr);
        FlushFileBuffers(pipe);

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}
