#include "ipc_server.h"
#include "ipc_protocol.h"
#include "ipc_handler.h"
#include "../utils/logger.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>

namespace deobf {

IpcServer::IpcServer()
{
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

IpcServer::~IpcServer()
{
    stop();
    if (stop_event_)
        CloseHandle(stop_event_);
}

bool IpcServer::start(const std::string& pipe_name)
{
    if (running_)
        return true;

    pipe_name_ = pipe_name;
    ResetEvent((HANDLE)stop_event_);
    running_ = true;
    thread_ = std::thread(&IpcServer::serverThread, this);
    logger::info("IPC server started on %s", pipe_name_.c_str());
    return true;
}

void IpcServer::stop()
{
    if (!running_)
        return;

    running_ = false;
    SetEvent((HANDLE)stop_event_);

    // Create a dummy connection to unblock ConnectNamedPipe
    HANDLE dummy = CreateFileA(pipe_name_.c_str(), GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (dummy != INVALID_HANDLE_VALUE)
        CloseHandle(dummy);

    if (thread_.joinable())
        thread_.join();

    logger::info("IPC server stopped");
}

bool IpcServer::isRunning() const
{
    return running_;
}

bool IpcServer::sendMessage(void* pipe, const std::string& msg)
{
    uint32_t len = (uint32_t)msg.size();
    DWORD written;

    if (!WriteFile((HANDLE)pipe, &len, sizeof(len), &written, nullptr))
        return false;
    if (!WriteFile((HANDLE)pipe, msg.data(), len, &written, nullptr))
        return false;

    return true;
}

bool IpcServer::recvMessage(void* pipe, std::string& msg)
{
    uint32_t len = 0;
    DWORD bytesRead;

    if (!ReadFile((HANDLE)pipe, &len, sizeof(len), &bytesRead, nullptr))
        return false;
    if (bytesRead != sizeof(len))
        return false;
    if (len > 1024 * 1024) // 1MB limit
        return false;

    msg.resize(len);
    if (!ReadFile((HANDLE)pipe, &msg[0], len, &bytesRead, nullptr))
        return false;
    if (bytesRead != len)
        return false;

    return true;
}

void IpcServer::handleClient(void* pipe_handle)
{
    HANDLE pipe = (HANDLE)pipe_handle;
    logger::info("IPC client connected");

    while (running_) {
        std::string request;
        if (!recvMessage(pipe, request))
            break;

        std::string response = deobf::handleCommand(request);
        if (!sendMessage(pipe, response))
            break;
    }

    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    logger::info("IPC client disconnected");
}

void IpcServer::serverThread()
{
    while (running_) {
        HANDLE pipe = CreateNamedPipeA(
            pipe_name_.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            nullptr
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            logger::error("Failed to create named pipe, error: %d", GetLastError());
            break;
        }

        BOOL connected = ConnectNamedPipe(pipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            if (!running_) break;
            continue;
        }

        if (!running_) {
            CloseHandle(pipe);
            break;
        }

        handleClient(pipe);
    }
}

} // namespace deobf
