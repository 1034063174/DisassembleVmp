#pragma once

#include <string>
#include <thread>
#include <atomic>

namespace deobf {

class IpcServer {
public:
    IpcServer();
    ~IpcServer();

    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    bool start(const std::string& pipe_name);
    void stop();
    bool isRunning() const;
    const std::string& pipeName() const { return pipe_name_; }

private:
    void serverThread();
    void handleClient(void* pipe_handle);
    bool sendMessage(void* pipe, const std::string& msg);
    bool recvMessage(void* pipe, std::string& msg);

    std::string pipe_name_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    void* stop_event_ = nullptr;
};

} // namespace deobf
