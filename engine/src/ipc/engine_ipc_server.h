#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <nlohmann/json.hpp>

class EngineIpcServer {
public:
    using CmdHandler = std::function<nlohmann::json(const std::string& cmd, const nlohmann::json& params)>;

    void start(const std::string& pipe_name, CmdHandler handler);
    void stop();
    bool isRunning() const { return running_; }

private:
    void serverLoop();

    std::string pipe_name_;
    CmdHandler handler_;
    std::atomic<bool> running_{false};
    std::thread thread_;
};
