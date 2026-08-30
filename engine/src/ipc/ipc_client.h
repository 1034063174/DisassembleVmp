#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

// Named Pipe IPC 客户端，与 x64dbg 内的 x64deobf 插件通信
class IpcClient {
public:
    bool isConnected() const { return connected_; }

    void setPipeName(const std::string& name) { pipe_name_ = name; }
    const std::string& pipeName() const { return pipe_name_; }

    nlohmann::json send(const std::string& cmd, const nlohmann::json& params = {});

    nlohmann::json ping();
    nlohmann::json getContext();
    nlohmann::json analyze(int count = 100);
    nlohmann::json nopAllJunk();
    nlohmann::json undoAll();
    nlohmann::json listPasses();
    nlohmann::json setPass(const std::string& name, bool enabled);

    static std::vector<std::string> scanPipes();

private:
    bool connected_ = false;
    std::string pipe_name_ = "\\\\.\\pipe\\x64deobf_0";
};
