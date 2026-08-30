#pragma once

#include <string>

namespace deobf {

constexpr const char* CMD_PING          = "ping";
constexpr const char* CMD_GET_CONTEXT   = "get_context";
constexpr const char* CMD_READ_MEMORY   = "read_memory";
constexpr const char* CMD_NOP_ADDRESSES = "nop_addresses";

constexpr const char* ERR_NOT_DEBUGGING = "NOT_DEBUGGING";
constexpr const char* ERR_NOT_PAUSED    = "NOT_PAUSED";
constexpr const char* ERR_UNKNOWN_CMD   = "UNKNOWN_CMD";

constexpr const char* PIPE_PREFIX = "\\\\.\\pipe\\x64deobf_";
constexpr int PIPE_BUFFER_SIZE  = 65536;

} // namespace deobf
