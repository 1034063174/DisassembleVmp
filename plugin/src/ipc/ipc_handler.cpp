#include "ipc_handler.h"
#include "ipc_protocol.h"
#include "../core/snapshot.h"
#include "../pluginmain.h"

#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

namespace deobf {

static std::string toHex(uint64_t v)
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << v;
    return ss.str();
}

static json makeError(const char* code, const std::string& message)
{
    return {{"status", "error"}, {"error", {{"code", code}, {"message", message}}}};
}

static json handlePing()
{
    return {{"status", "ok"}, {"data", {{"version", PLUGIN_VERSION}, {"name", PLUGIN_NAME}}}};
}

static json handleGetContext()
{
    SnapshotData snap;
    if (!takeSnapshot(snap)) {
        if (!snap.is_debugging) return makeError(ERR_NOT_DEBUGGING, "No active debugging session");
        if (!snap.is_paused) return makeError(ERR_NOT_PAUSED, "Target is running");
        return makeError("SNAPSHOT_FAIL", "Failed to take snapshot");
    }
    json regs;
    regs["rax"] = toHex(snap.rax); regs["rbx"] = toHex(snap.rbx);
    regs["rcx"] = toHex(snap.rcx); regs["rdx"] = toHex(snap.rdx);
    regs["rsi"] = toHex(snap.rsi); regs["rdi"] = toHex(snap.rdi);
    regs["rbp"] = toHex(snap.rbp); regs["rsp"] = toHex(snap.rsp);
    regs["r8"]  = toHex(snap.r8);  regs["r9"]  = toHex(snap.r9);
    regs["r10"] = toHex(snap.r10); regs["r11"] = toHex(snap.r11);
    regs["r12"] = toHex(snap.r12); regs["r13"] = toHex(snap.r13);
    regs["r14"] = toHex(snap.r14); regs["r15"] = toHex(snap.r15);
    regs["rflags"] = toHex(snap.rflags);
    return {{"status", "ok"}, {"data", {{"rip", toHex(snap.rip)}, {"module", snap.module_name},
        {"is_debugging", snap.is_debugging}, {"is_paused", snap.is_paused}, {"registers", regs}}}};
}

static json handleReadMemory(const json& params)
{
    if (!DbgIsDebugging()) return makeError(ERR_NOT_DEBUGGING, "No active debugging session");
    if (DbgIsRunning())    return makeError(ERR_NOT_PAUSED, "Target is running");

    std::string addr_str = params.value("address", "");
    int size = params.value("size", 64);
    if (size < 1)    size = 1;
    if (size > 65536) size = 65536;

    uint64_t addr = 0;
    try { addr = std::stoull(addr_str, nullptr, 16); }
    catch (...) { return makeError("INVALID_PARAM", "Invalid address: " + addr_str); }

    std::vector<uint8_t> buf(size, 0);
    if (!DbgMemRead(addr, buf.data(), (duint)size))
        return makeError("READ_FAILED", "DbgMemRead failed at 0x" + addr_str);

    std::ostringstream hex_ss;
    for (int i = 0; i < size; i++) {
        hex_ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)buf[i];
        if (i + 1 < size) hex_ss << " ";
    }
    return {{"status", "ok"}, {"data", {{"address", toHex(addr)}, {"size", size}, {"hex", hex_ss.str()}}}};
}

static json handleNopAddresses(const json& params)
{
    if (!DbgIsDebugging()) return makeError(ERR_NOT_DEBUGGING, "No active debugging session");
    if (DbgIsRunning())    return makeError(ERR_NOT_PAUSED, "Target is running");

    if (!params.contains("addresses") || !params["addresses"].is_array())
        return makeError("INVALID_PARAM", "Missing 'addresses' array");

    int patched = 0;
    std::vector<uint8_t> nops;
    for (auto& e : params["addresses"]) {
        uint64_t addr = 0;
        try { addr = std::stoull(e.value("addr", ""), nullptr, 16); }
        catch (...) { continue; }
        int sz = e.value("size", 1);
        if (sz < 1 || sz > 128) continue;
        nops.assign(sz, 0x90);
        if (DbgMemWrite(addr, nops.data(), (duint)sz)) patched++;
    }
    return {{"status","ok"},{"data",{{"patched", patched}}}};
}

std::string handleCommand(const std::string& json_str)
{
    json response;
    try {
        json request = json::parse(json_str);
        std::string cmd = request.value("cmd", "");
        json params = request.value("params", json::object());

        if (cmd == CMD_PING)              response = handlePing();
        else if (cmd == CMD_GET_CONTEXT)  response = handleGetContext();
        else if (cmd == CMD_READ_MEMORY)  response = handleReadMemory(params);
        else if (cmd == CMD_NOP_ADDRESSES) response = handleNopAddresses(params);
        else response = makeError(ERR_UNKNOWN_CMD, "Unknown command: " + cmd);
    } catch (const json::parse_error& e) {
        response = makeError("PARSE_ERROR", std::string("JSON parse error: ") + e.what());
    } catch (const std::exception& e) {
        response = makeError("INTERNAL_ERROR", std::string("Internal error: ") + e.what());
    }
    return response.dump();
}

} // namespace deobf
