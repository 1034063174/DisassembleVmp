#include "plugin.h"
#include "ipc/ipc_server.h"
#include "ipc/ipc_protocol.h"
#include "utils/logger.h"

static deobf::IpcServer g_ipc_server;

enum MenuIds { MENU_START_IPC = 0, MENU_STOP_IPC };

static void cbMenuEntry(CBTYPE, void* info)
{
    auto* entry = static_cast<PLUG_CB_MENUENTRY*>(info);
    switch (entry->hEntry) {
    case MENU_START_IPC: {
        std::string pn = std::string(deobf::PIPE_PREFIX) + std::to_string(GetCurrentProcessId());
        g_ipc_server.start(pn);
        break;
    }
    case MENU_STOP_IPC: g_ipc_server.stop(); break;
    }
}

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    deobf::logger::info("Plugin initializing (handle: %d)", pluginHandle);
    _plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);
    return true;
}

void pluginStop()
{
    g_ipc_server.stop();
}

void pluginSetup()
{
    _plugin_menuaddentry(hMenu, MENU_START_IPC, "Start IPC Server");
    _plugin_menuaddentry(hMenu, MENU_STOP_IPC,  "Stop IPC Server");
    std::string pipe_name = std::string(deobf::PIPE_PREFIX) + std::to_string(GetCurrentProcessId());
    g_ipc_server.start(pipe_name);
    deobf::logger::info("Plugin ready (pipe: %s)", pipe_name.c_str());
}
