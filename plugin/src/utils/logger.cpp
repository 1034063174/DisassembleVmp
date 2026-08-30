#include "logger.h"
#include "../pluginmain.h"
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>

namespace deobf {
namespace logger {

static FILE* g_logfile = nullptr;
static std::mutex g_mutex;

static void ensureFile()
{
    if (!g_logfile) {
        g_logfile = fopen("C:\\Users\\Admin\\Desktop\\x64deobf_debug.log", "a");
        if (g_logfile) {
            fprintf(g_logfile, "\n===== x64deobf log session started =====\n");
            fflush(g_logfile);
        }
    }
}

static void writeFile(const char* level, const char* buf)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    ensureFile();
    if (g_logfile) {
        time_t now = time(nullptr);
        struct tm t;
        localtime_s(&t, &now);
        fprintf(g_logfile, "[%02d:%02d:%02d][%s] %s\n",
                t.tm_hour, t.tm_min, t.tm_sec, level, buf);
        fflush(g_logfile);
    }
}

void info(const char* fmt, ...)
{
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    _plugin_logprintf("[x64deobf] %s\n", buf);
    writeFile("INFO", buf);
}

void error(const char* fmt, ...)
{
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    _plugin_logprintf("[x64deobf][ERROR] %s\n", buf);
    writeFile("ERROR", buf);
}

} // namespace logger
} // namespace deobf
