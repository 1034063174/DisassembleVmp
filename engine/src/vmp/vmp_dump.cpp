// vmp_dump.cpp — VMP 分析结果落盘（JSON）

#include "vmp_dump.h"

#include <cstdio>
#include <ctime>
#include <string>
#include <vector>
#include <fstream>

static std::string esc(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"')       out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else                out += c;
    }
    return out;
}

static void write_regs(std::string& o, const char* key, const VmpRegCtx& r, const std::string& ind) {
    char buf[512];
    snprintf(buf, sizeof(buf),
        "%s\"%s\": {"
        " \"rax\":\"%llX\", \"rbx\":\"%llX\", \"rcx\":\"%llX\", \"rdx\":\"%llX\","
        " \"rsi\":\"%llX\", \"rdi\":\"%llX\", \"rbp\":\"%llX\", \"rsp\":\"%llX\","
        " \"r8\":\"%llX\",  \"r9\":\"%llX\",  \"r10\":\"%llX\", \"r11\":\"%llX\","
        " \"r12\":\"%llX\", \"r13\":\"%llX\", \"r14\":\"%llX\", \"r15\":\"%llX\","
        " \"rflags\":\"%llX\" }",
        ind.c_str(), key,
        (unsigned long long)r.rax,    (unsigned long long)r.rbx,
        (unsigned long long)r.rcx,    (unsigned long long)r.rdx,
        (unsigned long long)r.rsi,    (unsigned long long)r.rdi,
        (unsigned long long)r.rbp,    (unsigned long long)r.rsp,
        (unsigned long long)r.r8,     (unsigned long long)r.r9,
        (unsigned long long)r.r10,    (unsigned long long)r.r11,
        (unsigned long long)r.r12,    (unsigned long long)r.r13,
        (unsigned long long)r.r14,    (unsigned long long)r.r15,
        (unsigned long long)r.rflags);
    o += buf;
}

static void write_stack(std::string& o, const char* key,
                        const std::vector<VmpStackEntry>& st, const std::string& ind) {
    o += ind + "\"" + key + "\": [\n";
    for (int i = 0; i < (int)st.size(); ++i) {
        char buf[128];
        snprintf(buf, sizeof(buf),
            "%s  { \"offset\":%lld, \"addr\":\"%llX\", \"value\":\"%llX\", \"is_rsp\":%s }",
            ind.c_str(),
            (long long)st[i].offset,
            (unsigned long long)st[i].addr,
            (unsigned long long)st[i].value,
            st[i].is_rsp ? "true" : "false");
        o += buf;
        o += (i + 1 < (int)st.size()) ? ",\n" : "\n";
    }
    o += ind + "]";
}

void vmp_dump_result(VmpAnalysisResult& res) {
    char ts[32];
    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_s(&tm_buf, &now);
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tm_buf);

    char path[512];
    snprintf(path, sizeof(path), "vmp_dump_%s.json", ts);

    std::string o;
    o.reserve(4 * 1024 * 1024);

    char meta[256];
    snprintf(meta, sizeof(meta),
        "{\n"
        "  \"meta\": {\n"
        "    \"vmCode_reg\": \"%s\",\n"
        "    \"vmStack_reg\": \"%s\",\n"
        "    \"vmRegBase\": \"%llX\",\n"
        "    \"total_insns\": %d,\n"
        "    \"junk_insns\": %d,\n"
        "    \"handler_count\": %d\n"
        "  },\n",
        esc(res.vmCode_reg).c_str(),
        esc(res.vmStack_reg).c_str(),
        (unsigned long long)res.vmRegBase,
        res.total_insns,
        res.junk_insns,
        (int)res.handlers.size());
    o += meta;

    o += "  \"handlers\": [\n";

    for (int hi = 0; hi < (int)res.handlers.size(); ++hi) {
        const auto& h = res.handlers[hi];

        char hdr[256];
        snprintf(hdr, sizeof(hdr),
            "    {\n"
            "      \"seg_idx\": %d,\n"
            "      \"type\": \"%s\",\n"
            "      \"detail\": \"%s\",\n"
            "      \"addr_start\": \"%llX\",\n"
            "      \"addr_end\": \"%llX\",\n"
            "      \"live_stores\": %d,\n"
            "      \"live_loads\": %d,\n"
            "      \"instructions\": [\n",
            h.seg_idx,
            esc(h.type).c_str(),
            esc(h.detail).c_str(),
            (unsigned long long)h.addr_start,
            (unsigned long long)h.addr_end,
            h.live_stores,
            h.live_loads);
        o += hdr;

        for (int ri = 0; ri < (int)h.row_indices.size(); ++ri) {
            const auto& row = res.rows[h.row_indices[ri]];

            char ibuf[256];
            snprintf(ibuf, sizeof(ibuf),
                "        {\n"
                "          \"step\": %d,\n"
                "          \"addr\": \"%llX\",\n"
                "          \"bytes\": \"%s\",\n"
                "          \"asm\": \"%s\",\n"
                "          \"is_junk\": %s,\n"
                "          \"has_deobf\": %s,\n",
                row.global_idx,
                (unsigned long long)row.addr,
                esc(row.bytes_str).c_str(),
                esc(row.asm_text).c_str(),
                row.is_junk   ? "true" : "false",
                row.has_deobf ? "true" : "false");
            o += ibuf;

            write_regs(o, "regs", row.regs, "          ");
            o += ",\n";

            if (row.has_deobf) {
                write_regs(o, "regs_deobf", row.regs_deobf, "          ");
                o += ",\n";
            }

            write_stack(o, "stack", row.stack, "          ");
            if (row.has_deobf && !row.stack_deobf.empty()) {
                o += ",\n";
                write_stack(o, "stack_deobf", row.stack_deobf, "          ");
            }
            o += "\n        }";
            o += (ri + 1 < (int)h.row_indices.size()) ? ",\n" : "\n";
        }

        o += "      ]\n    }";
        o += (hi + 1 < (int)res.handlers.size()) ? ",\n" : "\n";
    }

    o += "  ]\n}\n";

    std::ofstream f(path, std::ios::out | std::ios::trunc);
    if (f) {
        f << o;
        res.dump_path = path;
    }
}
