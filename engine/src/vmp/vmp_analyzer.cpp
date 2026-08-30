// vmp_analyzer.cpp — VMP handler 分析引擎
// 逻辑与 pcode_demo/main.cpp 完全一致，改为函数接口供 UI 调用

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vmp_analyzer.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_set>
#include <sstream>
#include <fstream>
#include <ctime>

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

#ifdef LoadImage
#undef LoadImage
#endif
#include "loadimage.hh"
#include "sleigh.hh"

#include "vmp_context.h"
#include "vmp_types.h"
#include "vmp_dead.h"
#include "vmp_dump.h"
#include "vmp_classifier.h"
#include "vmp_annotate.h"

// ── helpers ──────────────────────────────────────────────────────────────────

static uint64_t hex64(const std::string& s) {
    try {
        if (s.size() > 2 && s[0] == '0' && (s[1]=='x'||s[1]=='X'))
            return std::stoull(s.substr(2), nullptr, 16);
        return std::stoull(s, nullptr, 16);
    } catch (...) { return 0; }
}

static std::vector<uint8_t> hexbytes(const std::string& h) {
    std::vector<uint8_t> out;
    size_t i = 0;
    while (i < h.size()) {
        if (h[i]==' ') { ++i; continue; }
        if (i+1>=h.size()) break;
        try { out.push_back((uint8_t)std::stoul(h.substr(i,2),nullptr,16)); }
        catch (...) {}
        i += 2;
    }
    return out;
}

// ── Sleigh LoadImage ──────────────────────────────────────────────────────────

class MultiLoadImage : public ghidra::LoadImage {
    std::vector<MemPage>& pages_;
public:
    MultiLoadImage(std::vector<MemPage>& p)
        : ghidra::LoadImage("multi"), pages_(p) {}
    void loadFill(ghidra::uint1* ptr, ghidra::int4 n,
                  const ghidra::Address& a) override {
        ghidra::uintb base = a.getOffset();
        for (int i = 0; i < n; ++i) {
            ghidra::uintb addr = base + i; ptr[i] = 0;
            for (auto& pg : pages_)
                if (addr >= pg.base && addr < pg.base + pg.data.size())
                    { ptr[i] = pg.data[(size_t)(addr-pg.base)]; break; }
        }
    }
    std::string getArchType() const override { return "multi"; }
    void adjustVma(long) override {}
};

class PcodeCollect : public ghidra::PcodeEmit {
public:
    std::vector<RawOp> ops;
    void dump(const ghidra::Address&, ghidra::OpCode opc,
              ghidra::VarnodeData* out, ghidra::VarnodeData* ins,
              ghidra::int4 n) override {
        RawOp op; op.opc = opc;
        if (out) { op.has_out = true; op.out = *out; }
        for (int i = 0; i < n; ++i) op.ins.push_back(ins[i]);
        ops.push_back(std::move(op));
    }
};

// ── Unicorn hooks ─────────────────────────────────────────────────────────────

// 栈槽数：RSP-8*STACK_SLOTS .. RSP+8*STACK_SLOTS，共 2*STACK_SLOTS+1 项
static constexpr int STACK_SLOTS = 8;

struct StackSlot { int64_t offset; uint64_t addr; uint64_t value; };

struct TraceEntry {
    uint64_t addr;
    uint32_t size;
    RegCtx   regs;
    // 执行前直接从 Unicorn 读取的栈内存，与 pages[] 无关
    StackSlot stack[2 * STACK_SLOTS + 1];
};

struct HookCtx {
    int max_steps;
    std::vector<TraceEntry> trace;
    IpcClient* ipc;
    std::unordered_set<uint64_t> mapped_pages;
    std::vector<MemPage>* pages;
};

static void cb_code(uc_engine* uc, uint64_t addr, uint32_t size, void* user) {
    auto* c = (HookCtx*)user;
    TraceEntry te; te.addr = addr; te.size = size;
    RegCtx& r = te.regs;
    uc_reg_read(uc, UC_X86_REG_RAX, &r.rax); uc_reg_read(uc, UC_X86_REG_RBX, &r.rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &r.rcx); uc_reg_read(uc, UC_X86_REG_RDX, &r.rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &r.rsi); uc_reg_read(uc, UC_X86_REG_RDI, &r.rdi);
    uc_reg_read(uc, UC_X86_REG_RBP, &r.rbp); uc_reg_read(uc, UC_X86_REG_RSP, &r.rsp);
    uc_reg_read(uc, UC_X86_REG_R8,  &r.r8);  uc_reg_read(uc, UC_X86_REG_R9,  &r.r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r.r10); uc_reg_read(uc, UC_X86_REG_R11, &r.r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r.r12); uc_reg_read(uc, UC_X86_REG_R13, &r.r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r.r14); uc_reg_read(uc, UC_X86_REG_R15, &r.r15);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &r.rflags);

    // 栈快照：直接从 Unicorn 当前内存状态读取，而不是从 pages[] 读
    // UC_HOOK_CODE 在指令执行前触发，此时寄存器和内存都是执行前状态
    for (int slot = -STACK_SLOTS; slot <= STACK_SLOTS; ++slot) {
        int idx = slot + STACK_SLOTS;
        uint64_t sa = r.rsp + (uint64_t)((int64_t)slot * 8);
        te.stack[idx].offset = (int64_t)slot * 8;
        te.stack[idx].addr   = sa;
        te.stack[idx].value  = 0;
        uc_mem_read(uc, sa, &te.stack[idx].value, 8); // 读失败时 value 保持 0
    }

    c->trace.push_back(te);
    if ((int)c->trace.size() >= c->max_steps) uc_emu_stop(uc);
}

static bool cb_unmapped(uc_engine* uc, uc_mem_type, uint64_t addr,
                        int, int64_t, void* user) {
    auto* c = (HookCtx*)user;
    uint64_t page = addr & ~0xFFFULL;
    if (c->mapped_pages.count(page)) return false;
    char sa[32]; snprintf(sa, sizeof(sa), "%llX", (unsigned long long)page);
    auto r = c->ipc->send("read_memory", {{"address", sa}, {"size", 0x1000}});
    if (r.value("status","") == "ok") {
        auto data = hexbytes(r["data"].value("hex",""));
        if (!data.empty()) {
            data.resize(0x1000, 0);
            uc_mem_map(uc, page, 0x1000, UC_PROT_ALL);
            uc_mem_write(uc, page, data.data(), data.size());
            c->mapped_pages.insert(page);
            c->pages->push_back({page, std::move(data)});
            return true;
        }
    }
    uc_emu_stop(uc);
    return true;
}

// ── vmRegFile 检测（同 pcode_demo）──────────────────────────────────────────

static void detect_vmreg(const std::vector<InsnPcode>& insns,
                         uint64_t& vmRegBase,
                         std::map<uint64_t,std::string>& vmRegSlotMap)
{
    std::map<uint64_t,std::string> unique_to_reg;
    bool init_started = false, past_init = false;
    for (auto& ip : insns) {
        if (past_init) break;
        if (!init_started) {
            for (auto& op : ip.ops)
                if (!op.dead && op.opc == ghidra::CPUI_CALL)
                    { init_started = true; break; }
            continue;
        }
        for (auto& op : ip.ops)
            if (!op.dead && (op.opc == ghidra::CPUI_BRANCHIND ||
                             op.opc == ghidra::CPUI_RETURN))
                { past_init = true; break; }
        for (auto& op : ip.ops) {
            if (op.dead || op.opc != ghidra::CPUI_COPY) continue;
            if (!op.has_out || op.out.space->getName() != "unique") continue;
            if (op.ins.empty()) continue;
            if (op.ins[0].space->getName() == "register") {
                const char* rn = ghidra_reg_name(op.ins[0].offset);
                if (rn) unique_to_reg[op.out.offset] = rn;
            } else if (op.ins[0].space->getName() == "const") {
                char tmp[32];
                snprintf(tmp,sizeof(tmp),"const_%llX",(unsigned long long)op.ins[0].offset);
                unique_to_reg[op.out.offset] = tmp;
            }
        }
        for (auto& op : ip.ops) {
            if (op.dead || op.opc != ghidra::CPUI_STORE) continue;
            if (op.ins.size() < 3) continue;
            auto& val_vn = op.ins[2];
            std::string reg_name;
            if (val_vn.space->getName() == "register") {
                const char* rn = ghidra_reg_name(val_vn.offset);
                if (rn) reg_name = rn;
            } else if (val_vn.space->getName() == "unique") {
                auto it = unique_to_reg.find(val_vn.offset);
                if (it != unique_to_reg.end()) reg_name = it->second;
            }
            if (reg_name.empty()) continue;
            auto& dst_vn = op.ins[1];
            uint64_t store_addr = 0;
            if (dst_vn.space->getName() == "register") {
                int uc_id = ghidra_off_to_uc(dst_vn.offset);
                if (uc_id >= 0) store_addr = ip.regs.get(uc_id) - 8;
            } else if (dst_vn.space->getName() == "unique") {
                store_addr = ip.regs.rsp - 8;
            }
            if (store_addr) vmRegSlotMap[store_addr] = reg_name;
        }
    }
    if (vmRegSlotMap.empty()) return;
    std::vector<uint64_t> addrs;
    for (auto& kv : vmRegSlotMap) addrs.push_back(kv.first);
    size_t best_i=0, best_cnt=0;
    for (size_t i=0;i<addrs.size();++i) {
        size_t cnt=0;
        for (size_t j=i;j<addrs.size()&&addrs[j]<addrs[i]+20*8;++j) cnt++;
        if (cnt>best_cnt) { best_cnt=cnt; best_i=i; }
    }
    vmRegBase = addrs[best_i];
}

// ── vmCode / vmStack 检测（同 pcode_demo）───────────────────────────────────

static void detect_vmcode_vmstack(
    const std::vector<VmpHandlerSeg>& segs,
    const std::vector<InsnPcode>& insns,
    const std::vector<MemPage>& pages,
    uint64_t vmRegBase,
    std::string& vmCode_reg,
    std::string& vmStack_reg)
{
    auto is_mapped = [&](uint64_t addr) {
        for (auto& pg : pages)
            if (addr >= pg.base && addr < pg.base + pg.data.size()) return true;
        return false;
    };
    for (int si=1; si<(int)segs.size()
                   && (vmCode_reg.empty()||vmStack_reg.empty())
                   && si<=(vmStack_reg.empty()?1:5); ++si) {
        auto& seg = segs[si];
        for (int i=seg.start_idx; i<=seg.end_idx; ++i) {
            auto& ip = insns[i];
            auto  uv = build_unique_vals(ip);
            for (auto& op : ip.ops) {
                if (op.dead) continue;
                if (vmCode_reg.empty() && op.opc==ghidra::CPUI_LOAD
                        && op.ins.size()>=2
                        && op.ins[1].space->getName()=="register") {
                    int uid = ghidra_off_to_uc(op.ins[1].offset);
                    if (uid>=0) {
                        uint64_t ra = ip.regs.get(uid);
                        int64_t  sd = (int64_t)(ra-ip.regs.rsp);
                        if (is_mapped(ra) && (sd<-0x1000||sd>0x1000)
                                && (!vmRegBase||ra<vmRegBase||ra>=vmRegBase+32*8))
                            vmCode_reg = uc_reg_name(uid);
                    }
                }
                if (vmStack_reg.empty() && op.opc==ghidra::CPUI_STORE
                        && op.ins.size()>=2
                        && op.ins[1].space->getName()=="unique") {
                    auto it = uv.find(op.ins[1].offset);
                    if (it!=uv.end()) {
                        uint64_t sa  = it->second;
                        int64_t  off = (int64_t)(sa-ip.regs.rsp);
                        if (off>0 && off<0x10000) {
                            for (auto& op2 : ip.ops) {
                                if (op2.dead||!op2.has_out) continue;
                                if (op2.out.space->getName()!="unique") continue;
                                if (op2.out.offset!=op.ins[1].offset) continue;
                                if (op2.opc!=ghidra::CPUI_INT_ADD||op2.ins.size()!=2) continue;
                                for (auto& v : op2.ins) {
                                    if (v.space->getName()!="register") continue;
                                    if (ghidra_off_to_uc(v.offset)==UC_X86_REG_RSP) continue;
                                    const char* rn = ghidra_reg_name(v.offset);
                                    if (rn) vmStack_reg = rn;
                                    break;
                                }
                                if (!vmStack_reg.empty()) break;
                            }
                        }
                    }
                }
            }
        }
    }
    if (vmCode_reg.empty())  vmCode_reg  = "r11";
    if (vmStack_reg.empty()) vmStack_reg = "rsi";
}

static uint64_t vmcode_name_to_off(const std::string& name) {
    for (uint64_t off : {(uint64_t)0x98,0x00ULL,0x08ULL,0x10ULL,0x18ULL,
                          0x20ULL,0x28ULL,0x30ULL,0x38ULL,
                          0x80ULL,0x88ULL,0x90ULL,
                          0xa0ULL,0xa8ULL,0xb0ULL,0xb8ULL}) {
        const char* n = ghidra_reg_name(off);
        if (n && name==n) return off;
    }
    return 0x98;
}

// ── RegCtx → VmpRegCtx 转换 ──────────────────────────────────────────────────

static VmpRegCtx to_vmp_reg(const RegCtx& r) {
    VmpRegCtx v;
    v.valid=true;
    v.rax=r.rax; v.rbx=r.rbx; v.rcx=r.rcx; v.rdx=r.rdx;
    v.rsi=r.rsi; v.rdi=r.rdi; v.rbp=r.rbp; v.rsp=r.rsp;
    v.r8=r.r8;   v.r9=r.r9;   v.r10=r.r10; v.r11=r.r11;
    v.r12=r.r12; v.r13=r.r13; v.r14=r.r14; v.r15=r.r15;
    v.rflags=r.rflags;
    return v;
}

// ── RawOp → VmpPcodeOp 转换 ─────────────────────────────────────────────────

static const char* opc_to_name(int opc) {
    switch (opc) {
    case ghidra::CPUI_COPY:        return "COPY";
    case ghidra::CPUI_INT_ADD:     return "INT_ADD";
    case ghidra::CPUI_INT_SUB:     return "INT_SUB";
    case ghidra::CPUI_INT_AND:     return "INT_AND";
    case ghidra::CPUI_INT_OR:      return "INT_OR";
    case ghidra::CPUI_INT_XOR:     return "INT_XOR";
    case ghidra::CPUI_INT_NEGATE:  return "INT_NEGATE";
    case ghidra::CPUI_INT_2COMP:   return "INT_2COMP";
    case ghidra::CPUI_INT_LEFT:    return "INT_LEFT";
    case ghidra::CPUI_INT_RIGHT:   return "INT_RIGHT";
    case ghidra::CPUI_INT_SRIGHT:  return "INT_SRIGHT";
    case ghidra::CPUI_INT_MULT:    return "INT_MULT";
    case ghidra::CPUI_INT_DIV:     return "INT_DIV";
    case ghidra::CPUI_INT_SDIV:    return "INT_SDIV";
    case ghidra::CPUI_INT_REM:     return "INT_REM";
    case ghidra::CPUI_INT_SREM:    return "INT_SREM";
    case ghidra::CPUI_INT_EQUAL:   return "INT_EQUAL";
    case ghidra::CPUI_INT_NOTEQUAL:return "INT_NOTEQUAL";
    case ghidra::CPUI_INT_LESS:    return "INT_LESS";
    case ghidra::CPUI_INT_SLESS:   return "INT_SLESS";
    case ghidra::CPUI_INT_LESSEQUAL:return "INT_LESSEQUAL";
    case ghidra::CPUI_INT_SLESSEQUAL:return "INT_SLESSEQUAL";
    case ghidra::CPUI_INT_CARRY:   return "INT_CARRY";
    case ghidra::CPUI_INT_SCARRY:  return "INT_SCARRY";
    case ghidra::CPUI_INT_SBORROW: return "INT_SBORROW";
    case ghidra::CPUI_INT_ZEXT:    return "INT_ZEXT";
    case ghidra::CPUI_INT_SEXT:    return "INT_SEXT";
    case ghidra::CPUI_BOOL_AND:    return "BOOL_AND";
    case ghidra::CPUI_BOOL_OR:     return "BOOL_OR";
    case ghidra::CPUI_BOOL_XOR:    return "BOOL_XOR";
    case ghidra::CPUI_BOOL_NEGATE: return "BOOL_NEGATE";
    case ghidra::CPUI_LOAD:        return "LOAD";
    case ghidra::CPUI_STORE:       return "STORE";
    case ghidra::CPUI_BRANCH:      return "BRANCH";
    case ghidra::CPUI_CBRANCH:     return "CBRANCH";
    case ghidra::CPUI_BRANCHIND:   return "BRANCHIND";
    case ghidra::CPUI_CALL:        return "CALL";
    case ghidra::CPUI_CALLIND:     return "CALLIND";
    case ghidra::CPUI_CALLOTHER:   return "CALLOTHER";
    case ghidra::CPUI_RETURN:      return "RETURN";
    case ghidra::CPUI_PIECE:       return "PIECE";
    case ghidra::CPUI_SUBPIECE:    return "SUBPIECE";
    case ghidra::CPUI_POPCOUNT:    return "POPCOUNT";
    case ghidra::CPUI_LZCOUNT:     return "LZCOUNT";
    default:                       return "?";
    }
}

static const char* reg_name_by_off(uint64_t off, uint32_t size) {
    if (size >= 2) {
        const char* n = ghidra_reg_name(off);
        if (n) return n;
    }
    switch (off) {
    case 0x200: return "CF";  case 0x201: return "F1";
    case 0x202: return "PF";  case 0x203: return "F3";
    case 0x204: return "AF";  case 0x205: return "F5";
    case 0x206: return "ZF";  case 0x207: return "SF";
    case 0x208: return "TF";  case 0x209: return "IF";
    case 0x20a: return "DF";  case 0x20b: return "OF";
    default: break;
    }
    const char* n = ghidra_reg_name(off);
    return n ? n : "";
}

static VmpVarnode to_vmp_vn(const ghidra::VarnodeData& v) {
    VmpVarnode vn;
    vn.space  = v.space->getName();
    vn.offset = v.offset;
    vn.size   = v.size;
    if (vn.space == "register")
        vn.reg_name = reg_name_by_off(v.offset, v.size);
    return vn;
}

static std::vector<VmpPcodeOp> to_vmp_pcode(const std::vector<RawOp>& ops) {
    std::vector<VmpPcodeOp> out;
    out.reserve(ops.size());
    for (auto& op : ops) {
        VmpPcodeOp p;
        p.opc      = (int)op.opc;
        p.opc_name = opc_to_name((int)op.opc);
        p.has_out  = op.has_out;
        p.dead     = op.dead;
        if (op.has_out)
            p.out = to_vmp_vn(op.out);
        p.ins.reserve(op.ins.size());
        for (auto& v : op.ins)
            p.ins.push_back(to_vmp_vn(v));
        out.push_back(std::move(p));
    }
    return out;
}

// ── 主入口 ──────────────────────────────────────────────────────────────────

VmpAnalysisResult vmp_analyze(IpcClient& ipc,
                               const std::string& sla_path,
                               int steps,
                               bool ignore_eflag)
{
    VmpAnalysisResult res;

    // 1. 获取寄存器上下文
    auto ctx_r = ipc.send("get_context");
    if (ctx_r.value("status","") != "ok") {
        res.error = "get_context failed: " + ctx_r["error"].value("message","?");
        return res;
    }
    auto& d    = ctx_r["data"];
    auto& regs = d["registers"];
    uint64_t rip = hex64(d.value("rip","0"));
    uint64_t rsp = hex64(regs.value("rsp","0"));

    // 2. 预取内存页
    std::vector<MemPage> pages;
    auto fetch = [&](uint64_t page) {
        char sa[32]; snprintf(sa,sizeof(sa),"%llX",(unsigned long long)page);
        auto r = ipc.send("read_memory", {{"address",sa},{"size",0x1000}});
        if (r.value("status","") != "ok") return;
        auto data = hexbytes(r["data"].value("hex",""));
        if (!data.empty()) { data.resize(0x1000,0); pages.push_back({page,std::move(data)}); }
    };
    fetch(rip & ~0xFFFULL);
    fetch((rip & ~0xFFFULL) + 0x1000);
    if (rsp) for (int64_t off=-0x1000; off<=0x1000; off+=0x1000)
        fetch((rsp+off) & ~0xFFFULL);

    // 3. Unicorn 仿真
    uc_engine* uc = nullptr;
    if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) {
        res.error = "uc_open failed"; return res;
    }
    std::unordered_set<uint64_t> mapped_set;
    for (auto& pg : pages) {
        if (mapped_set.count(pg.base)) continue;
        uc_mem_map(uc, pg.base, 0x1000, UC_PROT_ALL);
        uc_mem_write(uc, pg.base, pg.data.data(), pg.data.size());
        mapped_set.insert(pg.base);
    }
    auto wr = [&](int reg, uint64_t v){ uc_reg_write(uc, reg, &v); };
    wr(UC_X86_REG_RAX, hex64(regs.value("rax","0")));
    wr(UC_X86_REG_RBX, hex64(regs.value("rbx","0")));
    wr(UC_X86_REG_RCX, hex64(regs.value("rcx","0")));
    wr(UC_X86_REG_RDX, hex64(regs.value("rdx","0")));
    wr(UC_X86_REG_RSI, hex64(regs.value("rsi","0")));
    wr(UC_X86_REG_RDI, hex64(regs.value("rdi","0")));
    wr(UC_X86_REG_RBP, hex64(regs.value("rbp","0")));
    wr(UC_X86_REG_RSP, hex64(regs.value("rsp","0")));
    wr(UC_X86_REG_R8,  hex64(regs.value("r8","0")));
    wr(UC_X86_REG_R9,  hex64(regs.value("r9","0")));
    wr(UC_X86_REG_R10, hex64(regs.value("r10","0")));
    wr(UC_X86_REG_R11, hex64(regs.value("r11","0")));
    wr(UC_X86_REG_R12, hex64(regs.value("r12","0")));
    wr(UC_X86_REG_R13, hex64(regs.value("r13","0")));
    wr(UC_X86_REG_R14, hex64(regs.value("r14","0")));
    wr(UC_X86_REG_R15, hex64(regs.value("r15","0")));
    uint64_t rflags = hex64(regs.value("rflags","0"));
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &rflags);

    HookCtx hctx;
    hctx.max_steps    = steps;
    hctx.ipc          = &ipc;
    hctx.mapped_pages = mapped_set;
    hctx.pages        = &pages;
    uc_hook hcode, hmem;
    uc_hook_add(uc, &hcode, UC_HOOK_CODE,         (void*)cb_code,     &hctx, 1, 0);
    uc_hook_add(uc, &hmem,  UC_HOOK_MEM_UNMAPPED, (void*)cb_unmapped, &hctx, 1, 0);
    uc_emu_start(uc, rip, 0, 0, 0);
    uc_close(uc);

    if (hctx.trace.empty()) { res.error = "Unicorn: no instructions executed"; return res; }

    // 4. Sleigh 初始化
    ghidra::AttributeId::initialize();
    ghidra::ElementId::initialize();
    MultiLoadImage loader(pages);
    ghidra::ContextInternal sctx;
    ghidra::DocumentStorage store;
    std::istringstream specxml("<sleigh>" + sla_path + "</sleigh>");
    ghidra::Sleigh trans(&loader, &sctx);
    try {
        ghidra::Element* root = store.parseDocument(specxml)->getRoot();
        store.registerTag(root);
        trans.initialize(store);
        sctx.setVariableDefault("longMode", 1);
        sctx.setVariableDefault("addrsize", 2);
        sctx.setVariableDefault("opsize",   1);
    } catch (const std::exception& e) {
        res.error = std::string("Sleigh init: ") + e.what();
        return res;
    }
    ghidra::AddrSpace* cs = trans.getDefaultCodeSpace();

    // 5. Capstone
    csh cap = 0;
    cs_open(CS_ARCH_X86, CS_MODE_64, &cap);
    cs_option(cap, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    cs_option(cap, CS_OPT_UNSIGNED, CS_OPT_ON);
    cs_option(cap, CS_OPT_DETAIL, CS_OPT_ON);

    // Capstone 操作数提取辅助：将 cs_insn 的结构化操作数转为 VmpX86Operand
    auto extract_operands = [&](cs_insn* ci, std::string& out_mnemonic,
                                std::vector<VmpX86Operand>& out_ops) {
        out_mnemonic = ci->mnemonic;
        if (!ci->detail) return;
        cs_x86& x = ci->detail->x86;
        for (uint8_t oi = 0; oi < x.op_count; ++oi) {
            cs_x86_op& cop = x.operands[oi];
            VmpX86Operand vo;
            vo.size = cop.size;
            switch (cop.type) {
            case X86_OP_REG:
                vo.type = "reg";
                vo.reg  = cs_reg_name(cap, cop.reg);
                break;
            case X86_OP_IMM:
                vo.type = "imm";
                vo.imm  = cop.imm;
                break;
            case X86_OP_MEM:
                vo.type = "mem";
                if (cop.mem.base != X86_REG_INVALID)
                    vo.mem_base = cs_reg_name(cap, cop.mem.base);
                if (cop.mem.index != X86_REG_INVALID)
                    vo.mem_index = cs_reg_name(cap, cop.mem.index);
                vo.mem_scale = cop.mem.scale;
                vo.mem_disp  = cop.mem.disp;
                break;
            default: vo.type = "other"; break;
            }
            out_ops.push_back(std::move(vo));
        }
    };

    // 6. Trace → InsnPcode
    std::vector<InsnPcode> insns;
    // 并行数组：Capstone 结构化操作数（InsnPcode 不含 VmpX86Operand 以避免头文件依赖）
    struct CapstoneMeta { std::string mnemonic; std::vector<VmpX86Operand> operands; };
    std::vector<CapstoneMeta> cs_meta;
    for (auto& te : hctx.trace) {
        InsnPcode ip; ip.addr = te.addr; ip.regs = te.regs; ip.size = te.size;
        // 复制 cb_code 采集的栈快照（执行前，直接来自 Unicorn 内存，无 pages[] 缓存问题）
        static_assert(sizeof(te.stack) / sizeof(te.stack[0]) == InsnPcode::NSLOTS, "");
        for (int si = 0; si < InsnPcode::NSLOTS; ++si) {
            ip.stack_slots[si].offset = te.stack[si].offset;
            ip.stack_slots[si].addr   = te.stack[si].addr;
            ip.stack_slots[si].value  = te.stack[si].value;
        }
        uint8_t ibuf[16] = {};
        for (auto& pg : pages)
            if (te.addr >= pg.base && te.addr+te.size <= pg.base+pg.data.size())
                { memcpy(ibuf, pg.data.data()+(size_t)(te.addr-pg.base), te.size); break; }
        CapstoneMeta cm;
        cs_insn* ci = nullptr;
        if (cs_disasm(cap, ibuf, te.size, te.addr, 1, &ci) > 0) {
            char buf[160]; snprintf(buf,sizeof(buf),"%-8s %s",ci->mnemonic,ci->op_str);
            ip.asm_text = buf;
            char byte_buf[64]={};
            int boff=0;
            for (uint16_t b=0;b<ci->size;b++)
                boff+=snprintf(byte_buf+boff,sizeof(byte_buf)-boff,"%02X ",ci->bytes[b]);
            ip.bytes_str = byte_buf;
            extract_operands(ci, cm.mnemonic, cm.operands);
            cs_free(ci,1);
        } else { ip.asm_text = "???"; }
        cs_meta.push_back(std::move(cm));
        ghidra::Address pos(cs, te.addr);
        PcodeCollect pc;
        try { trans.oneInstruction(pc, pos); } catch (...) {}
        ip.ops = std::move(pc.ops);
        insns.push_back(std::move(ip));
    }
    cs_close(&cap);

    // 7. 先切分 handler 段（VmpHelper: split before dead-code per node）
    auto handler_segs = split_handler_segs(insns);

    // 8. 逐段做死代码消除（VmpHelper: ActionVmpHandlerDeadCode per VmpNode）
    //    注意：必须逐段隔离，跨段会让后一段的活跃集倒流污染前一段，
    //    导致本段的垃圾寄存器写被误判为"活跃"而保留。
    for (auto& seg : handler_segs)
        eliminate_dead_seg(insns, seg.start_idx, seg.end_idx, ignore_eflag);

    // 段的 live_stores/live_loads 在切段时计算用的是 dead=false 状态，
    // 需要在消除完死代码后重新统计
    for (auto& seg : handler_segs) {
        seg.live_stores = 0; seg.live_loads = 0;
        for (int i = seg.start_idx; i <= seg.end_idx; ++i)
            for (auto& op : insns[i].ops) {
                if (op.dead) continue;
                if (op.opc == ghidra::CPUI_STORE) seg.live_stores++;
                if (op.opc == ghidra::CPUI_LOAD)  seg.live_loads++;
            }
    }

    // 9. vmRegFile 检测
    uint64_t vmRegBase = 0;
    std::map<uint64_t,std::string> vmRegSlotMap;
    detect_vmreg(insns, vmRegBase, vmRegSlotMap);

    // 10. vmCode / vmStack 检测
    std::string vmCode_reg, vmStack_reg;
    detect_vmcode_vmstack(handler_segs, insns, pages, vmRegBase,
                          vmCode_reg, vmStack_reg);

    // 11. 分类
    VmpCtx vctx;
    vctx.vmRegBase       = vmRegBase;
    vctx.vmRegSlotMap    = vmRegSlotMap;
    vctx.pages           = &pages;
    vctx.vmstack_off_reg = reg_name_to_ghidra_off(vmStack_reg);
    uint64_t global_vmcode_off = vmcode_name_to_off(vmCode_reg);

    std::vector<HandlerResult> classified;
    for (int si=0; si<(int)handler_segs.size(); ++si) {
        uint64_t seg_vmcode_off = detect_seg_vmcode(
            handler_segs[si], insns, vctx, global_vmcode_off);
        classified.push_back(
            classify_seg(si, handler_segs[si], insns, vctx, seg_vmcode_off));
    }

    // 12. 构建结果
    res.vmCode_reg  = vmCode_reg;
    res.vmStack_reg = vmStack_reg;
    res.vmRegBase   = vmRegBase;

    // 标记每条 insn 是否 junk（所有 PCode op 均 dead）
    std::vector<bool> is_junk(insns.size(), false);
    for (int i=0;i<(int)insns.size();++i) {
        if (insns[i].ops.empty()) continue;
        bool all_dead = true;
        for (auto& op : insns[i].ops) if (!op.dead) { all_dead=false; break; }
        is_junk[i] = all_dead;
        if (all_dead) res.junk_insns++;
    }
    res.total_insns = (int)insns.size();

    // ── 第二次仿真：连续执行 live 指令序列，跳过 junk ──────────────────────────
    //
    // 初始寄存器 = 第一条 live 指令的 insns[first_live].regs（第一次仿真真实值）
    // 逐条执行 live 指令，只写 RIP（跳过 junk 造成的地址间断），
    // 其余寄存器从上一条 live 的执行结果自然传递。
    //
    // clean_snap[i].regs  = 进入 live[i] 时的干净状态（无 junk 参与）
    // clean_snap[i].stack = 进入 live[i] 时的干净栈快照
    //
    // 对比：
    //   row.regs       = insns[i].regs（第一次仿真，含 junk 污染）
    //   row.regs_deobf = clean_snap[i].regs（第二次仿真，无 junk）
    //   差值 = junk 的真实副作用
    struct CleanSnap {
        RegCtx   regs;
        bool     valid = false;
        InsnPcode::StackSlot stack[InsnPcode::NSLOTS];
    };
    std::vector<CleanSnap> clean_snap(insns.size());

    {
        uc_engine* uc2 = nullptr;
        if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc2) == UC_ERR_OK) {
            std::unordered_set<uint64_t> mapped2;
            for (auto& pg : pages) {
                if (mapped2.count(pg.base)) continue;
                uc_mem_map(uc2, pg.base, 0x1000, UC_PROT_ALL);
                uc_mem_write(uc2, pg.base, pg.data.data(), pg.data.size());
                mapped2.insert(pg.base);
            }

            auto wr2 = [&](int reg, uint64_t v){ uc_reg_write(uc2, reg, &v); };
            auto rd2 = [&](int reg) -> uint64_t {
                uint64_t v = 0; uc_reg_read(uc2, reg, &v); return v;
            };

            // 找第一条 live 指令，写入初始寄存器（仅一次）
            int first_live = -1;
            for (int i = 0; i < (int)insns.size(); ++i)
                if (!is_junk[i]) { first_live = i; break; }

            if (first_live >= 0) {
                const RegCtx& r0 = insns[first_live].regs;
                wr2(UC_X86_REG_RAX, r0.rax); wr2(UC_X86_REG_RBX, r0.rbx);
                wr2(UC_X86_REG_RCX, r0.rcx); wr2(UC_X86_REG_RDX, r0.rdx);
                wr2(UC_X86_REG_RSI, r0.rsi); wr2(UC_X86_REG_RDI, r0.rdi);
                wr2(UC_X86_REG_RBP, r0.rbp); wr2(UC_X86_REG_RSP, r0.rsp);
                wr2(UC_X86_REG_R8,  r0.r8);  wr2(UC_X86_REG_R9,  r0.r9);
                wr2(UC_X86_REG_R10, r0.r10); wr2(UC_X86_REG_R11, r0.r11);
                wr2(UC_X86_REG_R12, r0.r12); wr2(UC_X86_REG_R13, r0.r13);
                wr2(UC_X86_REG_R14, r0.r14); wr2(UC_X86_REG_R15, r0.r15);
                wr2(UC_X86_REG_EFLAGS, r0.rflags);

                // 连续执行 live 指令序列
                for (int i = 0; i < (int)insns.size(); ++i) {
                    if (is_junk[i]) continue;
                    if (insns[i].size == 0) continue;

                    // 确保该指令所在页已映射
                    uint64_t pg_base = insns[i].addr & ~0xFFFULL;
                    if (!mapped2.count(pg_base)) {
                        for (auto& pg : pages) {
                            if (pg.base == pg_base) {
                                uc_mem_map(uc2, pg.base, 0x1000, UC_PROT_ALL);
                                uc_mem_write(uc2, pg.base, pg.data.data(), pg.data.size());
                                mapped2.insert(pg.base);
                                break;
                            }
                        }
                    }

                    // 只写 RIP（跳过 junk 导致地址不连续），其余寄存器自然传递
                    uint64_t rip_val = insns[i].addr;
                    uc_reg_write(uc2, UC_X86_REG_RIP, &rip_val);

                    // 执行前读寄存器 → clean_snap[i].regs（干净的进入状态）
                    auto& cs = clean_snap[i];
                    cs.regs.rax = rd2(UC_X86_REG_RAX); cs.regs.rbx = rd2(UC_X86_REG_RBX);
                    cs.regs.rcx = rd2(UC_X86_REG_RCX); cs.regs.rdx = rd2(UC_X86_REG_RDX);
                    cs.regs.rsi = rd2(UC_X86_REG_RSI); cs.regs.rdi = rd2(UC_X86_REG_RDI);
                    cs.regs.rbp = rd2(UC_X86_REG_RBP); cs.regs.rsp = rd2(UC_X86_REG_RSP);
                    cs.regs.r8  = rd2(UC_X86_REG_R8);  cs.regs.r9  = rd2(UC_X86_REG_R9);
                    cs.regs.r10 = rd2(UC_X86_REG_R10); cs.regs.r11 = rd2(UC_X86_REG_R11);
                    cs.regs.r12 = rd2(UC_X86_REG_R12); cs.regs.r13 = rd2(UC_X86_REG_R13);
                    cs.regs.r14 = rd2(UC_X86_REG_R14); cs.regs.r15 = rd2(UC_X86_REG_R15);
                    cs.regs.rflags = rd2(UC_X86_REG_EFLAGS);

                    // 执行前读栈快照
                    for (int slot = -STACK_SLOTS; slot <= STACK_SLOTS; ++slot) {
                        int idx = slot + STACK_SLOTS;
                        uint64_t sa = cs.regs.rsp + (uint64_t)((int64_t)slot * 8);
                        cs.stack[idx].offset = (int64_t)slot * 8;
                        cs.stack[idx].addr   = sa;
                        cs.stack[idx].value  = 0;
                        uc_mem_read(uc2, sa, &cs.stack[idx].value, 8);
                    }

                    cs.valid = true;

                    // 单步执行，状态自动传递给下一条 live
                    uc_emu_start(uc2, insns[i].addr, 0, 0, 1);
                }
            }
            uc_close(uc2);
        }
    }
    for (int si=0; si<(int)handler_segs.size(); ++si) {
        auto& seg = handler_segs[si];
        auto& hr  = classified[si];

        VmpHandlerSummary hs;
        hs.seg_idx     = si;
        hs.type        = hr.type;
        hs.live_stores = seg.live_stores;
        hs.live_loads  = seg.live_loads;
        hs.addr_start  = insns[seg.start_idx].addr;
        hs.addr_end    = insns[seg.end_idx].addr;

        // detail 字符串
        if (hr.type=="vPushReg"||hr.type=="vPopReg") {
            hs.detail = "(slot="+std::to_string(hr.slot)+", "+hr.reg_name+")";
        } else if (hr.type=="vPushImm") {
            char tmp[32];
            snprintf(tmp,sizeof(tmp),"(0x%llX)",(unsigned long long)hr.imm_val);
            hs.detail = tmp;
        }

        for (int i=seg.start_idx; i<=seg.end_idx; ++i) {
            VmpAsmRow row;
            row.addr       = insns[i].addr;
            row.seg_idx    = si;
            row.global_idx = i;
            row.asm_text   = insns[i].asm_text;
            row.bytes_str  = insns[i].bytes_str;
            row.is_junk    = is_junk[i];
            row.mnemonic   = cs_meta[i].mnemonic;
            row.operands   = cs_meta[i].operands;

            // ── 语义定义 ──────────────────────────────────────────────────────
            // regs[i]       = 第一次仿真进入 live[i] 时（含 junk 污染的真实值）
            // regs_deobf[i] = 第二次仿真进入 live[i] 时（只跑 live，无 junk 污染）
            //               = 上一条 live 指令在第二次仿真中的执行后结果
            // 两列均为"执行前"，差值 = 这条 live 指令前那些 junk 的副作用
            // 无 junk 污染 → 两列完全相同（全绿）
            // ──────────────────────────────────────────────────────────────────
            auto copy_stack_slots = [](const InsnPcode::StackSlot* slots) {
                std::vector<VmpStackEntry> out;
                out.reserve(InsnPcode::NSLOTS);
                for (int s = 0; s < InsnPcode::NSLOTS; ++s)
                    out.push_back({slots[s].offset, slots[s].addr,
                                   slots[s].value, slots[s].offset == 0});
                return out;
            };
            auto copy_stack = [](const InsnPcode& ip) {
                std::vector<VmpStackEntry> out;
                out.reserve(InsnPcode::NSLOTS);
                for (int s = 0; s < InsnPcode::NSLOTS; ++s)
                    out.push_back({ip.stack_slots[s].offset,
                                   ip.stack_slots[s].addr,
                                   ip.stack_slots[s].value,
                                   ip.stack_slots[s].offset == 0});
                return out;
            };

            row.regs  = to_vmp_reg(insns[i].regs);
            row.stack = copy_stack(insns[i]);
            row.pcode = to_vmp_pcode(insns[i].ops);

            // regs_deobf = 第二次连续仿真到达 live[i] 时的干净状态（执行前读取）
            // 差值 = junk 对寄存器的副作用，无 junk 污染则两列完全相同
            if (is_junk[i]) {
                row.has_deobf = false;
            } else if (clean_snap[i].valid) {
                row.regs_deobf  = to_vmp_reg(clean_snap[i].regs);
                row.stack_deobf = copy_stack_slots(clean_snap[i].stack);
                row.has_deobf   = true;
            } else {
                row.has_deobf = false;
            }

            hs.row_indices.push_back((int)res.rows.size());
            res.rows.push_back(row);
        }

        res.handlers.push_back(std::move(hs));
    }

    res.ok = true;
    vmp_annotate(res);
    vmp_dump_result(res);
    return res;
}
