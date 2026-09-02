// llvm_opt.cpp — 动态加载 LLVM-C.dll，提供 IR 优化和汇编生成
// 运行时通过 LoadLibrary + GetProcAddress 获取函数指针
// DLL 不存在时所有函数返回错误，不影响引擎正常使用

#include "llvm_opt.h"
#include <windows.h>
#include <cstdio>

// LLVM-C opaque types
typedef struct LLVMOpaqueContext*          LLVMContextRef;
typedef struct LLVMOpaqueModule*           LLVMModuleRef;
typedef struct LLVMOpaqueMemoryBuffer*     LLVMMemoryBufferRef;
typedef struct LLVMOpaqueTargetMachine*    LLVMTargetMachineRef;
typedef struct LLVMOpaqueTarget*           LLVMTargetRef;
typedef struct LLVMOpaquePassBuilderOptions* LLVMPassBuilderOptionsRef;
typedef struct LLVMOpaqueError*            LLVMErrorRef;
typedef int LLVMBool;

// LLVMCodeGenOptLevel
enum { LLVMCodeGenLevelNone = 0, LLVMCodeGenLevelLess, LLVMCodeGenLevelDefault, LLVMCodeGenLevelAggressive };
// LLVMRelocMode
enum { LLVMRelocDefault = 0, LLVMRelocStatic, LLVMRelocPIC };
// LLVMCodeModel
enum { LLVMCodeModelDefault = 0 };
// LLVMCodeGenFileType
enum { LLVMAssemblyFile = 0, LLVMObjectFile };

// ── 函数指针类型 ──

#define DECL_FN(ret, name, ...) typedef ret (*PFN_##name)(__VA_ARGS__); static PFN_##name p_##name = nullptr

DECL_FN(LLVMContextRef,         LLVMContextCreate, void);
DECL_FN(void,                   LLVMContextDispose, LLVMContextRef);
DECL_FN(LLVMMemoryBufferRef,    LLVMCreateMemoryBufferWithMemoryRangeCopy, const char*, size_t, const char*);
DECL_FN(void,                   LLVMDisposeMemoryBuffer, LLVMMemoryBufferRef);
DECL_FN(LLVMBool,               LLVMParseIRInContext, LLVMContextRef, LLVMMemoryBufferRef, LLVMModuleRef*, char**);
DECL_FN(void,                   LLVMDisposeModule, LLVMModuleRef);
DECL_FN(char*,                  LLVMPrintModuleToString, LLVMModuleRef);
DECL_FN(void,                   LLVMDisposeMessage, char*);

// target init
DECL_FN(void, LLVMInitializeX86TargetInfo, void);
DECL_FN(void, LLVMInitializeX86Target, void);
DECL_FN(void, LLVMInitializeX86TargetMC, void);
DECL_FN(void, LLVMInitializeX86AsmPrinter, void);
DECL_FN(void, LLVMInitializeX86AsmParser, void);

// target machine
DECL_FN(LLVMBool,              LLVMGetTargetFromTriple, const char*, LLVMTargetRef*, char**);
DECL_FN(LLVMTargetMachineRef,  LLVMCreateTargetMachine, LLVMTargetRef, const char*, const char*, const char*, int, int, int);
DECL_FN(void,                  LLVMDisposeTargetMachine, LLVMTargetMachineRef);

// new pass manager (LLVM 17+)
DECL_FN(LLVMErrorRef,                LLVMRunPasses, LLVMModuleRef, const char*, LLVMTargetMachineRef, LLVMPassBuilderOptionsRef);
DECL_FN(LLVMPassBuilderOptionsRef,   LLVMCreatePassBuilderOptions, void);
DECL_FN(void,                        LLVMDisposePassBuilderOptions, LLVMPassBuilderOptionsRef);

// error handling
DECL_FN(char*,    LLVMGetErrorMessage, LLVMErrorRef);
DECL_FN(void,     LLVMDisposeErrorMessage, char*);

// codegen
DECL_FN(LLVMBool, LLVMTargetMachineEmitToMemoryBuffer, LLVMTargetMachineRef, LLVMModuleRef, int, char**, LLVMMemoryBufferRef*);
DECL_FN(const char*, LLVMGetBufferStart, LLVMMemoryBufferRef);
DECL_FN(size_t,      LLVMGetBufferSize, LLVMMemoryBufferRef);

// module triple
DECL_FN(void, LLVMSetTarget, LLVMModuleRef, const char*);

// command line options (for intel asm syntax)
DECL_FN(void, LLVMParseCommandLineOptions, int, const char* const*, const char*);

#undef DECL_FN

// ── 状态 ──

static HMODULE g_dll = nullptr;
static bool g_available = false;
static bool g_target_inited = false;

// ── 加载 ──

#define LOAD_FN(name) do { p_##name = (PFN_##name)GetProcAddress(g_dll, #name); if (!p_##name) { err_msg = "Missing symbol: " #name; FreeLibrary(g_dll); g_dll = nullptr; return false; } } while(0)

bool llvm_opt::init(std::string& err_msg)
{
    if (g_available) return true;

    g_dll = LoadLibraryA("LLVM-C.dll");
    if (!g_dll) {
        // 尝试 exe 同目录
        char path[MAX_PATH];
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        std::string dir(path);
        auto pos = dir.find_last_of("\\/");
        if (pos != std::string::npos) dir = dir.substr(0, pos + 1);
        dir += "LLVM-C.dll";
        g_dll = LoadLibraryA(dir.c_str());
    }
    if (!g_dll) {
        err_msg = "LLVM-C.dll not found";
        return false;
    }

    LOAD_FN(LLVMContextCreate);
    LOAD_FN(LLVMContextDispose);
    LOAD_FN(LLVMCreateMemoryBufferWithMemoryRangeCopy);
    LOAD_FN(LLVMDisposeMemoryBuffer);
    LOAD_FN(LLVMParseIRInContext);
    LOAD_FN(LLVMDisposeModule);
    LOAD_FN(LLVMPrintModuleToString);
    LOAD_FN(LLVMDisposeMessage);

    LOAD_FN(LLVMInitializeX86TargetInfo);
    LOAD_FN(LLVMInitializeX86Target);
    LOAD_FN(LLVMInitializeX86TargetMC);
    LOAD_FN(LLVMInitializeX86AsmPrinter);
    LOAD_FN(LLVMInitializeX86AsmParser);

    LOAD_FN(LLVMGetTargetFromTriple);
    LOAD_FN(LLVMCreateTargetMachine);
    LOAD_FN(LLVMDisposeTargetMachine);

    LOAD_FN(LLVMRunPasses);
    LOAD_FN(LLVMCreatePassBuilderOptions);
    LOAD_FN(LLVMDisposePassBuilderOptions);

    LOAD_FN(LLVMGetErrorMessage);
    LOAD_FN(LLVMDisposeErrorMessage);

    LOAD_FN(LLVMTargetMachineEmitToMemoryBuffer);
    LOAD_FN(LLVMGetBufferStart);
    LOAD_FN(LLVMGetBufferSize);

    LOAD_FN(LLVMSetTarget);

    LOAD_FN(LLVMParseCommandLineOptions);

    // 设置 Intel 汇编语法
    const char* args[] = { "vmp_engine", "--x86-asm-syntax=intel" };
    p_LLVMParseCommandLineOptions(2, args, nullptr);

    g_available = true;
    return true;
}

#undef LOAD_FN

void llvm_opt::shutdown()
{
    if (g_dll) { FreeLibrary(g_dll); g_dll = nullptr; }
    g_available = false;
    g_target_inited = false;
}

bool llvm_opt::is_available()
{
    return g_available;
}

// ── 内部：初始化 X86 target ──

static void ensure_target()
{
    if (g_target_inited) return;
    p_LLVMInitializeX86TargetInfo();
    p_LLVMInitializeX86Target();
    p_LLVMInitializeX86TargetMC();
    p_LLVMInitializeX86AsmPrinter();
    p_LLVMInitializeX86AsmParser();
    g_target_inited = true;
}

// ── 内部：解析 IR → Module ──

static LLVMModuleRef parse_ir(const std::string& ir_text, LLVMContextRef ctx, std::string& err)
{
    auto buf = p_LLVMCreateMemoryBufferWithMemoryRangeCopy(ir_text.c_str(), ir_text.size(), "vmp_ir");
    LLVMModuleRef mod = nullptr;
    char* msg = nullptr;
    if (p_LLVMParseIRInContext(ctx, buf, &mod, &msg)) {
        err = msg ? msg : "IR parse error";
        if (msg) p_LLVMDisposeMessage(msg);
        return nullptr;
    }
    return mod;
}

// ── 内部：创建 TargetMachine ──

static LLVMTargetMachineRef create_tm(int opt_level, std::string& err)
{
    ensure_target();
    const char* triple = "x86_64-pc-windows-msvc";
    LLVMTargetRef target = nullptr;
    char* msg = nullptr;
    if (p_LLVMGetTargetFromTriple(triple, &target, &msg)) {
        err = msg ? msg : "target lookup failed";
        if (msg) p_LLVMDisposeMessage(msg);
        return nullptr;
    }
    int cg_level = LLVMCodeGenLevelDefault;
    if (opt_level >= 3) cg_level = LLVMCodeGenLevelAggressive;
    else if (opt_level == 0) cg_level = LLVMCodeGenLevelNone;
    return p_LLVMCreateTargetMachine(target, triple, "x86-64", "", cg_level, LLVMRelocDefault, LLVMCodeModelDefault);
}

// ── 公开接口 ──

std::string llvm_opt::optimize_ir(const std::string& ir_text, int opt_level, std::string& err)
{
    if (!g_available) { err = "LLVM not loaded"; return ""; }

    auto ctx = p_LLVMContextCreate();
    auto mod = parse_ir(ir_text, ctx, err);
    if (!mod) { p_LLVMContextDispose(ctx); return ""; }

    auto tm = create_tm(opt_level, err);
    if (!tm) { p_LLVMDisposeModule(mod); p_LLVMContextDispose(ctx); return ""; }

    p_LLVMSetTarget(mod, "x86_64-pc-windows-msvc");

    char passes[64];
    snprintf(passes, sizeof(passes), "default<O%d>", opt_level > 3 ? 3 : opt_level);
    auto opts = p_LLVMCreatePassBuilderOptions();
    LLVMErrorRef e = p_LLVMRunPasses(mod, passes, tm, opts);
    p_LLVMDisposePassBuilderOptions(opts);

    if (e) {
        char* msg = p_LLVMGetErrorMessage(e);
        err = msg ? msg : "pass error";
        if (msg) p_LLVMDisposeErrorMessage(msg);
        p_LLVMDisposeTargetMachine(tm);
        p_LLVMDisposeModule(mod);
        p_LLVMContextDispose(ctx);
        return "";
    }

    char* out = p_LLVMPrintModuleToString(mod);
    std::string result = out ? out : "";
    if (out) p_LLVMDisposeMessage(out);

    p_LLVMDisposeTargetMachine(tm);
    p_LLVMDisposeModule(mod);
    p_LLVMContextDispose(ctx);
    return result;
}

std::string llvm_opt::emit_asm(const std::string& ir_text, int opt_level, std::string& err)
{
    if (!g_available) { err = "LLVM not loaded"; return ""; }

    auto ctx = p_LLVMContextCreate();
    auto mod = parse_ir(ir_text, ctx, err);
    if (!mod) { p_LLVMContextDispose(ctx); return ""; }

    auto tm = create_tm(opt_level, err);
    if (!tm) { p_LLVMDisposeModule(mod); p_LLVMContextDispose(ctx); return ""; }

    p_LLVMSetTarget(mod, "x86_64-pc-windows-msvc");

    // 先跑优化
    char passes[64];
    snprintf(passes, sizeof(passes), "default<O%d>", opt_level > 3 ? 3 : opt_level);
    auto opts = p_LLVMCreatePassBuilderOptions();
    LLVMErrorRef e = p_LLVMRunPasses(mod, passes, tm, opts);
    p_LLVMDisposePassBuilderOptions(opts);

    if (e) {
        char* msg = p_LLVMGetErrorMessage(e);
        err = msg ? msg : "pass error";
        if (msg) p_LLVMDisposeErrorMessage(msg);
        p_LLVMDisposeTargetMachine(tm);
        p_LLVMDisposeModule(mod);
        p_LLVMContextDispose(ctx);
        return "";
    }

    // 生成汇编
    LLVMMemoryBufferRef asm_buf = nullptr;
    char* asm_err = nullptr;
    if (p_LLVMTargetMachineEmitToMemoryBuffer(tm, mod, LLVMAssemblyFile, &asm_err, &asm_buf)) {
        err = asm_err ? asm_err : "emit asm failed";
        if (asm_err) p_LLVMDisposeMessage(asm_err);
        p_LLVMDisposeTargetMachine(tm);
        p_LLVMDisposeModule(mod);
        p_LLVMContextDispose(ctx);
        return "";
    }

    std::string result(p_LLVMGetBufferStart(asm_buf), p_LLVMGetBufferSize(asm_buf));
    p_LLVMDisposeMemoryBuffer(asm_buf);
    p_LLVMDisposeTargetMachine(tm);
    p_LLVMDisposeModule(mod);
    p_LLVMContextDispose(ctx);
    return result;
}
