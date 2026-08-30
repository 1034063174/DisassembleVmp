#pragma once
// vmp_context.h — 寄存器快照 + Ghidra/Unicorn 寄存器映射
// 对应 VmpHelper: GhidraHelper.h (GetVarnodeRegName / reg offset tables)

#include <cstdint>
#include <unicorn/unicorn.h>

struct RegCtx {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8,  r9,  r10, r11, r12, r13, r14, r15;
    uint64_t rflags = 0;

    uint64_t get(int uc_reg_id) const {
        switch (uc_reg_id) {
        case UC_X86_REG_RAX: return rax; case UC_X86_REG_RBX: return rbx;
        case UC_X86_REG_RCX: return rcx; case UC_X86_REG_RDX: return rdx;
        case UC_X86_REG_RSI: return rsi; case UC_X86_REG_RDI: return rdi;
        case UC_X86_REG_RBP: return rbp; case UC_X86_REG_RSP: return rsp;
        case UC_X86_REG_R8:  return r8;  case UC_X86_REG_R9:  return r9;
        case UC_X86_REG_R10: return r10; case UC_X86_REG_R11: return r11;
        case UC_X86_REG_R12: return r12; case UC_X86_REG_R13: return r13;
        case UC_X86_REG_R14: return r14; case UC_X86_REG_R15: return r15;
        case UC_X86_REG_EFLAGS: return rflags;
        default: return 0;
        }
    }
};

static inline int ghidra_off_to_uc(uint64_t off) {
    switch (off) {
    case 0x00: return UC_X86_REG_RAX; case 0x08: return UC_X86_REG_RCX;
    case 0x10: return UC_X86_REG_RDX; case 0x18: return UC_X86_REG_RBX;
    case 0x20: return UC_X86_REG_RSP; case 0x28: return UC_X86_REG_RBP;
    case 0x30: return UC_X86_REG_RSI; case 0x38: return UC_X86_REG_RDI;
    case 0x80: return UC_X86_REG_R8;  case 0x88: return UC_X86_REG_R9;
    case 0x90: return UC_X86_REG_R10; case 0x98: return UC_X86_REG_R11;
    case 0xa0: return UC_X86_REG_R12; case 0xa8: return UC_X86_REG_R13;
    case 0xb0: return UC_X86_REG_R14; case 0xb8: return UC_X86_REG_R15;
    default:   return -1;
    }
}

static inline const char* ghidra_reg_name(uint64_t off) {
    switch (off) {
    case 0x00: return "rax"; case 0x08: return "rcx";
    case 0x10: return "rdx"; case 0x18: return "rbx";
    case 0x20: return "rsp"; case 0x28: return "rbp";
    case 0x30: return "rsi"; case 0x38: return "rdi";
    case 0x80: return "r8";  case 0x88: return "r9";
    case 0x90: return "r10"; case 0x98: return "r11";
    case 0xa0: return "r12"; case 0xa8: return "r13";
    case 0xb0: return "r14"; case 0xb8: return "r15";
    default:   return nullptr;
    }
}

static inline uint64_t reg_name_to_ghidra_off(const std::string& name) {
    static const uint64_t offs[] = {
        0x00,0x08,0x10,0x18,0x20,0x28,0x30,0x38,
        0x80,0x88,0x90,0x98,0xa0,0xa8,0xb0,0xb8
    };
    for (auto off : offs)
        if (ghidra_reg_name(off) && name == ghidra_reg_name(off)) return off;
    return 0;
}

static inline const char* uc_reg_name(int id) {
    switch (id) {
    case UC_X86_REG_RAX: return "rax"; case UC_X86_REG_RBX: return "rbx";
    case UC_X86_REG_RCX: return "rcx"; case UC_X86_REG_RDX: return "rdx";
    case UC_X86_REG_RSI: return "rsi"; case UC_X86_REG_RDI: return "rdi";
    case UC_X86_REG_RBP: return "rbp"; case UC_X86_REG_RSP: return "rsp";
    case UC_X86_REG_R8:  return "r8";  case UC_X86_REG_R9:  return "r9";
    case UC_X86_REG_R10: return "r10"; case UC_X86_REG_R11: return "r11";
    case UC_X86_REG_R12: return "r12"; case UC_X86_REG_R13: return "r13";
    case UC_X86_REG_R14: return "r14"; case UC_X86_REG_R15: return "r15";
    default: return "?";
    }
}
