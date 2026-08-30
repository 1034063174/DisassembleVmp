#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace deobf {

struct SnapshotData {
    uint64_t rip = 0;
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
    uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
    uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    uint64_t rflags = 0;
    uint64_t gs_base = 0;

    struct MemoryRegion {
        uint64_t base;
        std::vector<uint8_t> data;
    };

    std::vector<MemoryRegion> regions;

    std::string debuggee_name;
    std::string module_name;
    bool is_debugging = false;
    bool is_paused = false;
};

bool takeSnapshot(SnapshotData& snap);
bool readMemoryRegion(uint64_t base, size_t size, SnapshotData::MemoryRegion& region);

} // namespace deobf
