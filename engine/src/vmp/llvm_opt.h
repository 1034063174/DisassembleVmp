#pragma once
#include <string>

// 动态加载 LLVM-C.dll，提供 IR 优化和汇编生成功能
// DLL 不存在时优雅降级（函数返回错误信息）

namespace llvm_opt {

bool init(std::string& err_msg);
void shutdown();
bool is_available();

// 输入 LLVM IR 文本，输出优化后的 IR 文本
std::string optimize_ir(const std::string& ir_text, int opt_level, std::string& err);

// 输入 LLVM IR 文本，输出 x86-64 汇编
std::string emit_asm(const std::string& ir_text, int opt_level, std::string& err);

} // namespace llvm_opt
