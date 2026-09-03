# DisassembleVmp — VMProtect 虚拟化分析引擎

一个面向 VMProtect 虚拟化代码的可编程分析引擎。自动去除混淆，直观呈现虚拟化核心代码，配合 Lua 脚本 + LLVM 优化还原虚拟化保护背后的真实逻辑。

> **当前仅支持 64 位 (x86-64) 目标程序的 VMP 分析。**

## 效果演示

以 `pushtest_demo` 为例，原始代码经 VMProtect 虚拟化后变成 110+ 个 handler、5000+ 条混淆指令。经引擎分析 + LLVM 优化后还原为：

```asm
; ══ 原始代码 (pushtest.asm) ══          ; ══ LLVM 优化输出 ══
push rax                                ;
mov  rax, 12345679h                     ;  (死代码，被消除)
mov  rax, 12345678h                     ;
add  rcx, 1                             ;  (与 sub rcx,1 抵消)
mov  qword ptr [rcx], rax              mov  qword ptr [rcx + 1], 0x12345678  ✓
sub  rcx, 1                             ;  (与 add rcx,1 抵消)
pop  rax                                ;  (push/pop 抵消)
mov  byte ptr [rcx], 0ABh              mov  byte ptr [rcx], 0xAB             ✓
mov  dword ptr [rcx+1], 0DEADBEEFh     mov  dword ptr [rcx + 1], 0xDEADBEEF  ✓
mov  rcx, 123456789ABCDEFh             movabs rcx, 0x123456789ABCDEF         ✓
ret                                    ret                                   ✓
```

10 条原始指令 → 5 条等价输出。LLVM 自动完成：常量传播（`rax` → `0x12345678`）、死代码消除（`mov rax, 12345679h`）、`add/sub` 抵消、`push/pop` 消除、VMP 位运算展开（NAND/NOR）的化简。

## 设计理念

VMProtect 虚拟化的分析不能仅靠静态规则。每个被保护的程序都有不同的 handler 结构、寄存器映射和栈布局。DisassembleVmp 提供的是一个**分析基础设施**：

1. **自动化去混淆** — Unicorn 模拟执行 + Sleigh PCode 语义分析，自动识别并标记垃圾指令
2. **Handler 识别与分类** — 自动划分 VMP handler 边界，识别 vPush/vPop/vAdd/vStore/vLoad/vNand/vExit 等类型
3. **LLVM IR Lifting** — 将 handler 序列提升为 LLVM IR，经 O2 优化后输出等价的 x86-64 汇编
4. **Lua 脚本引擎** — 指令序列、寄存器快照、栈快照、PCode 语义、Capstone 结构化操作数全部导出到 Lua，支持用户自定义分析
5. **交互式右键分析** — 右键任意指令即可生成 Capstone 操作数匹配模板，直接粘贴到脚本中使用

## 项目结构

```
DisassembleVmp/
├── engine/              分析引擎（vmp_engine.exe）
│   ├── src/
│   │   ├── vmp/         核心分析（模拟、PCode、死代码消除、分类、Lua 引擎、LLVM 集成）
│   │   ├── ui/          ImGui 界面
│   │   └── ipc/         与 x64dbg 插件通信
│   ├── bin/             运行时依赖（LLVM-C.dll）
│   └── deps/imgui/      Dear ImGui 源码
├── plugin/              x64dbg 插件（x64deobf.dp64）
│   └── src/             IPC server + 内存读写 + 寄存器快照
├── libsla/              Ghidra Sleigh 翻译引擎（libsla.lib）
│   └── src/             Ghidra Decompiler C++ 源码
├── pushtest_demo/       测试目标程序（含内联汇编，用于验证分析流程）
├── deps/                预编译第三方依赖
│   ├── capstone/        反汇编引擎
│   ├── unicorn/         CPU 模拟引擎
│   ├── lua/             Lua 5.4 脚本引擎
│   ├── zlib/            压缩库
│   └── pluginsdk/       x64dbg 插件 SDK
├── specfiles/           Sleigh .sla 规范文件（运行时需要）
├── docs/                文档
│   └── lua-api.md       Lua API 完整说明
└── DisassembleVmp.sln   Visual Studio 解决方案
```

## 工作流程

```
x64dbg 调试目标程序
    │
    ▼
x64deobf 插件（named pipe IPC）
    │  提供：读内存、读寄存器、NOP 写入
    ▼
vmp_engine 分析引擎
    ├── Unicorn 模拟执行 → 指令序列 + 寄存器/栈快照
    ├── Capstone 反汇编 → 结构化操作数（type/reg/mem/imm）
    ├── Sleigh PCode 翻译 → 语义原子操作
    ├── 死代码消除 → 标记垃圾指令
    ├── Handler 分类 → 识别 VMP handler 类型
    ├── Lua 脚本引擎 → 用户自定义分析逻辑
    └── LLVM 优化 → IR lifting + O2 优化 → 还原 x86-64 汇编
```

## Lua 脚本系统

引擎将完整的分析结果导出到 Lua 环境。详细的 API 说明见 [docs/lua-api.md](docs/lua-api.md)。

### 核心脚本

| 脚本 | 功能 |
|------|------|
| `annotate.lua` | 修复假存活指令（PCode 全死但未标记 junk 的指令） |
| `split_handlers.lua` | Handler 语义分类（vPush/vPop/vAdd/vStore/vLoad/vNand/vNor/vExit 等） |
| `lift_to_llvm.lua` | 将 handler 序列提升为 LLVM IR（slot-based alloca + inline asm 寄存器绑定） |
| `demo_llvm.lua` | 一键流程：annotate → split → lift → LLVM O2 优化 → 输出汇编 |
| `decompile.lua` | 符号栈模式匹配反编译器（纯 Lua，不依赖 LLVM） |
| `tools.lua` | 公共工具函数（init 压栈解析、vmStack 寄存器识别、寄存器映射） |

### Handler 类型与 UI 颜色

| Handler 类型 | 语义 | UI 颜色 |
|-------------|------|---------|
| `vPop` | 从 vmStack 弹出值到 slot | 白色 |
| `vPushReg` | 从 slot 读值压入 vmStack | 绿色 |
| `vPushImm64/32/16` | 从 vmCode 读常量压入 vmStack | 绿色 |
| `vPushVSP` | 压入 vmStack 指针自身 | 黄色 |
| `vAdd/vSub` | 算术运算 | 紫色 |
| `vAnd/vOr/vXor` | 逻辑运算 | 紫色 |
| `vNand/vNor` | 复合运算（NOT+NOT+OR / NOT+NOT+AND） | 紫色 |
| `vNot/vNeg` | 一元运算 | 紫色 |
| `vStore8/32/64` | 写内存 | 橙色 |
| `vLoad8/32/64` | 读内存 | 青色 |
| `vExit` | 退出 VM，恢复物理寄存器 | 红色 |
| `unknown` | 未识别 | 红色 |

### LLVM 集成

引擎动态加载 `LLVM-C.dll`（随项目分发，~68MB），提供三个 Lua 函数：

```lua
llvm_available()                    -- 检查 LLVM-C.dll 是否已加载
llvm_optimize_ir(ir_text, level)    -- 优化 LLVM IR，返回优化后 IR 文本
llvm_emit_asm(ir_text, level)       -- 优化 + 编译为 x86-64 汇编（Intel 语法）
```

IR Lifting 技术要点：
- 每个 VMP slot offset 对应一个 LLVM `alloca`
- INIT 寄存器通过 inline asm 约束（`={rcx}`）绑定物理寄存器
- EXIT 只写回被修改的寄存器，pass-through 寄存器不产生代码
- `vPushVSP + vLoad` 优化为符号栈 dup（避免不透明内存读取阻碍优化）
- `vNand` 生成 `and + xor -1`，LLVM 可正确化简 VMP 的 sub 实现

## 使用方式

1. x64deobf.dp64 放到 x64dbg 插件目录，运行 x64dbg
2. 运行 vmp_engine.exe，点击"解析"
3. 点击"Lua"按钮执行分析脚本（如 `demo_llvm.lua`）

![image-20260830224533715](image-20260830224533715.png)

![image-20260830223559764](image-20260830223559764.png)

## 构建

**环境要求：** Visual Studio 2019+ (MSVC v142)，Windows SDK 10.0+

所有依赖已包含在仓库中，克隆即可编译：

```bash
git clone https://github.com/1034063174/DisassembleVmp.git
cd DisassembleVmp
msbuild DisassembleVmp.sln /p:Configuration=Release /p:Platform=x64 /m
```

**构建顺序：** libsla -> vmp_engine / x64deobf（sln 中已配置依赖关系）

**运行时依赖：** `LLVM-C.dll` 需放在 vmp_engine.exe 的工作目录下（已包含在 `engine/bin/` 中）。

**产物：**

| 项目 | 输出 | 说明 |
|------|------|------|
| libsla | `libsla\bin\Release\libsla.lib` | Sleigh 翻译引擎静态库 |
| vmp_engine | `engine\bin\Release\vmp_engine.exe` | 分析引擎主程序 |
| x64deobf | `plugin\bin\Release\x64deobf.dp64` | x64dbg 插件 |
| pushtest_demo | `pushtest_demo\bin\Release\pushtest_demo.exe` | 测试目标程序 |

## 许可证

本项目以 **GPL-3.0** 许可证发布。详见 [LICENSE](LICENSE) 文件。

选择 GPL-3.0 是因为本项目链接了 x64dbg SDK (GPL-3.0) 和 Unicorn Engine (GPL-2.0)，GPL-3.0 是满足所有依赖许可证要求的最宽松选择。

## 第三方依赖

| 依赖 | 版本 | 许可证 | 用途 |
|------|------|--------|------|
| [x64dbg](https://github.com/x64dbg/x64dbg) | — | GPL-3.0 | 调试器平台，插件 SDK |
| [Unicorn Engine](https://github.com/unicorn-engine/unicorn) | 2.x | GPL-2.0 | CPU 模拟执行引擎 |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) (Sleigh) | 12.1.2 | Apache-2.0 | PCode 语义翻译引擎 |
| [Capstone](https://github.com/capstone-engine/capstone) | 5.x | BSD-3-Clause | x86-64 反汇编与结构化操作数 |
| [Dear ImGui](https://github.com/ocornut/imgui) | 1.91+ | MIT | UI 渲染框架 (DirectX 11) |
| [Lua](https://www.lua.org/) | 5.4 | MIT | 内嵌脚本引擎 |
| [LLVM](https://llvm.org/) | 18.x | Apache-2.0 | IR 优化与代码生成（动态加载 LLVM-C.dll） |
| [nlohmann/json](https://github.com/nlohmann/json) | 3.x | MIT | JSON 解析 (IPC 协议) |
| [zlib](https://github.com/madler/zlib) | — | zlib | 数据压缩 (.sla 文件解析) |

### 许可证兼容性

- **GPL-3.0** (x64dbg) — 本项目整体遵循 GPL-3.0
- **GPL-2.0** (Unicorn) — 以动态链接方式集成 (unicorn.dll)
- **Apache-2.0** (Ghidra Sleigh, LLVM) — 与 GPL-3.0 兼容
- **BSD-3-Clause / MIT / zlib** — 宽松许可证，均与 GPL-3.0 兼容

### 第三方文件分布

```
deps/pluginsdk/          x64dbg 插件 SDK (GPL-3.0)
deps/capstone/           Capstone 头文件 + .lib (BSD-3-Clause)
deps/unicorn/            Unicorn 头文件 + .lib/.dll (GPL-2.0)
deps/lua/                Lua 头文件 + .lib (MIT)
deps/zlib/               zlib 头文件 + .lib (zlib)
libsla/src/              Ghidra Sleigh C++ 源码 (Apache-2.0)
engine/deps/imgui/       Dear ImGui 源码 (MIT)
engine/bin/LLVM-C.dll    LLVM C API 动态库 (Apache-2.0)
plugin/deps/nlohmann/    nlohmann/json 头文件 (MIT)
```

## 免责声明

本工具仅供安全研究与逆向工程学习使用。使用者应确保其行为符合所在地区的法律法规。作者不对任何滥用行为承担责任。
