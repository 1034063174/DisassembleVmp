# Lua API 说明

引擎在执行 Lua 脚本前，会将分析结果注入为全局变量。本文档基于 `engine/src/vmp/vmp_lua.cpp`。

## 全局变量

### 分析元信息

| 变量 | 类型 | 说明 |
|------|------|------|
| `vmCode_reg` | string | vmCode 寄存器名（如 `"r11"`） |
| `vmStack_reg` | string | vmStack 寄存器名（如 `"rbx"`） |
| `vmRegBase` | integer | vmReg 基址 |
| `total_insns` | integer | 总指令数 |
| `junk_insns` | integer | 垃圾指令数 |
| `context_row` | integer/nil | 右键菜单触发时的行索引（1-based），非右键触发为 nil |

### rows — 指令表

`rows` 是一个 1-based 数组，每个元素是一条指令的完整信息。

```lua
local row = rows[i]
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `row.addr` | integer | 指令地址 |
| `row.step` | integer | 全局步骤编号 |
| `row.seg_idx` | integer | 所属 handler 段号（1-based） |
| `row.asm` | string | 汇编文本（如 `"mov rax, [rbx]"`） |
| `row.bytes` | string | 字节码十六进制字符串 |
| `row.mnemonic` | string | 助记符（如 `"mov"`, `"add"`, `"pushfq"`） |
| `row.is_junk` | boolean | 是否为垃圾指令 |
| `row.has_deobf` | boolean | 是否有去混淆后的寄存器/栈快照 |
| `row.analysis` | string | 分析标注文本（可由脚本写入） |
| `row.operands` | table[] | Capstone 结构化操作数（见下文） |
| `row.regs` | table | 指令执行前的寄存器快照 |
| `row.regs_deobf` | table/nil | 去混淆后的寄存器快照（仅 has_deobf=true） |
| `row.stack` | table[] | 指令执行前的栈快照 |
| `row.stack_deobf` | table[]/nil | 去混淆后的栈快照 |
| `row.pcode` | table[] | Sleigh PCode 语义操作 |

#### row.operands[] — Capstone 操作数

每个操作数是一个 table：

```lua
local op = row.operands[1]
```

| 字段 | 类型 | 说明 | 适用 type |
|------|------|------|-----------|
| `op.type` | string | `"reg"` / `"imm"` / `"mem"` | 所有 |
| `op.size` | integer | 操作数大小（字节） | 所有 |
| `op.reg` | string | 寄存器名（如 `"rax"`） | reg |
| `op.imm` | integer | 立即数值 | imm |
| `op.mem_base` | string | 基址寄存器（如 `"rsp"`） | mem |
| `op.mem_index` | string | 索引寄存器（如 `"rsi"`，无则 `""`） | mem |
| `op.mem_scale` | integer | 缩放因子 | mem |
| `op.mem_disp` | integer | 偏移量 | mem |

示例 — 匹配 `mov [rsp+X], reg`：

```lua
if row.mnemonic == "mov"
   and op1.type == "mem" and op1.mem_base == "rsp"
   and op2.type == "reg" then
    local disp = op1.mem_disp
    local src_reg = op2.reg
end
```

#### row.regs — 寄存器快照

| 字段 | 类型 | 说明 |
|------|------|------|
| `regs.valid` | boolean | 快照是否有效 |
| `regs.rax` | integer | RAX 值 |
| `regs.rbx` | integer | RBX 值 |
| `regs.rcx` | integer | RCX 值 |
| `regs.rdx` | integer | RDX 值 |
| `regs.rsi` | integer | RSI 值 |
| `regs.rdi` | integer | RDI 值 |
| `regs.rbp` | integer | RBP 值 |
| `regs.rsp` | integer | RSP 值 |
| `regs.r8` ~ `regs.r15` | integer | R8-R15 值 |
| `regs.rflags` | integer | RFLAGS 值 |

可以通过寄存器名字符串动态访问：`regs[reg_name]`

#### row.stack[] — 栈快照

每个元素：

| 字段 | 类型 | 说明 |
|------|------|------|
| `offset` | integer | 相对于 RSP 的偏移 |
| `addr` | integer | 绝对地址 |
| `value` | integer | 8 字节值 |
| `is_rsp` | boolean | 是否为 RSP 指向的位置 |

#### row.pcode[] — PCode 语义操作

每个元素：

| 字段 | 类型 | 说明 |
|------|------|------|
| `opc` | integer | PCode 操作码编号 |
| `opc_name` | string | 操作码名称（如 `"COPY"`, `"INT_ADD"`, `"STORE"`, `"BRANCH"`） |
| `has_out` | boolean | 是否有输出 varnode |
| `dead` | boolean | 死代码消除标记（true = 不影响后续） |
| `out` | table/nil | 输出 varnode（仅 has_out=true） |
| `ins` | table[] | 输入 varnode 列表 |

Varnode 结构：

| 字段 | 类型 | 说明 |
|------|------|------|
| `space` | string | 地址空间（`"register"`, `"const"`, `"unique"`, `"ram"`） |
| `offset` | integer | 偏移 |
| `size` | integer | 大小（字节） |
| `reg_name` | string | 寄存器名（仅 space="register" 时有意义） |

### handlers — Handler 表

`handlers` 是一个 1-based 数组。

```lua
local h = handlers[i]
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `h.seg_idx` | integer | 段号 |
| `h.type` | string | Handler 类型（如 `"vPop"`, `"vPushReg"`, `"vAdd"`, `"unknown"`） |
| `h.detail` | string | 详细信息（如 `"vmStack[+0x48](rax) ->rsp+0x30"`） |
| `h.addr_start` | integer | 起始地址 |
| `h.addr_end` | integer | 结束地址 |
| `h.live_stores` | integer | 有效 STORE 操作数 |
| `h.live_loads` | integer | 有效 LOAD 操作数 |
| `h.summary` | string | 摘要文本（脚本可写入） |
| `h.row_indices` | integer[] | 包含的 rows 索引（1-based） |

## 全局函数

### log(...)

输出文本到引擎日志面板。支持多参数，自动以 tab 分隔。

```lua
log("handler", i, "type:", h.type)
```

### read_mem(addr, size) → string / nil

通过 IPC 从调试目标读取内存。返回十六进制字符串（如 `"48 89 5C 24"`），失败返回 nil。

```lua
local hex = read_mem(0x7FF601000000, 16)
```

### read_u64(addr) → integer / nil

读取 8 字节小端序整数。失败返回 nil。

```lua
local val = read_u64(row.regs.rsp)
```

### set_clipboard(text)

将文本写入系统剪贴板。

```lua
set_clipboard("mov rax, [rbx]")
```

### llvm_available() → boolean

检查 LLVM-C.dll 是否已加载。

### llvm_optimize_ir(ir_text [, opt_level]) → ir, err

优化 LLVM IR 文本。opt_level 默认 2（O2）。

返回两个值：优化后的 IR 文本和错误信息。成功时 err 为 nil，失败时 ir 为 nil。

```lua
local optimized, err = llvm_optimize_ir(ir_text, 2)
if err then log("[error]", err) end
```

### llvm_emit_asm(ir_text [, opt_level]) → asm, err

优化 LLVM IR 并编译为 x86-64 汇编（Intel 语法）。用法同上。

```lua
local asm_text, err = llvm_emit_asm(ir_text, 2)
```

## 回写机制

脚本可以通过设置全局变量 `writeback` 来声明需要回写到 C++ 的字段：

```lua
writeback = {"is_junk"}          -- 回写 rows[].is_junk 字段
writeback = {"handler_type"}     -- 回写 handlers[].type 和 .detail 字段
writeback = {"analysis"}         -- 回写 rows[].analysis 字段
```

回写在脚本执行完成后自动进行。

## 核心脚本说明

### annotate.lua

修复假存活指令。遍历所有未标记 junk 的指令，如果其 PCode 操作全部为 dead（或仅有 BRANCH/CBRANCH），则标记为 junk。

```
前置: 无
回写: is_junk
```

### split_handlers.lua

Handler 语义分类。通过顺序搜索指令模式识别 handler 类型：

- **vPop**: `mov REG, [vs_reg]` → `add vs_reg, 8` → `mov [rsp+X], REG`
- **vPush**: `sub vs_reg, N` → `mov [vs_reg], REG`，根据 REG 来源区分 vPushReg / vPushImm / vPushVSP
- **vOp**: `pushfq` → `pop [vs_reg]`，向前搜索算术/逻辑指令确定具体类型
- **vNand/vNor**: `or/and` 前有两个 `not` 指令
- **vStore**: `add vs_reg, M` + `mov REG, [vs_reg]` + `mov [REG], REG2`
- **vLoad**: `mov REG, [vs_reg]` + `mov REG2, [REG]` + `mov [vs_reg], REG2`
- **vExit**: `mov rsp, vs_reg` + 连续 pop + `ret`

```
前置: annotate.lua
回写: handler_type
```

### lift_to_llvm.lua

将 handler 序列提升为 LLVM IR。核心设计：

1. 每个 VMP slot offset 对应一个 `alloca`
2. INIT 映射：用 inline asm `={reg}` 读取物理寄存器初始值
3. 计算过程：符号栈模拟所有 handler
4. EXIT 映射：只对被修改的 slot 用 inline asm `{reg}` 写回物理寄存器
5. `vPushVSP + vLoad` 优化为 dup（复制栈顶）

```
前置: annotate.lua + split_handlers.lua
输出: vmp_lifted.ll（未优化 IR 文件）
```

### demo_llvm.lua

一键流程脚本。依次执行 annotate → split → lift → LLVM O2 → 输出。

```
前置: 无（自动调用前置脚本）
输出: vmp_optimized.ll, vmp_optimized.s, 日志中显示过滤后的汇编
```

### decompile.lua

纯 Lua 符号栈反编译器，不依赖 LLVM。通过模式匹配将 handler 序列翻译为伪汇编。

```
前置: annotate.lua + split_handlers.lua
输出: 日志中显示反编译结果
```

### tools.lua

公共工具函数库，被其他脚本 `dofile()` 调用。

| 函数 | 说明 |
|------|------|
| `get_init_pushes()` | 解析 init handler 的压栈顺序，返回 pushes 列表、vmstack_base、rsp_to_name 映射 |
| `get_vmstack_reg()` | 识别 vmStack 寄存器（分析 init handler 中 `sub REG, XX` 的目标寄存器） |
| `vmstack_lookup(ptr)` | 根据 vmStack 指针值查找对应的寄存器名和 slot 偏移 |
| `reg_size(name)` | 返回寄存器大小（字节）：al→1, ax→2, eax→4, rax→8 |
| `subreg_map[name]` | 子寄存器到 64 位基名的映射（如 `al→rax`, `r8d→r8`） |
| `get_reg_val(regs, name)` | 从寄存器快照中读取指定寄存器值（自动处理子寄存器截断） |
