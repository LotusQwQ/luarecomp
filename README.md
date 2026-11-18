# luarecomp

[![测试](https://github.com/LotusQwQ/luarecomp/actions/workflows/test.yml/badge.svg)](https://github.com/LotusQwQ/luarecomp/actions/workflows/test.yml)

把 **Lua 源码编译成各种"魔改格式"的字节码**，也能把魔改字节码转回标准格式，放进真正的 Lua 虚拟机里加载、运行和校验。

> Compile Lua source into modified bytecode formats and convert such bytecode back to the standard dump format, so it can be loaded, run and verified by the real VM. Supports PUC Lua 5.1 / 5.2 / 5.3 / 5.4 and LuaJIT 2.0 / 2.1. A format is described by a JSON profile.

```
源码.lua ──(真 Lua 编译器, lupa)──▶ 标准字节码 ──(profile)──▶ 魔改字节码
魔改字节码 ──(profile)──▶ 标准字节码 ──▶ 真 VM 里 load / 执行 / 静态校验
```

编译永远交给对应版本的**真实编译器**（lupa 自带 Lua 5.1–5.4、LuaJIT 2.0/2.1），本工具只负责格式转换，所以生成的指令和官方编译器完全一致。

设计思路、模块划分，以及能做到和做不到的事，见 [docs/DESIGN.md](docs/DESIGN.md)。

---

## 支持范围

| VM | 读写 | 编译 / 加载 / 执行验证 | 静态校验 | 无源码推 opcode | 注入 |
|---|---|---|---|---|---|
| Lua 5.1 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Lua 5.2 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Lua 5.3 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Lua 5.4 | ✓ | ✓ | ✓ | ✓ | ✓ |
| LuaJIT 2.0 / 2.1 | ✓ | ✓ | ✓ | ✓ | ✓ |

可描述的魔改：签名 / 版本 / format / LUAC_DATA、文件头字段的增删和顺序、尺寸字节、大小端、整数和浮点宽度、函数结构各段的**顺序**和**额外字段**、计数 / 行号 / 字符串长度的**编码方式**（int32、u16、varint、uleb128…）、常量类型标记重编号、opcode 平移或任意置换、**指令位域重新排布**、字符串常量 XOR。更深的改动用**插件**（几行 Python）补上。

## 安装

```bash
pip install lupa          # 必需，提供各版本真实的 Lua / LuaJIT
pip install -e .          # 可选：安装后有 `luarecomp` 命令
```

Python 3.10+。不安装也可以直接 `python -m luarecomp ...`。

## 快速开始

```bash
# 源码 → 魔改字节码
python -m luarecomp compile my.lua -p my_game.json -o my.bytes -n "@Scripts/My.lua"

# 魔改字节码 ↔ 标准字节码
python -m luarecomp to-std   game.bytes -p my_game.json -o game.luac
python -m luarecomp from-std game.luac  -p my_game.json -o game.bytes

# 验证 profile（带诊断）
python -m luarecomp check -p my_game.json chunks/*.bytes

# 反汇编、静态校验
python -m luarecomp disasm -p my_game.json game.bytes --max 200
python -m luarecomp verify -p my_game.json game.bytes

# 数据表：执行后导出成 JSON；改完再编回去（见下文「数据表」）
python -m luarecomp run game_table.bytes -p my_game.json --record Ctor -o table.json
python -m luarecomp build-table table.json -p my_game.json --constructor Ctor -o new_table.bytes
```

`-p` 可以是 JSON 路径，也可以是 `profiles/` 里的名字（如 `-p lua54`）。Windows 下通配符由工具自己展开。

---

## 为新游戏写 profile

本工具只处理**已经解密的**字节码。外层的加密、压缩、打包不在范围内（见文末「使用边界」）。

### 1. 文件头：`inspect`

```bash
python -m luarecomp inspect a.bytes b.bytes c.bytes -o my_game.json
```

`inspect` 会把签名长度、版本、LUAC_DATA 有无、尺寸字节的个数 / 含义 / 顺序、大小端等**每一种合理的排列都试一遍**，要求每份样本都能**完整解析到最后一个字节**并逐字节回写。存活下来的候选再按行为分组：

- 两个候选把样本转成标准格式的结果相同，**并且**把一段含长字符串、整数、浮点数的探针代码写回魔改格式的结果也相同，才算等价。
- 只有一组：`UNAMBIGUOUS`。尺寸字段的叫法可能有几种，但对结果没有影响。
- 多组：`AMBIGUOUS`。报告会列出到底是哪个设置没法确定（例如 `size.size_t=4` 还是 `8`），以及什么样的样本能区分它们（例如"加一个含 254 字节以上字符串的样本"）。

样本给得越多、越杂越好。如果没有任何排列能解析成功，会给出走得最远的那个候选，列出它解析失败的位置、最后成功读到的字段和附近的十六进制内容。这通常说明函数结构也被改过，需要按下面的「深度魔改」手写。

### 2. opcode：`infer-ops`（不需要源码）和 `match-ops`（需要源码）

```bash
python -m luarecomp infer-ops -p my_game.json chunks/*.bytes -o my_game.json
```

`infer-ops` 根据每条指令**对操作数做了什么**来排除不可能的映射，例如寄存器号必须小于 maxstack、常量下标不能越界、某个操作数必须是字符串常量、跳转目标必须落在函数内、EQ 后面必须跟 JMP、函数最后一条必须是返回、未使用的操作数是 0、CALL / SETLIST 的寄存器范围不能越界等。然后用"一一对应"约束和前后顺序约束做传播。

- **得出的结论不会出错。** 在 6 种 VM、随机置换的测试里，真实映射从未被排除。
- 平移（affine，`custom = std*mul + add`）类映射通常能**唯一确定**，并直接写进 profile。
- 结构上无法区分的 opcode（ADD / SUB / MUL… 对操作数的要求完全一样）会作为"歧义组"列出来，不会瞎猜。这时用 `match-ops` 补齐：

```bash
python -m luarecomp match-ops -p my_game.json --pair game_json.bytes json.lua --pair x.bytes x.lua -o known.json
python -m luarecomp infer-ops -p my_game.json chunks/*.bytes --known known.json -o my_game.json
```

`match-ops` 拿你知道源码的 chunk（游戏自带的 json.lua、class.lua 之类）用真实编译器编译后，与游戏 chunk **对齐**（difflib 序列对齐，不要求逐条一致），每条对齐的指令投一票，按多数决定映射。源码版本略有不同、局部被改过、函数多了少了，都能容忍；被编辑导致寄存器整体偏移的区段按位置配对，算作"弱票"，只在没有强票时采用。可以给多对样本累积覆盖率。

### 3. 验证：`check`

```bash
python -m luarecomp check -p my_game.json chunks/*.bytes
```

每个 chunk 依次验证三个步骤，失败时会告诉你**卡在哪里**：

1. **解析**：报告字节偏移、结构路径（如 `main/3/1`）、字段名（如 `K[12].tag`）、最后成功读到的几个字段，以及偏移附近的十六进制内容。还会给出提示，比如"LUAC_INT 不对，多半是整数宽度或大小端错了"。
2. **逐字节回写**：报告第一个不一致的字节，以及它在原文件里属于哪个字段、在重写结果里由哪个字段写出。
3. **语义**：转成标准字节码后跑静态校验器，再交给真实 VM 加载。违规按 opcode 汇总，直接指出**哪个自定义 opcode 号**可疑。

第 3 个步骤很重要：**Lua 5.2 以后的加载器根本不校验字节码**。opcode 映射错了，`load` 照样成功，运行时才崩溃或算错。v1 的 `check` 只做到 load 这一步，会把错误的 profile 报成 OK。如果只有极少数指令违规，提示会改成"更像是这一处数据损坏或手工生成"，而不是"映射错"。

`--json` 输出机器可读结果，`-q` 不打印十六进制内容。

---

## profile 参考

所有字段都可省略，省略即取该 VM 的标准值。未知字段会报错，并给出"你是不是想写 …"的提示。

```jsonc
{
  "name": "my_game",
  "lua": "5.3",                      // 5.1 | 5.2 | 5.3 | 5.4 | luajit2.0 | luajit2.1（省略 = 5.3，兼容 v1）

  // ---- 文件头（简单写法）
  "signature": "1b4c7561",           // hex，可带空格；LuaJIT 标准为 1b4c4a
  "version": 83, "format": 0,
  "luac_data": "1993 0d0a 1a0a",     // 没有这 6 字节就写 ""（5.2 里是 LUAC_TAIL）
  "sizes": [["int",4],["size_t",8],["instruction",4],["integer",8],["number",8]],
                                     // 文件头里【实际存在】的尺寸字节及顺序；也可写成 {"size_t": 4, ...}
  "endian": "little",
  "integral": 0,                     // 5.1/5.2：lua_Number 是否为整数
  "luac_int": 22136, "luac_num": 370.5, "check_luac_values": true,

  // ---- 文件头（完整写法，深度魔改用）：列出每一项及其顺序
  "header": ["signature", {"const": "c0de"}, "version", "format", {"keep": 3, "fill": "000000"},
             "size:size_t", "size:integer", "size:number", "nupvals", "luac_num", "luac_int"],
             // const：必须等于这些字节；keep：原样保留 n 个字节（从标准格式转过来时用 fill）

  // ---- 函数结构：各段的顺序，可插入额外字段
  "function": ["maxstack", "code", {"keep": "u8"}, "constants", "nparams", "vararg", "source",
               "line", "lastline", "protos", "upvals", "lines", "upnames", "locvars"],
             // 每个标准段必须恰好出现一次；keep 类型：u8 u16 u32 count string；也可用 {"const": hex}

  // ---- 编码方式
  "encoding": {"count": "uleb", "line": "u16", "lineinfo": "u16", "pc": "uleb", "string": "count"},
             // count/line/lineinfo/pc: i8 u8 i16 u16 i32 u32 varint uleb
             // string: lua51 (size_t 长度含 \0) | lua53 (1 字节, 0xFF 后跟 size_t) | lua54 (varint) | count

  "const_tags": {"integer": 7, "float": 8},     // 常量类型标记重编号（键名随版本不同，报错会列出可用的）

  // ---- 指令
  "opcodes": {"type": "affine", "mul": 1, "add": 11, "mod": 47},
             // 或 {"type": "table", "map": [每个标准 opcode 对应的自定义编号]}
             // 或 {"type": "names", "map": {"MOVE": 11, "LOADK": 12, ...}}
             // 或 {"type": "identity"}
  "instruction": {"op": [26, 6], "A": [18, 8], "B": [0, 9], "C": [9, 9], "Bx": [0, 18], "Ax": [0, 26]},
             // 位域重新排布：[起始位, 宽度]；5.4 还有 k、sJ，LuaJIT 是 op A B C D；*_bias 改有符号偏置

  "strings": {"type": "xor", "key": "a5c3", "scope": ["constants", "names", "source"]},
  "plugin": "my_hooks.py"            // 见下
}
```

`profiles/` 里有各版本的标准 profile（`lua51` … `luajit21`），以及两份**虚构**示例：`example_custom`（简单）和 `example_deep`（深度）。

### 插件

profile 描述不了的改动，用一个 Python 文件补上。下面这些钩子都是可选的：

| 钩子 | 作用 |
|---|---|
| `pre_read(data) -> data` / `post_write(data) -> data` | 整个文件读入前、写出后做变换（如去掉或加上尾巴） |
| `decode_instruction(word, ctx) -> std_word` / `encode_instruction(std_word, ctx) -> word` | 任意指令编码 |
| `decode_string(s, scope)` / `encode_string(s, scope)` | 任意字符串变换 |
| `read_keep(reader, type)` / `write_keep(writer, type, value)` | 自定义额外字段 |

**插件就是可执行代码**，所以只有显式传 `--allow-plugin`（库里是 `allow_plugins=True`）才会加载。别人给的 profile 如果带插件，先看过代码再用。`tests/data/rot7_plugin.py` 是一个虚构示例。

---

## 注入：在原 chunk 开头执行一段代码

整文件替换有时不可行，比如引擎在加载时注入了环境，或者你只想加一个 hook。这时可以用注入：

```bash
python -m luarecomp inject game.bytes -p my_game.json --code hook.lua --isolate -o game_patched.bytes --dry-run
```

```python
import luarecomp as R
from luarecomp import inject as I

prof = R.Profile.load("my_game.json")
ch = R.parse(open("game.bytes", "rb").read(), prof)
child = I.compile_child(b"Foo.Send = wrap(Foo.Send)", prof.lua, isolate=True, on_error="print(err)")
patched = I.inject(ch, child)          # 内部已调用 verify_injection
open("out.bytes", "wb").write(R.dump(patched, prof))
```

**实现方式**：新代码编译成子函数，追加到主函数子函数表的末尾，已有的 CLOSURE / FNEW 下标都不会变。主函数开头插入 `CLOSURE R0 k; CALL R0 1 1`（5.4 插在 VARARGPREP 之后；LuaJIT 用 `FNEW` / `CALL`）。子函数与原 chunk 共享环境：5.2+ 共享 `_ENV` upvalue，5.1 和 LuaJIT 继承函数环境。

**保证什么**（每次注入都会自动检查，不满足就报错）：

- 原有的每条指令、每个常量、每个子函数都不变，顺序也不变；
- 结果通过静态校验，并且能被真实 VM 加载；
- 已经注入过的 chunk 会被拒绝，避免重复注入；需要再注入一次时传 `--force`；
- 行号和局部变量的调试信息会同步平移，原代码报错时的行号与注入前完全一致（5.4 的相对行号表、LuaJIT 的压缩调试块都会正确重建）；
- `--isolate`：注入代码放在 `pcall` 里执行，**它出错不会让原 chunk 停下来**；`--on-error` 指定出错时执行的 Lua 代码，错误信息在变量 `err` 里。

**不保证什么**：注入代码在真实宿主里的运行行为，比如引擎对象是否已经就绪、加载顺序如何。注入代码在原 chunk **之前**运行，要 hook 的东西如果是原 chunk 自己定义的，得换思路（比如 hook 它依赖的全局对象，或者设置元表）。`--dry-run` 会在桩环境里把原版和注入版各跑一遍，对比返回值，能发现明显的问题，但最终要以真机为准。

---

## 数据表：导出成 JSON、改完再编回去

很多游戏把配置表编译成 chunk：执行后返回一张大表，表里每一行常常由宿主函数构造，比如 `Ctor("ItemData", {id = 1, ...})`。

```bash
# 导出：转成标准格式后在真实 VM 里执行，Ctor 换成记录类型的桩（返回 fields 加上 "__type"）
python -m luarecomp run game_table.bytes -p my_game.json --record Ctor -o table.json

# 修改 table.json 之后重建：JSON -> Lua 源码 -> 真实编译器 -> 魔改格式
python -m luarecomp build-table table.json -p my_game.json --constructor Ctor     --source table.lua --compare game_table.bytes -o new_table.bytes
```

- **不手拼字节码**：重建时生成的是普通 Lua 源码（可以用 `--source` 保存下来查看），由真实编译器来编译。RK 位宽、常量数量、SETLIST 分批这些细节都交给编译器处理。
- **自动回读**：构建完成后会立即在真实 VM 里执行一遍新 chunk，确认它返回的数据与 JSON **逐项一致**，否则报错。`--compare` 会再和原 chunk 对比，列出差异所在的路径（比如 `return[1][1][37].name: "sword" vs "axe"`）。
- **JSON 约定保证精确往返**：
  - 键为 1..n 的表导出为数组；
  - 整数键写成 `"123"`；
  - 键是布尔、浮点或者「长得像整数的字符串」的表，用 `{"__pairs__": [[键, 值], ...]}` 表示；
  - 非 UTF-8 字符串用 `{"__bytes__": "hex"}` 表示；
  - 整数和浮点数保持区分；
  - 键按固定顺序输出，方便做 diff。
- **局限**：重建出的字节码与原 chunk 的寄存器分配、常量顺序不一定相同，只保证**执行结果相同**。如果宿主除了返回值还依赖别的东西（比如全局副作用、函数值），需要用 `--env` 提供更完整的桩。

## 作为库使用

```python
import luarecomp as R

prof = R.Profile.load("my_game.json")
data = R.compile(open("new.lua", "rb").read(), prof, b"@Scripts/My.lua")   # 源码 → 魔改
std = R.to_std(open("game.bytes", "rb").read(), prof)                       # 魔改 → 标准
ok, err = R.load_check(open("game.bytes", "rb").read(), prof)

ch = R.parse(game_bytes, prof)       # Chunk；指令和常量标记一律是标准编号
for path, f in ch.walk(): ...        # path 形如 main/2/0
out = R.dump(ch, prof)

from luarecomp import verify, disasm, detect, opinfer, diagnose, runtime
runtime.run(std, "5.3", env_setup=b"function(env) env.CS = {} end")   # 在真实 VM 的桩环境里执行
```

### 从 v1 迁移

`lua53recomp.py` 仍然存在，v1 的函数、命令行和 profile 都**原样可用**。`tests/test_compat_v1.py` 就是 v1 的原测试，无改动，且全部通过。新代码请用 `import luarecomp`。

---

## 能做什么 / 不能做什么

**能做**：上面「支持范围」里列出的全部内容。

**做不到或做不全的**：

- **结构上无法区分的 opcode**：ADD、SUB、MUL 这类 opcode 对操作数的要求完全一样，单凭字节码分不出来。如果游戏用的不是平移类映射，就需要 `match-ops` 配合已知源码；样本覆盖不到的 opcode 也确定不了。
- **LuaJIT** 里运行时专用的 opcode（JFORL、ILOOP、FUNCF…）不会出现在字节码文件里，它们的编号对文件转换没有影响。
- **5.4 以外改了指令宽度**（不是 32 位）、在**指令流里插入非指令数据**、或者**每个函数用不同密钥**之类的改动，需要写插件。
- 外层的**加密、压缩、打包，不处理，也不打算处理**（见下文）。

## 测试

```bash
python -m unittest discover -s tests              # 约 4 秒
LUARECOMP_SLOW=1 python -m unittest discover -s tests   # 加上超大函数（EXTRAARG / LOADKX 等），约 30 秒
```

测试不依赖任何游戏文件，全部使用虚构格式和真实编译器的输出：

- 6 种 VM 的往返与语义一致性；
- 静态校验器对真实编译器全部产物零误报（PUC 5.1–5.4 覆盖了每一个 opcode）；
- LuaJIT 的 opcode 表与 VM 内部的 `lj_bc_mode` 逐项核对；
- 深度魔改与插件；
- opcode 推断；
- 注入的各项保证；
- `check` 的错误定位；
- profile 报错信息；
- 数据表导出与重建（6 种 VM）；
- 命令行；
- v1 兼容。

---

## 使用边界与免责声明

本工具是**字节码格式转换和分析**工具，用来在你**有权修改**的软件上做学习、研究、互操作和 Mod 开发。

**适用于：**

- 你自己编写的、或拥有修改权的程序；
- 许可协议或用户协议明确允许修改、Mod 的软件，或者已经取得权利人许可的互操作开发；
- 在本地、单机环境里学习和研究 Lua 字节码；
- 范围明确、事先取得书面授权的安全研究。

**不得用于：**

- 在网络游戏或任何多人服务中获取不公平优势，包括外挂、自动化，以及修改数值、伤害、掉落、抽卡结果等会影响服务端判定或其他用户体验的内容；
- 绕过或破坏反作弊、完整性校验、DRM、加密、授权或计费机制；
- 访问或篡改他人的账号、存档或服务器数据；
- 传播他人享有权利的脚本、数据、资源或修改后的客户端；
- 任何违反适用法律、许可协议或用户协议的用途。

**工具本身刻意：**

- 不提供解密、脱壳、内存读写、注入进程或对抗反作弊的功能。插件机制是为了描述格式差异，**不是**为了绕过保护。
- 本仓库**不收录、也不接受**针对具体商业产品的 profile、密钥、插件或字节码样本。仓库里所有 profile 和测试数据，均为虚构或来自标准 Lua / LuaJIT 实现。
- 贡献代码时请遵守同样的规则：Issue 和 PR 里不要附带第三方产品的文件或密钥。

**责任：** 使用者自行判断并承担使用本工具的全部责任。软件按 MIT 许可"原样"提供，不附带任何担保。本声明不构成法律意见：各地法律对逆向工程、互操作例外和技术保护措施的规定不同，不确定时请咨询专业人士。

## 反馈与问题

使用中遇到问题、发现 bug 或有改进建议，请到 [GitHub Issues](https://github.com/LotusQwQ/luarecomp/issues) 提交。

报告问题时最好附上：
- 运行的完整命令，以及完整的输出（`check` 的输出已经带有偏移和字段信息，直接贴上即可；需要 Python 调用栈时加 `--traceback`）；
- 你的 profile；
- Python、lupa 和本工具的版本（`python -m luarecomp --version`）。

请不要附带第三方商业产品的字节码文件、密钥或针对它们的 profile（见上文「使用边界」）。需要样本才能复现时，尽量用标准 Lua 编译一段最小代码，再用虚构的 profile 转换出来。

## License

MIT
