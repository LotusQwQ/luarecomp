# lua53-recompiler

把 **Lua 5.3 源码编译成各种"魔改格式"的 Lua 5.3 字节码**，也能把魔改字节码转回标准格式，放进真正的 Lua 5.3 里加载和运行。

> Compile Lua 5.3 source into modified Lua 5.3 bytecode formats (custom signature / header / size_t / shuffled opcodes / renumbered constant tags), and convert such bytecode back to stock Lua 5.3 so it can be loaded and executed by a real Lua 5.3 VM. A format is described by a small JSON profile.

## 为什么需要它

很多游戏（xLua、ToLua 5.3、SLua 等）发布的 Lua 字节码对**外层格式**做了改动：签名换掉、文件头字段增删、size_t 改成 4 字节、opcode 编号打乱、常量类型标记重新编号……
但**指令语义仍然是原版 Lua 5.3**。官方 `luac` 编出来的东西游戏无法识别，游戏里的 chunk 官方 Lua 也无法加载。

此时修改逻辑往往只能手工拼字节码：一条条拼指令、修跳转偏移、补行号信息，又慢又容易崩。

该工具思路为：

```
源码.lua ──(真 Lua 5.3 编译, lupa)──▶ 标准字节码 ──(profile)──▶ 魔改字节码
魔改字节码 ──(profile)──▶ 标准字节码 ──▶ 在真 Lua 5.3 里 load / 执行验证
```

编译交给真正的 Lua 5.3（通过 [lupa](https://github.com/scoder/lupa)），本工具只负责格式转换，所以生成的代码和官方编译器完全一致。

## 安装

```bash
pip install lupa        # 自带 Lua 5.1~5.4 运行时，本工具用其中的 lua53
```

单文件 `lua53recomp.py`，没有其它依赖，Python 3.8+。

## 快速开始

```bash
# 1. 源码 → 魔改字节码
python lua53recomp.py compile my.lua -p profiles/example_custom.json -o my.bytes -n "@Scripts/My.lua"

# 2. 魔改字节码 → 标准 Lua 5.3 字节码（可以交给 unluac 等反编译器，或在 Lua 5.3 里运行）
python lua53recomp.py to-std game.bytes -p my_game.json -o game.luac

# 3. 标准字节码 → 魔改字节码
python lua53recomp.py from-std game.luac -p my_game.json -o game.bytes

# 4. 验证 profile 是否正确（逐字节回转 + 真 Lua 5.3 加载）
python lua53recomp.py check -p my_game.json chunks/*.bytes
```

`-p` 可以给 JSON 路径，也可以直接写 `profiles/` 下的名字（如 `-p lua53`）。

## 为新游戏写 profile

### 第 0 步：拿到明文 chunk

本工具只处理**已经解密的** Lua 字节码。游戏外层的加密、打包（AssetBundle、自定义 zip、XOR 等）需自行解决。判断方法：文件开头前十几个字节里应该能看到 `0x53`（版本号），后面跟着 `19 93 0d 0a 1a 0a` 之类的结构。

### 第 1 步：分析文件头

```bash
python lua53recomp.py inspect game.bytes
```

输出示例：

```
signature b'GAME', version 0x53, format 1
LUAC_DATA: standard
size bytes (4): [4, 4, 8, 8]
LUAC_INT 0x5678 as 8-byte little, LUAC_NUM 370.5 as 8-byte
header length 33, main upvalues 1

draft profile:
{ "name": "draft", "signature": "47414d45", "version": 83, "format": 1,
  "endian": "little", "sizes": [["int",4],["size_t",4],["integer",8],["number",8]],
  "opcodes": {"type": "identity"} }
```

把草稿存成 `my_game.json`。**尺寸字段名是猜的**：标准 Lua 5.3 有 5 个尺寸字节（int、size_t、instruction、integer、number），只剩 4 个时最常见的是去掉了 instruction。如果后面 `check` 报错，回来调整这里。

### 第 2 步：推出 opcode 映射

找一份**你知道源码**的 chunk：游戏自带的第三方库（json.lua、inspect.lua、class.lua 等）往往就有原始源码，或者游戏里有些逻辑本来就是明文 Lua。然后运行：

```bash
python lua53recomp.py match-ops -p my_game.json game_json.bytes json.lua -n "@json.lua"
```

工具会把两份指令流逐条对齐，列出 `std 编号 → 游戏编号`。如果所有差值相同，会直接提示 `affine` 写法。示例：

```
  MOVE      std  0 -> custom 11
  LOADK     std  1 -> custom 12
  ...
22/47 opcodes observed; missing: ...
looks affine: "opcodes": {"type": "affine", "add": 11, "mod": 47}
```

- 前提是源码和 Lua 版本一致（5.3.x 的编译输出基本稳定）。报 `shape differs` 说明源码版本对不上。
- 如果映射不是简单的平移，就用多份 chunk 把 47 个 opcode 凑齐，写成 `table`。

### 第 3 步：验证

```bash
python lua53recomp.py check -p my_game.json 一堆游戏chunk/*
```

全部 `round-trip=True lua53-load=True` 才算 profile 正确：

- `round-trip`：游戏格式 → 标准 → 游戏格式，结果与原文件**逐字节一致**
- `lua53-load`：转出的标准字节码能被真 Lua 5.3 加载

尽量多放几十个不同的 chunk，覆盖更多的 opcode 和常量类型。

## profile 字段说明

```jsonc
{
  "name": "example_custom",
  "signature": "4741 4d45",          // 文件开头签名（hex，可带空格）。标准为 1b4c7561 (\x1bLua)
  "version": 83,                     // 0x53
  "format": 1,                       // 标准为 0
  "luac_data": "1993 0d0a 1a0a",     // 标准 LUAC_DATA；如果格式里没有这 6 字节，写 ""
  "sizes": [["int", 4], ["size_t", 4], ["integer", 8], ["number", 8]],
                                     // 文件头里【实际存在】的尺寸字节及顺序；没列出的取默认值
                                     // 默认 int4 size_t8 instruction4 integer8 number8
  "endian": "little",                // 或 "big"
  "luac_int": 22136,                 // 0x5678，一般不用改
  "luac_num": 370.5,
  "check_luac_values": true,         // 设 false 可跳过 LUAC_INT/NUM 校验
  "const_tags": {"float": 19, "integer": 3},
                                     // 常量类型标记重编号；可设 nil boolean float integer short_string long_string
                                     // 标准值 0 1 3 19 4 20
  "opcodes": {"type": "affine", "mul": 1, "add": 11, "mod": 47}
                                     // 游戏编号 = (标准编号 * mul + add) % mod
                                     // 或 {"type": "table", "map": [47 个数, map[标准编号] = 游戏编号]}
                                     // 或 {"type": "identity"}
}
```

`profiles/example_custom.json` 是一份**虚构**格式，用来演示所有选项。`profiles/lua53.json` 是标准格式。

## 作为库使用

```python
import lua53recomp as R

prof = R.Profile.load("my_game.json")

# 整文件替换
data = R.compile(open("new.lua", "rb").read(), prof, b"@Scripts/My.lua")

# 游戏 chunk → 标准字节码 → 在真 Lua 5.3 里执行
std = R.convert(open("game.bytes", "rb").read(), prof, R.STANDARD)
ok, err = R.load_check(std)

# 低层：解析 / 修改 / 写回（proto 内部一律使用标准 opcode 编号）
nup, root = R.parse(game_bytes, prof)
out = R.dump(root, prof, nup)
```

### 在原 chunk 开头注入一段代码

整文件替换有时不可行：比如引擎加载脚本时会注入 `this` 之类的环境，或者你只想加一个 hook、不想重写整个文件。`inject_prologue` 会把一段新代码作为子函数挂到原 chunk 上，并在最开头调用它，**共享原 chunk 的 `_ENV`**：

```python
nup, root = R.parse(game_bytes, prof)
child = R.compile_proto(b"""
    local old = SomeModule.Send
    SomeModule.Send = function(self, req, ...)
        req.headers["X-Sign"] = MySign(req)
        return old(self, req, ...)
    end
""", b"@hook")
patched = R.dump(R.inject_prologue(root, child), prof, nup)
```

实现方式：子函数追加到主函数子函数表的**末尾**（不影响已有 `CLOSURE` 下标），主函数前面插入 `CLOSURE R0 k; CALL R0 1 1`，同步修正行号表、局部变量范围和 maxstack。Lua 的跳转都是相对偏移，所以原有代码不受影响。

**注意**：这段代码在原 chunk **之前**运行，如果要 hook 的东西是原 chunk 自己定义的，需要换思路（比如 hook 它依赖的全局对象，或者设置元表等定义完成后再替换）。另外请自己防止重复注入。

### 先验证逻辑

转成标准字节码后，可以用 lupa 在自己搭的假环境里执行，提前发现大部分逻辑错误：

```python
lua = R._lua()   # lupa.lua53.LuaRuntime(encoding=None)
runner = lua.eval(b"""
function(b)
  local stub = setmetatable({}, {__index = function(t, k) return t end, __call = function(t) return t end})
  local env = setmetatable({CS = stub, require = function() return stub end},
                           {__index = _G})
  local f = assert(load(b, 'game', 'b', env))
  return f()
end""")
result = runner(std)
```

用万能桩对象（`__index` / `__call` 都返回自己）模拟引擎侧的 C# 对象，再检查定义出来的全局函数、返回的数据表是否符合预期。**引擎特有的行为（xLua 的泛型方法、C# 对象的元表细节等）模拟不了，最终仍以真机为准。**

## 能做什么 / 不能做什么

支持：Lua 5.3 指令集 + 任意签名 / format / LUAC_DATA / 尺寸字节组合 / size_t 4 或 8 / integer、number 4 或 8 / 大小端 / opcode 平移或任意置换 / 常量标记重编号

不支持：

- 其它 Lua 版本（5.1 / 5.2 / 5.4）：指令集和函数结构不同
- **LuaJIT** 字节码：完全是另一套格式（很多 ToLua 游戏用的是它）
- 改了指令位域布局、在函数结构里加字段 / 调换顺序、加密字符串常量等更深的魔改：需要自己改读写代码
- 游戏外层的加密、打包

## 测试

```bash
python -m unittest discover -s tests -v
```

测试不依赖任何游戏文件：用虚构格式验证编译、逐字节回转、执行结果一致、去除调试信息、注入、opcode 推导和 inspect。

## 免责声明

本工具仅用于学习、研究，以及在你有权修改的软件上做互操作和 Mod 开发。请遵守相关软件的用户协议和当地法律，不要用于破坏他人的服务、作弊或侵犯版权。

## License

MIT
