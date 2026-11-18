# -*- coding: utf-8 -*-
"""Lua sources that together use (almost) every opcode of each VM.

Used to check the ISA tables / verifier against what the real compilers emit, and as
input for opcode-inference tests.  `big_sources()` adds the rare encodings (EXTRAARG
after SETLIST / LOADKX) which need very large functions.
"""

COMMON = r"""
local M = {}
local up1, up2 = 1, "two"
local t = {1, 2, 3, "four", x = 5, ["y z"] = 6, [7] = 7.5, nested = {a = {b = {}}}}
local function vf(...) local a, b = ... return select('#', ...), a, b, ... end
local function rec(n) if n <= 1 then return 1 end return n * rec(n - 1) end
local function tail(n) if n == 0 then return "done" end return tail(n - 1) end
function M.method(self, a) self.v = (self.v or 0) + a return self end
local obj = {v = 0, method = M.method}
obj:method(3):method(4)
local s = 0
for i = 1, 10 do s = s + i end
for i = 10, 1, -2 do s = s - i end
for k, v in pairs(t) do if type(v) == "number" then s = s + v end end
for i, v in ipairs({5, 6, 7}) do s = s + i * v end
local w = 0
while w < 5 do w = w + 1 if w == 3 then break end end
repeat w = w - 1 until w <= 0
local a, b, c = 7, 3, nil
local arith = {a + b, a - b, a * b, a / b, a % b, a ^ b, -a, a + 1, 2 - a, a * 0.5}
local cmp = {a == b, a ~= b, a < b, a <= b, a > b, a >= b, a == 7, "x" < "y", not c}
local logic = (a and b) or c, (c or a) and b
local str = "con" .. "cat" .. a .. b .. tostring(c)
local len = #str + #t
local g1 = GLOBAL_X
GLOBAL_Y = { up1, up2 }
local function upd() up1 = up1 + 1 up2 = up2 .. "!" return up1, up2 end
upd()
local closures = {}
for i = 1, 3 do closures[i] = function() return i + up1 end end
do local x = {} setmetatable(x, {__index = function(_, k) return k end}) local _ = x.q end
local bigt = {}
for i = 1, 70 do bigt[i] = i end
local ctor = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,
  31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55, vf(1, 2)}
local t2 = {vf(1, 2, 3)}
local nilv = nil
local x1, x2, x3
local bool1, bool2 = true, false
local f2 = function(...) return ... end
local cond = a > 2 and "big" or "small"
if a then s = s + 1 elseif b then s = s + 2 else s = s + 3 end
if not (a < b) and (b < a or c) then s = s + 4 end
return rec(5), tail(3), s, len, str, cond, f2(1, 2), #ctor, #t2, vf(1, nil, 3)
"""

V52 = r"""
local r = 0
for i = 1, 3 do
  for j = 1, 3 do
    if j == 2 then goto continue end
    r = r + j
    ::continue::
  end
end
local _ENV = setmetatable({}, {__index = _ENV})
newglobal = r
return r, newglobal
"""

V53 = r"""
local a, b = 13, 5
local ints = {a // b, a & b, a | b, a ~ b, a << 2, a >> 1, ~a, a // 2.0, 7 // 2, 3 & 1}
local mt = math.type(1) .. math.type(1.0)
local big = 9223372036854775807
return ints[1], ints[7], mt, big, 0x10, 1e300
"""

V54 = r"""
local a <const> = 10
local b = 3
local ok = pcall(function()
  local h <close> = setmetatable({}, {__close = function() end})
  return h
end)
local ints = {b // 2, b & 1, b | 4, b ~ 7, b << 2, b >> 1, ~b, b + 1, b - 1, b * 2, b % 2, b ^ 2, b / 2,
              b + 1.5, b * 2.5, b - 0.5, b // 2.5, b % 1.5, b & 0xF0, b | 0x0F, b ~ 0xFF, b >> 3, b << 3}
local cmps = {b == 3, b == "x", b < 5, b <= 5, b > 5, b >= 5, b == 3.5, 3 < b, 3 <= b}
local t = {}
t.field = 1
t[1] = 2
t[b] = 3
t["k"] = b
local i = 0
for _, v in pairs({1, 2}) do i = i + v end
local s = b .. "x" .. a
local e = -b
local n = not b
local l = #t
local f = 1.5
local g = -7
local key = s
local z = t[key]
local sh = {2 << b, b << i, b >> i, 1 >> b}
return z, sh[1], a, ok, ints[1], cmps[1], t.field, t[1], i, s, e, n, l, f, g
"""

JIT = r"""
local ffi_ok = pcall(require, "ffi")
local t = {1, 2, "x", a = 1.5, b = {}, [3.25] = true, [-7] = "neg"}
local big, neg, fl = 123456789012, -5, 2.75
local function f(a, ...) local s = 0 for i = 1, select("#", ...) do s = s + select(i, ...) end return a .. s end
local function vf2(...) return ... end
local function tm0(...) return f(vf2(...)) end
local g = function() return t end
for k, v in pairs({p = 1}) do t[k] = v end
for i, v in ipairs({1, 2}) do t[i] = v end
for k, v in next, {q = 2} do t[k] = v end
while big > 1e11 do big = big / 2 end
local u = 1
local function setu(x) u = x u = "s" u = 1.5 u = true u = nil end
setu(3)
local n1, n2 = 3, 4
local r = {n1 + 1, n1 - 1, n1 * 2, n1 / 2, n1 % 2, 1 + n1, 1 - n1, 2 * n1, 2 / n1, 2 % n1,
           n1 + n2, n1 - n2, n1 * n2, n1 / n2, n1 % n2, n1 ^ n2, -n1, #t}
local c = {n1 < n2, n1 >= n2, n1 <= n2, n1 > n2, n1 == n2, n1 ~= n2, n1 == "s", n1 ~= "s", n1 == 3,
           n1 ~= 3, n1 == nil, n1 ~= true, not n1}
local t3 = {}
t3[n1] = n2 t3.k = n1 t3[1] = 2 t3[n1] = "s" t3[2] = "x"
local v = t3[n1] or t3.k or t3[1]
local cat = "a" .. n1 .. "b"
local cd = 0x7fffffffffffffffLL
local function tc(...) return f(...) end
local function tm(...) return f(vf2(...)) end
return f("r", 1, 2, 3), #t, t.a, neg * fl, g() == t, u, r[1], c[1], v, cat
"""


def sources(lua):
    """-> list of (name, source bytes) valid for `lua`."""
    out = []
    if lua.startswith("luajit"):
        out.append(("common", COMMON))
        jit = JIT if lua == "luajit2.1" else JIT.replace("local cd = 0x7fffffffffffffffLL\n", "")
        out.append(("jit", jit))
    else:
        out.append(("common", COMMON))
        if lua in ("5.2", "5.3", "5.4"):
            out.append(("v52", V52))
        if lua in ("5.3", "5.4"):
            out.append(("v53", V53))
        if lua == "5.4":
            out.append(("v54", V54))
    return [(n, s.encode()) for n, s in out]


def big_sources(lua):
    """Huge functions that force the extended encodings (slow to compile, ~1 s)."""
    out = []
    # > 25550 array items in one constructor -> SETLIST with C overflow (EXTRAARG / raw word)
    out.append(("bigsetlist", "return {" + ",".join(["1"] * 26000) + "}"))
    if lua in ("5.2", "5.3", "5.4"):
        # > 2^18 (5.2/5.3) or 2^17 (5.4) constants -> LOADKX + EXTRAARG
        n = 262200 if lua != "5.4" else 131200
        body = " ".join("x = %d" % (i + 1000000) for i in range(n))
        out.append(("bigk", "local function f() local x " + body + " return x end return f"))
    return [(n, s.encode()) for n, s in out]
