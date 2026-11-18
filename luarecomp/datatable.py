# -*- coding: utf-8 -*-
"""Data-table chunks: run a chunk in a stub environment and export what it returns as
JSON, and build a chunk back from JSON by generating Lua source and compiling it with
the real compiler (no hand-assembled bytecode).

JSON conventions (chosen so that export -> build -> export is exact):
  Lua table with keys 1..n        -> list
  Lua table with string/int keys  -> object; integer keys are written as "123"
  any other table (bool/float keys, or a string key that looks like an integer)
                                  -> {"__pairs__": [[key, value], ...]}
  string that is not valid UTF-8  -> {"__bytes__": "hex"}
  record built by a stubbed constructor  -> object with the type under "__type"
  empty table                     -> {}
  integers stay integers and floats stay floats (Lua 5.3+ keeps the difference)

Records: many games build every row through a host function, e.g.
``Ctor("ItemData", {id = 1, ...})``.  `run(..., records=["Ctor"])` replaces such globals
with a stub that returns the fields plus "__type"; `build(..., constructor="Ctor")` turns
objects that carry "__type" back into that call.
"""
import json
import math
import re

from . import core, runtime
from .errors import RecompError

TYPE_KEY = "__type"
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_INTLIKE = re.compile(r"^-?(0|[1-9][0-9]*)$")
_KEYWORDS = set("and break do else elseif end false for function goto if in local nil not or repeat "
                "return then true until while".split())


class TableError(RecompError):
    pass


# ---------------------------------------------------------------- run / export
def _stub_lua(records, type_key):
    names = ", ".join("%r" % n for n in records)
    return ("""function(env)
  for _, name in ipairs({%s}) do
    env[name] = function(tname, fields, ...)
      if select('#', ...) > 0 then error(name .. ': more than 2 arguments, adapt the stub with --env') end
      local t = {}
      if type(fields) == 'table' then for k, v in pairs(fields) do t[k] = v end end
      t['%s'] = tname
      return t
    end
  end
end""" % (names, type_key)).encode()


def run(data, prof, records=(), env_lua=None, type_key=TYPE_KEY):
    """Run a chunk (any profile) in a stub environment -> list of returned values as JSON data.

    records: names of global constructor functions to stub (see module docstring).
    env_lua: extra Lua source of a `function(env) ... end` run before the chunk."""
    std = core.to_std(data, prof)
    rt = runtime.runtime(prof.lua)
    setups = []
    if records:
        setups.append(rt.eval(_stub_lua(records, type_key)))
    if env_lua:
        setups.append(rt.eval(env_lua if isinstance(env_lua, bytes) else env_lua.encode()))
    lua51 = prof.lua in ("5.1", "luajit2.0", "luajit2.1")
    runner = rt.eval(("""function(s, setups)
  local env = setmetatable({}, {__index = _G})
  for i = 1, #setups do setups[i](env) end
  local f, e = %s
  if not f then error(e, 0) end
  %s
  local function pack(...) return {n = select('#', ...), ...} end
  return pack(f())
end""" % ("loadstring(s, 'chunk')" if lua51 else "load(s, 'chunk', 'b', env)",
          "setfenv(f, env)" if lua51 else "")).encode())
    t = runner(std, rt.table_from(setups))
    return [to_json(t[i]) for i in range(1, t[b"n"] + 1)]


def _is_table(v):
    return type(v).__name__ == "_LuaTable"


def _str(b):
    if isinstance(b, bytes):
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return {"__bytes__": b.hex()}
    return b


type_key_first = [TYPE_KEY]        # this key is listed first in exported objects


def to_json(v, _seen=None):
    """lupa value -> JSON-compatible Python value (see module docstring)."""
    if v is None or isinstance(v, (bool, int)):
        return v
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return {"__float__": repr(v)}
        return v
    if isinstance(v, bytes):
        return _str(v)
    if not _is_table(v):
        return {"__opaque__": type(v).__name__}
    _seen = _seen or set()
    key = id(v)
    if key in _seen:
        raise TableError("the returned data contains a reference cycle")
    _seen = _seen | {key}
    items = list(v.items())
    if not items:
        return {}
    keys = [k for k, _ in items]
    n = len(keys)
    if all(isinstance(k, int) and not isinstance(k, bool) for k in keys) and sorted(keys) == list(range(1, n + 1)):
        return [to_json(v[i], _seen) for i in range(1, n + 1)]
    simple = True
    for k in keys:
        if isinstance(k, bool) or not isinstance(k, (int, bytes)):
            simple = False
            break
        if isinstance(k, bytes):
            s = _str(k)
            if not isinstance(s, str) or _INTLIKE.match(s):
                simple = False
                break
    # stable order (Lua's own iteration order is not): integer keys ascending, then strings
    if simple:
        out = {}
        for k, x in sorted(items, key=lambda kv: (1, kv[0], b"") if isinstance(kv[0], bytes) else (0, b"", kv[0])):
            out[str(k) if isinstance(k, int) else k.decode("utf-8")] = to_json(x, _seen)
        if type_key_first[0] in out:
            out = dict([(type_key_first[0], out.pop(type_key_first[0]))] + list(out.items()))
        return out
    pairs = [[to_json(k, _seen), to_json(x, _seen)] for k, x in items]
    pairs.sort(key=lambda kv: json.dumps(kv[0], sort_keys=True))
    return {"__pairs__": pairs}


# ---------------------------------------------------------------- build
def _lua_str(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    out = bytearray(b'"')
    for b in s:
        if b in (0x22, 0x5C):
            out += b"\\" + bytes([b])
        elif b == 0x0A:
            out += b"\\n"
        elif b == 0x0D:
            out += b"\\r"
        elif b < 0x20 or b == 0x7F:
            out += b"\\%03d" % b
        else:
            out.append(b)
    out += b'"'
    return bytes(out)


def _lua_num(v):
    if isinstance(v, bool):
        return b"true" if v else b"false"
    if isinstance(v, int):
        if not -2 ** 63 <= v < 2 ** 63:
            raise TableError("integer %d does not fit in 64 bits" % v)
        if v == -2 ** 63:
            return b"math.mininteger"
        return str(v).encode()
    r = repr(float(v))
    if "e" not in r and "." not in r and "inf" not in r and "nan" not in r:
        r += ".0"
    return r.encode()


class _Gen:
    def __init__(self, constructor, type_key, type_name):
        self.ctor, self.type_key, self.type_name = constructor, type_key, type_name

    def value(self, v, path):
        if v is None:
            return b"nil"
        if isinstance(v, (bool, int, float)):
            return _lua_num(v)
        if isinstance(v, str):
            return _lua_str(v)
        if isinstance(v, list):
            return b"{" + b", ".join(self.value(x, "%s[%d]" % (path, i + 1)) for i, x in enumerate(v)) + b"}"
        if isinstance(v, dict):
            if set(v) == {"__bytes__"}:
                return _lua_str(bytes.fromhex(v["__bytes__"]))
            if set(v) == {"__float__"}:
                return {"inf": b"(1/0)", "-inf": b"(-1/0)", "nan": b"(0/0)"}[v["__float__"]]
            if set(v) == {"__pairs__"}:
                parts = [b"[" + self.value(k, path + ".key") + b"] = " + self.value(x, "%s[%r]" % (path, k))
                         for k, x in v["__pairs__"]]
                return b"{" + b", ".join(parts) + b"}"
            if "__opaque__" in v:
                raise TableError("%s: cannot rebuild an opaque %s value" % (path, v["__opaque__"]))
            if self.ctor and self.type_key in v:
                tname = self.type_name or v[self.type_key]
                fields = {k: x for k, x in v.items() if k != self.type_key}
                return (self.ctor.encode() + b"(" + self.value(tname, path) + b", " + self.fields(fields, path)
                        + b")")
            return self.fields(v, path)
        raise TableError("%s: unsupported JSON value %r" % (path, v))

    def fields(self, d, path):
        parts = []
        for k, x in d.items():
            if _INTLIKE.match(k):
                key = b"[" + k.encode() + b"]"
            elif _IDENT.match(k) and k not in _KEYWORDS:
                key = k.encode()
            else:
                key = b"[" + _lua_str(k) + b"]"
            parts.append(key + b" = " + self.value(x, "%s.%s" % (path, k)))
        return b"{" + b", ".join(parts) + b"}"


def build_source(values, constructor=None, type_key=TYPE_KEY, type_name=None, header=None):
    """JSON data (the list of values the chunk should return) -> Lua source bytes.

    Large arrays are emitted one element per line so compile errors point at a row."""
    if not isinstance(values, list):
        raise TableError("expected a JSON list of return values (as written by `run`)")
    g = _Gen(constructor, type_key, type_name)
    out = [b"-- " + (header or "generated by luarecomp build-table").encode()]
    if constructor:
        out.append(b"local " + constructor.encode() + b" = " + constructor.encode())
    names = []
    for i, v in enumerate(values):
        name = b"r%d" % (i + 1)
        _emit(out, g, name, v, "return[%d]" % (i + 1), constructor, type_key, 0)
        names.append(name)
    out.append(b"return " + b", ".join(names))
    return b"\n".join(out) + b"\n"


def _plain_dict(v, constructor, type_key):
    return isinstance(v, dict) and not (set(v) & {"__pairs__", "__bytes__", "__float__", "__opaque__"})         and not (constructor and type_key in v)


def _big(v, constructor, type_key):
    return (isinstance(v, list) or _plain_dict(v, constructor, type_key)) and len(v) > 8


def _emit(out, g, name, v, path, constructor, type_key, depth):
    """`local name = v`, one element per line for big containers; a small container of big
    ones (e.g. {rows, index}) gets its parts as separate locals first."""
    if depth < 2 and isinstance(v, list) and len(v) <= 8 and any(_big(x, constructor, type_key) for x in v):
        parts = []
        for j, x in enumerate(v):
            sub = name + b"_%d" % (j + 1)
            _emit(out, g, sub, x, "%s[%d]" % (path, j + 1), constructor, type_key, depth + 1)
            parts.append(sub)
        out.append(b"local " + name + b" = {" + b", ".join(parts) + b"}")
    elif isinstance(v, list) and len(v) > 8:
        out.append(b"local " + name + b" = {")
        for j, x in enumerate(v):
            out.append(b"  " + g.value(x, "%s[%d]" % (path, j + 1)) + b",")
        out.append(b"}")
    elif _plain_dict(v, constructor, type_key) and len(v) > 8:
        out.append(b"local " + name + b" = {")
        for k, x in v.items():
            out.append(b"  " + g.fields({k: x}, path)[1:-1] + b",")
        out.append(b"}")
    else:
        out.append(b"local " + name + b" = " + g.value(v, path))


def build(values, prof, chunkname=b"=table", **kw):
    """JSON data -> chunk bytes in the profile's format (compiled by the real compiler)."""
    src = build_source(values, **kw)
    return core.compile(src, prof, chunkname), src


# ---------------------------------------------------------------- compare
def diff(a, b, path="return", limit=20, out=None):
    """Structural differences between two JSON values -> list of 'path: ...' strings."""
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if type(a) is not type(b) and not ({type(a), type(b)} <= {dict, list} and not a and not b):
        out.append("%s: %s %s vs %s %s" % (path, type(a).__name__, _short(a), type(b).__name__, _short(b)))
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append("%s: length %d vs %d" % (path, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            diff(x, y, "%s[%d]" % (path, i + 1), limit, out)
    elif isinstance(a, dict):
        for k in a.keys() - b.keys():
            out.append("%s.%s: only in the first" % (path, k))
        for k in b.keys() - a.keys():
            out.append("%s.%s: only in the second" % (path, k))
        for k in a.keys() & b.keys():
            diff(a[k], b[k], "%s.%s" % (path, k), limit, out)
    elif a != b:
        out.append("%s: %s vs %s" % (path, _short(a), _short(b)))
    return out[:limit]


def _short(v):
    s = json.dumps(v, ensure_ascii=False)
    return s if len(s) < 60 else s[:57] + "..."
