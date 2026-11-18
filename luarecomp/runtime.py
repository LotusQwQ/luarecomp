# -*- coding: utf-8 -*-
"""Real Lua VMs (through lupa) for every supported version: compile, load-check, run."""
import importlib

from .errors import RecompError

_MODULES = {"5.1": "lua51", "5.2": "lua52", "5.3": "lua53", "5.4": "lua54",
            "luajit2.0": "luajit20", "luajit2.1": "luajit21"}
_cache = {}


class CompileError(RecompError):
    pass


def runtime(lua):
    """A fresh lupa LuaRuntime for `lua` (bytes in, bytes out)."""
    name = _MODULES.get(lua)
    if name is None:
        raise RecompError("no runtime for %r" % lua)
    try:
        mod = importlib.import_module("lupa." + name)
    except ImportError as exc:
        raise RecompError("lupa.%s is not available (%s). Install lupa >= 2.0: pip install lupa; "
                          "LuaJIT runtimes are not built for every platform." % (name, exc))
    return mod.LuaRuntime(encoding=None)


def _fn(lua, key, code):
    k = (lua, key)
    if k not in _cache:
        _cache[k] = runtime(lua).eval(code)
    return _cache[k]


def _loader(lua):
    # 5.1 / LuaJIT: loadstring(s, name); 5.2+: load(s, name, mode)
    return "loadstring(s, name)" if lua in ("5.1", "luajit2.0", "luajit2.1") else "load(s, name, mode)"


def _s(v):
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else v


def compile_std(src, lua="5.3", chunkname=b"=?", strip=False):
    """Lua source -> standard bytecode of `lua`, produced by that VM's own compiler."""
    if isinstance(src, str):
        src = src.encode("utf-8")
    if isinstance(chunkname, str):
        chunkname = chunkname.encode("utf-8")
    code = ("function(s, name, strip) local mode = 't'; local f, e = %s; "
            "if not f then return nil, e end; return string.dump(f, strip), nil end" % _loader(lua))
    out, err = _fn(lua, "compile", code.encode())(src, chunkname, strip)
    if out is None:
        raise CompileError("Lua %s compile error: %s" % (lua, _s(err)))
    return out


def load_check(std_bytes, lua="5.3"):
    """Load standard bytecode in the real VM without running it -> (ok, error message)."""
    code = ("function(s) local name, mode = 'chk', 'b'; local f, e = %s; return f ~= nil, e end"
            % _loader(lua))
    ok, err = _fn(lua, "load", code.encode())(std_bytes)
    return bool(ok), _s(err)


def run(std_bytes, lua="5.3", env_setup=None):
    """Load and run standard bytecode; returns the list of results (lupa values).

    `env_setup` is Lua source of a function(env) that may fill the environment table
    before the chunk runs (globals of the host VM stay visible through __index)."""
    rt = runtime(lua)
    setenv = ("setfenv(f, env)" if lua in ("5.1", "luajit2.0", "luajit2.1") else "")
    loader = ("loadstring(s, 'run')" if setenv else "load(s, 'run', 'b', env)")
    code = ("function(s, setup) local env = setmetatable({}, {__index = _G}); "
            "if setup then setup(env) end; local f, e = %s; if not f then error(e, 0) end; %s; "
            "local function pack(...) return {n = select('#', ...), ...} end; return pack(f()) end"
            % (loader, setenv))
    setup = rt.eval(env_setup) if env_setup else None
    t = rt.eval(code.encode())(std_bytes, setup)
    return [t[i] for i in range(1, t[b"n"] + 1)]
