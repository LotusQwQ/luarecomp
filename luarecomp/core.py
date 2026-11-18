# -*- coding: utf-8 -*-
"""Format-independent entry points: parse / dump / convert / compile."""
from . import luajit, puc, runtime
from .errors import FormatError
from .profile import Profile, standard  # noqa: F401  (re-exported)


def _codec(prof):
    return luajit if prof.family == "luajit" else puc


def parse(data, prof, trace=False):
    """bytes -> Chunk (instructions and constant tags in standard form)."""
    try:
        return _codec(prof).parse(data, prof, trace)
    except FormatError as exc:
        if exc.data is None:
            exc.data = data           # lets callers print a hex dump around the offset
        raise


def dump(chunk, prof, trace=False):
    """Chunk -> bytes in the profile's format."""
    return _codec(prof).dump(chunk, prof, trace)


def convert(data, src, dst):
    """Re-encode bytes from profile `src` to profile `dst` (same VM)."""
    return dump(parse(data, src), dst)


def to_std(data, prof):
    return convert(data, prof, standard(prof.lua))


def from_std(data, prof):
    return convert(data, standard(prof.lua), prof)


def compile(src, prof, chunkname=b"=?", strip=False):
    """Lua source -> bytecode in the profile's format, compiled by the real VM."""
    return from_std(runtime.compile_std(src, prof.lua, chunkname, strip), prof)


def compile_chunk(src, lua="5.3", chunkname=b"=?", strip=False):
    """Lua source -> Chunk (standard form), e.g. to inject into another chunk."""
    return parse(runtime.compile_std(src, lua, chunkname, strip), standard(lua))


def load_check(data, prof):
    """Convert to standard bytecode and load it in the real VM -> (ok, error)."""
    return runtime.load_check(to_std(data, prof), prof.lua)


__all__ = ["Profile", "standard", "parse", "dump", "convert", "to_std", "from_std", "compile",
           "compile_chunk", "load_check"]
