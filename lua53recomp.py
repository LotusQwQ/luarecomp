# -*- coding: utf-8 -*-
"""Compatibility module: the v1 single-file API of lua53recomp, now backed by the
`luarecomp` package (which adds Lua 5.1/5.2/5.4, LuaJIT, deep format changes, opcode
inference, diagnostics...).  New code should `import luarecomp`.

Everything v1 offered keeps working with the same signatures:
    Profile, STANDARD, FormatError, parse, dump, header, convert, compile_std, compile,
    compile_proto, load_check, inject_prologue, inspect_header, match_opcodes, OPNAMES,
    NUM_OPCODES, OP_CALL, OP_CLOSURE, main
The command line `python lua53recomp.py ...` forwards to `python -m luarecomp ...`.
"""
import struct
import sys

import luarecomp as _L
from luarecomp import core as _core, inject as _inject, isa as _isa, puc as _puc, runtime as _rt
from luarecomp.errors import FormatError  # noqa: F401
from luarecomp.profile import Profile as _Profile, STD_LUAC_DATA

__version__ = _L.__version__

NUM_OPCODES = _isa.LUA53.num
OP_CALL = _isa.LUA53.index["CALL"]
OP_CLOSURE = _isa.LUA53.index["CLOSURE"]
OPNAMES = tuple(_isa.LUA53.names)
SIZE_NAMES = ("int", "size_t", "instruction", "integer", "number")
STD_TAGS = {"nil": 0, "boolean": 1, "float": 3, "integer": 0x13, "short_string": 4, "long_string": 0x14}


class Profile(_Profile):
    """v1 profile: Lua 5.3 unless the JSON says otherwise."""


STANDARD = Profile({"name": "lua53"})


def parse(data, prof=STANDARD):
    """bytes -> (nupvals, main function proto with standard opcodes)."""
    ch = _puc.parse(data, prof)
    return ch.nupvals, ch.root


def dump(root, prof=STANDARD, nupvals=None):
    if nupvals is None:
        nupvals = len(root["upvals"])
    return _puc.dump(_puc.Chunk(prof.lua, root, nupvals), prof)


def header(prof, nupvals):
    w = _puc.Writer(prof)
    w.header(nupvals, [])
    return bytes(w.out)


def convert(data, src_prof, dst_prof):
    return _core.convert(data, src_prof, dst_prof)


def _lua():
    return _rt.runtime("5.3")


def compile_std(src, chunkname=b"=?", strip=False):
    return _rt.compile_std(src, "5.3", chunkname, strip)


def compile(src, prof, chunkname=b"=?", strip=False):
    return convert(compile_std(src, chunkname, strip), STANDARD, prof)


def compile_proto(src, chunkname=b"=?", strip=False):
    return parse(compile_std(src, chunkname, strip))[1]


def load_check(std_bytes):
    return _rt.load_check(std_bytes, "5.3")


def inject_prologue(root, child):
    """v1 API on raw protos.  Same result as before, now with the checks of luarecomp.inject."""
    ch = _puc.Chunk("5.3", root, len(root["upvals"]))
    kid = _puc.Chunk("5.3", child, len(child.get("upvals") or []) or 1)
    if not child.get("upvals"):
        kid.root = dict(child, upvals=[(1, 0)], upnames=[b"_ENV"])
    try:
        out = _inject.inject(ch, kid, check=False)
    except _inject.InjectError as exc:
        raise ValueError(str(exc))
    return out.root


# ---------------------------------------------------------------- v1 analysis helpers (unchanged)
def inspect_header(data):
    """Best-effort header analysis (v1).  `luarecomp.detect.inspect` is the thorough version."""
    lines = []
    d = {"name": "draft"}
    v = data.find(b"\x53", 0, 16)
    if v <= 0:
        raise FormatError("no 0x53 version byte in the first 16 bytes: probably not Lua 5.3 (or encrypted)")
    d["signature"] = data[:v].hex()
    d["version"] = 0x53
    d["format"] = data[v + 1]
    i = v + 2
    lines.append("signature %r, version 0x53, format %d" % (data[:v], d["format"]))
    if data[i:i + 6] == STD_LUAC_DATA:
        lines.append("LUAC_DATA: standard")
        i += 6
    else:
        lines.append("LUAC_DATA: not standard (%s)" % data[i:i + 6].hex())
        d["luac_data"] = data[i:i + 6].hex()
        i += 6
    for endian, ec in (("little", "<"), ("big", ">")):
        for isz, ifmt in ((8, "q"), (4, "i")):
            pat = struct.pack(ec + ifmt, 0x5678)
            j = data.find(pat, i, i + 8 + isz)
            if j < 0:
                continue
            nsizes = j - i
            sizes = list(data[i:j])
            for nsz, nfmt in ((8, "d"), (4, "f")):
                try:
                    num = struct.unpack_from(ec + nfmt, data, j + isz)[0]
                except struct.error:
                    continue
                if abs(num - 370.5) < 1e-6:
                    lines.append("size bytes (%d): %s" % (nsizes, sizes))
                    lines.append("LUAC_INT 0x5678 as %d-byte %s, LUAC_NUM 370.5 as %d-byte" % (isz, endian, nsz))
                    lines.append("header length %d, main upvalues %d" % (j + isz + nsz + 1, data[j + isz + nsz]))
                    d["endian"] = endian
                    d["sizes"] = _guess_size_names(sizes, isz, nsz)
                    lines.append("NOTE: size field names are a guess -- `python -m luarecomp inspect` checks them")
                    d["opcodes"] = {"type": "identity"}
                    lines.append("NOTE: opcodes cannot be derived from the header; use match-ops / infer-ops")
                    return lines, d
    lines.append("could not locate LUAC_INT/LUAC_NUM: header layout is non-standard, inspect by hand")
    return lines, d


def _guess_size_names(sizes, isz, nsz):
    if len(sizes) == 5:
        names = list(SIZE_NAMES)
    elif len(sizes) == 4:
        names = ["int", "size_t", "integer", "number"]
    else:
        names = list(SIZE_NAMES[:len(sizes)])
    return [[n, v] for n, v in zip(names, sizes)]


def match_opcodes(custom_root, std_root):
    """v1: strict position-by-position matching.  `luarecomp.opinfer.match_ops` aligns
    instruction streams and tolerates differences."""
    seen, conflicts = {}, []

    def walk(a, b, path):
        if len(a["code"]) != len(b["code"]) or len(a["protos"]) != len(b["protos"]):
            conflicts.append("%s: shape differs (code %d vs %d) -- not the same source/compiler?"
                             % (path, len(a["code"]), len(b["code"])))
            return
        for pc, (wc, ws) in enumerate(zip(a["code"], b["code"])):
            if wc & ~0x3F != ws & ~0x3F:
                conflicts.append("%s pc %d: operands differ" % (path, pc))
                continue
            s, c = ws & 0x3F, wc & 0x3F
            if seen.setdefault(s, c) != c:
                conflicts.append("%s pc %d: std op %d seen as both %d and %d" % (path, pc, s, seen[s], c))
        for n, (x, y) in enumerate(zip(a["protos"], b["protos"])):
            walk(x, y, "%s/%d" % (path, n))

    walk(custom_root, std_root, "main")
    return seen, conflicts


def main(argv=None):
    from luarecomp.cli import main as _main
    argv = list(sys.argv[1:] if argv is None else argv)
    # v1 syntax: match-ops -p P CUSTOM SOURCE [-n NAME]  ->  match-ops -p P --pair CUSTOM SOURCE
    if argv and argv[0] == "match-ops" and "--pair" not in argv:
        rest, pos, i = [], [], 1
        while i < len(argv):
            if argv[i] in ("-p", "--profile", "-n", "--chunkname", "-o", "--out"):
                rest += argv[i:i + 2]
                i += 2
            else:
                pos.append(argv[i])
                i += 1
        argv = ["match-ops"] + rest + (["--pair"] + pos[:2] if len(pos) >= 2 else pos)
    return _main(argv)


if __name__ == "__main__":
    sys.exit(main())
