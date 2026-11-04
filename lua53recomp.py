# -*- coding: utf-8 -*-
"""lua53recomp -- compile Lua 5.3 source into *modified* Lua 5.3 bytecode formats, and back.

Many games ship Lua 5.3 bytecode with a tweaked container: a different signature,
different header fields, 4-byte size_t, shuffled opcodes, renumbered constant tags...
The instruction semantics are still stock Lua 5.3.  This tool describes such a format
with a small JSON "profile" and converts between it and standard Lua 5.3 bytecode:

    source.lua --(real Lua 5.3 via lupa)--> standard bytecode --(profile)--> custom bytecode
    custom bytecode --(profile)--> standard bytecode --> load / run in real Lua 5.3

Internally every function prototype is kept with *standard* opcode numbers; a profile
is only applied when reading or writing bytes.

CLI (run `python lua53recomp.py -h` for details):
    compile    src.lua -> custom chunk
    to-std     custom chunk -> standard Lua 5.3 chunk
    from-std   standard chunk -> custom chunk
    check      custom chunks: parse, byte-exact round trip, load in real Lua 5.3
    inspect    print the header of an unknown chunk and a draft profile
    match-ops  infer the opcode map from a custom chunk and the same code compiled stock
"""
import argparse
import json
import os
import struct
import sys

__version__ = "1.0.0"

NUM_OPCODES = 47  # Lua 5.3: OP_MOVE(0) .. OP_EXTRAARG(46)
OP_CALL = 36
OP_CLOSURE = 44
STD_LUAC_DATA = b"\x19\x93\r\n\x1a\n"
STD_TAGS = {"nil": 0, "boolean": 1, "float": 3, "integer": 0x13,
            "short_string": 4, "long_string": 0x14}
SIZE_NAMES = ("int", "size_t", "instruction", "integer", "number")
DEFAULT_SIZES = {"int": 4, "size_t": 8, "instruction": 4, "integer": 8, "number": 8}


class FormatError(Exception):
    pass


# ---------------------------------------------------------------- profile
class Profile:
    """Describes one bytecode container format.  See profiles/*.json and README."""

    def __init__(self, d):
        self.name = d.get("name", "unnamed")
        self.signature = bytes.fromhex(d.get("signature", "1b4c7561"))
        self.version = d.get("version", 0x53)
        self.format = d.get("format", 0)
        ld = d.get("luac_data", STD_LUAC_DATA.hex())
        self.luac_data = bytes.fromhex(ld) if ld else b""
        # header size bytes actually present, in order; missing ones take defaults
        self.size_fields = [tuple(x) for x in d.get("sizes", [[n, DEFAULT_SIZES[n]] for n in SIZE_NAMES])]
        sizes = dict(DEFAULT_SIZES)
        for n, v in self.size_fields:
            if n not in SIZE_NAMES:
                raise ValueError("unknown size field %r" % n)
            sizes[n] = v
        if sizes["int"] != 4 or sizes["instruction"] != 4:
            raise ValueError("only int=4 and instruction=4 are supported")
        e = "<" if d.get("endian", "little") == "little" else ">"
        self.e = e
        self.fmt_size_t = e + {4: "I", 8: "Q"}[sizes["size_t"]]
        self.fmt_integer = e + {4: "i", 8: "q"}[sizes["integer"]]
        self.fmt_number = e + {4: "f", 8: "d"}[sizes["number"]]
        self.luac_int = d.get("luac_int", 0x5678)
        self.luac_num = d.get("luac_num", 370.5)
        self.check_luac_values = d.get("check_luac_values", True)
        tags = dict(STD_TAGS)
        tags.update(d.get("const_tags", {}))
        self.tag_to_std = {v: STD_TAGS[k] for k, v in tags.items()}
        self.std_to_tag = {STD_TAGS[k]: v for k, v in tags.items()}
        if len(self.tag_to_std) != len(STD_TAGS):
            raise ValueError("const_tags values must be distinct")
        self.op_to_std, self.std_to_op = _build_opmap(d.get("opcodes", {"type": "identity"}))

    @classmethod
    def load(cls, path_or_name):
        path = path_or_name
        if not os.path.exists(path):
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles", path_or_name + ".json")
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))


def _build_opmap(spec):
    t = spec.get("type", "identity")
    if t == "identity":
        fwd = list(range(NUM_OPCODES))
    elif t == "affine":   # custom = (std * mul + add) % mod
        mul, add, mod = spec.get("mul", 1), spec.get("add", 0), spec.get("mod", NUM_OPCODES)
        fwd = [(s * mul + add) % mod for s in range(NUM_OPCODES)]
    elif t == "table":    # map[std] = custom
        fwd = list(spec["map"])
        if len(fwd) != NUM_OPCODES:
            raise ValueError("opcode table must have %d entries" % NUM_OPCODES)
    else:
        raise ValueError("unknown opcode map type %r" % t)
    if len(set(fwd)) != NUM_OPCODES or not all(0 <= v < 64 for v in fwd):
        raise ValueError("opcode map must be a one-to-one mapping into 0..63")
    return {c: s for s, c in enumerate(fwd)}, {s: c for s, c in enumerate(fwd)}


STANDARD = Profile({"name": "lua53"})


# ---------------------------------------------------------------- reader
class _Reader:
    def __init__(self, b, prof):
        self.b, self.i, self.p = b, 0, prof

    def need(self, n):
        if self.i + n > len(self.b):
            raise FormatError("unexpected end of data at offset %d" % self.i)

    def u8(self):
        self.need(1)
        v = self.b[self.i]; self.i += 1; return v

    def unpack(self, fmt):
        n = struct.calcsize(fmt)
        self.need(n)
        v = struct.unpack_from(fmt, self.b, self.i)[0]; self.i += n; return v

    def i32(self):
        return self.unpack(self.p.e + "i")

    def string(self):
        n = self.u8()
        if n == 0xFF:
            n = self.unpack(self.p.fmt_size_t)
        if n == 0:
            return None
        self.need(n - 1)
        s = bytes(self.b[self.i:self.i + n - 1]); self.i += n - 1
        return s

    def header(self):
        p = self.p
        sig = bytes(self.b[:len(p.signature)])
        if sig != p.signature:
            raise FormatError("signature %r does not match profile %r (%r)" % (sig, p.name, p.signature))
        self.i = len(p.signature)
        ver, fmt = self.u8(), self.u8()
        if (ver, fmt) != (p.version, p.format):
            raise FormatError("version/format %#x/%d, profile expects %#x/%d" % (ver, fmt, p.version, p.format))
        self.need(len(p.luac_data))
        if bytes(self.b[self.i:self.i + len(p.luac_data)]) != p.luac_data:
            raise FormatError("LUAC_DATA mismatch")
        self.i += len(p.luac_data)
        for name, want in p.size_fields:
            got = self.u8()
            if got != want:
                raise FormatError("header size %s=%d, profile says %d" % (name, got, want))
        li, ln = self.unpack(p.fmt_integer), self.unpack(p.fmt_number)
        if p.check_luac_values and (li != p.luac_int or abs(ln - p.luac_num) > 1e-6):
            raise FormatError("LUAC_INT/LUAC_NUM mismatch (%r, %r): wrong size/endian settings?" % (li, ln))
        return self.u8()  # number of upvalues of the main function

    def func(self):
        p = self.p
        f = {"source": self.string(), "line": self.i32(), "lastline": self.i32(),
             "nparams": self.u8(), "vararg": self.u8(), "maxstack": self.u8()}
        n = self.i32()
        self.need(4 * n)
        code = list(struct.unpack_from("%s%dI" % (p.e, n), self.b, self.i)); self.i += 4 * n
        f["code"] = [_remap(w, p.op_to_std, "custom") for w in code]
        ks = []
        for _ in range(self.i32()):
            raw = self.u8()
            t = p.tag_to_std.get(raw)
            if t == 0: ks.append((0, None))
            elif t == 1: ks.append((1, bool(self.u8())))
            elif t == 3: ks.append((3, self.unpack(p.fmt_number)))
            elif t == 0x13: ks.append((0x13, self.unpack(p.fmt_integer)))
            elif t in (4, 0x14): ks.append((t, self.string()))
            else: raise FormatError("unknown constant tag %#x at offset %d" % (raw, self.i - 1))
        f["K"] = ks
        f["upvals"] = [(self.u8(), self.u8()) for _ in range(self.i32())]
        f["protos"] = [self.func() for _ in range(self.i32())]
        n = self.i32()
        f["lines"] = [self.i32() for _ in range(n)]
        f["locvars"] = [(self.string(), self.i32(), self.i32()) for _ in range(self.i32())]
        f["upnames"] = [self.string() for _ in range(self.i32())]
        return f


def _remap(w, table, side):
    op = w & 0x3F
    if op not in table:
        raise FormatError("opcode %d is not in the %s opcode map" % (op, side))
    return (w & ~0x3F) | table[op]


def parse(data, prof=STANDARD):
    """bytes -> (nupvals, main function proto with standard opcodes)."""
    r = _Reader(data, prof)
    nup = r.header()
    root = r.func()
    if r.i != len(data):
        raise FormatError("%d trailing bytes" % (len(data) - r.i))
    return nup, root


# ---------------------------------------------------------------- writer
def _w_string(s, p):
    if s is None:
        return b"\x00"
    n = len(s) + 1
    return (bytes([n]) if n < 0xFF else b"\xff" + struct.pack(p.fmt_size_t, n)) + s


def _w_func(f, p):
    e = p.e
    out = bytearray(_w_string(f["source"], p))
    out += struct.pack(e + "ii", f["line"], f["lastline"])
    out += bytes([f["nparams"], f["vararg"], f["maxstack"]])
    code = [_remap(w, p.std_to_op, "standard") for w in f["code"]]
    out += struct.pack("%si%dI" % (e, len(code)), len(code), *code)
    out += struct.pack(e + "i", len(f["K"]))
    for t, v in f["K"]:
        out.append(p.std_to_tag[t])
        if t == 1: out.append(1 if v else 0)
        elif t == 3: out += struct.pack(p.fmt_number, v)
        elif t == 0x13: out += struct.pack(p.fmt_integer, v)
        elif t in (4, 0x14): out += _w_string(v, p)
    out += struct.pack(e + "i", len(f["upvals"]))
    for a, b in f["upvals"]:
        out += bytes([a, b])
    out += struct.pack(e + "i", len(f["protos"]))
    for c in f["protos"]:
        out += _w_func(c, p)
    out += struct.pack("%si%di" % (e, len(f["lines"])), len(f["lines"]), *f["lines"])
    out += struct.pack(e + "i", len(f["locvars"]))
    for name, s, en in f["locvars"]:
        out += _w_string(name, p) + struct.pack(e + "ii", s, en)
    out += struct.pack(e + "i", len(f["upnames"]))
    for nm in f["upnames"]:
        out += _w_string(nm, p)
    return bytes(out)


def header(prof, nupvals):
    out = bytearray(prof.signature)
    out += bytes([prof.version, prof.format]) + prof.luac_data
    out += bytes(v for _, v in prof.size_fields)
    out += struct.pack(prof.fmt_integer, prof.luac_int) + struct.pack(prof.fmt_number, prof.luac_num)
    out.append(nupvals)
    return bytes(out)


def dump(root, prof=STANDARD, nupvals=None):
    """main function proto -> bytes in the given format."""
    if nupvals is None:
        nupvals = len(root["upvals"])
    return header(prof, nupvals) + _w_func(root, prof)


def convert(data, src_prof, dst_prof):
    nup, root = parse(data, src_prof)
    return dump(root, dst_prof, nup)


# ---------------------------------------------------------------- real Lua 5.3 (lupa)
def _lua():
    try:
        import lupa.lua53 as L
    except ImportError:
        raise SystemExit("lupa is required: pip install lupa")
    return L.LuaRuntime(encoding=None)


def compile_std(src, chunkname=b"=?", strip=False):
    """Lua source -> standard Lua 5.3 bytecode (compiled by real Lua 5.3)."""
    if isinstance(src, str):
        src = src.encode("utf-8")
    if isinstance(chunkname, str):
        chunkname = chunkname.encode("utf-8")
    fn = _lua().eval(b"function(src, name, strip) local f, e = load(src, name, 't'); "
                     b"if not f then error(e, 0) end; return string.dump(f, strip) end")
    return fn(src, chunkname, strip)


def compile(src, prof, chunkname=b"=?", strip=False):
    """Lua source -> bytecode in the profile's format."""
    return convert(compile_std(src, chunkname, strip), STANDARD, prof)


def compile_proto(src, chunkname=b"=?", strip=False):
    """Lua source -> main function proto (standard opcodes), e.g. for inject_prologue()."""
    return parse(compile_std(src, chunkname, strip))[1]


def load_check(std_bytes):
    """Load standard bytecode in real Lua 5.3 (structure check, nothing is executed)."""
    f = _lua().eval(b"function(b) local f, e = load(b, 'chk', 'b'); return f ~= nil, e end")
    ok, err = f(std_bytes)
    return bool(ok), (err.decode("utf-8", "replace") if isinstance(err, bytes) else err)


# ---------------------------------------------------------------- injection
def inject_prologue(root, child):
    """Make `child` run at the very start of `root` (both protos use standard opcodes).

    `child` becomes the last sub-function of `root` (existing CLOSURE indexes stay valid)
    and `CLOSURE R0 k; CALL R0 1 1` is put in front of root's code.  The child gets
    root's upvalue 0 (normally _ENV) as its only upvalue, so it sees the same globals /
    environment as the original chunk.  Jumps are relative, so existing code is unaffected.
    Returns a new proto; `root` is not modified.
    """
    if root["nparams"] != 0:
        raise ValueError("main function must have no fixed parameters")
    if not root["upnames"] or root["upnames"][0] != b"_ENV":
        raise ValueError("upvalue 0 of the main function is not _ENV")
    child = dict(child, upvals=[(0, 0)], upnames=[b"_ENV"])
    q = dict(root)
    k = len(root["protos"])
    q["protos"] = list(root["protos"]) + [child]
    closure = OP_CLOSURE | (0 << 6) | (k << 14)                  # iABx
    call = OP_CALL | (0 << 6) | (1 << 23) | (1 << 14)            # iABC: A=0 B=1 C=1
    q["code"] = [closure, call] + list(root["code"])
    if root["lines"]:
        first = root["lines"][0]
        q["lines"] = [first, first] + list(root["lines"])
    q["locvars"] = [(n, s + 2, e + 2) for n, s, e in root["locvars"]]
    q["maxstack"] = max(root["maxstack"], 2)
    return q


# ---------------------------------------------------------------- analysis helpers
def inspect_header(data):
    """Best-effort header analysis of an unknown Lua 5.3-like chunk -> (report lines, draft profile)."""
    lines = []
    d = {"name": "draft"}
    # signature: bytes up to the version byte 0x53
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
        # some formats keep 6 bytes of other data, some drop it; try both
        lines.append("LUAC_DATA: not standard (%s)" % data[i:i + 6].hex())
        d["luac_data"] = data[i:i + 6].hex()
        i += 6
    # find LUAC_INT 0x5678 to learn how many size bytes there are
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
                    lines.append("NOTE: size field names are a guess -- check them against the README")
                    d["opcodes"] = {"type": "identity"}
                    lines.append("NOTE: opcodes cannot be derived from the header; use match-ops")
                    return lines, d
    lines.append("could not locate LUAC_INT/LUAC_NUM: header layout is non-standard, inspect by hand")
    return lines, d


def _guess_size_names(sizes, isz, nsz):
    if len(sizes) == 5:
        names = list(SIZE_NAMES)
    elif len(sizes) == 4:
        names = ["int", "size_t", "integer", "number"]   # most common variant: no instruction byte
    else:
        names = list(SIZE_NAMES[:len(sizes)])
    return [[n, v] for n, v in zip(names, sizes)]


def match_opcodes(custom_root, std_root):
    """Walk two protos of the same code (custom read with an identity opcode map, std
    compiled stock) and collect std->custom opcode pairs.  -> (mapping, conflicts)."""
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


OPNAMES = ("MOVE LOADK LOADKX LOADBOOL LOADNIL GETUPVAL GETTABUP GETTABLE SETTABUP SETUPVAL "
           "SETTABLE NEWTABLE SELF ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR UNM BNOT "
           "NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP "
           "TFORCALL TFORLOOP SETLIST CLOSURE VARARG EXTRAARG").split()


# ---------------------------------------------------------------- CLI
def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (path, len(data)))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="lua53recomp", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def with_profile(sp):
        sp.add_argument("-p", "--profile", required=True, help="profile JSON path or name in profiles/")
        return sp

    sp = with_profile(sub.add_parser("compile", help="Lua source -> custom bytecode"))
    sp.add_argument("src")
    sp.add_argument("-o", "--out", required=True)
    sp.add_argument("-n", "--chunkname", help="chunk name stored in the bytecode (default: @<src>)")
    sp.add_argument("-s", "--strip", action="store_true", help="drop debug info")

    sp = with_profile(sub.add_parser("to-std", help="custom bytecode -> standard Lua 5.3 bytecode"))
    sp.add_argument("src"); sp.add_argument("-o", "--out", required=True)

    sp = with_profile(sub.add_parser("from-std", help="standard Lua 5.3 bytecode -> custom bytecode"))
    sp.add_argument("src"); sp.add_argument("-o", "--out", required=True)

    sp = with_profile(sub.add_parser("check", help="verify a profile against real chunks"))
    sp.add_argument("chunks", nargs="+")

    sp = sub.add_parser("inspect", help="analyse the header of an unknown chunk")
    sp.add_argument("chunk")

    sp = with_profile(sub.add_parser("match-ops", help="infer the opcode map"))
    sp.add_argument("custom_chunk", help="chunk in the custom format")
    sp.add_argument("source", help="the same code as Lua source, or as standard bytecode (*.luac)")
    sp.add_argument("-n", "--chunkname", default="=?", help="chunk name used when compiling source")

    a = ap.parse_args(argv)

    if a.cmd == "inspect":
        lines, d = inspect_header(_read(a.chunk))
        print("\n".join(lines))
        print("\ndraft profile:\n" + json.dumps(d, indent=2))
        return 0

    prof = Profile.load(a.profile)
    if a.cmd == "compile":
        name = a.chunkname or "@" + os.path.basename(a.src)
        _write(a.out, compile(_read(a.src), prof, name, a.strip))
    elif a.cmd == "to-std":
        _write(a.out, convert(_read(a.src), prof, STANDARD))
    elif a.cmd == "from-std":
        _write(a.out, convert(_read(a.src), STANDARD, prof))
    elif a.cmd == "check":
        bad = 0
        for path in a.chunks:
            data = _read(path)
            try:
                std = convert(data, prof, STANDARD)
                same = convert(std, STANDARD, prof) == data
                ok, err = load_check(std)
            except (FormatError, ValueError) as exc:
                same, ok, err = False, False, str(exc)
            bad += not (same and ok)
            print("%-40s round-trip=%s  lua53-load=%s %s" % (os.path.basename(path), same, ok, err or ""))
        print("%d/%d OK" % (len(a.chunks) - bad, len(a.chunks)))
        return 1 if bad else 0
    elif a.cmd == "match-ops":
        prof.op_to_std = prof.std_to_op = {i: i for i in range(64)}   # read raw opcodes
        _, croot = parse(_read(a.custom_chunk), prof)
        other = _read(a.source)
        std = other if other[:4] == b"\x1bLua" else compile_std(other, a.chunkname)
        _, sroot = parse(std)
        seen, conflicts = match_opcodes(croot, sroot)
        for s in sorted(seen):
            print("  %-9s std %2d -> custom %2d" % (OPNAMES[s], s, seen[s]))
        missing = [OPNAMES[s] for s in range(NUM_OPCODES) if s not in seen]
        print("%d/%d opcodes observed; missing: %s" % (len(seen), NUM_OPCODES, " ".join(missing) or "none"))
        for c in conflicts[:20]:
            print("  !", c)
        if seen:
            diffs = {(c - s) % NUM_OPCODES for s, c in seen.items()}
            if len(diffs) == 1:
                print('looks affine: "opcodes": {"type": "affine", "add": %d, "mod": %d}' % (diffs.pop(), NUM_OPCODES))
        return 1 if conflicts else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
