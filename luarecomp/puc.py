# -*- coding: utf-8 -*-
"""Reader / writer for PUC Lua 5.1-5.4 bytecode, driven by a Profile.

Internally a prototype is a dict with *standard* instructions (standard opcode numbers
and bit layout of that Lua version) and standard constant tags:

    source line lastline nparams vararg maxstack code K upvals protos lines locvars upnames
    nupvals (5.1 only)   abslines (5.4 only)   keep (values of {"keep": ...} sections)

The profile is applied only when bytes are read or written.
"""
import collections
import struct

from . import isa as ISA
from .errors import FormatError

KINDS = {
    "5.1": {0: "nil", 1: "bool", 3: "num", 4: "str"},
    "5.2": {0: "nil", 1: "bool", 3: "num", 4: "str"},
    "5.3": {0: "nil", 1: "bool", 3: "num", 0x13: "int", 4: "str", 0x14: "str"},
    "5.4": {0: "nil", 1: "none", 0x11: "none", 3: "int", 0x13: "num", 4: "str", 0x14: "str"},
}
_INT_FMT = {"i8": "b", "u8": "B", "i16": "h", "u16": "H", "i32": "i", "u32": "I"}


class Chunk:
    """A parsed chunk.  PUC: `root` proto + `nupvals`; LuaJIT: see luajit.py."""

    def __init__(self, lua, root=None, nupvals=None, keep=None, **extra):
        self.lua, self.root, self.nupvals = lua, root, nupvals
        self.keep = list(keep or [])
        self.__dict__.update(extra)

    @property
    def isa(self):
        return ISA.ISAS[self.lua]

    def walk(self):
        """Yield (path, proto) for every function, parents first."""
        if self.lua.startswith("luajit"):
            from .luajit import walk
            yield from walk(self)
            return
        stack = [("main", self.root)]
        while stack:
            path, f = stack.pop()
            yield path, f
            for i in range(len(f["protos"]) - 1, -1, -1):
                stack.append(("%s/%d" % (path, i), f["protos"][i]))

    def proto(self, path):
        for p, f in self.walk():
            if p == path:
                return f
        raise KeyError(path)


# ---------------------------------------------------------------- instruction mapping
class InsnCodec:
    """Converts instruction words between a profile's encoding and the standard one."""

    def __init__(self, prof):
        self.p = prof
        self.isa = prof.isa
        self.dec_hook = prof.hook("decode_instruction")
        self.enc_hook = prof.hook("encode_instruction")
        self.fast = (prof.opcodes_identity and not prof.custom_layout and not (self.dec_hook or self.enc_hook)) \
            or getattr(prof, "raw_opcodes", False)
        self.lua51 = self.isa.key == "5.1" and not getattr(prof, "raw_opcodes", False)
        self.setlist = self.isa.index.get("SETLIST")

    def _raw_follows(self, std_word):
        # Lua 5.1: SETLIST with C == 0 is followed by a raw integer (not an instruction)
        L = self.isa.layout
        return (self.lua51 and ISA.get_field(std_word, L, "op") == self.setlist
                and ISA.get_field(std_word, L, "C") == 0)

    def to_std(self, words, path="?"):
        if self.fast and not self.lua51:
            return list(words)
        p, isa = self.p, self.isa
        out, raw = [], False
        for pc, w in enumerate(words):
            if raw:
                out.append(w)
                raw = False
                continue
            if self.dec_hook:
                s = self.dec_hook(w, {"pc": pc, "path": path, "profile": p, "isa": isa})
            elif self.fast:
                s = w
            else:
                c = ISA.get_field(w, p.layout, "op")
                op = p.op_to_std.get(c)
                if op is None:
                    raise FormatError("custom opcode %d is not in the profile's opcode map" % c,
                                      path=path, field="code[%d]" % pc,
                                      hint="the opcode map is incomplete or wrong; use infer-ops / match-ops")
                if p.custom_layout:
                    s = ISA.encode(isa, ISA.decode(isa, w, p.layout, p.biases, op=op))
                else:
                    s = ISA.set_field(w, p.layout, "op", op)
            out.append(s)
            raw = self._raw_follows(s)
        return out

    def from_std(self, words, path="?"):
        if self.fast and not self.lua51:
            return list(words)
        p, isa = self.p, self.isa
        out, raw = [], False
        for pc, s in enumerate(words):
            if raw:
                out.append(s)
                raw = False
                continue
            raw = self._raw_follows(s)
            if self.enc_hook:
                out.append(self.enc_hook(s, {"pc": pc, "path": path, "profile": p, "isa": isa}))
                continue
            if self.fast:
                out.append(s)
                continue
            op = ISA.get_field(s, isa.layout, "op")
            c = p.std_to_op.get(op)
            if c is None:
                raise FormatError("standard opcode %d (%s) has no custom number" % (op, isa.opname(op)),
                                  path=path, field="code[%d]" % pc)
            if p.custom_layout:
                out.append(ISA.encode(isa, ISA.decode(isa, s), p.layout, p.biases, op_value=c))
            else:
                out.append(ISA.set_field(s, isa.layout, "op", c))
        return out


def _xor(b, key):
    return bytes(x ^ key[i % len(key)] for i, x in enumerate(b))


class _Strings:
    def __init__(self, prof):
        self.p = prof
        self.dec = prof.hook("decode_string")
        self.enc = prof.hook("encode_string")

    def decode(self, s, scope):
        if s is None:
            return s
        if self.p.string_xor and scope in self.p.string_scope:
            s = _xor(s, self.p.string_xor)
        if self.dec:
            s = self.dec(s, scope)
        return s

    def encode(self, s, scope):
        if s is None:
            return s
        if self.enc:
            s = self.enc(s, scope)
        if self.p.string_xor and scope in self.p.string_scope:
            s = _xor(s, self.p.string_xor)
        return s


# ---------------------------------------------------------------- reader
class Reader:
    def __init__(self, data, prof, trace=False):
        self.b, self.i, self.p = data, 0, prof
        self.v = prof.lua
        self.kinds = KINDS[self.v]
        self.insn = InsnCodec(prof)
        self.strs = _Strings(prof)
        self.path = "header"
        self.trail = collections.deque(maxlen=12)
        self.spans = [] if trace else None

    # -------------------------------------------------- errors
    def fail(self, msg, field=None, hint=None, offset=None):
        raise FormatError(msg, offset=self.i if offset is None else offset, path=self.path, field=field,
                          hint=hint, trail=self.trail)

    def note(self, start, field, val):
        self.trail.append((start, self.path, field, val))
        if self.spans is not None:
            self.spans.append((start, self.i, self.path, field))

    def need(self, n, field):
        if n < 0 or self.i + n > len(self.b):
            self.fail("need %d bytes but only %d remain" % (n, len(self.b) - self.i), field,
                      hint="truncated data, or an earlier length/count was read with the wrong size "
                           "(check size_t / integer sizes and the encoding settings)")

    # -------------------------------------------------- primitives
    def u8(self, field):
        self.need(1, field)
        v = self.b[self.i]
        self.i += 1
        return v

    def unpack(self, fmt, field):
        n = struct.calcsize(fmt)
        self.need(n, field)
        v = struct.unpack_from(fmt, self.b, self.i)[0]
        self.i += n
        return v

    def int(self, enc, field):
        if enc in _INT_FMT:
            return self.unpack(self.p.e + _INT_FMT[enc], field)
        start, x = self.i, 0
        if enc == "varint":                 # Lua 5.4: MSB first, last byte has bit 7 set
            while True:
                b = self.u8(field)
                x = (x << 7) | (b & 0x7F)
                if b & 0x80:
                    return x
                if self.i - start > 10:
                    self.fail("varint longer than 10 bytes", field, offset=start)
        shift = 0                           # uleb128: LSB first, bit 7 = more bytes
        while True:
            b = self.u8(field)
            x |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return x
            if shift > 70:
                self.fail("uleb128 longer than 10 bytes", field, offset=start)

    def count(self, field, limit_unit=1):
        start = self.i
        n = self.int(self.p.enc["count"], field)
        if n < 0 or n * limit_unit > len(self.b) - self.i:
            self.fail("count %d is impossible here (%d bytes left)" % (n, len(self.b) - self.i), field,
                      offset=start, hint="the bytes before this point were probably misread; "
                      "compare the field trail with the expected layout")
        return n

    def string(self, field, scope):
        start = self.i
        enc = self.p.enc["string"]
        if enc == "lua51":
            n = self.unpack(self.p.fmt_size_t, field)
            if n == 0:
                return None
            self.need(n, field)
            s = bytes(self.b[self.i:self.i + n])
            self.i += n
            if s[-1:] != b"\x00":
                self.fail("string is not NUL-terminated (Lua 5.1/5.2 strings end in \\0)", field, offset=start)
            s = s[:-1]
        else:
            if enc == "lua53":
                n = self.u8(field)
                if n == 0xFF:
                    n = self.unpack(self.p.fmt_size_t, field)
            elif enc == "lua54":
                n = self.int("varint", field)
            else:
                n = self.int(self.p.enc["count"], field)
            if n == 0:
                return None
            self.need(n - 1, field)
            s = bytes(self.b[self.i:self.i + n - 1])
            self.i += n - 1
        s = self.strs.decode(s, scope)
        self.note(start, field, s)
        return s

    # -------------------------------------------------- header
    def header(self):
        p = self.p
        meta = {"nupvals": None, "keep": []}
        for item in p.header_items:
            start = self.i
            kind = item[0]
            if kind == "field":
                name = item[1]
                if name == "signature":
                    got = bytes(self.b[self.i:self.i + len(p.signature)])
                    if got != p.signature:
                        self.fail("signature %s does not match profile %r (expects %s)"
                                  % (got.hex(), p.name, p.signature.hex()), "signature",
                                  hint="wrong profile, encrypted/compressed file, or a LuaJIT chunk "
                                       "(starts with 1b4c4a); try `inspect`")
                    self.i += len(p.signature)
                elif name in ("version", "format", "endian", "integral"):
                    want = {"version": p.version, "format": p.format, "integral": p.integral,
                            "endian": 1 if p.e == "<" else 0}[name]
                    got = self.u8(name)
                    if got != want:
                        hint = None
                        if name == "version":
                            hint = ("this looks like Lua %x.%x bytecode; set \"lua\" accordingly"
                                    % (got >> 4, got & 15) if 0x51 <= got <= 0x54 else None)
                        self.fail("%s byte is %d (0x%02x), profile expects %d" % (name, got, got, want),
                                  name, hint=hint, offset=start)
                elif name == "luac_data":
                    self.need(len(p.luac_data), name)
                    got = bytes(self.b[self.i:self.i + len(p.luac_data)])
                    if got != p.luac_data:
                        self.fail("LUAC_DATA is %s, profile expects %s" % (got.hex(), p.luac_data.hex()), name,
                                  hint='if the format has no LUAC_DATA, set "luac_data": ""')
                    self.i += len(p.luac_data)
                elif name == "luac_int":
                    v = self.unpack(p.fmt_integer, name)
                    if p.check_luac_values and v != p.luac_int:
                        self.fail("LUAC_INT is %#x, expected %#x" % (v, p.luac_int), name, offset=start,
                                  hint="integer size or endianness is wrong (or the size bytes are "
                                       "named/ordered differently); try `inspect`")
                elif name == "luac_num":
                    v = self.unpack(p.fmt_number, name)
                    if p.check_luac_values and abs(v - p.luac_num) > 1e-6:
                        self.fail("LUAC_NUM is %r, expected %r" % (v, p.luac_num), name, offset=start,
                                  hint="number size or endianness is wrong; try `inspect`")
                elif name == "nupvals":
                    meta["nupvals"] = self.u8(name)
                self.note(start, name, bytes(self.b[start:self.i]).hex())
            elif kind == "size":
                got = self.u8("size:" + item[1])
                want = p.sizes[item[1]]
                if got != want:
                    self.fail("size byte for %s is %d, profile says %d" % (item[1], got, want), "size:" + item[1],
                              offset=start, hint="the size bytes may be named or ordered differently than "
                                                 "the profile assumes; `inspect` tries every arrangement")
                self.note(start, "size:" + item[1], got)
            elif kind == "const":
                got = bytes(self.b[self.i:self.i + len(item[1])])
                if got != item[1]:
                    self.fail("constant header bytes are %s, profile expects %s" % (got.hex(), item[1].hex()),
                              "const")
                self.i += len(item[1])
            elif kind == "keep":
                self.need(item[1], "keep")
                meta["keep"].append(bytes(self.b[self.i:self.i + item[1]]))
                self.i += item[1]
                self.note(start, "keep", meta["keep"][-1].hex())
        return meta

    # -------------------------------------------------- function
    def func(self, path):
        saved, self.path = self.path, path
        p = self.p
        f = {}
        keep = {}
        for idx, sec in enumerate(p.func_sections):
            kind, name = sec[0], sec[1]
            start = self.i
            if kind == "keep":
                keep[idx] = self._keep(name)
                continue
            if kind == "const":
                got = bytes(self.b[self.i:self.i + len(name)])
                if got != name:
                    self.fail("constant bytes %s, profile expects %s" % (got.hex(), name.hex()), "const")
                self.i += len(name)
                continue
            if name == "source":
                f["source"] = self.string("source", "source")
            elif name in ("line", "lastline"):
                f[name] = self.int(p.enc["line"], name)
                self.note(start, name, f[name])
            elif name in ("nupvals", "nparams", "vararg", "maxstack"):
                f[name] = self.u8(name)
                self.note(start, name, f[name])
            elif name == "code":
                n = self.count("code.count", 4)
                self.need(4 * n, "code")
                words = list(struct.unpack_from("%s%dI" % (p.e, n), self.b, self.i))
                self.i += 4 * n
                self.note(start, "code", "%d instructions" % n)
                f["code"] = self.insn.to_std(words, path)
            elif name == "constants":
                f["K"] = self._constants()
            elif name == "upvals":
                width = 3 if self.v == "5.4" else 2
                n = self.count("upvals.count", width)
                f["upvals"] = [tuple(self.u8("upvals[%d]" % k) for _ in range(width)) for k in range(n)]
                self.note(start, "upvals", f["upvals"])
            elif name == "protos":
                n = self.count("protos.count")
                self.note(start, "protos.count", n)
                f["protos"] = [self.func("%s/%d" % (path, k)) for k in range(n)]
                self.path = path
            elif name == "lines":
                enc = p.enc["lineinfo"]
                n = self.count("lines.count")
                if enc in _INT_FMT:
                    fmt = _INT_FMT[enc]
                    sz = struct.calcsize(fmt)
                    self.need(sz * n, "lines")
                    f["lines"] = list(struct.unpack_from("%s%d%s" % (p.e, n, fmt), self.b, self.i))
                    self.i += sz * n
                else:
                    f["lines"] = [self.int(enc, "lines[%d]" % k) for k in range(n)]
                self.note(start, "lines", "%d entries" % n)
            elif name == "abslines":
                n = self.count("abslines.count")
                f["abslines"] = [(self.int(p.enc["pc"], "abslines.pc"), self.int(p.enc["pc"], "abslines.line"))
                                 for _ in range(n)]
                self.note(start, "abslines", "%d entries" % n)
            elif name == "locvars":
                n = self.count("locvars.count")
                f["locvars"] = [(self.string("locvars[%d].name" % k, "names"),
                                 self.int(p.enc["pc"], "locvars[%d].startpc" % k),
                                 self.int(p.enc["pc"], "locvars[%d].endpc" % k)) for k in range(n)]
            elif name == "upnames":
                n = self.count("upnames.count")
                f["upnames"] = [self.string("upnames[%d]" % k, "names") for k in range(n)]
        if keep:
            f["keep"] = keep
        if self.v == "5.1":
            f.setdefault("upvals", [])
        else:
            f.setdefault("nupvals", None)
        f.setdefault("abslines", [])
        self.path = saved
        return f

    def _keep(self, t):
        start = self.i
        hook = self.p.hook("read_keep")
        if hook:
            v = hook(self, t)
        elif t == "string":
            v = self.string("keep", "keep")
        elif t == "count":
            v = self.int(self.p.enc["count"], "keep")
        else:
            v = self.int(t, "keep")
        self.note(start, "keep:" + t, v)
        return v

    def _constants(self):
        p = self.p
        n = self.count("constants.count")
        ks = []
        for k in range(n):
            start = self.i
            field = "K[%d]" % k
            raw = self.u8(field + ".tag")
            t = p.tag_to_std.get(raw)
            kind = self.kinds.get(t)
            if kind is None:
                self.fail("unknown constant tag %d (0x%02x)" % (raw, raw), field + ".tag", offset=start,
                          hint="valid tags for this profile: %s; if the game renumbered them, set const_tags"
                               % sorted(p.tag_to_std))
            if kind == "nil":
                v = None
            elif kind == "bool":
                v = bool(self.u8(field))
            elif kind == "none":
                v = t == 0x11
            elif kind == "num":
                v = self.unpack(p.fmt_number, field)
            elif kind == "int":
                v = self.unpack(p.fmt_integer, field)
            else:
                v = self.string(field, "constants")
            ks.append((t, v))
            if self.spans is not None:
                self.spans.append((start, self.i, self.path, field))
        self.note(self.i, "constants", "%d entries" % n)
        return ks


# ---------------------------------------------------------------- writer
class Writer:
    def __init__(self, prof, trace=False):
        self.p = prof
        self.v = prof.lua
        self.kinds = KINDS[self.v]
        self.out = bytearray()
        self.insn = InsnCodec(prof)
        self.strs = _Strings(prof)
        self.spans = [] if trace else None
        self.path = "header"

    def mark(self, start, field):
        if self.spans is not None:
            self.spans.append((start, len(self.out), self.path, field))

    def int(self, enc, v, field="?"):
        if enc in _INT_FMT:
            try:
                self.out += struct.pack(self.p.e + _INT_FMT[enc], v)
            except struct.error:
                raise FormatError("value %r does not fit encoding %s" % (v, enc), path=self.path, field=field)
            return
        if v < 0:
            raise FormatError("negative value %d cannot be written as %s" % (v, enc), path=self.path, field=field)
        if enc == "varint":
            groups = [v & 0x7F]
            v >>= 7
            while v:
                groups.append(v & 0x7F)
                v >>= 7
            groups[0] |= 0x80
            self.out += bytes(reversed(groups))
            return
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                self.out.append(b | 0x80)
            else:
                self.out.append(b)
                return

    def string(self, s, scope, field="?"):
        start = len(self.out)
        s = self.strs.encode(s, scope)
        enc = self.p.enc["string"]
        if s is None:
            if enc == "lua51":
                self.out += struct.pack(self.p.fmt_size_t, 0)
            elif enc == "lua53":
                self.out.append(0)
            elif enc == "lua54":
                self.int("varint", 0)
            else:
                self.int(self.p.enc["count"], 0)
        elif enc == "lua51":
            self.out += struct.pack(self.p.fmt_size_t, len(s) + 1) + s + b"\x00"
        else:
            n = len(s) + 1
            if enc == "lua53":
                if n < 0xFF:
                    self.out.append(n)
                else:
                    self.out.append(0xFF)
                    self.out += struct.pack(self.p.fmt_size_t, n)
            elif enc == "lua54":
                self.int("varint", n)
            else:
                self.int(self.p.enc["count"], n)
            self.out += s
        self.mark(start, field)

    def header(self, nupvals, keep):
        p = self.p
        keep = list(keep or [])
        ki = 0
        for item in p.header_items:
            start = len(self.out)
            kind = item[0]
            if kind == "field":
                name = item[1]
                if name == "signature":
                    self.out += p.signature
                elif name == "version":
                    self.out.append(p.version)
                elif name == "format":
                    self.out.append(p.format)
                elif name == "endian":
                    self.out.append(1 if p.e == "<" else 0)
                elif name == "integral":
                    self.out.append(p.integral)
                elif name == "luac_data":
                    self.out += p.luac_data
                elif name == "luac_int":
                    self.out += struct.pack(p.fmt_integer, p.luac_int)
                elif name == "luac_num":
                    self.out += struct.pack(p.fmt_number, p.luac_num)
                elif name == "nupvals":
                    self.out.append(nupvals)
                self.mark(start, name)
            elif kind == "size":
                self.out.append(p.sizes[item[1]])
                self.mark(start, "size:" + item[1])
            elif kind == "const":
                self.out += item[1]
                self.mark(start, "const")
            elif kind == "keep":
                v = keep[ki] if ki < len(keep) and len(keep[ki]) == item[1] else item[2]
                ki += 1
                self.out += v
                self.mark(start, "keep")

    def func(self, f, path):
        saved, self.path = self.path, path
        p = self.p
        e = p.e
        for idx, sec in enumerate(p.func_sections):
            kind, name = sec[0], sec[1]
            start = len(self.out)
            if kind == "keep":
                self._keep(name, f.get("keep", {}).get(idx, sec[2]))
                continue
            if kind == "const":
                self.out += name
                self.mark(start, "const")
                continue
            if name == "source":
                self.string(f["source"], "source", "source")
            elif name in ("line", "lastline"):
                self.int(p.enc["line"], f[name], name)
                self.mark(start, name)
            elif name in ("nupvals", "nparams", "vararg", "maxstack"):
                v = f.get(name)
                if v is None and name == "nupvals":
                    v = len(f.get("upnames") or f.get("upvals") or [])
                self.out.append(v)
                self.mark(start, name)
            elif name == "code":
                code = self.insn.from_std(f["code"], path)
                self.int(p.enc["count"], len(code), "code.count")
                self.out += struct.pack("%s%dI" % (e, len(code)), *code)
                if self.spans is not None:
                    base = start + (len(self.out) - start - 4 * len(code))
                    self.spans.append((start, base, path, "code.count"))
                    for k in range(len(code)):
                        self.spans.append((base + 4 * k, base + 4 * k + 4, path, "code[%d]" % k))
            elif name == "constants":
                self._constants(f["K"])
            elif name == "upvals":
                self.int(p.enc["count"], len(f["upvals"]), "upvals.count")
                for u in f["upvals"]:
                    width = 3 if self.v == "5.4" else 2
                    u = tuple(u) + (0,) * (width - len(u))
                    self.out += bytes(u[:width])
                self.mark(start, "upvals")
            elif name == "protos":
                self.int(p.enc["count"], len(f["protos"]), "protos.count")
                self.mark(start, "protos.count")
                for k, c in enumerate(f["protos"]):
                    self.func(c, "%s/%d" % (path, k))
                self.path = path
            elif name == "lines":
                enc = p.enc["lineinfo"]
                self.int(p.enc["count"], len(f["lines"]), "lines.count")
                if enc in _INT_FMT:
                    self.out += struct.pack("%s%d%s" % (e, len(f["lines"]), _INT_FMT[enc]), *f["lines"])
                else:
                    for x in f["lines"]:
                        self.int(enc, x, "lines")
                self.mark(start, "lines")
            elif name == "abslines":
                self.int(p.enc["count"], len(f.get("abslines", [])), "abslines.count")
                for pc, line in f.get("abslines", []):
                    self.int(p.enc["pc"], pc, "abslines.pc")
                    self.int(p.enc["pc"], line, "abslines.line")
                self.mark(start, "abslines")
            elif name == "locvars":
                self.int(p.enc["count"], len(f["locvars"]), "locvars.count")
                for k, (nm, s, en) in enumerate(f["locvars"]):
                    self.string(nm, "names", "locvars[%d].name" % k)
                    a = len(self.out)
                    self.int(p.enc["pc"], s, "locvars.startpc")
                    self.int(p.enc["pc"], en, "locvars.endpc")
                    self.mark(a, "locvars[%d].pc" % k)
            elif name == "upnames":
                self.int(p.enc["count"], len(f["upnames"]), "upnames.count")
                for k, nm in enumerate(f["upnames"]):
                    self.string(nm, "names", "upnames[%d]" % k)
        self.path = saved

    def _keep(self, t, v):
        start = len(self.out)
        hook = self.p.hook("write_keep")
        if hook:
            hook(self, t, v)
        elif t == "string":
            self.string(v if isinstance(v, (bytes, type(None))) else str(v).encode(), "keep", "keep")
        elif t == "count":
            self.int(self.p.enc["count"], v, "keep")
        else:
            self.int(t, v, "keep")
        self.mark(start, "keep:" + t)

    def _constants(self, ks):
        p = self.p
        start = len(self.out)
        self.int(p.enc["count"], len(ks), "constants.count")
        self.mark(start, "constants.count")
        for k, (t, v) in enumerate(ks):
            start = len(self.out)
            kind = self.kinds.get(t)
            if kind is None or t not in p.std_to_tag:
                raise FormatError("constant tag %r is not valid for Lua %s" % (t, self.v), path=self.path,
                                  field="K[%d]" % k)
            self.out.append(p.std_to_tag[t])
            if kind == "bool":
                self.out.append(1 if v else 0)
            elif kind == "num":
                self.out += struct.pack(p.fmt_number, v)
            elif kind == "int":
                try:
                    self.out += struct.pack(p.fmt_integer, v)
                except struct.error:
                    raise FormatError("integer constant %d does not fit in %d bytes"
                                      % (v, p.sizes["integer"]), path=self.path, field="K[%d]" % k)
            elif kind == "str":
                self.string(v, "constants", "K[%d]" % k)
                continue
            self.mark(start, "K[%d]" % k)


# ---------------------------------------------------------------- API
def parse(data, prof, trace=False):
    pre = prof.hook("pre_read")
    if pre:
        data = pre(data)
    r = Reader(data, prof, trace)
    meta = r.header()
    root = r.func("main")
    if r.i != len(data):
        r.path = "end"
        r.fail("%d trailing bytes after the main function" % (len(data) - r.i), "trailing",
               hint="a section was read with the wrong size, or the file has an appended footer")
    chunk = Chunk(prof.lua, root, meta["nupvals"], meta["keep"])
    if trace:
        chunk.spans = r.spans
    return chunk


def dump(chunk, prof, trace=False):
    if chunk.lua != prof.lua:
        raise FormatError("chunk is Lua %s but the profile %r is for %s" % (chunk.lua, prof.name, prof.lua))
    w = Writer(prof, trace)
    nup = chunk.nupvals
    if nup is None:
        nup = len(chunk.root.get("upvals") or [])
    w.header(nup, chunk.keep)
    w.func(chunk.root, "main")
    out = bytes(w.out)
    post = prof.hook("post_write")
    if post:
        out = post(out)
    if trace:
        return out, w.spans
    return out
