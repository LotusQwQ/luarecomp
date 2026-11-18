# -*- coding: utf-8 -*-
"""Reader / writer for LuaJIT 2.0 / 2.1 bytecode dumps (lj_bcwrite.c / lj_bcread.c).

Layout:  ESC 'L' 'J' | version | flags(uleb) | [chunkname]  then prototypes in post-order
(children before their parent), each prefixed by its byte length, terminated by a 0 byte.
The chunk keeps prototypes as a flat list in file order, which makes round trips exact;
``walk()`` rebuilds the tree (each CHILD constant pops the most recently read prototype).
"""
import struct

from .errors import FormatError
from .puc import Chunk, InsnCodec, _Strings

F_BE, F_STRIP, F_FFI, F_FR2 = 1, 2, 4, 8
KGC_CHILD, KGC_TAB, KGC_I64, KGC_U64, KGC_COMPLEX, KGC_STR = 0, 1, 2, 3, 4, 5
KTAB_NIL, KTAB_FALSE, KTAB_TRUE, KTAB_INT, KTAB_NUM, KTAB_STR = 0, 1, 2, 3, 4, 5


class _R:
    def __init__(self, data, prof):
        self.b, self.i, self.p = data, 0, prof
        self.path = "header"
        self.strs = _Strings(prof)
        self.trail = []

    def fail(self, msg, field=None, hint=None, offset=None):
        raise FormatError(msg, offset=self.i if offset is None else offset, path=self.path, field=field,
                          hint=hint, trail=self.trail[-12:])

    def need(self, n, field):
        if self.i + n > len(self.b):
            self.fail("need %d bytes but only %d remain" % (n, len(self.b) - self.i), field)

    def u8(self, field):
        self.need(1, field)
        v = self.b[self.i]
        self.i += 1
        return v

    def uleb(self, field):
        start, v, sh = self.i, 0, 0
        while True:
            b = self.u8(field)
            v |= (b & 0x7F) << sh
            sh += 7
            if b < 0x80:
                return v
            if sh > 35:
                self.fail("uleb128 longer than 5 bytes", field, offset=start)

    def raw_uleb(self, field):
        start = self.i
        while self.u8(field) >= 0x80:
            pass
        return bytes(self.b[start:self.i])

    def bytes(self, n, field):
        self.need(n, field)
        s = bytes(self.b[self.i:self.i + n])
        self.i += n
        return s


def _w_uleb(out, v):
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return


def _ktabk(r, field):
    tp = r.uleb(field)
    if tp >= KTAB_STR:
        return ("str", r.strs.decode(r.bytes(tp - KTAB_STR, field), "constants"))
    if tp == KTAB_INT:
        return ("int", r.uleb(field))
    if tp == KTAB_NUM:
        return ("num", r.uleb(field), r.uleb(field))
    return (("nil", "false", "true")[tp],)


def _w_ktabk(out, k, strs):
    t = k[0]
    if t == "str":
        s = strs.encode(k[1], "constants")
        _w_uleb(out, KTAB_STR + len(s))
        out += s
    elif t == "int":
        _w_uleb(out, KTAB_INT)
        _w_uleb(out, k[1])
    elif t == "num":
        _w_uleb(out, KTAB_NUM)
        _w_uleb(out, k[1])
        _w_uleb(out, k[2])
    else:
        _w_uleb(out, ("nil", "false", "true").index(t))


def kn_value(raw):
    """Decode a raw number constant -> int or float."""
    v = raw[0] >> 1
    isnum = raw[0] & 1
    i = 1
    if v >= 0x40:
        v &= 0x3F
        sh = -1
        while True:
            b = raw[i]
            sh += 7
            v |= (b & 0x7F) << sh
            i += 1
            if b < 0x80:
                break
    v &= 0xFFFFFFFF
    if not isnum:
        return v - (1 << 32) if v >= 1 << 31 else v
    hi, sh = 0, 0
    while i < len(raw):
        b = raw[i]
        hi |= (b & 0x7F) << sh
        sh += 7
        i += 1
    return struct.unpack("<d", struct.pack("<II", v, hi & 0xFFFFFFFF))[0]


def kn_encode(value):
    """int / float -> raw bytes the way lj_bcwrite.c writes them."""
    out = bytearray()
    if isinstance(value, int) or (isinstance(value, float) and value.is_integer()
                                  and -2 ** 31 <= value < 2 ** 31 and not (value == 0 and str(value)[0] == "-")):
        k = int(value) & 0xFFFFFFFF
        _w_uleb(out, (2 * k | (k & 0x80000000)) & 0x1FFFFFFFF)
        if k & 0x80000000:
            out[-1] = (out[-1] & 7) | ((k >> 27) & 0x18)
        return bytes(out)
    lo, hi = struct.unpack("<II", struct.pack("<d", value))
    _w_uleb(out, (1 + (2 * lo | (lo & 0x80000000))) & 0x1FFFFFFFF)
    if lo >= 0x80000000:
        out[-1] = (out[-1] & 7) | ((lo >> 27) & 0x18)
    _w_uleb(out, hi)
    return bytes(out)


def parse(data, prof, trace=False):
    pre = prof.hook("pre_read")
    if pre:
        data = pre(data)
    r = _R(data, prof)
    sig = r.bytes(len(prof.signature), "signature") if len(data) >= len(prof.signature) else data
    if sig != prof.signature:
        r.fail("signature %s does not match profile %r (expects %s)" % (sig.hex(), prof.name, prof.signature.hex()),
               "signature", offset=0, hint="not LuaJIT bytecode, wrong profile, or still encrypted; try `inspect`")
    ver = r.u8("version")
    if ver != prof.version:
        r.fail("version byte %d, profile expects %d" % (ver, prof.version), "version", offset=r.i - 1,
               hint="LuaJIT 2.0 dumps use version 1, 2.1 uses 2")
    flags = r.uleb("flags")
    if prof.flags is not None and flags != prof.flags:
        r.fail("flags %#x, profile expects %#x" % (flags, prof.flags), "flags")
    if flags & ~0xF:
        r.fail("unknown flag bits %#x" % flags, "flags", hint="standard flags: 1=big-endian 2=strip 4=ffi 8=fr2")
    e = ">" if flags & F_BE else "<"
    chunkname = None
    if not flags & F_STRIP:
        n = r.uleb("chunkname.len")
        chunkname = r.strs.decode(r.bytes(n, "chunkname"), "source")
    codec = InsnCodec(prof)
    protos = []
    while True:
        r.path = "proto#%d" % len(protos)
        start = r.i
        n = r.uleb("proto.len")
        if n == 0:
            break
        end = r.i + n
        if end > len(data):
            r.fail("prototype length %d runs past the end of the data" % n, "proto.len", offset=start)
        pt = _proto(r, e, flags, codec, len(protos))
        if r.i != end:
            r.fail("prototype length says %d bytes, its fields used %d" % (n, r.i - (end - n)), "proto.len",
                   offset=start, hint="a field inside the prototype was read with the wrong encoding")
        protos.append(pt)
    if r.i != len(data):
        r.fail("%d trailing bytes after the terminating 0" % (len(data) - r.i), "trailing")
    ch = Chunk(prof.lua, None, None, flags=flags, chunkname=chunkname, protos=protos, endian=e)
    ch.root = _tree(ch)
    return ch


def _proto(r, e, flags, codec, idx):
    pt = {"flags": r.u8("flags"), "nparams": r.u8("numparams"), "framesize": r.u8("framesize")}
    sizeuv = r.u8("sizeuv")
    sizekgc, sizekn, sizebc = r.uleb("sizekgc"), r.uleb("sizekn"), r.uleb("sizebc")
    sizedbg = None
    if not flags & F_STRIP:
        sizedbg = r.uleb("sizedbg")
        if sizedbg:
            pt["firstline"], pt["numline"] = r.uleb("firstline"), r.uleb("numline")
    r.need(4 * sizebc, "bc")
    words = list(struct.unpack_from("%s%dI" % (e, sizebc), r.b, r.i))
    r.i += 4 * sizebc
    pt["code"] = codec.to_std(words, r.path)
    r.need(2 * sizeuv, "uv")
    pt["uv"] = list(struct.unpack_from("%s%dH" % (e, sizeuv), r.b, r.i))
    r.i += 2 * sizeuv
    kgc = []
    for k in range(sizekgc):
        f = "kgc[%d]" % k
        tp = r.uleb(f)
        if tp >= KGC_STR:
            kgc.append(("str", r.strs.decode(r.bytes(tp - KGC_STR, f), "constants")))
        elif tp == KGC_CHILD:
            kgc.append(("child",))
        elif tp == KGC_TAB:
            na, nh = r.uleb(f + ".narray"), r.uleb(f + ".nhash")
            arr = [_ktabk(r, f) for _ in range(na)]
            hsh = [(_ktabk(r, f), _ktabk(r, f)) for _ in range(nh)]
            kgc.append(("tab", arr, hsh))
        elif tp in (KGC_I64, KGC_U64):
            kgc.append(("i64" if tp == KGC_I64 else "u64", r.uleb(f), r.uleb(f)))
        else:
            kgc.append(("complex", r.uleb(f), r.uleb(f), r.uleb(f), r.uleb(f)))
    pt["kgc"] = kgc
    kn = []
    for k in range(sizekn):
        isnum = r.b[r.i] & 1 if r.i < len(r.b) else 0
        raw = r.raw_uleb("kn[%d]" % k)
        if isnum:
            raw += r.raw_uleb("kn[%d].hi" % k)
        kn.append(raw)
    pt["kn"] = kn
    pt["debug"] = r.bytes(sizedbg, "debug") if sizedbg else (b"" if sizedbg == 0 else None)
    r.trail.append((r.i, r.path, "proto", "bc=%d kgc=%d kn=%d" % (sizebc, sizekgc, sizekn)))
    return pt


def dump(chunk, prof, trace=False):
    if chunk.lua != prof.lua:
        raise FormatError("chunk is %s but the profile %r is for %s" % (chunk.lua, prof.name, prof.lua))
    strs = _Strings(prof)
    codec = InsnCodec(prof)
    flags = chunk.flags
    e = ">" if flags & F_BE else "<"
    out = bytearray(prof.signature)
    out.append(prof.version)
    _w_uleb(out, flags)
    if not flags & F_STRIP:
        name = strs.encode(chunk.chunkname or b"", "source")
        _w_uleb(out, len(name))
        out += name
    spans = [] if trace else None
    for n, pt in enumerate(chunk.protos):
        body = bytearray()
        path = "proto#%d" % n
        body.append(pt["flags"])
        body.append(pt["nparams"])
        body.append(pt["framesize"])
        body.append(len(pt["uv"]))
        _w_uleb(body, len(pt["kgc"]))
        _w_uleb(body, len(pt["kn"]))
        _w_uleb(body, len(pt["code"]))
        if not flags & F_STRIP:
            dbg = pt.get("debug") or b""
            _w_uleb(body, len(dbg))
            if dbg:
                _w_uleb(body, pt["firstline"])
                _w_uleb(body, pt["numline"])
        code = codec.from_std(pt["code"], path)
        body += struct.pack("%s%dI" % (e, len(code)), *code)
        body += struct.pack("%s%dH" % (e, len(pt["uv"])), *pt["uv"])
        for k in pt["kgc"]:
            t = k[0]
            if t == "str":
                s = strs.encode(k[1], "constants")
                _w_uleb(body, KGC_STR + len(s))
                body += s
            elif t == "child":
                _w_uleb(body, KGC_CHILD)
            elif t == "tab":
                _w_uleb(body, KGC_TAB)
                _w_uleb(body, len(k[1]))
                _w_uleb(body, len(k[2]))
                for x in k[1]:
                    _w_ktabk(body, x, strs)
                for a, b in k[2]:
                    _w_ktabk(body, a, strs)
                    _w_ktabk(body, b, strs)
            elif t in ("i64", "u64"):
                _w_uleb(body, KGC_I64 if t == "i64" else KGC_U64)
                _w_uleb(body, k[1])
                _w_uleb(body, k[2])
            else:
                _w_uleb(body, KGC_COMPLEX)
                for x in k[1:]:
                    _w_uleb(body, x)
        for raw in pt["kn"]:
            body += raw
        if not flags & F_STRIP and pt.get("debug"):
            body += pt["debug"]
        start = len(out)
        _w_uleb(out, len(body))
        out += body
        if spans is not None:
            spans.append((start, len(out), path, "proto"))
    out.append(0)
    out = bytes(out)
    post = prof.hook("post_write")
    if post:
        out = post(out)
    return (out, spans) if trace else out


def _tree(chunk):
    """Rebuild the prototype tree; sets pt['protos'] (children in kgc order) and returns main."""
    stack = []
    for n, pt in enumerate(chunk.protos):
        nchild = sum(1 for k in pt["kgc"] if k[0] == "child")
        if nchild > len(stack):
            raise FormatError("prototype needs %d children but only %d are pending" % (nchild, len(stack)),
                              path="proto#%d" % n, hint="prototypes are out of order or a CHILD constant is bogus")
        kids = [stack.pop() for _ in range(nchild)]
        pt["protos"] = kids
        pt["index"] = n
        stack.append(pt)
    if len(stack) != 1:
        raise FormatError("%d top-level prototypes (expected exactly 1)" % len(stack), path="end")
    return stack[0]


def walk(chunk):
    out = [("main", chunk.root)]
    i = 0
    while i < len(out):
        path, pt = out[i]
        for k, c in enumerate(pt["protos"]):
            out.append(("%s/%d" % (path, k), c))
        i += 1
    yield from out
