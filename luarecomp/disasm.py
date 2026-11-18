# -*- coding: utf-8 -*-
"""Human-readable listing of a parsed chunk (standard opcode names, with the custom opcode
number next to it when a profile is given, constants and jump targets resolved)."""
from . import isa as ISA
from .luajit import kn_value


def _k(v, limit=40):
    if isinstance(v, bytes):
        s = v.decode("utf-8", "replace")
        r = repr(s if len(s) <= limit else s[:limit] + "...")
        return r
    return repr(v)


def _note_puc(isa, f, pc, d, lua):
    notes = []
    names = isa.operand_names(d["op"])
    roles = isa.roles[d["op"]]
    K = f["K"]
    up = f.get("upnames") or []
    kbit = d.get("k", 0)
    for fld, role in zip(names, roles):
        v = d[fld]
        if role in ("K", "KS") and v < len(K):
            notes.append(_k(K[v][1]))
        elif role == "RK" and v >= 256 and v - 256 < len(K):
            notes.append(_k(K[v - 256][1]))
        elif role == "RKk" and kbit and v < len(K):
            notes.append(_k(K[v][1]))
        elif role == "U":
            notes.append("up:%s" % (up[v].decode("utf-8", "replace") if v < len(up) and up[v] else v))
        elif role in ("J", "Jb", "Jf", "Jf2"):
            t = {"J": pc + 1 + v, "Jb": pc + 1 - v, "Jf": pc + 1 + v, "Jf2": pc + 2 + v}[role]
            notes.append("-> %d" % t)
        elif role == "P":
            notes.append("proto %d" % v)
    return notes


def _note_lj(isa, f, pc, d):
    notes = []
    kgc = f["kgc"]
    for fld, role in zip(isa.operand_names(d["op"]), isa.roles[d["op"]]):
        v = d[fld]
        if role == "str" and v < len(kgc):
            notes.append(_k(kgc[len(kgc) - 1 - v][1]))
        elif role == "num" and v < len(f["kn"]):
            notes.append(repr(kn_value(f["kn"][v])))
        elif role == "jump":
            notes.append("-> %d" % (pc + 1 + v - 0x8000))
        elif role == "func":
            notes.append("child")
        elif role == "pri":
            notes.append(("nil", "false", "true")[v] if v < 3 else "?")
    return notes


def disasm(chunk, prof=None, max_lines=None):
    """-> list of text lines."""
    isa = chunk.isa
    out = []
    lj = isa.family == "luajit"
    for path, f in chunk.walk():
        if lj:
            out.append("function %s  params=%d framesize=%d  #bc=%d #kgc=%d #kn=%d #uv=%d" % (
                path, f["nparams"], f["framesize"], len(f["code"]), len(f["kgc"]), len(f["kn"]), len(f["uv"])))
        else:
            src = (f.get("source") or b"").decode("utf-8", "replace")
            out.append("function %s  %s:%s-%s  params=%d vararg=%d maxstack=%d  #code=%d #K=%d #up=%d #protos=%d"
                       % (path, src, f["line"], f["lastline"], f["nparams"], f["vararg"], f["maxstack"],
                          len(f["code"]), len(f["K"]), len(f.get("upvals") or []) or (f.get("nupvals") or 0),
                          len(f["protos"])))
        raw = 0
        for pc, w in enumerate(f["code"]):
            if raw:
                out.append("  %5d  %08x  (data word %d)" % (pc, w, w))
                raw = 0
                continue
            op = ISA.get_field(w, isa.layout, "op")
            if op >= isa.num:
                out.append("  %5d  %08x  ??? opcode %d" % (pc, w, op))
                continue
            d = ISA.decode(isa, w, op=op)
            ops = " ".join("%s=%d" % (k, d[k]) for k in isa.operand_names(op))
            custom = ""
            if prof is not None and op in prof.std_to_op and not prof.opcodes_identity:
                custom = "[%3d] " % prof.std_to_op[op]
            notes = _note_lj(isa, f, pc, d) if lj else _note_puc(isa, f, pc, d, chunk.lua)
            out.append("  %5d  %08x  %s%-10s %-24s %s" % (pc, w, custom, isa.opname(op), ops,
                                                         ("; " + ", ".join(notes)) if notes else ""))
            if chunk.lua == "5.1" and op == isa.index["SETLIST"] and d["C"] == 0:
                raw = 1
            if max_lines and len(out) >= max_lines:
                out.append("  ... (truncated)")
                return out
    return out
