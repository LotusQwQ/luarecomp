# -*- coding: utf-8 -*-
"""Static bytecode verifier.

Checks every instruction against the operand roles in isa.py: register numbers below
maxstack, constant / upvalue / prototype indexes in range, jump targets inside the
function, mandatory successors (EQ -> JMP, ...), functions ending in a return.

Real compilers never produce violations, so a violation after conversion almost always
means the opcode map (or the instruction layout) of the profile is wrong.  `summarize()`
groups the issues per opcode to point at the culprit.

Lua's own loader does not check any of this (5.2+ removed the bytecode verifier), which
is why a wrong profile can "load fine" and still crash or misbehave at run time.
"""
import collections

from . import isa as ISA

ERROR, WARN = "error", "warn"


class Issue:
    __slots__ = ("path", "pc", "op", "opname", "severity", "msg", "word")

    def __init__(self, path, pc, op, opname, severity, msg, word):
        self.path, self.pc, self.op, self.opname = path, pc, op, opname
        self.severity, self.msg, self.word = severity, msg, word

    def __str__(self):
        return "%s pc %d %s: %s" % (self.path, self.pc, self.opname, self.msg)

    def as_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


def _const_is_str(f, idx, lua):
    t = f["K"][idx][0]
    return t in (4, 0x14)


def verify_proto(f, path, isa, lua, soft=True):
    """-> list of Issue for one PUC prototype (instructions in standard form)."""
    out = []
    code = f["code"]
    n = len(code)
    ms = f["maxstack"]
    nk = len(f["K"])
    nu = f["nupvals"] if lua == "5.1" else len(f["upvals"])
    npr = len(f["protos"])
    L = isa.layout
    lua51 = lua == "5.1"
    lua54 = lua == "5.4"
    setlist = isa.index["SETLIST"]
    closure = isa.index["CLOSURE"]
    extra = isa.index.get("EXTRAARG")
    extra_ok = {isa.index[x] for x in ("LOADKX", "SETLIST", "NEWTABLE") if x in isa.index}
    skip = 0
    prev = None

    def bad(sev, msg):
        out.append(Issue(path, pc, op, isa.opname(op), sev, msg, w))

    for pc, w in enumerate(code):
        if skip:
            skip -= 1
            continue
        op = ISA.get_field(w, L, "op")
        if op >= isa.num:
            bad(ERROR, "opcode %d does not exist in Lua %s" % (op, lua))
            prev = None
            continue
        d = ISA.decode(isa, w, op=op)
        roles = isa.roles[op]
        names = isa.operand_names(op)
        kbit = d.get("k", 0)
        for fld, role in zip(names, roles):
            v = d[fld]
            if role == "N" or role == "k":
                continue
            if role == "-":
                if soft and v != 0:
                    bad(WARN, "unused operand %s is %d (compilers write 0)" % (fld, v))
                continue
            msg = None
            if role == "R" and v >= ms:
                msg = "register %s=%d >= maxstack %d" % (fld, v, ms)
            elif role == "Rb" and v > ms:
                msg = "register base %s=%d > maxstack %d" % (fld, v, ms)
            elif role in ("K", "KS"):
                if v >= nk:
                    msg = "constant %s=%d >= #K %d" % (fld, v, nk)
                elif role == "KS" and not _const_is_str(f, v, lua):
                    msg = "constant %s=%d is not a string" % (fld, v)
            elif role == "RK":
                if v >= 256:
                    if v - 256 >= nk:
                        msg = "RK constant %s=%d (K %d) >= #K %d" % (fld, v, v - 256, nk)
                elif v >= ms:
                    msg = "RK register %s=%d >= maxstack %d" % (fld, v, ms)
            elif role == "RKk":
                if kbit and v >= nk:
                    msg = "constant %s=%d >= #K %d" % (fld, v, nk)
                elif not kbit and v >= ms:
                    msg = "register %s=%d >= maxstack %d" % (fld, v, ms)
            elif role == "U" and v >= nu:
                msg = "upvalue %s=%d >= #upvalues %d" % (fld, v, nu)
            elif role == "P" and v >= npr:
                msg = "prototype %s=%d >= #protos %d" % (fld, v, npr)
            elif role == "01" and v not in (0, 1):
                msg = "%s=%d must be 0 or 1" % (fld, v)
            elif role in ("J", "Jb", "Jf", "Jf2"):
                t = {"J": pc + 1 + v, "Jb": pc + 1 - v, "Jf": pc + 1 + v, "Jf2": pc + 2 + v}[role]
                if not 0 <= t <= n:
                    msg = "jump target %d outside 0..%d" % (t, n)
            if msg:
                bad(ERROR, msg)
        rule = isa.rules.get(op)
        if rule is not None and not rule(d, ms, pc, n):
            bad(ERROR, "operands out of range for %s (%s)" % (isa.opname(op), ", ".join(
                "%s=%d" % (k, d[k]) for k in names)))
        # sequencing rules
        need = isa.successors.get(op)
        if need is not None:
            if pc + 1 >= n:
                bad(ERROR, "must be followed by %s but is the last instruction" % "/".join(isa.opname(x) for x in need))
            else:
                nxt = ISA.get_field(code[pc + 1], L, "op")
                if nxt not in need:
                    bad(ERROR, "must be followed by %s, found %s"
                        % ("/".join(isa.opname(x) for x in need), isa.opname(nxt)))
        if extra is not None and op == extra and prev not in extra_ok:
            bad(ERROR, "EXTRAARG after %s" % (isa.opname(prev) if prev is not None else "nothing"))
        if extra is not None and op == setlist and pc + 1 < n:
            needs_extra = kbit if lua54 else d["C"] == 0
            if needs_extra and ISA.get_field(code[pc + 1], L, "op") != extra:
                bad(ERROR, "SETLIST with extended count must be followed by EXTRAARG")
        if lua51 and op == setlist and d["C"] == 0:
            skip = 1        # raw count word follows
        if lua51 and op == closure and d["Bx"] < npr:
            skip = f["protos"][d["Bx"]]["nupvals"]   # pseudo-instructions, checked loosely
            for k in range(1, skip + 1):
                if pc + k < n:
                    po = ISA.get_field(code[pc + k], L, "op")
                    if po not in (isa.index["MOVE"], isa.index["GETUPVAL"]):
                        out.append(Issue(path, pc + k, po, isa.opname(po), ERROR,
                                         "CLOSURE upvalue pseudo-instruction must be MOVE or GETUPVAL", code[pc + k]))
        prev = op
    if n == 0:
        out.append(Issue(path, 0, -1, "-", ERROR, "function has no instructions", 0))
    else:
        last = ISA.get_field(code[-1], L, "op")
        if last not in isa.returns:
            out.append(Issue(path, n - 1, last, isa.opname(last), ERROR, "function does not end with a return",
                             code[-1]))
    return out


def verify_lj(pt, path, isa, soft=True):
    out = []
    code = pt["code"]
    n = len(code)
    fs = pt["framesize"]
    kgc = pt["kgc"]
    nkgc, nkn, nuv = len(kgc), len(pt["kn"]), len(pt["uv"])
    L = isa.layout
    for pc, w in enumerate(code):
        op = ISA.get_field(w, L, "op")

        def bad(sev, msg):
            out.append(Issue(path, pc, op, isa.opname(op), sev, msg, w))

        if op >= isa.num:
            bad(ERROR, "opcode %d does not exist in %s" % (op, isa.key))
            continue
        d = ISA.decode(isa, w, op=op)
        for fld, role in zip(isa.operand_names(op), isa.roles[op]):
            v = d[fld]
            msg = None
            if role in ("dst", "base", "var"):
                if v >= fs:
                    msg = "slot %s=%d >= framesize %d" % (fld, v, fs)
            elif role == "rbase":
                if v > fs:
                    msg = "slot base %s=%d > framesize %d" % (fld, v, fs)
            elif role == "uv":
                if v >= nuv:
                    msg = "upvalue %s=%d >= %d" % (fld, v, nuv)
            elif role in ("str", "tab", "func", "cdata"):
                if v >= nkgc:
                    msg = "GC constant %s=%d >= %d" % (fld, v, nkgc)
                else:
                    kind = kgc[nkgc - 1 - v][0]
                    want = {"str": ("str",), "tab": ("tab",), "func": ("child",),
                            "cdata": ("i64", "u64", "complex")}[role]
                    if kind not in want:
                        msg = "GC constant %s=%d is a %s, expected %s" % (fld, v, kind, role)
            elif role == "num":
                if v >= nkn:
                    msg = "number constant %s=%d >= %d" % (fld, v, nkn)
            elif role == "pri":
                if v > 2:
                    msg = "primitive %s=%d must be 0..2" % (fld, v)
            elif role == "jump":
                t = pc + 1 + v - isa.biases["jump"]
                if not 0 <= t <= n:
                    msg = "jump target %d outside 0..%d" % (t, n)
            elif role == "___":
                if soft and v != 0:
                    bad(WARN, "unused operand %s is %d" % (fld, v))
            if msg:
                bad(ERROR, msg)
        need = isa.successors.get(op)
        if need is not None:
            if pc + 1 >= n or ISA.get_field(code[pc + 1], L, "op") not in need:
                bad(ERROR, "must be followed by JMP")
        if op in isa.never_dumped:
            bad(ERROR, "%s is a runtime-only opcode and never appears in a bytecode dump" % isa.opname(op))
    if n and ISA.get_field(code[-1], L, "op") not in isa.returns:
        last = ISA.get_field(code[-1], L, "op")
        out.append(Issue(path, n - 1, last, isa.opname(last), ERROR, "function does not end with a return",
                         code[-1]))
    return out


def verify(chunk, soft=True):
    """Verify every function of a parsed chunk -> list of Issue."""
    isa = chunk.isa
    out = []
    for path, f in chunk.walk():
        if isa.family == "luajit":
            out += verify_lj(f, path, isa, soft)
        else:
            out += verify_proto(f, path, isa, chunk.lua, soft)
    return out


def summarize(issues, prof=None):
    """Group errors per standard opcode; with a profile also name the custom opcode number.
    -> list of text lines, most suspicious opcode first."""
    errs = [i for i in issues if i.severity == ERROR]
    if not errs:
        return []
    by_op = collections.Counter(i.opname for i in errs)
    ex = {}
    for i in errs:
        ex.setdefault(i.opname, i)
    lines = []
    for name, cnt in by_op.most_common(10):
        i = ex[name]
        extra = ""
        if prof is not None and i.op >= 0 and i.op in prof.std_to_op:
            extra = " (custom opcode %d)" % prof.std_to_op[i.op]
        lines.append("%-10s%s: %d violation(s), e.g. %s" % (name, extra, cnt, i))
    return lines
