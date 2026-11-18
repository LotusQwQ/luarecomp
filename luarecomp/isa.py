# -*- coding: utf-8 -*-
"""Instruction sets of every supported VM.

For each ISA we keep: opcode names (index = standard opcode number), the instruction
format of each opcode, the *role* of each operand (used by the verifier, the
disassembler and opcode inference) and the standard bit layout of an instruction.

Operand roles
    R    register, < maxstack            Rb  register base, <= maxstack
    K    constant index                  KS  constant index that must be a string
    RK   register, or constant if >= 256 (Lua 5.1-5.3, 9-bit B/C)
    RKk  constant if the k bit is set, else register (Lua 5.4)
    U    upvalue index                   P   child prototype index
    J    relative jump: target = pc + 1 + sBx
    Jb   Lua 5.4 backward jump: target = pc + 1 - Bx
    Jf   Lua 5.4 forward jump:  target = pc + 1 + Bx
    Jf2  Lua 5.4 FORPREP:        target = pc + 2 + Bx
    01   0 or 1                          N   any number
    -    unused (the reference compilers always write 0)

LuaJIT roles follow lj_bc.h: dst base var rbase uv lit lits pri num str tab func jump cdata ___.
"""


class ISA:
    def __init__(self, key, names, formats, roles, layout, biases, successors, returns, family="puc"):
        self.key, self.family = key, family
        self.names = names
        self.num = len(names)
        self.index = {n: i for i, n in enumerate(names)}
        self.formats = formats            # op -> "ABC" | "ABx" | "AsBx" | "Ax" | "sJ" | "AD"
        self.roles = roles                # op -> tuple of roles for the operands of the format
        self.layout = layout              # field -> (pos, width)
        self.biases = biases              # field -> bias for signed fields
        self.successors = successors      # op -> set of ops that must follow (hard)
        self.returns = returns            # ops that may end a function

    def op(self, name):
        return self.index[name]

    def opname(self, op):
        return self.names[op] if 0 <= op < self.num else "OP_%d" % op

    def operand_names(self, op):
        return FORMAT_FIELDS[self.formats[op]]


FORMAT_FIELDS = {
    "ABC": ("A", "B", "C"),
    "ABCk": ("A", "B", "C", "k"),
    "ABx": ("A", "Bx"),
    "AsBx": ("A", "sBx"),
    "Ax": ("Ax",),
    "sJ": ("sJ",),
    "AD": ("A", "D"),
}


def _table(spec):
    names, formats, roles = [], {}, {}
    for line in spec.strip().splitlines():
        parts = line.split()
        if not parts or parts[0].startswith("#"):
            continue
        group, fmt, r = parts[0].split(","), parts[1], tuple(parts[2:])
        for n in group:
            formats[len(names)] = fmt
            roles[len(names)] = r
            names.append(n)
    return names, formats, roles


# ---------------------------------------------------------------- Lua 5.1
_S51 = """
MOVE ABC R R -
LOADK ABx R K
LOADBOOL ABC R 01 01
LOADNIL ABC R R -
GETUPVAL ABC R U -
GETGLOBAL ABx R KS
GETTABLE ABC R R RK
SETGLOBAL ABx R KS
SETUPVAL ABC R U -
SETTABLE ABC R RK RK
NEWTABLE ABC R N N
SELF ABC R R RK
ADD,SUB,MUL,DIV,MOD,POW ABC R RK RK
UNM,NOT,LEN ABC R R -
CONCAT ABC R R R
JMP AsBx - J
EQ,LT,LE ABC 01 RK RK
TEST ABC R - 01
TESTSET ABC R R 01
CALL,TAILCALL ABC R N N
RETURN ABC Rb N -
FORLOOP,FORPREP AsBx R J
TFORLOOP ABC R - N
SETLIST ABC R N N
CLOSE ABC Rb - -
CLOSURE ABx R P
VARARG ABC R N -
"""

# ---------------------------------------------------------------- Lua 5.2 / 5.3
_S52_HEAD = """
MOVE ABC R R -
LOADK ABx R K
LOADKX ABx R -
LOADBOOL ABC R 01 01
LOADNIL ABC R N -
GETUPVAL ABC R U -
GETTABUP ABC R U RK
GETTABLE ABC R R RK
SETTABUP ABC U RK RK
SETUPVAL ABC R U -
SETTABLE ABC R RK RK
NEWTABLE ABC R N N
SELF ABC R R RK
"""
_S52_TAIL = """
CONCAT ABC R R R
JMP AsBx N J
EQ,LT,LE ABC 01 RK RK
TEST ABC R - 01
TESTSET ABC R R 01
CALL,TAILCALL ABC R N N
RETURN ABC Rb N -
FORLOOP,FORPREP AsBx R J
TFORCALL ABC R - N
TFORLOOP AsBx R J
SETLIST ABC R N N
CLOSURE ABx R P
VARARG ABC R N -
EXTRAARG Ax N
"""
_S52 = _S52_HEAD + """
ADD,SUB,MUL,DIV,MOD,POW ABC R RK RK
UNM,NOT,LEN ABC R R -
""" + _S52_TAIL
_S53 = _S52_HEAD + """
ADD,SUB,MUL,MOD,POW,DIV,IDIV,BAND,BOR,BXOR,SHL,SHR ABC R RK RK
UNM,BNOT,NOT,LEN ABC R R -
""" + _S52_TAIL

# ---------------------------------------------------------------- Lua 5.4
_S54 = """
MOVE ABC R R -
LOADI,LOADF AsBx R N
LOADK ABx R K
LOADKX ABx R -
LOADFALSE,LFALSESKIP,LOADTRUE ABC R - -
LOADNIL ABC R N -
GETUPVAL ABC R U -
SETUPVAL ABC R U -
GETTABUP ABC R U KS
GETTABLE ABC R R R
GETI ABC R R N
GETFIELD ABC R R KS
SETTABUP ABC U KS RKk
SETTABLE ABC R R RKk
SETI ABC R N RKk
SETFIELD ABC R KS RKk
NEWTABLE ABC R N N
SELF ABC R R RKk
ADDI ABC R R N
ADDK,SUBK,MULK,MODK,POWK,DIVK,IDIVK,BANDK,BORK,BXORK ABC R R K
SHRI,SHLI ABC R R N
ADD,SUB,MUL,MOD,POW,DIV,IDIV,BAND,BOR,BXOR,SHL,SHR ABC R R R
MMBIN ABC R R N
MMBINI ABC R N N
MMBINK ABC R K N
UNM,BNOT,NOT,LEN ABC R R -
CONCAT ABC R N -
CLOSE,TBC ABC R - -
JMP sJ J
EQ,LT,LE ABC R R -
EQK ABC R K -
EQI,LTI,LEI,GTI,GEI ABC R N N
TEST ABC R - -
TESTSET ABC R R -
CALL,TAILCALL ABC R N N
RETURN ABC Rb N N
RETURN0 ABC Rb N -
RETURN1 ABC R N -
FORLOOP ABx R Jb
FORPREP ABx R Jf2
TFORPREP ABx R Jf
TFORCALL ABC R - N
TFORLOOP ABx R Jb
SETLIST ABC R N N
CLOSURE ABx R P
VARARG ABC R - N
VARARGPREP ABC N - -
EXTRAARG Ax N
"""

_PUC_LAYOUT = {"op": (0, 6), "A": (6, 8), "C": (14, 9), "B": (23, 9), "Bx": (14, 18), "Ax": (6, 26)}
_PUC_BIAS = {"sBx": (1 << 17) - 1}
_P54_LAYOUT = {"op": (0, 7), "A": (7, 8), "k": (15, 1), "B": (16, 8), "C": (24, 8),
               "Bx": (15, 17), "Ax": (7, 25), "sJ": (7, 25)}
_P54_BIAS = {"sBx": (1 << 16) - 1, "sJ": (1 << 24) - 1}


def _puc(key, spec, layout, bias, succ, rets):
    names, formats, roles = _table(spec)
    idx = {n: i for i, n in enumerate(names)}
    successors = {idx[a]: {idx[b] for b in bs} for a, bs in succ.items()}
    return ISA(key, names, formats, roles, layout, bias, successors, {idx[r] for r in rets})


_CMP_JMP = {n: ["JMP"] for n in ("EQ", "LT", "LE", "TEST", "TESTSET")}

LUA51 = _puc("5.1", _S51, _PUC_LAYOUT, _PUC_BIAS, dict(_CMP_JMP, TFORLOOP=["JMP"]), ["RETURN"])
LUA52 = _puc("5.2", _S52, _PUC_LAYOUT, _PUC_BIAS,
             dict(_CMP_JMP, TFORCALL=["TFORLOOP"], LOADKX=["EXTRAARG"]), ["RETURN"])
LUA53 = _puc("5.3", _S53, _PUC_LAYOUT, _PUC_BIAS,
             dict(_CMP_JMP, TFORCALL=["TFORLOOP"], LOADKX=["EXTRAARG"]), ["RETURN"])
_succ54 = {n: ["JMP"] for n in ("EQ", "LT", "LE", "EQK", "EQI", "LTI", "LEI", "GTI", "GEI", "TEST", "TESTSET")}
_succ54.update({n: ["MMBIN"] for n in "ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR".split()})
_succ54.update({n: ["MMBINK"] for n in "ADDK SUBK MULK MODK POWK DIVK IDIVK BANDK BORK BXORK".split()})
_succ54.update({n: ["MMBINI"] for n in ("ADDI", "SHRI", "SHLI")})
_succ54.update(TFORCALL=["TFORLOOP"], LOADKX=["EXTRAARG"], NEWTABLE=["EXTRAARG"])
LUA54 = _puc("5.4", _S54, _P54_LAYOUT, _P54_BIAS, _succ54, ["RETURN", "RETURN0", "RETURN1"])
for _op, _f in list(LUA54.formats.items()):
    if _f == "ABC":
        LUA54.formats[_op] = "ABCk"
        LUA54.roles[_op] = LUA54.roles[_op] + ("k",)

# ---------------------------------------------------------------- LuaJIT
# name  ma  mb  mcd   (lj_bc.h BCDEF).  "+" marks opcodes that only exist in 2.1.
_LJ = """
ISLT var ___ var
ISGE var ___ var
ISLE var ___ var
ISGT var ___ var
ISEQV var ___ var
ISNEV var ___ var
ISEQS var ___ str
ISNES var ___ str
ISEQN var ___ num
ISNEN var ___ num
ISEQP var ___ pri
ISNEP var ___ pri
ISTC dst ___ var
ISFC dst ___ var
IST ___ ___ var
ISF ___ ___ var
+ISTYPE var ___ lit
+ISNUM var ___ lit
MOV dst ___ var
NOT dst ___ var
UNM dst ___ var
LEN dst ___ var
ADDVN dst var num
SUBVN dst var num
MULVN dst var num
DIVVN dst var num
MODVN dst var num
ADDNV dst var num
SUBNV dst var num
MULNV dst var num
DIVNV dst var num
MODNV dst var num
ADDVV dst var var
SUBVV dst var var
MULVV dst var var
DIVVV dst var var
MODVV dst var var
POW dst var var
CAT dst rbase rbase
KSTR dst ___ str
KCDATA dst ___ cdata
KSHORT dst ___ lits
KNUM dst ___ num
KPRI dst ___ pri
KNIL base ___ base
UGET dst ___ uv
USETV uv ___ var
USETS uv ___ str
USETN uv ___ num
USETP uv ___ pri
UCLO rbase ___ jump
FNEW dst ___ func
TNEW dst ___ lit
TDUP dst ___ tab
GGET dst ___ str
GSET var ___ str
TGETV dst var var
TGETS dst var str
TGETB dst var lit
+TGETR dst var var
TSETV var var var
TSETS var var str
TSETB var var lit
TSETM base ___ num
+TSETR var var var
CALLM base lit lit
CALL base lit lit
CALLMT base ___ lit
CALLT base ___ lit
ITERC base lit lit
ITERN base lit lit
VARG base lit lit
ISNEXT base ___ jump
RETM base ___ lit
RET rbase ___ lit
RET0 rbase ___ lit
RET1 rbase ___ lit
FORI base ___ jump
JFORI base ___ jump
FORL base ___ jump
IFORL base ___ jump
JFORL base ___ lit
ITERL base ___ jump
IITERL base ___ jump
JITERL base ___ lit
LOOP rbase ___ jump
ILOOP rbase ___ jump
JLOOP rbase ___ lit
JMP rbase ___ jump
FUNCF rbase ___ ___
IFUNCF rbase ___ ___
JFUNCF rbase ___ lit
FUNCV rbase ___ ___
IFUNCV rbase ___ ___
JFUNCV rbase ___ lit
FUNCC rbase ___ ___
FUNCCW rbase ___ ___
"""
LJ_MODES = ("___", "dst", "base", "var", "rbase", "uv", "lit", "lits", "pri", "num", "str",
            "tab", "func", "jump", "cdata")
_LJ_LAYOUT = {"op": (0, 8), "A": (8, 8), "C": (16, 8), "B": (24, 8), "D": (16, 16)}
_LJ_BIAS = {"jump": 0x8000}


def _luajit(key, v21):
    names, formats, roles = [], {}, {}
    for line in _LJ.strip().splitlines():
        n, ma, mb, mcd = line.split()
        if n.startswith("+"):
            if not v21:
                continue
            n = n[1:]
        op = len(names)
        names.append(n)
        formats[op] = "AD" if mb == "___" else "ABC"
        roles[op] = (ma, mcd) if mb == "___" else (ma, mb, mcd)
    idx = {n: i for i, n in enumerate(names)}
    succ = {idx[n]: {idx["JMP"]} for n in ("ISLT", "ISGE", "ISLE", "ISGT", "ISEQV", "ISNEV", "ISEQS",
                                           "ISNES", "ISEQN", "ISNEN", "ISEQP", "ISNEP", "ISTC",
                                           "ISFC", "IST", "ISF")}
    rets = {idx[n] for n in ("RET", "RET0", "RET1", "RETM", "CALLT", "CALLMT")}
    isa = ISA(key, names, formats, roles, _LJ_LAYOUT, _LJ_BIAS, succ, rets, family="luajit")
    isa.modes = {op: _lj_modebits(r, formats[op]) for op, r in roles.items()}
    return isa


def _lj_modebits(roles, fmt):
    """lj_bc_mode value (ma | mb<<3 | mcd<<7); jit.util.funcbc returns it, which lets the
    test-suite check this table against the real VM.  The metamethod bits (<<11) are not kept."""
    if fmt == "AD":
        ma, mb, mcd = roles[0], "___", roles[1]
    else:
        ma, mb, mcd = roles
    return LJ_MODES.index(ma) | (LJ_MODES.index(mb) << 3) | (LJ_MODES.index(mcd) << 7)


LUAJIT20 = _luajit("luajit2.0", False)
LUAJIT21 = _luajit("luajit2.1", True)

ISAS = {i.key: i for i in (LUA51, LUA52, LUA53, LUA54, LUAJIT20, LUAJIT21)}


# ---------------------------------------------------------------- field codec
def get_field(word, layout, name):
    pos, w = layout[name]
    return (word >> pos) & ((1 << w) - 1)


def set_field(word, layout, name, value):
    pos, w = layout[name]
    mask = ((1 << w) - 1) << pos
    return (word & ~mask) | ((value << pos) & mask)


def decode(isa, word, layout=None, biases=None, op=None):
    """word -> dict of operand values (signed fields already unbiased).  `op` is the
    *standard* opcode, given when the op field holds a custom number."""
    layout = layout or isa.layout
    biases = biases or isa.biases
    if op is None:
        op = get_field(word, layout, "op")
    fmt = isa.formats.get(op, "ABC")
    out = {"op": op}
    for f in FORMAT_FIELDS[fmt]:
        if f == "sBx":
            out[f] = get_field(word, layout, "Bx") - biases["sBx"]
        elif f == "sJ":
            out[f] = get_field(word, layout, "sJ") - biases["sJ"]
        else:
            out[f] = get_field(word, layout, f)
    return out


def encode(isa, fields, layout=None, biases=None, op_value=None):
    layout = layout or isa.layout
    biases = biases or isa.biases
    op = fields["op"]
    fmt = isa.formats.get(op, "ABC")
    w = set_field(0, layout, "op", op if op_value is None else op_value)
    for f in FORMAT_FIELDS[fmt]:
        v = fields[f]
        if f == "sBx":
            w = set_field(w, layout, "Bx", v + biases["sBx"])
        elif f == "sJ":
            w = set_field(w, layout, "sJ", v + biases["sJ"])
        else:
            w = set_field(w, layout, f, v)
    return w


# ---------------------------------------------------------------- range rules
# Extra per-opcode constraints that the reference compilers always satisfy (checked against
# the test corpus of every version).  f(d, ms, pc, n) -> True when the instruction is
# plausible; d = decoded operands, ms = maxstack, pc = index, n = #code.
def _rules_puc(v):
    r = {
        "CALL": lambda d, ms, pc, n: (d["B"] == 0 or d["A"] + d["B"] - 1 < ms) and (d["C"] == 0 or d["A"] + d["C"] - 2 < ms),
        "RETURN": lambda d, ms, pc, n: d["B"] == 0 or d["A"] + d["B"] - 1 <= ms,
        "SELF": lambda d, ms, pc, n: d["A"] + 1 < ms,
        "SETLIST": lambda d, ms, pc, n: d["B"] == 0 or d["A"] + d["B"] < ms,
        "FORLOOP": lambda d, ms, pc, n: d["A"] + 3 < ms,
        "FORPREP": lambda d, ms, pc, n: d["A"] + 3 < ms,
    }
    if v != "5.4":
        r["TAILCALL"] = lambda d, ms, pc, n: d["C"] == 0 and (d["B"] == 0 or d["A"] + d["B"] - 1 < ms)
        r["VARARG"] = lambda d, ms, pc, n: d["B"] == 0 or d["A"] + d["B"] - 2 < ms
        r["CONCAT"] = lambda d, ms, pc, n: d["B"] < d["C"] < ms
    if v == "5.1":
        r["LOADNIL"] = lambda d, ms, pc, n: d["A"] <= d["B"] < ms
        r["TFORLOOP"] = lambda d, ms, pc, n: d["A"] + 2 + d["C"] < ms
    else:
        r["LOADNIL"] = lambda d, ms, pc, n: d["A"] + d["B"] < ms
        r["TFORCALL"] = lambda d, ms, pc, n: d["A"] + 2 + d["C"] < ms
    if v == "5.4":
        r["TAILCALL"] = lambda d, ms, pc, n: d["B"] == 0 or d["A"] + d["B"] - 1 < ms
        r["VARARG"] = lambda d, ms, pc, n: d["C"] == 0 or d["A"] + d["C"] - 2 < ms
        r["CONCAT"] = lambda d, ms, pc, n: d["B"] >= 2 and d["A"] + d["B"] - 1 < ms
        r["RETURN0"] = lambda d, ms, pc, n: d["B"] == 1
        r["RETURN1"] = lambda d, ms, pc, n: d["B"] == 2
        r["VARARGPREP"] = lambda d, ms, pc, n: pc == 0
        r["TFORPREP"] = lambda d, ms, pc, n: d["A"] + 3 < ms
    return r


for _isa in (LUA51, LUA52, LUA53, LUA54):
    _isa.rules = {_isa.index[k]: f for k, f in _rules_puc(_isa.key).items()}
for _isa in (LUAJIT20, LUAJIT21):
    _isa.rules = {}

# opcodes that never occur in a bytecode dump: LuaJIT normalises the JIT/interpreter
# variants back to the base opcode when writing (lj_bcwrite.c) and never stores the
# function header; they still need a number in a full opcode map, but inference skips them.
_LJ_RUNTIME = ("JFORI IFORL JFORL IITERL JITERL ILOOP JLOOP FUNCF IFUNCF JFUNCF FUNCV IFUNCV JFUNCV "
               "FUNCC FUNCCW").split()
for _isa in (LUAJIT20, LUAJIT21):
    _isa.never_dumped = {_isa.index[n] for n in _LJ_RUNTIME}
for _isa in (LUA51, LUA52, LUA53, LUA54):
    _isa.never_dumped = set()
