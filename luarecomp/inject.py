# -*- coding: utf-8 -*-
"""Running extra code at the start of an existing chunk ("prologue injection").

The new code is compiled as its own chunk and attached as a *child* of the main function;
two instructions at the start of the main function create and call it:

    PUC   CLOSURE R0 k ; CALL R0 1 1          (5.4: after VARARGPREP)
    JIT   FNEW 0 k     ; CALL 0 1 1

The child shares the main chunk's environment (_ENV upvalue for 5.2+, inherited function
environment for 5.1 / LuaJIT).  Lua jumps are relative and the child is appended so that
existing CLOSURE / FNEW indexes do not move, hence the original code is left byte-for-byte
unchanged after the two new instructions.

What is guaranteed, and checked by `verify_injection` (also run by `inject` itself):
  * every original instruction, constant and child function is unchanged, in order
  * the result passes the static verifier and loads in the real VM
  * a chunk that was already injected is refused (unless force=True)
  * with isolate=True the injected code runs under pcall, so its errors cannot stop the
    original chunk
Not guaranteed: what your code does at run time in the real host (engine objects, load
order); `dry_run` executes both chunks in a stub environment to catch the obvious cases.
Line and local-variable debug info of the main function is shifted, so error messages from
the original code keep their line numbers.
"""
from . import core, runtime, verify
from . import isa as ISA
from .errors import RecompError, VerifyError
from .profile import standard
from .puc import Chunk


class InjectError(RecompError):
    pass


MARK = b"luarecomp-inject"     # chunk name given to injected children (detects double injection)


def compile_child(src, lua, isolate=False, on_error=None, chunkname=None):
    """Compile `src` for injection.  isolate=True wraps it in pcall; on_error is Lua code
    run with the error in `err` when the injected code fails."""
    if isinstance(src, str):
        src = src.encode("utf-8")
    if isolate:
        handler = on_error.encode() if isinstance(on_error, str) else (on_error or b"")
        src = (b"local __ok, err = pcall(function() " + src + b"\nend) if not __ok then " + handler + b" end")
    name = chunkname or (b"=" + MARK)
    return core.compile_chunk(src, lua, name)


def _puc_marker(f, isa, lua):
    """Index where the prologue would start, and whether a prologue is already there."""
    start = 1 if lua == "5.4" and f["code"] and \
        ISA.get_field(f["code"][0], isa.layout, "op") == isa.index["VARARGPREP"] else 0
    code = f["code"]
    if len(code) >= start + 2 and f["protos"]:
        a = ISA.decode(isa, code[start])
        b = ISA.decode(isa, code[start + 1])
        if (a["op"] == isa.index["CLOSURE"] and a["A"] == 0 and a["Bx"] == len(f["protos"]) - 1
                and b["op"] == isa.index["CALL"] and b["A"] == 0 and b["B"] == 1 and b["C"] == 1):
            return start, True
    return start, False


def _lines54(f):
    """Lua 5.4 relative line info -> absolute line per instruction."""
    absd = dict(f.get("abslines") or [])
    out, line = [], f["line"]
    for pc, d in enumerate(f["lines"]):
        if d == -0x80:
            line = absd[pc]
        else:
            line += d
        out.append(line)
    return out


def _encode54(f, lines):
    """Absolute lines -> (lineinfo, abslineinfo) exactly as lcode.c:savelineinfo builds them."""
    rel, absl = [], []
    prev, iwthabs = f["line"], 0
    for pc, line in enumerate(lines):
        dif = line - prev
        if abs(dif) >= 0x80 or iwthabs >= 128:
            absl.append((pc, line))
            dif = -0x80
            iwthabs = 1
        else:
            iwthabs += 1
        rel.append(dif)
        prev = line
    return rel, absl


def inject(chunk, child, force=False, check=True):
    """Return a new Chunk running `child` (a Chunk, see compile_child) before `chunk`."""
    if chunk.lua != child.lua:
        raise InjectError("chunk is %s but the injected code was compiled for %s" % (chunk.lua, child.lua))
    if chunk.lua.startswith("luajit"):
        out = _inject_lj(chunk, child, force)
    else:
        out = _inject_puc(chunk, child, force)
    if check:
        verify_injection(chunk, out)
    return out


def _inject_puc(chunk, child, force):
    isa, lua = chunk.isa, chunk.lua
    root = chunk.root
    croot = dict(child.root)
    if root["nparams"] != 0:
        raise InjectError("the main function has %d fixed parameters; only main chunks can be injected"
                          % root["nparams"])
    start, already = _puc_marker(root, isa, lua)
    if already and not force:
        raise InjectError("this chunk already starts with an injected prologue (pass force=True / --force "
                          "to add another one)")
    if lua == "5.1":
        if croot.get("nupvals"):
            raise InjectError("injected 5.1 code must not have upvalues")
    else:
        if len(croot["upvals"]) != 1:
            raise InjectError("injected code must be a plain chunk (exactly one upvalue, _ENV); got %d"
                              % len(croot["upvals"]))
        names = root.get("upnames") or []
        if b"_ENV" in names:
            env = names.index(b"_ENV")
        elif len(root["upvals"]) == 1:
            env = 0                   # stripped main chunk: its only upvalue is _ENV
        else:
            raise InjectError("cannot tell which upvalue of the main function is _ENV (stripped debug "
                              "info and %d upvalues)" % len(root["upvals"]))
        u = (0, env, 0) if lua == "5.4" else (0, env)
        croot["upvals"] = [u]
        croot["upnames"] = [b"_ENV"] if croot.get("upnames") else []
    k = len(root["protos"])
    closure = ISA.encode(isa, {"op": isa.index["CLOSURE"], "A": 0, "Bx": k})
    callf = {"op": isa.index["CALL"], "A": 0, "B": 1, "C": 1}
    if lua == "5.4":
        callf["k"] = 0
    call = ISA.encode(isa, callf)
    q = dict(root)
    q["protos"] = list(root["protos"]) + [croot]
    q["code"] = root["code"][:start] + [closure, call] + root["code"][start:]
    q["maxstack"] = max(root["maxstack"], 2)
    q["locvars"] = [(n, s + 2 if s >= start else s, e + 2 if e > start else e) for n, s, e in root["locvars"]]
    if root["lines"]:
        if lua == "5.4":
            absl = _lines54(root)
            line = absl[start] if start < len(absl) else (absl[-1] if absl else root["line"])
            new = absl[:start] + [line, line] + absl[start:]
            q["lines"], q["abslines"] = _encode54(root, new)
        else:
            line = root["lines"][start] if start < len(root["lines"]) else root["lines"][-1]
            q["lines"] = root["lines"][:start] + [line, line] + root["lines"][start:]
    return Chunk(lua, q, chunk.nupvals, chunk.keep)


def _inject_lj(chunk, child, force):
    isa = chunk.isa
    root = chunk.root
    code = root["code"]
    kgc = root["kgc"]
    if len(code) >= 2 and kgc and kgc[0][0] == "child":
        a, b = ISA.decode(isa, code[0]), ISA.decode(isa, code[1])
        if (a["op"] == isa.index["FNEW"] and a["A"] == 0 and a["D"] == len(kgc) - 1
                and b["op"] == isa.index["CALL"] and b["A"] == 0 and b["B"] == 1 and b["C"] == 1):
            if not force:
                raise InjectError("this chunk already starts with an injected prologue (pass force=True / "
                                  "--force to add another one)")
    if root["nparams"] != 0:
        raise InjectError("the main function has fixed parameters; only main chunks can be injected")
    if any(p["uv"] for p in [child.root]):
        raise InjectError("injected code must not have upvalues")
    q = dict(root)
    # new GC constant goes to the *front* of the file order: it gets the highest index
    # D = sizekgc-1, and existing D values (counted from the end) do not change
    q["kgc"] = [("child",)] + list(kgc)
    q["flags"] = root["flags"] | 0x01          # PROTO_CHILD
    d = len(q["kgc"]) - 1
    fnew = ISA.encode(isa, {"op": isa.index["FNEW"], "A": 0, "D": d})
    call = ISA.encode(isa, {"op": isa.index["CALL"], "A": 0, "B": 1, "C": 1})
    q["code"] = [fnew, call] + list(code)
    q["framesize"] = max(root["framesize"], 3)
    if q.get("debug"):
        q["debug"] = _shift_lj_debug(root, 2, chunk.endian)
    # the child's prototypes must be read right before the main one (it is popped first)
    protos = list(chunk.protos[:-1]) + list(child.protos) + [q]
    out = Chunk(chunk.lua, None, None, flags=chunk.flags, chunkname=chunk.chunkname, protos=protos,
                endian=chunk.endian)
    from .luajit import _tree
    out.root = _tree(out)
    return out


def _shift_lj_debug(pt, k, endian):
    """Insert `k` instructions at the start of a LuaJIT prototype's debug blob.

    Blob = lineinfo (one entry per instruction, 1/2/4 bytes depending on numline, relative to
    firstline) + upvalue names (NUL-terminated) + varinfo (name, uleb startpc delta, uleb length;
    startpc deltas are relative to the previous entry, so only the first one moves)."""
    dbg, n = pt["debug"], len(pt["code"])
    w = 1 if pt["numline"] < 256 else 2 if pt["numline"] < 65536 else 4
    li, rest = dbg[:w * n], dbg[w * n:]
    first = li[:w] if li else bytes(w)
    p = 0
    for _ in range(len(pt["uv"])):
        p = rest.index(b"\0", p) + 1
    uvinfo, varinfo = rest[:p], rest[p:]
    if varinfo and varinfo[0] != 0:
        q = 1 if varinfo[0] < 7 else varinfo.index(b"\0") + 1      # VARNAME_* codes are < 7
        v, sh, j = 0, 0, q
        while True:
            b = varinfo[j]
            v |= (b & 0x7F) << sh
            sh += 7
            j += 1
            if b < 0x80:
                break
        enc = bytearray()
        v += k
        while True:
            b, v = v & 0x7F, v >> 7
            enc.append(b | 0x80 if v else b)
            if not v:
                break
        varinfo = varinfo[:q] + bytes(enc) + varinfo[j:]
    return first * k + li + uvinfo + varinfo


def verify_injection(orig, new):
    """Raise VerifyError unless `new` is `orig` plus exactly one prologue.  -> list of checks passed."""
    done = []
    isa = orig.isa
    if orig.lua.startswith("luajit"):
        o, n = orig.root, new.root
        if n["code"][2:] != o["code"]:
            raise VerifyError("original main-function instructions changed")
        if n["kgc"][1:] != o["kgc"] or n["kn"] != o["kn"] or n["uv"] != o["uv"]:
            raise VerifyError("original constants changed")
        old_kids = [p for p in orig.protos[:-1]]
        if new.protos[:len(old_kids)] != old_kids:
            raise VerifyError("original child functions changed or moved")
    else:
        o, n = orig.root, new.root
        start, _ = _puc_marker(o, isa, orig.lua)
        if n["code"][:start] + n["code"][start + 2:] != o["code"]:
            raise VerifyError("original main-function instructions changed")
        if n["K"] != o["K"] or n["upvals"] != o["upvals"]:
            raise VerifyError("original constants or upvalues changed")
        if n["protos"][:-1] != o["protos"]:
            raise VerifyError("original child functions changed or moved")
    done.append("original instructions, constants and child functions unchanged")
    errs = [i for i in verify.verify(new) if i.severity == verify.ERROR]
    if errs:
        raise VerifyError("static verification failed: %s" % "; ".join(str(e) for e in errs[:5]))
    done.append("static verifier: no errors")
    std = core.dump(new, standard(new.lua))
    ok, err = runtime.load_check(std, new.lua)
    if not ok:
        raise VerifyError("the real %s VM rejects the result: %s" % (new.lua, err))
    done.append("loads in the real %s VM" % new.lua)
    return done


def dry_run(orig, new, env_setup=None):
    """Run both chunks (standard form) in a stub environment and compare the results.
    -> (same, original results or error, patched results or error)"""
    def plain(v):
        if v is None or isinstance(v, (bool, int, float, bytes, str)):
            return v
        return "<%s>" % type(v).__name__        # tables / functions differ by identity

    def go(ch):
        try:
            return True, [plain(v) for v in runtime.run(core.dump(ch, standard(ch.lua)), ch.lua, env_setup)]
        except Exception as exc:  # noqa: BLE001 - report whatever the chunk raised
            return False, "%s: %s" % (type(exc).__name__, exc)
    a, b = go(orig), go(new)
    return a == b, a, b
