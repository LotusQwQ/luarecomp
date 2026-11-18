# -*- coding: utf-8 -*-
"""Header / layout detection for unknown chunks (`inspect`).

Instead of guessing what the size bytes mean, every plausible header arrangement is
tried: each candidate profile must parse *all* given samples to the last byte.  The
survivors are then grouped by behaviour -- two candidates are equivalent when they
convert every sample to identical standard bytecode.  One group means the answer is
certain (names may differ only cosmetically); several groups mean the samples cannot
tell the arrangements apart, and the report says which setting is undetermined and
what kind of sample would decide it.

Opcode numbers are not needed for parsing, so candidates are tried with raw opcodes.
"""
import itertools
import struct

from . import core
from .errors import FormatError, RecompError
from .profile import STD_LUAC_DATA, Profile

PUC_SIZE_NAMES = {
    "5.1": ("int", "size_t", "instruction", "number"),
    "5.2": ("int", "size_t", "instruction", "number"),
    "5.3": ("int", "size_t", "instruction", "integer", "number"),
    "5.4": ("instruction", "integer", "number"),
}


class Candidate:
    def __init__(self, d, why):
        self.d, self.why = d, why
        self.ok = False
        self.error = None
        self.reached = 0
        self.deep = False         # got through at least one function's code before failing
        self.std = None

    def profile(self):
        p = Profile(dict(self.d))
        p.raw_opcodes = True
        return p


def _try(cand, samples):
    try:
        prof = cand.profile()
    except RecompError as exc:
        cand.error = exc
        return False
    outs = []
    for data in samples:
        try:
            ch = core.parse(data, prof)
            if core.dump(ch, prof) != data:
                cand.error = FormatError("parses but does not round-trip byte-exactly")
                cand.reached = len(data)
                return False
            outs.append(core.dump(ch, _raw_std(prof.lua)))
        except FormatError as exc:
            cand.error = exc
            cand.reached = max(cand.reached, exc.offset or 0)
            cand.deep = any(t[2] in ("code", "proto") for t in exc.trail)
            return False
    # Writing must agree too: two arrangements can read the samples identically yet encode
    # other code differently (e.g. size_t only shows up in strings of 254+ bytes).
    probe = _probe(prof.lua)
    if probe is not None:
        try:
            outs.append(core.dump(probe, prof))
        except FormatError as exc:
            outs.append(b"error: %s" % str(exc).encode())
    cand.ok = True
    cand.std = tuple(outs)
    return True


_PROBE_SRC = (b"local s = '" + b"L" * 300 + b"' local i, f = 123456789, 0.1 "
              b"local function g(...) return s, i, f, ... end return g(true, nil)")
_PROBES = {}


def _probe(lua):
    """A standard chunk with long strings and numeric constants, parsed (raw opcodes)."""
    if lua.startswith("luajit"):
        return None
    if lua not in _PROBES:
        from . import runtime
        _PROBES[lua] = core.parse(runtime.compile_std(_PROBE_SRC, lua, b"=probe"), _raw_std(lua))
    return _PROBES[lua]


_RAW_STD = {}


def _raw_std(lua):
    if lua not in _RAW_STD:
        p = Profile({"lua": lua})
        p.raw_opcodes = True
        _RAW_STD[lua] = p
    return _RAW_STD[lua]


# ---------------------------------------------------------------- candidate generation
def _puc_candidates(data):
    out = []
    for k in range(1, 13):
        if k + 2 >= len(data):
            break
        ver = data[k]
        if not 0x51 <= ver <= 0x54:
            continue
        lua = "5.%d" % (ver - 0x50)
        base = {"name": "draft", "lua": lua, "signature": data[:k].hex(), "version": ver, "format": data[k + 1]}
        i0 = k + 2
        names = PUC_SIZE_NAMES[lua]
        if lua in ("5.1", "5.2"):
            if data[i0] not in (0, 1):
                continue
            endian = "little" if data[i0] == 1 else "big"
            i = i0 + 1
            for m in range(len(names), -1, -1):
                vals = list(data[i:i + m])
                if len(vals) < m or any(x not in (4, 8) for x in vals):
                    continue
                for combo in itertools.combinations(names, m):
                    d = dict(base, endian=endian, sizes=[[n, x] for n, x in zip(combo, vals)])
                    j = i + m
                    integral = data[j] if j < len(data) else None
                    if integral in (0, 1):
                        d["integral"] = integral
                        if lua == "5.2":
                            tail = data[j + 1:j + 7]
                            d["luac_data"] = tail.hex() if tail == STD_LUAC_DATA else ""
                            if tail != STD_LUAC_DATA:
                                d2 = dict(d, luac_data=tail.hex())
                                out.append(Candidate(d2, "5.2 with non-standard LUAC_TAIL"))
                        out.append(Candidate(d, "size bytes %s" % ", ".join(combo)))
            continue
        # 5.3 / 5.4
        variants = []
        if data[i0:i0 + 6] == STD_LUAC_DATA:
            variants.append((STD_LUAC_DATA.hex(), i0 + 6))
        else:
            variants.append(("", i0))
            variants.append((data[i0:i0 + 6].hex(), i0 + 6))
        for ld, i in variants:
            for m in range(len(names), -1, -1):
                vals = list(data[i:i + m])
                if len(vals) < m or any(x not in (4, 8) for x in vals):
                    continue
                for combo in itertools.combinations(names, m):
                    sizes = dict(zip(combo, vals))
                    isz, nsz = sizes.get("integer", 8), sizes.get("number", 8)
                    j = i + m
                    for endian, e in (("little", "<"), ("big", ">")):
                        try:
                            li = struct.unpack_from(e + {4: "i", 8: "q"}[isz], data, j)[0]
                            ln = struct.unpack_from(e + {4: "f", 8: "d"}[nsz], data, j + isz)[0]
                        except struct.error:
                            continue
                        if li != 0x5678 or abs(ln - 370.5) > 1e-6:
                            continue
                        d = dict(base, endian=endian, luac_data=ld, sizes=[[n, x] for n, x in zip(combo, vals)])
                        out.append(Candidate(d, "size bytes %s" % (", ".join(combo) or "none")))
    return out


def _luajit_candidates(data):
    out = []
    for k in range(1, 9):
        if k + 2 > len(data):
            break
        ver = data[k]
        if ver not in (1, 2):
            continue
        flags = data[k + 1]
        if flags & ~0xF or (ver == 1 and flags & 8):
            continue
        lua = "luajit2.0" if ver == 1 else "luajit2.1"
        out.append(Candidate({"name": "draft", "lua": lua, "signature": data[:k].hex(), "version": ver},
                             "LuaJIT %s dump, flags %#x" % (lua[6:], flags)))
    return out


# ---------------------------------------------------------------- analysis
def _effective(d):
    """Settings that change how bytes are read, for explaining ambiguity."""
    p = Profile(dict(d))
    if p.family == "luajit":
        return {"lua": p.lua}
    out = {"lua": p.lua, "endian": p.endian_name, "luac_data": p.luac_data.hex()}
    out.update({"size." + k: v for k, v in p.sizes.items()})
    return out


def inspect(samples):
    """samples: list of bytes (several chunks from the same game give a better answer).
    -> dict(report=[lines], profile=draft dict or None, groups=[[Candidate]], best_failure=Candidate)"""
    if not samples:
        raise RecompError("no samples")
    samples = sorted(samples, key=len)
    first = samples[0]
    common = first
    for s in samples[1:]:
        n = 0
        while n < min(len(common), len(s)) and common[n] == s[n]:
            n += 1
        common = common[:n]
    rep = []
    cands = _luajit_candidates(first) + _puc_candidates(first)
    # signature must be shared by every sample
    cands = [c for c in cands if all(s.startswith(bytes.fromhex(c.d["signature"])) for s in samples)]
    if not cands:
        rep.append("no Lua 5.1-5.4 / LuaJIT header pattern found in the first bytes: %s" % first[:16].hex())
        rep.append("the file is probably encrypted or compressed (outer layer not handled by this tool), "
                   "or the header is modified beyond what inspect tries -- write the \"header\" list by hand")
        return {"report": rep, "profile": None, "groups": [], "best_failure": None}
    passed = [c for c in cands if _try(c, samples)]
    deep = [c for c in cands if c.deep]
    best = max(deep, key=lambda c: c.reached) if deep else None
    if not passed and best is None:
        rep.append("header-like bytes found, but no arrangement gets through even one function: %s"
                   % first[:16].hex())
        rep.append("the file is probably encrypted or compressed (outer layer not handled by this tool), "
                   "or the header is modified beyond what inspect tries -- write the \"header\" list by hand")
        return {"report": rep, "profile": None, "groups": [], "best_failure": best}
    if not passed:
        rep.append("%d header arrangements tried, none parses every sample." % len(cands))
        rep.append("closest: %s (%s), failed at byte %d:" % (best.d["lua"], best.why, best.reached))
        err = best.error
        rep.append("  " + (err.report(samples[0]) if isinstance(err, FormatError) else str(err)).replace("\n", "\n  "))
        rep.append("the function layout is probably modified too: compare the field trail above with the "
                   "standard layout and describe the difference with \"function\" / \"encoding\" / \"const_tags\"")
        return {"report": rep, "profile": best.d, "groups": [], "best_failure": best}
    groups = {}
    for c in passed:
        groups.setdefault(c.std, []).append(c)
    groups = list(groups.values())
    lua = passed[0].d["lua"]
    rep.append("format: %s, signature %s, %d sample(s), %d arrangement(s) parse every sample"
               % (lua, passed[0].d["signature"], len(samples), len(passed)))
    if len(groups) == 1:
        g = groups[0]
        rep.append("result is UNAMBIGUOUS: all surviving arrangements convert the samples, and a probe chunk "
                   "with long strings and numbers, identically")
        if len(g) > 1:
            rep.append("  (%d of them differ only in what the size bytes are called, which does not "
                       "change the output: %s)" % (len(g), "; ".join(c.why for c in g)))
    else:
        rep.append("result is AMBIGUOUS: %d groups of arrangements fit the samples but would convert other "
                   "code differently:" % len(groups))
        effs = [_effective(g[0].d) for g in groups]
        keys = sorted({k for e in effs for k in e if len({str(x.get(k)) for x in effs}) > 1})
        for g, e in zip(groups, effs):
            rep.append("  - %s  (%d arrangement(s), e.g. %s)" % (", ".join("%s=%s" % (k, e.get(k)) for k in keys),
                                                                 len(g), g[0].why))
        rep.append("  " + _ambiguity_hint(keys))
    best = groups[0][0]
    if len(groups) > 1:
        # prefer the arrangement closest to the standard one
        std_names = [n for n, _ in Profile({"lua": lua}).size_fields] if passed[0].d["lua"][0] == "5" else []
        best = max(passed, key=lambda c: sum(1 for n, _ in c.d.get("sizes", []) if n in std_names))
    d = dict(best.d)
    d["opcodes"] = {"type": "identity"}
    rep.append("opcode numbers cannot be read from the header: run `infer-ops` (no source needed) "
               "or `match-ops` (with known source), then `check`")
    return {"report": rep, "profile": d, "groups": groups, "best_failure": None}


def _ambiguity_hint(keys):
    hints = []
    if "size.size_t" in keys:
        hints.append("size_t only matters for strings of 254+ bytes (and Lua 5.1/5.2 strings): add a sample "
                     "that contains a long string constant")
    if "size.integer" in keys or "size.number" in keys:
        hints.append("integer/number sizes only matter for numeric constants: add a sample with integer and "
                     "float constants")
    if "endian" in keys:
        hints.append("endianness is decided by multi-byte fields: add a larger sample")
    if not hints:
        hints.append("add more, and more varied, samples")
    return "to decide: " + "; ".join(hints)
