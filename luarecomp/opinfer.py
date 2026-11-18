# -*- coding: utf-8 -*-
"""Recovering the opcode map of a modified format.

match_ops  -- with known source: compile it with the real VM, align the instruction
              streams (difflib, operands only) and let every aligned instruction vote.
              Tolerates different compiler builds, partial edits and extra functions.
infer_ops  -- without source: use what each opcode does to its operands (register <
              maxstack, constant index in range, string constant, jump target inside the
              function, EQ must be followed by JMP, ...).  Each custom opcode keeps the
              standard opcodes that are consistent with every place it occurs; the
              one-to-one requirement and the sequencing rules are then propagated until
              nothing changes.  Opcodes that behave identically on the operand level (ADD /
              SUB / MUL ...) cannot be told apart this way: they are reported as a group and
              an affine map (custom = std*mul + add) is tested against all constraints,
              which recovers the whole map whenever the game used a simple rotation.

Both work on chunks parsed with raw opcodes (profile header settings must be right).
"""
import collections
import difflib

from . import core
from . import isa as ISA
from .errors import RecompError
from .profile import Profile, standard


def raw_profile(prof):
    """Copy of `prof` that leaves opcode numbers untouched when parsing."""
    p = Profile(dict(prof.raw, opcodes={"type": "identity"}), source=prof.source)
    if prof.custom_layout:
        p.layout, p.biases, p.custom_layout = prof.layout, prof.biases, False
    p.raw_opcodes = True
    p.plugin = prof.plugin
    return p


# ---------------------------------------------------------------- match-ops
def _key_custom(w, prof):
    return w & ~(((1 << prof.layout["op"][1]) - 1) << prof.layout["op"][0])


def _key_std(w, isa, prof):
    if not prof.custom_layout:
        return ISA.set_field(w, isa.layout, "op", 0) if isa.layout["op"] == prof.layout["op"] else \
            _key_custom(ISA.encode(isa, ISA.decode(isa, w), prof.layout, prof.biases, op_value=0), prof)
    return _key_custom(ISA.encode(isa, ISA.decode(isa, w), prof.layout, prof.biases, op_value=0), prof)


def _pair_protos(a, b):
    """Pair children of two prototypes: by position when counts agree, else by line range."""
    ka, kb = a["protos"], b["protos"]
    if len(ka) == len(kb):
        return list(zip(ka, kb))
    def key(f):
        return (f.get("line", f.get("firstline")), f.get("lastline", f.get("numline")))
    idx = {}
    for f in kb:
        idx.setdefault(key(f), []).append(f)
    out = []
    for f in ka:
        lst = idx.get(key(f))
        if lst:
            out.append((f, lst.pop(0)))
    return out


def match_ops(pairs, prof):
    """pairs: [(custom_bytes, standard_bytes_of_same_code)].
    -> dict(votes={std: Counter(custom)}, mapping={std: custom}, conflicts=[...], aligned=int, total=int)"""
    isa = prof.isa
    rp = raw_profile(prof)
    std_prof = standard(prof.lua)
    votes = collections.defaultdict(collections.Counter)
    weak = collections.defaultdict(collections.Counter)
    aligned = total = 0
    for cbytes, sbytes in pairs:
        cch = core.parse(cbytes, rp)
        sch = core.parse(sbytes, std_prof)
        todo = [(cch.root, sch.root)]
        while todo:
            a, b = todo.pop()
            ca, cb = a["code"], b["code"]
            total += len(ca)
            ka = [_key_custom(w, prof) for w in ca]
            kb = [_key_std(w, isa, prof) for w in cb]
            sm = difflib.SequenceMatcher(None, ka, kb, autojunk=False)
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == "equal":
                    target = votes
                    aligned += i2 - i1
                elif tag == "replace" and i2 - i1 == j2 - j1:
                    # same length, different operands: typically registers shifted by an edit;
                    # pair positionally but only as weak evidence
                    target = weak
                else:
                    continue
                for k in range(i2 - i1):
                    c = ISA.get_field(ca[i1 + k], prof.layout, "op")
                    s = ISA.get_field(cb[j1 + k], isa.layout, "op")
                    target[s][c] += 1
            todo.extend(_pair_protos(a, b))
    mapping, conflicts = {}, []
    for s, cnt in votes.items():
        (c, n), *rest = cnt.most_common()
        mapping[s] = c
        # a few stray votes come from operand patterns that align by coincidence around
        # edited code; only a real minority (> 20 %) is a conflict
        if rest and rest[0][1] * 5 > n:
            conflicts.append("%s: custom %d (%d votes) but also %s" % (
                isa.opname(s), c, n, ", ".join("%d (%d)" % x for x in rest[:3])))
    used = set(mapping.values())
    weak_used = {}
    for s, cnt in weak.items():
        if s in mapping:
            continue
        (c, n), *rest = cnt.most_common()
        if c not in used and (not rest or rest[0][1] * 2 < n):
            mapping[s] = c
            used.add(c)
            weak_used[s] = n
    rev = collections.defaultdict(list)
    for s, c in mapping.items():
        rev[c].append(s)
    for c, ss in rev.items():
        if len(ss) > 1:
            conflicts.append("custom %d chosen for several standard opcodes: %s" % (c, ", ".join(isa.opname(s) for s in ss)))
    for s, n in weak_used.items():
        votes[s][mapping[s]] = 0
    return {"votes": votes, "mapping": mapping, "conflicts": conflicts, "aligned": aligned, "total": total,
            "weak": weak_used}


# ---------------------------------------------------------------- infer-ops
class _Ctx:
    __slots__ = ("f", "n", "ms", "nk", "nu", "np", "kstr", "lj")


def _contexts(chunk):
    lj = chunk.isa.family == "luajit"
    for path, f in chunk.walk():
        c = _Ctx()
        c.f, c.n, c.lj = f, len(f["code"]), lj
        if lj:
            c.ms, c.nk, c.nu, c.np = f["framesize"], len(f["kn"]), len(f["uv"]), len(f["kgc"])
            c.kstr = [k[0] for k in reversed(f["kgc"])]          # index by D
        else:
            c.ms, c.nk = f["maxstack"], len(f["K"])
            c.nu = f["nupvals"] if chunk.lua == "5.1" else len(f["upvals"])
            c.np = len(f["protos"])
            c.kstr = [t in (4, 0x14) for t, _ in f["K"]]
        yield path, c


def _ok(isa, c, pc, w, s, strict):
    """Could word `w` at `pc` be standard opcode `s`?  (operand checks only)"""
    if not c.lj and s == isa.index.get("EXTRAARG"):
        if pc == 0:
            return False
        prev = c.f["code"][pc - 1]
        L = isa.layout
        if isa.key == "5.4":
            # after LOADKX (Bx unused), SETLIST with k, or NEWTABLE (always)
            return True
        # after LOADKX (Bx == 0) or SETLIST with C == 0
        return ISA.get_field(prev, L, "Bx") == 0 or ISA.get_field(prev, L, "C") == 0
    d = ISA.decode(isa, w, op=s)
    if c.lj:
        for fld, role in zip(isa.operand_names(s), isa.roles[s]):
            v = d[fld]
            if role in ("dst", "base", "var"):
                if v >= c.ms:
                    return False
            elif role == "rbase":
                if v > c.ms:
                    return False
            elif role == "uv":
                if v >= c.nu:
                    return False
            elif role in ("str", "tab", "func", "cdata"):
                if v >= c.np:
                    return False
                want = {"str": ("str",), "tab": ("tab",), "func": ("child",),
                        "cdata": ("i64", "u64", "complex")}[role]
                if c.kstr[v] not in want:
                    return False
            elif role == "num":
                if v >= c.nk:
                    return False
            elif role == "pri":
                if v > 2:
                    return False
            elif role == "jump":
                t = pc + 1 + v - 0x8000
                if not 0 <= t <= c.n:
                    return False
            elif role == "___" and strict and v:
                return False
        return True
    rule = isa.rules.get(s)
    if rule is not None and not rule(d, c.ms, pc, c.n):
        return False
    kbit = d.get("k", 0)
    for fld, role in zip(isa.operand_names(s), isa.roles[s]):
        v = d[fld]
        if role in ("N", "k"):
            continue
        if role == "-":
            if strict and v:
                return False
        elif role == "R":
            if v >= c.ms:
                return False
        elif role == "Rb":
            if v > c.ms:
                return False
        elif role == "K":
            if v >= c.nk:
                return False
        elif role == "KS":
            if v >= c.nk or not c.kstr[v]:
                return False
        elif role == "RK":
            if (v - 256 >= c.nk) if v >= 256 else (v >= c.ms):
                return False
        elif role == "RKk":
            if (v >= c.nk) if kbit else (v >= c.ms):
                return False
        elif role == "U":
            if v >= c.nu:
                return False
        elif role == "P":
            if v >= c.np:
                return False
        elif role == "01":
            if v > 1:
                return False
        elif role in ("J", "Jb", "Jf", "Jf2"):
            t = {"J": pc + 1 + v, "Jb": pc + 1 - v, "Jf": pc + 1 + v, "Jf2": pc + 2 + v}[role]
            if not 0 <= t <= c.n:
                return False
    return True


def _predecessors(isa):
    """op -> set of ops that must precede it (inverse of the 'must be followed by' rules
    where the follower can only appear in that position)."""
    pre = {}
    n = isa.index
    if "EXTRAARG" in n:
        pre[n["EXTRAARG"]] = {n[x] for x in ("LOADKX", "SETLIST", "NEWTABLE") if x in n}
    if isa.key == "5.4":
        pre[n["MMBIN"]] = {n[x] for x in "ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR".split()}
        pre[n["MMBINI"]] = {n[x] for x in ("ADDI", "SHRI", "SHLI")}
        pre[n["MMBINK"]] = {n[x] for x in "ADDK SUBK MULK MODK POWK DIVK IDIVK BANDK BORK BXORK".split()}
    if isa.key in ("5.2", "5.3", "5.4"):
        pre[n["TFORLOOP"]] = {n["TFORCALL"]}
    return pre


def infer_ops(chunks, prof, strict=True, fixed=None):
    """chunks: list of bytes in the custom format.  fixed: {std: custom} already known
    (e.g. from match_ops).  -> dict with domains, determined, groups, affine, report lines."""
    isa = prof.isa
    rp = raw_profile(prof)
    opw = prof.layout["op"]
    lua51 = isa.key == "5.1"
    funcs = []                     # per function: ctx, [(pc, std-layout word, custom op)], maybe-raw flags
    last_ops, first_vararg = set(), set()
    for data in chunks:
        ch = core.parse(data, rp)
        for path, c in _contexts(ch):
            code = c.f["code"]
            ws, maybe = [], []
            for pc, w in enumerate(code):
                op = ISA.get_field(w, prof.layout, "op")
                sw = _relayout(isa, prof, w) if prof.custom_layout else w
                # Lua 5.1: a word after SETLIST with C == 0 is raw data, not an instruction.
                # Any word after a C == 0 word might be one until SETLIST is ruled out there.
                maybe.append(lua51 and pc > 0 and ISA.get_field(ws[-1][1], isa.layout, "C") == 0)
                ws.append((pc, sw, op))
            if code:
                last_ops.add(ws[-1][2])
                if isa.key == "5.4" and c.f.get("vararg"):
                    first_vararg.add(ws[0][2])
            funcs.append((c, ws, maybe))
    if not funcs or not any(ws for _, ws, _ in funcs):
        raise RecompError("no instructions in the samples")
    pre = _predecessors(isa)
    setlist = isa.index.get("SETLIST")
    while True:
        instances = collections.defaultdict(list)       # custom -> [(ctx, pc, word)]
        pairs = set()
        for c, ws, maybe in funcs:
            for k, (pc, sw, op) in enumerate(ws):
                if maybe[k]:
                    continue
                instances[op].append((c, pc, sw))
                if k + 1 < len(ws) and not maybe[k + 1]:
                    pairs.add((op, ws[k + 1][2]))
        domains = {}
        for c_op, lst in instances.items():
            cand = set(range(isa.num)) - isa.never_dumped
            for ctx, pc, w in lst:
                cand = {s for s in cand if _ok(isa, ctx, pc, w, s, strict)}
                if not cand:
                    break
            domains[c_op] = cand
        for c_op in last_ops:
            if c_op in domains:
                domains[c_op] &= set(isa.returns)
        for c_op in first_vararg:
            domains[c_op] &= {isa.index["VARARGPREP"]}
        for s, c_op in (fixed or {}).items():
            for k in domains:
                domains[k].discard(s)
            if c_op in domains:
                domains[c_op] = {s}
        _propagate(domains, pairs, isa.successors, pre)
        if not lua51:
            break
        # words whose predecessor cannot be SETLIST are instructions after all
        progress = False
        for c, ws, maybe in funcs:
            for k in range(1, len(ws)):
                if maybe[k] and not maybe[k - 1] and setlist not in domains.get(ws[k - 1][2], {setlist}):
                    maybe[k] = False
                    progress = True
        if not progress:
            break
    determined = {c: next(iter(d)) for c, d in domains.items() if len(d) == 1}
    empty = sorted(c for c, d in domains.items() if not d)
    groups = collections.defaultdict(list)
    for c, d in domains.items():
        if len(d) > 1:
            groups[frozenset(d)].append(c)
    affine = _affine(domains, isa.num, 1 << opw[1])
    rep = []
    rep.append("%d distinct custom opcodes in %d sample(s); %d determined, %d undetermined, %d impossible"
               % (len(domains), len(chunks), len(determined), sum(len(v) for v in groups.values()), len(empty)))
    for c in sorted(determined, key=lambda c: determined[c]):
        rep.append("  %-10s std %2d -> custom %3d   (%d occurrences)" % (
            isa.opname(determined[c]), determined[c], c, len(instances[c])))
    for d, cs in sorted(groups.items(), key=lambda x: len(x[0])):
        rep.append("  ambiguous: custom %s  is one of  %s" % (
            sorted(cs), " ".join(isa.opname(s) for s in sorted(d))))
    if empty:
        rep.append("  IMPOSSIBLE: custom %s fit no standard opcode -- the header/layout settings are wrong, the "
                   "samples were not produced by a stock compiler (try --loose), or the VM is not %s"
                   % (empty, isa.key))
    unseen = [isa.opname(s) for s in range(isa.num)
              if s not in isa.never_dumped and not any(s in d for d in domains.values())]
    if unseen:
        rep.append("  never observed: %s" % " ".join(unseen))
    if affine:
        rep.append("affine maps consistent with every constraint: %s" % ", ".join(
            '{"type": "affine", "mul": %d, "add": %d, "mod": %d}' % a for a in affine[:5]))
        if len(affine) == 1:
            rep.append("=> unique: the full opcode map is recovered")
    else:
        rep.append("no affine map fits; resolve the ambiguous groups with match-ops on a chunk whose "
                   "source you know, then write a \"table\" or \"names\" map")
    return {"domains": domains, "determined": determined, "groups": dict(groups), "empty": empty,
            "affine": affine, "report": rep, "instances": {c: len(v) for c, v in instances.items()}}


def _relayout(isa, prof, w):
    c = ISA.get_field(w, prof.layout, "op")
    fields = {}
    for f in ("A", "B", "C", "k", "Bx", "Ax", "sJ", "D"):
        if f in prof.layout:
            fields[f] = ISA.get_field(w, prof.layout, f)
    out = ISA.set_field(0, isa.layout, "op", c)
    # small fields first, composite ones are implied by them in the standard layout
    for f in ("A", "B", "C", "k"):
        if f in fields and f in isa.layout:
            out = ISA.set_field(out, isa.layout, f, fields[f])
    return out


def _propagate(domains, pairs, succ, pre):
    """AC-3 style propagation of the sequencing rules plus all-different filtering."""
    changed = True
    while changed:
        changed = False
        for a, b in pairs:
            if a not in domains or b not in domains:
                continue
            da, db = domains[a], domains[b]
            # value s of a needs some value t of b allowed after s (and t allows s before it)
            keep_a = {s for s in da if any(_pair_ok(s, t, succ, pre) for t in db)}
            keep_b = {t for t in db if any(_pair_ok(s, t, succ, pre) for s in keep_a)}
            if keep_a != da or keep_b != db:
                domains[a], domains[b] = keep_a, keep_b
                changed = True
        if _alldiff(domains):
            changed = True


def _pair_ok(s, t, succ, pre):
    if s in succ and t not in succ[s]:
        return False
    if t in pre and s not in pre[t]:
        return False
    return True


def _alldiff(domains):
    """Remove values that cannot be part of any one-to-one assignment (Regin's filter:
    an edge survives if it is matched, lies on an alternating cycle, or is reachable by an
    alternating path from a free value)."""
    keys = [k for k in domains if domains[k]]
    match_v = {}
    for k in keys:
        if not _augment(k, domains, match_v, set()):
            return False          # no complete assignment at all: leave domains alone
    match_k = {k: v for v, k in match_v.items()}
    # directed graph: matched var->value, unmatched value->var
    graph = collections.defaultdict(list)
    for k in keys:
        for v in domains[k]:
            if match_k[k] == v:
                graph[("k", k)].append(("v", v))
            else:
                graph[("v", v)].append(("k", k))
    values = {v for k in keys for v in domains[k]}
    reach = set()
    stack = [("v", v) for v in values if v not in match_v]
    while stack:
        n = stack.pop()
        if n in reach:
            continue
        reach.add(n)
        stack.extend(graph[n])
    comp = _scc(graph)
    changed = False
    for k in keys:
        for v in list(domains[k]):
            if match_k[k] == v:
                continue
            if ("v", v) in reach or comp.get(("v", v)) == comp.get(("k", k)):
                continue
            domains[k].discard(v)
            changed = True
    return changed


def _augment(k, domains, match_v, seen):
    for v in domains[k]:
        if v in seen:
            continue
        seen.add(v)
        owner = match_v.get(v)
        if owner is None or _augment(owner, domains, match_v, seen):
            match_v[v] = k
            return True
    return False


def _scc(graph):
    """Tarjan (iterative) -> node -> component id."""
    index, low, comp, stack, on = {}, {}, {}, [], set()
    counter = [0]
    nodes = set(graph)
    for vs in graph.values():
        nodes.update(vs)
    for root in nodes:
        if root in index:
            continue
        work = [(root, 0)]
        while work:
            node, i = work.pop()
            if i == 0:
                index[node] = low[node] = counter[0]
                counter[0] += 1
                stack.append(node)
                on.add(node)
            edges = graph.get(node, [])
            if i < len(edges):
                work.append((node, i + 1))
                nxt = edges[i]
                if nxt not in index:
                    work.append((nxt, 0))
                elif nxt in on:
                    low[node] = min(low[node], index[nxt])
                continue
            if low[node] == index[node]:
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp[w] = node
                    if w == node:
                        break
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return comp


def _affine(domains, n, opspace):
    out = []
    obs = [(c, d) for c, d in domains.items()]
    for mod in sorted({n, opspace}):
        for mul in range(1, mod):
            if _gcd(mul, mod) != 1:
                continue
            for add in range(mod):
                ok = True
                for c, d in obs:
                    # custom c must equal (s*mul + add) % mod for some s in d
                    if not any((s * mul + add) % mod == c for s in d):
                        ok = False
                        break
                if ok:
                    fwd = [(s * mul + add) % mod for s in range(n)]
                    if len(set(fwd)) == n:
                        out.append((mul, add, mod))
            if len(out) > 20:
                return out
    return out


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a
