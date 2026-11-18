# -*- coding: utf-8 -*-
"""`check` with diagnostics: why does a profile not fit a chunk, and where.

Three layers, each one only runs when the previous one passed:
  1. parse      -> FormatError with offset, structural path, field, field trail, hex dump
  2. round trip -> first differing byte, which field it belongs to in the original
                   (reader trace) and which field produced it in the rewrite (writer trace)
  3. semantics  -> static verifier on the converted code + load in the real VM; violations
                   are grouped per opcode so a wrong opcode-map entry stands out
"""
from . import core, runtime, verify
from .errors import FormatError, RecompError, hexdump
from .profile import standard


class CheckResult:
    def __init__(self, name):
        self.name = name
        self.stage = None          # "parse" | "round-trip" | "verify" | "load" | None (ok)
        self.ok = False
        self.lines = []
        self.issues = []
        self.data = {}

    def as_dict(self):
        return {"name": self.name, "ok": self.ok, "stage": self.stage, "details": self.lines, **self.data}


def _span_at(spans, off):
    best = None
    for s, e, path, field in spans or []:
        if s <= off < e and (best is None or e - s < best[1] - best[0]):
            best = (s, e, path, field)
    return best


def check(data, prof, name="chunk", verbose=True, run_verify=True):
    r = CheckResult(name)
    try:
        ch = core.parse(data, prof, trace=True)
    except FormatError as exc:
        r.stage = "parse"
        r.lines.append("parse failed: " + str(exc))
        if verbose:
            r.lines += exc.report(data).splitlines()[1:]
        r.data.update(offset=exc.offset, path=exc.path, field=exc.field)
        return r
    except RecompError as exc:
        r.stage = "parse"
        r.lines.append("parse failed: %s" % exc)
        return r
    try:
        out, wspans = core.dump(ch, prof, trace=True)
    except FormatError as exc:
        r.stage = "round-trip"
        r.lines.append("could not write the chunk back: %s" % exc)
        return r
    if out != data:
        r.stage = "round-trip"
        n = min(len(out), len(data))
        off = next((i for i in range(n) if out[i] != data[i]), n)
        r.lines.append("round trip differs: first difference at offset %d (0x%x); original %d bytes, "
                       "rewritten %d bytes" % (off, off, len(data), len(out)))
        a = _span_at(getattr(ch, "spans", None), off)
        b = _span_at(wspans, off)
        if a:
            r.lines.append("  in the original this byte belongs to %s %s (bytes %d..%d)" % (a[2], a[3], a[0], a[1]))
        if b:
            r.lines.append("  in the rewrite it was produced by %s %s (bytes %d..%d)" % (b[2], b[3], b[0], b[1]))
        r.lines.append("  hint: the reader accepted something the writer encodes differently -- a non-minimal "
                       "varint/uleb, a long-string length that fits in one byte, extra padding, or a "
                       "section the profile does not describe; describe it with \"keep\" items")
        if verbose:
            r.lines.append("  original:")
            r.lines += ["    " + l for l in hexdump(data, off, 24)]
            r.lines.append("  rewritten:")
            r.lines += ["    " + l for l in hexdump(out, off, 24)]
        r.data.update(offset=off, original_field=a and a[3], path=a and a[2])
        return r
    if run_verify:
        issues = [i for i in verify.verify(ch) if i.severity == verify.ERROR]
        if issues:
            r.stage = "verify"
            r.issues = issues
            r.lines.append("parses and round-trips, but %d instruction(s) are impossible for a %s compiler:"
                           % (len(issues), prof.lua))
            r.lines += ["  " + l for l in verify.summarize(issues, prof)]
            n_code = sum(len(f["code"]) for _, f in ch.walk())
            if len(issues) <= 3 and len(issues) * 1000 < n_code:
                r.lines.append("  hint: only %d bad instruction(s) among %d -- more likely corrupted or hand-made "
                               "bytecode at that spot than a wrong profile (a wrong opcode map breaks "
                               "thousands)" % (len(issues), n_code))
            else:
                r.lines.append("  hint: the opcode map (or the instruction layout) is wrong for the opcodes listed "
                               "first; `infer-ops` on these chunks shows which numbers fit")
            r.data.update(violations=len(issues))
    std = core.dump(ch, standard(prof.lua))
    ok, err = runtime.load_check(std, prof.lua)
    if not ok:
        r.stage = r.stage or "load"
        r.lines.append("the real %s VM refuses the converted chunk: %s" % (prof.lua, err))
        return r
    if r.stage is None:
        r.ok = True
        n_fn = sum(1 for _ in ch.walk())
        r.lines.append("ok: parse, byte-exact round trip, verifier clean, loads in real %s (%d functions)"
                       % (prof.lua, n_fn))
    return r
