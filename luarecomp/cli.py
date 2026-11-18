# -*- coding: utf-8 -*-
"""Command line interface:  python -m luarecomp <command> ...   (or the `luarecomp` script)."""
import argparse
import glob
import json
import os
import sys
import traceback

from . import __version__, core, datatable, detect, diagnose, disasm, inject, opinfer, runtime, verify
from .errors import FormatError, RecompError
from .profile import Profile, standard

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def _read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as exc:
        raise RecompError("cannot read %s: %s" % (path, exc.strerror))


def _write(path, data):
    d = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(d):
        raise RecompError("output directory does not exist: %s" % d)
    with open(path, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (path, len(data)))


def _paths(items):
    out = []
    for it in items:
        hits = sorted(glob.glob(it))         # the Windows shell does not expand wildcards
        if not hits and not os.path.exists(it):
            raise RecompError("no such file: %s" % it)
        out.extend(hits or [it])
    return out


def _profile(a, data=None):
    if getattr(a, "profile", None):
        return Profile.load(a.profile, allow_plugins=a.allow_plugin)
    if data is not None:
        if data[:5] in (b"\x1bLuaQ", b"\x1bLuaR", b"\x1bLuaS", b"\x1bLuaT"):
            return standard("5.%d" % (data[4] - 0x50))
        if data[:3] == b"\x1bLJ" and len(data) > 3 and data[3] in (1, 2):
            return standard("luajit2.0" if data[3] == 1 else "luajit2.1")
    raise RecompError("this command needs -p/--profile (the file is not standard bytecode)")


def _is_bytecode(data):
    return data[:4] == b"\x1bLua" or data[:3] == b"\x1bLJ"


# ---------------------------------------------------------------- commands
def cmd_compile(a):
    prof = _profile(a)
    name = a.chunkname or "@" + os.path.basename(a.src)
    _write(a.out, core.compile(_read(a.src), prof, name.encode("utf-8"), a.strip))


def cmd_to_std(a):
    prof = _profile(a)
    _write(a.out, core.to_std(_read(a.src), prof))


def cmd_from_std(a):
    prof = _profile(a)
    _write(a.out, core.from_std(_read(a.src), prof))


def cmd_check(a):
    prof = _profile(a)
    results = []
    for path in _paths(a.chunks):
        r = diagnose.check(_read(path), prof, os.path.basename(path), verbose=not a.quiet)
        results.append(r)
        if not a.json:
            mark = "OK  " if r.ok else "FAIL"
            print("%s %s" % (mark, path))
            if not r.ok or a.verbose:
                for line in r.lines:
                    print("     " + line)
    bad = [r for r in results if not r.ok]
    if a.json:
        print(json.dumps([r.as_dict() for r in results], ensure_ascii=False, indent=1))
    else:
        print("%d/%d OK" % (len(results) - len(bad), len(results)))
        stages = {}
        for r in bad:
            stages.setdefault(r.stage, []).append(r.name)
        for st, names in stages.items():
            print("  failed at %-10s: %d chunk(s), e.g. %s" % (st, len(names), ", ".join(names[:3])))
    return EXIT_FAIL if bad else EXIT_OK


def cmd_inspect(a):
    samples = [_read(p) for p in _paths(a.chunks)]
    res = detect.inspect(samples)
    print("\n".join(res["report"]))
    if res["profile"]:
        txt = json.dumps(res["profile"], indent=2)
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(txt + "\n")
            print("draft profile written to %s" % a.out)
        else:
            print("\ndraft profile:\n" + txt)
    return EXIT_OK if res["groups"] and len(res["groups"]) == 1 else EXIT_FAIL


def _known(path, isa):
    if not path:
        return None
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    m = d.get("opcodes", d)
    if m.get("type") == "names":
        m = m["map"]
    out = {}
    for name, c in m.items():
        if name not in isa.index:
            raise RecompError("%s: unknown opcode name %r" % (path, name))
        out[isa.index[name]] = int(c)
    return out


def cmd_infer_ops(a):
    prof = _profile(a)
    samples = [_read(p) for p in _paths(a.chunks)]
    res = opinfer.infer_ops(samples, prof, strict=not a.loose, fixed=_known(a.known, prof.isa))
    print("\n".join(res["report"]))
    ops = None
    if len(res["affine"]) == 1:
        mul, add, mod = res["affine"][0]
        ops = {"type": "affine", "mul": mul, "add": add, "mod": mod}
    elif not res["groups"] and not res["empty"] and len(res["determined"]) + len(prof.isa.never_dumped) >= prof.isa.num:
        ops = _complete_names(res["determined"], prof)
    if a.out:
        if ops is None:
            print("not writing %s: the map is not fully determined (see above)" % a.out)
            return EXIT_FAIL
        d = dict(prof.raw, opcodes=ops)
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)
        print("profile with the recovered opcode map written to %s" % a.out)
    return EXIT_OK if ops else EXIT_FAIL


def _complete_names(det, prof):
    isa = prof.isa
    m = {isa.opname(s): c for c, s in det.items()}
    free = [c for c in range(1 << prof.layout["op"][1]) if c not in det]
    for s in range(isa.num):
        if isa.opname(s) not in m:
            m[isa.opname(s)] = free.pop(0)     # never-dumped opcodes: any unused number
    return {"type": "names", "map": m}


def cmd_match_ops(a):
    prof = _profile(a)
    pairs = []
    for custom, src in a.pair:
        other = _read(src)
        std = other if _is_bytecode(other) else runtime.compile_std(other, prof.lua, a.chunkname.encode())
        pairs.append((_read(custom), std))
    res = opinfer.match_ops(pairs, prof)
    isa = prof.isa
    print("%d of %d instructions aligned" % (res["aligned"], res["total"]))
    for s in sorted(res["mapping"]):
        votes = res["votes"][s]
        if s in res["weak"]:
            print("  %-10s std %3d -> custom %3d   (weak: %d positional pairs in edited regions)"
                  % (isa.opname(s), s, res["mapping"][s], res["weak"][s]))
            continue
        print("  %-10s std %3d -> custom %3d   (%d votes%s)" % (isa.opname(s), s, res["mapping"][s],
                                                               votes[res["mapping"][s]],
                                                               ", disputed" if len(votes) > 1 else ""))
    missing = [isa.opname(s) for s in range(isa.num) if s not in res["mapping"] and s not in isa.never_dumped]
    print("%d/%d opcodes observed; missing: %s" % (len(res["mapping"]), isa.num - len(isa.never_dumped),
                                                   " ".join(missing) or "none"))
    for c in res["conflicts"][:20]:
        print("  !", c)
    diffs = {(c - s) % isa.num for s, c in res["mapping"].items()}
    if res["mapping"] and len(diffs) == 1:
        print('looks affine: "opcodes": {"type": "affine", "add": %d, "mod": %d}' % (diffs.pop(), isa.num))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump({isa.opname(s): c for s, c in res["mapping"].items()}, f, indent=1)
        print("known opcodes written to %s (use with infer-ops --known)" % a.out)
    return EXIT_FAIL if res["conflicts"] else EXIT_OK


def cmd_disasm(a):
    data = _read(a.chunk)
    prof = _profile(a, data)
    ch = core.parse(data, prof)
    lines = disasm.disasm(ch, prof, a.max)
    print("\n".join(lines))


def cmd_verify(a):
    data = _read(a.chunk)
    prof = _profile(a, data)
    ch = core.parse(data, prof)
    issues = verify.verify(ch, soft=a.warnings)
    for i in issues[:a.max]:
        print("%-5s %s" % (i.severity, i))
    errs = [i for i in issues if i.severity == verify.ERROR]
    if errs:
        print("\nper opcode:")
        print("\n".join("  " + l for l in verify.summarize(errs, prof)))
    print("%d error(s), %d warning(s)" % (len(errs), len(issues) - len(errs)))
    return EXIT_FAIL if errs else EXIT_OK


def cmd_inject(a):
    data = _read(a.chunk)
    prof = _profile(a, data)
    ch = core.parse(data, prof)
    child = inject.compile_child(_read(a.code), prof.lua, isolate=a.isolate, on_error=a.on_error)
    new = inject.inject(ch, child, force=a.force)
    for line in inject.verify_injection(ch, new):
        print("  check: " + line)
    if a.dry_run:
        same, r1, r2 = inject.dry_run(ch, new)
        print("  dry run (stub environment): original %s" % (r1,))
        print("                              patched  %s" % (r2,))
    _write(a.out, core.dump(new, prof))


def cmd_run(a):
    data = _read(a.chunk)
    prof = _profile(a, data)
    env = _read(a.env) if a.env else None
    values = datatable.run(data, prof, records=a.record or (), env_lua=env)
    txt = json.dumps(values, ensure_ascii=False, indent=1 if a.pretty else None)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(txt)
            f.write("\n")
        print("wrote %s: %d return value(s)" % (a.out, len(values)))
    else:
        print(txt)


def cmd_build_table(a):
    prof = _profile(a)
    try:
        with open(a.json, encoding="utf-8") as f:
            values = json.load(f)
    except (OSError, ValueError) as exc:
        raise RecompError("cannot read %s: %s" % (a.json, exc))
    if not a.values:
        values = [values]              # the file holds the single returned value
    data, src = datatable.build(values, prof, a.chunkname.encode("utf-8"), constructor=a.constructor,
                                type_name=a.type_name)
    if a.source:
        with open(a.source, "wb") as f:
            f.write(src)
        print("wrote %s (generated Lua source)" % a.source)
    records = [a.constructor] if a.constructor else ()
    back = datatable.run(data, prof, records=records)
    d = datatable.diff(values, back)
    if d:
        print("the built chunk does NOT return the input data:")
        for line in d:
            print("  " + line)
        return EXIT_FAIL
    print("  check: the built chunk returns exactly the input data")
    rc = EXIT_OK
    if a.compare:
        orig = datatable.run(_read(a.compare), prof, records=records)
        d = datatable.diff(orig, back)
        if d:
            print("  compare with %s (original first): %s difference(s):"
                  % (a.compare, "%d+" % len(d) if len(d) >= 20 else len(d)))
            for line in d:
                print("    " + line)
            rc = EXIT_FAIL
        else:
            print("  compare with %s: identical results" % a.compare)
    _write(a.out, data)
    return rc


# ---------------------------------------------------------------- parser
def build_parser():
    ap = argparse.ArgumentParser(prog="luarecomp", description="Compile Lua source into modified bytecode "
                                 "formats (Lua 5.1-5.4, LuaJIT 2.0/2.1) and convert them back.")
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--allow-plugin", action="store_true",
                    help="allow profiles to load their Python plugin (runs code from the plugin file)")
    ap.add_argument("--traceback", action="store_true", help="show Python tracebacks for errors")
    sub = ap.add_subparsers(dest="cmd", metavar="command")
    sub.required = True

    def prof(sp, required=True):
        sp.add_argument("-p", "--profile", required=required, help="profile JSON path or built-in name")
        return sp

    sp = prof(sub.add_parser("compile", help="Lua source -> modified bytecode"))
    sp.add_argument("src")
    sp.add_argument("-o", "--out", required=True)
    sp.add_argument("-n", "--chunkname", help="chunk name stored in the bytecode (default @<file name>)")
    sp.add_argument("-s", "--strip", action="store_true", help="drop debug info")
    sp.set_defaults(fn=cmd_compile)

    sp = prof(sub.add_parser("to-std", help="modified bytecode -> standard bytecode"))
    sp.add_argument("src")
    sp.add_argument("-o", "--out", required=True)
    sp.set_defaults(fn=cmd_to_std)

    sp = prof(sub.add_parser("from-std", help="standard bytecode -> modified bytecode"))
    sp.add_argument("src")
    sp.add_argument("-o", "--out", required=True)
    sp.set_defaults(fn=cmd_from_std)

    sp = prof(sub.add_parser("check", help="verify a profile against real chunks, with diagnostics"))
    sp.add_argument("chunks", nargs="+")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.add_argument("-q", "--quiet", action="store_true", help="no hex dumps")
    sp.add_argument("-v", "--verbose", action="store_true", help="also print details of passing chunks")
    sp.set_defaults(fn=cmd_check)

    sp = sub.add_parser("inspect", help="work out the header of unknown chunks, draft a profile")
    sp.add_argument("chunks", nargs="+", help="one or more chunks from the same game (more = better)")
    sp.add_argument("-o", "--out", help="write the draft profile here")
    sp.set_defaults(fn=cmd_inspect)

    sp = prof(sub.add_parser("infer-ops", help="recover the opcode map without source code"))
    sp.add_argument("chunks", nargs="+")
    sp.add_argument("--loose", action="store_true",
                    help="do not require unused operands to be 0 (for chunks not made by a stock compiler)")
    sp.add_argument("--known", help="JSON {opcode name: custom number} of already known opcodes (match-ops -o)")
    sp.add_argument("-o", "--out", help="write the profile with the recovered map here")
    sp.set_defaults(fn=cmd_infer_ops)

    sp = prof(sub.add_parser("match-ops", help="recover opcodes from chunks whose source you have"))
    sp.add_argument("--pair", nargs=2, action="append", required=True, metavar=("CHUNK", "SOURCE"),
                    help="a chunk and its source (.lua) or standard bytecode; repeat for more pairs")
    sp.add_argument("-n", "--chunkname", default="=?", help="chunk name used when compiling sources")
    sp.add_argument("-o", "--out", help="write {opcode name: custom number} here")
    sp.set_defaults(fn=cmd_match_ops)

    sp = prof(sub.add_parser("disasm", help="list instructions"), required=False)
    sp.add_argument("chunk")
    sp.add_argument("--max", type=int, help="stop after this many lines")
    sp.set_defaults(fn=cmd_disasm)

    sp = prof(sub.add_parser("verify", help="static check of every instruction"), required=False)
    sp.add_argument("chunk")
    sp.add_argument("-w", "--warnings", action="store_true", help="also report non-zero unused operands")
    sp.add_argument("--max", type=int, default=50, help="issues to print")
    sp.set_defaults(fn=cmd_verify)

    sp = prof(sub.add_parser("inject", help="run extra Lua code at the start of a chunk"), required=False)
    sp.add_argument("chunk")
    sp.add_argument("--code", required=True, help="Lua source file to inject")
    sp.add_argument("-o", "--out", required=True)
    sp.add_argument("--isolate", action="store_true", help="run the injected code under pcall")
    sp.add_argument("--on-error", help="Lua code run (with the message in `err`) when isolated code fails")
    sp.add_argument("--force", action="store_true", help="inject even if the chunk was injected before")
    sp.add_argument("--dry-run", action="store_true", help="also run both versions in a stub environment")
    sp.set_defaults(fn=cmd_inject)

    sp = prof(sub.add_parser("run", help="run a chunk in a stub environment, print what it returns as JSON"),
              required=False)
    sp.add_argument("chunk")
    sp.add_argument("--record", action="append", metavar="NAME",
                    help="stub this global constructor: NAME(type, fields) returns fields + __type (repeatable)")
    sp.add_argument("--env", help="Lua file with function(env) ... end, run before the chunk")
    sp.add_argument("-o", "--out", help="write the JSON here")
    sp.add_argument("--pretty", action="store_true")
    sp.set_defaults(fn=cmd_run)

    sp = prof(sub.add_parser("build-table", help="JSON -> Lua source -> compiled chunk (inverse of run)"))
    sp.add_argument("json", help="JSON file; by default the list of return values written by `run`")
    sp.add_argument("-o", "--out", required=True)
    sp.add_argument("--single", dest="values", action="store_false",
                    help="the JSON file is one value (the chunk returns just that)")
    sp.add_argument("--constructor", metavar="NAME", help="objects with __type become NAME(type, {fields})")
    sp.add_argument("--type-name", help="use this type name for every record")
    sp.add_argument("--source", help="also write the generated Lua source here")
    sp.add_argument("--compare", metavar="CHUNK", help="report differences against this original chunk")
    sp.add_argument("-n", "--chunkname", default="=table")
    sp.set_defaults(fn=cmd_build_table)
    return ap


def main(argv=None):
    ap = build_parser()
    a = ap.parse_args(argv)
    try:
        rc = a.fn(a)
        return EXIT_OK if rc is None else rc
    except FormatError as exc:
        print("error: " + exc.report(), file=sys.stderr)
    except RecompError as exc:
        print("error: %s" % exc, file=sys.stderr)
    except KeyboardInterrupt:
        return 130
    except Exception:  # noqa: BLE001 - last-resort handler for the CLI
        if a.traceback:
            raise
        print("internal error (this is a bug, please report it with the traceback below):", file=sys.stderr)
        traceback.print_exc()
        return EXIT_ERROR
    if a.traceback:
        traceback.print_exc()
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
