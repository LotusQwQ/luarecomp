"""Command line smoke tests (exit codes and key output)."""
import contextlib
import io
import json
import os
import tempfile
import unittest

import util  # noqa: F401  (sets sys.path)
from util import R, RT, sources
from luarecomp import cli


def call(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class CLI(unittest.TestCase):
    def test_workflow(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "a.lua")
            with open(src, "w") as f:
                f.write("local t = {} for i = 1, 3 do t[i] = i * 2 end return #t, t[3]\n")
            out = os.path.join(d, "a.bytes")
            rc, o, e = call("compile", src, "-p", "example_custom", "-o", out)
            self.assertEqual(rc, 0, e)
            rc, o, e = call("check", "-p", "example_custom", out)
            self.assertEqual(rc, 0, o + e)
            rc, o, e = call("inspect", out, "-o", os.path.join(d, "draft.json"))
            self.assertIn("signature 47414d45", o)
            rc, o, e = call("disasm", "-p", "example_custom", out)
            self.assertIn("FORLOOP", o)
            rc, o, e = call("verify", "-p", "example_custom", out)
            self.assertEqual(rc, 0, o + e)
            hook = os.path.join(d, "hook.lua")
            with open(hook, "w") as f:
                f.write("HOOKED = true\n")
            rc, o, e = call("inject", "-p", "example_custom", out, "--code", hook, "--isolate",
                            "-o", os.path.join(d, "b.bytes"))
            self.assertEqual(rc, 0, e)
            self.assertIn("unchanged", o)

    def test_errors_are_readable(self):
        rc, o, e = call("check", "-p", "no_such_profile", "x")
        self.assertEqual(rc, 2)
        self.assertTrue(e.startswith("error:"))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.bytes")
            with open(p, "wb") as f:
                f.write(b"GAME" + bytes(10))
            rc, o, e = call("to-std", "-p", "example_custom", p, "-o", os.path.join(d, "y"))
            self.assertEqual(rc, 2)
            self.assertIn("offset", e)
            self.assertIn("bytes around offset", e)

    def test_v1_command_line(self):
        import lua53recomp
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "a.lua")
            with open(src, "w") as f:
                f.write("return 1 + 2\n")
            out = os.path.join(d, "a.bytes")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(lua53recomp.main(["compile", src, "-p", "example_custom", "-o", out]), 0)
                self.assertEqual(lua53recomp.main(["match-ops", "-p", "example_custom", out, src,
                                                   "-n", "@a.lua"]), 0)


def write(d, name, data):
    """Write bytes, text or a JSON value to d/name -> path."""
    if not isinstance(data, (bytes, str)):
        data = json.dumps(data)
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    return p


# fictional 5.3 format with a standard header and an affine opcode map
AFFINE = {"lua": "5.3", "opcodes": {"type": "affine", "mul": 5, "add": 11, "mod": 47}}


class Commands(unittest.TestCase):
    def test_to_std_and_from_std(self):
        with tempfile.TemporaryDirectory() as d:
            std = RT.compile_std(b"local t = {1, 2} return #t", "5.3", b"=x")
            p = write(d, "s.bytes", std)
            c, back = os.path.join(d, "c.bytes"), os.path.join(d, "b.bytes")
            rc, o, e = call("from-std", "-p", "example_custom", p, "-o", c)
            self.assertEqual(rc, 0, e)
            self.assertIn("wrote", o)
            self.assertEqual(call("to-std", "-p", "example_custom", c, "-o", back)[0], 0)
            with open(back, "rb") as f:
                self.assertEqual(f.read(), std)
            rc, o, e = call("to-std", "-p", "example_custom", c, "-o", os.path.join(d, "no", "dir", "x"))
            self.assertEqual(rc, 2)
            self.assertIn("output directory does not exist", e)

    def test_check_reports_failure(self):
        with tempfile.TemporaryDirectory() as d:
            src = write(d, "a.lua", sources("5.3")[0][1])
            out = os.path.join(d, "a.bytes")
            self.assertEqual(call("compile", src, "-p", "example_custom", "-o", out)[0], 0)
            raw = dict(R.Profile.load("example_custom").raw, opcodes={"type": "affine", "add": 12})
            wrong = write(d, "wrong.json", raw)
            rc, o, e = call("check", "-p", wrong, out, "-q")
            self.assertEqual(rc, 1, o + e)
            self.assertIn("FAIL", o)
            self.assertIn("0/1 OK", o)
            self.assertIn("failed at", o)
            rc, o, e = call("check", "-p", wrong, os.path.join(d, "*.bytes"), "--json")
            self.assertEqual(rc, 1)
            res = json.loads(o)
            self.assertEqual(len(res), 1)
            self.assertFalse(res[0]["ok"])
            rc, o, e = call("check", "-p", "example_custom", out, "-v")
            self.assertEqual(rc, 0, o + e)
            self.assertIn("1/1 OK", o)
            self.assertEqual(call("check", "-p", "example_custom", os.path.join(d, "none*.bytes"))[0], 2)

    def test_infer_ops(self):
        prof = R.Profile(AFFINE)
        with tempfile.TemporaryDirectory() as d:
            files = [write(d, "%s.bytes" % name, R.compile(src, prof)) for name, src in sources("5.3")]
            out = os.path.join(d, "found.json")
            rc, o, e = call("infer-ops", "-p", "lua53", *files, "-o", out)
            self.assertEqual(rc, 0, o + e)
            with open(out, encoding="utf-8") as f:
                found = R.Profile(json.load(f))
            self.assertEqual(found.std_to_op, prof.std_to_op)
            # one tiny chunk cannot pin the map down: nothing is written
            tiny = write(d, "tiny.bytes", R.compile(b"return 1", prof))
            rc, o, e = call("infer-ops", "-p", "lua53", tiny, "-o", os.path.join(d, "no.json"))
            self.assertEqual(rc, 1)
            self.assertIn("not writing", o)
            self.assertFalse(os.path.exists(os.path.join(d, "no.json")))

    def test_match_ops_then_known(self):
        prof = R.Profile(AFFINE)
        with tempfile.TemporaryDirectory() as d:
            name, src = sources("5.3")[0]
            lua = write(d, "a.lua", src)
            chunk = write(d, "a.bytes", R.compile(src, prof, b"=?"))
            std = write(d, "a.std", RT.compile_std(src, "5.3", b"=?"))
            known = os.path.join(d, "known.json")
            for other in (lua, std):                   # the pair may hold source or standard bytecode
                rc, o, e = call("match-ops", "-p", "lua53", "--pair", chunk, other, "-o", known)
                self.assertEqual(rc, 0, o + e)
                self.assertIn("instructions aligned", o)
                self.assertNotIn("disputed", o)
            with open(known, encoding="utf-8") as f:
                m = json.load(f)
            isa = prof.isa
            self.assertTrue(m)
            for op, c in m.items():
                self.assertEqual(prof.std_to_op[isa.index[op]], c)
            files = [chunk] + [write(d, "%s.bytes" % n, R.compile(s, prof)) for n, s in sources("5.3")[1:]]
            rc, o, e = call("infer-ops", "-p", "lua53", *files, "--known", known)
            self.assertEqual(rc, 0, o + e)
            bad = write(d, "bad.json", {"NOSUCHOP": 1})
            rc, o, e = call("infer-ops", "-p", "lua53", chunk, "--known", bad)
            self.assertEqual(rc, 2)
            self.assertIn("unknown opcode name", e)

    def test_inject_dry_run(self):
        with tempfile.TemporaryDirectory() as d:
            p = write(d, "a.bytes", RT.compile_std(b"MARK = MARK or 'orig' return MARK", "5.3"))
            hook = write(d, "hook.lua", "MARK = 'hooked'\n")
            rc, o, e = call("inject", p, "--code", hook, "--dry-run", "-o", os.path.join(d, "b.bytes"))
            self.assertEqual(rc, 0, e)
            self.assertIn("original (True, [b'orig'])", o)
            self.assertIn("patched  (True, [b'hooked'])", o)


if __name__ == "__main__":
    unittest.main()
