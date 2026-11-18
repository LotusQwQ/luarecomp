"""Command line smoke tests (exit codes and key output)."""
import contextlib
import io
import os
import tempfile
import unittest

import util  # noqa: F401  (sets sys.path)
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


if __name__ == "__main__":
    unittest.main()
