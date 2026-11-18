"""Prologue injection on every VM, with its guarantees."""
import unittest

from util import R, RT, VERSIONS
from luarecomp import inject as I

ORIG = b"""local n = 0
while n < 3 do n = n + 1 end
local function f(...) return select('#', ...) end
if MARK == nil then MARK = 'orig' end
if FAIL then error("boom") end
return MARK, n, f(1, 2)
"""


class Inject(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = []
        for v in VERSIONS:
            for strip in (False, True):
                cls.cases.append((v, strip, R.parse(RT.compile_std(ORIG, v, b"@t.lua", strip), R.standard(v))))

    def test_runs_first_and_keeps_original(self):
        for v, strip, ch in self.cases:
            with self.subTest(v=v, strip=strip):
                new = I.inject(ch, I.compile_child(b"MARK = 'injected'", v))
                self.assertEqual(RT.run(R.dump(new, R.standard(v)), v), [b"injected", 3, 2])
                self.assertEqual(len(I.verify_injection(ch, new)), 3)

    def test_survives_custom_format(self):
        for v, strip, ch in self.cases:
            prof = R.Profile({"lua": v, "opcodes": {"type": "affine", "add": 7}})
            new = I.inject(ch, I.compile_child(b"MARK = 'x'", v))
            custom = R.dump(new, prof)
            self.assertEqual(R.to_std(custom, prof), R.dump(new, R.standard(v)))

    def test_double_injection_refused(self):
        for v, strip, ch in self.cases:
            child = I.compile_child(b"X = 1", v)
            new = I.inject(ch, child)
            with self.assertRaises(I.InjectError):
                I.inject(new, child)
            I.inject(new, child, force=True)

    def test_isolation(self):
        for v, strip, ch in self.cases:
            child = I.compile_child(b"error('hook failed')", v, isolate=True, on_error="HOOKERR = err")
            new = I.inject(ch, child)
            self.assertEqual(RT.run(R.dump(new, R.standard(v)), v), [b"orig", 3, 2])

    def test_line_numbers_preserved(self):
        for v, strip, ch in self.cases:
            if strip:
                continue
            new = I.inject(ch, I.compile_child(b"X = 1", v))
            msgs = []
            for c in (ch, new):
                with self.assertRaises(Exception) as cm:
                    RT.run(R.dump(c, R.standard(v)), v, b"function(env) env.FAIL = true end")
                msgs.append(str(cm.exception).splitlines()[0])
            with self.subTest(v=v):
                self.assertEqual(msgs[0], msgs[1])
                self.assertIn("t.lua:5", msgs[0])

    def test_wrong_version_child(self):
        ch = self.cases[0][2]
        with self.assertRaises(I.InjectError):
            I.inject(ch, I.compile_child(b"X = 1", "5.3"))


if __name__ == "__main__":
    unittest.main()
