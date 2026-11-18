"""inspect: header arrangements are tried, not guessed; ambiguity is reported."""
import unittest

from util import R
from luarecomp import detect

LONG = b"local s = '" + b"x" * 300 + b"' return s, 1, 2.5"
SHORT = b"return 'short', 1, 2.5"


class Detect(unittest.TestCase):
    def test_unambiguous_with_long_strings(self):
        prof = R.Profile({"signature": "47414d45", "format": 1,
                          "sizes": [["int", 4], ["size_t", 4], ["integer", 8], ["number", 8]],
                          "opcodes": {"type": "affine", "add": 11}})
        res = detect.inspect([R.compile(LONG, prof)])
        self.assertEqual(len(res["groups"]), 1, res["report"])
        d = R.Profile(dict(res["profile"], opcodes=prof.raw["opcodes"]))
        self.assertEqual(R.compile(LONG, d), R.compile(LONG, prof))

    def test_ambiguous_without_long_strings(self):
        prof = R.Profile({"signature": "47414d45",
                          "sizes": [["int", 4], ["size_t", 4], ["integer", 8], ["number", 8]]})
        res = detect.inspect([R.compile(SHORT, prof)])
        self.assertGreater(len(res["groups"]), 1)
        text = "\n".join(res["report"])
        self.assertIn("AMBIGUOUS", text)
        self.assertIn("size_t", text)
        self.assertIn("long string", text)

    def test_other_versions(self):
        for d in ({"lua": "5.1"}, {"lua": "5.2", "endian": "big"},
                  {"lua": "5.4", "sizes": [["instruction", 4], ["integer", 4], ["number", 4]]},
                  {"lua": "luajit2.0", "signature": "1b4c58"}):
            with self.subTest(d=d):
                prof = R.Profile(d)
                res = detect.inspect([R.compile(LONG, prof)])
                self.assertEqual(len(res["groups"]), 1, res["report"])
                self.assertEqual(res["profile"]["lua"], prof.lua)

    def test_garbage(self):
        res = detect.inspect([bytes(range(256)) * 4])
        self.assertIsNone(res["profile"])
        self.assertIn("encrypted", "\n".join(res["report"]))

    def test_modified_function_layout_reports_closest(self):
        prof = R.Profile({"function": ["source", "line", "lastline", "nparams", "vararg", "maxstack", "code",
                                       {"keep": "u32"}, "constants", "upvals", "protos", "lines", "locvars",
                                       "upnames"]})
        res = detect.inspect([R.compile(LONG, prof)])
        self.assertEqual(res["groups"], [])
        self.assertIn("closest", "\n".join(res["report"]))


if __name__ == "__main__":
    unittest.main()
