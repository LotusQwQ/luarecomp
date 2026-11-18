"""Profile validation produces errors that say what is wrong and where."""
import json
import os
import tempfile
import unittest

from util import R


class ProfileErrors(unittest.TestCase):
    def err(self, d):
        with self.assertRaises(R.ProfileError) as cm:
            R.Profile(d)
        return str(cm.exception)

    def test_messages(self):
        self.assertIn("did you mean 'signature'", self.err({"signatur": "00"}))
        self.assertIn("unsupported VM '5.5'", self.err({"lua": "5.5"}))
        self.assertIn("not valid hex", self.err({"signature": "zz"}))
        self.assertIn("sizes[0]", self.err({"sizes": [["innt", 4]]}))
        self.assertIn("const_tags.float", self.err({"lua": "5.1", "const_tags": {"float": 9}}))
        self.assertIn("MOVE and LOADK both map", self.err({"opcodes": {"type": "table", "map": [0] * 47}}))
        self.assertIn("must list 83 numbers", self.err({"lua": "5.4", "opcodes": {"type": "table", "map": [1]}}))
        self.assertIn("did you mean 'GETTABUP'",
                      self.err({"opcodes": {"type": "names", "map": {"GETTABUPP": 1}}}))
        self.assertIn("does not fit in the 6-bit op field",
                      self.err({"opcodes": {"type": "affine", "add": 30, "mod": 100}}))
        self.assertIn("sections missing: upnames", self.err({"function": [
            "source", "line", "lastline", "nparams", "vararg", "maxstack", "code", "constants", "upvals",
            "protos", "lines", "locvars"]}))
        self.assertIn("overlap", self.err({"instruction": {"A": [0, 8]}}))
        self.assertIn("not used for LuaJIT", self.err({"lua": "luajit2.1", "sizes": []}))

    def test_load_errors(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w") as f:
                f.write('{"lua": "5.3",\n "x": }')
            with self.assertRaises(R.ProfileError) as cm:
                R.Profile.load(p)
            self.assertIn("line 2", str(cm.exception))
        with self.assertRaises(R.ProfileError) as cm:
            R.Profile.load("example_custm")
        self.assertIn("did you mean 'example_custom'", str(cm.exception))

    def test_builtin_profiles_valid(self):
        here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "profiles")
        for fn in os.listdir(here):
            if fn.endswith(".json"):
                with self.subTest(profile=fn):
                    R.Profile.load(os.path.join(here, fn))

    def test_v1_profile_is_lua53(self):
        p = R.Profile(json.loads('{"signature": "47414d45", "format": 1}'))
        self.assertEqual(p.lua, "5.3")


if __name__ == "__main__":
    unittest.main()
