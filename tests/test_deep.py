"""Deep format changes: header items, section order, encodings, bit layout, strings, plugins."""
import os
import random
import unittest

from util import DATA, R, RT, VERSIONS, run, sources
from luarecomp import verify as V

perm = list(range(47))
random.Random(3).shuffle(perm)

DEEP = {
    "deep53": {
        "lua": "5.3", "signature": "5a5a", "format": 7, "luac_data": "",
        "sizes": {"int": 4, "size_t": 4, "integer": 8, "number": 8},
        "header": ["signature", {"const": "c0de"}, "version", "format", {"keep": 3, "fill": "010203"},
                   "size:size_t", "size:integer", "size:number", "nupvals", "luac_num", "luac_int"],
        "function": ["maxstack", "code", {"keep": "u8", "fill": 9}, "constants", "nparams", "vararg",
                     "source", "line", "lastline", "protos", "upvals", "lines", "upnames", "locvars"],
        "encoding": {"count": "uleb", "line": "u16", "lineinfo": "u16", "pc": "uleb", "string": "count"},
        "const_tags": {"integer": 7, "float": 8, "short_string": 9, "long_string": 10, "nil": 11, "boolean": 12},
        "instruction": {"op": [26, 6], "A": [18, 8], "B": [0, 9], "C": [9, 9], "Bx": [0, 18], "Ax": [0, 26]},
        "opcodes": {"type": "table", "map": perm},
        "strings": {"type": "xor", "key": "a5c3", "scope": ["constants", "names", "source"]},
    },
    "deep54": {"lua": "5.4", "endian": "big", "luac_data": "",
               "instruction": {"op": [25, 7], "A": [17, 8], "k": [16, 1], "B": [8, 8], "C": [0, 8],
                               "Bx": [0, 17], "Ax": [0, 25], "sJ": [0, 25]},
               "opcodes": {"type": "affine", "mul": 7, "add": 3, "mod": 128}},
    "deep51": {"lua": "5.1", "endian": "big",
               "sizes": [["int", 4], ["size_t", 4], ["instruction", 4], ["number", 8]],
               "instruction": {"op": [0, 6], "A": [24, 8], "B": [6, 9], "C": [15, 9], "Bx": [6, 18]},
               "const_tags": {"number": 1, "boolean": 3}, "opcodes": {"type": "affine", "add": 5}},
    "deepjit": {"lua": "luajit2.1", "signature": "4c4a21",
                "instruction": {"op": [24, 8], "A": [16, 8], "C": [8, 8], "B": [0, 8], "D": [0, 16]},
                "opcodes": {"type": "affine", "mul": 3, "add": 40, "mod": 256},
                "strings": {"type": "xor", "key": "77"}},
    "plugin52": {"lua": "5.2", "plugin": "rot7_plugin.py", "opcodes": {"type": "affine", "add": 9}},
}


class Deep(unittest.TestCase):
    def test_deep_formats(self):
        for name, d in DEEP.items():
            prof = R.Profile(dict(d, name=name), base_dir=DATA, allow_plugins=True)
            if prof.lua not in VERSIONS:
                with self.subTest(profile=name):
                    self.skipTest("%s not available" % prof.lua)
                continue
            for sname, src in sources(prof.lua, big=prof.lua == "5.1"):
                with self.subTest(profile=name, src=sname):
                    std = RT.compile_std(src, prof.lua, b"@" + sname.encode())
                    custom = R.from_std(std, prof)
                    self.assertNotEqual(custom, std)
                    self.assertEqual(R.to_std(custom, prof), std)
                    self.assertEqual(R.from_std(R.to_std(custom, prof), prof), custom)
                    self.assertEqual([i for i in V.verify(R.parse(custom, prof)) if i.severity == "error"], [])
                    self.assertEqual(run(R.to_std(custom, prof), prof.lua), run(std, prof.lua))

    def test_xor_strings_hidden(self):
        prof = R.Profile(dict(DEEP["deep53"], name="x"))
        custom = R.compile(b"return 'secret-constant'", prof)
        self.assertNotIn(b"secret-constant", custom)
        self.assertIn(b"secret-constant", R.to_std(custom, prof))

    def test_keep_values_survive(self):
        prof = R.Profile(dict(DEEP["deep53"], name="x"))
        custom = bytearray(R.compile(b"return 1", prof))
        custom[2 + 2 + 1 + 1] = 0x77               # first "keep" header byte
        ch = R.parse(bytes(custom), prof)
        self.assertEqual(ch.keep[0][:1], b"\x77")
        self.assertEqual(R.dump(ch, prof), bytes(custom))

    def test_plugin_needs_permission(self):
        with self.assertRaises(R.PluginError) as cm:
            R.Profile(dict(DEEP["plugin52"], name="p"), base_dir=DATA)
        self.assertIn("--allow-plugin", str(cm.exception))

    def test_plugin_import_error_reported(self):
        bad = os.path.join(DATA, "_broken_plugin.py")
        with open(bad, "w") as f:
            f.write("raise RuntimeError('boom')\n")
        try:
            with self.assertRaises(R.PluginError) as cm:
                R.Profile({"plugin": bad}, allow_plugins=True)
            self.assertIn("boom", str(cm.exception))
        finally:
            os.remove(bad)


if __name__ == "__main__":
    unittest.main()
