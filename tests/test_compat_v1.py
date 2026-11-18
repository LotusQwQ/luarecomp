"""Run with:  python -m unittest discover -s tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import lua53recomp as R  # noqa: E402

SRC = b"""
local t = {}
for i = 1, 10 do t[#t + 1] = i * 2.5 // 1 end
local long = "x" .. string.rep("y", 300)
local function f(a, ...) return a and select('#', ...) or nil end
local s = 0
for k, v in pairs({a = 1, b = 2}) do s = s + v end
local x, y = 6, 3
return #t, t[10], #long, f(true, 1, 2), x & y, x | y, x ~ y, x << 2, x >> 1, -x, ~x,
       x / y, x % 4, x ^ 2, x == y, x < y, x <= y, not x, s, 9007199254740993, 1.5e300,
       "\\0binary\\255", math.type(3), math.type(3.0)
"""

CUSTOM = R.Profile.load("example_custom")


def run(std_bytes):
    lua = R._lua()
    f = lua.eval(b"function(b) local f = assert(load(b, 't', 'b')); return table.pack(f()) end")
    t = f(std_bytes)
    return [t[i] for i in range(1, t[b"n"] + 1)]


class Tests(unittest.TestCase):
    def test_standard_round_trip(self):
        std = R.compile_std(SRC, b"@t.lua")
        self.assertEqual(R.convert(std, R.STANDARD, R.STANDARD), std)

    def test_custom_round_trip_and_semantics(self):
        std = R.compile_std(SRC, b"@t.lua")
        custom = R.compile(SRC, CUSTOM, b"@t.lua")
        self.assertTrue(custom.startswith(b"GAME"))
        self.assertNotEqual(custom, std)
        back = R.convert(custom, CUSTOM, R.STANDARD)
        self.assertEqual(back, std)
        self.assertEqual(R.convert(back, R.STANDARD, CUSTOM), custom)
        self.assertEqual(run(back), run(std))

    def test_stripped(self):
        std = R.compile_std(SRC, b"@t.lua", strip=True)
        custom = R.convert(std, R.STANDARD, CUSTOM)
        self.assertEqual(R.convert(custom, CUSTOM, R.STANDARD), std)

    def test_wrong_profile_rejected(self):
        custom = R.compile(SRC, CUSTOM)
        with self.assertRaises(R.FormatError):
            R.parse(custom, R.STANDARD)

    def test_load_check(self):
        self.assertTrue(R.load_check(R.compile_std(SRC))[0])
        self.assertFalse(R.load_check(b"\x1bLuaS\x00garbage")[0])

    def test_inject_prologue(self):
        _, root = R.parse(R.compile_std(b"local a = 1 return marker, a"))
        child = R.compile_proto(b"marker = 'injected'")
        out = R.dump(R.inject_prologue(root, child))
        self.assertTrue(R.load_check(out)[0])
        self.assertEqual(run(out), [b"injected", 1])
        # survives conversion to a custom format and back
        self.assertEqual(R.convert(R.convert(out, R.STANDARD, CUSTOM), CUSTOM, R.STANDARD), out)

    def test_match_opcodes_recovers_map(self):
        custom = R.compile(SRC, CUSTOM, b"@t.lua")
        raw = R.Profile.load("example_custom")
        raw.op_to_std = raw.std_to_op = {i: i for i in range(64)}
        _, croot = R.parse(custom, raw)
        _, sroot = R.parse(R.compile_std(SRC, b"@t.lua"))
        seen, conflicts = R.match_opcodes(croot, sroot)
        self.assertEqual(conflicts, [])
        self.assertTrue(seen)
        for s, c in seen.items():
            self.assertEqual(c, CUSTOM.std_to_op[s])

    def test_inspect_drafts_usable_header(self):
        custom = R.compile(SRC, CUSTOM)
        _, d = R.inspect_header(custom)
        self.assertEqual(d["signature"], CUSTOM.signature.hex())
        self.assertEqual(d["sizes"], [["int", 4], ["size_t", 4], ["integer", 8], ["number", 8]])

    def test_table_opcode_map(self):
        perm = list(range(R.NUM_OPCODES))[::-1]
        prof = R.Profile({"signature": "1b4c7561", "opcodes": {"type": "table", "map": perm}})
        std = R.compile_std(SRC)
        self.assertEqual(R.convert(R.convert(std, R.STANDARD, prof), prof, R.STANDARD), std)
        with self.assertRaises(ValueError):
            R.Profile({"signature": "00", "opcodes": {"type": "table", "map": [0] * R.NUM_OPCODES}})


if __name__ == "__main__":
    unittest.main()
