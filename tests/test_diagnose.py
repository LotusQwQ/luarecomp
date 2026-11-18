"""check: failures are located (stage, offset, field, culprit opcode)."""
import unittest

from util import R, sources
from luarecomp import diagnose, isa as ISA

PROF = R.Profile({"signature": "47414d45", "format": 1, "opcodes": {"type": "affine", "add": 11}})
SRC = sources("5.3")[0][1]


class Diagnose(unittest.TestCase):
    def setUp(self):
        self.data = R.compile(SRC, PROF, b"@t.lua")

    def test_ok(self):
        r = diagnose.check(self.data, PROF)
        self.assertTrue(r.ok, r.lines)

    def test_wrong_opcode_map_is_caught_although_it_loads(self):
        bad = R.Profile(dict(PROF.raw, opcodes={"type": "affine", "add": 12}))
        self.assertTrue(R.load_check(self.data, bad)[0])     # the VM itself accepts it
        r = diagnose.check(self.data, bad)
        self.assertFalse(r.ok)
        self.assertEqual(r.stage, "verify")
        self.assertIn("custom opcode", "\n".join(r.lines))

    def test_parse_failure_located(self):
        bad = R.Profile(dict(PROF.raw, sizes=[["int", 4], ["size_t", 4], ["integer", 8], ["number", 8]]))
        r = diagnose.check(self.data, bad)
        self.assertEqual(r.stage, "parse")
        self.assertIsNotNone(r.data["offset"])
        self.assertIn("size", "\n".join(r.lines))

    def test_round_trip_difference_located(self):
        # the source name's length written with the 0xFF escape although it fits in one byte
        ch = R.parse(self.data, PROF)
        src = ch.root["source"]
        i = self.data.index(bytes([len(src) + 1]) + src)
        d = self.data[:i] + b"\xff" + (len(src) + 1).to_bytes(8, "little") + self.data[i + 1:]
        r = diagnose.check(d, PROF)
        self.assertEqual(r.stage, "round-trip")
        self.assertEqual(r.data["offset"], i)
        self.assertIn("source", "\n".join(r.lines))

    def test_single_corrupted_instruction(self):
        ch = R.parse(self.data, PROF)
        isa = ch.isa
        f = ch.root
        for pc, w in enumerate(f["code"]):
            if ISA.get_field(w, isa.layout, "op") == isa.index["LOADK"]:
                f["code"][pc] = ISA.set_field(w, isa.layout, "Bx", 60000)
                break
        r = diagnose.check(R.dump(ch, PROF), PROF)
        self.assertEqual(r.stage, "verify")
        self.assertIn("pc %d" % pc, "\n".join(r.lines))


if __name__ == "__main__":
    unittest.main()
