"""Disassembly listing: constants, jumps, upvalues and children are resolved on every VM."""
import os
import tempfile
import unittest

from util import R, RT, VERSIONS
from luarecomp import disasm as D, isa as ISA

SRC = b"""local s, n = 'hello', 1.5
local up = {}
local function f(x) if x then up[1] = x end return x end
return f(s), n, nil, true
"""


def listing(v, prof=None, **kw):
    ch = R.parse(RT.compile_std(SRC, v, b"@d.lua"), R.standard(v))
    return D.disasm(ch, prof, **kw), ch


class Disasm(unittest.TestCase):
    def test_notes(self):
        for v in VERSIONS:
            with self.subTest(v=v):
                text = "\n".join(listing(v)[0])
                self.assertIn("'hello'", text)
                self.assertIn("1.5", text)
                self.assertRegex(text, r"; .*-> \d+")
                if v.startswith("luajit"):
                    self.assertIn("child", text)
                    self.assertRegex(text, r"KPRI .*; true")
                    self.assertIn("#kgc=", text)
                else:
                    self.assertIn("proto 0", text)
                    self.assertIn("up:up", text)
                    self.assertIn("@d.lua:", text)

    def test_custom_opcode_column(self):
        for v in VERSIONS:
            prof = R.Profile({"lua": v, "opcodes": {"type": "affine", "add": 7}})
            lines, ch = listing(v, prof)
            first = ISA.get_field(ch.root["code"][0], ch.isa.layout, "op")
            with self.subTest(v=v):
                self.assertIn("[%3d] %s" % (prof.std_to_op[first], ch.isa.opname(first)), lines[1])
                self.assertNotRegex(listing(v, R.standard(v))[0][1], r"\[\s*\d+\] ")   # identity: no column

    def test_truncate_and_unknown_opcode(self):
        for v in VERSIONS:
            with self.subTest(v=v):
                lines, _ = listing(v, max_lines=3)
                self.assertEqual(len(lines), 4)
                self.assertEqual(lines[-1], "  ... (truncated)")
                ch = R.parse(RT.compile_std(SRC, v), R.standard(v))
                ch.root["code"][0] = ISA.set_field(ch.root["code"][0], ch.isa.layout, "op", ch.isa.num)
                self.assertIn("??? opcode %d" % ch.isa.num, D.disasm(ch)[1])

    def test_cli_detects_standard_bytecode(self):
        from test_cli import call
        with tempfile.TemporaryDirectory() as d:
            for v in VERSIONS:
                p = os.path.join(d, "x.bytes")
                with open(p, "wb") as f:
                    f.write(RT.compile_std(SRC, v))
                rc, o, e = call("disasm", p, "--max", "5")
                with self.subTest(v=v):
                    self.assertEqual(rc, 0, e)
                    self.assertIn("KSTR" if v.startswith("luajit") else "LOADK", o)
            with open(p, "wb") as f:
                f.write(b"GAME" + bytes(20))
            rc, o, e = call("disasm", p)
            self.assertEqual(rc, 2)
            self.assertIn("needs -p", e)


if __name__ == "__main__":
    unittest.main()
