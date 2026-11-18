"""The verifier accepts everything the real compilers produce and flags broken code."""
import unittest

from util import R, RT, VERSIONS, sources
from luarecomp import isa as ISA, verify as V


class Verify(unittest.TestCase):
    def test_reference_compilers_are_clean(self):
        for v in VERSIONS:
            seen = set()
            for name, src in sources(v, big=True):
                for strip in (False, True):
                    ch = R.parse(RT.compile_std(src, v, b"=x", strip), R.standard(v))
                    issues = V.verify(ch)
                    with self.subTest(v=v, src=name, strip=strip):
                        self.assertEqual([str(i) for i in issues], [])
                    for _, f in ch.walk():
                        seen.update(ISA.get_field(w, ch.isa.layout, "op") for w in f["code"])
            isa = ISA.ISAS[v]
            if isa.family == "puc":      # every PUC opcode is exercised by the corpus
                self.assertEqual(len(seen), isa.num, v)

    def test_luajit_modes_match_vm(self):
        # a function containing every opcode; jit.util.funcbc reports each opcode's mode bits
        for v, isa in (("luajit2.0", ISA.LUAJIT20), ("luajit2.1", ISA.LUAJIT21)):
            if v not in VERSIONS:
                with self.subTest(v=v):
                    self.skipTest("%s not available" % v)
                continue
            st = R.standard(v)
            ch = R.parse(RT.compile_std(b"return 1", v, b"=x", strip=True), st)
            ch.root["code"] = list(range(isa.num))
            fn = RT.runtime(v).eval(b"""function(b, n) local f = assert(loadstring(b))
                local u = require('jit.util') local out = {}
                for pc = 1, n do local _, m = u.funcbc(f, pc) out[pc] = m end return out end""")
            modes = fn(R.dump(ch, st), isa.num)
            for op in range(isa.num):
                self.assertEqual(modes[op + 1] & 0x7FF, isa.modes[op], (v, isa.names[op]))

    def test_detects_wrong_opcode(self):
        ch = R.parse(RT.compile_std(sources("5.3")[0][1], "5.3"), R.standard("5.3"))
        isa = ch.isa
        f = ch.root
        for pc, w in enumerate(f["code"]):
            if ISA.get_field(w, isa.layout, "op") == isa.index["LOADK"]:
                f["code"][pc] = ISA.set_field(w, isa.layout, "op", isa.index["EQ"])   # EQ needs a JMP next
                break
        issues = [i for i in V.verify(ch) if i.severity == V.ERROR]
        self.assertTrue(issues)
        self.assertIn("EQ", V.summarize(issues)[0])


if __name__ == "__main__":
    unittest.main()
