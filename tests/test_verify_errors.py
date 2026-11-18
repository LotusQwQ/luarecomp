"""Every kind of verifier error: one hand-broken instruction each, on every VM."""
import unittest

from util import R, RT, VERSIONS
from luarecomp import isa as ISA, verify as V

SRC = b"""local s, n = 'str', 1.5
local up = {}
local function f(x, y)
  local a = x + #up
  local b = a
  if a < y then return 'lt' end
  if x then b = b * 0.5 end
  return b
end
local t = {k = s}
return f(3, 4), t.k, n, nil, true
"""
PUC_VMS = [v for v in VERSIONS if not v.startswith("luajit")]
LJ_VMS = [v for v in VERSIONS if v.startswith("luajit")]


def parse(v):
    return R.parse(RT.compile_std(SRC, v, b"=x"), R.standard(v))


def find(ch, name, child=False):
    """-> (path, function, pc) of the first instruction with standard opcode `name`
    (with child=True: inside f, not the main function)."""
    isa = ch.isa
    for path, f in ch.walk():
        if child and f is ch.root:
            continue
        for pc, w in enumerate(f["code"]):
            if ISA.get_field(w, isa.layout, "op") == isa.index[name]:
                return path, f, pc
    raise AssertionError("%s not in the test chunk" % name)


def errors_at(ch, path, pc, sev=V.ERROR):
    return [i.msg for i in V.verify(ch) if i.severity == sev and i.path == path and i.pc == pc]


class Common(object):
    def break_op(self, v, name, child=False, **fields):
        """Change operands of the first `name` instruction; values may be functions of the prototype."""
        ch = parse(v)
        path, f, pc = find(ch, name, child)
        d = ISA.decode(ch.isa, f["code"][pc])
        for k, x in fields.items():
            d[k] = x(f) if callable(x) else x
        f["code"][pc] = ISA.encode(ch.isa, d)
        return ch, path, f, pc

    def assertFlagged(self, ch, path, pc, text, sev=V.ERROR):
        msgs = errors_at(ch, path, pc, sev)
        self.assertTrue(any(text in m for m in msgs), "%r not in %r" % (text, msgs))

    def check_unknown_opcode(self, v, name):
        ch = parse(v)
        path, f, pc = find(ch, name)
        f["code"][pc] = ISA.set_field(f["code"][pc], ch.isa.layout, "op", ch.isa.num)
        self.assertFlagged(ch, path, pc, "does not exist")

    def check_successor(self, v, cmp, other):
        ch = parse(v)
        path, f, pc = find(ch, cmp)
        f["code"][pc + 1] = ISA.set_field(f["code"][pc + 1], ch.isa.layout, "op", ch.isa.index[other])
        self.assertFlagged(ch, path, pc, "must be followed by")
        f["code"] = f["code"][:pc + 1]
        self.assertTrue(any("followed by" in i.msg for i in V.verify(ch) if i.pc == pc))

    def check_no_return(self, v, name):
        ch = parse(v)
        path, f, pc = find(ch, name)
        f["code"][-1] = f["code"][pc]
        self.assertFlagged(ch, path, len(f["code"]) - 1, "does not end with a return")


class PUC(Common, unittest.TestCase):
    def test_operand_ranges(self):
        for v in PUC_VMS:
            with self.subTest(v=v):
                ch, path, f, pc = self.break_op(v, "LOADK", A=lambda f: f["maxstack"])
                self.assertFlagged(ch, path, pc, "register A=")
                ch, path, f, pc = self.break_op(v, "LOADK", Bx=lambda f: len(f["K"]))
                self.assertFlagged(ch, path, pc, "constant Bx=")
                ch, path, f, pc = self.break_op(v, "GETUPVAL", B=lambda f: f["nupvals"] if v == "5.1"
                                                else len(f["upvals"]))
                self.assertFlagged(ch, path, pc, "upvalue B=")
                ch, path, f, pc = self.break_op(v, "CLOSURE", Bx=lambda f: len(f["protos"]))
                self.assertFlagged(ch, path, pc, "prototype Bx=")
                ch, path, f, pc = self.break_op(v, "JMP", **{"sJ" if v == "5.4" else "sBx": 10000})
                self.assertFlagged(ch, path, pc, "jump target")
                ch, path, f, pc = self.break_op(v, "RETURN", A=lambda f: f["maxstack"] + 1)
                self.assertFlagged(ch, path, pc, "register base A=")

    def test_rk_constants(self):
        for v in PUC_VMS:
            if v == "5.4":
                continue                      # 5.4 has no RK operands on ADD
            with self.subTest(v=v):
                ch, path, f, pc = self.break_op(v, "ADD", C=lambda f: 256 + len(f["K"]))
                self.assertFlagged(ch, path, pc, "RK constant C=")
                ch, path, f, pc = self.break_op(v, "ADD", C=lambda f: f["maxstack"])
                self.assertFlagged(ch, path, pc, "RK register C=")

    def test_54_string_constant(self):
        if "5.4" not in PUC_VMS:
            self.skipTest("5.4 not available")
        num = lambda f: next(i for i, (t, _) in enumerate(f["K"]) if t not in (4, 0x14))  # noqa: E731
        ch, path, f, pc = self.break_op("5.4", "GETFIELD", C=num)
        self.assertFlagged(ch, path, pc, "is not a string")
        ch, path, f, pc = self.break_op("5.4", "GETFIELD", C=lambda f: len(f["K"]))
        self.assertFlagged(ch, path, pc, "constant C=")

    def test_sequencing(self):
        for v in PUC_VMS:
            with self.subTest(v=v):
                self.check_unknown_opcode(v, "LOADK")
                self.check_successor(v, "LT", "LOADK" if v != "5.4" else "MOVE")
                self.check_no_return(v, "LOADK")

    def test_extraarg_and_empty(self):
        for v in PUC_VMS:
            with self.subTest(v=v):
                if "EXTRAARG" in ISA.ISAS[v].index:
                    ch = parse(v)
                    ch.root["code"][0] = ISA.encode(ch.isa, {"op": ch.isa.index["EXTRAARG"], "Ax": 0})
                    self.assertTrue(any("EXTRAARG after nothing" in i.msg for i in V.verify(ch) if i.pc == 0))
                ch = parse(v)
                ch.root["code"] = []
                self.assertIn("function has no instructions", [i.msg for i in V.verify(ch)])

    def test_unused_operand_is_a_warning(self):
        for v in PUC_VMS:
            with self.subTest(v=v):
                # in 5.1 the MOVEs after CLOSURE in main are upvalue pseudo-instructions; use f's MOVE
                ch, path, f, pc = self.break_op(v, "MOVE", child=True, C=1)
                self.assertFlagged(ch, path, pc, "unused operand C is 1", V.WARN)
                self.assertEqual(errors_at(ch, path, pc), [])
                self.assertEqual([i for i in V.verify(ch, soft=False) if i.pc == pc and i.path == path], [])



class LuaJIT(Common, unittest.TestCase):
    def setUp(self):
        if not LJ_VMS:
            self.skipTest("LuaJIT not available")

    def test_operand_ranges(self):
        for v in LJ_VMS:
            with self.subTest(v=v):
                ch, path, f, pc = self.break_op(v, "KSTR", A=lambda f: f["framesize"])
                self.assertFlagged(ch, path, pc, "slot A=")
                ch, path, f, pc = self.break_op(v, "KSTR", D=lambda f: len(f["kgc"]))
                self.assertFlagged(ch, path, pc, "GC constant D=")
                ch, path, f, pc = self.break_op(v, "UGET", D=lambda f: len(f["uv"]))
                self.assertFlagged(ch, path, pc, "upvalue D=")
                ch, path, f, pc = self.break_op(v, "KNUM", D=lambda f: len(f["kn"]))
                self.assertFlagged(ch, path, pc, "number constant D=")
                ch, path, f, pc = self.break_op(v, "KPRI", D=3)
                self.assertFlagged(ch, path, pc, "primitive D=3")
                ch, path, f, pc = self.break_op(v, "JMP", D=0xFFFF)
                self.assertFlagged(ch, path, pc, "jump target")
                ch, path, f, pc = self.break_op(v, "JMP", A=lambda f: f["framesize"] + 1)
                self.assertFlagged(ch, path, pc, "slot base A=")

    def test_constant_kind(self):
        for v in LJ_VMS:
            with self.subTest(v=v):
                def a_string(f):
                    n = len(f["kgc"])
                    return next(d for d in range(n) if f["kgc"][n - 1 - d][0] == "str")
                ch, path, f, pc = self.break_op(v, "FNEW", D=a_string)
                self.assertFlagged(ch, path, pc, "is a str, expected func")

    def test_sequencing(self):
        for v in LJ_VMS:
            with self.subTest(v=v):
                self.check_unknown_opcode(v, "KSTR")
                cmp = next(n for n in ("ISLT", "ISGE", "ISLE", "ISGT")
                           if any(ISA.get_field(w, ISA.ISAS[v].layout, "op") == ISA.ISAS[v].index[n]
                                  for _, f in parse(v).walk() for w in f["code"]))
                self.check_successor(v, cmp, "MOV")
                self.check_no_return(v, "KSTR")
                ch = parse(v)
                path, f, pc = find(ch, "KSTR")
                f["code"][pc] = ISA.set_field(f["code"][pc], ch.isa.layout, "op", ch.isa.index["JFORI"])
                self.assertFlagged(ch, path, pc, "runtime-only opcode")

    def test_unused_operand_is_a_warning(self):
        for v in LJ_VMS:
            with self.subTest(v=v):
                isa = ISA.ISAS[v]
                ch = parse(v)
                hit = None
                for path, f in ch.walk():
                    for pc, w in enumerate(f["code"]):
                        op = ISA.get_field(w, isa.layout, "op")
                        if op < isa.num and "___" in isa.roles[op]:
                            hit = path, f, pc, op
                            break
                    if hit:
                        break
                path, f, pc, op = hit
                fld = isa.operand_names(op)[isa.roles[op].index("___")]
                f["code"][pc] = ISA.set_field(f["code"][pc], isa.layout, fld, 1)
                self.assertFlagged(ch, path, pc, "unused operand %s is 1" % fld, V.WARN)


if __name__ == "__main__":
    unittest.main()
