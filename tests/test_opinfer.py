"""Opcode recovery with and without source."""
import random
import unittest

from util import R, RT, VERSIONS, sources
from luarecomp import isa as ISA, opinfer


class InferOps(unittest.TestCase):
    def test_affine_recovered_without_source(self):
        for v in VERSIONS:
            n = ISA.ISAS[v].num
            ops = {"type": "affine", "mul": 5 if n % 5 else 3, "add": 11, "mod": n}
            prof = R.Profile({"lua": v, "opcodes": ops})
            samples = [R.compile(s, prof) for _, s in sources(v)]
            res = opinfer.infer_ops(samples, R.Profile({"lua": v}))
            with self.subTest(v=v):
                self.assertEqual(res["affine"], [(ops["mul"], ops["add"], n)])

    def test_permutation_never_wrong(self):
        rnd = random.Random(1)
        for v in VERSIONS:
            n = ISA.ISAS[v].num
            perm = list(range(n))
            rnd.shuffle(perm)
            prof = R.Profile({"lua": v, "opcodes": {"type": "table", "map": perm}})
            samples = [R.compile(s, prof) for _, s in sources(v)]
            res = opinfer.infer_ops(samples, R.Profile({"lua": v}))
            with self.subTest(v=v):
                self.assertEqual(res["empty"], [])
                for c, dom in res["domains"].items():
                    self.assertIn(prof.op_to_std[c], dom)       # the truth is never eliminated

    def test_match_ops_tolerates_edits(self):
        prof = R.Profile({"opcodes": {"type": "affine", "add": 20}})
        src = sources("5.3")[0][1]
        custom = R.compile(src, prof, b"=x")
        edited = src.replace(b"local s = 0", b"local s = 0\nlocal extra = {1, 2, 3}\nprint(extra)")
        res = opinfer.match_ops([(custom, RT.compile_std(edited, "5.3", b"=x"))], R.Profile({}))
        exact = opinfer.match_ops([(custom, RT.compile_std(src, "5.3", b"=x"))], R.Profile({}))
        self.assertEqual(res["conflicts"], [])
        for s, c in res["mapping"].items():
            self.assertEqual(c, prof.std_to_op[s])
        # the edit shifts registers in the rest of the function; most opcodes are still found
        self.assertGreaterEqual(len(res["mapping"]), 0.7 * len(exact["mapping"]))

    def test_known_opcodes_resolve_groups(self):
        perm = list(range(47))
        random.Random(2).shuffle(perm)
        prof = R.Profile({"opcodes": {"type": "table", "map": perm}})
        samples = [R.compile(s, prof) for _, s in sources("5.3")]
        base = opinfer.infer_ops(samples, R.Profile({}))
        res = opinfer.infer_ops(samples, R.Profile({}), fixed={s: perm[s] for s in range(0, 47, 2)})
        self.assertGreater(len(res["determined"]), len(base["determined"]))
        for c, s in res["determined"].items():
            self.assertEqual(perm[s], c)


if __name__ == "__main__":
    unittest.main()
