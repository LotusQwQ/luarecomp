"""Standard and modified formats of every VM: byte-exact round trips, same behaviour."""
import unittest

from util import R, RT, VERSIONS, run, sources

AFFINE = {v: R.Profile({"lua": v, "signature": "1b4c4a" if v.startswith("luajit") else "47414d45",
                        "opcodes": {"type": "affine", "add": 11}}) for v in VERSIONS}


class Formats(unittest.TestCase):
    def test_standard_round_trip(self):
        for v in VERSIONS:
            st = R.standard(v)
            for name, src in sources(v):
                for strip in (False, True):
                    with self.subTest(v=v, src=name, strip=strip):
                        std = RT.compile_std(src, v, b"@" + name.encode(), strip)
                        self.assertEqual(R.dump(R.parse(std, st), st), std)

    def test_custom_round_trip_and_semantics(self):
        for v in VERSIONS:
            prof = AFFINE[v]
            for name, src in sources(v):
                with self.subTest(v=v, src=name):
                    std = RT.compile_std(src, v, b"@" + name.encode())
                    custom = R.compile(src, prof, b"@" + name.encode())
                    self.assertNotEqual(custom, std)
                    back = R.to_std(custom, prof)
                    self.assertEqual(back, std)
                    self.assertEqual(R.from_std(back, prof), custom)
                    self.assertEqual(run(back, v), run(std, v))

    def test_extended_encodings(self):
        # SETLIST overflow (EXTRAARG / 5.1 raw word) through a custom opcode map
        for v in VERSIONS:
            name, src = [s for s in sources(v, big=True) if s[0] == "bigsetlist"][0]
            with self.subTest(v=v):
                std = RT.compile_std(src, v)
                self.assertEqual(R.to_std(R.from_std(std, AFFINE[v]), AFFINE[v]), std)

    def test_wrong_vm_rejected(self):
        std = RT.compile_std(b"return 1", "5.3")
        with self.assertRaises(R.FormatError) as cm:
            R.parse(std, R.standard("5.4"))
        self.assertIn("version", str(cm.exception))
        self.assertIn("5.3", str(cm.exception))   # the hint names the right version

    def test_luajit_number_constants(self):
        from luarecomp import luajit as LJ
        for v in (0, 1, -1, 2 ** 31 - 1, -2 ** 31, 0.5, -0.0, 1e300, -1e-310, 4294967296.5, 3.0):
            self.assertEqual(LJ.kn_value(LJ.kn_encode(v)), v)

    def test_compile_error_message(self):
        with self.assertRaises(RT.CompileError) as cm:
            R.compile(b"local x = = 1", AFFINE["5.3"])
        self.assertIn("unexpected symbol", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
