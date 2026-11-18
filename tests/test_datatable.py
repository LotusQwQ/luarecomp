"""Data tables: run -> JSON -> build -> run is exact; the generated source is plain Lua."""
import json
import os
import tempfile
import unittest

from util import R, VERSIONS
from luarecomp import datatable as T

# a fictional game data table: records built through a host constructor, an index keyed by
# id then owner, and every awkward kind of key and value
TABLE = r"""
local rows = {}
local index = {}
local function add(fields)
  rows[#rows + 1] = Make("ItemData", fields)
  index[fields.id] = index[fields.id] or {}
  index[fields.id][fields.owner] = #rows
end
add({id = 10, owner = 101, name = "sword", tags = {3, 1, 2}, extra = {}, rate = 0.25, on = true})
add({id = 10, owner = 202, name = "sword+", tags = {}, extra = {[5] = "five", ["7"] = "seven"}})
add({id = 11, owner = 101, name = "\0bin\255", big = 9007199254740993, neg = -3, f = 1.0, nested = {a = {b = {c = 1}}}})
local odd = {[true] = 1, [2.5] = "x", ["and"] = 3, ["with space"] = 4}
return {rows, index}, odd, "tail", 42, 0.5
"""

# big enough (> 8 entries per container) for the one-element-per-line layout of build-table
BIG = r"""
local rows, index, names = {}, {}, {}
for i = 1, 20 do
  rows[i] = Make("ItemData", {id = i, owner = 100 + i % 3, name = "item" .. i})
  index[i] = index[i] or {}
  index[i][100 + i % 3] = i
end
for i = 1, 12 do names["n" .. i] = i * 0.5 end
return {rows, index}, names, "small"
"""


class DataTable(unittest.TestCase):
    def test_round_trip_every_vm(self):
        for v in VERSIONS:
            prof = R.Profile({"lua": v, "opcodes": {"type": "affine", "add": 9}})
            with self.subTest(v=v):
                chunk = R.compile(TABLE.encode(), prof)
                first = T.run(chunk, prof, records=["Make"])
                built, src = T.build(first, prof, constructor="Make")
                self.assertEqual(T.diff(first, T.run(built, prof, records=["Make"])), [])
                self.assertEqual(json.loads(json.dumps(first)), first)       # JSON-safe

    def test_big_tables_one_element_per_line(self):
        prof = R.Profile({})
        data = T.run(R.compile(BIG.encode(), prof), prof, records=["Make"])
        built, src = T.build(data, prof, constructor="Make")
        self.assertEqual(T.diff(data, T.run(built, prof, records=["Make"])), [])
        lines = src.splitlines()
        self.assertIn(b"local r1 = {r1_1, r1_2}", lines)      # {rows, index} split into locals
        for name in (b"r1_1", b"r1_2", b"r2"):
            self.assertIn(b"local " + name + b" = {", lines)
        self.assertGreater(len(lines), 20 + 12)                # one row / key per line
        self.assertIn(b'local r3 = "small"', lines)

    def test_json_shape(self):
        prof = R.Profile({})
        data = T.run(R.compile(TABLE.encode(), prof), prof, records=["Make"])
        rows, index = data[0]
        self.assertEqual(rows[0]["__type"], "ItemData")
        self.assertEqual(index["10"], {"101": 1, "202": 2})             # id -> owner -> row
        self.assertEqual(index["11"], {"101": 3})
        self.assertIn("__pairs__", rows[1]["extra"])                     # int 5 and string "7"
        self.assertEqual(rows[2]["name"], {"__bytes__": "0062696eff"})
        self.assertIsInstance(rows[2]["f"], float)
        self.assertEqual(rows[2]["big"], 9007199254740993)
        self.assertIn("__pairs__", data[1])
        self.assertEqual(data[2:], ["tail", 42, 0.5])

    def test_diff_reports_paths(self):
        a = [{"x": [1, 2, {"y": 3}]}]
        b = [{"x": [1, 2, {"y": 4}], "z": 1}]
        d = T.diff(a, b)
        self.assertIn("return[1].x[3].y: 3 vs 4", d)
        self.assertIn("return[1].z: only in the second", d)

    def test_cli(self):
        from test_cli import call
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "t.lua")
            with open(src, "w") as f:
                f.write(TABLE)
            orig = os.path.join(d, "t.bytes")
            js = os.path.join(d, "t.json")
            out = os.path.join(d, "u.bytes")
            self.assertEqual(call("compile", src, "-p", "example_custom", "-o", orig)[0], 0)
            self.assertEqual(call("run", "-p", "example_custom", orig, "--record", "Make", "-o", js)[0], 0)
            rc, o, e = call("build-table", js, "-p", "example_custom", "-o", out, "--constructor", "Make",
                            "--compare", orig, "--source", os.path.join(d, "u.lua"))
            self.assertEqual(rc, 0, o + e)
            self.assertIn("returns exactly the input data", o)
            self.assertIn("identical results", o)
            with open(js, encoding="utf-8") as f:
                data = json.load(f)
            data[0][0][0]["name"] = "axe"
            with open(js, "w", encoding="utf-8") as f:
                json.dump(data, f)
            rc, o, e = call("build-table", js, "-p", "example_custom", "-o", out, "--constructor", "Make",
                            "--compare", orig)
            self.assertEqual(rc, 1)
            self.assertIn('return[1][1][1].name: "sword" vs "axe"', o)     # original first


if __name__ == "__main__":
    unittest.main()
