import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import luarecomp as R  # noqa: E402
from luarecomp import runtime as RT  # noqa: E402
import corpus  # noqa: E402

ALL_VERSIONS = ("5.1", "5.2", "5.3", "5.4", "luajit2.0", "luajit2.1")


def _available(v):
    try:
        RT.runtime(v)
        return True
    except RT.RecompError:
        return False


# lupa does not ship LuaJIT for every platform (e.g. macOS arm64); tests for missing VMs are skipped.
# LUARECOMP_REQUIRE_ALL=1 (set in CI where all VMs exist) turns a missing VM into an error instead.
VERSIONS = tuple(v for v in ALL_VERSIONS if _available(v))
MISSING = tuple(v for v in ALL_VERSIONS if v not in VERSIONS)
if MISSING:
    if os.environ.get("LUARECOMP_REQUIRE_ALL") == "1":
        raise RuntimeError("Lua VMs missing from lupa: %s" % ", ".join(MISSING))
    sys.stderr.write("note: skipping tests for unavailable Lua VMs: %s\n" % ", ".join(MISSING))


SLOW = os.environ.get("LUARECOMP_SLOW") == "1"     # also run the huge-function corpus everywhere
DATA = os.path.join(HERE, "data")


def plain(values):
    """lupa results -> comparable Python values (tables compared by length)."""
    out = []
    for v in values:
        if v is None or isinstance(v, (bool, int, float, bytes)):
            out.append(v)
        else:
            try:
                out.append(("table", len(v)))
            except TypeError:
                out.append(type(v).__name__)
    return out


def run(std, lua):
    return plain(RT.run(std, lua))


def sources(lua, big=False):
    return corpus.sources(lua) + (corpus.big_sources(lua) if big or SLOW else [])
