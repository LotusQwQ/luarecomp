# -*- coding: utf-8 -*-
"""Exceptions that carry enough context to find the problem.

Every parse error knows *where* it happened: the byte offset, the structural path
(``main/3/1``), the field being read, and optionally a hint about the likely cause.
``str(exc)`` gives a one-line message; ``exc.report(data)`` adds a hex dump around
the offset and the trail of fields that were read successfully just before.
"""


class RecompError(Exception):
    """Base class for all errors raised by luarecomp."""


class ProfileError(RecompError, ValueError):
    """A profile JSON is invalid.  ``key`` is the JSON path of the offending field.
    (Also a ValueError, which is what v1 raised.)"""

    def __init__(self, msg, key=None, source=None):
        self.key, self.source = key, source
        where = ""
        if source:
            where += "%s: " % source
        if key:
            where += "%s: " % key
        super().__init__(where + msg)


class PluginError(RecompError):
    pass


class FormatError(RecompError):
    """Bytes do not match the expected format."""

    def __init__(self, msg, offset=None, path=None, field=None, hint=None, trail=None):
        self.msg, self.offset, self.path, self.field, self.hint = msg, offset, path, field, hint
        self.trail = list(trail or [])
        self.data = None
        super().__init__(self._line())

    def _line(self):
        loc = []
        if self.offset is not None:
            loc.append("offset %d (0x%x)" % (self.offset, self.offset))
        if self.path:
            loc.append(self.path)
        if self.field:
            loc.append("field %s" % self.field)
        s = self.msg
        if loc:
            s = "%s [%s]" % (s, ", ".join(loc))
        if self.hint:
            s += "\n  hint: " + self.hint
        return s

    def report(self, data=None, context=32):
        if data is None:
            data = self.data
        lines = [self._line()]
        if self.trail:
            lines.append("  last fields read successfully:")
            for off, path, field, val in self.trail[-8:]:
                lines.append("    @%-8d %-28s %-14s %s" % (off, path, field, _short(val)))
        if data is not None and self.offset is not None:
            lines.append("  bytes around offset %d:" % self.offset)
            lines.extend("    " + l for l in hexdump(data, self.offset, context))
        return "\n".join(lines)


class VerifyError(RecompError):
    """Bytecode parsed fine but is semantically impossible (see verify.py)."""


def _short(v, n=48):
    r = repr(v)
    return r if len(r) <= n else r[:n - 3] + "..."


def hexdump(data, center, context=32, mark=None):
    """Hex dump of data[center-context : center+context], marking byte `mark` (default center)."""
    if mark is None:
        mark = center
    start = max(0, (center - context) // 16 * 16)
    end = min(len(data), center + context)
    out = []
    for row in range(start, end, 16):
        chunk = data[row:row + 16]
        cells = []
        for i, b in enumerate(chunk):
            cells.append(("[%02x]" if row + i == mark else " %02x " ) % b)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%08x %s  %s" % (row, "".join(cells), asc))
    if center >= len(data):
        out.append("%08x  <end of data, %d bytes total>" % (len(data), len(data)))
    return out
