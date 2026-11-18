# -*- coding: utf-8 -*-
"""Profiles: JSON descriptions of a (possibly modified) bytecode format.

A profile names the VM (``"lua": "5.1" | "5.2" | "5.3" | "5.4" | "luajit2.0" | "luajit2.1"``,
default 5.3 for compatibility with v1 profiles) and then describes how the container
differs from that VM's standard dump format.  Everything is optional; omitted keys take
the standard value.  See README.md for the full reference.
"""
import difflib
import importlib.util
import json
import os

from . import isa as ISA
from .errors import ProfileError, PluginError

STD_LUAC_DATA = b"\x19\x93\r\n\x1a\n"
SIZE_NAMES = ("int", "size_t", "instruction", "integer", "number")

# standard constant tags of each version
STD_TAGS = {
    "5.1": {"nil": 0, "boolean": 1, "number": 3, "string": 4},
    "5.2": {"nil": 0, "boolean": 1, "number": 3, "string": 4},
    "5.3": {"nil": 0, "boolean": 1, "float": 3, "integer": 0x13, "short_string": 4, "long_string": 0x14},
    "5.4": {"nil": 0, "false": 1, "true": 0x11, "integer": 3, "float": 0x13, "short_string": 4,
            "long_string": 0x14},
}

DEFAULT_SIZES = {
    "5.1": [["int", 4], ["size_t", 8], ["instruction", 4], ["number", 8]],
    "5.2": [["int", 4], ["size_t", 8], ["instruction", 4], ["number", 8]],
    "5.3": [["int", 4], ["size_t", 8], ["instruction", 4], ["integer", 8], ["number", 8]],
    "5.4": [["instruction", 4], ["integer", 8], ["number", 8]],
}

# header items of the standard dump, in order
STD_HEADER = {
    "5.1": ["signature", "version", "format", "endian", "@sizes", "integral"],
    "5.2": ["signature", "version", "format", "endian", "@sizes", "integral", "luac_data"],
    "5.3": ["signature", "version", "format", "luac_data", "@sizes", "luac_int", "luac_num", "nupvals"],
    "5.4": ["signature", "version", "format", "luac_data", "@sizes", "luac_int", "luac_num", "nupvals"],
}
HEADER_FIELDS = {
    "5.1": {"signature", "version", "format", "endian", "integral"},
    "5.2": {"signature", "version", "format", "endian", "integral", "luac_data"},
    "5.3": {"signature", "version", "format", "luac_data", "luac_int", "luac_num", "nupvals"},
    "5.4": {"signature", "version", "format", "luac_data", "luac_int", "luac_num", "nupvals"},
}

# order of the sections of a function prototype
STD_FUNCTION = {
    "5.1": ["source", "line", "lastline", "nupvals", "nparams", "vararg", "maxstack", "code",
            "constants", "protos", "lines", "locvars", "upnames"],
    "5.2": ["line", "lastline", "nparams", "vararg", "maxstack", "code", "constants", "protos",
            "upvals", "source", "lines", "locvars", "upnames"],
    "5.3": ["source", "line", "lastline", "nparams", "vararg", "maxstack", "code", "constants",
            "upvals", "protos", "lines", "locvars", "upnames"],
    "5.4": ["source", "line", "lastline", "nparams", "vararg", "maxstack", "code", "constants",
            "upvals", "protos", "lines", "abslines", "locvars", "upnames"],
}

STD_ENCODING = {
    "5.1": {"count": "i32", "line": "i32", "lineinfo": "i32", "pc": "i32", "string": "lua51"},
    "5.2": {"count": "i32", "line": "i32", "lineinfo": "i32", "pc": "i32", "string": "lua51"},
    "5.3": {"count": "i32", "line": "i32", "lineinfo": "i32", "pc": "i32", "string": "lua53"},
    "5.4": {"count": "varint", "line": "varint", "lineinfo": "i8", "pc": "varint", "string": "lua54"},
}
INT_ENCODINGS = ("i8", "u8", "i16", "u16", "i32", "u32", "varint", "uleb")
STRING_ENCODINGS = ("lua51", "lua53", "lua54", "count")
KEEP_TYPES = ("u8", "u16", "u32", "count", "string")

STD_SIGNATURE = {"puc": "1b4c7561", "luajit": "1b4c4a"}
STD_VERSION = {"5.1": 0x51, "5.2": 0x52, "5.3": 0x53, "5.4": 0x54, "luajit2.0": 1, "luajit2.1": 2}

KNOWN_KEYS = {
    "name", "_comment", "lua", "signature", "version", "format", "luac_data", "sizes", "endian",
    "luac_int", "luac_num", "check_luac_values", "integral", "const_tags", "opcodes", "header",
    "function", "encoding", "instruction", "strings", "plugin", "flags",
}


def _suggest(key, choices):
    m = difflib.get_close_matches(key, list(choices), n=1)
    return " (did you mean %r?)" % m[0] if m else ""


def _hex(v, key, src):
    if not isinstance(v, str):
        raise ProfileError("expected a hex string, got %r" % (v,), key, src)
    try:
        return bytes.fromhex(v.replace(" ", ""))
    except ValueError:
        raise ProfileError("not valid hex: %r" % v, key, src)


class Profile:
    """A parsed, validated profile.  Build with Profile(dict) or Profile.load(path_or_name)."""

    def __init__(self, d, source=None, base_dir=None, allow_plugins=False):
        if not isinstance(d, dict):
            raise ProfileError("profile must be a JSON object", None, source)
        self.raw, self.source = d, source
        for k in d:
            if k not in KNOWN_KEYS and not k.startswith("_"):
                raise ProfileError("unknown key%s" % _suggest(k, KNOWN_KEYS), k, source)
        self.name = d.get("name", "unnamed")
        lua = str(d.get("lua", "5.3"))
        if lua not in ISA.ISAS:
            raise ProfileError("unsupported VM %r; choose one of %s" % (lua, ", ".join(ISA.ISAS)), "lua", source)
        self.lua = lua
        self.isa = ISA.ISAS[lua]
        self.family = self.isa.family
        self.signature = _hex(d.get("signature", STD_SIGNATURE[self.family]), "signature", source)
        self.version = self._int(d, "version", STD_VERSION[lua], 0, 255)
        e = d.get("endian", "little")
        if e not in ("little", "big"):
            raise ProfileError("must be 'little' or 'big'", "endian", source)
        self.endian_name = e
        self.e = "<" if e == "little" else ">"
        self._strings(d)
        self._plugin(d, base_dir, allow_plugins)
        if self.family == "luajit":
            self._luajit(d)
        else:
            self._puc(d)
        self._opcodes(d.get("opcodes", {"type": "identity"}))
        self._instruction(d.get("instruction"))

    # ------------------------------------------------------------ helpers
    def _int(self, d, key, default, lo, hi):
        v = d.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ProfileError("expected an integer in %d..%d, got %r" % (lo, hi, v), key, self.source)
        return v

    def err(self, msg, key=None):
        return ProfileError(msg, key, self.source)

    # ------------------------------------------------------------ PUC Lua
    def _puc(self, d):
        v = self.lua
        self.format = self._int(d, "format", 0, 0, 255)
        ld = d.get("luac_data", STD_LUAC_DATA.hex())
        self.luac_data = _hex(ld, "luac_data", self.source) if ld else b""
        self.integral = self._int(d, "integral", 0, 0, 1)
        sizes = d.get("sizes", DEFAULT_SIZES[v])
        if isinstance(sizes, dict):
            sizes = list(sizes.items())
        try:
            self.size_fields = [(str(n), int(x)) for n, x in sizes]
        except (TypeError, ValueError):
            raise self.err('expected [["int", 4], ["size_t", 8], ...]', "sizes")
        self.sizes = {"int": 4, "size_t": 8, "instruction": 4, "integer": 8, "number": 8}
        for i, (n, x) in enumerate(self.size_fields):
            if n not in SIZE_NAMES:
                raise self.err("unknown size field %r%s" % (n, _suggest(n, SIZE_NAMES)), "sizes[%d]" % i)
            self.sizes[n] = x
        for n, ok in (("int", (4,)), ("size_t", (4, 8)), ("instruction", (4,)), ("integer", (4, 8)),
                      ("number", (4, 8))):
            if self.sizes[n] not in ok:
                raise self.err("%s size %d is not supported (supported: %s)" % (n, self.sizes[n], ok), "sizes")
        self.fmt_size_t = self.e + {4: "I", 8: "Q"}[self.sizes["size_t"]]
        self.fmt_integer = self.e + {4: "i", 8: "q"}[self.sizes["integer"]]
        self.fmt_number = self.e + {4: "f", 8: "d"}[self.sizes["number"]]
        if v in ("5.1", "5.2") and self.integral:
            self.fmt_number = self.e + {4: "i", 8: "q"}[self.sizes["number"]]
        self.luac_int = d.get("luac_int", 0x5678)
        self.luac_num = d.get("luac_num", 370.5)
        self.check_luac_values = bool(d.get("check_luac_values", True))
        self._header(d.get("header"))
        self._function(d.get("function"))
        enc = dict(STD_ENCODING[v])
        for k, val in (d.get("encoding") or {}).items():
            if k not in enc:
                raise self.err("unknown encoding key%s" % _suggest(k, enc), "encoding.%s" % k)
            allowed = STRING_ENCODINGS if k == "string" else INT_ENCODINGS
            if val not in allowed:
                raise self.err("must be one of %s" % ", ".join(allowed), "encoding.%s" % k)
            enc[k] = val
        self.enc = enc
        std = STD_TAGS[v]
        tags = dict(std)
        for k, val in (d.get("const_tags") or {}).items():
            if k not in std:
                raise self.err("unknown constant type for Lua %s%s; valid: %s"
                               % (v, _suggest(k, std), ", ".join(std)), "const_tags.%s" % k)
            tags[k] = val
        self.tag_to_std = {val: std[k] for k, val in tags.items()}
        self.std_to_tag = {std[k]: val for k, val in tags.items()}
        if len(self.tag_to_std) != len(std):
            raise self.err("values must be distinct: %r" % tags, "const_tags")

    def _header(self, items):
        v = self.lua
        if items is None:
            items = []
            for it in STD_HEADER[v]:
                if it == "@sizes":
                    items += ["size:" + n for n, _ in self.size_fields]
                elif it == "luac_data" and not self.luac_data:
                    continue
                else:
                    items.append(it)
        out = []
        for i, it in enumerate(items):
            key = "header[%d]" % i
            if isinstance(it, str):
                if it.startswith("size:"):
                    if it[5:] not in SIZE_NAMES:
                        raise self.err("unknown size field%s" % _suggest(it[5:], SIZE_NAMES), key)
                    out.append(("size", it[5:]))
                elif it in HEADER_FIELDS[v]:
                    out.append(("field", it))
                else:
                    raise self.err("unknown header field %r for Lua %s%s" % (it, v, _suggest(it, HEADER_FIELDS[v])), key)
            elif isinstance(it, dict) and "const" in it:
                out.append(("const", _hex(it["const"], key + ".const", self.source)))
            elif isinstance(it, dict) and "keep" in it:
                n = it["keep"]
                if not isinstance(n, int) or n <= 0:
                    raise self.err("keep needs a positive byte count", key)
                fill = _hex(it.get("fill", "00" * n), key + ".fill", self.source)
                if len(fill) != n:
                    raise self.err("fill must be %d bytes" % n, key)
                out.append(("keep", n, fill))
            else:
                raise self.err('expected a field name, {"const": hex} or {"keep": n}', key)
        names = [x[1] for x in out if x[0] == "field"]
        if "signature" not in names:
            raise self.err("the header must contain 'signature'", "header")
        self.header_items = out

    def _function(self, items):
        v = self.lua
        std = STD_FUNCTION[v]
        if items is None:
            self.func_sections = [("field", s) for s in std]
            return
        out, seen = [], set()
        for i, it in enumerate(items):
            key = "function[%d]" % i
            if isinstance(it, str):
                if it not in std:
                    raise self.err("unknown section %r for Lua %s%s" % (it, v, _suggest(it, std)), key)
                if it in seen:
                    raise self.err("section %r listed twice" % it, key)
                seen.add(it)
                out.append(("field", it))
            elif isinstance(it, dict) and "keep" in it:
                if it["keep"] not in KEEP_TYPES:
                    raise self.err("keep type must be one of %s" % ", ".join(KEEP_TYPES), key)
                out.append(("keep", it["keep"], it.get("fill", "" if it["keep"] == "string" else 0)))
            elif isinstance(it, dict) and "const" in it:
                out.append(("const", _hex(it["const"], key + ".const", self.source)))
            else:
                raise self.err('expected a section name, {"keep": type} or {"const": hex}', key)
        missing = [s for s in std if s not in seen]
        if missing:
            raise self.err("sections missing: %s (every standard section must appear once)"
                           % ", ".join(missing), "function")
        self.func_sections = out

    # ------------------------------------------------------------ LuaJIT
    def _luajit(self, d):
        for k in ("format", "luac_data", "sizes", "luac_int", "luac_num", "integral", "const_tags",
                  "header", "function", "encoding"):
            if k in d:
                raise self.err("not used for LuaJIT profiles", k)
        f = d.get("flags")
        if f is not None and (not isinstance(f, int) or f < 0):
            raise self.err("expected a non-negative integer", "flags")
        self.flags = f

    # ------------------------------------------------------------ opcodes / instruction layout
    def _opcodes(self, spec):
        isa = self.isa
        n = isa.num
        if not isinstance(spec, dict):
            raise self.err("expected an object", "opcodes")
        t = spec.get("type", "identity")
        if t == "identity":
            fwd = list(range(n))
        elif t == "affine":
            mul, add, mod = spec.get("mul", 1), spec.get("add", 0), spec.get("mod", n)
            fwd = [(s * mul + add) % mod for s in range(n)]
        elif t == "table":
            fwd = spec.get("map")
            if not isinstance(fwd, list) or len(fwd) != n:
                raise self.err("map must list %d numbers (map[standard] = custom) for %s"
                               % (n, isa.key), "opcodes.map")
        elif t == "names":
            m = spec.get("map")
            if not isinstance(m, dict):
                raise self.err('map must be {"MOVE": 11, ...}', "opcodes.map")
            unknown = [k for k in m if k not in isa.index]
            if unknown:
                raise self.err("unknown opcode name %r%s" % (unknown[0], _suggest(unknown[0], isa.names)),
                               "opcodes.map")
            missing = [x for x in isa.names if x not in m]
            if missing:
                raise self.err("%d opcodes missing: %s" % (len(missing), " ".join(missing)), "opcodes.map")
            fwd = [m[x] for x in isa.names]
        else:
            raise self.err("type must be identity, affine, table or names", "opcodes.type")
        self.op_width_hint = max(fwd) if fwd else 0
        seen = {}
        for s, c in enumerate(fwd):
            if not isinstance(c, int) or isinstance(c, bool) or c < 0:
                raise self.err("custom opcode for %s must be a non-negative integer, got %r" % (isa.names[s], c),
                               "opcodes")
            if c in seen:
                raise self.err("%s and %s both map to custom opcode %d (the map must be one-to-one)"
                               % (isa.names[seen[c]], isa.names[s], c), "opcodes")
            seen[c] = s
        self.std_to_op = dict(enumerate(fwd))
        self.op_to_std = {c: s for s, c in enumerate(fwd)}
        self.opcodes_identity = fwd == list(range(n))

    def _instruction(self, spec):
        isa = self.isa
        self.layout = dict(isa.layout)
        self.biases = dict(isa.biases)
        self.custom_layout = False
        if spec is None:
            self._check_op_range()
            return
        if not isinstance(spec, dict):
            raise self.err("expected an object", "instruction")
        for k, v in spec.items():
            if k.endswith("_bias"):
                f = k[:-5]
                if f not in self.biases:
                    raise self.err("no signed field %r in %s" % (f, isa.key), "instruction." + k)
                self.biases[f] = v
            elif k in self.layout:
                if (not isinstance(v, list) or len(v) != 2 or not all(isinstance(x, int) for x in v)
                        or v[0] < 0 or v[1] <= 0 or v[0] + v[1] > 32):
                    raise self.err("expected [bit_position, width] within 32 bits", "instruction." + k)
                self.layout[k] = tuple(v)
            else:
                raise self.err("unknown field%s; fields: %s" % (_suggest(k, self.layout), ", ".join(self.layout)),
                               "instruction." + k)
        self.custom_layout = self.layout != isa.layout or self.biases != isa.biases
        for f, (p, w) in self.layout.items():
            if f in ("Bx", "Ax", "sJ", "D"):
                continue  # composite fields overlap the small ones by design
            for g, (q, x) in self.layout.items():
                if g <= f or g in ("Bx", "Ax", "sJ", "D"):
                    continue
                if p < q + x and q < p + w:
                    raise self.err("fields %s and %s overlap" % (f, g), "instruction")
        self._check_op_range()

    def _check_op_range(self):
        w = self.layout["op"][1]
        big = [c for c in self.std_to_op.values() if c >= 1 << w]
        if big:
            raise self.err("custom opcode %d does not fit in the %d-bit op field" % (big[0], w), "opcodes")

    # ------------------------------------------------------------ strings / plugin
    def _strings(self, d):
        s = d.get("strings")
        self.string_xor = None
        self.string_scope = ()
        if s is None:
            return
        if not isinstance(s, dict) or s.get("type") != "xor":
            raise self.err('only {"type": "xor", "key": hex} is built in; use a plugin for others', "strings")
        key = _hex(s.get("key", ""), "strings.key", self.source)
        if not key:
            raise self.err("empty key", "strings.key")
        scope = s.get("scope", ["constants"])
        bad = [x for x in scope if x not in ("constants", "source", "names")]
        if bad:
            raise self.err("scope entries must be constants, source or names", "strings.scope")
        self.string_xor, self.string_scope = key, tuple(scope)

    def _plugin(self, d, base_dir, allow):
        self.plugin = None
        path = d.get("plugin")
        if path is None:
            return
        if base_dir and not os.path.isabs(path):
            path = os.path.join(base_dir, path)
        if not allow:
            raise PluginError("profile %r uses plugin %s; plugins run arbitrary Python code, so they are "
                              "only loaded when you pass --allow-plugin (allow_plugins=True)"
                              % (self.name, path))
        if not os.path.exists(path):
            raise self.err("plugin file not found: %s" % path, "plugin")
        spec = importlib.util.spec_from_file_location("luarecomp_plugin_%d" % id(self), path)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as exc:  # noqa: BLE001 - surface any plugin import failure
            raise PluginError("plugin %s failed to import: %s: %s" % (path, type(exc).__name__, exc))
        hooks = ("pre_read", "post_write", "decode_string", "encode_string", "decode_instruction",
                 "encode_instruction", "read_keep", "write_keep")
        if not any(hasattr(mod, h) for h in hooks):
            raise PluginError("plugin %s defines none of the hooks: %s" % (path, ", ".join(hooks)))
        self.plugin = mod

    def hook(self, name):
        return getattr(self.plugin, name, None) if self.plugin else None

    # ------------------------------------------------------------ loading
    @classmethod
    def load(cls, path_or_name, allow_plugins=False):
        path = path_or_name
        if not os.path.exists(path):
            here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "profiles")
            cand = os.path.join(here, path_or_name + ".json")
            if not os.path.exists(cand):
                names = sorted(f[:-5] for f in os.listdir(here) if f.endswith(".json")) if os.path.isdir(here) else []
                raise ProfileError("no such file, and no built-in profile of that name%s; built-in: %s"
                                   % (_suggest(path_or_name, names), ", ".join(names)), None, path_or_name)
            path = cand
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except json.JSONDecodeError as exc:
            raise ProfileError("invalid JSON at line %d column %d: %s" % (exc.lineno, exc.colno, exc.msg),
                               None, path)
        return cls(d, source=path, base_dir=os.path.dirname(os.path.abspath(path)), allow_plugins=allow_plugins)

    def to_dict(self):
        return dict(self.raw)

    def __repr__(self):
        return "<Profile %s (%s)>" % (self.name, self.lua)


_STANDARD = {}


def standard(lua):
    """The standard (unmodified) profile of a VM."""
    if lua not in _STANDARD:
        _STANDARD[lua] = Profile({"name": "standard-" + lua, "lua": lua})
    return _STANDARD[lua]
