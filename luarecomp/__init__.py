# -*- coding: utf-8 -*-
"""luarecomp -- compile Lua source into modified bytecode formats, and back.

Supports PUC Lua 5.1 / 5.2 / 5.3 / 5.4 and LuaJIT 2.0 / 2.1.  A format is described by a
JSON profile (see README.md).  Compilation is done by the real VM through lupa; this
package only converts between the standard dump format and the modified one.
"""
from .core import (compile, compile_chunk, convert, dump, from_std, load_check, parse,  # noqa: F401
                   to_std)
from .errors import FormatError, PluginError, ProfileError, RecompError, VerifyError  # noqa: F401
from .profile import Profile, standard  # noqa: F401
from .puc import Chunk  # noqa: F401

__version__ = "2.0.0"
