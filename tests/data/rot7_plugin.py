"""Fictional plugin used by the tests: instruction words are rotated by 7 bits on top of
the opcode map, and the file carries a 4-byte footer."""
from luarecomp import isa as I


def decode_instruction(w, ctx):
    w = ((w >> 7) | (w << 25)) & 0xFFFFFFFF
    p = ctx["profile"]
    return I.set_field(w, p.layout, "op", p.op_to_std[I.get_field(w, p.layout, "op")])


def encode_instruction(w, ctx):
    p = ctx["profile"]
    w = I.set_field(w, p.layout, "op", p.std_to_op[I.get_field(w, p.layout, "op")])
    return ((w << 7) | (w >> 25)) & 0xFFFFFFFF


def pre_read(data):
    if not data.endswith(b"END!"):
        raise ValueError("missing footer")
    return data[:-4]


def post_write(data):
    return data + b"END!"
