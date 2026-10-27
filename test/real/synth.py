#!/usr/bin/env python3
"""synth.py <out.bin> <entries.txt>: one tiny function per opcode (the opcode with benign operands,
then RTS), 16 bytes apart from $8000, for the decompiler check.  Control-flow opcodes that need a
target (branches, JMP, JSR, CALLF) get one that stays inside the function."""
import sys
out, ents = sys.argv[1:3]
img = bytearray(0x100 * 16)
lines = []
for op in range(256):
    a = op * 16
    if op in (0x20, 0x4C): body = bytes([op, (a + 0x80) & 0xFF, 0x80]) + b"\x60"       # JSR/JMP to the RTS
    elif op == 0x6C: body = bytes([op, 0x00, 0x02]) + b"\x60"
    elif op == 0x22: body = bytes([op, 0x00]) + (0x8000 + a + 4).to_bytes(2, "little") + b"\x80"   # CALLF to the RETF after it
    elif op in (0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0): body = bytes([op, 0x00, 0x60])
    elif op == 0x00: body = b"\x00\x60"
    else: body = bytes([op, 0x12, 0x02]) + b"\x60"
    img[a:a + len(body)] = body
    lines.append("%x" % (0x8000 + a))
open(out, "wb").write(img)
open(ents, "w").write("\n".join(lines) + "\n")
