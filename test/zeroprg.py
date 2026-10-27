#!/usr/bin/env python3
"""zeroprg.py <in.prg> <out.prg>: re-pack a sim65 program so that it is loaded at $0000 with all RAM
below $FFC0 zero-filled (sim65 otherwise starts with 0xFF-filled RAM; Ghidra's emulator starts with
zeros).  Reset address and everything else are unchanged."""
import sys
f = open(sys.argv[1], "rb").read()
load = int.from_bytes(f[8:10], "little")
img = f[12:]
hdr = f[:8] + (0).to_bytes(2, "little") + f[10:12]
open(sys.argv[2], "wb").write(hdr + bytes(load) + img + bytes(max(0, 0xFFC0 - load - len(img))))
