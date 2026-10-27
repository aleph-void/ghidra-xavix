#!/usr/bin/env python3
"""executed.py <name> <sim65> <zero-filled .prg> <ghidra.dis> [entries-out]

Every instruction address that sim65 executes (its --trace) must be the start of an instruction, of
the same length, in the listing Ghidra recovered by analysis.  Programs that patch their own code
(cc65's callmain trampoline `jmp $0000` is filled in at run time) cannot be followed statically;
the targets of such instructions (rows whose bytes differ from the image) are written to
entries-out so that a second import can start there.  Exit status 1 if anything is missing."""
import re, subprocess, sys
name, sim, prg, dis = sys.argv[1:5]
entries_out = sys.argv[5] if len(sys.argv) > 5 else None
img = open(prg, "rb").read()[12:]          # loaded at $0000
starts, bit_abs = {}, set()
for l in open(dis):
    a, b, _ = l.split(" ", 2)
    starts[int(a, 16)] = len(b) // 2
    if b.startswith("2c"):          # BIT abs: cc65 hides a 2-byte instruction in its operand to skip it
        bit_abs.update((int(a, 16) + 1, int(a, 16) + 2))
out = subprocess.run([sim, "--trace", prg], capture_output=True, text=True).stdout
seen, patched = {}, set()
for ln in out.splitlines():
    m = re.search(r"\d+\s+\d+\s+([0-9A-F]{4})\s+((?:[0-9A-F]{2} )+)\s+(\w+)", ln)
    if not m: continue
    a = int(m.group(1), 16)
    b = bytes(int(x, 16) for x in m.group(2).split())
    seen[a] = len(b)
    if img[a:a + len(b)] != b and m.group(3) in ("jmp", "jsr") and len(b) == 3:
        patched.add(b[1] | (b[2] << 8))
miss, overlap = [], 0
for a, n in sorted(seen.items()):
    if a in starts and starts[a] == n: continue
    if a in bit_abs: overlap += 1; continue       # an instruction inside another one cannot be listed twice
    miss.append((hex(a), n))
print("%s: sim65 executed %d distinct instruction addresses; %d are not instruction starts of the same length in Ghidra's listing (+ %d inside a BIT abs operand, the skip idiom)" % (name, len(seen), len(miss), overlap))
for m in miss[:10]: print("   ", m)
if entries_out:
    open(entries_out, "w").write("".join("%x\n" % a for a in sorted(patched)))
sys.exit(1 if miss else 0)
