#!/usr/bin/env python3
"""real_compare.py <name> <ghidra.dis> <workdir>: every instruction Ghidra found in a real program,
re-decoded by MAME unidasm (-arch xavix, black box) from the same bytes; reports agreement.
ghidra.dis lines: "<addr-hex> <bytes-hex> <text>"."""
import os, re, subprocess, sys
name, dis, work = sys.argv[1:4]
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from canon import canon
rows = []
for ln in open(dis):
    a, b, t = ln.rstrip("\n").split(" ", 2)
    rows.append((int(a, 16), bytes.fromhex(b), t))
binf = os.path.join(work, name + ".uni.bin")
with open(binf, "wb") as f:
    for a, b, t in rows: f.write(b + b"\0" * (8 - len(b)))
out = subprocess.run(["unidasm", binf, "-arch", "xavix", "-norawbytes", "-basepc", "0"], capture_output=True, text=True, check=True).stdout.splitlines()
uni = {}
for ln in out:
    m = re.match(r"^([0-9a-f]+): (.*)$", ln)
    if m: uni[int(m.group(1), 16)] = m.group(2)
agree = diff = 0
ex = []
for k, (a, b, t) in enumerate(rows):
    u = uni.get(k * 8)
    if u is None: diff += 1; ex.append((hex(a), b.hex(), t, None)); continue
    if canon(u, k * 8, True) == canon(t, a, False): agree += 1
    else: diff += 1; ex.append((hex(a), b.hex(), t, u))
print("%s: %d instructions re-decoded by unidasm: %d identical, %d different" % (name, len(rows), agree, diff))
for e in ex[:10]: print("   ", e)
sys.exit(1 if diff else 0)
