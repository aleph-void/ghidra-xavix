#!/usr/bin/env python3
"""Decode differential: Ghidra vs MAME unidasm -arch xavix (black box).

usage: diff_unidasm.py <workdir> [--random N] [--seed S] [--break]
Corpus: every opcode x every second byte x 12 third bytes x 4 fourth bytes (4-byte records,
distinct byte strings after truncation to the length unidasm reports), plus N random records.
--break corrupts one Ghidra result: the run must then report a difference.
"""
import os, random, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
work = args[0]
nrand, seed, brk = 200000, 1, False
i = 1
while i < len(args):
    if args[i] == "--random": nrand = int(args[i + 1]); i += 2
    elif args[i] == "--seed": seed = int(args[i + 1]); i += 2
    elif args[i] == "--break": brk = True; i += 1
    else: raise SystemExit("bad arg " + args[i])
os.makedirs(work, exist_ok=True)
LANG = os.environ.get("XAVIX_LANG", "XaviX:LE:24:default")
ARCH = "xavix"
THIRD = [0x00, 0x01, 0x12, 0x55, 0x7f, 0x80, 0x81, 0xa5, 0xc3, 0xfe, 0xff, 0x34]
FOURTH = [0x00, 0x56, 0x80, 0xff]
recs = [bytes([a, b, c, d]) for a in range(256) for b in range(256) for c in THIRD for d in FOURTH
        if (a == 0x22 or d == 0)]
rnd = random.Random(seed)
for _ in range(nrand):
    recs.append(bytes(rnd.randrange(256) for _ in range(4)))

binf = os.path.join(work, "rec.bin")
with open(binf, "wb") as f:
    for r in recs:
        f.write(r + b"\0" * 4)
p = subprocess.run(["unidasm", binf, "-arch", ARCH, "-norawbytes", "-basepc", "0"],
                   capture_output=True, text=True, check=True)
addr_text = []
for ln in p.stdout.splitlines():
    m = re.match(r"^([0-9a-f]+): (.*)$", ln)
    if m: addr_text.append((int(m.group(1), 16), m.group(2)))
bytext = dict(addr_text)
addrs = [a for a, _ in addr_text]
nxt = {addrs[k]: addrs[k + 1] for k in range(len(addrs) - 1)}
oracle = [(bytext.get(k * 8), nxt.get(k * 8, k * 8 + 1) - k * 8) for k in range(len(recs))]
# Branch operands are relative to the instruction, so compare them as offsets from the instruction
# address; unidasm saw the record at k*8, Ghidra at 0x1000.

uniq = {}
for r, (t, n) in zip(recs, oracle):
    uniq[r[:n]] = None
hexf = os.path.join(work, "cases.hex")
with open(hexf, "w") as f:
    for r in uniq: f.write(r.hex() + "\n")
outf = os.path.join(work, "ghidra.out")
subprocess.run([os.path.join(HERE, "dis.sh"), LANG, hexf, outf], check=True)
ghi = {}
for ln in open(outf):
    h, n, t = ln.rstrip("\n").split(" ", 2)
    ghi[bytes.fromhex(h)] = (int(n), t)
if brk:
    k0 = next(iter(ghi)); ghi[k0] = (ghi[k0][0], ghi[k0][1] + " 0x7")

from canon import canon

masked = agree = bad_len = diff = undec = 0
ex = {}
for k, (r, (t, n)) in enumerate(zip(recs, oracle)):
    key = r[:n]
    gn, gt = ghi.get(key, (0, "BAD"))
    if gt == "BAD":
        undec += 1; ex.setdefault("ghidra-undecoded", []).append((key.hex(), t, gt)); continue
    if gn != n:
        bad_len += 1; ex.setdefault("length", []).append((key.hex(), t, gt)); continue
    cm, cg = canon(t, k * 8, True), canon(gt, 0x1000, False)
    if cm == cg: agree += 1
    elif cm[0] == "callf" == cg[0] and int(cm[1][1:], 16) & 0x3fffff == int(cg[1][1:], 16):
        # explained: the 22-bit extbus masks the bank byte (bits 22-23 are not decoded)
        masked += 1
    else:
        diff += 1; ex.setdefault("text", []).append((key.hex(), t, gt))
print("records %d  distinct byte strings %d" % (len(recs), len(uniq)))
print("explained (callf bank byte masked to the 22-bit bus): %d" % masked)
print("agree %d  length-different %d  ghidra-undecoded %d  text-different %d" % (agree, bad_len, undec, diff))
for k, v in ex.items():
    print("--", k, len(v))
    for e in v[:15]: print("   ", e)
sys.exit(1 if (bad_len or undec or diff) else 0)
