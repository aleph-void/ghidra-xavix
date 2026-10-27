#!/usr/bin/env python3
"""Semantic differential: Ghidra's p-code emulation of random 6502 instruction sequences versus the
cc65 project's sim65 simulator (--cpu 6502X, run as a black box with --trace).

usage: diff_sim65.py <workdir> [--n N] [--seed S] [--legal] [--break]
Each test is a preamble (stack pointer, flags, a few memory cells, A/X/Y), 1-8 random non-control
opcodes (and conditional branches over 0-3 NOPs) with operands near the data cells, and an epilogue reading back the cells.  The register
state (A X Y S N V D I Z C) before every instruction is compared with sim65's trace.  Tests during
which the program wrote the XaviX bank registers (lowbus:FE/FF) are skipped (a flat 64K machine
has no such registers).  --legal restricts the pool to documented NMOS opcodes; ANE/LXA/LAS (whose
results are chip specific) are only included with --unstable.
Addressing modes/lengths come from unidasm -arch xavix (black box).  Environment: SIM65 (sim65).
"""
import os, random, re, subprocess, sys, collections, concurrent.futures as cf

HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
work = args[0]; N = 3000; seed = 1; legal = False; brk = False; unstable = False
i = 1
while i < len(args):
    if args[i] == "--n": N = int(args[i + 1]); i += 2
    elif args[i] == "--seed": seed = int(args[i + 1]); i += 2
    elif args[i] == "--legal": legal = True; i += 1
    elif args[i] == "--unstable": unstable = True; i += 1
    elif args[i] == "--break": brk = True; i += 1
    else: raise SystemExit("bad arg " + args[i])
os.makedirs(work, exist_ok=True)
SIM = os.environ.get("SIM65", "sim65")

# --- opcode table (mode, mnemonic) from unidasm
tab = os.path.join(work, "optab.bin")
open(tab, "wb").write(b"".join(bytes([op, 0x12, 0x34, 0, 0, 0, 0, 0]) for op in range(256)))
txt = subprocess.run(["unidasm", tab, "-arch", "xavix", "-norawbytes", "-basepc", "0"], capture_output=True, text=True, check=True).stdout.splitlines()
modes = {}
mnem = {}
for ln in txt:
    m = re.match(r"^([0-9a-f]+): (\w+)\s*(.*)$", ln)
    if not m: continue
    a, mn, ops = int(m.group(1), 16), m.group(2), m.group(3).strip()
    if a % 8: continue
    op = a // 8
    mnem[op] = mn
    if ops == "" or ops == "a": mode = "imp"
    elif ops.startswith("#"): mode = "imm"
    elif ops.endswith(", x)"): mode = "izx"
    elif ops.endswith("), y"): mode = "izy"
    elif ops.endswith(", x"): mode = "zpx" if len(ops) <= 7 else "abx"
    elif ops.endswith(", y"): mode = "zpy" if len(ops) <= 7 else "aby"
    elif len(ops) <= 3: mode = "zp"
    else: mode = "abs"
    modes[op] = mode

CONTROL = {0x00, 0x20, 0x40, 0x4C, 0x60, 0x6C, 0x22, 0x80,
           0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0,
           0x02, 0x12, 0x32, 0x42, 0x52, 0x62, 0x72, 0x92, 0xB2, 0xD2, 0xF2}
LEGAL_MN = set("adc and asl bit clc cld cli clv cmp cpx cpy dec dex dey eor inc inx iny lda ldx ldy lsr nop ora pha php pla plp rol ror sbc sec sed sei sta stx sty tax tay tsx txa txs tya".split())
UNSTABLE = {0x8B, 0xAB, 0xBB}    # ANE, LXA, LAS: chip-specific results, excluded unless --unstable
pool = [o for o in range(256) if o not in CONTROL and (unstable or o not in UNSTABLE) and (not legal or (mnem[o] in LEGAL_MN and o in
        {x for x in range(256) if not (mnem[x] == "nop" and x != 0xEA)}))]
rnd = random.Random(seed)

def operand(mode):
    if mode == "imp": return b""
    if mode == "imm": return bytes([rnd.randrange(256)])
    if mode in ("zp",): return bytes([rnd.choice([0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13])])
    if mode in ("zpx", "zpy"): return bytes([rnd.choice([0x10, 0x11, 0x12, 0x13, 0x14, 0x15])])
    if mode in ("izx", "izy"): return bytes([rnd.choice([0x00, 0x02, 0x04, 0x10, 0x12])])
    base = rnd.choice([0x0200, 0x0201, 0x0202, 0x0203, 0x0210, 0x0001, 0x0002])
    return base.to_bytes(2, "little")

def gen():
    p = bytearray()
    p += bytes([0xA2, rnd.randrange(0x30), 0x9A])                      # ldx #s ; txs
    p += bytes([0xA9, (rnd.randrange(256) & 0xCF) | (0x08 if rnd.random() < .3 else 0), 0x48, 0x28])  # flags
    for _ in range(rnd.randrange(3, 9)):
        v = rnd.randrange(256)
        cell = rnd.choice([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x0200, 0x0201, 0x0202, 0x0203, 0x0210, 0x0211, 0x0212])
        # pointers in zero page must stay in RAM below $8000 to keep both models flat
        if cell < 0x20: v &= 0x7F
        p += bytes([0xA9, v]) + (bytes([0x85, cell]) if cell < 0x100 else bytes([0x8D, cell & 0xFF, cell >> 8]))
    p += bytes([0xA2, rnd.randrange(0x10), 0xA0, rnd.randrange(0x10), 0xA9, rnd.randrange(256)])
    for _ in range(rnd.randrange(1, 9)):
        if rnd.random() < 0.2:      # conditional branch over 0-3 NOPs (taken or not, both reach a boundary)
            k = rnd.choice([0, 1, 2, 3])
            p += bytes([rnd.choice([0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0]), k]) + bytes([0xEA]) * k
            continue
        o = rnd.choice(pool)
        p += bytes([o]) + operand(modes[o])
    for c in list(range(0x20)) + list(range(0x0200, 0x0220)):
        p += bytes([0xA5, c]) if c < 0x100 else bytes([0xAD, c & 0xFF, c >> 8])
    return bytes(p)

progs = [gen() for _ in range(N)]
hexf = os.path.join(work, "tests.hex")
open(hexf, "w").write("\n".join(p.hex() for p in progs) + "\n")

def run_sim(k):
    f = os.path.join(work, "t%d.prg" % k)
    # load at $0000 with all RAM below $FFF0 zero-filled: sim65's RAM is otherwise 0xFF-filled
    hdr = b"sim65" + bytes([2, 0, 0x00]) + (0).to_bytes(2, "little") + (0x8000).to_bytes(2, "little")
    open(f, "wb").write(hdr + bytes(0x8000) + progs[k] + bytes([0x4C, 0xF9, 0xFF]) + bytes(0xFFC0 - 0x8000 - len(progs[k]) - 3))
    r = subprocess.run([SIM, "--cpu", "6502X", "--trace", f], capture_output=True, text=True)
    os.remove(f)
    states = []
    for ln in r.stdout.splitlines():
        m = re.search(r"A=([0-9A-F]{2}) X=([0-9A-F]{2}) Y=([0-9A-F]{2}) S=([0-9A-F]{2}) Flags=(\w{6})", ln)
        a = re.match(r"\s*\d+\s+\d+\s+([0-9A-F]{4})", ln)
        if m and a:
            fl = "".join("1" if c.isupper() else "0" for c in m.group(5))
            states.append((int(a.group(1), 16), int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16), fl))
    return states

with cf.ThreadPoolExecutor(8) as ex:
    sims = list(ex.map(run_sim, range(N)))
outf = os.path.join(work, "ghidra.out")
subprocess.run([os.path.join(HERE, "trace-run.sh"), hexf, outf], check=True)

def parse(path):
    res, cur = [], None
    for ln in open(path):
        ln = ln.rstrip("\n")
        if ln.startswith("T "): cur = {"st": [], "end": None, "err": None, "mem": []}; res.append(cur)
        elif ln.startswith("END"): cur["end"] = tuple(int(x, 16) for x in ln.split()[1:])
        elif ln.startswith("ERR"): cur["err"] = ln
        elif ln.startswith("M "): cur["mem"].append(bytes.fromhex(ln[2:]))
        else:
            f = ln.split()
            cur["st"].append((int(f[0], 16), int(f[1], 16), int(f[2], 16), int(f[3], 16), int(f[4], 16), f[5]))
    return res

ghi = parse(outf)
assert len(ghi) == N, (len(ghi), N)

ok = skipped = bad = errs = 0
buckets = collections.Counter(); examples = {}
izy_cands = []
for k in range(N):
    g, s = ghi[k], sims[k]
    if g["end"] != (0, 0):
        skipped += 1; continue
    if g["err"]:
        errs += 1; examples.setdefault("emulation error", []).append((k, g["err"])); continue
    gs = g["st"]
    if brk and k == 0:
        j = len(gs) // 2; gs[j] = gs[j][:1] + (gs[j][1] ^ 1,) + gs[j][2:]
    s = s[:len(gs)]            # sim65 also traces the final jmp
    div = next((j for j in range(min(len(gs), len(s))) if gs[j] != s[j]), None)
    if div is None and len(gs) == len(s):
        ok += 1; continue
    j = div if div is not None else min(len(gs), len(s))
    pc = gs[j - 1][0] if j > 0 else gs[0][0]
    op = progs[k][pc - 0x8000]
    if modes[op] == "izy":
        izy_cands.append((k, j - 1, op)); continue
    bad += 1
    key = "%02X %s" % (op, mnem[op])
    buckets[key] += 1
    examples.setdefault(key, []).append((k, j, gs[j] if j < len(gs) else None, s[j] if j < len(s) else None))

# (zp),Y divergences: sim65 keeps its counter peripheral ($FFC0-$FFC9), paravirtualization hooks and
# vectors at $FFC0-$FFFF, so a read through a pointer into that window is not plain RAM there (reads
# return 0xFF) while Ghidra's model has zero RAM.  Re-run those tests with the zero page dumped and
# confirm pointer+Y lands in the window.
explained = 0
if izy_cands:
    sub = os.path.join(work, "izy.hex")
    open(sub, "w").write("\n".join(progs[k].hex() for k, _, _ in izy_cands) + "\n")
    subprocess.run([os.path.join(HERE, "trace-run.sh"), sub, os.path.join(work, "izy.out"), "zp"], check=True)
    for (k, step, op), g in zip(izy_cands, parse(os.path.join(work, "izy.out"))):
        pc, a, x, y, sp, fl = g["st"][step]
        zpb = progs[k][pc - 0x8000 + 1]
        mem = g["mem"][step]
        ptr = mem[zpb] | (mem[(zpb + 1) & 0xFF] << 8)
        if ptr + y >= 0xFFC0: explained += 1
        else:
            bad += 1
            key = "%02X %s (izy)" % (op, mnem[op])
            buckets[key] += 1; examples.setdefault(key, []).append((k, step))
print("tests %d  identical %d  skipped(bank regs written) %d  emulation-error %d  explained(sim65 $FFC0-$FFFF window) %d  different %d"
      % (N, ok, skipped, errs, explained, bad))
for key, c in buckets.most_common():
    print("  %-14s %d   e.g. %s" % (key, c, examples[key][0]))
for k, v in examples.items():
    if k == "emulation error": print(k, v[:5])
sys.exit(1 if (bad or errs) else 0)
