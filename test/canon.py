"""Normalises unidasm and Ghidra instruction text for comparison (shared by the XaviX decode tests)."""
import re

BR = {"bpl", "bmi", "bvc", "bvs", "bcc", "bcs", "bne", "beq"}
ACC = {"asl", "lsr", "rol", "ror"}

def canon(t, addr, mame):
    t = t.strip().lower()
    m = re.match(r"^(\w+)\s*(.*)$", t)
    mn, ops = m.group(1), m.group(2).replace(" ", "")
    if mame:
        ops = ops.replace("$", "0x")
    if mn in ACC and ops == "a": ops = ""      # display: "asl a" vs "asl"
    def hx(mm): return "0x%x" % int(mm.group(0), 16)
    if mn in BR:
        v = int(ops, 16)
        ops = "t%x" % ((v - addr) & 0xffff)
    elif mn == "callf":
        v = int(ops.lstrip("#"), 16)
        ops = "f%x" % v
    elif mn in ("jmp", "jsr") and not ops.startswith("("):
        ops = "a%x" % (int(ops, 16) & 0xffff)
    else:
        ops = re.sub(r"0x[0-9a-f]+", hx, ops)
    return mn, ops

