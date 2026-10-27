#!/usr/bin/env bash
# Runs every XaviX check.
#
#   GHIDRA_INSTALL_DIR=<Ghidra with this module linked into Ghidra/Processors/XaviX> \
#     test/run-tests.sh [--real] [--n <random-cases>] <workdir>
#
# Needs: MAME's `unidasm` on PATH (the decode oracle, used as a black box), python3, a JDK for Ghidra.
# --real also fetches and builds cc65 (pinned commit + SHA-256, needs network and a C compiler) and
# runs the sim65 differential, the cc65 self-checking C programs in Ghidra's emulator, the headless
# import/decompile checks and the decompiler check on one tiny function per opcode.
# Exit status 0 only if every step passes.
set -uo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(dirname "$HERE")
REAL=0; N=200000
while [[ ${1:-} == --* ]]; do
	case $1 in --real) REAL=1; shift ;; --n) N=$2; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;; esac
done
W=$(mkdir -p "$1" && cd "$1" && pwd)
export TMPDIR=${TMPDIR:-/tmp}      # Ghidra project paths must not contain a hidden directory
command -v unidasm >/dev/null || { echo "unidasm (MAME) not found on PATH" >&2; exit 2; }
fail=0
step() { echo "== $*"; }
ok() { "$@" || { echo "FAILED: $*"; fail=1; }; }

step "spec compiles (sleigh -l: no unresolved pattern conflicts)"
out=$("$GHIDRA_INSTALL_DIR/support/sleigh" -l "$MOD/data/languages/XaviX.slaspec" 2>&1)
if grep -q "ERROR\|Error" <<<"$out"; then echo "$out" | grep -i error | head; echo "FAILED: XaviX.slaspec"; fail=1; else echo "XaviX compiles, no conflicts"; fi

step "decode vs MAME unidasm -arch xavix: every opcode x 256 second bytes x 12 third bytes (x 4 fourth bytes for CALLF), plus $N random records"
ok python3 "$HERE/diff_unidasm.py" "$W/dm" --random "$N"
step "decode check can fail (a corrupted result must be reported)"
if python3 "$HERE/diff_unidasm.py" "$W/dm-brk" --random 100 --break >/dev/null; then
	echo "FAILED: the broken result was not detected"; fail=1; else echo "broken result detected"; fi

step "every constructor is reached"
out=$("$HERE/every-entry.sh" XaviX:LE:24:default "$W/dm/cases.hex" "$W/ee.txt")
echo "$out"
grep -q " 0 not reached" <<<"$out" || { echo FAILED; fail=1; }

step "p-code: hand-computed emulator cases (and a deliberately wrong expectation)"
ok "$HERE/emu-test.sh" "$HERE/emu/cases.txt" "$W/emu"

if ((REAL)); then
	CC=$("$HERE/fetch-cc65.sh" "$W/dl") || { echo "FAILED: fetching cc65"; exit 1; }
	export SIM65=$CC/bin/sim65
	step "p-code vs sim65 (--cpu 6502X): 40,000 random instruction sequences, register state compared before every instruction"
	ok python3 "$HERE/diff_sim65.py" "$W/ss" --n 40000 --seed 11
	step "sim65 comparison can fail"
	if python3 "$HERE/diff_sim65.py" "$W/ss-brk" --n 40 --seed 5 --break >/dev/null; then
		echo "FAILED: the broken trace was not detected"; fail=1; else echo "broken trace detected"; fi
	step "cc65 C programs: sim65 vs Ghidra emulator, import/analysis/decompile, unidasm re-decode"
	ok "$HERE/real-check.sh" "$W/real"
	step "decompiler: one function per opcode"
	python3 "$HERE/real/synth.py" "$W/synth.bin" "$W/synth.ents"
	PROJ=$(mktemp -d "$TMPDIR/xavix-synth.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$W/synth.bin" -loader BinaryLoader \
		-loader-baseAddr 0x8000 -processor XaviX:LE:24:default -scriptPath "$HERE" \
		-preScript SetEntry.java "@$W/synth.ents" -postScript RealCheck.java "$W/synth" 60 -deleteProject >"$PROJ/log.txt" 2>&1 \
		|| { tail -20 "$PROJ/log.txt"; fail=1; }
	rm -rf "$PROJ"
	grep -v "^bookmark" "$W/synth.summary"
	grep -q "decompile: [0-9]* ok, 0 failed, 0 timeouts" "$W/synth.summary" || { echo "FAILED: decompile"; fail=1; }
fi
((fail)) && { echo "SOME CHECKS FAILED"; exit 1; }
echo "ALL CHECKS PASSED"
