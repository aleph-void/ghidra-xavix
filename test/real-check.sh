#!/usr/bin/env bash
# Real-code checks on programs built from public source with a free toolchain (cc65, zlib license):
# a set of cc65's own self-checking C tests (test/val) is compiled for the sim6502 target with a linker
# configuration that puts the image at $8000, then
#   1. sim65 (the reference simulator) runs each and must exit 0;
#   2. Ghidra's p-code emulator runs the same image from the reset address and must reach sim65's
#      exit address with A = 0 (exit code) -- see RunImg.java for the paravirtualization calls;
#   3. the images are imported headless (processor XaviX, raw image at extbus:8000), analysed,
#      decompiled, and every instruction Ghidra found is re-decoded by MAME unidasm; the ld65 label
#      file says where the compiler's code is.
#
#   GHIDRA_INSTALL_DIR=... test/real-check.sh <workdir> [all]
# "all" runs every val test in the emulator (about 300, a few minutes); the default runs 24.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
MODE=${2:-}
CC=$("$HERE/fetch-cc65.sh" "$W/dl")
export CC65_HOME=$CC PATH=$CC/bin:$PATH
mkdir -p "$W/val" "$W/valz"
rc=0
ls "$CC"/test/val/*.c | xargs -P"$(nproc)" -I{} sh -c 'b=$(basename {} .c); cl65 -t sim6502 -C '"$HERE"'/xavix8000.cfg -o '"$W"'/val/$b.prg {} >/dev/null 2>&1 || rm -f '"$W"'/val/$b.prg'
: > "$W/list.txt"
for f in "$W"/val/*.prg; do
	python3 "$HERE/zeroprg.py" "$f" "$W/valz/$(basename "$f")"
	# programs sim65 rejects, and the few that run for more than 1.5 million cycles (the emulator
	# executes about 10,000 instructions a second), are not used
	if timeout 60 sim65 -c "$W/valz/$(basename "$f")" >"$W/cyc.txt" 2>&1; then
		cyc=$(sed -n 's/^\([0-9]*\) cycles.*/\1/p' "$W/cyc.txt" | tail -1) 
		((cyc <= 1500000)) && echo "$f" >> "$W/list.txt" || echo "skipped (long): $(basename "$f") $cyc cycles"
	else
		echo "sim65 rejects $(basename "$f") (not used)"
	fi
done
N=$(wc -l < "$W/list.txt")
if [[ $MODE != all ]]; then
	# every 13th program plus the larger ones used below
	awk 'NR % 13 == 1' "$W/list.txt" > "$W/list-small.txt"
	for b in snprintf-test cq714 compare-rev13 atoi-test bug1108 bitfield-union; do grep "/$b.prg$" "$W/list.txt" >> "$W/list-small.txt" || true; done
	sort -u "$W/list-small.txt" -o "$W/list-small.txt"
	mv "$W/list-small.txt" "$W/list.txt"
fi
echo "== emulator: $(wc -l < "$W/list.txt") of $N sim65-passing programs"
"$HERE/run-img.sh" "$W/list.txt" "$W/emu.out" 5000000
good=$(grep -c 'exit=0 ' "$W/emu.out" || true)
skip=$(grep -c UNSUPPORTED "$W/emu.out" || true)
bad=$(grep -v 'exit=0 ' "$W/emu.out" | grep -vc UNSUPPORTED || true)
steps=$(sed -n 's/.*steps=\([0-9]*\).*/\1/p' "$W/emu.out" | paste -sd+ | bc)
echo "emulator: $good programs exit 0 ($steps instructions executed), $skip use file-system calls the harness does not emulate (not counted), $bad fail"
grep -v 'exit=0 ' "$W/emu.out" | grep -v UNSUPPORTED || true
((bad)) && rc=1
echo "== import, analyse, decompile, re-decode"
analyse() {   # <image> <prefix> <entries...>   (headless import, analysis, RealCheck)
	local img=$1 prefix=$2; shift 2
	local proj; proj=$(mktemp -d "${TMPDIR:-/tmp}/xavix-real.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$proj" p -import "$img" -loader BinaryLoader \
		-loader-baseAddr 0x8000 -processor XaviX:LE:24:default -scriptPath "$HERE" \
		-preScript SetEntry.java "$@" -postScript RealCheck.java "$prefix" 120 -deleteProject >"$proj/log.txt" 2>&1 \
		|| { tail -40 "$proj/log.txt" >&2; rm -rf "$proj"; exit 1; }
	rm -rf "$proj"
}
for b in snprintf-test cq714 compare-rev13 atoi-test bug1108 bitfield-union; do
	f="$W/val/$b.prg"; [[ -f $f ]] || continue
	tail -c +13 "$f" > "$W/$b.img"
	P="$W/$b"
	analyse "$W/$b.img" "$P" 8000
	# programs that patch their own code: start a second analysis at the patched jump targets
	python3 "$HERE/real/executed.py" "$b" "$CC/bin/sim65" "$W/valz/$b.prg" "$P.dis" "$P.entries" >/dev/null || true
	if [[ -s $P.entries ]]; then
		analyse "$W/$b.img" "$P" 8000 $(cat "$P.entries")
		echo "$b: second analysis from the self-patched jump targets: $(tr '\n' ' ' < "$P.entries")"
	fi
	grep -v "^bookmark" "$P.summary" | sed "s/^/$b: /"
	python3 "$HERE/real/real_compare.py" "$b" "$P.dis" "$W" || rc=1
	python3 "$HERE/real/executed.py" "$b" "$CC/bin/sim65" "$W/valz/$b.prg" "$P.dis" || rc=1
	grep -q "decompile: .* 0 failed, 0 timeouts" "$P.summary" || { echo "$b: decompile failures"; rc=1; }
done
exit $rc
