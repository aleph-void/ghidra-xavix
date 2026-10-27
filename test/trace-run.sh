#!/usr/bin/env bash
# test/trace-run.sh <tests.hex> <out.txt>   (GHIDRA_INSTALL_DIR set)
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
IN=$(readlink -f "$1"); OUT=$(readlink -m "$2"); EXTRA=${3:-}
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/xavix-tr.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 65536 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-loader-baseAddr 0 -processor "XaviX:LE:24:default" -noanalysis -scriptPath "$HERE" \
	-postScript TraceRun.java "$IN" "$OUT" $EXTRA -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
