#!/usr/bin/env bash
# test/run-img.sh <list.txt> <out.txt> [max-steps]   (GHIDRA_INSTALL_DIR set)
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
IN=$(readlink -f "$1"); OUT=$(readlink -m "$2"); MAX=${3:-20000000}; TR=${4:-}
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/xavix-ri.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 65536 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-loader-baseAddr 0 -processor "XaviX:LE:24:default" -noanalysis -scriptPath "$HERE" \
	-postScript RunImg.java "$IN" "$OUT" "$MAX" $TR -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
