#!/usr/bin/env bash
# test/pcode.sh <hex>   prints the p-code of one instruction (GHIDRA_INSTALL_DIR set)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/xavix-pc.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 64 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader -loader-baseAddr 0 \
	-processor "XaviX:LE:24:default" -noanalysis -scriptPath "$HERE" -postScript Pcode.java "$1" -deleteProject 2>&1 | grep -E "^(INFO  Pcode.java> |ERROR)" | sed 's/^INFO  Pcode.java> //'
