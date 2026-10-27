#!/usr/bin/env bash
# Fetches cc65 (zlib license) at a pinned commit, verifies the SHA-256 and builds the tools the real-code
# tests use (cc65, ca65, ld65, sim65) and the sim6502 library.  Nothing is committed.
#   test/fetch-cc65.sh <workdir>   -> prints the cc65 directory
set -euo pipefail
W=$(mkdir -p "$1" && cd "$1" && pwd)
SHA=5725066bfb86cdb52c8f4afb94b6401cb320cb21
URL=https://github.com/cc65/cc65/archive/$SHA.tar.gz
SUM=56100ceaa5a01fa3e1da896495bbff87b38416154bc3d57a4605d2d048cca1b8
if [[ ! -x $W/cc65/bin/sim65 || ! -f $W/cc65/lib/sim6502.lib ]]; then
	[[ -f $W/cc65.tar.gz ]] || curl -sSL -o "$W/cc65.tar.gz" "$URL"
	echo "$SUM  $W/cc65.tar.gz" | sha256sum -c - >&2
	rm -rf "$W/cc65" "$W/cc65-$SHA"
	tar -C "$W" -xzf "$W/cc65.tar.gz"
	mv "$W/cc65-$SHA" "$W/cc65"
	make -C "$W/cc65" -j"$(nproc)" bin >/dev/null
	make -C "$W/cc65" -j"$(nproc)" lib >/dev/null
fi
echo "$W/cc65"
