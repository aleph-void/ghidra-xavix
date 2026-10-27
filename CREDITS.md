# Credits and changes (XaviX)

## Upstream

- Repository: https://github.com/widberg/rad_sbw (the Ghidra language is in
  `ghidra/Ghidra/Processors/XaviX`; the rest of the repository is tooling for one commercial game's ROM and
  is not included). This repository holds that directory's history only (`git subtree split`), with the
  original commits and authors
- Commit imported: `fb0551ed6370f09447b4776189ca0ecaeb9c34f4` ("Add killedbycall list to cspec",
  2026-04-02), the last upstream commit touching the module
- License: MIT, Copyright (c) 2025 widberg (`LICENSE`); the module also carries Ghidra's template
  `LICENSE.txt` (Apache-2.0)
- Original author: widberg (widberg@widberg.me), who wrote the SLEIGH language, the compiler and
  processor specs. The semantics comments say they follow the behaviour of MAME's XaviX core
  (dummy bus cycles, the bank stack, the `B` flag forced on `PLP`); Ghidra-Rare did not read MAME's
  source and has no opinion on that part beyond what the tests below show.
- Not used: tahg/x2ghidra (no license).

## What Ghidra-Rare changed

All changes are commits on the `ghidra-rare` branch of the fork.

| Change | Why |
|---|---|
| `pushWord` pushes the high and low byte separately (`pushByte` also truncates its argument) | `JSR`, `CALLF` and `BRK` stored a 16-bit value with a 1-byte push, and the p-code STORE takes the size of its value: every push zeroed the byte above the stack top and corrupted the caller's frame. Found by running cc65-compiled programs in Ghidra's emulator against sim65 |
| `PHP` pushes the `B` bit set (`pushSR(bval)`) | The `B` register is 0 until the first `PLP`, so `PHP` pushed a status byte with bit 4 clear |
| `JMP abs`/`JSR abs` with `CODE_BANK` >= $80 pass the operand (`imm16`) to `segment`, not `ADDR16LO` | `ADDR16LO` exports a dereferenced varnode, which in an expression is the memory at the operand |
| Banked addresses are computed inline (`segptr` macro) instead of calling the `segment` userop | An unimplemented userop stops Ghidra's emulator at the first access to extbus. The userop and the pspec `segmentop` stay so the decompiler still sees far pointers |
| `ADDR16LO`/`ADDR24LO` export the operand field (`export *[lowbus]:2 imm16`); `JMP` branches to a label, not to `ADDR16LO`, on the bank test | They exported a dereference of a p-code local, so `JMP`, `JSR` and `CALLF` to an address below $8000 branched to `unique:...`: the emulator stopped there and the decompiler failed |
| `RTS`, `RTI`, `RETF`, `JMP (ind)` and `BRK` compute the destination without branches (`farTarget` macro) | Two conditional branches in front of the indirect transfer made the decompiler fail with "Conditional execution: Illegal op in iblock" after a push/pop pair |
| The discarded bus cycles (dummy reads of stack, code, indexed and page-crossing addresses, branch-taken reads) are no longer modelled; the macros stay, empty | They had no architectural result but left branching loads in the p-code: with them about 1 in 25 functions of the cc65 test programs failed to decompile and a third carried warnings. The read-modify-write dummy write is kept |
| Removed the `OP2R` accumulator constructor | No opcode can reach it (found by the every-constructor test) |
| `.gitignore`, `LICENSE`, `build.gradle`, `extension.properties` | Release zips for Ghidra 12.1.3, 12.1.4 and 12.2 |
| `README.md` section, `GHIDRA-RARE.md`, this file, `test/` | Verification notes and the test suite |

## Sources used by Ghidra-Rare

- MOS Technology MCS6500 Microcomputer Family Programming Manual (the manual the language's
  `.idx` already points to) and the documented behaviour of the NMOS 6502 and its unintended
  opcodes for the hand-computed emulator cases.
- MAME `unidasm -arch xavix` (decode oracle) and the cc65 project's `sim65 --cpu 6502X` (execution
  oracle, zlib license): both run as black boxes, no source read.
- cc65 (https://github.com/cc65/cc65, zlib license), commit
  `5725066bfb86cdb52c8f4afb94b6401cb320cb21`: compiler, assembler, linker, simulator and its
  `test/val` self-checking C programs, used as real code. Fetched by `test/fetch-cc65.sh` with a pinned
  SHA-256, never committed.
- Test scaffolding follows the layout of the other modules in this repository.
