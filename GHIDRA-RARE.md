# SSD XaviX: verification notes (Ghidra-Rare)

Module at the repository root (upstream path `ghidra/Ghidra/Processors/XaviX/` in widberg/rad_sbw; extension name `XaviX`), language `XaviX:LE:24:default`
(the original XaviX core, `unidasm -arch xavix`: a 6502 with the NMOS unintended opcodes, `CALLF`/`RETF`,
a bank register pair at $FE/$FF and a 22-bit external bus). Provenance and the list of changes are in
[CREDITS.md](CREDITS.md). Everything below is reproduced by `test/run-tests.sh [--real] <workdir>` (needs
MAME's `unidasm` on `PATH`; `--real` also needs network access and a C compiler to build cc65).
Run against Ghidra 12.1.4; the release zips also build for 12.1.3 and 12.2 (the spec is compiled with
each version's SLEIGH compiler).

## Results

| Area | Result |
|---|---|
| Build | `XaviX.slaspec` compiles on 12.1.3, 12.1.4 and 12.2 with `sleigh -l` reporting no pattern conflicts; the `.sla` is 17 KB |
| Decode vs MAME | `unidasm -arch xavix` as a black box: 995,648 records (every opcode x 256 second bytes x 12 third bytes, x 4 fourth bytes for `CALLF`, plus 200,000 random 4-byte records; 354,306 distinct byte strings after truncating to the length unidasm reports): 987,461 identical, 8,187 explained (a `CALLF` bank byte above $3F, which Ghidra's 22-bit external bus masks in the target), 0 length differences, 0 undecoded, 0 unexplained. All 256 opcodes are valid in both |
| Every constructor reached | 155/155 |
| Semantics: hand-computed | 78 emulator cases with expectations worked out by hand from the MCS6500 manual and the published NMOS behaviour (ADC/SBC incl. decimal, logic, compares, shifts, inc/dec, transfers, flags, all addressing modes, stack, branches, JSR/RTS, JMP, BRK/RTI, unintended opcodes, bank addressing, CALLF/RETF, jumps to $0000-$7FFF); all pass, and one deliberately wrong expectation is reported as failing. The XaviX-only parts (banks, CALLF/RETF, bank stack) have no public document: their cases check the contract the module documents and are labelled "self-consistency" |
| Semantics: sim65 | The cc65 simulator `sim65 --cpu 6502X` (zlib license, black box, `--trace`) against Ghidra's p-code emulator: 40,000 random sequences (each: stack pointer, flags incl. decimal, memory cells, A/X/Y, 1-8 random non-control instructions from all 244 non-control opcodes except ANE/LXA/LAS, plus conditional branches over 0-3 NOPs, and an epilogue reading the cells back), register and flag state compared before every instruction: 39,995 identical, 5 skipped (the program wrote the bank registers $FE/$FF, which a flat 64K machine does not have), 0 different. A corrupted trace is detected |
| Real code | 27 of cc65's self-checking C programs (`test/val`, zlib; compiled with cc65 for the sim6502 target and a linker config that puts the image at $8000): sim65 and Ghidra's emulator both exit 0, 743,432 instructions executed in the emulator by `run-tests.sh --real`; a full run of all 261 programs that sim65 passes within 1.5 million cycles (and need no file system) executed 5.37 million instructions, all exit 0 (see below). 6 of them imported headless with auto-analysis and decompiled: 1,100 to 12,312 instructions each, every instruction identical to unidasm's decode of the same bytes, every instruction address sim65 executes is an instruction of the same length in Ghidra's listing (after a second analysis from the self-patched `jmp` targets; one instruction hides inside a `BIT abs` operand, cc65's skip idiom), 0 decompile failures and 0 timeouts except one lone `JMP $0000` trampoline per program that the program patches at run time |
| Decompiler | One tiny function per opcode (255 functions; two opcodes share one through a jump): all decompile, no analysis hang |
| Doesn't work | See below |
| Unverified | See below |

## Method

- **Decode.** `test/diff_unidasm.py`: unidasm disassembles the records on an 8-byte stride; its
  lengths truncate the records and Ghidra decodes the distinct byte strings (`DisCases.java`).
  `--break` shows the comparison can fail.
- **Semantics.** `test/emu/cases.txt` (format in the header of `EmuTest.java`); `test/diff_sim65.py`
  with `TraceRun.java` for the sim65 differential. sim65's RAM starts as $FF, so the programs are
  re-packed with zero-filled RAM below $FFC0 (`zeroprg.py`) to match Ghidra's emulator.
- **Real code.** `test/real-check.sh`: `RunImg.java` runs a sim65 image in the emulator from its
  reset address to sim65's exit address $FFF9 and compares the exit code (the sim65 paravirtualized
  `write` and start-up calls are emulated; programs that open files are not used);
  `RealCheck.java`, `real/real_compare.py`, `real/executed.py` for import, decompile and re-decode.
- **Sources of semantics.** MCS6500 programming manual and NMOS behaviour; sim65 and unidasm as
  black boxes; no MAME or other GPL source read.

## Bugs found and fixed in the module

All found by the tests above; the commits are listed in CREDITS.md.

1. `JSR`, `CALLF` and `BRK` zeroed the byte above the stack top (a 16-bit value stored with a 1-byte push): found by running C programs against sim65.
2. `JMP`, `JSR` and `CALLF` to an address below $8000 branched into the unique space (emulator stopped, decompiler failed).
3. `PHP` pushed B clear until the first `PLP`.
4. `JMP abs`/`JSR abs` with the code bank >= $80 used the contents of memory at the operand.
5. The `segment` userop stopped the emulator at the first banked access.
6. Decompiler failures ("Conditional execution: Illegal op in iblock") in about 1 function in 25, and warnings in a third: branches in front of the indirect transfers and discarded bus cycles in the p-code.
7. `KIL` was an operation-free p-code loop that hung auto-analysis.
8. One constructor (`OP2R` accumulator form) no opcode could reach.

## Design notes

- Two address spaces: `lowbus` (the 16-bit CPU bus: RAM, the I/O registers, zero page and stack) and
  `extbus` (22-bit, the ROM). An access goes to `extbus` when the bank register is >= $80 or the
  address is >= $8000: `((bank << 16) + address) & 0x3fffff`. `CALLF` pushes the bank byte on a
  separate bank stack (`bankstack`, pointer `SSP`).
- Decimal mode is modelled with branches in ADC/SBC/ARR, as on the NMOS part (sim65 agrees, flags included).
- The read-modify-write dummy write is kept; the other discarded bus cycles are not modelled (see below).

## Doesn't work

- **XaviX2000 (`unidasm -arch xavix2000`, a different opcode map) and XaviX2 (`xavix2`, a different
  instruction set) are not implemented.** They are not in the upstream module; the only oracle for them is
  a disassembler (no semantics), and no non-GPL document describes them.
- **Relative branches, and indirect jumps/returns/interrupt entries to addresses below $8000, go to
  `extbus`, not RAM (`lowbus`).** SLEIGH cannot name the address space of a relative or computed
  destination, and cannot set context in another space. Direct `JMP`/`JSR`/`CALLF` to low addresses do
  reach `lowbus`. Code executing from RAM therefore flows correctly only through direct jumps and calls.
- **A lone `JMP` into memory that holds no code fails to decompile** (self-patched trampolines such as
  cc65's `jmp $0000`): the decompiler cannot follow a branch to a missing instruction. Disassembly is fine;
  define the target and it decompiles.
- **The discarded bus cycles (dummy reads, page-crossing and branch-taken reads) are not modelled.** p-code
  could express them, but as branching loads with unused results they made about 1 function in 25 fail to
  decompile; they only matter to an emulator that wants to trigger read side effects of I/O registers on
  the extra cycle.
- Interrupts (NMI/IRQ entry) are not modelled: Ghidra has no asynchronous events. `BRK` always uses the IRQ
  vector (the NMI redirect race of the hardware is not representable).

## Unverified

- The XaviX-specific behaviour: `CALLF`/`RETF`, the bank stack, `BRK`/`RTI` bank handling and the vector
  enable ($7FF9), the `DATA_BANK`/`CODE_BANK` address arithmetic and the 22-bit mask. No public document or
  independent implementation was available to compare against; the tests check internal consistency only.
  The mnemonics and operand layouts are verified against unidasm.
- `ANE`, `LXA`, `LAS`: their results are chip specific. The module's values differ from sim65's NMOS ones;
  neither can be confirmed without the hardware. They are excluded from the sim65 comparison.
- `JMP (ind)` page-wrap behaviour and `SHA/SHX/SHY/TAS` page-cross corner cases agree with sim65 in
  random tests but are not covered by a manual.
- Real commercial XaviX ROMs were not used (no freely licensed ones exist); the vector table and entry
  points of a real console image are not exercised.

## Confirmed reference-tool bugs

None found. unidasm shows the `CALLF` bank byte unmasked (Ghidra shows the 22-bit bus address; classed
as explained above). sim65 reserves $FFC0-$FFFF (counter peripheral, hooks, vectors): reads there are not RAM,
which the comparison accounts for (a divergence through a pointer that lands there is classed as explained).
