// Runs sim65-format programs (12-byte header, image loaded at the header's load address, which must
// be in extbus $8000-$FFBF) in Ghidra's p-code emulator from the header's reset address until the
// program jumps to sim65's exit address $FFF9, and prints "<file> exit=<A> steps=<n>" (or an error).
// The paravirtualization calls write ($FFF7: discards the output) and args ($FFF8: argc = 0) are
// emulated here; any other call ends the run with an UNSUPPORTED result.
// Script args: <list.txt> <outfile> [max-steps] [trace]   (trace: print the register state before every step)
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;

public class RunImg extends GhidraScript {
	private AddressSpace ext, low;

	private int rd(EmulatorHelper emu, int a) {
		AddressSpace sp = a >= 0x8000 ? ext : low;
		return emu.readMemory(sp.getAddress(a & 0xffff), 1)[0] & 0xff;
	}

	private void wr(EmulatorHelper emu, int a, int v) {
		AddressSpace sp = a >= 0x8000 ? ext : low;
		emu.writeMemory(sp.getAddress(a & 0xffff), new byte[] { (byte) v });
	}

	private int rd16(EmulatorHelper emu, int a) {
		return rd(emu, a) | (rd(emu, a + 1) << 8);
	}

	private void wr16(EmulatorHelper emu, int a, int v) {
		wr(emu, a, v & 0xff);
		wr(emu, a + 1, v >> 8);
	}

	/**
	 * The sim65 paravirtualization calls that the C library makes without files: write (output is
	 * discarded, returns the count) and the start-up argument call (no arguments). Returns null when
	 * handled, else a description. Then performs the RTS of the JSR that called the hook.
	 */
	private String hook(EmulatorHelper emu, int pc, int csp) {
		int a = emu.readRegister("A").intValue();
		int x = emu.readRegister("X").intValue();
		int ax = a | (x << 8);
		if (pc == 0xFFF7) {                       // PVWrite(fd, buf, count): pops fd and buf
			wr16(emu, csp, rd16(emu, csp) + 4);
		}
		else if (pc == 0xFFF8) {                  // PVArgs(argv): argc = 0
			int sp = rd16(emu, csp);
			int args = sp - 2;
			wr16(emu, ax, args);
			wr16(emu, args, csp);
			wr16(emu, csp, args);
			emu.writeRegister("A", 0);
			emu.writeRegister("X", 0);
		}
		else {
			return String.format("UNSUPPORTED paravirtualization call $%04X", pc);
		}
		int s = emu.readRegister("S").intValue();
		int ret = rd(emu, 0x100 + ((s + 1) & 0xff)) | (rd(emu, 0x100 + ((s + 2) & 0xff)) << 8);
		emu.writeRegister("S", (s + 2) & 0xff);
		emu.writeRegister(emu.getPCRegister(), (ret + 1) & 0xffff);
		return null;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(new java.io.FileOutputStream(args[1]), true);
		long max = args.length > 2 ? Long.parseLong(args[2]) : 20_000_000L;
		boolean trace = args.length > 3 && args[3].equals("trace");
		String[] flags = { "N", "V", "D", "I", "Z", "C" };
		Address watch = System.getenv("XAVIX_WATCH") == null ? null
				: currentProgram.getAddressFactory().getAddressSpace("lowbus").getAddress(
					Long.parseLong(System.getenv("XAVIX_WATCH"), 16));
		ext = currentProgram.getAddressFactory().getAddressSpace("extbus");
		low = currentProgram.getAddressFactory().getAddressSpace("lowbus");
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String path;
			while ((path = r.readLine()) != null) {
				path = path.trim();
				if (path.isEmpty()) {
					continue;
				}
				byte[] f = Files.readAllBytes(Paths.get(path));
				int load = (f[8] & 0xff) | ((f[9] & 0xff) << 8);
				int csp = f[7] & 0xff;
				int reset = (f[10] & 0xff) | ((f[11] & 0xff) << 8);
				byte[] img = java.util.Arrays.copyOfRange(f, 12, f.length);
				Address base = ext.getAddress(load);
				clearListing(new AddressSet(ext.getAddress(0x8000), ext.getAddress(0xFFFF)));
				setBytes(ext.getAddress(0x8000), new byte[0x8000]);
				setBytes(base, img);
				EmulatorHelper emu = new EmulatorHelper(currentProgram);
				String res;
				try {
					emu.writeRegister(emu.getPCRegister(), reset);
					Address exit = ext.getAddress(0xFFF9);
					long steps = 0;
					res = null;
					while (!emu.getExecutionAddress().equals(exit)) {
						long pcv = emu.getExecutionAddress().getOffset();
						if (pcv >= 0xFFF1 && pcv <= 0xFFF8) {
							String h = hook(emu, (int) pcv, csp);
							if (h != null) {
								res = h;
								break;
							}
							continue;
						}
						if (trace) {
							StringBuilder sb = new StringBuilder("S ");
							sb.append(String.format("%04x %02x %02x %02x %02x ",
								emu.getExecutionAddress().getOffset() & 0xffff,
								emu.readRegister("A").intValue(), emu.readRegister("X").intValue(),
								emu.readRegister("Y").intValue(), emu.readRegister("S").intValue()));
							for (String fl : flags) {
								sb.append(emu.readRegister(fl).intValue() != 0 ? "1" : "0");
							}
							if (watch != null) {
								byte[] w = emu.readMemory(watch, 2);
								sb.append(String.format(" %02x%02x", w[0] & 0xff, w[1] & 0xff));
							}
							out.println(sb);
						}
						if (++steps > max) {
							res = "TIMEOUT pc=" + emu.getExecutionAddress();
							break;
						}
						if (!emu.step(monitor)) {
							res = "ERROR " + emu.getLastError() + " pc=" + emu.getExecutionAddress();
							break;
						}
					}
					if (res == null) {
						res = String.format("exit=%d steps=%d", emu.readRegister("A").intValue(), steps);
					}
				}
				finally {
					emu.dispose();
				}
				out.println(Paths.get(path).getFileName() + " " + res);
			}
		}
		out.close();
	}
}
