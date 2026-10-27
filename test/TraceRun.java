// Runs each program of a test list in Ghidra's emulator and prints the register state before every
// instruction (same shape as sim65's --trace), plus the bank registers at the end.
// Script args: <tests.hex> <outfile> [zp]   (zp: also print the first 64 bytes of lowbus before each step)   (one hex program per line, placed at extbus:8000, run to its end)
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class TraceRun extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		Address base = currentProgram.getAddressFactory().getAddressSpace("extbus").getAddress(0x8000);
		Address lowFE = currentProgram.getAddressFactory().getAddressSpace("lowbus").getAddress(0xFE);
		boolean zp = args.length > 2 && args[2].equals("zp");
		Address zero = currentProgram.getAddressFactory().getAddressSpace("lowbus").getAddress(0);
		String[] flags = { "N", "V", "D", "I", "Z", "C" };
		int idx = 0;
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				byte[] code = new byte[line.length() / 2];
				for (int i = 0; i < code.length; i++) {
					code[i] = (byte) Integer.parseInt(line.substring(2 * i, 2 * i + 2), 16);
				}
				clearListing(new AddressSet(base, base.add(0x2ff)));
				setBytes(base, new byte[0x300]);
				setBytes(base, code);
				Address end = base.add(code.length);
				EmulatorHelper emu = new EmulatorHelper(currentProgram);
				out.println("T " + idx++);
				try {
					emu.writeRegister(emu.getPCRegister(), base.getOffset());
					int steps = 0;
					String err = null;
					while (!emu.getExecutionAddress().equals(end)) {
						StringBuilder sb = new StringBuilder();
						sb.append(String.format("%04x ", emu.getExecutionAddress().getOffset() & 0xffff));
						sb.append(String.format("%02x %02x %02x %02x ",
							emu.readRegister("A").intValue(), emu.readRegister("X").intValue(),
							emu.readRegister("Y").intValue(), emu.readRegister("S").intValue()));
						for (String f : flags) {
							sb.append(emu.readRegister(f).intValue() != 0 ? "1" : "0");
						}
						if (zp) {
							StringBuilder m = new StringBuilder("M ");
							for (byte x : emu.readMemory(zero, 0x40)) {
								m.append(String.format("%02x", x & 0xff));
							}
							out.println(m);
						}
						out.println(sb);
						if (++steps > 5000 || !emu.step(monitor)) {
							err = "ERR " + emu.getLastError();
							break;
						}
					}
					if (err != null) {
						out.println(err);
					}
					byte[] b = emu.readMemory(lowFE, 2);
					out.printf("END %02x %02x%n", b[0] & 0xff, b[1] & 0xff);
				}
				finally {
					emu.dispose();
				}
			}
		}
		out.close();
	}
}
