// Pre-analysis script: disassembles and makes a function at each given extbus address (the reset
// entry of a program imported as a raw image).  Script args: <hex-address>... | @<file with one hex
// address per line>
//@category Testing
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SetEntry extends GhidraScript {
	@Override
	protected void run() throws Exception {
		List<String> addrs = new ArrayList<>();
		for (String s : getScriptArgs()) {
			if (s.startsWith("@")) {
				addrs.addAll(Files.readAllLines(Paths.get(s.substring(1))));
			}
			else {
				addrs.add(s);
			}
		}
		int n = 0;
		for (String s : addrs) {
			if (s.isBlank()) {
				continue;
			}
			Address a = currentProgram.getAddressFactory().getAddressSpace("extbus").getAddress(
				Long.parseLong(s.trim(), 16));
			new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
			createFunction(a, "f_" + (n++));
		}
	}
}
