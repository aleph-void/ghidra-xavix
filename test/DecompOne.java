// Decompiles the function at one extbus address and prints the C or the error.  Script args: <hex address>
//@category Testing
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompOne extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Address a = currentProgram.getAddressFactory().getAddressSpace("extbus").getAddress(
			Long.parseLong(getScriptArgs()[0], 16));
		Function f = getFunctionAt(a);
		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(currentProgram);
		DecompileResults r = ifc.decompileFunction(f, 60, monitor);
		println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "FAILED: " + r.getErrorMessage());
		println("SIGNATURE " + f.getSignature());
	}
}
