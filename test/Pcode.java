// Prints the p-code of one instruction. Script args: <hex bytes>   (decoded at extbus:8000)
//@category Testing
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.pcode.PcodeOp;

public class Pcode extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String hex = getScriptArgs()[0];
		byte[] b = new byte[hex.length() / 2 + 8];
		for (int i = 0; i < hex.length() / 2; i++) {
			b[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		Language lang = currentProgram.getLanguage();
		Address a = currentProgram.getAddressFactory().getAddressSpace("extbus").getAddress(0x8000);
		ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
		ByteMemBufferImpl buf = new ByteMemBufferImpl(a, b, true);
		InstructionPrototype proto = lang.parse(buf, ctx, false);
		PseudoInstruction pi = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
		println(pi.toString());
		for (PcodeOp op : pi.getPcode()) {
			println(op.toString());
		}
	}
}
