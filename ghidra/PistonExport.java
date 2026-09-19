// Export an analyzed program into streaming JSON Lines.
// @category Piston
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import com.google.gson.Gson;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.BufferedWriter;
import java.util.*;

public class PistonExport extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected export path");
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Cannot open decompiler");
        Gson gson = new Gson();
        try (BufferedWriter out = Files.newBufferedWriter(Path.of(args[0]), StandardCharsets.UTF_8)) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("address", function.getEntryPoint().toString());
                row.put("name", function.getName());
                row.put("size", function.getBody().getNumAddresses());
                row.put("thunk", function.isThunk());
                row.put("external", function.isExternal());
                var result = decompiler.decompileFunction(function, 60, monitor);
                row.put("pseudocode", result.decompileCompleted() ? result.getDecompiledFunction().getC() : "");
                Set<String> callees = new TreeSet<>();
                Set<String> imports = new TreeSet<>();
                Set<String> strings = new TreeSet<>();
                for (Function callee : function.getCalledFunctions(monitor)) {
                    callees.add(callee.getEntryPoint().toString());
                    if (callee.isExternal() || callee.isThunk()) imports.add(callee.getName());
                }
                StringBuilder disassembly = new StringBuilder();
                StringBuilder pcode = new StringBuilder();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                while (instructions.hasNext() && !monitor.isCancelled()) {
                    Instruction instruction = instructions.next();
                    if (disassembly.length() < 100000) disassembly.append(instruction.getAddress()).append(": ").append(instruction).append('\n');
                    if (pcode.length() < 100000) for (var op : instruction.getPcode()) pcode.append(op).append('\n');
                    for (Reference ref : instruction.getReferencesFrom()) {
                        Data data = currentProgram.getListing().getDataAt(ref.getToAddress());
                        if (data != null && data.hasStringValue() && strings.size() < 256) strings.add(String.valueOf(data.getValue()));
                    }
                }
                row.put("callees", callees);
                row.put("imports", imports);
                row.put("strings", strings);
                row.put("disassembly", disassembly.toString());
                row.put("pcode", pcode.toString());
                out.write(gson.toJson(row));
                out.newLine();
            }
            monitor.checkCancelled();
        } finally { decompiler.dispose(); }
    }
}
