// Bounded queries against the current program. This script never saves or modifies it.
// @category PistonDecompiler
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class PistonQuery extends GhidraScript {
    private final Gson gson = new Gson();
    private DecompInterface decompiler;

    private Address address(JsonObject query) {
        Address result = currentProgram.getAddressFactory().getAddress(query.get("address").getAsString());
        if (result == null) throw new IllegalArgumentException("Invalid program address");
        return result;
    }

    private Map<String,Object> function(Function function) {
        return Map.of("address", function.getEntryPoint().toString(), "name", function.getName(true), "local_name", function.getName(),
            "comment", Objects.toString(function.getComment(), ""), "signature", function.getSignature().toString(),
            "size", function.getBody().getNumAddresses(), "external", function.isExternal(), "thunk", function.isThunk());
    }

    private Map<String,Object> reference(Reference reference) {
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("from", reference.getFromAddress().toString());
        result.put("to", reference.getToAddress().toString());
        result.put("type", reference.getReferenceType().toString());
        result.put("operand", reference.getOperandIndex());
        Function caller = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
        if (caller != null) result.put("function", function(caller));
        return result;
    }

    private Object query(JsonObject query) throws Exception {
        int limit = query.has("limit") ? query.get("limit").getAsInt() : 100;
        int offset = query.has("offset") ? query.get("offset").getAsInt() : 0;
        if (limit < 1 || limit > 1024 || offset < 0 || offset > 100000) throw new IllegalArgumentException("Invalid query bounds");
        switch (query.get("kind").getAsString()) {
            case "function": {
                Function found = currentProgram.getFunctionManager().getFunctionContaining(address(query));
                if (found == null) throw new IllegalArgumentException("No function contains this address");
                Map<String,Object> result = new LinkedHashMap<>(function(found));
                if (query.get("decompile").getAsBoolean()) {
                    if (decompiler == null) {
                        decompiler = new DecompInterface();
                        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
                    }
                    int timeout = query.get("timeout_secs").getAsInt();
                    if (timeout < 1 || timeout > 120) throw new IllegalArgumentException("Invalid decompilation timeout");
                    var decompiled = decompiler.decompileFunction(found, timeout, monitor);
                    monitor.checkCancelled();
                    result.put("decompiled", decompiled.decompileCompleted());
                    result.put("error", Objects.toString(decompiled.getErrorMessage(), ""));
                    if (decompiled.getDecompiledFunction() != null) {
                        String code = decompiled.getDecompiledFunction().getC();
                        int maximum = query.get("max_chars").getAsInt();
                        if (maximum < 1 || maximum > 262144) throw new IllegalArgumentException("Invalid output limit");
                        result.put("pseudocode", code.substring(0, Math.min(code.length(), maximum)));
                        result.put("truncated", code.length() > maximum);
                    }
                }
                return result;
            }
            case "references": {
                Address target = address(query);
                String direction = query.get("direction").getAsString();
                Iterator<Reference> iterator;
                if (direction.equals("from")) iterator = Arrays.asList(currentProgram.getReferenceManager().getReferencesFrom(target)).iterator();
                else iterator = currentProgram.getReferenceManager().getReferencesTo(target);
                List<Object> entries = new ArrayList<>();
                int skipped = 0;
                boolean more = false;
                while (iterator.hasNext()) {
                    monitor.checkCancelled();
                    Reference ref = iterator.next();
                    if (direction.equals("callers") && !ref.getReferenceType().isCall()) continue;
                    if (skipped++ < offset) continue;
                    if (entries.size() == limit) { more = true; break; }
                    entries.add(reference(ref));
                }
                return Map.of("entries", entries, "next_offset", more ? offset + entries.size() : -1);
            }
            case "functions": {
                String needle = query.get("name_contains").getAsString().toLowerCase(Locale.ROOT);
                var iterator = currentProgram.getFunctionManager().getFunctions(true);
                List<Object> entries = new ArrayList<>();
                int skipped = 0;
                boolean more = false;
                while (iterator.hasNext()) {
                    monitor.checkCancelled();
                    Function found = iterator.next();
                    if (!found.getName(true).toLowerCase(Locale.ROOT).contains(needle)) continue;
                    if (skipped++ < offset) continue;
                    if (entries.size() == limit) { more = true; break; }
                    entries.add(function(found));
                }
                return Map.of("entries", entries, "next_offset", more ? offset + entries.size() : -1);
            }
            case "memory": {
                Address start = address(query);
                int length = query.get("length").getAsInt();
                if (length < 1 || length > 65536) throw new IllegalArgumentException("Invalid memory length");
                byte[] bytes = new byte[length];
                int read = currentProgram.getMemory().getBytes(start, bytes);
                List<Object> instructions = new ArrayList<>();
                if (query.get("disassemble").getAsBoolean()) {
                    var iterator = currentProgram.getListing().getInstructions(start, true);
                    while (iterator.hasNext() && instructions.size() < limit) {
                        monitor.checkCancelled();
                        var instruction = iterator.next();
                        if (instruction.getAddress().subtract(start) >= read) break;
                        instructions.add(Map.of("address", instruction.getAddress().toString(), "text", instruction.toString(),
                            "length", instruction.getLength()));
                    }
                }
                return Map.of("address", start.toString(), "hex", HexFormat.of().formatHex(bytes, 0, read),
                    "read", read, "instructions", instructions);
            }
            case "vtable": {
                Address start = address(query);
                int count = query.get("count").getAsInt();
                if (count < 1 || count > 512) throw new IllegalArgumentException("Invalid table length");
                int width = currentProgram.getDefaultPointerSize();
                List<Object> slots = new ArrayList<>();
                for (int index = 0; index < count; index++) {
                    monitor.checkCancelled();
                    Address slot = start.add((long)index * width);
                    long pointer = width == 8 ? getLong(slot) : Integer.toUnsignedLong(getInt(slot));
                    Address target = start.getAddressSpace().getAddress(pointer);
                    Map<String,Object> item = new LinkedHashMap<>();
                    item.put("index", index); item.put("offset", index * width); item.put("slot", slot.toString());
                    item.put("target", target.toString());
                    var block = currentProgram.getMemory().getBlock(target);
                    item.put("executable", block != null && block.isExecute());
                    Function found = currentProgram.getFunctionManager().getFunctionAt(target);
                    if (found != null) item.put("function", function(found));
                    slots.add(item);
                }
                return Map.of("classification", "pointer_table_candidate", "address", start.toString(), "pointer_width", width, "slots", slots);
            }
            default: throw new IllegalArgumentException("Unknown query kind");
        }
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Expected query and report paths");
        JsonArray queries = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonArray();
        if (queries.size() < 1 || queries.size() > 32) throw new IllegalArgumentException("Expected 1 to 32 queries");
        List<Object> results = new ArrayList<>();
        try {
            for (JsonElement element : queries) {
                monitor.checkCancelled();
                try { results.add(Map.of("ok", true, "result", query(element.getAsJsonObject()))); }
                catch (Exception error) {
                    monitor.checkCancelled();
                    results.add(Map.of("ok", false, "error", error.toString()));
                }
            }
            Map<String,Object> report = new LinkedHashMap<>();
            report.put("program", currentProgram.getName());
            report.put("sha256", Objects.toString(currentProgram.getExecutableSHA256(), ""));
            report.put("image_base", currentProgram.getImageBase().toString());
            report.put("pointer_width", currentProgram.getDefaultPointerSize());
            report.put("results", results);
            Files.writeString(Path.of(args[1]), gson.toJson(report));
        } finally { if (decompiler != null) decompiler.dispose(); }
    }
}
