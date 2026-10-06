// Apply verified function annotations as one compare-and-set transaction.
// @category PistonDecompiler
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class PistonAnnotate extends GhidraScript {
    private JsonArray items;
    private String operation;
    private String encoded;
    public boolean applied() {
        return encoded != null && encoded.equals(currentProgram.getOptions("PistonDecompiler").getString(operation, ""));
    }

    public void verifyApplied() throws Exception {
        if (!encoded.equals(currentProgram.getOptions("PistonDecompiler").getString(operation, "")))
            throw new IllegalStateException("Annotation operation marker is missing");
        for (JsonElement element : items) {
            JsonObject item = element.getAsJsonObject();
            var function = currentProgram.getFunctionManager().getFunctionAt(toAddr(item.get("address").getAsString()));
            if (function == null || !function.getName().equals(item.get("name").getAsString()) ||
                !Objects.toString(function.getComment(), "").equals(item.get("comment").getAsString()))
                throw new IllegalStateException("Annotations changed after this operation");
        }
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("Expected operation, annotations and report paths");
        operation = "research-" + args[0];
        items = JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonArray();
        encoded = new Gson().toJson(items);
        String marker = currentProgram.getOptions("PistonDecompiler").getString(operation, "");
        if (!marker.isEmpty()) {
            if (!marker.equals(encoded)) throw new IllegalStateException("Annotation operation identity conflict");
            verifyApplied();
        } else {
            for (JsonElement element : items) {
                monitor.checkCancelled();
                JsonObject item = element.getAsJsonObject();
                var function = currentProgram.getFunctionManager().getFunctionAt(toAddr(item.get("address").getAsString()));
                if (function == null || !function.getName().equals(item.get("expected_name").getAsString()) ||
                    !Objects.toString(function.getComment(), "").equals(item.get("expected_comment").getAsString())) {
                    Files.writeString(Path.of(args[2]), new Gson().toJson(Map.of("status", "conflict", "address", item.get("address"),
                        "error", "Function name or comment changed since inspection; no annotations were changed")));
                    return;
                }
            }
            int transaction = currentProgram.startTransaction("Verified research annotations");
            boolean success = false;
            try {
                for (JsonElement element : items) {
                    monitor.checkCancelled();
                    JsonObject item = element.getAsJsonObject();
                    var function = currentProgram.getFunctionManager().getFunctionAt(toAddr(item.get("address").getAsString()));
                    function.setName(item.get("name").getAsString(), SourceType.USER_DEFINED);
                    function.setComment(item.get("comment").getAsString());
                }
                currentProgram.getOptions("PistonDecompiler").setString(operation, encoded);
                verifyApplied();
                success = true;
            } finally { currentProgram.endTransaction(transaction, success); }
        }
        Files.writeString(Path.of(args[2]), new Gson().toJson(Map.of("status", "applied", "items", items)));
    }
}
