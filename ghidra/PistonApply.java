// Apply reviewed function names and summaries through one headless writer.
// @category Piston
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class PistonApply extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected proposal path");
        JsonArray proposals = JsonParser.parseString(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8)).getAsJsonArray();
        for (JsonElement element : proposals) {
            monitor.checkCancelled();
            JsonObject proposal = element.getAsJsonObject();
            var function = currentProgram.getFunctionManager().getFunctionAt(toAddr(proposal.get("address").getAsString()));
            if (function == null) throw new IllegalArgumentException("Function does not exist: " + proposal.get("address"));
            function.setName(proposal.get("name").getAsString(), SourceType.USER_DEFINED);
            function.setComment(proposal.get("summary").getAsString());
        }
    }
}
