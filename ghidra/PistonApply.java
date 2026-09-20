// Apply an exact reviewed change set and report conflicts without overwriting external edits.
// @category PistonDecompiler
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class PistonApply extends GhidraScript {
    public void verifyApplied() throws Exception {
        JsonArray report=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[1]),StandardCharsets.UTF_8)).getAsJsonArray();
        for(JsonElement element:report) {
            JsonObject item=element.getAsJsonObject();
            if(!item.get("status").getAsString().equals("applied")) continue;
            var function=currentProgram.getFunctionManager().getFunctionAt(toAddr(item.get("address").getAsString()));
            if(function==null || !function.getName().equals(item.get("name").getAsString()) || !Objects.toString(function.getComment(),"").equals(item.get("summary").getAsString()))
                throw new IllegalStateException("Saved name or comment does not match the applied operation");
        }
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Expected change set and report paths");
        JsonArray proposals = JsonParser.parseString(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8)).getAsJsonArray();
        for (JsonElement element : proposals) {
            monitor.checkCancelled();
            JsonObject proposal = element.getAsJsonObject();
            var function = currentProgram.getFunctionManager().getFunctionAt(toAddr(proposal.get("address").getAsString()));
            String name = proposal.get("name").getAsString();
            String summary = proposal.get("summary").getAsString();
            String expectedName = proposal.get("expected_name").getAsString();
            String expectedComment = proposal.get("expected_comment").getAsString();
            boolean alreadyApplied = function != null && function.getName().equals(name) && Objects.toString(function.getComment(), "").equals(summary);
            boolean unchanged = function != null && function.getName().equals(expectedName) && Objects.toString(function.getComment(), "").equals(expectedComment);
            if (!alreadyApplied && !unchanged) {
                proposal.addProperty("status", "conflict");
                proposal.addProperty("error", "Function is missing or its name/comment changed since extraction or the previous apply.");
                continue;
            }
            if (!alreadyApplied) {
                function.setName(name, SourceType.USER_DEFINED);
                function.setComment(summary);
            }
            if (!function.getName().equals(name) || !Objects.toString(function.getComment(), "").equals(summary)) throw new IllegalStateException("Writeback verification failed");
            proposal.addProperty("status", "applied");
            proposal.addProperty("error", "");
        }
        Files.writeString(Path.of(args[1]), new Gson().toJson(proposals), StandardCharsets.UTF_8);
    }
}
