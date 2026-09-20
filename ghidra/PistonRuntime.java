// Persist observed coverage and its durable trace reference without changing code bytes.
import ghidra.app.script.GhidraScript;
import com.google.gson.*;
import java.nio.file.*;

public class PistonRuntime extends GhidraScript {
    private String category;
    private String manifest;
    @Override protected void run() throws Exception {
        manifest = Files.readString(Path.of(getScriptArgs()[0]));
        JsonObject data = JsonParser.parseString(manifest).getAsJsonObject();
        category = "Piston recording " + data.get("session").getAsString();
        if (getScriptArgs().length > 1 && getScriptArgs()[1].equals("verify")) {
            verifyApplied();
            Files.writeString(Path.of(getScriptArgs()[0] + ".verified"), data.get("session").getAsString());
            return;
        }
        int transaction = currentProgram.startTransaction("Import runtime evidence");
        boolean commit = false;
        try {
            for (JsonElement item : data.getAsJsonArray("functions")) {
                monitor.checkCancelled();
                JsonObject observation = item.getAsJsonObject();
                var address = toAddr(observation.get("address").getAsString());
                if (currentProgram.getFunctionManager().getFunctionAt(address) == null)
                    throw new IllegalStateException("Recorded function no longer exists: " + address);
                currentProgram.getBookmarkManager().setBookmark(address, "Note", category,
                    data.get("scenario").getAsString() + ": " + observation.get("events").getAsInt()
                    + " observations. Trace: " + data.get("trace").getAsString());
            }
            currentProgram.getOptions("Piston runtime evidence").setString(category, manifest);
            commit = true;
        } finally { currentProgram.endTransaction(transaction, commit); }
        verifyApplied();
        Files.writeString(Path.of(getScriptArgs()[0] + ".applied"), data.get("session").getAsString());
    }
    public void verifyApplied() {
        if (!manifest.equals(currentProgram.getOptions("Piston runtime evidence").getString(category, "")))
            throw new IllegalStateException("Runtime evidence was not saved");
        JsonObject data = JsonParser.parseString(manifest).getAsJsonObject();
        for (JsonElement item : data.getAsJsonArray("functions")) {
            var address = toAddr(item.getAsJsonObject().get("address").getAsString());
            if (currentProgram.getBookmarkManager().getBookmark(address, "Note", category) == null)
                throw new IllegalStateException("Runtime bookmark is missing: " + address);
        }
    }
}
