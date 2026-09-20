// Run the normal Ghidra desktop and execute Piston operations on its open program.
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.GhidraRun;
import ghidra.app.script.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitorAdapter;
import com.google.gson.*;
import java.io.PrintWriter;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

public class PistonDesktop implements GhidraLaunchable {
    private final Gson gson = new Gson();
    private volatile TaskMonitorAdapter monitor;
    private volatile Path activeRequest;
    private PluginTool tool;
    private Program program;
    private Project project;
    private Path bridge;
    private String session;

    @Override public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("Expected project, bridge directory, and session");
        bridge = Path.of(args[1]);
        session = args[2];
        new GhidraRun().launch(layout, new String[]{args[0]});
        Thread worker = new Thread(() -> {
            try { connect(Path.of(args[0])); serve(); }
            catch (Exception e) { e.printStackTrace(); }
        }, "Piston desktop operations");
        worker.setDaemon(true);
        worker.start();
    }

    private void connect(Path expected) throws Exception {
        while (true) {
            project = AppInfo.getActiveProject();
            if (project != null) break;
            Thread.sleep(500);
        }
        if (project == null || !project.getProjectLocator().getMarkerFile().toPath().toRealPath().equals(expected.toRealPath()))
            throw new IllegalStateException("Ghidra did not open the requested project");
        DomainFile file = project.getProjectData().getFile("/program.bin");
        if (file == null) throw new IllegalStateException("Extract the binary before opening its desktop project");
        Swing.runNow(() -> {
            tool = project.getToolServices().launchDefaultTool(List.of(file));
            if (tool != null) program = tool.getService(ProgramManager.class).getCurrentProgram();
        });
        if (program == null) throw new IllegalStateException("CodeBrowser did not open program.bin");
    }

    private void atomic(Path path, Object value) throws Exception {
        Path temporary = Path.of(path + ".tmp");
        Files.writeString(temporary, gson.toJson(value));
        Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private void serve() throws Exception {
        Path status = bridge.resolve("session.json");
        ScheduledExecutorService heartbeat = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "Piston desktop heartbeat"); thread.setDaemon(true); return thread;
        });
        heartbeat.scheduleAtFixedRate(() -> {
            try {
                atomic(status, Map.of("session", session, "pid", ProcessHandle.current().pid(), "updated_at", System.currentTimeMillis()/1000,
                    "ready", !program.isClosed(), "busy", activeRequest != null));
                Path request = activeRequest;
                TaskMonitorAdapter task = monitor;
                if (request != null && task != null && Files.exists(Path.of(request + ".cancel"))) task.cancel();
            } catch (Exception e) { e.printStackTrace(); }
        }, 0, 1, TimeUnit.SECONDS);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            heartbeat.shutdownNow();
            try { Files.deleteIfExists(status); } catch (Exception e) { e.printStackTrace(); }
        }));
        while (!program.isClosed()) {
            try (var files = Files.list(bridge)) {
                for (Path path : files.filter(p -> p.toString().endsWith(".request.json")).sorted().toList()) {
                    execute(path);
                }
            }
            Thread.sleep(100);
        }
        heartbeat.shutdownNow();
        atomic(status, Map.of("session", session, "pid", ProcessHandle.current().pid(), "updated_at", System.currentTimeMillis()/1000, "ready", false, "busy", false));
    }

    private void execute(Path path) throws Exception {
        JsonObject request = JsonParser.parseString(Files.readString(path)).getAsJsonObject();
        // Old requests are never replayed into a different desktop session.
        if (!session.equals(request.get("session").getAsString())) { Files.delete(path); return; }
        Path response = Path.of(path.toString().replace(".request.json", ".response.json"));
        if (Files.exists(response)) { Files.delete(path); return; }
        activeRequest = path;
        monitor = new TaskMonitorAdapter();
        try {
            if (Files.exists(Path.of(path + ".cancel"))) throw new IllegalStateException("Operation cancelled before execution");
            String name = request.get("script").getAsString();
            if (name.equals("focus")) {
                Swing.runNow(() -> tool.toFront());
            } else {
                GhidraScript script = switch (name) {
                    case "PistonRuntime.java" -> new PistonRuntime();
                    case "PistonExport.java" -> new PistonExport();
                    case "PistonTypes.java" -> new PistonTypes();
                    case "PistonApply.java" -> new PistonApply();
                    default -> throw new IllegalArgumentException("Unsupported Piston operation");
                };
                String[] args = gson.fromJson(request.get("args"), String[].class);
                script.setScriptArgs(args);
                GhidraState state = new GhidraState(tool, project, program, null, null, null);
                int transaction = program.startTransaction("Piston " + name);
                boolean success = false;
                try {
                    script.execute(state, new ScriptControls(new PrintWriter(System.out,true),new PrintWriter(System.err,true),monitor));
                    monitor.checkCancelled();
                    success = true;
                } finally { program.endTransaction(transaction, success); }
                // Saving also persists the operation's reconciliation marker before acknowledging it.
                if (name.equals("PistonRuntime.java") || name.equals("PistonApply.java") || (name.equals("PistonTypes.java") && args[0].equals("apply"))) {
                    Swing.runNow(() -> tool.prepareToSave(program));
                    while (!program.lock("Save Piston changes")) {
                        monitor.checkCancelled();
                        Thread.sleep(50);
                    }
                    try {
                        program.save("Piston operation", monitor);
                        if(script instanceof PistonRuntime runtime) runtime.verifyApplied();
                        if(script instanceof PistonTypes types) types.verifyApplied();
                        if(script instanceof PistonApply names) names.verifyApplied();
                    }
                    finally { program.unlock(); }
                }
                program.flushEvents();
            }
            atomic(response, Map.of("ok", true));
        } catch (Exception e) {
            e.printStackTrace();
            atomic(response, Map.of("ok", false, "error", e.toString()));
        } finally {
            activeRequest = null;
            monitor = null;
            Files.deleteIfExists(path);
            Files.deleteIfExists(Path.of(path + ".cancel"));
        }
    }
}
