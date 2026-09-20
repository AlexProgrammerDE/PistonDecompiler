// Add the desktop connection to Ghidra's own classloader before starting its native UI.
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraClassLoader;
import ghidra.GhidraLaunchable;
import ghidra.GhidraLauncher;
import java.util.Arrays;

public class PistonLaunch {
    public static void main(String[] args) throws Exception {
        GhidraApplicationLayout layout = GhidraLauncher.initializeGhidraEnvironment();
        GhidraClassLoader loader = (GhidraClassLoader) ClassLoader.getSystemClassLoader();
        loader.addPath(args[0]);
        GhidraLaunchable desktop = (GhidraLaunchable) loader.loadClass("PistonDesktop").getConstructor().newInstance();
        desktop.launch(layout, Arrays.copyOfRange(args, 1, args.length));
    }
}
