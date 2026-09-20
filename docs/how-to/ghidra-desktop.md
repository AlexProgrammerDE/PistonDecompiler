# See changes in the native Ghidra desktop

After extraction, select **Open in Ghidra** in the binary header.
Piston opens Ghidra's normal project window and CodeBrowser with `program.bin` selected.
**Show Ghidra** brings an existing connected window forward.
The header reports whether the desktop is starting, connected, closed, or disconnected.

For automatic opening, set these top-level options in `pistondecompiler.toml`:

```toml
ghidra_home = "/persistent/path/to/ghidra"
ghidra_gui = true
```

Restart the backend after changing configuration.
Initial extraction still uses headless Ghidra. The native desktop opens when extraction completes.
Later previews, writeback, and refreshed decompilation use the program already open in that desktop.
Closing Ghidra allows subsequent operations to use headless mode, unless automatic GUI opening is enabled.

You can also open the desktop from the CLI while the web server is stopped:

```bash
cargo run -- open-ghidra BINARY_ID
```

Use the web button while the server owns the data directory.
The desktop opens on the backend computer and requires a graphical desktop session and a JDK compatible with the installed Ghidra version.
This connection was tested with Ghidra 12.0.4 on Linux.

## Settings survive reboots

Piston reads `pistondecompiler.toml` from its working directory, or the file selected with `--config`.
Relative paths inside that file resolve against its containing directory.
Use persistent directories for both `ghidra_home` and `data_dir`.
Avoid `/tmp`, which can be cleared during reboot.

Ghidra stores its own preferences separately.
On this Linux installation, the location is `~/.config/ghidra/ghidra_12.0.4_PUBLIC/preferences`.
Acceptance of its first-launch agreement is recorded as `USER_AGREEMENT=ACCEPT`.
Reboots do not reset that preference. A different Ghidra version can use a different preferences directory.
Review and accept any first-launch agreement in the native Ghidra window yourself.

## One program, one writer

The desktop owns the Ghidra project while it is open.
Piston sends only its export, validated-name, and structured-type operations to that process.
Changes run in Ghidra transactions and trigger its normal program change events.
Write operations save the program before reporting success, including any existing unsaved program edits.
Read operations do not save the program.

The local connection uses a private directory under `data/binaries/BINARY_ID/desktop`.
It has no network listener and accepts no arbitrary scripts.
Requests carry a desktop session identity, so a new session does not replay old requests.
The connection serializes operations and refuses headless fallback while desktop ownership is uncertain.

If you close only the program tab, close Ghidra before selecting **Open in Ghidra** again.
If an operation times out or loses its connection, inspect its outcome before retrying.
Existing exact-operation reconciliation still applies to uncertain writeback.
On Linux, dead desktop processes are detected automatically, including after a reboot.
A stale heartbeat from a still-running process requires attention in that Ghidra window.

Startup and operation errors are recorded in `desktop/desktop.log` and in the application's event view.

## Integration reference

[ReVa](https://github.com/cyberkaida/reverse-engineering-assistant) demonstrates an assistant working with an open Ghidra program.
Piston uses the same program-ownership principle while retaining its existing validated scripts and automatic recovery workflow.
It does not install ReVa or expose its MCP tools.

## Reopen after a reboot

Ghidra is the authoritative destination for recovered program definitions.
SQLite stores pipeline coordination and evidence, but it is not a replacement for the Ghidra project.

Each binary has a persistent native project:

```text
data/binaries/BINARY_ID/ghidra/
  piston.gpr
  piston.rep/
```

Keep both the `.gpr` file and its `.rep` directory.
The `.rep` directory contains the actual program database, including recovered types, signatures, namespaces, names, comments, and analysis state.
You can open `piston.gpr` directly in Ghidra without running Piston.

Piston applies a change in a Ghidra transaction, prepares the native tool for saving, and saves the program before acknowledging success.
After a reboot, **Open in Ghidra** opens that existing project.
It does not reimport the binary, rerun initial analysis, or replay applied definitions from SQLite.
If extraction was interrupted, retry processes the existing project instead of overwriting it.
An incomplete project that contains no saved program requires repair; Piston does not silently replace it.
Ghidra can regenerate a function's displayed pseudocode when you view it, using the definitions already saved in its program database.

Relative data paths resolve against the configuration file's directory.
Starting Piston from a different working directory with the same `--config` therefore opens the same data directory.
The default project configuration uses the persistent repository `data` directory, not a temporary directory.

Use Ghidra's normal Save command for manual edits made outside Piston operations.
An interrupted operation can remain uncertain; that does not erase previous successfully saved changes.
Back up the complete data directory with Ghidra and Piston stopped.
This includes native projects and their SQLite evidence together.
