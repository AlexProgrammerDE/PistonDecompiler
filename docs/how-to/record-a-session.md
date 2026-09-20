# Record a manual application session

Use the Recordings view to collect evidence while you operate an application.
The recorder runs beside Ghidra. Ghidra stores coverage bookmarks and recovered definitions in its native project.

## Configure the recorder

Create a Python environment in the repository:

```sh
python3 -m venv .venv-runtime
.venv-runtime/bin/pip install -r scripts/runtime/requirements.txt
```

Set the interpreter in `pistondecompiler.toml`:

```toml
runtime_python = ".venv-runtime/bin/python"
```

Relative interpreter paths resolve beside the configuration file.
The Python environment persists after reboot. Restart the Piston server after configuration changes.

## Record an action

1. Import and extract the binary.
2. Open its **Recordings** view.
3. Enter a scenario, such as `take damage`.
4. Select **Launch and record** or **Attach to process**.
5. Enter the original executable path. For attachment, enter its process ID too.
6. Select a capture level.
7. For Investigate, expand **Capture scope** and select functions.
8. Press **Launch and record** or **Attach and record**.
9. Perform the action inside the application.
10. Add markers before or after important actions.
11. Press **Stop and import**.

Launching supports a working directory and one argument per line. Arguments are passed directly, without a shell.
Stopping detaches instrumentation and leaves the application open.
The recorder also stops at the time limit, storage limit, or target exit.

Explore collects broad function coverage and bounded return samples.
Investigate adds ordered calls, blocks, raw argument slots, and entry/return snapshots for selected functions.
Explore accepts up to 10,000 functions. A manual selection accepts up to 200 functions.

Argument slots depend on the native ABI. They are candidate values, not confirmed parameter types.
Floating-point parameters and custom calling conventions need specific adapters.
An unreadable pointer produces no snapshot. A readable pointer does not prove that the bytes contain a valid object.

The optional x86-64 memory mode records supported scalar MOV reads and writes in selected functions.
It excludes vector operations, atomics, string instructions, and segment-relative accesses.
Detailed tracing can reduce application performance.

## Add markers without switching windows

The optional `pynput` integration listens for **Ctrl+Alt+M** and adds a numbered timeline observation.
Desktop support varies. In particular, XWayland hooks cannot observe keys in every native Wayland application.
The Recordings view shows whether the listener started. Its label does not guarantee delivery across desktop security boundaries.

For a desktop-managed shortcut, bind this command once. It follows the active recording:

```sh
.venv-runtime/bin/python scripts/runtime/capture.py \
  --mark-active /absolute/data/recordings --label "Action marker"
```

The shortcut uses the same command queue as the web controls.
A visible marker count confirms delivery. **Add marker** in the web app accepts a custom label.

## Analyze and inspect

After import, the session shows observed functions and newly observed functions.
**Analyze observed functions** queues those functions through the existing dependency scheduler.
The request includes runtime artifacts with scenario markers, timestamps, and memory provenance.
Repeated Analyze requests resume the same run. Pipeline controls handle failed jobs.

Import pauses analysis to prevent requests from mixing evidence revisions.
An active provider request must finish before recording starts.
The pipeline remains paused until you request analysis or resume it.

Ghidra receives a bookmark for each observed function and a project option containing the recording manifest.
The recorder verifies the saved manifest before it reports `saved`.
**Save evidence in Ghidra** retries this operation if Ghidra was unavailable.
An older open desktop bridge must be closed and reopened after a software update that adds the recording script.

Runtime bytes remain evidence. The system does not replace static program bytes with captured process memory.
Model proposals still use the existing review, type validation, and Ghidra writeback workflow.

## Recover after interruption

Session files live under `data/recordings/SESSION_ID/`:

- `plan.json`: function scope, capture settings, allocator profile, and launch arguments.
- `metadata.json`: binary identity, module base, architecture, and session identity.
- `events.jsonl`: incremental observations, flushed and synced every half second.
- `progress.json`: counts, marker feedback, target process, and remaining time limit.
- `trace.json`: finalized evidence for import.
- `ghidra.json`: coverage bookmarks and the trace reference saved in Ghidra.
- `capture.log`: recorder startup and collector errors.

After a server restart, interrupted sessions offer **Recover saved recording**.
Recovery preserves complete journal lines and rejects corruption before the final incomplete line.
A partial recording remains partial. Recovery does not resume a process or recreate missing observations.
An existing finalized trace remains unchanged so import retries retain their content hash.

Back up the recordings directory, SQLite database, and both native Ghidra project files together.
The `.gpr` file and matching `.rep` directory preserve recovered definitions independently of trace import.

## Configure a custom allocator

Allocator profiles apply only to the exact binary hash:

```toml
[[runtime_allocators]]
binary_sha256 = "REPLACE_WITH_BINARY_SHA256"
allocate_rva = 4096
free_rva = 8192
size_argument = 0
```

Addresses are offsets from the main module base.
The allocator returns the object pointer and receives its byte size in the selected argument slot.
The release function receives the pointer in its first argument slot.
Different allocator contracts need a collector adapter.

The built-in collector handles `malloc`, `calloc`, `realloc`, and `free` when their exports are available.
Interior pointers can reference known allocations.
Pre-existing objects and untracked allocators use readable-region observations with unknown lifetimes.
Unknown regions receive separate observation identities. Equal addresses do not establish a shared object lifetime.
