# Managed runtime recordings

A recording separates manual scenario execution from evidence collection and interpretation.
The user operates the target. A Frida child process records observations. The server imports them and maps addresses to Ghidra functions.

## Ownership and state

The server owns recording state in SQLite. A partial unique index permits one active recorder per workspace.
Starting a recording pauses the binary under a database write lock and checks for active or uncertain model jobs.
A database trigger prevents analysis from resuming while capture or import is active.
The existing Ghidra semaphore serializes recording setup and publishing with extraction and native program writes.

The normal transition is:

```text
starting → recording → stopping → importing → ready
     any active state → failed or interrupted
failed or interrupted → importing → ready
```

A failed Ghidra publish does not discard an imported recording.
Its separate status offers a retry. Analysis run identity is also separate from recording status.
Repeated analysis requests resume the same run instead of creating duplicate provider work.

## Data flow

The server generates a plan from the current Ghidra instruction map.
It invokes the configured Python interpreter with argument vectors, without a shell.
The recorder checks the executable hash and attached module path before instrumentation starts.

The child receives Stop and marker commands through atomically renamed files.
A pipe detects server exit. Normal Stop detaches from the target without terminating it.
A watchdog bounds recorder runtime. A forced recorder stop retains the journal for recovery.

The journal contains complete JSON lines and syncs every half second.
A bounded message queue and storage budget stop collection before memory use grows without limit.
On overflow, the recorder preserves a contiguous prefix and counts omitted observations.
Recovery discards only an incomplete final line. Earlier corruption fails validation.

## Evidence semantics

Function-relative addresses survive ASLR. Each recording stores the loaded module base and binary hash.
Allocation identities refer to observed lifetimes. Readable-region identities explicitly lack that lifetime evidence.
Snapshots include invocation, argument slot, and entry/return phase.
An instruction memory observation describes a supported access. A snapshot difference does not identify its writer.

Event sequence is collector order. Buffered block and call timestamps describe delivery time.
The collector does not infer a causal ordering between threads or claim that unobserved instructions never ran.

The importer retains the full trace and creates bounded, citable artifacts for observed functions.
Those artifacts include marker context and referenced allocation or region observations.
Existing model context budgets still apply. Collection volume does not imply that every byte enters a prompt.

## Native Ghidra persistence

Publishing adds session-specific bookmarks to observed functions and stores a manifest in program options.
The manifest references the durable trace file. Raw process memory does not overwrite the static program.

The desktop bridge commits and saves its live Program before acknowledgment.
Headless publishing exits, reopens the same project, and verifies the manifest and bookmarks.
A failed verification remains retryable. Publishing the same session replaces its own bookmarks rather than duplicating them.

Recovered names, structures, and signatures continue through the existing proposal and writeback workflow.
The native `.gpr` and `.rep` project state remains the durable home of those definitions.
