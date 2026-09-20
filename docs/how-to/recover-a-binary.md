# Recover a binary with static and runtime evidence

The CLI owns the data-directory lock. Stop the server before these commands.
The `recover` command runs the integrated loop. The existing `run` command only runs queued analysis jobs.

## Prepare the binary

1. Set `ghidra_home` to an installed Ghidra directory in the configuration file.
2. Configure the reasoning model, Jev, and your provider’s spending limit.
3. Import and extract the binary:

```sh
pistondecompiler import /path/to/program --extract
```

Use the returned binary ID in subsequent commands.
For providers that support JSON Schema responses, set `ai.structured_outputs = true`.
The response schema requires linked claims and constrains supported type representations.
Local validation still checks citations, layouts, and names.

OpenRouter models can also use `ai.reasoning_effort` with a supported effort level.
Omit it to retain the model default.
Reasoning tokens can consume the output allowance before the model returns analysis JSON.
If that happens, adjust the effort or `ai.max_output_tokens` within your budget.

For an existing project with older export metadata, refresh it before creating a capture plan:

```sh
pistondecompiler refresh BINARY_ID
```

## Collect runtime evidence

For interactive recording, use the [Recordings view](record-a-session.md). The steps below describe the standalone adapter.

1. Create a capture plan:

```sh
pistondecompiler capture-plan BINARY_ID > capture-plan.json
```

2. Select relevant functions in the plan.
3. Set each selected function's `arguments` count from its known ABI.
4. Set `snapshot_bytes` for bounded snapshots of allocated objects.
5. Install Frida in a dedicated Python environment:

```sh
python3 -m venv .venv-runtime
.venv-runtime/bin/pip install frida
```

6. Capture a representative scenario:

```sh
.venv-runtime/bin/python scripts/runtime/capture.py \
  /path/to/program capture-plan.json inventory.json \
  --scenario inventory --seconds 30
```

The command starts the supplied executable. Add `--pid PID` to attach to an existing process instead.
The adapter checks the main module path and the binary hash.
It does not start or attach to a target automatically during static analysis.

`trace_calls` enables observed call edges. `trace_blocks` enables block observations.
Both options use Stalker and can increase capture overhead.
Function-entry coverage and selected argument samples work without Stalker.

The initial adapter supports the main module and `malloc`/`free` lifetimes.
Readable untracked pointers use region observations with unknown allocation lifetimes. Interior pointers retain known allocation identity.
The managed recorder also supports allocator profiles and bounded x86-64 MOV memory tracing.
Other modules and allocator contracts need additional adapters.

## Import observations

1. Pause the binary:

```sh
pistondecompiler control BINARY_ID pause
```

2. Import the trace:

```sh
pistondecompiler import-trace BINARY_ID inventory.json
```

3. Inspect coverage and scenario gains:

```sh
pistondecompiler coverage BINARY_ID
```

The report distinguishes observed functions from unresolved regions.
Scenario gains count newly observed functions relative to previous imported sessions.
The unresolved-region ranking does not predict which gameplay action will reach each region.

## Run recovery

Start the integrated recovery loop:

```sh
pistondecompiler recover BINARY_ID --iterations 3
```

The server runs the same recovery automatically after the active analysis queue drains.
No accept, reject, preview, or apply action is required.

Independent AI assessments select supported names, summaries, and types.
Structural checks and a rolled-back Ghidra transaction validate each merged type plan.
Conflicting or uncertain proposals are deferred automatically.
Supported names and summaries can proceed even when a type plan is deferred.

Writeback saves the existing Ghidra project and refreshes decompilation.
Changed evidence queues affected functions for another callee-first pass.
The iteration limit counts all analysis passes, including the initial pass. It does not require convergence before other functions can finish.

Read progress and stop reasons:

```sh
pistondecompiler recovery-status BINARY_ID
```

Recovery persists its phase, operation IDs, and pass count across restarts.
It retries an interrupted writeback using the same operation ID.
An unresolved provider request retains its accounting status; restarting does not silently resend it.

Type application currently re-exports the whole Ghidra program.
Only changed evidence invalidates prior results. Targeted export remains an optimization for large programs.
