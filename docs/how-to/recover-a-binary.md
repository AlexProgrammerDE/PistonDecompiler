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

The default creates a type preview and stops before type application.
Inspect the preview through its saved operation and the linked analysis result.

To authorize automatic application of assessed type proposals, use:

```sh
pistondecompiler recover BINARY_ID --iterations 3 --apply-types
```

Automatic application requires model confidence of at least 0.95 and a supporting Jev assessment.
Structural and Ghidra conflict validation still apply.
A conflicting or uncertain proposal stops recovery before caller analysis.

Inspect progress and stop reasons:

```sh
pistondecompiler recovery-status BINARY_ID
```

A new invocation creates new analysis runs and can incur new provider charges.
It does not silently resume an unfinished model request or reset its accounting.

## Apply a reviewed type proposal manually

```sh
pistondecompiler preview-types RESULT_ID
pistondecompiler apply-types OPERATION_ID
```

Application refreshes decompilation from the existing Ghidra project.
The operation preserves historical results, reviews, and cost accounting.

To combine compatible proposals in one preview, pass multiple result IDs:

```sh
pistondecompiler preview-types RESULT_ID_1 RESULT_ID_2
```

Conflicting definitions or signatures stop the preview before Ghidra changes.

If application stops with an uncertain outcome, inspect the Ghidra log and retry the same operation ID.
The Ghidra transaction stores the operation identity for idempotent reconciliation.
Do not create a replacement operation while the original remains uncertain.
