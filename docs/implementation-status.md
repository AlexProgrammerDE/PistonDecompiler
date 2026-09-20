# Implementation status

The architecture documents define the target. The current implementation exposes the recovery workflow through the CLI.

## Implemented

- Static Ghidra evidence, type context, call edges, and SCC membership.
- Component dependency barriers for queued, running, batched, and uncertain callee work.
- Runtime trace validation, idempotent ingestion, observed call edges, and citable runtime artifacts.
- A Frida collector for selected arguments, returns, allocation lifetimes, snapshots, calls, and blocks.
- Coverage reports with per-scenario marginal coverage and unresolved-region ranking.
- Structured structures, enums, pointers, arrays, function pointers, and method signatures.
- Layout validation, evidence-linked proposals, Jev assessment, and bounded provider accounting.
- Exact Ghidra previews, transactional type changes, class namespaces, and operation reconciliation.
- Refreshed decompilation without loss of historical evidence, reviews, or accounting.
- Bounded recovery iterations, fixed SCC evidence snapshots, oscillation detection, and graph-change replanning.
- Persistent iteration status through `recovery-status`.
- Native Ghidra desktop ownership, save verification, and reopening saved projects without replaying definitions.
- Live extraction and analysis reports, measured estimates, and downloadable status snapshots.

## Current boundaries

The integrated `recover` command processes components in dependency order and runs members of a component concurrently.
The ordinary analysis scheduler can also run independent ready components concurrently.
Parallel component recovery with coordinated type writes remains an optimization.

Type application currently re-exports the whole Ghidra program.
Only changed evidence invalidates prior results, but targeted export remains an optimization for large programs.

The collector targets one main module and `malloc`/`free` allocations.
Custom allocators, instruction-level memory instrumentation, and multi-module capture require additional adapters.
The importer already accepts normalized memory observations from such adapters.

Type recovery does not yet represent unions, bitfields, inheritance metadata, or explicit parameter storage.
The system preserves unresolved facts rather than manufacturing these layouts.

Runtime session management, type previews, and recovery controls currently use CLI commands.
Dedicated web controls for these operations remain to be built.
A restarted recovery command creates new analysis runs. It does not automatically resume a partially completed component iteration.

## Validation

Targeted tests cover dependency barriers, recursive snapshots, runtime identity, allocation bounds, idempotent import, and invalid layouts.
A real Ghidra round trip creates a structure, applies a method signature, and re-decompiles field accesses.
The optional recovery integration test uses real Ghidra with local deterministic model responses.
It does not spend OpenRouter credits.

```sh
PISTON_TEST_GHIDRA_HOME=/path/to/ghidra \
  cargo test --test recovery real_ghidra -- --ignored --nocapture
```

Set `PISTON_TEST_GHIDRA_DESKTOP=1` to test the native desktop connection as well.
This test saves recovered definitions, terminates that Ghidra process, and opens a new process against the same project.
It verifies preserved fields, method namespace, and decompilation without importing or applying the type plan again.
Run it on a test display when available to avoid interrupting desktop work.
