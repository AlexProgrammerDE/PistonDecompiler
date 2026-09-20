# Implementation status

The architecture documents define the target. The current implementation exposes the recovery workflow through the CLI.

## Implemented

- Static Ghidra evidence, type context, call edges, and SCC membership.
- Explicit import-thunk and non-executable entry classification before paid analysis.
- Component dependency barriers for queued, running, batched, and uncertain callee work.
- Runtime trace validation, idempotent ingestion, observed call edges, and citable runtime artifacts.
- A managed Frida recorder with launch/attach, markers, manual Stop, automatic import, and recorded-function analysis.
- Durable journals, interrupted-session recovery, and native Ghidra coverage bookmarks with save verification.
- Selected argument slots, returns, allocation lifetimes, snapshots, calls, blocks, and bounded x86-64 MOV memory observations.
- Coverage reports with per-scenario marginal coverage and unresolved-region ranking.
- Structured structures, enums, pointers, arrays, function pointers, and method signatures.
- Layout validation, evidence-linked proposals, Jev assessment, and bounded provider accounting.
- Optional provider JSON Schema responses and numbered evidence for citation checks.
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

The collector targets one main module. Configured allocator profiles use allocation/release functions with explicit argument slots.
Memory instruction tracing currently covers scalar x86-64 MOV operations. Other instructions and architectures need adapters.
Multi-module capture, floating-point argument decoding, and arbitrary allocator contracts remain extensions.

Type recovery does not yet represent unions, bitfields, inheritance metadata, or explicit parameter storage.
The system preserves unresolved facts rather than manufacturing these layouts.

Runtime session management and recorded-function analysis have web controls.
Structured type previews and the full iterative recovery command still use the CLI.
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
