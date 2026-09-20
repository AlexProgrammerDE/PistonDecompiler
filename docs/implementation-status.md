# Implementation status

The architecture documents define the target. The current implementation runs recovery through the server and CLI.

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
- Bounded recovery passes with wider context and early stopping when no new evidence is available.
- Persistent iteration status through `recovery-status`.
- C++ pointer-table and RTTI evidence, runtime virtual dispatch, base layouts, typed vtable data, and stable local-variable refinement.
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

Type recovery supports explicit base subobjects, multiple vptrs, typed vtable bindings, and local refinements.
Unions, bitfields, overlapping base layouts, and explicit parameter storage remain unsupported.
See [C++ recovery](architecture/cpp-recovery.md) for evidence, writeback, and platform limits.
The system preserves unresolved facts rather than manufacturing these layouts.

Runtime session management and recorded-function analysis have web controls.
The server applies supported fields and runs bounded reanalysis automatically. The CLI uses the same durable recovery phases.
Uncertain fields are deferred without manual review. Provider errors and unreconciled writeback failures remain explicit operational failures.

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

Run the C++ integration test with the recorder's Python environment:

```sh
PISTON_TEST_GHIDRA_HOME=/path/to/ghidra \
PISTON_TEST_PYTHON=/path/to/python-with-frida \
  cargo test --test cpp native_cpp -- --ignored
```

This test uses both symbol-bearing and stripped C++ fixtures. It verifies secondary base pointers, adjustor thunks, and saved refinements without provider calls.
