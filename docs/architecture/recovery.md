# Evidence-based binary recovery

## Purpose

PistonDecompiler combines static analysis, runtime observations, and model proposals to recover a useful Ghidra program database.
Names alone do not satisfy this goal. Recovery includes structures, fields, classes, method namespaces, parameters, return types, and calling conventions.

## Analysis loop

1. Import an immutable binary and record its hash, architecture, compiler specification, and image base.
2. Extract Ghidra pseudocode, instructions, P-code, references, signatures, existing types, and call edges.
3. Import runtime observations from representative scenarios.
4. Normalize code addresses using module identity and relative addresses.
5. Rebuild strongly connected components from static and observed call edges.
6. Process callees before callers, with independent components in parallel.
7. Use Jev to classify evidence, route reasoning, and assess proposals.
8. Generate evidence-linked type and behavioral proposals with the reasoning model.
9. Validate layouts, ABI constraints, references, and conflicts with existing Ghidra data.
10. Apply accepted changes through one Ghidra writer.
11. Re-decompile affected functions and their callers.
12. Repeat affected recursive components until facts stabilize or the iteration budget expires.

Model confidence is not proof. Unsupported proposals remain unresolved, with their evidence and contradictions available for review.
Jev assessments supplement structural validation. They do not establish field meanings or silently override human corrections.

## Evidence model

Every observation belongs to a binary, extraction or runtime session, and immutable evidence artifact.
Every proposal identifies the exact artifacts and lines that support it.
Derived interpretations retain dependencies on earlier results and type revisions.
Changes invalidate dependent interpretations. Historical evidence remains available for audit.

An observation and an inference are different records. A value of 100 does not prove that a field represents health.
Repeated offsets, access widths, allocation sizes, call sites, and scenario changes constrain candidate layouts.
Static analysis extends these constraints into functions that no scenario executes.

## Runtime strategy

Coverage acquisition uses broad scenarios: startup, menus, loading, movement, combat, inventory, networking, and shutdown.
Detailed sampling targets selected functions and objects after coverage identifies useful regions.
Continuous whole-process instruction and memory tracing is not the default.

The system distinguishes dynamically observed, statically inferred, and unresolved functions.
Coverage means execution evidence, not semantic understanding.
Scenario recommendations rank unresolved regions by potential information gain, execution cost, and previous marginal coverage.
The ranking is a heuristic, not a claimed probability of discovery.

## Boundaries

The collector runs beside the target process. Ghidra and the model do not execute arbitrary instructions from a proposal.
The model receives bounded evidence, not unrestricted process access.
Imported trace data and binary strings are untrusted inputs.
Each model iteration retains native provider receipts. The scheduler has no local dollar limit.
