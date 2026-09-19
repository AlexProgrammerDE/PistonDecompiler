# Evaluate analysis quality

This corpus exercises configuration parsing and file handling across compiler optimizations.
It separates behavioral correctness from exact symbol recovery.

## Build

Run from the repository root with a C compiler and `strip` installed:

```bash
bash fixtures/evaluation/build.sh /tmp/pistondecompiler-evaluation
```

The script creates `O0`, `O2`, and `Os` binaries, plus stripped copies.
Source code and `expected.json` provide ground truth. Do not include them in model prompts.

## Compare runs

1. Import and extract one stripped binary with Ghidra.
2. Run the initial map pass with explicit provider prices and a budget.
3. Locate the configuration loader and create an investigation using the question in `expected.json`.
4. Save the map results before requesting deeper evidence analysis on the same scope.
5. Review both result revisions against the source and the rubric.
6. Correct an incorrect callee finding. Check that dependent findings become stale, then rerun only that scope.
7. Restart the backend and confirm that notes, revisions, evidence, and accounting remain available.
8. Preview accepted changes, apply them, and export the Ghidra project again to verify persistence.

For each binary and pass, record the model, provider, configuration, supported findings, unsupported claims,
unresolved findings, elapsed time, corrections, and accounted cost.
Record Ghidra and compiler versions. Compare equivalent scopes rather than raw function counts across optimization levels.
Citation validation checks reference existence and line ranges. Human review must check whether each reference supports its claim.

## Current verification

The local verification used Ghidra 12.1.3 and the stripped O0 binary on Linux.
It indexed 28 functions and 20 call edges, then exercised 10 eligible functions through Rig with a local fixture provider.
A reviewed name and comment survived apply and a fresh export. A second preview contained no changes.
The fixture provider deliberately returns synthetic content; this verifies integration, not model quality.
No paid model comparison has been performed. O2 and Os quality measurements remain to be recorded.
