# Automatic Ghidra recovery

Starting analysis authorizes AI validation and Ghidra writeback. No manual review gate remains in the normal workflow.
Runtime recordings can still require a person to exercise the target application.

## Field decisions

Jev assesses names, summaries, and type plans independently against the supplied evidence.
A field passes when both its confidence and supported probability meet the configured decision threshold.
Model confidence alone does not authorize writeback.
Missing assessments, uncertain fields, and stale results are deferred automatically.

A rejected type plan does not prevent a supported name or summary from being applied.
Conflicting definitions or signatures defer all source plans in that conflict. Independent plans remain eligible.
The saved result includes the automatic field outcomes and reason.
Historical evidence, result revisions, and provider receipts remain available.

## Writeback and reanalysis

After the active queue drains, recovery claims the binary's writer flag and the Ghidra process semaphore.
Provider job claims cannot run while this writer flag is held.
Names and comments use saved expected-value change sets.
Type previews exercise the full plan inside a Ghidra transaction and roll it back.
Application uses the validated plan and saves the native project.
An unchanged type plan needs no second application.

Fresh decompilation invalidates results whose code or type context changed, including dependent results.
Those functions enter another analysis run using the existing callee-first SCC scheduler.
The server allows three total analysis passes, including the initial pass. The CLI accepts one through five.
Unresolved fields also qualify for another pass when wider context supplies new evidence.
The second pass doubles the input allowance; the third quadruples it, capped at 96,000 bytes unless the configured base exceeds that.
Recovery adds caller and callee code, available runtime artifacts, and the previous assessment.
Previous model output is feedback, not source evidence.
A function stops early when the wider prompt contains no new evidence.
Supported fields from the final pass can still be applied. Remaining uncertainty is deferred automatically. This is a bounded stopping condition, not a claim that all functions are understood.

## Durable phases

SQLite stores assessment, names, types, refresh, and reanalysis phases in `automatic_recovery`.
Each cycle retains its operation IDs, pass count, failure count, and status reason.
A restart clears the abandoned writer flag and resumes the persisted phase.
An interrupted writeback reconciles the exact saved operation before continuing.
Three unsuccessful attempts end the cycle with a reported failure.

Pause stops new phases and model requests. An operation already saving Ghidra is allowed to finish.
Provider limits and unresolved provider requests remain separate operational states.
They do not create a manual proposal-review queue or fabricate provider costs.

The progress report shows the active phase and pass count.
The pass limit is not an ETA. Timing remains unavailable when no reliable estimate exists.
