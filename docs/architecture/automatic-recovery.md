# Automatic Ghidra recovery

Starting analysis authorizes AI validation and Ghidra writeback. No manual review gate remains in the normal workflow.
Runtime recordings can still require a person to exercise the target application.

## Field decisions

Jev assesses names, summaries, and type plans independently against the supplied evidence.
A supported verdict authorizes a name or summary. Confidence scores remain diagnostic data and do not gate these fields.
Names describe observed behavior; they need not match the original source or imply a single responsibility.
Type changes also require local structural checks and a successful Ghidra transaction preview.
Jev separately assesses up to eight cited claims, signatures, and local changes per result.
An unsupported combined plan can retain independently supported signatures and locals with valid dependencies.
The complete verdict map and accepted type plan remain in the result audit.
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
If native local identities change during preview, recovery omits the local refinements and retries the remaining layouts and signatures.
This repair uses native validation only. It does not repeat model analysis.
The audit retains the omitted-local outcome alongside the applied type plan.

Fresh decompilation invalidates results when instruction P-code or structural type evidence changes.
Cosmetic symbol, local-name, and prototype-name changes do not invalidate callers.
A new model interpretation also does not invalidate callers by itself. Explicit corrections still invalidate their dependents.

Selected runs create prompts when jobs execute, after their callees finish. Investigation prompts retain their explicit scoped question.
Each prompt records fingerprints of its function and direct callees: instruction P-code, structural types, and runtime artifacts.
Recovery compares these fingerprints before scheduling a follow-up.
A changed fingerprint can qualify an unresolved or stale function.
The model can also return `context_requests` with a specific question, function address, evidence kind, and line range.
Recovery fetches up to three bounded excerpts from that function or its direct callers and callees.
Only existing stored evidence qualifies: pseudocode, types, instruction P-code, disassembly, or runtime observations.
Already supplied excerpts, repeated requests, unavailable data, and requests outside this scope do not qualify.
Models never request recordings, user input, or manual actions. Unavailable data leaves the best supported result in place.
Low confidence, ambiguous names, and mixed responsibilities cannot trigger another pass.
Legacy prompts without fingerprints stop conservatively until a fresh analysis establishes their baseline.

Follow-ups use the normal input budget. They skip repeated preprocessing and ask the model to reconsider conclusions affected by changed evidence.
The server allows three total passes, including the initial pass. The CLI accepts one through five.
The pass limit is a ceiling. Unchanged evidence ends the cycle early, even with unresolved fields.
The pipeline does not invent an evidence request from an uncertainty score.
A user can independently import recordings; that is separate from automatic model work.

Invalid type proposals and invalid citations are omitted locally while useful behavior is retained when possible.
An unusable response ends with a reported failure instead of repeating the whole analysis for the same validation error.
Transport failures retain bounded retries. Unsupported verification verdicts do not trigger paid model escalation.
Supported fields can still be applied; unresolved fields remain documented without requiring manual review.

## Durable phases

SQLite stores assessment, names, types, refresh, and reanalysis phases in `automatic_recovery`.
Each cycle retains its operation IDs, pass count, failure count, and status reason.
`recovery_passes` retains each run ID, pass number, selected function count, and selection reason.
Join its run ID to `jobs` and `provider_requests` for actual provider charges.
Missing receipts remain unknown; no estimated costs replace them.
A restart clears the abandoned writer flag and resumes the persisted phase.
An interrupted writeback reconciles the exact saved operation before continuing.
Three unsuccessful attempts end the cycle with a reported failure.

Pause stops new phases and model requests. An operation already saving Ghidra is allowed to finish.
Provider limits and unresolved provider requests remain separate operational states.
They do not create a manual proposal-review queue or fabricate provider costs.

The progress report shows the active phase and pass count.
The pass limit is not an ETA. Timing remains unavailable when no reliable estimate exists.
