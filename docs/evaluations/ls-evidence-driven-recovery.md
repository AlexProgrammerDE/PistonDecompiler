# ls recovery evaluation, 20 September 2026

The revised policy selected 107 of 197 functions for pass 2 (54.3%).
The previous policy selected 189 (95.9%). That is 82 fewer functions, a 43.4% reduction.

All three passes and native Ghidra writeback are complete. Pass 3 selected 44 functions, or 22.3% of the original 197. All selected functions completed analysis and verification.

The cycle stopped at the three-pass limit with 86 functions retaining uncertain or unapplied fields. Its terminal status is `deferred`; this does not request manual review. See the [readability comparison](ls-readability.md) for measured improvements and limitations.

## Conditions

The evaluation uses the existing saved Ghidra project and recorded runtime evidence.
It does not restore the original untouched binary analysis, so this is not a controlled comparison of identical starting states.
The reasoning model remains `deepseek/deepseek-v4.1-flash`; Jev remains `typesafe/jev-1.13`.
The input budget stays at 24,000 bytes in every pass. Follow-ups skip repeated preprocessing.

Pass 1 analyzed and verified all 197 eligible functions, without permanent job failures.
Its request-processing span was 1,243 seconds, about 20 minutes 43 seconds.
There were 610 provider requests: 591 normal stage requests and 19 additional attempts.
Transport retries and malformed decision metadata account for the overhead; no confidence-triggered full-analysis retries were scheduled.

## Native writeback

The first pass saved changes to 135 functions: 38 function names and 123 comments changed.
These counts overlap because some functions received both changes.
After native validation repair, 57 result plans were applied to the saved Ghidra project.
Unsupported fields remain omitted automatically. No manual review or new recording is requested.

The live run exposed a native validation defect: one changed local-variable identity rejected the combined type preview.
Recovery now omits local refinements when this identity check fails, then validates the remaining layouts and signatures again.
The original model outputs and the accepted subset remain in the audit.

An initial pass-2 attempt selected 37 functions before this defect was repaired.
That number is not the final comparison: it excluded useful follow-ups from type writeback that had failed.
The attempt was stopped after 15 model results and three verifications.
Its remaining jobs were cancelled, and its receipts were retained.
The completed pass-1 checkpoint was reused for native repair; pass 1 was not purchased again.

## Why 107 functions qualify

| Reason | Functions |
| --- | ---: |
| Native evidence changed after type writeback | 90 |
| Model requested available evidence not previously supplied | 17 |
| Total | 107 |

There were 55 explicit context-request results in pass 1.
Requests for existing evidence do not qualify automatically: the resolver checks availability, scope, prior excerpts, and the context budget.
Requests can fetch stored pseudocode, disassembly, instruction P-code, type context, and runtime observations.
They cannot create manual tasks or request recordings.

## Provider charges

These are sums of raw OpenRouter receipt costs, without local estimates.
Missing costs are unknown, not zero.

| Scope | Reported cost, USD | Missing cost receipts |
| --- | ---: | ---: |
| Completed pass 1, 197 functions | 0.6481689604 | 15 |
| Completed pass 2, 107 functions | 0.3066581596 | 4 |
| Completed pass 3, 44 functions | 0.1319140364 | 2 |
| Interrupted diagnostic attempt | 0.0330012806 | 0 |
| Previous policy's completed pass 2 | 0.93929789 | 27 |

The three completed passes reported $1.0867411564. Including the interrupted diagnostic attempt, the experiment reported $1.1197424370. There are 21 missing cost receipts across the completed passes.

Passes 2 and 3 together reported $0.4385721960, 53.3% less than the previous pass 2 alone. The corrected pass 2 alone reported 67.4% less. These compare reported charges, not complete invoices or controlled runs from identical starting states.

The three native type operations applied 57, 37, and 9 result plans. Their definition/signature counts were 7/55, 6/35, and 2/9. These overlap across passes and must not be summed as unique recovered types. None applied explicit local-variable refinements after the native identity fallback.

A read-only reopening of a copy of the saved Ghidra project reproduced all 416 exported function names, comments, pseudocode bodies, and parsed type contexts. No definitions were replayed for this check.

## Reproducibility

- Binary ID: `df3f9f19-a4de-4821-8d8e-b35e5226253f`.
- Pass-1 run: `239bb4dd-4bab-45a3-81b3-c6aff4e01b26`.
- Interrupted attempt: `144d1fef-24f5-4b62-b40f-cbb588574616`.
- Corrected cycle: `9e3fe8cc-a06d-42f4-9653-a7945b9da60c`.
- Corrected pass-2 run: `e9930bf8-6130-4016-8b51-762c0bd997aa`.
- Pass-3 run: `fd0a8d36-e485-41d0-828b-d45a1263e279`.

`recovery_passes` preserves the selected counts and run IDs.
Join `provider_requests.job_id` to `jobs.id`, then group by `jobs.run_id` for native charges.
Result audits preserve each function's follow-up reason, verifier verdicts, and accepted type plan.
