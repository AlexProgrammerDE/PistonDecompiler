# Automatic parameter experiments

Parameter recovery tests plausible interpretations before it saves them in Ghidra. A rejected signature no longer prevents useful parameter names from being tried independently.

## Source analysis

This implementation adapts algorithmic ideas from these sources. It does not copy or vendor their code.

- TypeForge's [InterSolver](https://github.com/noobone123/TypeForge/blob/0f2ceff872362a1e4a4e927c589f9f5be465ebeb/src/main/java/typeforge/base/dataflow/solver/InterSolver.java) joins argument and parameter relationships across functions.
- Its [SlidingWindowProcessor](https://github.com/noobone123/TypeForge/blob/0f2ceff872362a1e4a4e927c589f9f5be465ebeb/src/main/java/typeforge/base/passes/SlidingWindowProcessor.java) tests repeated, contiguous layout patterns and excludes inconsistent offsets.
- Its [double-elimination selection](https://github.com/noobone123/TypeForge/blob/0f2ceff872362a1e4a4e927c589f9f5be465ebeb/scripts/judge/double_elimination.py) compares decompiled variants with an LLM. Its [DecompilerHelper](https://github.com/noobone123/TypeForge/blob/0f2ceff872362a1e4a4e927c589f9f5be465ebeb/src/main/java/typeforge/utils/DecompilerHelper.java) applies types through native high symbols.
- BTIGhidra's [runner](https://github.com/trailofbits/BTIGhidra/blob/6d0495f3b9587eb5ee5ab7627fc65be6dedddeed/plugin/src/main/java/binary_type_inference/BinaryTypeInferenceRunner.java) delegates inference to a separate engine.
- That engine's [constraint generation](https://github.com/trailofbits/binary_type_inference/blob/349faf33dc9737e19e896367315235f9c0e64513/src/constraint_generation/mod.rs) links actual and formal arguments. Its [SCC solver](https://github.com/trailofbits/binary_type_inference/blob/349faf33dc9737e19e896367315235f9c0e64513/src/solver/scc_constraint_generation.rs) builds summaries in dependency order.

Our adaptation uses a bounded, deterministic search over parameter edits. It does not implement TypeForge's layout enumeration or BTIGhidra's full subtyping solver.

## Candidate generation

The analysis response accepts `parameter_candidates`, separate from the supported `type_plan`:

```json
{
  "parameter_candidates": [
    {"index": 0, "name": "buffer", "data_type": null},
    {"index": 1, "name": "length", "data_type": {"kind": "primitive", "name": "u64"}}
  ]
}
```

The index identifies a parameter in the current decompiled prototype. A null type requests a name-only experiment. The prompt requests descriptive candidates for used anonymous parameters, including uncertain interpretations. It does not request invented roles for unused arguments.

Existing structured signatures also supply candidates, even if their full-signature verifier verdict was uncertain. Names and types become separate trials. Missing named definitions prevent a type trial, but do not prevent its name trial.

Native analysis supplies additional types from direct calls. It traces unchanged parameter values through COPY and same-width CAST operations into callee parameters. Conflicting callee types suppress that propagated candidate. A shared descriptive callee parameter name can also supply a naming candidate when no AI name wins. Arithmetic, loads, and PHI joins do not merge unrelated objects. This is a restricted constraint transfer, not general alias analysis.

Functions are processed in call-graph dependency order. Existing recovery passes handle subsequent evidence changes. Experiments themselves make no additional provider requests.

## Native selection

`PistonParameters.java` opens a separate copy of the saved program. Each candidate is applied there, then the function and its direct callers are re-decompiled. A transaction rollback removes the trial. The script checks the prototype and storage state after rollback.

The search starts with the existing interpretation. Accepted edits remain in the candidate bundle for later trials. A later type can replace an earlier choice only if its measured output improves. Name alternatives do not repeatedly rename the same parameter.

Checks preserve parameter count and storage. Candidate types must match the inferred parameter width. The experiment does not change the return type, calling convention, function name, or namespace.

The comparison checks partial-register expressions, casts, undefined-type spellings, structure member access, and decompiler diagnostics. Type trials must not increase casts. Name-only trials may expose additional casts when Ghidra commits previously inferred parameter types. Those casts remain in the audit; naming does not count as proof of type correctness. A caller that already fails to decompile blocks type trials, but does not stop independent names or other functions. An unavailable target is recorded without changes.

A more specific type can replace an unknown type when the output passes these checks. Semantic names remain provisional AI interpretations. Readability measurements do not establish equivalence with original source.

The scope is bounded to 64 parameters and 64 direct callers. Functions with implicit ABI parameters or custom storage retain their existing interpretation. AI candidates are limited to 192 entries per function.

## Persistence and scheduling

Automatic recovery runs these experiments after ordinary type writeback and before the final pseudocode refresh. No manual review is required.

`parameter_operations` stores one durable operation per function, recovery cycle, and pass. Each report records candidate outcomes and native coverage before and after selection. A marker in the saved Ghidra program permits reconciliation after an interrupted response. Completed operations do not repeat their trials after a process restart.

The native bridge saves winners before acknowledging them. A fresh export then supplies the next recovery pass with the changed evidence. The three-pass cap still applies.

## Limits

This change increases opportunities to recover parameter names and types. It does not guarantee a particular coverage percentage. Existing recordings inform AI candidates through the normal evidence context; native trials do not request new recordings.

Local-variable remapping, arbitrary class-layout alternatives, implicit C++ ABI parameters, and full bidirectional constraint solving remain separate work. The native checks are heuristics and can reject useful candidates or accept imperfect interpretations.

## Measured validation

The native fixture changed from zero named parameters out of two to two out of two. It rejected an incompatible floating-point candidate while retaining independent names. A new Ghidra process reproduced the saved operation report without repeating trials. The complete automatic recovery integration test also passed with deterministic local model responses.

A separate saved copy of the `ls` project tested 25 functions whose existing AI signatures still contained anonymous native parameters. These functions had 46 parameters in total. Experiments named 28 of them across 16 functions, without additional provider requests. All 25 operations completed.

This selected subset went from 0/46 to 28/46 named parameters. It is not a whole-binary coverage percentage. The count of parameters with non-unknown native types stayed at 17/46. These results demonstrate naming gains from existing proposals, not additional type recovery or the performance of a fresh AI run using the new candidate schema.

Local reports and the saved comparison project are under `data/ls-evaluation/parameter-experiments/`. The comparison did not replace the user's live Ghidra project.
