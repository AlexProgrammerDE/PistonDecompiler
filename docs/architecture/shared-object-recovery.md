# Shared object recovery

This document explains how binary evidence improves partial layouts across functions.
It describes the implementation and its current limits for developers.

## Evidence boundary

Recovery reads the imported binary, Ghidra exports, existing program types, and recorded runtime artifacts.
The inference path does not read reference source, evaluation reports, or external source repositories.
Reference source belongs only to evaluation. Test fixtures compile small programs, but inference receives their binaries and exports.

## Shared context

The exporter records these facts from decompiler SSA operations:

- Parameter indices, widths, and existing type identities.
- Reads and writes through parameters, with constant offsets, access widths, and instruction addresses.
- Direct call argument transfers, with source and destination parameter indices.
- Comparisons and return operations for interpretation of signedness, flags, and return values.

The origin resolver follows bounded, lossless copies and constant pointer adjustments.
It does not follow loads or ambiguous merges as proof of object identity.

Zero-offset argument transfers connect parameter views across functions.
Parameters with the same existing structure type also share layout context.
This relationship describes compatible type views, not a claim that runtime object instances are identical.
Nonzero offsets remain subobject evidence. They do not merge the enclosing layouts.
Names and matching offsets alone do not connect objects.

Each prompt includes bounded artifact excerpts from related functions and direct callers.
Caller evidence helps interpret return values as well as argument roles.
Some untyped call sites omit arguments in decompiler SSA. Those missing links remain unknown until better signatures expose them.
Existing inferred names remain hypotheses, rather than independent confirmation.

Traversal stops after 4,096 parameter nodes and returns at most 64 related functions.
The prompt byte budget also limits excerpts. These bounds do not imply complete alias coverage.

## Partial and complete layouts

A structure has an `extent` property:

```json
{"kind":"minimum"}
```

This default means `size` is the known extent of a partial view.
Unknown bytes between fields are not proven padding.
Older proposals without extent metadata also use this interpretation.
A partial view can describe an object through a pointer.
It cannot define a by-value parameter, return value, embedded field, or array element stride.
Ghidra still materializes a concrete prefix length. Implicit pointer arithmetic therefore remains an interpretation that needs evidence and native checks.

A complete layout requires a citation to supplied binary evidence:

```json
{"kind":"exact","artifact_id":"artifact-id","start_line":12,"end_line":16}
```

The citation check establishes provenance, not semantic proof of completeness.
The automatic assessment still evaluates the interpretation.
Verified array strides or binary type metadata can support an exact size.
An allocation capacity alone does not establish the size of an object within that allocation.

Compatible proposals for the same named layout can combine fields when they share an identical field.
Conflicting field identities remain unresolved. Final validation checks bounds and overlaps in the combined plan.
Different proposed type names do not automatically become aliases.

## Native trials and persistence

A preview opens a separate copy of the saved Ghidra program.
The trial applies the proposed definitions and signatures, then decompiles the affected code.
Layout trials examine all available nonexternal, nonthunk functions because global type changes can affect distant uses.
Signature trials examine the target and its callers. Local trials include the containing function.

Trials reject new decompilation failures, changed decompiler warnings, and increased partial-register artifacts.
Before-and-after metrics remain in the operation report.
Functions that already fail to decompile remain unavailable evidence. Their presence does not establish a successful validation.
These checks detect regressions. They do not prove field meaning or recover the original source type.

Writeback preserves existing fields omitted by a later partial proposal.
It grows partial layouts without shrinking earlier observations.
A field replacement must match existing component boundaries.
Conflicting offsets, partial overlaps, or size claims that discard evidence stop the operation.
Automatic recovery splits rejected proposal groups and retains changes that pass native trials together.
The saved program retains extent metadata, operation markers, and accumulated fields.

## Improvement triggers

Evidence fingerprints include related object users, callers, callees, and runtime artifacts.
Recovery considers previously accepted results as well as unresolved results.
A relevant evidence change can trigger another pass within the configured pass limit.
Without changed evidence or a specific available context request, recovery retains the current result.
It does not request human review or new recordings.

## Limits and validation

The implementation supplies shared evidence to the model. It is not a complete points-to analysis.
It does not automatically unify differently named types or infer every allocation boundary.
Boolean, signedness, field meaning, and count-versus-index interpretations still require evidence-based inference.
Existing incorrect annotations do not become correct merely through a refresh.

Unit tests cover object-flow boundaries, layout merging, and invalid uses of partial layouts.
Native tests cover field accumulation, overlap rejection, isolated previews, and saved state preservation.
Source comparisons remain separate evaluation artifacts.
