# C++ recovery

C++ recovery extends the automatic analysis and Ghidra writeback cycle. It does not introduce a manual review queue.
The model proposes supported changes from static and runtime evidence. Existing independent field assessments still control application.

## Static evidence

Each function's `type_context.cpp` contains qualified symbols, symbol aliases, thunk targets, local variable identities, and indirect-call sites.
It also contains relevant pointer-table candidates and bounded store observations.
Constructor, destructor, and wrapper indicators are candidates, not confirmed classifications.
Ghidra's existing demangling supplies qualified names when symbols are available.

The exporter scans initialized, readable, non-executable blocks for runs of known function pointers.
It examines at most 32 MiB per block, 4,096 tables, and 128 slots per table.
A table needs at least two consecutive known targets. Single-slot tables can remain unresolved.
Tables enter a function's context when it references them or appears among their targets.

For possible Itanium tables, the exporter records the preceding offset-to-top and RTTI pointer.
Identified typeinfo can supply an encoded name and single or multiple inheritance descriptors.
A virtual-base descriptor's offset identifies a vtable location, not a fixed object offset.
Absent symbols or unsupported RTTI encodings remain unresolved. Pointer runs alone do not prove C++ class identity.

## Runtime evidence

Investigate recordings enable bounded object-dispatch capture on x86-64.
The collector uses the Windows x64 or System V receiver register, depending on the target platform.
At tracked indirect calls, it matches the receiver's vptr and table entries against the actual target.
Memory operands can identify an exact slot. Ambiguous duplicate targets are omitted when the operand cannot distinguish their slots.

`virtual_dispatch` records the call site, target, vtable RVA, slot offset, receiver address, object identity, and subobject offset.
Known allocations retain their lifetime identity. Unknown readable regions remain observations with unknown lifetime.
`this_adjustment` links a dispatch invocation to an observed method-entry receiver.
Known thunk targets allow the collector to compare the receiver after an adjustor thunk.
An adjustment is only recorded when both receivers belong to the known region or allocation.

The importer rejects expired objects, invalid receiver bounds, misaligned slots, and unmatched receiver adjustments.
Observed targets extend the scheduling graph. Missing targets never prove that another implementation is impossible.
Capture remains scoped to the main module, selected functions, supported instructions, and sampling limits.

## Class and readability plans

`type_plan.cpp` contains class layouts, vtable bindings, and local refinements.

- A class references an ordinary structure definition. Bases are explicit embedded structure fields with offsets and virtual-base metadata.
- Multiple vptrs can belong to the object or its embedded bases. Each must match a typed pointer field.
- A vtable binding names its address, structure type, and ordered observed targets. Each slot requires a function-pointer field.
- A local refinement uses the function address, storage, first-use address, and expected name from the decompiler export.

Existing signatures provide method namespaces and named parameters. Existing enum definitions support evidence-backed state and flag types.
The analysis prompt asks for state-transition and wrapper explanations in summaries.
Renaming is conditional on stable variable identity, rather than matching a temporary name alone.
Unsupported overlapping base layouts, missing identities, and conflicting definitions are deferred automatically.

## Saved Ghidra state

The type writer previews all changes in a rolled-back transaction before application.
It checks vtable pointer bytes and known targets before defining typed data at the table address.
It persists class layout metadata, class namespaces, types, and local names in the native project.
Local refinements use Ghidra's decompiler variable API and require fresh decompilation afterward.

Recording publication adds observed computed-call references without replacing other observed targets or forcing a unique target.
It saves the project, verifies references after reopening, and refreshes exported pseudocode.
The existing bounded recovery cycle then analyzes changed evidence.

## Validation

`fixtures/cpp/dispatch.cpp` exercises virtual methods, multiple inheritance, secondary base receivers, and repeated object lifetimes.
`tests/cpp.rs` checks model-plan constraints and trace validation without external tools.
Its native integration test requires Ghidra, g++, and a Python environment containing Frida.
It exercises extraction, capture, saved references, typed vtables, class metadata, local renaming, and reopened-project verification.

These checks verify the machinery against known source. They do not establish complete C++ ABI recovery for arbitrary binaries.
