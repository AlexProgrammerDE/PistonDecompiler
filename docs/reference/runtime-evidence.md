# Runtime evidence contract

## Identity

Each session contains a unique session ID, scenario label, binary SHA-256, image base, architecture, pointer width, and collector version.
Module-relative addresses identify code. Runtime virtual addresses alone cannot identify code across ASLR relocations.
An allocation identity combines session, process, allocation sequence, and lifetime. Reused addresses never imply reused objects.

## Observation types

| Observation | Required evidence |
| --- | --- |
| Function coverage | Function-relative address, hit count, scenario |
| Basic block coverage | Block-relative address and owning function |
| Indirect call | Caller, call site, observed target, thread |
| Argument or return | Function, invocation, argument index, raw value, ABI |
| Allocation | Allocation ID, base address, size, allocator, sequence |
| Free | Allocation ID and sequence |
| Memory access | Instruction, allocation ID, offset, width, read/write, value |
| Object snapshot | Allocation ID, offset, bytes, capture phase |
| Vtable observation | Object identity, vtable-relative address, slot targets |

A snapshot records bytes at a point in time. It does not prove that an instruction accessed those bytes.
Missing observations do not prove absence. Each session records sampling limits and dropped observations.

## Ingestion rules

Import is atomic and idempotent by session ID and content hash.
Reject a duplicate ID with different content, mismatched binary identity, invalid bounds, and impossible allocation lifetimes.
Do not invent a function for an unresolved address. Retain unresolved observations for later mapping.
Preserve provenance when summaries enter model context.
Bound input sizes, event counts, individual values, and model context independently.

## Collector approach

A Frida adapter can collect selected function arguments, return values, object snapshots, and allocator lifetimes.
Stalker can collect scoped call and block coverage. The managed recorder offers a bounded scalar x86-64 MOV access mode.
Platform allocator hooks and ABI descriptions must be explicit. Custom allocators require configured hooks.

API reference: [Frida JavaScript API](https://frida.re/docs/javascript-api/).

## JSON version 1

The importer accepts one JSON object, limited to 32 MiB and 200,000 events.
Addresses and offsets are unsigned integer values. Snapshot bytes use hexadecimal text.
Event sequence numbers increase strictly within a session.

```json
{
  "version": 1,
  "id": "example-session",
  "binary_sha256": "SHA256_OF_IMPORTED_BINARY",
  "scenario": "inventory",
  "image_base": 4194304,
  "pointer_width": 8,
  "collector": "example-adapter-v1",
  "dropped_events": 0,
  "events": [
    {"sequence": 1, "thread": 1, "function_rva": 4096, "kind": "coverage", "hits": 1},
    {"sequence": 2, "thread": 1, "function_rva": null, "kind": "allocation", "allocation": "object-1", "address": 8192, "size": 8},
    {"sequence": 3, "thread": 1, "function_rva": 4096, "kind": "snapshot", "allocation": "object-1", "offset": 0, "bytes": "640000000a000000"},
    {"sequence": 4, "thread": 1, "function_rva": null, "kind": "free", "allocation": "object-1"}
  ]
}
```

`image_base` is the Ghidra image base. `function_rva` identifies an entry point relative to the loaded module base.
A collector must subtract the runtime module base before it emits this field.

The implemented event variants are `coverage`, `block`, `call`, `argument`, `return`, `allocation`, `free`, `memory`, `snapshot`, `region`, and `marker`.
`region` uses the allocation-shaped address and size fields but makes no claim about an allocation lifetime.
Snapshots can include `invocation`, `phase` (`entry` or `return`), and `argument_index`.
Events can include `timestamp_us`, measured from collector startup with millisecond resolution.
Buffered Stalker timestamps reflect delivery, not exact instruction execution time. Thread order does not establish cross-thread causality.
Markers contain a `label` and enter each observed function’s bounded evidence context.
The Rust definitions in `src/runtime.rs` specify the fields for each variant.
The `virtual_dispatch` and `this_adjustment` variants add receiver, slot, target, and lifetime evidence.
See [C++ recovery](../architecture/cpp-recovery.md) for capture scope and validation.
Multi-process sessions remain unsupported.

Each function receives up to 128 sampled observation lines per session in model evidence.
Referenced allocation records accompany those samples.
The full trace remains in the database. Context limits can exclude evidence from an individual model request.
