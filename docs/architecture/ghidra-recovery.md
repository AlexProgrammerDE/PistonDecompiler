# Ghidra type recovery

## Structured proposals

A type proposal contains a name, kind, byte size, fields, evidence references, and an expected prior revision.
A field contains its name, byte offset, type reference, and width.
Type references represent primitives, pointers, arrays, named structures, enums, and function pointers explicitly.
Unknown bytes remain undefined. A guessed complete layout is worse than an accurate partial layout.

A signature proposal identifies the function address, namespace or class, method name, return type, parameters, and calling convention.
Parameter order, pointer width, variadic behavior, and implicit `this` handling follow the target compiler specification.
Vtable slots use function-pointer signatures. Inheritance and overlapping fields require explicit representations rather than accidental field replacement.

## Validation and application

Resolve named types in two passes so mutually referential pointers can refer to forward declarations.
Reject unresolved references, illegal by-value cycles, overlapping structure fields, invalid sizes, and unknown calling conventions.
Separate layout evidence from semantic field names.

A change set records expected prior Ghidra values and desired values.
A preview shows exact differences before application.
One writer owns a binary. A Ghidra transaction commits the complete validated change set or rolls it back.
External Ghidra edits produce conflicts. Retrying an identical operation reconciles an uncertain outcome without duplicate changes.

## Fresh decompilation

After application, flush the decompiler cache and export affected functions and callers.
The refreshed extraction records the applied type revision and tool versions.
Do not use the destructive initial-import path to refresh an existing database.
Preserve reviews, history, evidence, and job accounting while adding new artifacts.
The scheduler releases callers only after the refreshed extraction is durable.

API references: [Function](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html),
[StructureDataType](https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/StructureDataType.html).

## Native desktop ownership

The desktop connection launches Ghidra's normal `GhidraRun` entry point and opens the extracted program in CodeBrowser.
When connected, previews, writeback, and exports operate on that same `Program` instance.
The desktop owns the project lock. No headless writer runs beside it.
See [desktop setup and persistence](../how-to/ghidra-desktop.md) for configuration and recovery behavior.
