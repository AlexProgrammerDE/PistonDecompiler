# Structured type plans

The model response contains an optional `type_plan` object.
Empty `definitions` and `signatures` arrays mean that no type change is proposed.

```json
{
  "definitions": [
    {
      "kind": "structure",
      "name": "Player",
      "size": 8,
      "fields": [
        {"name": "health", "offset": 0, "data_type": {"kind": "primitive", "name": "i32"}},
        {"name": "armor", "offset": 4, "data_type": {"kind": "primitive", "name": "i32"}}
      ]
    }
  ],
  "signatures": [
    {
      "address": "00401000",
      "name": "take_damage",
      "namespace": ["Player"],
      "return_type": {"kind": "primitive", "name": "i32"},
      "parameters": [
        {"name": "player", "data_type": {"kind": "pointer", "to": {"kind": "named", "name": "Player"}}},
        {"name": "amount", "data_type": {"kind": "primitive", "name": "i32"}}
      ],
      "calling_convention": "",
      "variadic": false
    }
  ]
}
```

## Supported references

- `primitive`: `void`, `bool`, signed and unsigned integers of 8, 16, 32, or 64 bits, `f32`, and `f64`.
- `named`: a definition included in the same plan.
- `pointer`: a pointer to another reference.
- `array`: an element reference and a positive count.
- `function`: a return reference and ordered parameter references, used through a pointer.

Enumeration definitions contain `kind: enumeration`, `name`, `size`, and a `values` map of member names to integers.
Function pointers permit typed vtable layouts. Identifying vtable slots remains an evidence problem rather than a guaranteed inference.

## Constraints

Plans contain at most 128 definitions and 128 signatures.
Structures contain at most 512 fields and occupy at most 1 MiB.
Signatures contain at most 64 parameters. Type nesting cannot exceed 32 levels.

Named references must resolve. By-value cycles, overlapping fields, invalid array sizes, and invalid identifiers fail validation.
Pointer width comes from the target Ghidra program during preview.
Signatures from a per-function model request can only target that function.

Recovered definitions live in `/PistonRecovered`.
The writer uses expected prior definitions and signatures to detect external edits.
Unknown bytes remain undefined. Existing unrelated Ghidra types remain outside the recovered category.

Unions, bitfields, overlapping subobjects, and explicit register or stack parameter storage are not supported by this format yet.
Ghidra assigns parameter storage through the selected calling convention.
The format does not promise complete C++ ABI recovery.

## C++ plans and locals

An optional `cpp` object extends the same validated transaction:

```json
{
  "classes": [
    {"name": "Player", "bases": [{"name": "Entity", "offset": 0, "virtual_base": false}], "vptrs": [{"offset": 0, "table_type": "EntityVtable"}]}
  ],
  "vtables": [
    {"address": "00403000", "table_type": "EntityVtable", "targets": ["00401000", "00401200"]}
  ],
  "locals": [
    {"function": "00401000", "storage": "Stack[-0x10]:4", "first_use": "00401008", "expected_name": "local_10", "name": "remaining_health", "data_type": {"kind": "primitive", "name": "i32"}}
  ]
}
```

Copy local storage and first-use values from exported evidence. The example identities above are illustrative.
Supply the referenced structure definitions in the enclosing plan.
Base subobjects must match embedded fields. Vptrs must match pointer fields, including fields inside bases.
Vtable bindings require supplied static slot evidence and exact matching pointer bytes in Ghidra.
Class metadata supports fixed observed layouts, including multiple vptrs and virtual-base annotations.
It does not calculate unknown virtual-base offsets or represent overlapping subobjects.

Each plan permits 128 classes, 128 table bindings, and 256 local refinements.
Local changes can only target the function under analysis. Conflicting plans are deferred automatically.
