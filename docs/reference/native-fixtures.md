# Native instruction fixture format

The `piston-native` package uses Unicorn to execute selected PE32+ AMD64 instructions.
Capstone provides bounded disassembly through the Python API.
The executable stays at its preferred image base. The runner does not resolve imports or launch the game.

## Manifest

```json
{
  "format": 1,
  "sha256": "replace-with-the-executable-sha256",
  "instruction_limit": 30000,
  "timeout_ms": 1000,
  "return_boundaries": [],
  "patches": [],
  "cases": [
    {
      "id": "addition",
      "entry_rva": "0x1000",
      "input": {"a": 5, "b": 7},
      "registers": {"RCX": 5, "RDX": 7},
      "stack_arguments": [],
      "memory": [],
      "observe": [{"name": "result", "register": "RAX"}],
      "expected": {"result": "0xc"}
    }
  ]
}
```

This example assumes an addition function at RVA `0x1000`.
It cannot run until you supply the matching executable and hash.

| Field | Meaning |
| --- | --- |
| `format` | Must be `1`. |
| `sha256` | Exact executable SHA-256, as 64 lowercase hex digits. |
| `instruction_limit` | Maximum instructions per call, from 1 to 1,000,000. |
| `timeout_ms` | Per-call time limit, from 1 to 10,000 milliseconds. |
| `cases` | From 1 to 10,000 cases with unique string IDs. |
| `entry_rva` | Entry address relative to the PE image base. |
| `registers` | General registers or XMM registers as integers or `0x` strings. XMM values contain raw bits. |
| `stack_arguments` | Up to 32 arguments after the first four Windows x64 register arguments. |
| `memory` | Objects with absolute `address` and initializer bytes in `hex`. |
| `observe` | Named register observations or memory observations with absolute `address` and `length`. |
| `expected` | Optional exact observations that the native result must match. |
| `input` | Translation inputs passed unchanged to a local comparator. |

The runner owns `RSP` and `RIP`. The synthetic arena starts at `0x7000000000` and spans `0x40000` bytes.
Each case gets a fresh machine. Mutable memory and register values do not carry across cases.
PE virtual section tails are zero-filled. Undeclared addresses outside the image or arena fail.
`pistondecompiler native-test` and its MCP tool also enforce a 120-second process limit and bounded input/output files.

## Explicit boundaries and patches

A `return_boundaries` entry contains a function `rva` and optional integer `value`.
At that address, the runner supplies `RAX` and returns to the caller.
This records a supplied boundary, rather than proving the intercepted function's behavior.

A `patches` entry contains `rva` and `hex` replacement bytes.
Use patches only when your fixture needs a documented setup change.
Global and per-case boundaries and patches appear in the output.
Record their purpose with the private fixture evidence.

No allocator, OS API, registry accessor or security-cookie stub is installed automatically.
For complex object graphs, import `PEImage` and `NativeMachine` from Python.
Use `allocate`, `write`, `qword`, `call`, `hook_return`, or explicit Unicorn hooks to supply the required boundaries.

## Translation comparison

`--compare` runs a trusted local command with an argument array, without a shell.
The command receives JSON lines containing `id` and `input`.
It must return one line per case containing the same `id` and an `observed` object.

Register observations use lowercase `0x` strings without leading zeroes.
Memory observations use lowercase byte hex strings.
The comparison is exact and requires every case once.
The runner exits with failure when observations differ.
The report lists mismatches and preserves the native observations.

Keep proprietary instructions, raw exports, credentials and game-specific fixtures private.
The checked-in tests use a synthetic PE image authored for the test suite.
