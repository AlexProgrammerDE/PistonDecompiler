# Research a binary through Ghidra and MCP

Use this workflow to trace a small group of native functions and retain verified interpretations.

## Connect an MCP client

Start PistonDecompiler with your existing configuration:

```sh
cargo run --release -- --config pistondecompiler.toml serve
```

Connect your MCP client to `http://127.0.0.1:7070/mcp` using Streamable HTTP.
Use the configured listen port if it differs from 7070.
The endpoint shares the web application's Ghidra gate and desktop connection.
It accepts loopback hosts and matching local browser origins.
After upgrading an already running desktop bridge, close its project and reopen it through PistonDecompiler.
This loads the new query and annotation scripts.

If the web server is stopped, you can use stdio instead:

```sh
pistondecompiler --config /absolute/path/pistondecompiler.toml mcp
```

Configure this executable and its arguments in your MCP client.
Use an absolute configuration path so the client can start from another directory.
The stdio command holds the data-directory lock. It cannot run beside the web server.

## Inspect related functions

1. Call `list_binaries` to select the imported binary and verify its hash.
2. Open its [Ghidra desktop](ghidra-desktop.md) if you want to inspect the same program in CodeBrowser.
3. Call `query_program` with up to 32 queries.
4. Follow callers, cross-references and table slots to identify related functions.

For example:

```json
{
  "binary_id": "your-imported-binary-id",
  "queries": [
    {"kind": "function", "address": "140001000"},
    {"kind": "references", "address": "140001000", "direction": "callers"},
    {"kind": "memory", "address": "140001000", "length": 64, "disassemble": true},
    {"kind": "vtable", "address": "140010000", "count": 16}
  ]
}
```

The addresses above are examples. Use addresses from your imported program.
Save the query array to a file to use the same operations from the CLI:

```sh
pistondecompiler query-program BINARY_ID queries.json
```

Each batch returns program identity, image base, pointer width and individual query outcomes.
A missing function produces an error for that query. Other queries can still succeed.
Read queries do not change program annotations.
A disconnected desktop prevents headless fallback while ownership remains uncertain.

## Save verified annotations

1. Pause binary analysis through the web app or `pistondecompiler control BINARY_ID pause`.
2. Inspect each function with `decompile: false` to obtain `local_name` and `comment`.
3. Call `preview_annotations` with those values as `expected_name` and `expected_comment`.
4. Inspect the returned operation and call `apply_research_operation` with its exact ID.

Names must be identifiers. Comments can contain your evidence and remaining uncertainties.
Use function entry addresses, rather than addresses inside their bodies.
The apply operation checks every inspected value before changing any annotation.
If one value changed, it rejects the batch without applying its annotations.

Use `preview_research_types` for [structured types and signatures](../reference/type-plans.md).
The existing type engine validates the plan in an isolated program before returning its operation ID.
Type writeback also refreshes the indexed decompilation. This refresh can be slow for large programs.
Name and comment writeback updates the corresponding index entries without a full export.

Successful desktop writeback saves the program, including existing unsaved manual edits.
If a request times out, is cancelled, or loses its connection, inspect `get_research_operation`.
Retry the same operation ID to reconcile an uncertain outcome.
The saved marker prevents a retry from overwriting subsequent changes.
Do not create a replacement operation to bypass unresolved writeback.

## Verify behavior with native instructions

Install the fixture runner in a private Python environment:

```sh
python3 -m venv .venv-native
.venv-native/bin/python -m pip install ./scripts/native
```

On Windows, use `.venv-native\Scripts\python.exe` for these commands.
Set `runtime_python` in your Piston configuration to this environment's Python executable.
This setting also selects the Python interpreter for runtime recording.
Install the recording dependencies there if you use both features.

Keep executable files and fixtures under ignored `data/` or `captures/` directories.
Create a fixture using the [native fixture format](../reference/native-fixtures.md).
Pin it to the executable's SHA-256 hash.

Run it from the CLI:

```sh
pistondecompiler native-test BINARY_ID fixture.json
```

For MCP, put the fixture in `data/binaries/BINARY_ID/native-fixtures/`.
Call `run_native_fixture` with its relative path. The tool does not accept comparator commands.

To compare a Java translation, use the standalone runner:

```sh
.venv-native/bin/python -m piston_native fixture.json --binary captures/game.exe \
  --output data/comparison.json --compare java -cp /path/to/classes NativeComparator
```

The comparator reads one JSON object per line from stdin.
Each input contains `id` and `input`. Return the same `id` with an `observed` object on stdout.
Use register hex values or raw byte hex strings to compare exact float bits.
The runner fails for mismatches, missing cases or duplicate case IDs.
Keep diagnostics on stderr.

These tests cover selected instructions and supplied fixture boundaries.
They do not replace native client comparisons, server movement tests or platform join tests.
