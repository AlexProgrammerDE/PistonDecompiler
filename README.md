# PistonDecompiler

[![CI](https://github.com/AlexProgrammerDE/PistonDecompiler/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexProgrammerDE/PistonDecompiler/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/LICENSE)

PistonDecompiler connects Ghidra's binary analysis to a persistent Rust pipeline and a TanStack web workbench.
Import a binary, index its functions and call graph, then run automatic AI analysis, validation, and Ghidra recovery.

**Status: active development.** The workbench supports evidence inspection, scoped investigations, and automatic Ghidra writeback.
Rust tests and a real Ghidra 12.1.3 extraction, apply, and re-export round trip passed on Linux.
Model quality and large-binary performance remain unmeasured.

## What is implemented

- Immutable binary snapshots, SHA-256 identity, and ELF, PE, Mach-O, and COFF metadata.
- Ghidra headless export of pseudocode, assembly, P-code, strings, imports, and call edges.
- SQLite persistence, full-text function search, graph neighborhoods, and resumable jobs.
- Bounded Tokio workers and AI requests with pinned inputs, dependency summaries, and read-only evidence tools.
- Optional Jev preprocessing and candidate assessment through the OpenRouter Decisions API.
- Immutable extraction artifacts, linked evidence, result history, and human corrections with downstream invalidation.
- Saved investigations with questions, notes, findings, scope, and durable spending limits.
- Live event replay, a Three.js call graph with a keyboard-accessible 2D view, and Motion transitions.
- Tailwind animation utilities with reduced-motion support.
- Configurable provider endpoints, concurrency, context limits, and native provider cost reporting.
- Asynchronous batch submission, remote ID recovery, and idempotent result collection.
- Automatic field validation and Ghidra writeback, with conflict checks, durable operation receipts, and bounded reanalysis.
- A gRPC-Web API and a Bun/Vite frontend served from the same Rust endpoint.
- TanStack Router, Query, Store, Table, Form, Pacer, Charts, and development tools.

The frontend uses shadcn preset `b6TqMNb5Wb`. TanStack Start was removed after initialization.
The public [project site](https://decompiler.pistonmaster.net) uses Jekyll. It does not host the analysis workbench.

## Run locally

Install Rust through rustup, Bun 1.4, and Ghidra with the Java version required by your Ghidra release.
The repository pins its Rust toolchain in `rust-toolchain.toml`.

```bash
git clone https://github.com/AlexProgrammerDE/PistonDecompiler.git
cd PistonDecompiler
bun install --cwd web
cp pistondecompiler.example.toml pistondecompiler.toml
export GHIDRA_HOME=/path/to/ghidra
bun run build
./target/release/pistondecompiler serve
```

Open [the local workbench](http://127.0.0.1:7070).
Import a binary, then select **Extract with Ghidra**.

Before AI analysis, configure a model and API key in `pistondecompiler.toml`.
Copy `.env.example` to `.env` and enter your OpenRouter key as `PISTONDECOMPILER_AI_API_KEY`.
The CLI loads `.env` beside the selected configuration file before starting its workers.
Existing environment variables take precedence. Local `.env` files are ignored by Git.
For other providers, use the variable named by `ai.api_key_env`.
The default variable is `PISTONDECOMPILER_AI_API_KEY`.
No paid requests start without this configuration.

For frontend development, run the backend and Vite in separate terminals:

```bash
cargo run -- serve
bun run dev
```

Vite serves port 3000 and proxies gRPC-Web to port 7070.

## Jev preprocessing with OpenRouter

Add this table to `pistondecompiler.toml` to enable decision routing:

```toml
[ai.decisions]
endpoint = "https://openrouter.ai/api/alpha/decisions"
model = "typesafe/jev-1.13"
confidence_threshold = 0.95
max_input_bytes = 96000
```

The decision client uses the same `ai.api_key_env` as generation.
The Decisions endpoint differs from the chat-completions endpoint.
Set spending limits on your OpenRouter key. The application does not impose a local dollar limit.

Each new analysis scope starts with `preprocess`.
Jev classifies the function's role, evidence sufficiency, and complexity against pinned Ghidra evidence.

- Sufficient or uncertain evidence routes to the configured generation model.
- Strong evidence of missing context defers generation until you request another analysis.
- Complex functions route to `ai.escalation_model` when that model is configured.
- Generated proposals receive separate name, summary, and parameter-type assessments.
- An uncertain initial proposal can trigger one escalation. The escalation assessment cannot trigger another escalation.

Both confidence and the selected probability must meet the configured threshold for a decisive assessment.
Missing confidence or probabilities never count as a passed check.
The threshold is a routing policy, not a measured accuracy guarantee.
Assessments never accept proposals or apply changes to Ghidra.

Open **Assessments** in the function view to inspect these decisions.
The `inspect FUNCTION_ID` command also includes requests, responses, evidence identity, usage, and routes.
Each stage stores the provider response before validating its content. Costs come only from the response’s `usage.cost` field.

On resume, untouched initial jobs enter preprocessing. Existing pinned jobs retain their original inputs.
Tiny functions, thunks, and identical pseudocode retain separate identities and remain eligible for analysis.
External functions and functions without exported code remain excluded from the initial queue.
Provider batches cannot run with decision routing enabled.

This integration covers static preprocessing, selective generation, and candidate assessment.
The CLI now supports runtime trace ingestion, structured type proposals, Ghidra type writeback, and bounded callee-first recovery.
See the [recovery workflow](docs/how-to/recover-a-binary.md), [architecture](docs/architecture/recovery.md), and [implementation boundaries](docs/implementation-status.md).

## CLI

```bash
pistondecompiler import /path/to/program --extract
pistondecompiler status
pistondecompiler status BINARY_ID
pistondecompiler inspect FUNCTION_ID
pistondecompiler run BINARY_ID
pistondecompiler control BINARY_ID pause
pistondecompiler control BINARY_ID retry
pistondecompiler recover BINARY_ID --iterations 3
pistondecompiler recovery-status BINARY_ID
```

Use `pistondecompiler --help` for the full command list.
The CLI and server share a data-directory lock. Stop the server before a CLI operation on that directory.

For a compatible asynchronous batch provider:

```bash
pistondecompiler batch submit BINARY_ID
pistondecompiler batch list
pistondecompiler batch collect BATCH_ID
pistondecompiler batch abandon BATCH_ID
```

Enable `ai.batch_enabled` and verify the provider's endpoint behavior first.
The current adapter uses `/files`, `/batches`, and a 24-hour completion window.
Batch costs remain unknown unless the provider returns billing data.
`batch abandon` returns a batch that stopped during preparation to the queue.
If submission started, inspect the provider first. Then use `--confirmed-not-submitted` only when no matching provider batch exists.

## Investigate and recover

Select a function, then open **Investigations** to save a question and its direct call neighborhood.
Queue that scope and select **Run analysis**. The queue pins evidence and dependency revisions before requests start.
The investigation question is included in each scoped prompt. Notes and findings persist across restarts.
An active scope holds unrelated queued work. **Include all queued work** restores the full queue.

Open a result's evidence links to inspect immutable artifacts and cited lines.
A valid citation proves that the referenced lines were supplied, not that the model's interpretation is correct.
Names, summaries, and types receive independent AI assessments. Supported fields are applied automatically after the active queue drains.
Uncertain fields are deferred automatically. They do not create a manual review task or block unrelated fields.
Ghidra validates type changes in a rolled-back transaction before application.
Expected-value checks protect changes made outside the operation.

Writeback saves the native Ghidra project and refreshes pseudocode. Affected functions enter another callee-first analysis pass.
The server allows up to three total analysis passes per recovery cycle. Remaining uncertainty stays visible when the limit is reached.
Recovery phases and operation IDs persist in SQLite. Interrupted writeback retries the same operation, with three attempts before reporting failure.
A provider rejection, unavailable Ghidra installation, or exhausted retries can still stop work. These are operational failures, not review requests.
See [Automatic recovery](docs/architecture/automatic-recovery.md) for state and restart behavior.

## Upgrading an existing checkout

The executable is now `pistondecompiler`; the default configuration is `pistondecompiler.toml`.
Rename an existing configuration or pass its path through `--config`.
Remove the obsolete top-level `ai.confidence_threshold` setting and update the API-key variable if using the new default.
The existing data directory, database name, Ghidra project name, and Protobuf package remain compatible.
SQLite migrations preserve old results. Legacy extraction provenance is explicitly marked unknown.
The review and apply API requests changed; rebuild the frontend and backend together.

## Accounting and limitations

Cost tracking is retrospective. The scheduler does not reserve money or estimate request prices.
The database retains raw provider receipts, including charges for responses that fail analysis validation.
Missing cost stays unknown; an explicit zero remains zero. Displayed subtotals include only reported charges.
OpenRouter enforces its key limit. An HTTP 402 response pauses the affected binary until you resume it.

Remove `budget_usd`, all `*_usd_per_million` fields, and `batch_price_multiplier` from your configuration.
The migration removes local budget and reservation columns and discards historical estimated totals.
It preserves native decision receipts and marks older chat costs unknown because those receipts were not saved.
Older failed requests without saved receipts cannot be included in the subtotal. Check OpenRouter for the complete bill.

Ghidra runs as a subprocess under your account. PistonDecompiler does not sandbox Ghidra or execute the imported program.
The server binds to loopback and currently has no user authentication.
Use it only in a trusted local environment. Read [SECURITY.md](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/SECURITY.md) before processing sensitive binaries.

Current gaps include BSim matching, inferred-type writeback, provider failover, module-level AI summaries, and live Ghidra RPC tools.
Escalation tools read the indexed Ghidra evidence instead.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
bun run --cwd web typecheck
bun run --cwd web build
```

Rust integration tests exercise queue concurrency, native billing receipts, recovery, idempotency, search, and bounded evidence tools with a local mock provider.
The [evaluation corpus](https://github.com/AlexProgrammerDE/PistonDecompiler/tree/main/fixtures/evaluation) provides optimized and stripped variants, a behavioral rubric, and a repeatable review procedure.
The [sample C program](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/fixtures/sample.c) supports manual Ghidra smoke tests.

See [CONTRIBUTING.md](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/SECURITY.md) for private vulnerability reports.

## License

[GNU Affero General Public License v3.0 only](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/LICENSE), SPDX identifier `AGPL-3.0-only`.
