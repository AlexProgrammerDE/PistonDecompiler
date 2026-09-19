# PistonDecompiler

[![CI](https://github.com/AlexProgrammerDE/PistonDecompiler/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexProgrammerDE/PistonDecompiler/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/LICENSE)

Piston connects Ghidra's binary analysis to a persistent Rust pipeline and a TanStack web workbench.
Import a binary, index its functions and call graph, then run bounded AI analysis and review the proposed changes.

**Status: initial implementation.** Local Rust tests, a production frontend build, and a real Ghidra extraction passed.
Paid provider integration, large-binary performance, and the full writeback lifecycle still need validation.
See [the development handoff](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/docs/continuation.md) for the current checkpoint.

## What is implemented

- Immutable binary snapshots, SHA-256 identity, and ELF, PE, Mach-O, and COFF metadata.
- Ghidra headless export of pseudocode, assembly, P-code, strings, imports, and call edges.
- SQLite persistence, full-text function search, graph neighborhoods, and resumable jobs.
- Parallel map analysis, dependency summaries, and bounded escalation through read-only evidence tools.
- Configurable provider endpoints, prices, concurrency, context limits, and budget reservations.
- Asynchronous batch submission, remote ID recovery, and idempotent result collection.
- Proposal review and a single Ghidra writer for accepted function names and comments.
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
cp piston.example.toml piston.toml
export GHIDRA_HOME=/path/to/ghidra
bun run build
./target/release/piston serve
```

Open [the local workbench](http://127.0.0.1:7070).
Import a binary, then select **Extract with Ghidra**.

Before AI analysis, configure a model and its current token prices in `piston.toml`.
Set the key in the environment variable named by `ai.api_key_env`.
The default variable is `PISTON_AI_API_KEY`.
No paid requests start without this configuration.

For frontend development, run the backend and Vite in separate terminals:

```bash
cargo run -- serve
bun run dev
```

Vite serves port 3000 and proxies gRPC-Web to port 7070.

## CLI

```bash
piston import /path/to/program --extract
piston status
piston status BINARY_ID
piston run BINARY_ID
piston control BINARY_ID pause
piston control BINARY_ID retry
piston review FUNCTION_ID --accept
piston apply BINARY_ID
```

Use `piston --help` for the full command list.
The CLI and server share a data-directory lock. Stop the server before a CLI operation on that directory.

For a compatible asynchronous batch provider:

```bash
piston batch submit BINARY_ID
piston batch list
piston batch collect BATCH_ID
piston batch abandon BATCH_ID
```

Enable `ai.batch_enabled` and verify the provider's endpoint behavior first.
The current adapter uses `/files`, `/batches`, and a 24-hour completion window.
A batch discount is never assumed. Configure `batch_price_multiplier` for your endpoint.
`batch abandon` returns a batch that stopped during preparation to the queue.
If submission started, inspect the provider first. Then use `--confirmed-not-submitted` only when no matching provider batch exists.

## Accounting and limitations

The scheduler reserves estimated maximum request costs before dispatch.
A request without confirmed usage retains a conservative charge.
Provider prices, token usage reports, and invoices determine actual billing.

Ghidra runs as a subprocess under your account. Piston does not sandbox Ghidra or execute the imported program.
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

Rust integration tests exercise queue concurrency, reservations, recovery, idempotency, search, and bounded evidence tools with a local mock provider.
The [sample C program](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/fixtures/sample.c) supports manual Ghidra smoke tests.

See [CONTRIBUTING.md](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/CONTRIBUTING.md) for contribution guidelines and [SECURITY.md](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/SECURITY.md) for private vulnerability reports.

## License

[GNU Affero General Public License v3.0 only](https://github.com/AlexProgrammerDE/PistonDecompiler/blob/main/LICENSE), SPDX identifier `AGPL-3.0-only`.
