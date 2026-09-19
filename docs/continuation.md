# Continuation prompt

Continue building **PistonDecompiler**, a local Rust and TanStack workbench for evidence-based binary analysis with Ghidra.
Repository: https://github.com/AlexProgrammerDE/PistonDecompiler

Work on `main`. Inspect current code, Git status, and CI before changing anything.
Do not create branches or bypass commit hooks. Use Conventional Commits with explanatory bodies for substantial changes.
Commit and push verified work. Link any mentioned commit hash to its full GitHub commit URL.

## Product direction

Import a binary once, extract evidence with Ghidra, and build persistent knowledge through bounded AI analysis and human review.
The workbench must make it clear what was observed, what was inferred, what changed, and which conclusions need reconsideration.
Preserve human decisions. Treat model confidence as an uncalibrated estimate, not proof.
Use the complete product name PistonDecompiler, consistent with PistonQueue, PistonMOTD, and PistonChat.

## Current architecture

- Rust owns extraction, persistence, scheduling, provider requests, and Ghidra writeback.
- SQLx/SQLite stores immutable artifacts, result history, exact review revisions, dependency edges, investigations, runs, and apply operations.
- Tokio workers issue bounded concurrent requests through Rig's OpenAI-compatible completion model.
- CPU graph calculations run through `spawn_blocking`; Ghidra mutations use a single writer.
- Initial analysis is a map pass. Scoped reruns pin all inputs before dispatch and hold unrelated queued jobs.
- Escalation is explicit and uses bounded read-only tools over indexed evidence.
- Provider batches retain their separate durable submission and collection protocol.
- The frontend uses Bun, Vite, React, TanStack Router/Query/Store/Table/Form/Pacer/Charts, and shadcn Base UI.
- Durable SSE events drive live updates. Motion animates the bounded call graph and event log with reduced-motion support.
- Production assets and gRPC-Web share the Rust origin. Vite proxies RPC, health, and events during development.

Read `src/knowledge.rs`, `src/pipeline.rs`, `src/ai.rs`, `src/ghidra.rs`, `src/batch.rs`, and `src/live.rs` for the main boundaries.
The typed contract is `proto/piston/v1/piston.proto`; migrations are in `migrations/`.
Internal storage and protocol names retain `piston` for compatibility. The executable and default configuration use `pistondecompiler`.

## Verification

Run the current repository checks after changes:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bun run --cwd web check
bun run --cwd web build
```

Tests cover concurrency, reservations, recovery, batches, prompt packing, linked evidence, dependency invalidation,
review conflicts, investigation scope, old-database migration, SSE replay, and writeback recovery.
A Linux Ghidra 12.1.3 round trip extracted the evaluation O0 binary, applied a reviewed name and comment,
and verified persistence through a fresh export. A local fixture provider exercised Rig without paid requests.
This is integration evidence, not a model-quality score. Use `fixtures/evaluation/README.md` and its rubric for quality comparisons.
Temporary smoke artifacts are not required on another device.

## Remaining product work

- Measure real model quality and cost across the evaluation variants with explicitly configured providers.
- Benchmark large binaries, extraction throughput, database growth, and concurrent SSE clients.
- Extend graph navigation beyond the bounded overview and direct neighborhoods.
- Consider recursive SCC convergence with explicit stopping rules; repeated automatic propagation is not implemented.
- Add module-level synthesis, known-library/BSim matching, inferred-type review/writeback, and provider failover only as tested vertical slices.
- Escalation tools read indexed artifacts; they are not live Ghidra RPC tools.
- Add meaningful browser behavior tests. Current automated tests primarily cover Rust/API behavior.
- Verify platforms beyond Linux before claiming support.

## Local operation and publication

Copy `pistondecompiler.example.toml` to `pistondecompiler.toml`, configure Ghidra and provider prices, and build with `bun run build`.
Run `./target/release/pistondecompiler serve`. The workbench defaults to http://127.0.0.1:7070.
The server and CLI hold the same data-directory lock. Stop the server before using the CLI on its data directory.
See README for exact review and preview/apply commands, migration notes, and budget behavior.

The public site https://decompiler.pistonmaster.net uses Jekyll and documents the project; it cannot run the workbench.
Check current Pages, DNS, and HTTPS state before making deployment claims. Do not infer a need to change DNS from older handoffs.
The repository is public under AlexProgrammerDE and licensed AGPL-3.0-only.

## Implementation conventions

Preserve the olive/lime shadcn preset, IBM Plex Sans, Space Grotesk, and Phosphor icons.
Use frontend-design, uncodixfy, shadcn, and relevant React skills for UI work.
Use simple-english and documentation-writer in pragmatic mode for documentation.
Prefer leaf-level loading, stable identities, `gap-*`, consumer fixes over upstream UI edits, and real behavior tests.
Do not leave dummy components, compatibility shims, or fake metrics. Avoid em dashes in human-facing text.
Do not spawn subagents unless explicitly authorized. Continue authorized implementation without repeated approval requests.
