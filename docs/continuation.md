# Continuation prompt

Copy everything below into a new Codex task on the other device. This is an intermediate checkpoint, not a completed product.

---

Continue building **PistonDecompiler**, a Rust and TanStack application for persistent, efficient AI-assisted reverse engineering with Ghidra.

Repository: https://github.com/AlexProgrammerDE/PistonDecompiler

Work on **main**. The original workstation path was `/home/alex/Projects/PistonDecompiler`, but discover the checkout path on this device. Fetch and inspect the current repository before making changes. All source and configuration needed for continuation should be in this repository. Do not assume access to the original conversation or its attachments.

The previous session was interrupted because I asked the agent to checkpoint, commit, push, and stop. Continue the original implementation and verification rather than treating the current source as finished. Preserve useful existing work, review it critically, and fix defects thoroughly. Do not replace the project with a prototype or static mockup.

## My intended product

Pass the Rust program a binary. It creates an immutable snapshot, runs Ghidra headless, indexes everything useful, builds a persistent knowledge graph and job queue, communicates with AI providers efficiently, and exposes an inspection and control API. A companion web application lets me inspect binaries, functions, pseudocode, references, proposed names, analysis evidence, queue state, and detailed operational statistics.

The Rust process owns all analysis, persistence, AI orchestration, and Ghidra integration. It exposes **gRPC-Web**, and it serves the production frontend from the same endpoint. The frontend is **Bun + Vite + React + TanStack Router**, not TanStack Start. Use TanStack Query, Store, Table, Form, Pacer, Charts, and Devtools where appropriate. Do not substitute Recharts for TanStack Charts.

The specified shadcn command was:

```bash
bunx --bun shadcn@latest init --preset b6TqMNb5Wb --template start
```

The previous agent ran this with `--name web --yes`, then removed Start and converted the generated app to a Router SPA. Preserve the resulting preset, theme, fonts, and Base UI components. The preset uses `base-mira`, olive neutrals, lime primary colors, IBM Plex Sans, Space Grotesk headings, and Phosphor icons. `web/components.json` and `web/src/styles.css` contain the actual generated settings.

On the original workstation, `../Fox/fox-web` provided the Rust/Tonic/Axum/Connect-Web reference pattern, including production static assets. `../steward` provided AI orchestration inspiration: bounded requests, provider adapters, timeouts, and controlled tool use. If these sibling repositories exist here, inspect them. Do not edit them or treat their project-specific instructions as authorization for unrelated actions.

## Architecture from the original attachments

Three attachments discussed asynchronous batches, cheap AI providers, and a persistent reverse-engineering pipeline. Their architectural direction matters more than their unverified model names and pricing:

1. Extract once with Ghidra. Persist function pseudocode, P-code, assembly, cross-references, callers, callees, strings, imports, and other relevant evidence.
2. Filter deterministic low-value work before AI: thunks, imports, tiny functions, compiler/runtime code, known libraries, and duplicate functions. Eventually consider BSim or normalized semantic fingerprints.
3. Run a cheap map pass over bounded function neighborhoods. Prefer compact structured output to lengthy prose.
4. Propagate summaries from callees toward callers. Handle recursive strongly connected components rather than assuming an acyclic graph.
5. Group related functions into modules and eventually synthesize module descriptions.
6. Escalate uncertain, complex, central, or conflicting results to a stronger model. Give escalation workers narrowly scoped, read-only evidence tools.
7. Store AI names, types, summaries, side effects, confidence, uncertainty, evidence, model, prompt version, and token accounting as proposals. Keep provenance.
8. Use a single controlled writer to apply accepted changes to Ghidra. Never allow independent workers to mutate the project concurrently.
9. Persist progress, retries, reservations, provider batch IDs, and outcomes. A restart must not silently lose work or duplicate paid requests.
10. Separate concurrent real-time requests from **true asynchronous provider batch APIs**. Parallel requests are not automatically discounted. Prices, models, limits, and batch discounts must be configured for the actual provider.

The product should eventually support substantial binaries and multi-day analysis. Focused requests, durable queues, graph context, and selective escalation are the intended optimization, not uncontrolled autonomous agents wandering through Ghidra.

Do not hard-code attachment price claims or advertise hypothetical savings as measured facts. Do not configure or invoke paid providers without an actual configured model, rates, credentials, and authorization for the relevant data.

## Current repository structure

- `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`: Rust 2024 application, pinned toolchain 1.98.1.
- `src/main.rs`: Clap CLI and exclusive data-directory lock.
- `src/config.rs`: TOML configuration, validation, provider settings.
- `src/db.rs`: SQLite persistence, binary import, full-text search, function details, overview queries.
- `src/ghidra.rs`: headless subprocess orchestration, exporter import, review writeback.
- `src/graph.rs`: SCC-based dependency ranks and bounded deterministic label propagation.
- `src/ai.rs`: OpenAI-compatible chat-completions adapter, structured result validation, bounded prompts, read-only evidence tools, token usage.
- `src/pipeline.rs`: atomic claims, budget reservations, completion, failure, retries, pause/resume, and proposal review.
- `src/batch.rs`: asynchronous file upload, batch submission, persisted manifests, remote-ID attachment, and collection.
- `src/server.rs`: Tonic gRPC-Web service, Axum static hosting, loopback restriction, workers, Ghidra semaphore.
- `proto/piston/v1/piston.proto`: shared typed API.
- `build.rs`: vendored protoc and Rust code generation.
- `migrations/0001_initial.sql`: initial SQLite schema and FTS5 index.
- `ghidra/PistonExport.java`: streaming JSONL exporter.
- `ghidra/PistonApply.java`: accepted function-name/comment writer.
- `fixtures/sample.c`: small source fixture for Ghidra smoke tests.
- `tests/pipeline.rs`: behavior-oriented integration tests.
- `web/`: Bun/Vite React app, generated Protobuf client, shadcn components, and TanStack integrations.
- `piston.example.toml`: documented configuration template. Live `piston.toml` is ignored.
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`: initial public project documentation.
- `_config.yml`, `CNAME`: Jekyll project site using `jekyll-theme-hacker`.
- `.github/`: CI, dependency updates, CODEOWNERS, bug template, and PR template.

The web API uses `@connectrpc/connect-web`'s `createGrpcWebTransport` against the current origin. Vite proxies `/piston.v1.PistonService` and `/healthz` to `127.0.0.1:7070`. The Rust server serves `web/dist` and falls back to `index.html` for SPA routes.

The workbench currently includes a binary library, import dialog, searchable/paginated function table, pseudocode/assembly/reference/JSON detail pane, proposal acceptance/rejection, pipeline controls, stage counts, job list, events, provider configuration status, and a lazily loaded TanStack token chart.

## Commands

From the repository root:

```bash
bun install --cwd web
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
bun run --cwd web typecheck
bun run --cwd web build
```

Use `bun run --cwd web COMMAND`, not `bun --cwd web run COMMAND`, which printed help with the installed Bun version.

Development:

```bash
cargo run -- serve
bun run dev
```

Production:

```bash
bun run build
./target/release/piston serve
```

Copy `piston.example.toml` to `piston.toml` and set `GHIDRA_HOME` or `ghidra_home`. The default server is `127.0.0.1:7070`. The frontend development port is 3000.

CLI operations include:

```bash
piston import /path/to/program --extract
piston extract BINARY_ID
piston import-export BINARY_ID /path/to/functions.jsonl
piston status
piston status BINARY_ID
piston run BINARY_ID
piston control BINARY_ID pause
piston control BINARY_ID resume
piston control BINARY_ID retry
piston review FUNCTION_ID --accept
piston apply BINARY_ID
piston batch submit BINARY_ID
piston batch list
piston batch collect BATCH_ID
piston batch attach BATCH_ID REMOTE_ID
```

The server and CLI cannot open the same data directory simultaneously because the current implementation takes an exclusive process lock. Use the API during server operation, or stop the server for CLI work.

## Verification already performed

The following passed before the handoff, although rerun checks after any changes:

- Rust compilation.
- Three unit tests: Unicode-safe clipping, structured-result validation, recursive graph ranking.
- Six integration tests: concurrent unique claims with bounded reservations; idempotent completion and map ordering; restart recovery and uncertain charges; conservative failure accounting/backoff; transactional import and FTS query escaping; a bounded two-round evidence agent against a local mock provider.
- TypeScript checking after adapting TanStack Table v9 APIs.
- Vite production build, including the lazily loaded TanStack Charts bundle.
- A real Ghidra 12.0.4 headless export of the compiled `fixtures/sample.c` on the original workstation.
- Browser inspection of the production frontend served by Rust, including generated gRPC-Web calls, function list, and checksum pseudocode.

The Ghidra smoke test recovered 22 functions, 14 call edges, and 10 eligible functions. The workbench displayed those real results. No paid AI provider was called.

The original smoke files were under `/tmp/piston-smoke`; those are deliberately not committed or required on another device. The original Ghidra installation was under the user's Downloads directory and is not portable. The test server was stopped for this checkpoint.

The production build reported a main JavaScript chunk around 728 kB before gzip. This is a performance improvement opportunity, not a passed optimization goal.

Final checkpoint checks passed: Rust Clippy with warnings denied, frontend Oxlint with warnings denied, and TypeScript checking. An initial Clippy warning in the integration test was fixed with `filter_map(...)`. Inspect CI after publication as well.

There is no frontend behavior test suite yet. The package's aggregate check does not claim to run one. Rust tests cover the main logic. Add meaningful frontend/API integration checks rather than redundant string assertions.

## Known gaps and risks to address first

This is a working initial implementation, with several areas that need a serious production-readiness pass:

1. **Local API security.** Loopback binding alone is insufficient. Review Host and Origin checks, DNS rebinding, cross-origin gRPC-Web behavior, authentication options, and static fallback behavior. The current `SECURITY.md` explicitly describes this gap. Do not expose the service publicly.
2. **Large-binary import.** `Db::import` currently reads the entire binary into memory. Change it to stream the snapshot and SHA-256 digest. Consider `object::read::ReadCache` for metadata parsing without mapping the full file. Preserve hash/snapshot consistency, clean failed imports, and handle concurrent duplicate imports.
3. **Budget semantics.** Current reservation math assumes input bytes conservatively bound input tokens and adds protocol overhead. It uses configured prices and provider usage. Audit all paths for under-reservation, repeated settlement, malformed usage, retries, missing responses, and crash recovery. Avoid claiming an absolute provider billing guarantee.
4. **Prompt packing.** The current packer bounds serialized messages but can truncate serialized evidence text. Improve structured context selection without corrupting the context object. Configuration now requires at least 4096 input bytes to avoid a tiny-limit loop. Add boundary tests.
5. **Batch lifecycle.** Test actual compatible provider behavior with local mock integration tests before real paid use. Persisted manifests pin model/prices/hash. Submission intent is recorded before HTTP. Ambiguous submissions require remote-ID attachment. Audit preparing/submitting crashes, partial terminal results, failed uploads, retries, malformed outputs, and per-job conservation. A recovery command for abandoned pre-submission batches is missing.
6. **CLI run behavior.** Check behavior when only batched jobs remain or propagation waits on a remote batch. It should not hang indefinitely without an actionable status.
7. **Ghidra writeback.** Export compiled and ran successfully. `PistonApply.java` and accepted-writeback orchestration have not yet received a full real Ghidra round-trip smoke test. Test failures, partial updates, idempotent reapplication, function identity, concurrent review, and cancellation.
8. **Shutdown and process lifecycle.** Ghidra subprocesses use a process group on Unix and a timeout. Audit cancellation, Java descendants, unexpected worker failure, graceful shutdown, and lock release. Platform support is not established beyond Linux.
9. **Graph quality.** Label propagation currently assigns generic module IDs. This is not Leiden or module-level AI synthesis. SCC ranking is implemented, but full dependency scheduling, cycles, failed children, and second-pass ordering need deeper validation.
10. **Analysis scope.** Escalation tools inspect indexed Ghidra evidence only. Live Ghidra RPC/MCP, BSim, type recovery/application, known-library identification, and provider failover are not implemented. Decide and implement a clear next vertical slice rather than pretending these exist.
11. **Observability.** Current metrics include functions, stages, tokens, costs, reservations, modules, edges, job attempts, and events. Extend with useful latency percentiles, throughput, error classes, provider/model/pass breakdowns, tool calls, cache effectiveness, extraction timings, and export statistics. Use actual measured data.
12. **Frontend ergonomics.** Finish responsive and keyboard testing, empty/error/loading states, long-name overflow, deep-link details, selection when switching projects, accessibility, and production chunk splitting. The initial screenshot showed a functional dense table and pseudocode pane, but mobile and all interaction paths remain unverified.
13. **Input format claims.** Verify which `object` features and Ghidra loaders are actually enabled before promising Wasm or unusual formats. Some current UI text includes Wasm, while broad support was not tested.
14. **Documentation accuracy.** Keep README, security policy, configuration example, and site consistent with verified behavior. Remove unsupported claims. Separate tutorials, reference, and architecture explanation as the project grows.
15. **Tooling and dependencies.** Review generated shadcn files and unused components/dependencies, pin any remaining `latest` entries appropriately, and decide whether to add hooks/release workflows. Keep upstream UI components as close to upstream as practical.

## Publishing requirements

I explicitly requested a **public GitHub repository under AlexProgrammerDE**, on **main**, with a useful description and topics.

The repository was created as `AlexProgrammerDE/PistonDecompiler`. Its intended description is:

> Persistent AI-assisted binary analysis with Ghidra, Rust, gRPC-Web, and a TanStack workbench.

Topics include rust, ghidra, reverse-engineering, decompiler, binary-analysis, artificial-intelligence, grpc-web, tanstack, sqlite, and agpl-3-0. Issues/discussions are enabled. Wiki/projects are disabled. Private vulnerability reporting was enabled successfully. Verify actual settings with `gh` on continuation.

The license is **AGPL-3.0-only**. The full official license text is in `LICENSE`, and Cargo/frontend package metadata declare the SPDX identifier.

The project site must use **Jekyll**, matching the basic approach in the sibling AnarchyMod and AnarchyClient repositories. Those use `jekyll-theme-hacker`, `show_downloads: false`, a root `CNAME`, a root README as site content, and exclusions for application/build files. The current `_config.yml` follows this approach. The custom hostname is **decompiler.pistonmaster.net**.

The last DNS check returned no CNAME or A record for that hostname. The required DNS configuration is normally:

```text
Type: CNAME
Name: decompiler
Target: alexprogrammerde.github.io
```

Check current DNS before making claims. GitHub Pages settings and CNAME publication alone do not create DNS records. Complete Pages setup, verify the Jekyll build, verify the custom domain, and enable HTTPS when GitHub provisions the certificate. If no authorized DNS connector exists, state the exact remaining DNS action rather than inventing access or claiming deployment success.

The Pages site documents the project. It cannot run the Rust backend or analyze uploaded binaries. The production analysis app remains part of the local/backend deployment.

## Coding and collaboration instructions

- Stay on **main**. Never create another branch unless I explicitly ask.
- Always use Conventional Commit messages: `type(scope): description`. Add a body for nontrivial motivation or behavior.
- Do not bypass hooks or Lefthook. Never use `git commit -n`. Wait for hooks to finish.
- Whenever mentioning a Git commit, link its short hash to its full GitHub commit URL.
- Use Bun for frontend dependencies and scripts.
- Keep Rust, React, TanStack, Protobuf, and shadcn usage idiomatic for the installed versions. Read current package types/docs rather than guessing APIs.
- React components use PascalCase files. Hooks and utilities use kebab-case files.
- Never use array indexes as React keys. Use real identity. For skeletons, use a `generateN` utility with stable generated IDs.
- Use `gap-*`, never Tailwind `space-*`.
- First fix shadcn issues in consumers, not `components/ui`.
- Do not leave shims, dummy components, dead code, or fake metrics.
- Prefer leaf-level loading states. Keep headings, navigation, labels, and independently loaded content mounted.
- Tests should cover actual logic, concurrency, failure recovery, and accounting. Avoid tests that only assert implementation strings.
- Use the frontend-design, uncodixfy, shadcn, and relevant React skills for UI work when available.
- Use simple-english and documentation-writer skills for docs, in pragmatic mode unless strict controlled English is requested.
- Write natural, direct prose. Do not use em dashes.
- Do not ask for repeated confirmation for authorized implementation, fixing, committing, pushing, or repository/site setup.
- Continue work until the intended scope is fulfilled or a real external blocker remains. Be explicit about partial verification.

Start by inspecting the checked-in handoff, current Git status, GitHub repository settings, Pages state, and CI. Then repair remaining correctness gaps and complete the pipeline in tested, reviewable increments.
