# Contributing

Discuss substantial changes in an issue before implementation.
For security issues, follow [the security policy](SECURITY.md).

## Local checks

Install the pinned Rust toolchain and Bun 1.4.

```bash
bun install --cwd web
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
bun run --cwd web typecheck
bun run --cwd web build
```

Keep backend secrets and generated analysis data out of Git.
Add targeted tests for scheduler transitions, accounting, and provider behavior.
Tests must exercise behavior rather than assert source-code text.

## Changes

- Use Conventional Commits: `type(scope): concise imperative description`.
- Do not bypass commit hooks.
- Keep React components in PascalCase files and utility files in kebab-case.
- Use Tailwind `gap-*` utilities instead of `space-*`.
- Prefer fixes in application components before changing shadcn primitives.
- Keep loading states local to unresolved values and rows.
- Regenerate Protobuf clients after changes to the service schema.
- Document configuration changes and limitations in plain English.

Contributions are provided under the repository's AGPL-3.0-only license.
