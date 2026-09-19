# Security policy

## Supported versions

PistonDecompiler is in initial development. Security fixes target the latest code on the default branch.
There are no supported stable releases yet.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/AlexProgrammerDE/PistonDecompiler/security/advisories/new).
Do not publish credentials, proprietary binaries, or exploit details in a public issue.

Include the affected revision, operating system, reproduction steps, and expected impact.
Use a minimal sample that you have permission to share.
There is no guaranteed response time.

## Trust boundaries

- The server is a local, single-user tool. It binds to loopback and has no authentication.
- Ghidra parses untrusted files in a subprocess under the current user's account. There is no sandbox.
- The imported program is stored and analyzed, not executed by Piston.
- Binary strings, pseudocode, names, and model responses are untrusted input.
- AI tools can read indexed evidence from the selected binary. They cannot run shell commands or mutate Ghidra.
- Names and comments reach Ghidra only through accepted proposals and the single writer.
- Provider keys stay in backend environment variables. They are not returned through the API.
- AI requests transmit selected decompiled code and related evidence to the configured provider.
- SQLite, exports, and Ghidra projects can contain sensitive source material. Protect the data directory.

The server accepts only its configured loopback address or `localhost`, with the configured port, in the request authority.
It rejects browser origins outside its local origins and the explicit `browser_origins` list.
Requests without an Origin header must have same-origin Fetch Metadata, user-navigation metadata, or no Fetch Metadata.
These checks protect against DNS rebinding and requests from unrelated websites. They do not authenticate other local processes.
Native clients can omit Origin and Fetch Metadata headers.
Do not expose it through an unauthenticated proxy or use it as a multi-user service.

For Vite development, add the exact development origin to `browser_origins`, such as `http://localhost:3000`.
The Vite proxy rewrites Host for the backend and preserves Origin for validation.
Keep this list empty for normal use through the Rust server.

## Cost boundaries

Budget checks rely on configured prices and provider usage reports.
Unknown outcomes retain conservative charges to reduce accidental repeat spending.
Provider billing can differ from local estimates.
