# PistonDecompiler documentation

This documentation serves contributors who build and operate evidence-based binary recovery.

- [Architecture](architecture/recovery.md): the intended end-to-end system and its invariants.
- [Dependency scheduler](architecture/scheduling.md): callee-first scheduling and recursive convergence.
- [Recording architecture](architecture/recordings.md): session state, durability, and native Ghidra persistence.
- [Manual recording](how-to/record-a-session.md): launch or attach, mark actions, stop, import, and analyze.
- [Runtime evidence](reference/runtime-evidence.md): trace identity, observations, and coverage.
- [Ghidra recovery](architecture/ghidra-recovery.md): structures, method signatures, and refreshed decompilation.
- [Recovery workflow](how-to/recover-a-binary.md): capture observations and run bounded recovery.
- [Type plan format](reference/type-plans.md): structures, signatures, and validation limits.
- [Native Ghidra desktop](how-to/ghidra-desktop.md): open CodeBrowser and see applied changes.
- [Progress reports](reference/progress.md): extraction phases, analysis timing, and estimate limits.
- [Implementation status](implementation-status.md): verified capabilities and remaining work.

The architecture describes the target. The status document distinguishes working code from planned capabilities.
