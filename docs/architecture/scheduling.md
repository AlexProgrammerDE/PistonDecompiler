# Callee-first scheduling

A call edge points from caller to callee. Kosaraju partitions this graph into strongly connected components (SCCs).
Each recursive component becomes one node in the condensation DAG. Leaf components are ready first.

## Readiness

Priority only orders ready work. It cannot replace a dependency barrier.
A caller cannot begin reasoning while a required callee component has queued, running, batched, or uncertain work.
Verification and escalation belong to the same component lifecycle.
A pending Ghidra change or refreshed extraction also blocks downstream analysis in the full recovery loop.

Members of the same SCC do not wait for each other within an iteration.
Independent SCCs remain eligible for parallel work.
Terminal failures must remain visible and must not produce an infinite wait without an explanation.
Deferred evidence is an explicit unresolved outcome. It does not become a successful type recovery.

## Recursive convergence

Each iteration reads a fixed evidence and type revision.
Workers propose changes independently. A deterministic merge rejects conflicting layouts and preserves human decisions.
The writer applies validated changes, then exports fresh decompilation before the next iteration.

A normalized hash of accepted types and signatures determines convergence.
Cosmetic summary changes do not extend the loop.
The default limit is three iterations, with an explicit maximum of five.
A repeated hash indicates oscillation. The component stops with an unresolved conflict.

## Graph changes

Runtime indirect calls add observed edges without removing static edges.
A new edge can merge SCCs. The scheduler rebuilds components while the binary is paused and no jobs are active.
Results that depended on the old graph require reconsideration.
An observation from another binary build cannot modify this graph.
