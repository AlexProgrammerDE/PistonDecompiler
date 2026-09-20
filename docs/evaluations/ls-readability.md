# ls readability after three recovery passes

The tool made some functions substantially easier to read, especially those that access recovered structures. Improvement across the whole binary is uneven. Most generated local names remain, and one inferred return type made the decompiler output worse.

All three passes and native writeback finished on 20 September 2026. The [run report](ls-evidence-driven-recovery.md) records costs, selection counts, and run IDs.

## Measured changes

The original snapshot matches the earliest stored static export for all 416 functions. The comparison below covers the 197 functions eligible for analysis.

| Measure | Original static export | Final saved program |
| --- | ---: | ---: |
| Functions with comments | 0 | 147 |
| Anonymous parameter identifiers | 422 | 309 |
| Generated local identifiers | 1,151 | 1,141 |
| Undefined-type spellings | 212 | 175 |
| Functions that gained named structure member access | 0 | 8 |

Identifier counts sum distinct matching tokens within each function, excluding comments. They are readability heuristics, not formal variable counts or correctness scores.

Pseudocode changed in 109 functions after comments were removed from the comparison. This includes signature and name changes, not just changes to function bodies. There were 43 function renames, but 196 of the 197 functions already had meaningful names in the baseline.

These measurements describe cumulative improvement from the original static export. The latest three-pass experiment started with earlier saved improvements and runtime evidence. For example, scratch-buffer recovery predates this experiment.

## Clear improvement: file timestamp comparison

At `00103db0`, the original signature discarded the comparator return value:

```c
void strcmp_ctime(undefined8 *param_1,undefined8 *param_2)
```

Timestamp accesses used array offsets such as `param_1[0x10]` and `param_1[0x11]`. The name comparison cast `*param_1` and `*param_2` to character pointers.

The final exported body, with its comment omitted, is:

```c
int strcmp_ctime(file_sort_record *a,file_sort_record *b)
{
  int iVar1;

  iVar1 = ((uint)(a->ctime_nsec < b->ctime_nsec) - (uint)(b->ctime_nsec < a->ctime_nsec)) +
          ((uint)(a->ctime_sec < b->ctime_sec) - (uint)(b->ctime_sec < a->ctime_sec)) * 2;
  if (iVar1 == 0) {
    iVar1 = strcmp(a->name,b->name);
    return iVar1;
  }
  return iVar1;
}
```

The fields explain what the comparator reads. The recovered return type also exposes its result. The arithmetic still reflects the compiled implementation.

## Clear improvement: date output structure

At `0010fff0`, the signature changed from:

```c
undefined8 gregorian_to_persian(int *param_1,uint param_2,int param_3,int param_4)
```

To:

```c
int gregorian_to_persian(persian_date *out,uint year,int month,int day)
```

Selected output assignments changed from:

```c
param_1[2] = uVar4 + 1;
*(undefined ***)(param_1 + 4) = &PTR_DAT_00124800;
param_1[1] = uVar5;
```

To:

```c
out->day = uVar4 + 1;
out->unknown_ptr = &PTR_DAT_00124800;
out->month = uVar5;
```

The invalid-year result now reads `return -1;` instead of `return 0xffffffff;`. Calendar arithmetic still contains generated locals and hexadecimal constants. The unresolved pointer stays explicitly unknown.

## Mixed result: extended attributes

At `001063b0`, `has_xattr` gained an `attribute_list_context` parameter and named fields. However, its inferred return type widened from `char` to `uint`.

An original return expression was:

```c
return *piVar5 == 0x22 || *piVar5 == 7;
```

The final corresponding expression is:

```c
return (uint)CONCAT71((int7)((ulong)piVar4 >> 8),iVar2 == 0x22) |
       CONCAT31((int3)((uint)iVar2 >> 8),iVar2 == 7);
```

This is a readability regression. Native type validation accepted the signature, but acceptance does not prove that the inferred width matches the machine-code semantics. The output needs an automatic quality check for newly introduced partial-register expressions before retaining such a change.

## What remains unresolved

The three new native type operations applied no explicit local refinements after local-identity validation failed and the fallback omitted those changes. That helps explain why generated locals barely improved. Large functions still contain dense control flow, temporary names, and unexplained constants.

The recovery cycle ended at its three-pass cap with 86 functions retaining uncertain or unapplied fields. These are recorded limitations, not tasks for the user. More passes without new evidence would not necessarily fix them.

The next useful improvements are to apply local refinements against stable native identities after type changes, detect decompilation regressions from inferred types, and recover constants only when evidence supports their meaning. This evaluation does not establish semantic correctness against original source.

## Runtime evidence and persistence

Five recording sessions observed 60 of the 197 eligible functions. Runtime evidence was available to the pipeline, but improvements cannot all be attributed to recordings. The date-conversion and hash examples had no runtime observations and benefited from static inference.

This binary is C. It does not validate C++ inheritance, vtable, or virtual-dispatch recovery.

After final writeback, a separate Ghidra process reopened a copy of the saved native project in read-only mode, without analysis or definition replay. All 416 names, comments, pseudocode bodies, and parsed type contexts matched the final application snapshot. The native GUI project remains available for resuming work.

Local evaluation artifacts are under `data/ls-evaluation/`: `before.json`, `after-final.json`, `readability-metrics.json`, the per-function exports in `final-comparison/`, and `persistence-check/comparison.json`. These runtime artifacts are not committed to the repository.
