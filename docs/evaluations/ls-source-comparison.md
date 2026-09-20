# ls mappings compared with source

The recovered code explains several operations correctly, but semantic field identities and complete object layouts remain unreliable. Readability gains are real; they are not a correctness score.

## Reference and scope

The imported binary and `/usr/bin/ls` have the same SHA-256:
`54e936d37decdad9ecaf189b1de347605a0a99037ec87bd17679b6cbde871a0c`.
The installed binary reports GNU Coreutils 9.10.

The reference is [Coreutils v9.10](https://github.com/coreutils/coreutils/tree/v9.10), including its pinned [Gnulib source](https://github.com/coreutils/gnulib/tree/1c5e0277c2143dd570d8c88f8923eed2afd8e13b). This identifies the upstream release, not every downstream patch or compiler flag used for the installed package.

The audit compares the final three-pass snapshot and all 28 names accepted by the subsequent parameter experiment. It examines selected recovered structures and function behavior; it is not a correctness audit of all 197 eligible functions.

Source was obtained after inference. These findings have not been applied to the live program or used to regenerate the assessed mappings.

## Behavior and type findings

| Mapping | Source comparison | Assessment |
| --- | --- | --- |
| `strcmp_ctime` | Descending ctime comparison, then name comparison, with an integer return. Source uses `struct fileinfo`; our timestamp fields at offsets 128 and 136 match its nested stat fields. | Behavior and accessed offsets are useful. The 144-byte recovered structure is only a partial view of the 208-byte source object. |
| `gregorian_to_persian` | Date conversion, output year/month/day, and 0/-1 results match. `unknown_ptr` is `month_names` in the shared `calendar_date` structure. Source input year is signed, and month is zero-based. | Good behavioral recovery; incomplete semantic typing and signedness. |
| `triple_hash` | Source hashes a filename and combines it with the inode. Our `str` corresponds to `name`; `seed` corresponds to `st_ino`. The third field is `st_dev`. | Hash mechanics match, but the seed interpretation is misleading and the device field is missing. |
| `has_xattr` | Source uses `bool`. Our `context->name` is an attribute-name buffer, and `context->state` is `u.err`. The probe checks ERANGE/E2BIG, not EINVAL/E2BIG as our comment says. | Readable output conceals incorrect return typing and errno interpretation. |
| Scratch-buffer growth | Growth, copying, allocation failure, and heap/inline transitions match. Source uses `bool`, `length`, and an aligned union containing 1,024 inline bytes. | Useful behavior, but our `int` return and one-byte inline field do not recover the source declaration accurately. |
| `calculate_columns` | `column_major` describes source `by_columns`. Source returns the column count, not the zero-based index of the last active column stated in our summary. | Good parameter role; summary has an off-by-one interpretation error. |
| `argmatch` | `arg`, `arglist`, and `argvalues` correspond to the input, candidate strings, and parallel values. | Useful parameter roles. Source has an additional element-size argument; the compiled specialization uses four-byte values. |
| `hash_table_transfer_entries` | Source `transfer_entries` takes destination table, source table, and `safe`. Safe mode moves overflow entries while leaving bucket heads for later. | `table` lacks direction, `entries` obscures the source-table role, and `skip_keys` is misleading. |

Sources: [ls.c](https://github.com/coreutils/coreutils/blob/v9.10/src/ls.c), [calendar conversion](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/calendar-persian.h), [calendar structures](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/calendars.h), [file hashing](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/hashcode-named-file.c), [file identity](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/hashcode-file.h), [extended attributes](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/file-has-acl.c), [ACL layout](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/acl.h), [scratch buffer](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/malloc/scratch_buffer.h), [growth implementation](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/malloc/scratch_buffer_grow_preserve.c), [argument matching](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/argmatch.c), [hash tables](https://github.com/coreutils/gnulib/blob/1c5e0277c2143dd570d8c88f8923eed2afd8e13b/lib/hash.c).

## Layout completeness

The source declarations were compiled in a small local C probe against this machine's headers. These sizes describe this ABI; they are not a reconstruction of the original build configuration.

| Structure | Our saved size | Source declaration size |
| --- | ---: | ---: |
| File information | 144 | 208 |
| Filename/inode/device triple | 16 | 24 |
| ACL information | 32 | 184 |
| Scratch buffer | 1,048 | 1,040 |

The probe also confirms ctime at offset 128 and the ACL errno union at offset 28. Correct observed offsets do not establish the full allocation size. The algorithm needs to distinguish a partial object view from a complete structure definition.

## Audit of the 28 new parameter names

This is a manual source comparison of the entire accepted naming subset, using semantic correspondence rather than exact spelling.

| Group | Names | Assessment |
| --- | ---: | --- |
| Seven comparator wrappers, `a` and `b` | 14 | Consistent with the source macros. |
| Extension comparator, `left` and `right` | 2 | Reasonable equivalents of the source operands. |
| `hash_free`, `table` | 1 | Matches the source role. |
| `calculate_columns`, `column_major` | 1 | Reasonable equivalent of `by_columns`. |
| `argmatch`, `arg`, `arglist`, `argvalues` | 3 | Consistent with source roles; `argvalues` corresponds to `vallist`. |
| Transfer helper, `table`, `entries`, `skip_keys` | 3 | Needs refinement, especially the flag and source/destination distinction. |
| Free wrappers, `__ptr`; timezone/string helpers, `__s` | 4 | Generic pointer/string labels. They improve the naming counter without recovering much purpose. |

Therefore, 21 of the 28 names are useful source-consistent roles under this assessment, four are generic, and three need refinement. This is not a whole-program accuracy percentage.

## Consequences for the algorithm

Coverage must distinguish named entities from meaningful semantic mappings. Partial structures need known extents and unknown tails instead of unjustified complete sizes. Shared object uses must be reconciled across functions: the hash function alone does not access the device field, while other users do.

Source-backed evaluation should measure field identities, widths, signedness, object completeness, flag meaning, and return behavior separately from readability. These findings can serve as held-out regression cases before any source-derived corrections are fed into the program model.
