<!-- SPDX-License-Identifier: BSD-2-Clause -->

# MISRA C:2012 Deviation Record — xdp-iec61850

| Field             | Value                                      |
|-------------------|--------------------------------------------|
| Project           | xdp-iec61850 (IEC 61850 GOOSE/SV/MMS stack on XDP) |
| Target SIL        | SIL 2 (IEC 61508)                         |
| Standard          | MISRA C:2012 (Amendment 2)                 |
| Tool              | clang-tidy with MISRA checkers             |
| Scan date         | 2026-03-14                                 |
| Total violations  | 1,074                                      |
| Prepared by       |                                            |
| Approved by       | PENDING                                    |

## 1. Summary

This document records all MISRA C:2012 deviations for the xdp-iec61850
project. Each rule with reported violations is listed with its category,
occurrence count, disposition, and rationale.

Dispositions used:

- **Deviated** — Rule is intentionally not followed; rationale provided and
  accepted per the project deviation process.
- **Deviated (PENDING)** — Deviation requires human sign-off before the
  safety case is complete. These are substantive deviations affecting
  type safety, memory safety, or control flow predictability.
- **Disapplied** — Rule does not apply to the context in which the
  violation was reported (e.g., test-only code).

## 2. Deviation Table

| Rule ID | Category | Count | Disposition | Rationale |
|---------|----------|------:|-------------|-----------|
| 15.5 | Advisory | 299 | Deviated | The project uses early-return for error handling throughout the codebase. This pattern produces shorter, flatter functions with clear guard clauses rather than deeply nested if-else chains. Early-return is an industry-accepted idiom for C error handling and improves readability and maintainability. Widely deviated across safety-critical C projects. |
| 2.5 | Advisory | 150 | Deviated | Macros are defined for IEC 61850 protocol completeness: ASN.1 tag constants, GOOSE/SV/MMS error codes, and configuration limits. Not all are referenced in the current codebase but are required for protocol conformance and future service implementations. Removing them would break the 1:1 mapping to the IEC 61850 standard definitions. |
| 10.4 | Required | 122 | Deviated | Essential type conversions occur in protocol encoding/decoding where network byte-order integers (unsigned) interact with signed length fields, enum values, and BER tag arithmetic. Each instance has been reviewed to confirm no value is lost or misinterpreted. Explicit casts are used where narrowing occurs. |
| 12.1 | Advisory | 116 | Deviated | Operator precedence in flagged expressions follows standard C precedence rules and is unambiguous to experienced C developers (e.g., bitwise operations combined with shifts, arithmetic with comparisons). Adding redundant parentheses to 116 expressions would reduce readability without improving correctness. |
| 17.7 | Required | 94 | Deviated | Return values are intentionally discarded in best-effort cleanup paths (e.g., close(), munmap()), fire-and-forget logging calls, and diagnostic output. In these contexts, acting on a failure return is not possible or meaningful. Each instance has been reviewed to confirm it is not on a control-flow-critical path. |
| 8.7 | Advisory | 92 | Deviated | Functions and variables with external linkage are part of the public API or are accessed across translation units via the library's header contracts. Reducing linkage scope would break the modular library architecture (separate BPF, transport, protocol, and codec layers each exposing symbols to the layer above). |
| 13.3 | Advisory | 66 | Deviated | Side effects in conditions are limited to idiomatic C patterns: function calls in if/while conditions (e.g., `if ((ret = func()) < 0)`), which are standard practice in systems C code and reduce redundant temporary variables. No violations involve undefined or sequence-point-dependent behavior. |
| 17.3 | Required | 45 | Deviated | Implicit declarations arise from BPF helper function prototypes provided by the kernel (bpf_helpers.h) and libbpf headers that use compiler built-ins. These are outside project control. Userspace code has no implicit declarations; all violations are in BPF compilation units where kernel headers dictate the interface. |
| 11.5 | Required | 21 | Deviated (PENDING) | Cast from `void *` is required in two contexts: (1) BPF map lookups via `bpf_map_lookup_elem()` which returns `void *` by kernel API contract, and (2) generic container APIs (ring buffer, fixed array) that store heterogeneous protocol data. Each cast site has a corresponding size/type check or is immediately used with a known-type pointer. **Requires human sign-off.** |
| 18.4 | Advisory | 10 | Deviated (PENDING) | Union types are used for MMS type-value variants (`mms_data_t`), protocol PDU overlays where a field can hold one of several PDU types, and GOOSE `allData` multi-type values. Unions are the standard C mechanism for tagged variants; each usage is accompanied by a discriminator field that is checked before member access. **Requires human sign-off.** |
| 21.6 | Advisory | 9 | Disapplied | All `stdio.h` usage (printf, fprintf, snprintf) is confined to test harnesses (`tests/`), diagnostic/debug logging (`src/logger.c`), and error reporting paths that are compiled out in production builds via `NDEBUG`. No stdio calls exist in the BPF fast path or protocol state machine code. |
| 19.2 | Advisory | 8 | Deviated (PENDING) | Union members containing bit-fields are used in `sv_quality_t` to map the IEC 61850-7-3 Quality bit-field (13 defined bits in 4 bytes) to both a structured accessor and a raw uint32 for wire encoding. The union ensures zero-copy conversion between the bit-field view and the network byte-order wire format. **Requires human sign-off.** |
| 21.3 | Required | 6 | Deviated (PENDING) | Dynamic memory allocation (`malloc`, `calloc`, `free`) is used exclusively in system initialization paths: `packet_io_create_raw()`, `iec61850_graph_create()`, and MMS server session setup. No heap allocation occurs in the real-time data path (GOOSE/SV subscriber callbacks, BPF programs). All allocations are bounded and checked for NULL. **Requires human sign-off.** |
| 21.10 | Required | 6 | Deviated | Date/time functions are used for IEC 61850 UTC timestamp handling (EntryTime, TimeOfEntry) and certificate validity checking in the security module. These are protocol requirements — IEC 61850-8-1 mandates UTC time in GOOSE and MMS timestamps. Usage is limited to `time()`, `gmtime_r()`, and `mktime()` with known-safe inputs. |
| 21.1 | Required | 6 | Deviated | Reserved identifier violations come from BPF section macros (`__section`, `__uint`, `__type`) and kernel-style attributes (`__attribute__`) that are mandated by the BPF toolchain (libbpf, clang BPF backend). These names cannot be changed without breaking BPF program loading. All violations are in BPF compilation units. |
| 21.16 | Required | 3 | Deviated | `memcmp()` is used to compare fixed-size protocol fields (MAC addresses, APPID bytes, security key IDs) that are defined as byte arrays. Comparisons are always between objects of the same type and size. No padding bytes are involved. |
| 20.7 | Required | 3 | Deviated | Macro arguments not enclosed in parentheses occur in BPF map definition macros inherited from libbpf conventions (`__uint(type, val)`, `__type(key, t)`) where the argument is used as a type specifier and cannot be parenthesized. |
| 20.12 | Advisory | 3 | Deviated | Macro composition violations arise from BPF helper macros that build map definitions and program section attributes by composing inner macros. These follow libbpf coding conventions and cannot be restructured without breaking compatibility. |
| 20.10 | Advisory | 3 | Deviated | The `#` (stringification) operator is used in diagnostic macros for assertion messages and BPF section name generation. Usage is limited to debug/test infrastructure. |
| 10.8 | Required | 3 | Deviated | Composite expression width violations occur in BER length encoding where intermediate arithmetic on uint8_t values produces int-width results before assignment to a sized variable. Each instance has been verified to not exceed the target type's range. |
| 5.9 | Advisory | 2 | Deviated | Internal linkage name collisions are between static helper functions in separate translation units that share the same descriptive name (e.g., `parse_tag`, `encode_length`). Since they have internal linkage, there is no actual conflict. |
| 17.8 | Advisory | 2 | Deviated | Function parameter modification occurs in iterative parsers where the buffer pointer is advanced through the input. Using the parameter directly avoids an unnecessary local copy and matches the prevalent coding pattern in protocol parsers. |
| 15.7 | Required | 2 | Deviated | Missing final `else` clause in if-else-if chains where the conditions are exhaustive (e.g., protocol version checks with only two defined values). Adding an unreachable else would require dead code. |
| 21.14 | Required | 1 | Deviated | `memcmp` called with a non-const-qualified pointer to data that is effectively constant. The pointer originates from a network buffer API that does not use const in its signature. The compared memory is not modified. |
| 17.2 | Required | 1 | Deviated (PENDING) | Recursion occurs in MMS structured data encoding where nested `mms_data_t` structures (AccessResult containing structured sub-values) require recursive traversal. Recursion depth is bounded to a maximum of 3 levels by the MMS data model (verified by CBMC proof `mms_encode_recursion_bound`). Stack usage at maximum depth is under 512 bytes. **Requires human sign-off.** |
| 15.4 | Advisory | 1 | Deviated | A single loop contains two break statements: one for the normal termination condition and one for an error-detected-mid-iteration exit. Restructuring to a single break would require additional flag variables and reduce clarity. |
| 10.6 | Required | 1 | Deviated | A composite expression is assigned to a wider type in a BER length calculation where the intermediate result is known to fit in the target type. The expression has been verified by range analysis. |

## 3. Deviations Pending Sign-Off

The following deviations are substantive and require explicit human
approval before the safety case is considered complete:

| Rule | Topic | Risk | Mitigation |
|------|-------|------|------------|
| 11.5 | void* casts | Type confusion, memory corruption | Each cast site checked against known type; ASAN testing covers all paths |
| 17.2 | Recursion | Stack overflow | Bounded to depth 3; CBMC proof verifies bound; stack < 512 bytes |
| 18.4 | Union types | Uninitialized member access | Discriminator field checked before access; Frama-C EVA covers union paths |
| 19.2 | Union bit-fields | Implementation-defined layout | Single target (x86-64 Linux); layout verified by static assertion |
| 21.3 | Heap allocation | Memory leaks, fragmentation | Init-time only; no real-time path allocation; ASAN leak detection enabled |

**Sign-off:**

| Approver | Role | Date | Signature |
|----------|------|------|-----------|
| | Safety Engineer | | |
| | Project Lead | | |

## 4. Compliance Summary

| Category | Rules Assessed | Compliant | Deviated | Disapplied | Pending |
|----------|---------------|-----------|----------|------------|---------|
| Mandatory | 0 | 0 | 0 | 0 | 0 |
| Required | 16 | 0 | 12 | 0 | 4 |
| Advisory | 11 | 0 | 10 | 1 | 0 |
| **Total** | **27** | **0** | **22** | **1** | **4** |

Total violations across all deviated rules: **1,074**

## 5. References

- IEC 61508:2010, Functional safety of E/E/PE safety-related systems
- MISRA C:2012, Guidelines for the use of the C language in critical systems
- IEC 61850 series, Communication networks and systems for power utility automation
- Project FMEA: `verification/fmea.md`
- CBMC proofs: `verification/cbmc/`
- Frama-C analyses: `verification/frama-c/`
- TLA+ specifications: `verification/tlaplus/`
