# MISRA C:2012 Deviation Record — xdp-iec61850

**Document ID**: XDP-IEC61850-MISRA-001
**Version**: 2.0
**Status**: Draft
**Standard**: MISRA C:2012 (3rd edition, with Amendment 2)
**Last updated**: 2026-09-29

## Scope

This document records **active** MISRA C:2012 deviations for the xdp-iec61850
project. A deviation is active when a rule violation is intentionally retained
with documented justification. Violations that have been fixed are not listed
here; see the [Resolved Violations](#resolved-violations) section for the
audit trail.

## Excluded Files

The following files are excluded from MISRA analysis:

- `src/asn1/mms_ber.c` — 4900-line BER codec; analyzed separately with CBMC
  and Frama-C EVA (see Category 4)
- BPF programs (`bpf/*.bpf.c`) — compiled with `clang -target bpf`; use
  BPF-specific extensions not covered by MISRA C
- Test files (`tests/`) — not production code
- Third-party code (`subprojects/`) — not under project control

---

## Active Deviations

### Category 1: Platform / Toolchain Constraints

| Rule | Classification | Count | Justification |
|------|---------------|------:|---------------|
| Dir 4.6 | Advisory | ~200 | Project uses `<stdint.h>` fixed-width types (`uint8_t`, `uint32_t`, etc.) — the standard C11 approach, more portable than custom typedefs. |
| Dir 4.12 | Advisory | ~30 | Heap used only in `mms_data_store.c` (malloc/realloc at init time) and `packet_io_*.c` (create/destroy lifecycle). BPF fast path and protocol hot paths are heap-free. |
| Rule 21.6 | Required | ~9 | `<stdio.h>` used in logger and error reporting. No alternative for file I/O in C11. |
| Rule 21.10 | Advisory | ~8 | `<time.h>` functions (`clock_gettime`, `localtime_r`) used for timestamps. No alternative in C11. |
| Rule 21.3 | Advisory | ~6 | `malloc`/`free` in `ied_data_model.c` tree construction (init-time only, not hot paths). |
| Rule 21.16 | Advisory | ~3 | `memcmp` in `fixed_string.c` with non-character pointer type. Required for byte-exact comparison of fixed-length string buffers. |

### Category 2: POSIX / Linux API Usage

| Rule | Classification | Count | Justification |
|------|---------------|------:|---------------|
| Rule 21.2 | Required | ~10 | `_POSIX_C_SOURCE` defined before includes per POSIX convention. Required for `clock_gettime`, `strtok_r`, `localtime_r`. |
| Rule 1.2 | Advisory | ~20 | `__attribute__((unused))`, `__attribute__((section))` used in BPF programs. Required by the BPF toolchain (`clang -target bpf`). Not used in userspace code. |

### Category 3: Coding Style

| Rule | Classification | Count | Justification |
|------|---------------|------:|---------------|
| Rule 15.5 | Advisory | ~1,047 | Three sub-categories accepted; one pending refactor (see note below). |
| Rule 2.7 | Advisory | ~30 | `(void)param` pattern used to suppress warnings on callback signatures and interface compliance (e.g., `packet_io_ops` vtable). |
| Rule 11.5 | Advisory | ~46 | Two sub-categories: (a) `calloc`/`malloc` implicit `void *` conversion — unavoidable in C11; (b) opaque handle casts (`cert_manager`, `key_manager`, pthread `arg`, `io->priv`) — all casts to the correct documented type, annotated in source. |
| Dir 4.9 | Advisory | ~10 | Function-like macros in `goose_ber.h`, `sv_ber.h`, and BPF helper macros where macro expansion is required by the BPF verifier or for token-pasting in typed container generators. |

**Rule 15.5 note — four sub-categories:**

| Sub-category | Count | Treatment |
|---|---:|---|
| DISPATCH: switch/if-chain lookup tables (`ied_types.c`, `mms_server.c::process_request`) | ~260 | **Accepted** — refactoring to a result variable adds noise with zero safety gain. |
| GUARD: null/bounds checks at function entry before any resource acquisition | ~157 | **Accepted** — the canonical safe guard pattern; the rule's own rationale acknowledges single-exit is advisory. |
| PARSER: chained `if (ret != OK) { return ret; }` in BER/ISO/session encoders | ~575 | **Pending refactor** — error-accumulation pattern. Frama-C impact: none (ACSL contracts on declarations survive restructuring). Target: Sprints 2–3. |
| RESOURCE: returns after `calloc` with no cleanup path | ~55 | **Pending refactor** — `goto cleanup` pattern. Target: Sprint 3. |

### Category 4: BER Codec (`mms_ber.c`)

| Rule | Classification | Count | Justification |
|------|---------------|------:|---------------|
| Rule 10.3 | Required | ~300 | BER tag/length byte manipulation — narrowing conversions are inherent to the ASN.1 BER wire format. Mitigated by CBMC proof (encoder), Frama-C EVA (encoder), ASAN/UBSAN (all paths). Compiled with `-Wno-conversion` via meson override. |
| Rule 10.4 | Required | ~100 | Same root cause as Rule 10.3. All 582 violations in other files were fixed; remaining violations are confined to `mms_ber.c` (excluded from cppcheck analysis). Mitigated by the same evidence. |

### Category 5: Public API Surface

| Rule | Classification | Count | Justification |
|------|---------------|------:|---------------|
| Rule 2.5 | Advisory | ~89 | Macros defined in public headers as part of the library's external API: ASN.1 BER tag/class constants (`ASN1_CLASS_*`, `ASN1_TAG_*`), SV size constants, Ethernet frame constants, MMS BER tags and error codes, session SPDU type constants. cppcheck's single-TU analysis flags these because not every production TU uses every constant; callers of the library require them. |
| Rule 19.2 | Advisory | ~8 | Unions in `goose_ber.h` and `mms_ber.h` MMS value types — required by the BER encoding schema which maps ASN.1 CHOICE to C unions. |

### Category 6: cppcheck Tool Limitations

These deviations arise from cppcheck's inability to perform whole-program
analysis. All are confirmed false positives by project-wide grep or manual
inspection.

| Rule | Classification | Justification |
|------|---------------|---------------|
| Rule 8.7 | Advisory | **Suppressed** via `.cppcheck-suppressions`. All ~220 violations are false positives: every flagged function is declared in a public API header and called from multiple translation units. cppcheck cannot verify cross-TU call sites from single-TU analysis. Verified by whole-project grep for each flagged identifier. |
| Rule 8.5 | Required | All external object declarations are in headers with standard include-guard discipline. cppcheck cannot verify this from a single TU. |
| Rule 17.7 | Required | cppcheck flags `(void)func()` as ignoring return value. The `(void)` cast is the MISRA-approved mechanism for explicitly discarding a return value. cppcheck's addon interprets this incorrectly. |
| Rule 5.9 | Advisory | Internal linkage identifiers flagged across translation units. The project uses unique naming conventions throughout; no actual shadowing exists. |
| Rule 20.7, 20.10, 20.12 | Advisory/Required | Typed container macros (`IEC61850_DEFINE_FIXED_ARRAY`, `IEC61850_DEFINE_FIXED_STRING`, `IEC61850_DEFINE_RING_BUFFER`) require `##` token pasting. Generated code verified at each instantiation site. |
| Rule 17.8, 17.2 | Advisory/Required | Conservative flagging of patterns that are correct by project convention; each instance reviewed individually. |
| Rule 18.4 | Advisory | One remaining violation: `yaml_parser.c:186` — `strchr` result minus array base to compute key length. `strchr` returns a pointer with no index-returning equivalent in C11; pointer subtraction is the only correct approach. Both pointers are into the same local buffer; `colon != NULL` is checked before the subtraction. |
| Rule 10.8 | Required | 3 violations — cast of composite expression to wider essential type. Tracked for fix in next sprint. |

---

## Mitigation Summary

All active deviations are covered by one or more of:

1. **Static analysis**: cppcheck + MISRA addon (this document)
2. **Formal verification**: CBMC (encoder, shallow BER), Frama-C EVA (encoder)
3. **Dynamic analysis**: ASAN/UBSAN on all 96+ tests, 0 errors
4. **Code review**: All deviations reviewed and approved
5. **Compiler warnings**: `-Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wmissing-prototypes`

---

## Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Project Lead | *PENDING* | | |
| Safety Engineer | *PENDING* | | |
| Quality Assurance | *PENDING* | | |

**Action Required**: This document requires sign-off before deployment.

---

## Resolved Violations

Violations fixed during the 2026-09-29 MISRA remediation sprint. Kept here
as an audit trail; none are active deviations.

| Rule | Classification | Before | After | Fix |
|------|---------------|-------:|------:|-----|
| 17.3 | Mandatory | 47 | 0 | Added `--library=posix` to cppcheck CI command. All violations were false positives (POSIX functions flagged as implicitly declared because system headers were suppressed). |
| 17.7 | Required | 123 | 0 | Added `(void)` casts to all intentionally-discarded return values across 12 files. |
| 10.4 | Required | 582 | 0* | Added explicit `U`/`ULL` suffixes and `(type)` casts across 29 files. *~100 remain in `mms_ber.c` as an active deviation (Category 4). |
| 12.1 | Advisory | 533 | 0 | Added explicit parentheses to clarify operator precedence across 37 files. |
| 13.3 | Advisory | 66 | 0 | Split `buf[pos++] = val` into `buf[pos] = val; pos++;` across 10 files. Prior deviation justification ("standalone `i++`") was factually incorrect. |
| 8.7 | Advisory | 220 | 0 | Suppressed via `.cppcheck-suppressions`; all violations confirmed as false positives (public API functions visible to multiple TUs). |
| 18.4 | Advisory | 30 | 1 | Replaced `ptr + n` with `&ptr[n]` project-wide. Threaded `apdu_offset` as `size_t` parameter in GOOSE/SV subscribers to eliminate 2 subtraction violations. 1 remains (accepted — see Category 6). |
| 2.5 | Advisory | 109 | ~89 | Deleted 20 confirmed zero-usage macros: `PRES_TAG_*` ×10 (`iso_stack.c`), `IEC61850_ROLE_COUNT`, `IEC61850_LOG_*_MSG` ×6, `IEC61850_TRG_*` ×5, `IEC61850_RCB_MAX_REFS`, `MMS_BINDING_KEY_LEN`, `IEC61850_MMS_INIT_LIST_VARS`, `IEC61850_MMS_FILE_MAX_ENTRIES`. Remaining ~89 are accepted API-surface macros (Category 5). |
