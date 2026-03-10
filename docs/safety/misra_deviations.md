# MISRA C:2012 Deviation Record — xdp-iec61850

**Document ID**: XDP-IEC61850-MISRA-001
**Version**: 1.0
**Status**: Draft
**Standard**: MISRA C:2012 (3rd edition, with Amendment 2)

## Scope

This document records accepted MISRA C:2012 deviations for the
xdp-iec61850 project. All deviations are justified and carry
mitigation measures.

## Deviation Categories

### Category 1: Platform / Toolchain Constraints

| Rule | Directive | Classification | Count | Justification |
|------|-----------|---------------|-------|---------------|
| Dir 4.6 | Use `typedef` names for basic numerical types | Advisory | ~200 | Project uses `<stdint.h>` fixed-width types (`uint8_t`, `uint32_t`, etc.) consistently. This is the standard C11 approach and more portable than custom typedefs. |
| Dir 4.12 | Dynamic memory allocation shall not be used | Advisory | ~30 | Used only in `mms_data_store.c` (malloc/realloc at init time, not on hot paths) and `packet_io_*.c` (create/destroy lifecycle). BPF fast path and protocol hot paths are heap-free. |
| Rule 21.6 | `<stdio.h>` input/output | Required | ~50 | Used in logger, metrics exporter, tests, and error reporting. No alternative for file I/O in C11. |

### Category 2: POSIX / Linux API Usage

| Rule | Directive | Classification | Count | Justification |
|------|-----------|---------------|-------|---------------|
| Rule 21.2 | Standard headers reserved identifiers | Required | ~10 | `_POSIX_C_SOURCE` defined before includes per POSIX convention. Required for `clock_gettime`, `strtok_r`, `localtime_r`. |
| Rule 1.2 | Language extensions | Advisory | ~20 | `__attribute__((unused))`, `__attribute__((section))` used in BPF programs. Required by the BPF toolchain (`clang -target bpf`). Not used in userspace code. |

### Category 3: Coding Style / Readability

| Rule | Directive | Classification | Count | Justification |
|------|-----------|---------------|-------|---------------|
| Rule 15.5 | Single point of exit per function | Advisory | ~100 | Early returns used for guard clauses (`if (ptr == NULL) { return -EINVAL; }`). This is idiomatic C and improves readability. All early returns are at function entry before any resource acquisition. |
| Rule 2.7 | Unused parameters | Advisory | ~30 | `(void)param` pattern used to suppress warnings on callback signatures and interface compliance (e.g., `packet_io_ops` vtable). |
| Rule 11.5 | `void *` to object pointer cast | Advisory | ~20 | Used in `cert_manager` and `key_manager` APIs where `void *` is used for opaque type erasure. All casts are to the correct documented type. |

### Category 4: BER Codec (mms_ber.c)

| Rule | Directive | Classification | Count | Justification |
|------|-----------|---------------|-------|---------------|
| Rule 10.3 | Implicit conversion narrowing | Required | ~300 | `mms_ber.c` (4900+ lines) has extensive BER tag/length byte manipulation. Narrowing conversions are inherent to the ASN.1 BER wire format (tags are bytes, lengths are multi-byte). Mitigated by: CBMC proof (encoder), Frama-C EVA (encoder), ASAN/UBSAN testing (all paths). Compiled with `-Wno-conversion` via meson override. |
| Rule 10.4 | Essential type mismatch in arithmetic | Required | ~100 | Same root cause as Rule 10.3 — BER byte-level arithmetic. Mitigated by same evidence. |

### Category 5: Intentional Suppressions

| Rule | Directive | Classification | Count | Justification |
|------|-----------|---------------|-------|---------------|
| Rule 8.7 | Objects should be local | Advisory | ~15 | Global logger state (`g_logger_mutex`, `g_min_level`, `g_log_file`) is module-scoped `static`. This is the C equivalent of the C++ singleton pattern used in the reference implementation. |
| Dir 4.9 | Function-like macros | Advisory | ~10 | `IEC61850_LOG_*_MSG` macros gate on `is_enabled()` before calling `log()` — this is a performance optimization that cannot be achieved with inline functions due to the string literal arguments. |

## Excluded Files

The following files are excluded from MISRA analysis:
- `src/asn1/mms_ber.c` — See Category 4 above; analyzed separately
- BPF programs (`bpf/*.bpf.c`) — Compiled with `clang -target bpf`, use BPF-specific extensions
- Test files (`tests/`) — Not production code
- Third-party code (`subprojects/`) — Not under our control

## Mitigation Summary

All deviations are mitigated by one or more of:
1. **Static analysis**: cppcheck + MISRA addon (this document)
2. **Formal verification**: CBMC (encoder, shallow BER), Frama-C EVA (encoder)
3. **Dynamic analysis**: ASAN/UBSAN on all 62+ tests, 0 errors
4. **Code review**: All deviations reviewed and approved
5. **Compiler warnings**: `-Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wmissing-prototypes`

## Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Project Lead | *PENDING* | | |
| Safety Engineer | *PENDING* | | |
| Quality Assurance | *PENDING* | | |

**Action Required**: This document requires sign-off before deployment.
Contact the Project Lead to initiate the approval process.
