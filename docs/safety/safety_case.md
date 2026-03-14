# Safety Case — xdp-iec61850

**Document ID**: XDP-IEC61850-SC-001
**Version**: 1.0
**Status**: Draft
**Target**: IEC 61508 SIL 2

## Goal Structuring Notation (GSN)

### Top-Level Goal

**[G1]** The xdp-iec61850 IEC 61850 protocol stack is acceptably safe
for deployment in IEC 61508 SIL 2 substation automation applications.

**[C1]** Context: The system implements GOOSE, SV, and MMS protocols
over XDP/AF_XDP, replacing a C++/DPDK implementation with a C11/BPF
split-plane architecture.

**[A1]** Assumption: The underlying Linux kernel XDP subsystem,
xdp-graph-lib, and hardware NIC drivers are assumed correct.

### Safety Argument Structure

**[G1]** System is acceptably safe
├── **[S1]** Strategy: Argue over functional correctness and freedom from systematic faults
│   ├── **[G2]** Protocol state machines are correct
│   │   ├── **[Sn1]** TLA+ GOOSE: Basic verified (89.5M states), Comprehensive verified (986K states, 0 errors), Stress verified with fairness (FairSpec)
│   │   ├── **[Sn2]** TLA+ SV: Basic verified (224.7M states), Comprehensive verified (1.0B states, 0 errors), Stress verified (1.0B states, 0 errors)
│   │   ├── **[Sn3]** Property-based tests (16,500+ iterations per property)
│   │   └── **[Sn3a]** Note: GOOSE Stress liveness properties require weak fairness (WF_vars(Next)) to prevent trivial stuttering counterexamples. Safety invariants hold without fairness.
│   │
│   ├── **[G3]** BER codec is memory-safe
│   │   ├── **[Sn4]** CBMC proof: encoder (0/1048 failures), decoder primitives (0/1797 failures)
│   │   ├── **[Sn5]** CBMC full APDU decode: state space explosion (decomposed into primitives proof above)
│   │   ├── **[Sn6]** Frama-C EVA: encoder (0 alarms, 24/24), decoder (0 alarms, 27/27, 84% stmt), GOOSE (57% stmt, 0 invalid), SV (79% stmt, 0 invalid)
│   │   ├── **[Sn7]** ASAN/UBSAN + fuzz testing covers paths not reached by formal proofs
│   │   └── **[Sn8]** ACSL contracts on all BER functions
│   │
│   ├── **[G4]** BPF fast path is bounded and safe
│   │   ├── **[Sn9]** CBMC proof: shallow BER walker terminates (shallow_ber_harness.c)
│   │   ├── **[Sn10]** BPF verifier acceptance (compile-time proof)
│   │   └── **[Sn11]** BER_MAX_ITERATIONS = 15 covers all GOOSE/SV fields
│   │
│   ├── **[G5]** ISO transport stack interoperates correctly
│   │   ├── **[Sn12]** COTP CR/CC handshake (BUG-4 fix)
│   │   ├── **[Sn13]** Fragmented TCP reads (recv_exact, BUG-5 fix)
│   │   ├── **[Sn14]** GIVE_TOKENS + DATA SPDU format (BUG-6 fix)
│   │   ├── **[Sn15]** Presentation A0 wrapper (BUG-7 fix)
│   │   └── **[Sn16]** Session User Requirements tag 0x14 (BUG-8 fix)
│   │
│   └── **[G6]** No critical hazards remain
│       ├── **[Sn17]** FMEA: 16 failure modes, 0 critical RPNs (fmea.md)
│       └── **[Sn18]** Safety requirements: 10 requirements, all with verification (safety_requirements.md)
│
├── **[S2]** Strategy: Argue over testing coverage
│   ├── **[Sn19]** 49+ unit tests (default build), 75+ (full build incl. interop)
│   ├── **[Sn20]** Property-based tests with randomized inputs
│   ├── **[Sn21]** ASAN/UBSAN clean: all 75 tests, 0 memory errors
│   └── **[Sn22]** Fuzz targets for GOOSE and SV decoders
│
└── **[S3]** Strategy: Argue over process compliance
    ├── **[Sn23]** CI pipeline: build, test, ASAN, static analysis, coverage, verification
    ├── **[Sn24]** Safety requirements traceability (requirements → code → tests → evidence)
    └── **[J1]** Justification: C11 with -Wall -Wextra -Werror -Wconversion provides
        compile-time detection of common defects

## Evidence Summary

| Evidence Type | Count | Status | Log |
|--------------|-------|--------|-----|
| TLA+ specifications | 2 (GOOSE, SV) | Complete | — |
| TLA+ model checking | 6 configs (Basic + Comprehensive + Stress × 2) | GOOSE: 89.5M + 986K + Stress (FairSpec); SV: 224.7M + 1.0B + 1.0B; all 0 errors. Note: GOOSE Stress liveness requires WF_vars(Next) fairness. | `verification/logs/tlaplus_*.log` |
| CBMC harnesses | 4 (encoder, decoder full, decoder primitives, shallow BER) | Encoder (0/1048), shallow BER (0/72), decoder primitives (0/1797) VERIFIED; decoder full: state space explosion | `verification/logs/cbmc_*.log` |
| Frama-C EVA | 4 (encoder, decoder, GOOSE, SV) | Encoder: 24/24 (100%), Decoder: 27/27 (84% stmt), GOOSE: 57% stmt (0 invalid), SV: 79% stmt (0 invalid) | `verification/logs/frama-c_*.log` |
| Unit tests | 75+ (full build incl. interop) | All passing | — |
| Property tests | 7 suites | All passing | — |
| Fuzz targets | 2 (GOOSE, SV decoder) | Complete | — |
| FMEA | 1 (16 failure modes) | Complete | — |
| Safety requirements | 10 | Documented | — |
| CI pipeline | 1 (.gitlab-ci.yml) | Complete | — |
| ASAN/UBSAN | All 75+ tests | Clean (0 memory errors) | — |
