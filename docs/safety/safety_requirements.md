# Safety Requirements Specification — xdp-iec61850

**Document ID**: XDP-IEC61850-SRS-001
**Version**: 1.0
**Status**: Draft
**Target SIL**: SIL 2 (IEC 61508)

## Applicable Standards

- IEC 61508: Functional Safety of E/E/PE Systems
- IEC 61850-8-1: GOOSE Protocol Specification
- IEC 61850-9-2: Sampled Values
- IEC 61850-90-12: Communication Networks in Substations

## Keyword Definitions (RFC 2119)

- **SHALL**: Mandatory requirement
- **SHALL NOT**: Prohibition
- **SHOULD**: Recommended but not mandatory
- **MAY**: Optional

---

## SR-001: BER Encoder Buffer Safety

**Statement**: The BER encoder SHALL NOT write beyond the provided buffer boundary for any input.

**Rationale**: Buffer overflow in encoding can corrupt adjacent memory, leading to unpredictable behavior in safety-critical systems.

**Verification**: CBMC bounded model checking (ber_encoder_harness.c)

**Evidence**: `verification/cbmc/encoder.log`

**Priority**: Critical

---

## SR-002: BER Decoder Input Validation

**Statement**: The BER decoder SHALL NOT read beyond the provided buffer boundary for any input, including malformed or adversarial packets.

**Rationale**: Out-of-bounds read on untrusted network input can leak sensitive data or cause crashes.

**Verification**: CBMC bounded model checking (ber_decoder_harness.c)

**Evidence**: `verification/cbmc/decoder.log`

**Priority**: Critical

---

## SR-003: BPF Walker Bounded Iteration

**Statement**: The BPF shallow BER walker SHALL terminate within BER_MAX_ITERATIONS (15) loop iterations for any input.

**Rationale**: BPF verifier requires bounded loops. Unbounded iteration would prevent program loading.

**Verification**: CBMC (shallow_ber_harness.c), BPF verifier (compile-time)

**Evidence**: `verification/cbmc/shallow_ber.log`, BPF ELF compilation logs

**Priority**: Critical

---

## SR-004: GOOSE State Number Monotonicity

**Statement**: The GOOSE subscriber SHALL discard messages with stNum less than the latest received stNum from the same publisher.

**Rationale**: State regression can cause incorrect protection decisions.

**Verification**: TLA+ model checking (GOOSEProtocol.tla), unit tests

**Evidence**: `verification/tlaplus/goose_*.log`, `tests/unit/test_subscriber_advanced.c`

**Priority**: Critical

---

## SR-005: GOOSE Sequence Number Reset

**Statement**: When stNum increments, the publisher SHALL reset sqNum to 0.

**Rationale**: Ensures receivers can detect state transitions vs. retransmissions.

**Verification**: TLA+ model checking, property-based tests

**Evidence**: `verification/tlaplus/goose_*.log`, `tests/property/test_state_machine_properties.c`

**Priority**: High

---

## SR-006: SV Sample Counter Wraparound

**Statement**: The SV subscriber SHALL correctly detect gaps across the smpCnt wraparound boundary using modular arithmetic.

**Rationale**: Incorrect gap detection at wraparound can trigger false quality degradation alarms.

**Verification**: TLA+ model checking (SampledValuesProtocol.tla), unit tests

**Evidence**: `verification/tlaplus/sv_*.log`, `tests/unit/test_subscriber_advanced.c`

**Priority**: High

---

## SR-007: ISO Stack COTP Negotiation

**Statement**: The ISO stack SHALL perform COTP CR/CC handshake before Session layer exchange.

**Rationale**: Interoperability with standard MMS implementations requires COTP negotiation.

**Verification**: Integration tests

**Evidence**: `tests/integration/test_mms_e2e.c`

**Priority**: High

---

## SR-008: Fragmented TCP Read

**Statement**: The TCP transport SHALL handle fragmented reads by reading the exact number of bytes specified in the TPKT length field.

**Rationale**: Single recv() may return partial frames, causing protocol desynchronization.

**Verification**: Unit tests, integration tests

**Priority**: High

---

## SR-009: Security Key ID Completeness

**Statement**: The security extension SHALL include the full 20-byte SHA-1 key ID, not a truncated version.

**Rationale**: Truncated key IDs can cause key misidentification in multi-key environments.

**Verification**: Unit tests

**Evidence**: `tests/unit/test_security_sign_verify.c`

**Priority**: Medium

---

## SR-010: Control Service Ownership

**Statement**: MMS control services SHALL enforce session-scoped ownership: only the session that selected a control object MAY operate or cancel it.

**Rationale**: Prevents unauthorized control operations from different sessions.

**Verification**: Unit tests

**Priority**: High

---

## Traceability Matrix

| Requirement | Source File(s) | Test File(s) | Verification |
|-------------|---------------|--------------|--------------|
| SR-001 | src/asn1/goose_ber.c | verification/cbmc/ber_encoder_harness.c | CBMC |
| SR-002 | src/asn1/goose_ber_decode.c | verification/cbmc/ber_decoder_harness.c | CBMC |
| SR-003 | src/bpf/ber_shallow.bpf.h | verification/cbmc/shallow_ber_harness.c | CBMC |
| SR-004 | src/goose/goose_subscriber.c | tests/unit/test_subscriber_advanced.c | TLA+, Unit |
| SR-005 | src/goose/goose_publisher.c | tests/property/test_state_machine_properties.c | TLA+, Property |
| SR-006 | src/sv/sv_subscriber.c | tests/unit/test_subscriber_advanced.c | TLA+, Unit |
| SR-007 | src/transport/iso_stack.c | tests/integration/test_mms_e2e.c | Integration |
| SR-008 | src/transport/tcp_socket.c | tests/unit/test_tcp_iso_coverage.c | Unit, Integration |
| SR-009 | src/goose/goose_publisher.c, src/sv/sv_publisher.c | tests/unit/test_security_sign_verify.c | Unit |
| SR-010 | src/mms/mms_control.c | tests/unit/test_mms_control.c | Unit |
