# Changelog

## 0.2.0 (2026-11-14) — Gap-closure release: full IEC 61850 on XDP

Everything from the gap analysis implemented and gated. ~50 work
packages through the frozen-interface / worktree / merge-gate
process; every feature interop-validated against the reference
implementation (black box) or wire-validated with tshark.

### Hardening (Wave 0)
- Fuzzing for the MMS BER codec, ISO transport stack, and SCL
  parser (AFL/libFuzzer-compatible harnesses, replay suites in CI)
- ~20 library bugs fixed, including remotely-triggerable
  out-of-bounds reads in the MMS and ISO decoders, short-form BER
  length corruption in list responses, in-band read/write failures
  mishandled as timeouts/successes, and the MS-10 NVL encoder bug
  (non-interoperable since the initial commit)
- PREVAIL eBPF verification gate; MISRA C:2012 baseline discipline

### IEC 61850 reporting, client + server (Waves 1–2)
- Client: poll-driven async core (blocking API preserved as a
  wrapper), IEC 61850-7-2 report decoder, RCB enrollment with
  Ed.2 component naming ($-separated), BRCB EntryID resume
- Server: RCB/control/SGCB bridges over the data store, pre-commit
  Ed.2 validation surfacing as real MMS errors, BRCB buffering
  across client loss, CommandTermination as the conformant
  unsolicited InformationReport (deferred to post-response)
- Wire-conformant end to end: zero BER dissection errors under
  tshark; oracle interop in both directions (reports, controls,
  setting groups)

### IEC 62351 security (Phases 3–4)
- TLS for MMS associations (62351-4): three certificate-policy
  modes (compatible / strict-62351 / SPIFFE), plain+TLS dual
  listener, SIGPIPE-safe OpenSSL layer, rotation-ready certificate
  provider (static PEM + SPIFFE/SPIRE file-watch backends)
- Routable profiles (IEC TR 61850-90-5): R-GOOSE/R-SV codecs
  (clean-room wire layout), UDP transport with userspace IP/UDP
  framing, XDP IPv4/UDP dispatch with BPF SPDU-number dedup keyed
  by APPID, HMAC-SHA256 and AES-GMAC secured publication
- GOOSE/SV 62351-6 signatures retained from the earlier work

### XDP datapath (Phases 4–5)
- 90-5 traffic filtered and deduplicated at XDP; per-APPID/
  per-dport token-bucket rate limiting (defaults 32 MiB/s + 4 MiB
  burst); 802.1ad QinQ double-tag support; all BPF nodes
  PREVAIL-verified
- Rootless AF_XDP fd handoff daemon preserved and extended

### Data model (Phase 6)
- Complete CDC set (33 factories per IEC 61850-7-3)
- 54-class LN library (7-4) with declarative tables and model
  instantiation; generic all-classes verification sweep
- Model-driven publishing: one DataAttribute write fans out to MMS
  reports, GOOSE, and SV from a single model
- SCL: template-driven model construction (SDO/struct/enum chains,
  $-separator MMS naming), SCD/CID/IID/ICD acceptance, FCDA
  resolution, and fully automatic publisher configuration from
  GSEControl/SampledValueControl (whole-DO and whole-SDO datasets)

### Build and process
- Default-on feature policy: enable_mms/enable_security are meson
  auto features (on when dependencies found)
- Three build configurations verified on every gate (default /
  fully disabled / full); fuzz smoke script; wire-PCAP conformance
  suites for MMS, reporting, control, setting groups, TLS, and the
  routable profiles

### Known limitations (documented in-tree)
- The 90-5 wire layout, several CDC attribute sets, and the LN
  class tables derive from clean-room public sources pending
  conformance review against the owned IEC standards
- Root-gated test suites (XDP datapath, rate-limit floods, vm
  scripts) are code-complete with run instructions; they require a
  privileged (CAP_BPF) runner
- SGCB is a single global instance (per-LD, CnfEdit semantics
  deferred); the legacy CommandTermination encoder is deprecated

## 0.1.0
- Initial release: GOOSE/SV on XDP (codecs, pub/sub, retransmission,
  62351-6 signing), MMS server/client with reporting foundations,
  SCL import, rootless AF_XDP daemon
