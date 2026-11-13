# Fuzz corpora

Seed corpora for the fuzz targets. One directory per target; each seed is a
raw input file fed to `LLVMFuzzerTestOneInput`.

Seeding sources (per target):

- `mms_decoder/` — encoded MMS PDUs: unit-test vectors from
  `tests/unit/test_mms_ber.c`, payloads extracted from
  `tests/interop/wire/reference/mms_*.pcap` (tshark field extraction).
- `iso_stack/` — TPKT/session/presentation/ACSE records from
  `tests/unit/test_iso_stack.c` vectors and MMS reference PCAPs.
- `scl_parser/` — valid and truncated SCL documents: `tests/data/test.scd`,
  `tests/interop/scl/interop_test.icd`, plus mutations (truncations, bad
  attribute values, nested elements).

- `r_profile/` — R-GOOSE/R-SV SPDUs (WP-4a): roundtrip vectors (secure
  and plain, 8 seeds committed).
