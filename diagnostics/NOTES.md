# WP-ms10-investigation — MS-10 root cause (DIAGNOSTIC ONLY, NO FIXES)

Branch: `wp/ms10-investigation` (base `bebb018`)
Date: 2026-11-13

## 1. Failure reproduction

```
meson setup builddir-wp -Denable_mms=true -Denable_security=true
meson test -C builddir-wp --suite interop --num-processes 1
```

Result: 7 OK, 1 FAIL (`mms_interop_server`), 6 SKIP — 13/1 pass/fail inside the
binary, matching the reported signature.

```
[INTEROP] MS-10: named variable list lifecycle ... FAIL: ret == IEC61850_MMS_CLIENT_OK (-6 != 0)
```

Step-by-step repro (`diagnostics/ms10_repro.c`, no oracle involved — MS-10 is a
self-test that uses OUR client against OUR server):

```
server_start           = 0
client_connect         = 0
define_named_varlist   = 0        <-- define succeeds
read_named_varlist     = -6       <-- ERR_MMS here
```

## 2. The failing exchange

MS-10's failing call is `iec61850_mms_client_read_named_varlist()` (the test's
first three asserts are identical in shape; the stepwise repro shows define
passes and read fails).

Wire bytes our client puts on the wire for that request (BER round-trip repro,
`diagnostics/ms10_ber_roundtrip.c` — no sockets needed):

```
A0 18                       confirmedRequest
  02 01 03                  invokeID 3
  A4 13                     read [4]
    A1 11                   variableAccessSpecification [1]
      07 49 45 44 31 4C 44 30       <-- raw length-prefixed "IED1LD0"
      08 54 65 73 74 4C 69 73 74    <-- raw length-prefixed "TestList"
```

Feeding those exact bytes to our own server-side decoder
(`mms_decode_confirmed_request`):

```
decode ret = 26
decoded.service     = 14 (READ_NAMED_VARLIST)
decoded.domain      = ""          <-- empty!
decoded.list_name   = ""          <-- empty!
```

The server-side Read decoder (`src/asn1/mms_ber.c`, `MMS_SERVICE_READ` case,
variableListName branch) skips CONSTRUCTED wrappers (`A1/A3/A0/A4`) and then
requires two `0x1A` VisibleString elements (domain, list name). The client
encoder emits **raw length-prefixed strings with no `0x1A` tags and no inner
domain-specific `[1]` wrapper** — the decoder's wrapper-skip loop does not
advance, the `0x1A` checks fail, and `domain`/`list_name` stay `""`.

Server-side consequence: `MMS_SERVICE_TYPE_READ_NAMED_VARLIST` dispatch calls
`iec61850_mms_ds_get_list_attrs(store, "", "")` → fails → `map_ds_error` →
ConfirmedError PDU → client `transact()` sets `got_error` →
`IEC61850_MMS_CLIENT_ERR_MMS` (-6). Fast failure, not a timeout — matches the
-6 signature.

## 3. Which side is wrong? (clean-room oracle evidence)

The oracle (libiec61850 `server_example_basic_io`, wire observation only, via
`diagnostics/logproxy.c`) **rejects** our client's flat-format request:

- request (59 bytes): `... A4 20 A1 1E 11 'simpleIOGenericIO' 0B 'LLN0$Events'`
- oracle reply (28 bytes): `A4 06 80 01 03 85 01 01` — echoes invokeID 3, no
  Read-Response; no listOfAccessResult. A reject-style PDU. Our client does not
  match it to the pending request (core_wait eventually times out with -5
  against the oracle; the MS-10 self-test gets a fast -6 because OUR server
  answers with a ConfirmedError).

The oracle's own client (`mms_utility -a simpleIOGenericIO -v LLN0$Events`)
reads the same dataset with this request body (captured through the proxy):

```
A4 29                      read [4]
  80 01 01                 specificationWithResult [0] = TRUE
  A1 24                    variableAccessSpecification [1]
    A1 22                  variableListName → ObjectName domain-specific [1]
      A1 20                inner SEQUENCE wrapper
        1A 11 'simpleIOGenericIO'   domainId (VisibleString)
        1A 0B 'LLN0$Events'         itemId   (VisibleString)
```

**Our server decoder's variableListName branch (skip `A1/A3/A0/A4` wrappers,
then parse two `0x1A` strings) matches the real-world format.** A hand-crafted
standard-format probe with only two nested `[1]` wrappers got no reply from the
oracle — the real nesting is three levels deep, exactly what our decoder
accepts. Conclusion: the **client encoder** is the deviant side.

## 4. Hypothesis table

| # | Hypothesis | Verdict | Evidence |
|---|-----------|---------|----------|
| a | Define/GetAttrs/DeleteNamedVariableList server handling broken | REFUTED | define returns OK (stepwise repro); define/delete/getattrs decoders parse the same flat dialect our client emits (`mms_ber.c` lines 2406-2545+) |
| a' | ReadNamedVariableList request encoding gap (client flat vs server standard) | **CONFIRMED — root cause** | BER round-trip repro: decoder yields domain="" list_name=""; oracle rejects flat format; oracle's own client uses `A1 A1 A1 1A dom 1A name` which our decoder accepts |
| b | WP-1f long-form length fix changed encodings intersecting MS-10 | REFUTED | `encode_read_named_varlist_req_body` is byte-identical since the initial commit 3ce853c; WP-1f (eafb10c) touched only Read/Write *response* failure decoding (BUG-R2), not the request path; failure predates all WPs (born in 9dff7de, ancestor of 159ca3c/WP-S1) |
| c | Data-store NVL lifecycle (list not surviving, scoping) | REFUTED | define→ds works; failure occurs in the codec layer before the data store is consulted (empty names); data store correctly rejects ""/"" |

## 5. Root cause + confidence

**Root cause:** `encode_read_named_varlist_req_body()` (src/asn1/mms_ber.c,
client-side, introduced in initial commit 3ce853c) emits a proprietary flat
ObjectName encoding (`A1 L <dom_len> <domain> <name_len> <name>`), while the
server-side Read-request decoder was upgraded to the standard MMS encoding
(three nested `[1]` constructed wrappers + `0x1A` VisibleString tags) in
pre-WP commit 9dff7de ("fix: MMS interop — proper ASN.1/BER encoding for all
services") — which deleted the old flat-format `ReadNamedVariableList` branch
but did not update the client encoder. Since then, our client's
read-named-varlist request decodes with empty domain/list names on any
conformant server (ours and the oracle alike), and MS-10 fails with ERR_MMS.

The failure was therefore BORN in 9dff7de and predates WP-S1/159ca3c and every
WP — matching "fails identically on every base since at least 159a3c".
(159a3c does not exist in this repo; earliest related base is 159ca3c, WP-S1.
At 9dff7de~1 = 0b791f1 the decoder still had the flat
`ReadNamedVariableList: A1 { domLen dom listLen list }` branch, so MS-10 was
self-consistent there.)

**Confidence: HIGH.** Proven by (1) offline BER round-trip showing empty
decoded names, (2) oracle rejecting the flat bytes on the wire, (3) oracle's
own client's standard bytes matching our decoder's accepted shape, (4) git
archaeology pinpointing the divergence commit.

## 6. Recommended fix WP

Scope: make the client-side named-variable-list encoders emit standard MMS
(and keep server decoders tolerant where they already are).

Files to own:
- `src/asn1/mms_ber.c`
  - `encode_read_named_varlist_req_body()`: emit `A1 L { A1 L2 { 1A dom } { 1A name } }`
    matching the captured oracle format (`A4 L [80 01 01] A1 L A1 L2 A1 L3 1A dom 1A name`;
    specificationWithResult optional). The server decoder already parses this.
  - `encode_define_named_varlist_req_body()`,
    `encode_delete_named_varlist_req_body()`,
    `encode_get_named_varlist_attrs_req_body()`: same ObjectName standardization
    (flat `[0] L <dom_len>...` today). NOTE: their server-side decoders parse
    the flat dialect, so these are self-consistent today but non-interoperable
    with real clients — decide whether the fix WP covers them (recommended) or
    files a follow-up. If changed, the matching decoders must keep accepting
    both forms or be updated in lockstep.
- Latent bugs to cover while in there (response path, `mms_ber.c` response
  decode ~line 3957): a named-variable-list with exactly ONE member is
  classified as a plain single-variable Read (`num_values == 1` heuristic), so
  `read_named_varlist()` on a 1-member list returns ERR_MMS; an EMPTY list
  decodes as "unknown content" (MMS_ERROR_SERVICE_ERROR). Consider a request/
  response correlation flag instead of the value-count heuristic.

Tests to update/add:
- `tests/interop/mms/test_mms_interop_server.c` MS-10 (should pass unchanged
  once the encoder is fixed; add a 1-member-list variant for the latent bug).
- Add MC-scenario coverage: our client reading a dataset from the oracle
  (currently NO MC test exercises read_named_varlist against a real server —
  that is why this never surfaced). The oracle exposes
  `simpleIOGenericIO/LLN0$Events` (4 members), `LLN0$Events2`,
  `LLN0$Measurements`.

## 7. Artifacts in this directory (diagnostic only, not wired into meson)

- `NOTES.md`      — this file
- `ms10_repro.c`  — stepwise MS-10 self-test repro (sockets, no oracle)
- `ms10_ber_roundtrip.c` — offline proof: client encode → server decode → ""
- `ms10_oracle_probe.c`  — clean-room probe: flat vs standard format vs oracle
- `logproxy.c`    — TCP byte-logging proxy used for wire capture

Build examples:
```
cc -g -O0 -Iinclude/iec61850 diagnostics/ms10_ber_roundtrip.c \
   builddir-wp/libmms_ber.a -o /tmp/ms10_rt
cc -g -O0 -Iinclude/iec61850 diagnostics/ms10_repro.c \
   builddir-wp/libiec61850.a builddir-wp/libmms_ber.a -lpthread -o /tmp/ms10_repro
```
