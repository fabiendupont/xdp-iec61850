/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IEC TR 61850-90-5 R-GOOSE / R-SV Codecs
 *
 * WP-4a: roundtrip (plain + secured, every header field verified
 * against the documented wire layout, including the revised
 * appid/spdu_number/key_id/time_to_next_key/security_algos fields),
 * malformed-input (truncation at every offset, overspecified
 * lengths, bad security-extension lengths, wrong profile/SI/
 * version), and replay-window coverage. Wire layout: see the
 * derivation comment in src/asn1/rgoose_ber.c.
 */

#include "asn1/r_profile.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* --- test-vector helpers --- */

/* Explicit encode parameters, deliberately distinct from every
 * implicit source (GOOSE sqNum, SV smpCnt) to prove the mappings
 * are gone and the parameters are used verbatim. */
#define T_APPID        0x1234U
#define T_SPDU_NUMBER  987654U

static uint16_t t_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t t_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void t_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void make_goose(goose_apdu_t *a)
{
    goose_apdu_init(a);
    (void)goose_set_gocbref(a, "IED1LD0/LLN0$GOOSE_PUB1");
    (void)goose_set_datset(a, "IED1LD0/LLN0$DS_DATASET1");
    (void)goose_set_goid(a, "GO_ID_1");
    a->timeAllowedtoLive = 5000U;
    a->timestamp = 1234567890ULL * 1000000ULL;
    a->stNum = 7U;
    a->sqNum = 42U; /* != T_SPDU_NUMBER */
    a->confRev = 3U;
    a->test = false;
    a->ndsCom = false;
    (void)goose_add_boolean(a, true);
    (void)goose_add_int32(a, -1234);
    a->numDatSetEntries = 2U;
}

static void make_sv(sv_apdu_t *a)
{
    sv_apdu_init(a);
    a->noASDU = 1U;
    (void)sv_set_svid(&a->asdu[0], "IED1MU01_A"); /* < 128 bytes APDU */
    (void)sv_set_datset(&a->asdu[0], "IED1LD0/LLN0$DS_MU01");
    a->asdu[0].smpCnt = 1723U; /* != T_SPDU_NUMBER */
    a->asdu[0].confRev = 5U;
    a->asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;
    {
        sv_quality_t q;
        (void)memset(&q, 0, sizeof(q));
        (void)sv_add_sample(&a->asdu[0], 32510, q);
        (void)sv_add_sample(&a->asdu[0], -812, q);
    }
}

static void make_sec(iec61850_r_security_t *s, size_t siglen)
{
    size_t i;

    (void)memset(s, 0, sizeof(*s));
    s->present = true;
    s->key_id = 0xDEADBEEFU;           /* full 32-bit wire field */
    s->time_of_current_key = 1731400000U; /* epoch seconds */
    s->time_to_next_key = 720U;        /* minutes */
    s->security_algos = 0x0102U;       /* encryption | HMAC bits */
    s->signature_len = siglen;
    for (i = 0U; i < siglen; i++) {
        s->signature[i] = (uint8_t)(0xA0U + (i & 0x3FU));
    }
}

static void check_goose_apdu(const goose_apdu_t *in, const goose_apdu_t *out)
{
    ASSERT_TRUE(strcmp(out->gocbRef, in->gocbRef) == 0);
    ASSERT_TRUE(strcmp(out->datSet, in->datSet) == 0);
    ASSERT_TRUE(strcmp(out->goID, in->goID) == 0);
    ASSERT_TRUE(out->has_goID == in->has_goID);
    ASSERT_EQ(out->timeAllowedtoLive, in->timeAllowedtoLive);
    ASSERT_TRUE(out->timestamp == in->timestamp);
    ASSERT_EQ(out->stNum, in->stNum);
    ASSERT_EQ(out->sqNum, in->sqNum);
    ASSERT_EQ(out->confRev, in->confRev);
    ASSERT_TRUE(out->test == in->test);
    ASSERT_TRUE(out->ndsCom == in->ndsCom);
    ASSERT_EQ(out->numDatSetEntries, in->numDatSetEntries);
    ASSERT_EQ(out->allData[0].type, GOOSE_DATA_BOOLEAN);
    ASSERT_TRUE(out->allData[0].value.boolean == in->allData[0].value.boolean);
    ASSERT_EQ(out->allData[1].type, GOOSE_DATA_INT32);
    ASSERT_EQ(out->allData[1].value.int32, in->allData[1].value.int32);
}

static void check_sv_apdu(const sv_apdu_t *in, const sv_apdu_t *out)
{
    ASSERT_EQ(out->noASDU, in->noASDU);
    ASSERT_TRUE(strcmp(out->asdu[0].svID, in->asdu[0].svID) == 0);
    ASSERT_TRUE(out->asdu[0].has_datSet == in->asdu[0].has_datSet);
    ASSERT_TRUE(strcmp(out->asdu[0].datSet, in->asdu[0].datSet) == 0);
    ASSERT_EQ(out->asdu[0].smpCnt, in->asdu[0].smpCnt);
    ASSERT_EQ(out->asdu[0].confRev, in->asdu[0].confRev);
    ASSERT_EQ(out->asdu[0].num_samples, in->asdu[0].num_samples);
    ASSERT_EQ(out->asdu[0].samples[0].value, in->asdu[0].samples[0].value);
    ASSERT_EQ(out->asdu[0].samples[1].value, in->asdu[0].samples[1].value);
}

static void check_plain_header(const iec61850_r_header_t *hdr, int total)
{
    ASSERT_EQ(hdr->spdu_length, (size_t)total);
    ASSERT_EQ(hdr->spdu_number, T_SPDU_NUMBER);
    ASSERT_EQ(hdr->appid, T_APPID);
    ASSERT_TRUE(!hdr->security.present);
    ASSERT_EQ(hdr->security.key_id, 0U);
    ASSERT_EQ(hdr->security.time_of_current_key, 0U);
    ASSERT_EQ(hdr->security.time_to_next_key, 0U);
    ASSERT_EQ(hdr->security.security_algos, 0U);
    ASSERT_EQ(hdr->security.signature_len, 0U);
}

static void check_sec_header(const iec61850_r_header_t *hdr,
                             const iec61850_r_security_t *sec, int total)
{
    ASSERT_EQ(hdr->spdu_length, (size_t)total);
    ASSERT_EQ(hdr->spdu_number, T_SPDU_NUMBER);
    ASSERT_EQ(hdr->appid, T_APPID);
    ASSERT_TRUE(hdr->security.present);
    ASSERT_EQ(hdr->security.key_id, sec->key_id);
    ASSERT_EQ(hdr->security.time_of_current_key, sec->time_of_current_key);
    ASSERT_EQ(hdr->security.time_to_next_key, sec->time_to_next_key);
    ASSERT_EQ(hdr->security.security_algos, sec->security_algos);
    ASSERT_EQ(hdr->security.signature_len, sec->signature_len);
}

/* ======================================================================
 * Roundtrips
 * ====================================================================== */

static void test_rgoose_roundtrip_plain(void)
{
    goose_apdu_t in, out;
    iec61850_r_header_t hdr;
    uint8_t buf[1024];
    int total;

    TEST("rgoose_roundtrip_plain");

    make_goose(&in);
    total = iec61850_rgoose_encode(&in, T_APPID, T_SPDU_NUMBER, NULL,
                                   buf, sizeof(buf));
    ASSERT_TRUE(total > 0);

    /* Wire layout (plain): SI/LI/PI/LI, SPDU Length, version */
    ASSERT_EQ(buf[0], 0xA1);              /* SI: non-tunneled GOOSE */
    ASSERT_EQ(buf[1], 12);                /* LI: plain parameter area */
    ASSERT_EQ(buf[2], 0x80);              /* PI: common session header */
    ASSERT_EQ(buf[3], 10);                /* LI: plain common header */
    ASSERT_EQ(t_be32(&buf[4]), (uint32_t)(total - 8)); /* SPDU Length */
    ASSERT_EQ(t_be16(&buf[12]), 1U);      /* Version = 1 */
    ASSERT_EQ(buf[18], 0x81);             /* Payload Type: GOOSE */
    ASSERT_EQ(buf[19], 0);                /* Simulation: false */
    ASSERT_EQ(t_be16(&buf[20]), T_APPID); /* APPID (explicit) */
    ASSERT_EQ(t_be16(&buf[22]),
              (uint16_t)(total - 24 + 2)); /* APDU Length = PDU + 2 */
    ASSERT_EQ(t_be32(&buf[14]),
              (uint32_t)(total - 24 + 10)); /* Payload Length */

    /* Explicit spdu_number is used verbatim (sqNum mapping gone) */
    ASSERT_EQ(t_be32(&buf[8]), T_SPDU_NUMBER);
    ASSERT_TRUE(T_SPDU_NUMBER != in.sqNum);

    /* Decode with metadata */
    (void)memset(&hdr, 0xAA, sizeof(hdr));
    ASSERT_EQ(iec61850_rgoose_decode(buf, (size_t)total, &out, &hdr), total);
    check_plain_header(&hdr, total);
    check_goose_apdu(&in, &out);
    /* Inner APDU untouched by the session layer */
    ASSERT_EQ(out.sqNum, in.sqNum);

    /* hdr == NULL still decodes; trailing padding is not consumed */
    ASSERT_EQ(iec61850_rgoose_decode(buf, (size_t)total, &out, NULL), total);
    ASSERT_EQ(iec61850_rgoose_decode(buf, (size_t)total + 8U, &out, NULL),
              total);
    PASS();
}

static void test_rgoose_roundtrip_secured(void)
{
    goose_apdu_t in, out;
    iec61850_r_security_t sec;
    iec61850_r_header_t hdr;
    uint8_t buf[1024];
    int total;

    TEST("rgoose_roundtrip_secured");

    make_goose(&in);
    make_sec(&sec, 32U);
    total = iec61850_rgoose_encode(&in, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    ASSERT_TRUE(total > 0);

    /* Wire layout (secured) */
    ASSERT_EQ(buf[0], 0xA1);
    ASSERT_EQ(buf[1], 24);                /* LI: secured parameter area */
    ASSERT_EQ(buf[2], 0x80);
    ASSERT_EQ(buf[3], 22);                /* LI: secured common header */
    ASSERT_EQ(t_be32(&buf[4]), (uint32_t)(total - 8));
    ASSERT_EQ(t_be32(&buf[8]), T_SPDU_NUMBER); /* SPDU Number (explicit) */
    ASSERT_EQ(t_be16(&buf[12]), 1U);
    ASSERT_EQ(t_be32(&buf[14]), sec.time_of_current_key);
    ASSERT_EQ(t_be16(&buf[18]), sec.time_to_next_key);
    ASSERT_EQ(t_be16(&buf[20]), sec.security_algos);
    ASSERT_EQ(t_be32(&buf[22]), sec.key_id); /* full 32-bit Key ID */
    ASSERT_EQ(buf[26 + 4], 0x81);         /* Payload Type at H=26 */
    ASSERT_EQ(t_be16(&buf[26 + 6]), T_APPID);
    ASSERT_EQ(t_be32(&buf[26]),
              (uint32_t)(total - 38 - 32 + 10)); /* Payload Length */
    ASSERT_EQ(buf[total - 34], 0x85);     /* Signature tag */
    ASSERT_EQ(buf[total - 33], 32);       /* Signature length */
    ASSERT_TRUE(memcmp(&buf[total - 32], sec.signature, 32) == 0);

    (void)memset(&hdr, 0, sizeof(hdr));
    ASSERT_EQ(iec61850_rgoose_decode(buf, (size_t)total, &out, &hdr), total);
    check_sec_header(&hdr, &sec, total);
    ASSERT_TRUE(memcmp(hdr.security.signature, sec.signature, 32) == 0);
    check_goose_apdu(&in, &out);
    ASSERT_EQ(out.sqNum, in.sqNum);

    /* MACNone: security block present, zero-length signature */
    make_sec(&sec, 0U);
    total = iec61850_rgoose_encode(&in, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    ASSERT_EQ(buf[total - 2], 0x85);
    ASSERT_EQ(buf[total - 1], 0);
    (void)memset(&hdr, 0, sizeof(hdr));
    ASSERT_EQ(iec61850_rgoose_decode(buf, (size_t)total, &out, &hdr), total);
    ASSERT_TRUE(hdr.security.present);
    ASSERT_EQ(hdr.security.key_id, sec.key_id);
    ASSERT_EQ(hdr.security.time_to_next_key, sec.time_to_next_key);
    ASSERT_EQ(hdr.security.security_algos, sec.security_algos);
    ASSERT_EQ(hdr.security.signature_len, 0U);
    check_goose_apdu(&in, &out);
    PASS();
}

static void test_rsv_roundtrip_plain(void)
{
    sv_apdu_t in, out;
    iec61850_r_header_t hdr;
    uint8_t buf[1024];
    int total;

    TEST("rsv_roundtrip_plain");

    make_sv(&in);
    total = iec61850_rsv_encode(&in, T_APPID, T_SPDU_NUMBER, NULL,
                                buf, sizeof(buf));
    ASSERT_TRUE(total > 0);

    ASSERT_EQ(buf[0], 0xA2);              /* SI: non-tunneled SV */
    ASSERT_EQ(buf[1], 12);
    ASSERT_EQ(buf[2], 0x80);
    ASSERT_EQ(buf[3], 10);
    ASSERT_EQ(t_be32(&buf[4]), (uint32_t)(total - 8));
    ASSERT_EQ(t_be32(&buf[8]), T_SPDU_NUMBER); /* explicit (not smpCnt) */
    ASSERT_TRUE(T_SPDU_NUMBER != in.asdu[0].smpCnt);
    ASSERT_EQ(t_be16(&buf[12]), 1U);
    ASSERT_EQ(buf[18], 0x82);             /* Payload Type: SV */
    ASSERT_EQ(t_be16(&buf[20]), T_APPID);
    ASSERT_EQ(t_be32(&buf[14]), (uint32_t)(total - 24 + 10));
    ASSERT_EQ(t_be16(&buf[22]), (uint16_t)(total - 24 + 2));

    (void)memset(&hdr, 0xAA, sizeof(hdr));
    ASSERT_EQ(iec61850_rsv_decode(buf, (size_t)total, &out, &hdr), total);
    check_plain_header(&hdr, total);
    check_sv_apdu(&in, &out);
    ASSERT_EQ(out.asdu[0].smpCnt, in.asdu[0].smpCnt);

    ASSERT_EQ(iec61850_rsv_decode(buf, (size_t)total, &out, NULL), total);
    ASSERT_EQ(iec61850_rsv_decode(buf, (size_t)total + 8U, &out, NULL),
              total);
    PASS();
}

static void test_rsv_roundtrip_secured(void)
{
    sv_apdu_t in, out;
    iec61850_r_security_t sec;
    iec61850_r_header_t hdr;
    uint8_t buf[1024];
    int total;

    TEST("rsv_roundtrip_secured");

    make_sv(&in);
    make_sec(&sec, 16U);
    total = iec61850_rsv_encode(&in, T_APPID, T_SPDU_NUMBER, &sec,
                                buf, sizeof(buf));
    ASSERT_TRUE(total > 0);

    ASSERT_EQ(buf[0], 0xA2);
    ASSERT_EQ(buf[1], 24);
    ASSERT_EQ(buf[3], 22);
    ASSERT_EQ(t_be32(&buf[14]), sec.time_of_current_key);
    ASSERT_EQ(t_be16(&buf[18]), sec.time_to_next_key);
    ASSERT_EQ(t_be16(&buf[20]), sec.security_algos);
    ASSERT_EQ(t_be32(&buf[22]), sec.key_id);
    ASSERT_EQ(buf[26 + 4], 0x82);
    ASSERT_EQ(t_be16(&buf[26 + 6]), T_APPID);
    ASSERT_EQ(buf[total - 18], 0x85);
    ASSERT_EQ(buf[total - 17], 16);
    ASSERT_TRUE(memcmp(&buf[total - 16], sec.signature, 16) == 0);

    (void)memset(&hdr, 0, sizeof(hdr));
    ASSERT_EQ(iec61850_rsv_decode(buf, (size_t)total, &out, &hdr), total);
    check_sec_header(&hdr, &sec, total);
    ASSERT_TRUE(memcmp(hdr.security.signature, sec.signature, 16) == 0);
    check_sv_apdu(&in, &out);
    PASS();
}

/* ======================================================================
 * Malformed input: truncation at every offset
 * ====================================================================== */

static void test_rgoose_truncations(void)
{
    goose_apdu_t in, out;
    iec61850_r_security_t sec;
    uint8_t buf[1024];
    int total;
    int i;
    int bad = 0;

    TEST("rgoose_truncations_every_offset");

    make_goose(&in);
    total = iec61850_rgoose_encode(&in, T_APPID, T_SPDU_NUMBER, NULL,
                                   buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    for (i = 0; i < total; i++) {
        if (iec61850_rgoose_decode(buf, (size_t)i, &out, NULL) >= 0) {
            bad++;
        }
    }

    make_sec(&sec, 32U);
    total = iec61850_rgoose_encode(&in, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    for (i = 0; i < total; i++) {
        if (iec61850_rgoose_decode(buf, (size_t)i, &out, NULL) >= 0) {
            bad++;
        }
    }
    ASSERT_EQ(bad, 0);
    PASS();
}

static void test_rsv_truncations(void)
{
    sv_apdu_t in, out;
    iec61850_r_security_t sec;
    uint8_t buf[1024];
    int total;
    int i;
    int bad = 0;

    TEST("rsv_truncations_every_offset");

    make_sv(&in);
    total = iec61850_rsv_encode(&in, T_APPID, T_SPDU_NUMBER, NULL,
                                buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    for (i = 0; i < total; i++) {
        if (iec61850_rsv_decode(buf, (size_t)i, &out, NULL) >= 0) {
            bad++;
        }
    }

    make_sec(&sec, 16U);
    total = iec61850_rsv_encode(&in, T_APPID, T_SPDU_NUMBER, &sec,
                                buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    for (i = 0; i < total; i++) {
        if (iec61850_rsv_decode(buf, (size_t)i, &out, NULL) >= 0) {
            bad++;
        }
    }
    ASSERT_EQ(bad, 0);
    PASS();
}

/* ======================================================================
 * Malformed input: overspecified / inconsistent lengths
 * ====================================================================== */

static void test_overspecified_lengths(void)
{
    goose_apdu_t gin, gout;
    sv_apdu_t sin, sout;
    iec61850_r_security_t sec;
    iec61850_r_header_t hdr;
    uint8_t buf[1024];
    int total;
    size_t h; /* session-header length: 14 plain / 26 secured */

    TEST("overspecified_lengths");

    make_goose(&gin);
    make_sec(&sec, 32U);

    /* SPDU Length + 1 (secured) */
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    buf[7]++; /* last octet of the 4-byte SPDU Length */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout, &hdr) < 0);

    /* SPDU Length - 1 (secured): payload no longer fits */
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    buf[7]--;
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout, &hdr) < 0);

    /* Payload Length + 1 (secured, H = 26) */
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    buf[29]++;
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout, &hdr) < 0);

    /* APDU Length + 1: breaks Payload-Length consistency (plain) */
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, NULL,
                                   buf, sizeof(buf));
    buf[23]++; /* last octet of the 2-byte APDU Length at H+8 = 22 */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout, &hdr) < 0);

    /* Inner BER length + 1: APDU Length over-specifies the PDU */
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, NULL,
                                   buf, sizeof(buf));
    buf[24 + 3]++; /* GOOSE APDU reserves 0x82 + 2 length octets */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout, &hdr) < 0);

    /* Signature length + 1 */
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    buf[total - 33]++; /* signature length octet */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout, &hdr) < 0);

    /* SV: inner BER length + 1 (short-form length octet) */
    make_sv(&sin);
    total = iec61850_rsv_encode(&sin, T_APPID, T_SPDU_NUMBER, NULL,
                                buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    h = 14U;
    ASSERT_TRUE(buf[h + 10U + 1U] < 0x80U); /* short form in this vector */
    buf[h + 10U + 1U]++;
    ASSERT_TRUE(iec61850_rsv_decode(buf, (size_t)total, &sout, &hdr) < 0);

    /* SV: SPDU Length + 1 (plain) */
    total = iec61850_rsv_encode(&sin, T_APPID, T_SPDU_NUMBER, NULL,
                                buf, sizeof(buf));
    buf[7]++;
    ASSERT_TRUE(iec61850_rsv_decode(buf, (size_t)total, &sout, &hdr) < 0);
    PASS();
}

static void test_bad_security_extension_lengths(void)
{
    goose_apdu_t gin, gout;
    iec61850_r_security_t sec;
    iec61850_r_header_t hdr;
    uint8_t buf[1024];
    uint8_t plain[1024];
    int total;
    int plain_total;

    TEST("bad_security_extension_lengths");

    make_goose(&gin);
    make_sec(&sec, 32U);
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    plain_total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, NULL,
                                         plain, sizeof(plain));
    ASSERT_TRUE(plain_total > 0);

    /* Outer LI not 12/24 */
    (void)memcpy(buf, plain, (size_t)plain_total);
    buf[1] = 13;
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)plain_total, &gout,
                                      &hdr) < 0);
    (void)memcpy(buf, plain, (size_t)plain_total);
    buf[1] = 0;
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)plain_total, &gout,
                                      &hdr) < 0);

    /* Inner LI inconsistent with outer LI */
    (void)memcpy(buf, plain, (size_t)plain_total);
    buf[1] = 24; /* claims secured */
    buf[3] = 10; /* but plain common header */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)plain_total, &gout,
                                      &hdr) < 0);
    (void)memcpy(buf, plain, (size_t)plain_total);
    buf[3] = 22; /* claims secured PV without the LI to match */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)plain_total, &gout,
                                      &hdr) < 0);

    /* PI not 0x80 */
    (void)memcpy(buf, plain, (size_t)plain_total);
    buf[2] = 0x81;
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)plain_total, &gout,
                                      &hdr) < 0);

    /* Plain SPDU with an injected signature (no key metadata) */
    (void)memcpy(buf, plain, (size_t)plain_total);
    buf[plain_total] = 0x85;
    buf[plain_total + 1] = 1;
    buf[plain_total + 2] = 0xAA;
    { /* extend SPDU Length by the 3 injected bytes */
        uint32_t sl = t_be32(&buf[4]);
        t_put32(&buf[4], sl + 3U);
    }
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)(plain_total + 3),
                                      &gout, &hdr) < 0);

    /* Bad signature tag on a secured SPDU */
    make_sec(&sec, 32U);
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    buf[total - 34] = 0x86;
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout, &hdr) < 0);

    /* Secured SPDU with signature TLV short by one byte */
    make_sec(&sec, 32U);
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                   buf, sizeof(buf));
    { /* shrink SPDU Length by 1: remainder != 2 + sig_len */
        uint32_t sl = t_be32(&buf[4]);
        t_put32(&buf[4], sl - 1U);
    }
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout, &hdr) < 0);
    PASS();
}

/* ======================================================================
 * Wrong profile / SI / payload type / version / args
 * ====================================================================== */

static void test_wrong_profile_and_header(void)
{
    goose_apdu_t gin, gout;
    sv_apdu_t sin, sout;
    iec61850_r_header_t hdr;
    uint8_t buf[1024];
    int total;

    TEST("wrong_profile_and_header");

    make_goose(&gin);
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, NULL,
                                   buf, sizeof(buf));
    ASSERT_TRUE(total > 0);

    /* R-SV decoder must reject an R-GOOSE SPDU and vice versa */
    make_sv(&sin);
    ASSERT_TRUE(iec61850_rsv_decode(buf, (size_t)total, &sout, &hdr) < 0);
    ASSERT_TRUE(iec61850_rsv_encode(&sin, T_APPID, T_SPDU_NUMBER, NULL,
                                    buf, sizeof(buf)) > 0);
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout,
                                       &hdr) < 0);

    /* Bad SI values */
    buf[0] = 0xA0; /* tunneled (out of scope for this codec) */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout,
                                       &hdr) < 0);
    buf[0] = 0xA3; /* management */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout,
                                       &hdr) < 0);
    buf[0] = 0xA1;

    /* Wrong payload type */
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, NULL,
                                   buf, sizeof(buf));
    buf[18] = 0x82; /* SV payload type inside an R-GOOSE SPDU */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout,
                                       &hdr) < 0);

    /* Bad version */
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, NULL,
                                   buf, sizeof(buf));
    buf[13] = 0; /* version 0 */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout,
                                       &hdr) < 0);
    buf[13] = 2; /* version 2 */
    ASSERT_TRUE(iec61850_rgoose_decode(buf, (size_t)total, &gout,
                                       &hdr) < 0);

    /* NULL / zero-length arguments */
    total = iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, NULL,
                                   buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    ASSERT_EQ(iec61850_rgoose_decode(NULL, 16U, &gout, &hdr), -EINVAL);
    ASSERT_EQ(iec61850_rgoose_decode(buf, 0U, &gout, &hdr), -EBADMSG);
    ASSERT_EQ(iec61850_rgoose_decode(buf, 16U, NULL, &hdr), -EINVAL);
    total = iec61850_rsv_encode(&sin, T_APPID, T_SPDU_NUMBER, NULL,
                                buf, sizeof(buf));
    ASSERT_TRUE(total > 0);
    ASSERT_EQ(iec61850_rsv_decode(NULL, 16U, &sout, &hdr), -EINVAL);
    ASSERT_EQ(iec61850_rsv_decode(buf, 0U, &sout, &hdr), -EBADMSG);
    ASSERT_EQ(iec61850_rsv_decode(buf, 16U, NULL, &hdr), -EINVAL);
    PASS();
}

static void test_encode_errors(void)
{
    goose_apdu_t gin;
    sv_apdu_t sin;
    iec61850_r_security_t sec;
    uint8_t buf[1024];

    TEST("encode_errors");

    make_goose(&gin);
    make_sv(&sin);
    make_sec(&sec, 32U);

    /* NULL arguments */
    ASSERT_EQ(iec61850_rgoose_encode(NULL, T_APPID, T_SPDU_NUMBER, NULL,
                                     buf, sizeof(buf)), -EINVAL);
    ASSERT_EQ(iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, NULL,
                                     NULL, sizeof(buf)), -EINVAL);
    ASSERT_EQ(iec61850_rsv_encode(NULL, T_APPID, T_SPDU_NUMBER, NULL,
                                  buf, sizeof(buf)), -EINVAL);
    ASSERT_EQ(iec61850_rsv_encode(&sin, T_APPID, T_SPDU_NUMBER, NULL,
                                  NULL, sizeof(buf)), -EINVAL);

    /* Buffer too small for the session header */
    ASSERT_EQ(iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, NULL,
                                     buf, 10U), -ENOSPC);
    ASSERT_EQ(iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                     buf, 20U), -ENOSPC);
    ASSERT_EQ(iec61850_rsv_encode(&sin, T_APPID, T_SPDU_NUMBER, NULL,
                                  buf, 10U), -ENOSPC);

    /* Buffer too small for header + APDU + signature */
    ASSERT_EQ(iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                     buf, 90U), -ENOSPC);

    /* Signature exceeding the 1-byte wire length field */
    make_sec(&sec, 256U);
    ASSERT_EQ(iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                     buf, sizeof(buf)), -EOVERFLOW);
    ASSERT_EQ(iec61850_rsv_encode(&sin, T_APPID, T_SPDU_NUMBER, &sec,
                                  buf, sizeof(buf)), -EOVERFLOW);

    /* sec != NULL but !present is treated as plain */
    make_sec(&sec, 32U);
    sec.present = false;
    ASSERT_TRUE(iec61850_rgoose_encode(&gin, T_APPID, T_SPDU_NUMBER, &sec,
                                       buf, sizeof(buf)) > 0);
    ASSERT_EQ(buf[1], 12); /* plain parameter area */
    PASS();
}

/* ======================================================================
 * 90-5 replay window
 * ====================================================================== */

static void test_time_in_window(void)
{
    TEST("replay_window");

    /* Equal timestamps: in window */
    ASSERT_TRUE(iec61850_r_time_in_window(500000U, 500000U));
    /* Small forward / backward skew: in window */
    ASSERT_TRUE(iec61850_r_time_in_window(500001U, 500000U));
    ASSERT_TRUE(iec61850_r_time_in_window(499999U, 500000U));
    /* Boundary: exactly +/- 10 s is accepted */
    ASSERT_TRUE(iec61850_r_time_in_window(510000U, 500000U));
    ASSERT_TRUE(iec61850_r_time_in_window(490000U, 500000U));
    /* One millisecond outside: rejected */
    ASSERT_TRUE(!iec61850_r_time_in_window(510001U, 500000U));
    ASSERT_TRUE(!iec61850_r_time_in_window(489999U, 500000U));

    /* Midnight wraparound (ms since midnight, day = 86,400,000) */
    /* 10 ms across midnight: in window */
    ASSERT_TRUE(iec61850_r_time_in_window(5U, 86399995U));
    /* Exactly 10 s across midnight: accepted */
    ASSERT_TRUE(iec61850_r_time_in_window(9000U, 86399000U));
    /* 10 s + 1 ms across midnight: rejected */
    ASSERT_TRUE(!iec61850_r_time_in_window(9001U, 86399000U));
    /* Replay of a message from 11 s before "now" (same day): rejected */
    ASSERT_TRUE(!iec61850_r_time_in_window(86389000U, 0U));
    /* 1000 s apart: rejected */
    ASSERT_TRUE(!iec61850_r_time_in_window(86399999U, 10000U));
    /* Full-day-old timestamp: distance 0 => accepted (documented:
     * the window is a circular distance; callers tracking t_last
     * per session reject same-tod replays via the SPDU Number). */
    ASSERT_TRUE(iec61850_r_time_in_window(500000U + 86400000U, 500000U));

    /* Epoch-second domain: small differences behave identically
     * (domain-agnostic circular comparison). */
    ASSERT_TRUE(iec61850_r_time_in_window(1731400005U, 1731400000U));
    ASSERT_TRUE(iec61850_r_time_in_window(1731399995U, 1731400000U));
    ASSERT_TRUE(!iec61850_r_time_in_window(1731410001U, 1731400000U));
    /* Ring-multiple crossing in the epoch domain */
    ASSERT_TRUE(iec61850_r_time_in_window(86400005U, 86399995U));
    ASSERT_TRUE(!iec61850_r_time_in_window(86410000U, 86399995U));
    PASS();
}

int main(void)
{
    printf("=== R-Profile (90-5) Codec Unit Tests ===\n");

    test_rgoose_roundtrip_plain();
    test_rgoose_roundtrip_secured();
    test_rsv_roundtrip_plain();
    test_rsv_roundtrip_secured();
    test_rgoose_truncations();
    test_rsv_truncations();
    test_overspecified_lengths();
    test_bad_security_extension_lengths();
    test_wrong_profile_and_header();
    test_encode_errors();
    test_time_in_window();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
