/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Frama-C Harness for GOOSE BER Encoder + Decoder
 *
 * Verifies ACSL contracts on GOOSE BER functions using
 * Frama-C EVA (abstract interpretation) plugin.
 *
 * Uses C99 {0} initialization to avoid memset modeling issues.
 * Encoder primitive tests + decoder roundtrip with hand-crafted frame.
 *
 * Run: frama-c -eva -eva-precision 3 goose_ber_harness.c \
 *      ../../src/asn1/goose_ber.c ../../src/containers/fixed_string.c \
 *      -cpp-extra-args="-I ../../include/iec61850 -D_POSIX_C_SOURCE=200809L"
 */

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"

int main(void)
{
    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    size_t offset;
    int ret;

    /* === Encoder Primitives (each resets offset) === */

    /* Test 1: ber_encode_tag */
    offset = 0;
    ret = ber_encode_tag(buf, sizeof(buf), &offset, GOOSE_APDU_TAG);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 1; */
    /*@ assert buf[0] == GOOSE_APDU_TAG; */

    /* Test 2: ber_encode_length (short form) */
    offset = 0;
    ret = ber_encode_length(buf, sizeof(buf), &offset, 50);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 1; */

    /* Test 3: ber_encode_length (long form 1 byte) */
    offset = 0;
    ret = ber_encode_length(buf, sizeof(buf), &offset, 200);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 2; */

    /* Test 4: ber_encode_boolean */
    offset = 0;
    ret = ber_encode_boolean(buf, sizeof(buf), &offset,
                              GOOSE_TAG_TEST, true);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 3; */

    /* Test 5: ber_encode_int32 */
    offset = 0;
    ret = ber_encode_int32(buf, sizeof(buf), &offset,
                            GOOSE_TAG_STNUM, 42);
    /*@ assert ret == GOOSE_BER_OK; */

    /* Test 6: ber_encode_uint32 */
    offset = 0;
    ret = ber_encode_uint32(buf, sizeof(buf), &offset,
                             GOOSE_TAG_STNUM, 1000);
    /*@ assert ret == GOOSE_BER_OK; */

    /* Test 7: ber_encode_visiblestring */
    offset = 0;
    ret = ber_encode_visiblestring(buf, sizeof(buf), &offset,
                                    GOOSE_TAG_GOCBREF, "gcb01");
    /*@ assert ret == GOOSE_BER_OK; */

    /* Test 8: ber_encode_utctime */
    offset = 0;
    ret = ber_encode_utctime(buf, sizeof(buf), &offset,
                              GOOSE_TAG_T, 1700000000000000ULL, 0x00);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 10; */

    /* Test 9: Buffer overflow protection */
    uint8_t small_buf[4];
    offset = 0;
    ret = ber_encode_visiblestring(small_buf, sizeof(small_buf), &offset,
                                    GOOSE_TAG_GOCBREF, "this_is_too_long");
    /*@ assert ret == GOOSE_BER_ERR_BUFFER_FULL; */

    /* Test 10: NULL pointer protection */
    ret = ber_encode_tag(NULL, sizeof(buf), &offset, 0x00);
    /*@ assert ret == GOOSE_BER_ERR_INVALID_ARG; */

    /* === Decoder Roundtrip (hand-crafted minimal GOOSE APDU) === */

    /* Minimal valid GOOSE APDU:
     * [61] GOOSE APDU tag (APPLICATION 1 | CONSTRUCTED)
     *   [80] gocbRef = "g"
     *   [81] timeAllowedtoLive = 1000
     *   [82] datSet = "d"
     *   [83] goID = ""  (empty, optional - skip)
     *   [84] t = 8 bytes (UTC timestamp)
     *   [85] stNum = 1
     *   [86] sqNum = 0
     *   [87] test = false
     *   [88] confRev = 1
     *   [89] ndsCom = false
     *   [8A] numDatSetEntries = 0
     *   [AB] allData (empty SEQUENCE)
     */
    uint8_t goose_frame[] = {
        0x61, 0x2A,                     /* GOOSE APDU, length 42 */
          0x80, 0x01, 0x67,             /* gocbRef = "g" */
          0x81, 0x02, 0x03, 0xE8,       /* timeAllowedtoLive = 1000 */
          0x82, 0x01, 0x64,             /* datSet = "d" */
          0x83, 0x00,                   /* goID = "" (empty) */
          0x84, 0x08,                   /* t = UTC time (8 bytes) */
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
          0x85, 0x01, 0x01,             /* stNum = 1 */
          0x86, 0x01, 0x00,             /* sqNum = 0 */
          0x87, 0x01, 0x00,             /* test = false */
          0x88, 0x01, 0x01,             /* confRev = 1 */
          0x89, 0x01, 0x00,             /* ndsCom = false */
          0x8A, 0x01, 0x00,             /* numDatSetEntries = 0 */
          0xAB, 0x00                    /* allData (empty) */
    };

    goose_apdu_t decoded = {0};
    ret = goose_decode_apdu(goose_frame, sizeof(goose_frame), &decoded);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert decoded.stNum == 1; */
    /*@ assert decoded.sqNum == 0; */
    /*@ assert decoded.confRev == 1; */

    /* Decoder error: truncated frame */
    goose_apdu_t trunc = {0};
    ret = goose_decode_apdu(goose_frame, 5, &trunc);
    /*@ assert ret != GOOSE_BER_OK; */

    /* Decoder error: completely invalid data */
    uint8_t bad[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    goose_apdu_t bad_decoded = {0};
    ret = goose_decode_apdu(bad, sizeof(bad), &bad_decoded);
    (void)ret;  /* may fail — must not crash */

    return 0;
}
