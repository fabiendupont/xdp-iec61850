/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CBMC Harness for GOOSE APDU Decoder (constrained)
 *
 * Constructs a structurally valid GOOSE APDU with non-deterministic
 * field values. Proves decoder safety and roundtrip correctness.
 *
 * Run: cbmc --unwind 10 --object-bits 12 --unwinding-assertions \
 *      --unwindset goose_decode_alldata.0:3,ber_decode_visiblestring.0:6 \
 *      verification/cbmc/ber_decoder_apdu_harness.c \
 *      src/asn1/goose_ber_decode.c src/asn1/goose_ber.c \
 *      src/containers/fixed_string.c \
 *      -I include/iec61850
 */

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include <assert.h>

int main(void)
{
    /* Non-deterministic field values */
    uint8_t nd_stNum;
    uint8_t nd_sqNum;
    uint8_t nd_confRev;
    uint8_t nd_timeAllowed;
    uint8_t nd_test_byte;      /* raw byte: 0x00 = false, else true */
    uint8_t nd_ndsCom_byte;

    __CPROVER_assume(nd_confRev > 0);

    /* Fixed-structure GOOSE APDU (41 bytes content) */
    uint8_t buf[43];   /* 2 (tag+len) + 41 content */

    /* APDU header */
    buf[0] = 0x61;  /* GOOSE APDU tag */
    buf[1] = 41;    /* content length */

    /* [0] gocbRef = "g" */
    buf[2] = 0x80; buf[3] = 1; buf[4] = 'g';

    /* [1] timeAllowedtoLive */
    buf[5] = 0x81; buf[6] = 1; buf[7] = nd_timeAllowed;

    /* [2] datSet = "d" */
    buf[8] = 0x82; buf[9] = 1; buf[10] = 'd';

    /* [3] goID = "" (empty) */
    buf[11] = 0x83; buf[12] = 0;

    /* [4] t = UTC timestamp (8 zero bytes) */
    buf[13] = 0x84; buf[14] = 8;
    buf[15] = 0; buf[16] = 0; buf[17] = 0; buf[18] = 0;
    buf[19] = 0; buf[20] = 0; buf[21] = 0; buf[22] = 0;

    /* [5] stNum */
    buf[23] = 0x85; buf[24] = 1; buf[25] = nd_stNum;

    /* [6] sqNum */
    buf[26] = 0x86; buf[27] = 1; buf[28] = nd_sqNum;

    /* [7] test */
    buf[29] = 0x87; buf[30] = 1; buf[31] = nd_test_byte;

    /* [8] confRev */
    buf[32] = 0x88; buf[33] = 1; buf[34] = nd_confRev;

    /* [9] ndsCom */
    buf[35] = 0x89; buf[36] = 1; buf[37] = nd_ndsCom_byte;

    /* [10] numDatSetEntries = 0 */
    buf[38] = 0x8A; buf[39] = 1; buf[40] = 0;

    /* [11] allData (empty SEQUENCE) */
    buf[41] = 0xAB; buf[42] = 0;

    /* Decode */
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    int ret = goose_decode_apdu(buf, sizeof(buf), &apdu);

    /* Must succeed */
    assert(ret == GOOSE_BER_OK);

    /* Roundtrip: values match */
    assert(apdu.stNum == nd_stNum);
    assert(apdu.sqNum == nd_sqNum);
    assert(apdu.confRev == nd_confRev);
    assert(apdu.timeAllowedtoLive == nd_timeAllowed);
    assert(apdu.test == (nd_test_byte != 0));
    assert(apdu.ndsCom == (nd_ndsCom_byte != 0));
    assert(apdu.numDatSetEntries == 0);

    return 0;
}
