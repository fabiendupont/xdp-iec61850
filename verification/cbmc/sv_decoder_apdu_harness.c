/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CBMC Harness for SV APDU Decoder (constrained)
 *
 * Constructs a structurally valid SV APDU with non-deterministic
 * field values. Frame structure validated against real encoder output.
 *
 * Run: cbmc --unwind 10 --object-bits 12 --unwinding-assertions \
 *      --unwindset decode_samples.0:3,ber_decode_visiblestring.0:6 \
 *      verification/cbmc/sv_decoder_apdu_harness.c \
 *      src/asn1/sv_ber.c src/asn1/goose_ber.c \
 *      src/asn1/goose_ber_decode.c src/containers/fixed_string.c \
 *      -I include/iec61850
 */

#include "asn1/sv_ber.h"
#include <assert.h>

int main(void)
{
    /* Non-deterministic field values */
    uint8_t nd_smpCnt;
    uint8_t nd_confRev;
    uint8_t nd_smpSynch;
    uint8_t nd_sample_hi;   /* sample value high byte */
    uint8_t nd_sample_lo;   /* sample value low byte */
    uint8_t nd_quality;

    __CPROVER_assume(nd_confRev > 0);
    __CPROVER_assume(nd_smpSynch <= 2);

    /* Build valid SV APDU: 31 bytes total.
     * Structure matches real sv_encode_apdu output:
     *   62 1D — SV APDU tag, length 29
     *     80 01 01 — noASDU = 1
     *     A1 18 — seqASDU, length 24
     *       30 16 — ASDU SEQUENCE, length 22
     *         80 01 XX — svID = "S"
     *         82 01 XX — smpCnt
     *         83 01 XX — confRev
     *         85 01 XX — smpSynch
     *         A7 08 — seqData, length 8
     *           02 02 XX XX — INTEGER sample value
     *           03 02 00 XX — BIT STRING quality
     */
    uint8_t buf[31];

    buf[0]  = 0x62; buf[1]  = 29;      /* SV APDU, length 29 */
    buf[2]  = 0x80; buf[3]  = 1;  buf[4]  = 1;   /* noASDU = 1 */
    buf[5]  = 0xA1; buf[6]  = 24;      /* seqASDU, length 24 */
    buf[7]  = 0x30; buf[8]  = 22;      /* ASDU, length 22 */
    buf[9]  = 0x80; buf[10] = 1;  buf[11] = 'S';  /* svID = "S" */
    buf[12] = 0x82; buf[13] = 1;  buf[14] = nd_smpCnt;
    buf[15] = 0x83; buf[16] = 1;  buf[17] = nd_confRev;
    buf[18] = 0x85; buf[19] = 1;  buf[20] = nd_smpSynch;
    buf[21] = 0xA7; buf[22] = 8;       /* seqData, length 8 */
    buf[23] = 0x02; buf[24] = 2;       /* INTEGER, length 2 */
    buf[25] = nd_sample_hi;
    buf[26] = nd_sample_lo;
    buf[27] = 0x03; buf[28] = 2;       /* BIT STRING, length 2 */
    buf[29] = 0;                        /* unused bits = 0 */
    buf[30] = nd_quality;

    /* Decode */
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);

    int ret = sv_decode_apdu(buf, sizeof(buf), &apdu);

    /* Must succeed on valid structure */
    assert(ret == SV_BER_OK);

    /* Roundtrip */
    assert(apdu.noASDU == 1);
    assert(apdu.asdu[0].smpCnt == nd_smpCnt);
    assert(apdu.asdu[0].confRev == nd_confRev);
    assert((uint8_t)apdu.asdu[0].smpSynch == nd_smpSynch);
    assert(apdu.asdu[0].num_samples == 1);

    /* Verify sample value decoded correctly (2-byte big-endian signed) */
    int16_t expected_value = (int16_t)((uint16_t)nd_sample_hi << 8 | nd_sample_lo);
    assert(apdu.asdu[0].samples[0].value == (int32_t)expected_value);

    return 0;
}
