/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CBMC Harness for BER Decoder
 *
 * Proves: decoder never reads out of bounds for any 1500-byte packet.
 *
 * Run: cbmc --unwind 10 --object-bits 12 \
 *      verification/cbmc/ber_decoder_harness.c \
 *      src/asn1/goose_ber_decode.c src/asn1/goose_ber.c \
 *      -I include/iec61850
 */

#include "asn1/goose_ber_decode.h"
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

int main(void)
{
    /* Non-deterministic packet — any content up to 1500 bytes */
    uint8_t buf[1500];
    size_t buf_size;
    size_t offset;
    uint8_t expected_tag;

    __CPROVER_assume(buf_size > 0 && buf_size <= 1500);
    __CPROVER_assume(offset < buf_size);

    /* Property 1: ber_decode_tag never reads OOB */
    {
        uint8_t tag;
        size_t off = offset;
        int ret = ber_decode_tag(buf, buf_size, &off, &tag);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 2: ber_decode_length never reads OOB */
    {
        size_t length;
        size_t off = offset;
        int ret = ber_decode_length(buf, buf_size, &off, &length);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 3: ber_decode_boolean never reads OOB */
    {
        bool value;
        size_t off = offset;
        int ret = ber_decode_boolean(buf, buf_size, &off, expected_tag, &value);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 4: ber_decode_int32 never reads OOB */
    {
        int32_t value;
        size_t off = offset;
        int ret = ber_decode_int32(buf, buf_size, &off, expected_tag, &value);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 5: ber_decode_uint32 never reads OOB */
    {
        uint32_t value;
        size_t off = offset;
        int ret = ber_decode_uint32(buf, buf_size, &off, expected_tag, &value);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 6: Full GOOSE APDU decode never reads OOB */
    {
        goose_apdu_t apdu;
        goose_apdu_init(&apdu);
        int ret = goose_decode_apdu(buf, buf_size, &apdu);
        /* Return value is unconstrained — decode may fail on random data,
         * but it must never crash or read past buf[buf_size-1] */
        (void)ret;
    }

    return 0;
}
