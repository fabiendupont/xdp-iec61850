/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CBMC Harness for BER Decoder Primitives
 *
 * Proves: individual decoder primitives never read out of bounds.
 * Decomposed from ber_decoder_harness.c to avoid state space explosion
 * from full goose_decode_apdu().
 *
 * Run: cbmc --unwind 10 --object-bits 12 \
 *      verification/cbmc/ber_decoder_primitives_harness.c \
 *      src/asn1/goose_ber_decode.c src/asn1/goose_ber.c \
 *      src/containers/fixed_string.c \
 *      -I include/iec61850
 */

#include "asn1/goose_ber_decode.h"
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

int main(void)
{
    uint8_t buf[256];
    size_t buf_size;
    size_t offset;
    uint8_t expected_tag;

    __CPROVER_assume(buf_size > 0 && buf_size <= 256);
    __CPROVER_assume(offset < buf_size);

    /* Property 1: ber_decode_tag */
    {
        uint8_t tag;
        size_t off = offset;
        int ret = ber_decode_tag(buf, buf_size, &off, &tag);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 2: ber_decode_length */
    {
        size_t length;
        size_t off = offset;
        int ret = ber_decode_length(buf, buf_size, &off, &length);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 3: ber_decode_boolean */
    {
        bool value;
        size_t off = offset;
        int ret = ber_decode_boolean(buf, buf_size, &off, expected_tag, &value);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 4: ber_decode_int32 */
    {
        int32_t value;
        size_t off = offset;
        int ret = ber_decode_int32(buf, buf_size, &off, expected_tag, &value);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 5: ber_decode_uint32 */
    {
        uint32_t value;
        size_t off = offset;
        int ret = ber_decode_uint32(buf, buf_size, &off, expected_tag, &value);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 6: ber_decode_visiblestring */
    {
        char str[128];
        size_t off = offset;
        int ret = ber_decode_visiblestring(buf, buf_size, &off, expected_tag,
                                             str, sizeof(str));
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 7: ber_decode_utctime */
    {
        uint64_t value;
        uint8_t time_quality;
        size_t off = offset;
        int ret = ber_decode_utctime(buf, buf_size, &off, expected_tag,
                                       &value, &time_quality);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_ENCODING ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    return 0;
}
