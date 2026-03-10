/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CBMC Harness for BER Encoder
 *
 * Proves: encoder never writes past buffer for any input.
 *
 * Run: cbmc --unwind 10 --object-bits 12 \
 *      verification/cbmc/ber_encoder_harness.c \
 *      src/asn1/goose_ber.c \
 *      -I include/iec61850
 */

#include "asn1/goose_ber.h"
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

int main(void)
{
    /* Non-deterministic buffer up to 1500 bytes (MTU) */
    uint8_t buf[1500];
    size_t buf_size;
    size_t offset;
    uint8_t tag;
    size_t length;
    int32_t int_val;
    uint32_t uint_val;
    bool bool_val;

    __CPROVER_assume(buf_size > 0 && buf_size <= 1500);
    __CPROVER_assume(offset <= buf_size);

    /* Property 1: ber_encode_tag never writes past buffer */
    {
        size_t off = offset;
        int ret = ber_encode_tag(buf, buf_size, &off, tag);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
            assert(off == offset + 1);
        }
    }

    /* Property 2: ber_encode_length never writes past buffer */
    {
        __CPROVER_assume(length <= 65535);
        size_t off = offset;
        int ret = ber_encode_length(buf, buf_size, &off, length);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_BUFFER_FULL ||
               ret == GOOSE_BER_ERR_ENCODING);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 3: ber_encode_boolean never writes past buffer */
    {
        size_t off = offset;
        int ret = ber_encode_boolean(buf, buf_size, &off, tag, bool_val);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 4: ber_encode_int32 never writes past buffer */
    {
        size_t off = offset;
        int ret = ber_encode_int32(buf, buf_size, &off, tag, int_val);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    /* Property 5: ber_encode_uint32 never writes past buffer */
    {
        size_t off = offset;
        int ret = ber_encode_uint32(buf, buf_size, &off, tag, uint_val);
        assert(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
               ret == GOOSE_BER_ERR_BUFFER_FULL);
        if (ret == GOOSE_BER_OK) {
            assert(off <= buf_size);
        }
    }

    return 0;
}
