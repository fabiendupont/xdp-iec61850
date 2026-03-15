/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Frama-C Verification Harness for BER Encoder
 *
 * This file provides entry points for formal verification of the BER encoder
 * using Frama-C EVA (Evolved Value Analysis).
 *
 * Verification Goals:
 * 1. Memory safety (no buffer overflows)
 * 2. Absence of undefined behavior
 * 3. Integer overflow protection
 */

#include "asn1/goose_ber.h"
#include <stdint.h>
#include <stdbool.h>

/*@
  @ requires \valid(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires \valid(tag_out);
  @ requires buf_size > 0;
  @ requires *offset < buf_size;
  @ assigns buf[*offset], *offset, *tag_out;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_BUFFER_FULL;
  @*/
int verify_ber_encode_tag(uint8_t *buf, size_t buf_size, size_t *offset, uint8_t tag, uint8_t *tag_out)
{
    int ret = ber_encode_tag(buf, buf_size, offset, tag);
    if (ret == GOOSE_BER_OK) {
        *tag_out = buf[*offset - 1];
    }
    return ret;
}

/*@
  @ requires \valid(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires buf_size > 0;
  @ requires *offset < buf_size;
  @ assigns buf[*offset .. buf_size-1], *offset;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_BUFFER_FULL || \result == GOOSE_BER_ERR_ENCODING;
  @*/
int verify_ber_encode_length(uint8_t *buf, size_t buf_size, size_t *offset, size_t length)
{
    return ber_encode_length(buf, buf_size, offset, length);
}

/*@
  @ requires \valid(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires buf_size >= 3;
  @ requires *offset < buf_size - 2;
  @ assigns buf[*offset .. buf_size-1], *offset;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_BUFFER_FULL;
  @*/
int verify_ber_encode_boolean(uint8_t *buf, size_t buf_size, size_t *offset,
                               uint8_t tag, bool value)
{
    return ber_encode_boolean(buf, buf_size, offset, tag, value);
}

/*@
  @ requires \valid(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires buf_size >= 7;
  @ requires *offset < buf_size - 6;
  @ assigns buf[*offset .. buf_size-1], *offset;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_BUFFER_FULL;
  @*/
int verify_ber_encode_int32(uint8_t *buf, size_t buf_size, size_t *offset,
                             uint8_t tag, int32_t value)
{
    return ber_encode_int32(buf, buf_size, offset, tag, value);
}

/*@
  @ requires \valid(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires buf_size >= 7;
  @ requires *offset < buf_size - 6;
  @ assigns buf[*offset .. buf_size-1], *offset;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_BUFFER_FULL;
  @*/
int verify_ber_encode_uint32(uint8_t *buf, size_t buf_size, size_t *offset,
                              uint8_t tag, uint32_t value)
{
    return ber_encode_uint32(buf, buf_size, offset, tag, value);
}

/*
 * Main verification entry point
 *
 * Tests all low-level BER encoding functions with bounded inputs.
 */
void main(void)
{
    uint8_t buffer[256];
    size_t offset;
    uint8_t tag_result;
    int ret;

    /* Initialize buffer to zero */
    /*@ loop assigns i, buffer[0..255];
      @ loop invariant 0 <= i <= 256;
      @ loop variant 256 - i;
      @*/
    for (size_t i = 0; i < 256; i++) {
        buffer[i] = 0;
    }

    /* Test 1: Encode tag */
    offset = 0;
    ret = verify_ber_encode_tag(buffer, 256, &offset, 0x80, &tag_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 1; */
    /*@ assert buffer[0] == 0x80; */

    /* Test 2: Encode short length (< 128) */
    offset = 0;
    ret = verify_ber_encode_length(buffer, 256, &offset, 42);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 1; */
    /*@ assert buffer[0] == 42; */

    /* Test 3: Encode long length (128-255) */
    offset = 0;
    ret = verify_ber_encode_length(buffer, 256, &offset, 200);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 2; */
    /*@ assert buffer[0] == 0x81; */
    /*@ assert buffer[1] == 200; */

    /* Test 4: Encode boolean TRUE */
    offset = 0;
    ret = verify_ber_encode_boolean(buffer, 256, &offset, 0x87, true);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 3; */
    /*@ assert buffer[0] == 0x87; */
    /*@ assert buffer[1] == 0x01; */
    /*@ assert buffer[2] == 0xFF; */

    /* Test 5: Encode boolean FALSE */
    offset = 0;
    ret = verify_ber_encode_boolean(buffer, 256, &offset, 0x87, false);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 3; */
    /*@ assert buffer[2] == 0x00; */

    /* Test 6: Encode positive int32 */
    offset = 0;
    ret = verify_ber_encode_int32(buffer, 256, &offset, 0x85, 12345);
    /*@ assert ret == GOOSE_BER_OK; */

    /* Test 7: Encode negative int32 */
    offset = 0;
    ret = verify_ber_encode_int32(buffer, 256, &offset, 0x85, -12345);
    /*@ assert ret == GOOSE_BER_OK; */

    /* Test 8: Encode zero */
    offset = 0;
    ret = verify_ber_encode_int32(buffer, 256, &offset, 0x85, 0);
    /*@ assert ret == GOOSE_BER_OK; */

    /* Test 9: Encode uint32 */
    offset = 0;
    ret = verify_ber_encode_uint32(buffer, 256, &offset, 0x86, 0x12345678U);
    /*@ assert ret == GOOSE_BER_OK; */

    /* Test 10: Buffer overflow protection - tag */
    offset = 255;
    ret = verify_ber_encode_tag(buffer, 256, &offset, 0x80, &tag_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /* Call ber_encode_tag directly — offset==buf_size intentionally violates
       verify_ber_encode_tag's precondition to test the overflow guard. */
    offset = 256;
    ret = ber_encode_tag(buffer, 256, &offset, 0x80);
    /*@ assert ret == GOOSE_BER_ERR_BUFFER_FULL; */

    /* Test 11: NULL pointer protection */
    ret = ber_encode_tag(NULL, 256, &offset, 0x80);
    /*@ assert ret == GOOSE_BER_ERR_INVALID_ARG; */
    ret = ber_encode_tag(buffer, 256, NULL, 0x80);
    /*@ assert ret == GOOSE_BER_ERR_INVALID_ARG; */
}
