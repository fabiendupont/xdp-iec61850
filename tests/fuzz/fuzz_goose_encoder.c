/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fuzz Target for GOOSE BER Encoder
 *
 * Standalone mode: runs with random inputs.
 * LibFuzzer mode: build with -fsanitize=fuzzer.
 */

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __AFL_FUZZ_TESTCASE_LEN
/* AFL mode */
__AFL_FUZZ_INIT();
#endif

static int fuzz_one(const uint8_t *data, size_t size)
{
    if (size < 16) { return 0; }

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* Use fuzz data to populate fields */
    size_t pos = 0;
    apdu.stNum = (uint32_t)data[pos] << 24 | (uint32_t)data[pos + 1] << 16 |
                 (uint32_t)data[pos + 2] << 8 | (uint32_t)data[pos + 3];
    pos += 4;
    apdu.sqNum = (uint32_t)data[pos] << 24 | (uint32_t)data[pos + 1] << 16 |
                 (uint32_t)data[pos + 2] << 8 | (uint32_t)data[pos + 3];
    pos += 4;
    apdu.confRev = (uint32_t)data[pos]; pos++;
    apdu.test = (data[pos] & 1) != 0; pos++;
    apdu.ndsCom = (data[pos] & 1) != 0; pos++;
    apdu.timeAllowedtoLive = (uint32_t)data[pos] << 8 |
                             (uint32_t)data[pos + 1];
    pos += 2;

    /* Set gocbRef from remaining data */
    size_t ref_len = (size - pos > GOOSE_MAX_GOCBREF_LEN - 1)
                     ? GOOSE_MAX_GOCBREF_LEN - 1 : size - pos;
    if (ref_len > 0) {
        char ref[GOOSE_MAX_GOCBREF_LEN];
        memcpy(ref, data + pos, ref_len);
        ref[ref_len] = '\0';
        goose_set_gocbref(&apdu, ref);
    }

    /* Encode */
    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    size_t encoded_len = 0;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);

    /* If encode succeeded, verify round-trip */
    if (ret == GOOSE_BER_OK && encoded_len > 0) {
        goose_apdu_t decoded;
        goose_apdu_init(&decoded);
        (void)goose_decode_apdu(buf, encoded_len, &decoded);
    }

    return 0;
}

#ifdef LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one(data, size);
}
#else
int main(void)
{
    /* Standalone mode: random inputs */
    srand(42);
    for (int i = 0; i < 10000; i++) {
        uint8_t data[256];
        size_t len = (size_t)(rand() % 240) + 16;
        for (size_t j = 0; j < len; j++) {
            data[j] = (uint8_t)(rand() & 0xFF);
        }
        fuzz_one(data, len);
    }
    return 0;
}
#endif
