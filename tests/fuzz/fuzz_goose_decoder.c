/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fuzz Target: GOOSE BER Decoder
 *
 * Feed random bytes to goose_decode_apdu. Must not crash or trigger UB.
 * Compatible with both AFL and libFuzzer entry points.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -I include/iec61850 \
 *         tests/fuzz/fuzz_goose_decoder.c src/asn1/goose_ber.c \
 *         src/asn1/goose_ber_decode.c -o fuzz_goose_decoder
 *
 * Or run as standalone for 10 seconds with random input:
 *   ./fuzz_goose_decoder --standalone
 *
 * License: BSD-2-Clause
 */

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* libFuzzer entry point */
#ifdef __AFL_COMPILER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* Try to decode: must not crash */
    (void)goose_decode_apdu(data, size, &apdu);

    /* Also try decode_ex variant */
    goose_apdu_init(&apdu);
    size_t consumed = 0;
    (void)goose_decode_apdu_ex(data, size, &apdu, &consumed);

    return 0;
}

/* Standalone mode for non-fuzzer testing */
#ifndef __AFL_COMPILER
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("GOOSE decoder fuzz: standalone mode (10 seconds)\n");
    srand((unsigned int)time(NULL));

    time_t start = time(NULL);
    uint64_t iterations = 0;

    while (time(NULL) - start < 10) {
        /* Generate random input */
        size_t len = (size_t)(rand() % 2048);
        uint8_t *buf = (uint8_t *)malloc(len);
        if (buf == NULL) { continue; }

        for (size_t i = 0; i < len; i++) {
            buf[i] = (uint8_t)(rand() % 256);
        }

        LLVMFuzzerTestOneInput(buf, len);
        free(buf);
        iterations++;
    }

    printf("Completed %lu iterations without crash\n", (unsigned long)iterations);
    return 0;
}

#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
#endif /* __AFL_COMPILER */
