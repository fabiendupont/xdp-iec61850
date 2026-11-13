/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fuzz Target: MMS BER Decoder (scaffold — WP-0a)
 *
 * Feed random bytes to the MMS BER decode surface. Must not crash or
 * trigger UB. Compatible with both AFL and libFuzzer entry points.
 *
 * This file is scaffolded by WP-S0; WP-0a (fuzz-mms) fills in full
 * decode-surface coverage: confirmed request/response/error, reject,
 * InformationReport, all service decoders (Read, Write, GetNameList,
 * control, file, journal, named-variable-list), mms_decode_length and
 * mms_decode_value.
 *
 * License: BSD-2-Clause
 */

#include "asn1/mms_ber.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* libFuzzer entry point */
#ifdef __AFL_COMPILER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Smoke-level coverage until WP-0a expands the harness */
    size_t length = 0;
    (void)mms_decode_length(data, size, &length);
    return 0;
}

/* Standalone mode for non-fuzzer testing */
#ifndef __AFL_COMPILER
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("MMS decoder fuzz: standalone mode (10 seconds)\n");
    srand((unsigned int)time(NULL));

    time_t start = time(NULL);
    uint64_t iterations = 0;

    while (time(NULL) - start < 10) {
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
