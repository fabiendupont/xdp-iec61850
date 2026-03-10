/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fuzz Target: SV BER Decoder
 *
 * Feed random bytes to sv_decode_apdu. Must not crash or trigger UB.
 *
 * License: BSD-3-Clause
 */

#include "asn1/sv_ber.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);

    /* Try to decode: must not crash */
    (void)sv_decode_apdu(data, size, &apdu);

    return 0;
}

#ifndef __AFL_COMPILER
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("SV decoder fuzz: standalone mode (10 seconds)\n");
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

#endif
#endif
