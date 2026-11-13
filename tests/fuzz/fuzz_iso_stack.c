/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fuzz Target: ISO Transport Stack Decoder
 *
 * Feed random bytes to the ISO stack decode surface (TPKT, ISO 8327
 * Session, ISO 8823 Presentation, ACSE). Must not crash or trigger UB.
 * Compatible with both AFL and libFuzzer entry points.
 *
 * Every decoder declared in include/iec61850/transport/iso_stack.h is
 * exercised twice: once with the raw fuzz input, and once through a
 * chained pass that peels valid layers (TPKT → Session → Presentation
 * → ACSE) so full-stack frames from the corpus reach the deeper
 * decoders.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -I include/iec61850 \
 *         tests/fuzz/fuzz_iso_stack.c src/transport/iso_stack.c \
 *         -o fuzz_iso_stack
 *
 * Or run as standalone for 10 seconds with random input:
 *   ./fuzz_iso_stack --standalone
 *
 * License: BSD-2-Clause
 */

#include "transport/iso_stack.h"

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
    /* ----------------------------------------------------------------
     * Layer 1: TPKT (RFC 1006)
     * ---------------------------------------------------------------- */
    const uint8_t *tpkt_payload = NULL;
    size_t tpkt_payload_len = 0;
    (void)iec61850_tpkt_decode(data, size, &tpkt_payload, &tpkt_payload_len);

    /* ----------------------------------------------------------------
     * Layer 2: ISO 8327 Session
     * ---------------------------------------------------------------- */
    uint8_t si_type = 0;
    iec61850_session_params_t session_params;
    iec61850_session_params_init(&session_params);
    const uint8_t *user_data = NULL;
    size_t user_data_len = 0;
    (void)iec61850_session_decode(data, size, &si_type, &session_params,
                                    &user_data, &user_data_len);

    /* Same call with NULL params (documented in the unit tests) */
    si_type = 0;
    user_data = NULL;
    user_data_len = 0;
    (void)iec61850_session_decode(data, size, &si_type, NULL,
                                    &user_data, &user_data_len);

    /* ----------------------------------------------------------------
     * Layer 3: ISO 8823 Presentation
     * ---------------------------------------------------------------- */
    uint8_t pcid = 0;
    const uint8_t *app_pdu = NULL;
    size_t app_len = 0;
    (void)iec61850_pres_decode(data, size, &pcid, &app_pdu, &app_len);

    /* ----------------------------------------------------------------
     * Layer 4: ACSE (ISO 8650)
     * ---------------------------------------------------------------- */
    uint8_t acse_tag = 0;
    iec61850_acse_params_t acse_params;
    iec61850_acse_params_init(&acse_params);
    iec61850_aare_result_t result = IEC61850_AARE_ACCEPTED;
    const uint8_t *acse_app_pdu = NULL;
    size_t acse_app_len = 0;
    (void)iec61850_acse_decode(data, size, &acse_tag, &acse_params,
                                 &result, &acse_app_pdu, &acse_app_len);

    /* ----------------------------------------------------------------
     * Chained pass: peel valid layers so full-stack frames reach the
     * deeper decoders. Payload pointers stay inside the input buffer.
     * ---------------------------------------------------------------- */
    if (tpkt_payload != NULL) {
        uint8_t chained_si = 0;
        iec61850_session_params_t chained_session;
        iec61850_session_params_init(&chained_session);
        const uint8_t *chained_ud = NULL;
        size_t chained_ud_len = 0;

        if ((iec61850_session_decode(tpkt_payload, tpkt_payload_len,
                                       &chained_si, &chained_session,
                                       &chained_ud, &chained_ud_len) == 0) &&
            (chained_ud != NULL)) {
            uint8_t chained_pcid = 0;
            const uint8_t *chained_app = NULL;
            size_t chained_app_len = 0;

            if ((iec61850_pres_decode(chained_ud, chained_ud_len,
                                        &chained_pcid, &chained_app,
                                        &chained_app_len) == 0) &&
                (chained_app != NULL)) {
                uint8_t chained_tag = 0;
                iec61850_acse_params_t chained_acse;
                iec61850_acse_params_init(&chained_acse);
                iec61850_aare_result_t chained_result = IEC61850_AARE_ACCEPTED;
                const uint8_t *chained_acse_app = NULL;
                size_t chained_acse_app_len = 0;

                (void)iec61850_acse_decode(chained_app, chained_app_len,
                                             &chained_tag, &chained_acse,
                                             &chained_result,
                                             &chained_acse_app,
                                             &chained_acse_app_len);
            }
        }
    }

    return 0;
}

/* Standalone mode for non-fuzzer testing */
#ifndef __AFL_COMPILER
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("ISO stack fuzz: standalone mode (10 seconds)\n");
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
