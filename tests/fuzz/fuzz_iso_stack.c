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
/* POSIX (stat/opendir) comes from the project-wide
 * -D_POSIX_C_SOURCE/-D_DEFAULT_SOURCE command-line defines. */
#include <sys/stat.h>
#include <dirent.h>

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

/* Corpus replay helper: feed one file (or every file in a directory,
 * one level deep, hidden entries skipped) to the harness once.
 * Returns the number of inputs run, or -1 on I/O error. */
static int fuzz_replay_path(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "replay: cannot stat %s\n", path);
        return -1;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (dir == NULL) {
            fprintf(stderr, "replay: cannot open %s\n", path);
            return -1;
        }
        int ran = 0;
        const struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '.') { continue; }
            char full[1024];
            int n = snprintf(full, sizeof(full), "%s/%s",
                             path, ent->d_name);
            if (n <= 0 || (size_t)n >= sizeof(full)) { continue; }
            int r = fuzz_replay_path(full);
            if (r < 0) { continue; }
            ran += r;
        }
        closedir(dir);
        return ran;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) { return -1; }
    (void)fseek(f, 0, SEEK_END);
    long len = ftell(f);
    (void)fseek(f, 0, SEEK_SET);
    if (len < 0) { (void)fclose(f); return -1; }
    uint8_t *buf = (uint8_t *)malloc(len > 0 ? (size_t)len : 1);
    if (buf == NULL) { (void)fclose(f); return -1; }
    size_t got = 0;
    if (len > 0) { got = fread(buf, 1, (size_t)len, f); }
    (void)fclose(f);

    printf("replay: %s (%zu bytes)\n", path, got);
    LLVMFuzzerTestOneInput(buf, got);
    free(buf);
    return 1;
}

/* Standalone mode for non-fuzzer testing */
#ifndef __AFL_COMPILER
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

int main(int argc, char **argv)
{
    if (argc > 1) {
        /* Corpus replay mode: deterministic regression check used by
         * the 'fuzz' test suite and scripts/fuzz_smoke.sh. */
        int ran = 0;
        for (int i = 1; i < argc; i++) {
            int r = fuzz_replay_path(argv[i]);
            if (r < 0) {
                fprintf(stderr, "replay failed: %s\n", argv[i]);
                return 1;
            }
            ran += r;
        }
        printf("ISO stack fuzz: replayed %d inputs without crash\n", ran);
        return 0;
    }

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
