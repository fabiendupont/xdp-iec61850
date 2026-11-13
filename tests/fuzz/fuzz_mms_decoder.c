/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fuzz Target: MMS BER Decoder
 *
 * Feed random bytes to the full MMS BER decode surface declared in
 * include/iec61850/asn1/mms_ber.h. Must not crash or trigger UB.
 * Compatible with both AFL and libFuzzer entry points.
 *
 * Decode functions exercised:
 *   - mms_decode_length, mms_decode_value
 *   - mms_decode_initiate_request / initiate_response
 *   - mms_decode_conclude_request / conclude_response
 *   - mms_decode_confirmed_request / confirmed_response / confirmed_error
 *   - mms_decode_information_report
 *   - mms_decode_iec61850_report (IEC 61850-7-2 URCB reports)
 *   - control services: select, select-with-value, operate, cancel
 *     (request + response) and command termination
 *
 * Every decoder receives the same fuzz input; return codes are ignored
 * (the contract is no crash / no UB). A truncated view of the input is
 * additionally fed to a few decoders to exercise partial-buffer paths.
 *
 * License: BSD-2-Clause
 */

#include "asn1/mms_ber.h"

/* POSIX (stat/opendir) comes from the project-wide
 * -D_POSIX_C_SOURCE/-D_DEFAULT_SOURCE command-line defines. */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>

/* libFuzzer entry point */
#ifdef __AFL_COMPILER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /*
     * Output structs are large (up to a few hundred KB); keep them in
     * static storage and re-initialize before each decode call.
     */
    static mms_initiate_request_t initiate_req;
    static mms_initiate_response_t initiate_resp;
    static mms_conclude_request_t conclude_req;
    static mms_conclude_response_t conclude_resp;
    static mms_confirmed_request_t confirmed_req;
    static mms_confirmed_response_t confirmed_resp;
    static mms_confirmed_error_t confirmed_err;
    static mms_information_report_t info_report;
    static mms_select_request_t select_req;
    static mms_select_response_t select_resp;
    static mms_select_with_value_request_t select_wv_req;
    static mms_select_with_value_response_t select_wv_resp;
    static mms_operate_request_t operate_req;
    static mms_operate_response_t operate_resp;
    static mms_cancel_request_t cancel_req;
    static mms_cancel_response_t cancel_resp;
    static mms_command_termination_t cmd_term;
    static mms_value_t value;
    size_t length = 0;

    /* Helper decoders */
    (void)mms_decode_length(data, size, &length);

    memset(&value, 0, sizeof(value));
    (void)mms_decode_value(data, size, &value);

    /* Association management */
    memset(&initiate_req, 0, sizeof(initiate_req));
    (void)mms_decode_initiate_request(data, size, &initiate_req);

    memset(&initiate_resp, 0, sizeof(initiate_resp));
    (void)mms_decode_initiate_response(data, size, &initiate_resp);

    memset(&conclude_req, 0, sizeof(conclude_req));
    (void)mms_decode_conclude_request(data, size, &conclude_req);

    memset(&conclude_resp, 0, sizeof(conclude_resp));
    (void)mms_decode_conclude_response(data, size, &conclude_resp);

    /* Confirmed services (covers Read, Write, GetNameList, file, journal,
     * named-variable-list and type service decoders via the union in
     * mms_confirmed_request_t / mms_confirmed_response_t) */
    memset(&confirmed_req, 0, sizeof(confirmed_req));
    (void)mms_decode_confirmed_request(data, size, &confirmed_req);

    memset(&confirmed_resp, 0, sizeof(confirmed_resp));
    (void)mms_decode_confirmed_response(data, size, &confirmed_resp);

    memset(&confirmed_err, 0, sizeof(confirmed_err));
    (void)mms_decode_confirmed_error(data, size, &confirmed_err);

    /* Unconfirmed services */
    memset(&info_report, 0, sizeof(info_report));
    (void)mms_decode_information_report(data, size, &info_report);

    /* Full IEC 61850-7-2 URCB report format (WP-1b) */
    memset(&info_report, 0, sizeof(info_report));
    (void)mms_decode_iec61850_report(data, size, &info_report);

    /* Control services */
    memset(&select_req, 0, sizeof(select_req));
    (void)mms_decode_select_request(data, size, &select_req);

    memset(&select_resp, 0, sizeof(select_resp));
    (void)mms_decode_select_response(data, size, &select_resp);

    memset(&select_wv_req, 0, sizeof(select_wv_req));
    (void)mms_decode_select_with_value_request(data, size, &select_wv_req);

    memset(&select_wv_resp, 0, sizeof(select_wv_resp));
    (void)mms_decode_select_with_value_response(data, size, &select_wv_resp);

    memset(&operate_req, 0, sizeof(operate_req));
    (void)mms_decode_operate_request(data, size, &operate_req);

    memset(&operate_resp, 0, sizeof(operate_resp));
    (void)mms_decode_operate_response(data, size, &operate_resp);

    memset(&cancel_req, 0, sizeof(cancel_req));
    (void)mms_decode_cancel_request(data, size, &cancel_req);

    memset(&cancel_resp, 0, sizeof(cancel_resp));
    (void)mms_decode_cancel_response(data, size, &cancel_resp);

    memset(&cmd_term, 0, sizeof(cmd_term));
    (void)mms_decode_command_termination(data, size, &cmd_term);

    /* Truncated views exercise partial-buffer bounds checks */
    if (size > 1) {
        const uint8_t *half = data + size / 2;
        size_t half_len = size / 2;

        memset(&value, 0, sizeof(value));
        (void)mms_decode_value(half, half_len, &value);

        memset(&confirmed_req, 0, sizeof(confirmed_req));
        (void)mms_decode_confirmed_request(half, half_len, &confirmed_req);

        memset(&confirmed_resp, 0, sizeof(confirmed_resp));
        (void)mms_decode_confirmed_response(half, half_len, &confirmed_resp);

        memset(&info_report, 0, sizeof(info_report));
        (void)mms_decode_information_report(half, half_len, &info_report);

        memset(&info_report, 0, sizeof(info_report));
        (void)mms_decode_iec61850_report(half, half_len, &info_report);
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
        /* Corpus replay mode: feed each given file or directory to
         * the harness once. Used by the 'fuzz' test suite and
         * scripts/fuzz_smoke.sh as a deterministic regression check. */
        int ran = 0;
        for (int i = 1; i < argc; i++) {
            int r = fuzz_replay_path(argv[i]);
            if (r < 0) {
                fprintf(stderr, "replay failed: %s\n", argv[i]);
                return 1;
            }
            ran += r;
        }
        printf("MMS decoder fuzz: replayed %d inputs without crash\n", ran);
        return 0;
    }

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
