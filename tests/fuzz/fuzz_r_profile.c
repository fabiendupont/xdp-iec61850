/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fuzz Target: IEC TR 61850-90-5 R-GOOSE / R-SV Decoders
 *
 * Feed random bytes to the routable-profile decoders. Must not crash
 * or trigger UB. Compatible with both AFL and libFuzzer entry points.
 *
 * WP-S4 scaffold — harness filled in by WP-4a alongside the codecs.
 */

#include "asn1/r_profile.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

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

/* libFuzzer entry point */
#ifdef __AFL_COMPILER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Smoke-level coverage until WP-4a expands the harness */
    goose_apdu_t goose;
    goose_apdu_init(&goose);
    iec61850_r_header_t hdr;
    (void)iec61850_rgoose_decode(data, size, &goose, &hdr);

    sv_apdu_t sv;
    sv_apdu_init(&sv);
    (void)iec61850_rsv_decode(data, size, &sv, &hdr);

    (void)iec61850_r_time_in_window(
        (uint32_t)(size & 0xFFFFFFFFU), (uint32_t)(size >> 5));
    return 0;
}

/* Standalone mode for non-fuzzer testing */
#ifndef __AFL_COMPILER
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

int main(int argc, char **argv)
{
    if (argc > 1) {
        /* Corpus replay mode (deterministic regression check). */
        int ran = 0;
        for (int i = 1; i < argc; i++) {
            int r = fuzz_replay_path(argv[i]);
            if (r < 0) {
                fprintf(stderr, "replay failed: %s\n", argv[i]);
                return 1;
            }
            ran += r;
        }
        printf("R-profile fuzz: replayed %d inputs without crash\n", ran);
        return 0;
    }

    printf("R-profile fuzz: standalone mode (10 seconds)\n");
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
