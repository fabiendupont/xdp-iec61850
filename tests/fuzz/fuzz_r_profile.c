/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fuzz Target: IEC TR 61850-90-5 R-GOOSE / R-SV Decoders
 *
 * Feed random bytes to the routable-profile decoders, and round-trip
 * input-driven encodings (plain + secured) with a full truncation
 * sweep of the encoded SPDU. Must not crash or trigger UB.
 * Compatible with both AFL and libFuzzer entry points.
 *
 * Harness completed by WP-4a alongside the codecs.
 */

#include "asn1/r_profile.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    goose_apdu_t goose;
    iec61850_r_header_t hdr;
    int ret;

    /* Raw decoders: both profiles, with and without metadata
     * extraction. Must reject malformed input without crashing. */
    goose_apdu_init(&goose);
    (void)iec61850_rgoose_decode(data, size, &goose, &hdr);
    goose_apdu_init(&goose);
    (void)iec61850_rgoose_decode(data, size, &goose, NULL);

    {
        sv_apdu_t sv;
        sv_apdu_init(&sv);
        (void)iec61850_rsv_decode(data, size, &sv, &hdr);
        sv_apdu_init(&sv);
        (void)iec61850_rsv_decode(data, size, &sv, NULL);
    }

    (void)iec61850_r_time_in_window(
        (uint32_t)(size & 0xFFFFFFFFU), (uint32_t)(size >> 5));

    /* Encode-roundtrip driven by the input: build an APDU and a
     * security extension from the fuzz bytes, encode, decode back,
     * and sweep every truncation of the encoded SPDU. The guard
     * covers every input byte the parameter derivation reads
     * (data[0..19]). */
    if (size >= 20U) {
        uint8_t out[2048];
        iec61850_r_security_t sec;
        size_t i;

        (void)memset(&sec, 0, sizeof(sec));
        sec.present = (data[0] & 1U) != 0U;
        sec.key_id = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
                     ((uint32_t)data[3] << 8) | data[4];
        sec.time_of_current_key = ((uint32_t)data[5] << 24) |
                                  ((uint32_t)data[6] << 16) |
                                  ((uint32_t)data[7] << 8) | data[8];
        sec.time_to_next_key = (uint16_t)(((uint16_t)data[9] << 8) |
                                          data[10]);
        sec.security_algos = (uint16_t)(((uint16_t)data[11] << 8) |
                                        data[12]);
        sec.signature_len = (size_t)data[13];
        for (i = 0U; i < sec.signature_len; i++) {
            sec.signature[i] = data[(14U + i) % size];
        }

        /* Explicit session parameters derived from the input */
        {
            uint16_t fuzz_appid = (uint16_t)(((uint16_t)data[14] << 8) |
                                             data[15]);
            uint32_t fuzz_spdu_number = ((uint32_t)data[16] << 24) |
                                        ((uint32_t)data[17] << 16) |
                                        ((uint32_t)data[18] << 8) |
                                        data[19];

        /* R-GOOSE */
        {
            goose_apdu_t back;

            goose_apdu_init(&goose);
            (void)goose_set_gocbref(&goose, "FUZZ_GO_CB1");
            (void)goose_set_datset(&goose, "FUZZ_DS1");
            goose.stNum = ((uint32_t)data[10] << 8) | data[11];
            goose.sqNum = ((uint32_t)data[12] << 8) | data[13];
            goose.timeAllowedtoLive = 1000U;
            goose.confRev = 1U;
            goose.timestamp = 1000000ULL * (uint64_t)data[14];
            (void)goose_add_int32(&goose, (int32_t)data[15]);
            goose.numDatSetEntries = 1U;

            ret = iec61850_rgoose_encode(&goose, fuzz_appid,
                                         fuzz_spdu_number,
                                         sec.present ? &sec : NULL,
                                         out, sizeof(out));
            if (ret > 0) {
                goose_apdu_init(&back);
                (void)iec61850_rgoose_decode(out, (size_t)ret, &back, &hdr);
                (void)iec61850_rgoose_decode(out, (size_t)ret, &back, NULL);
                for (i = 0U; i < (size_t)ret; i++) {
                    (void)iec61850_rgoose_decode(out, i, &back, NULL);
                }
            }
        }

        /* R-SV */
        {
            sv_apdu_t sv;
            sv_apdu_t back;

            sv_apdu_init(&sv);
            sv.noASDU = 1U;
            (void)sv_set_svid(&sv.asdu[0], "FUZZ_SV1");
            sv.asdu[0].smpCnt = (uint16_t)(((uint16_t)data[10] << 8) |
                                           data[11]);
            sv.asdu[0].confRev = 1U;
            sv.asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;
            {
                sv_quality_t q;
                (void)memset(&q, 0, sizeof(q));
                (void)sv_add_sample(&sv.asdu[0], (int32_t)data[12], q);
                (void)sv_add_sample(&sv.asdu[0], (int32_t)data[13], q);
            }

            ret = iec61850_rsv_encode(&sv, fuzz_appid, fuzz_spdu_number,
                                      sec.present ? &sec : NULL,
                                      out, sizeof(out));
            if (ret > 0) {
                sv_apdu_init(&back);
                (void)iec61850_rsv_decode(out, (size_t)ret, &back, &hdr);
                (void)iec61850_rsv_decode(out, (size_t)ret, &back, NULL);
                for (i = 0U; i < (size_t)ret; i++) {
                    (void)iec61850_rsv_decode(out, i, &back, NULL);
                }
            }
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
