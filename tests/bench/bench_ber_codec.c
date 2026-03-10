/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * BER Encode/Decode Throughput Benchmark
 *
 * Measures GOOSE and SV BER codec throughput in ops/sec.
 */

#define _POSIX_C_SOURCE 199309L

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include "asn1/sv_ber.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define ITERATIONS 100000

static double elapsed_ms(struct timespec *start, struct timespec *end)
{
    double s = (double)(end->tv_sec - start->tv_sec) * 1000.0;
    double ns = (double)(end->tv_nsec - start->tv_nsec) / 1000000.0;
    return s + ns;
}

static void bench_goose_encode(void)
{
    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    goose_apdu_t apdu;
    size_t encoded;
    struct timespec start, end;

    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    goose_set_goid(&apdu, "GOOSE1");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    apdu.confRev = 1;
    apdu.timeAllowedtoLive = 2000;

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        apdu.sqNum = (uint32_t)i;
        goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double ms = elapsed_ms(&start, &end);
    printf("GOOSE encode: %d iterations in %.1f ms (%.0f ops/sec)\n",
           ITERATIONS, ms, (double)ITERATIONS / ms * 1000.0);
}

static void bench_goose_decode(void)
{
    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    goose_apdu_t apdu;
    size_t encoded;
    struct timespec start, end;

    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    apdu.confRev = 1;
    goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        goose_apdu_t decoded;
        goose_apdu_init(&decoded);
        goose_decode_apdu(buf, encoded, &decoded);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double ms = elapsed_ms(&start, &end);
    printf("GOOSE decode: %d iterations in %.1f ms (%.0f ops/sec)\n",
           ITERATIONS, ms, (double)ITERATIONS / ms * 1000.0);
}

static void bench_sv_encode(void)
{
    uint8_t buf[1024];
    sv_apdu_t apdu;
    size_t encoded;
    struct timespec start, end;

    sv_apdu_init(&apdu);
    sv_set_svid(&apdu.asdu[0], "SV1");
    apdu.asdu[0].confRev = 1;
    apdu.asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;
    sv_quality_t q;
    memset(&q, 0, sizeof(q));
    for (int c = 0; c < 8; c++) {
        sv_add_sample(&apdu.asdu[0], 1000 + c, q);
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < ITERATIONS; i++) {
        apdu.asdu[0].smpCnt = (uint16_t)(i % 4000);
        sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double ms = elapsed_ms(&start, &end);
    printf("SV encode:    %d iterations in %.1f ms (%.0f ops/sec)\n",
           ITERATIONS, ms, (double)ITERATIONS / ms * 1000.0);
}

int main(void)
{
    printf("=== BER Codec Benchmark ===\n\n");
    bench_goose_encode();
    bench_goose_decode();
    bench_sv_encode();
    printf("\nDone.\n");
    return 0;
}
