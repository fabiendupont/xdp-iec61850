/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Performance Benchmark for IEC 61850 Stack
 *
 * Measures latency and throughput for key operations:
 *   1. GOOSE BER encode/decode
 *   2. SV BER encode/decode
 *   3. MMS request-response roundtrip
 *
 * Results are compared against the 4ms IEC 61850 FR-006 deadline.
 * This is a benchmark, not assertion-based -- always returns 0.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include "asn1/sv_ber.h"
#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#define GOOSE_SV_ITERATIONS  10000
#define MMS_ITERATIONS       1000
#define MMS_BENCH_PORT       10650
#define FR006_DEADLINE_US    4000.0  /* IEC 61850 FR-006: 4 ms */

/*
 * Timing helpers
 */
static double timespec_diff_us(const struct timespec *start,
                               const struct timespec *end)
{
    double s  = (double)(end->tv_sec  - start->tv_sec)  * 1000000.0;
    double ns = (double)(end->tv_nsec - start->tv_nsec) / 1000.0;
    return s + ns;
}

static int compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return  1;
    return 0;
}

/*
 * Statistics from a sorted array of latencies (microseconds).
 */
typedef struct {
    const char *name;
    int    count;
    double min_us;
    double avg_us;
    double p95_us;
    double p99_us;
    double max_us;
} bench_stats_t;

static bench_stats_t compute_stats(const char *name, double *lat,
                                   int count)
{
    bench_stats_t s;
    s.name   = name;
    s.count  = count;

    qsort(lat, (size_t)count, sizeof(double), compare_double);

    s.min_us = lat[0];
    s.max_us = lat[count - 1];
    s.p95_us = lat[(int)((double)(count - 1) * 0.95)];
    s.p99_us = lat[(int)((double)(count - 1) * 0.99)];

    double sum = 0.0;
    for (int i = 0; i < count; i++)
        sum += lat[i];
    s.avg_us = sum / (double)count;

    return s;
}

static void print_header(void)
{
    printf("%-30s %7s %10s %10s %10s %10s %10s  %s\n",
           "Operation", "Count", "Min(us)", "Avg(us)",
           "P95(us)", "P99(us)", "Max(us)", "FR-006");
    printf("%-30s %7s %10s %10s %10s %10s %10s  %s\n",
           "------------------------------", "-------",
           "----------", "----------", "----------",
           "----------", "----------", "------");
}

static void print_stats(const bench_stats_t *s)
{
    const char *verdict = (s->p99_us < FR006_DEADLINE_US) ? "PASS" : "WARN";
    printf("%-30s %7d %10.2f %10.2f %10.2f %10.2f %10.2f  %s\n",
           s->name, s->count, s->min_us, s->avg_us,
           s->p95_us, s->p99_us, s->max_us, verdict);
}

/*
 * Benchmark 1: GOOSE BER encode latency
 */
static bench_stats_t bench_goose_encode(void)
{
    static double latencies[GOOSE_SV_ITERATIONS];
    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    goose_apdu_t apdu;
    size_t encoded;
    struct timespec t0, t1;

    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    goose_set_goid(&apdu, "GOOSE1");
    apdu.stNum = 1;
    apdu.confRev = 1;
    apdu.timeAllowedtoLive = 2000;
    goose_add_boolean(&apdu, true);
    goose_add_int32(&apdu, 42);
    goose_add_float32(&apdu, 3.14f);
    uint8_t quality[] = {0x00, 0x00, 0x00, 0x00};
    goose_add_bitstring(&apdu, quality, sizeof(quality));

    for (int i = 0; i < GOOSE_SV_ITERATIONS; i++) {
        apdu.sqNum = (uint32_t)i;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        latencies[i] = timespec_diff_us(&t0, &t1);
    }

    return compute_stats("GOOSE BER encode", latencies,
                         GOOSE_SV_ITERATIONS);
}

/*
 * Benchmark 2: GOOSE BER decode latency
 */
static bench_stats_t bench_goose_decode(void)
{
    static double latencies[GOOSE_SV_ITERATIONS];
    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    goose_apdu_t apdu;
    size_t encoded;
    struct timespec t0, t1;

    /* Encode a reference frame */
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    goose_set_goid(&apdu, "GOOSE1");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    apdu.confRev = 1;
    apdu.timeAllowedtoLive = 2000;
    goose_add_boolean(&apdu, true);
    goose_add_int32(&apdu, 42);
    goose_add_float32(&apdu, 3.14f);
    uint8_t quality[] = {0x00, 0x00, 0x00, 0x00};
    goose_add_bitstring(&apdu, quality, sizeof(quality));
    goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded);

    for (int i = 0; i < GOOSE_SV_ITERATIONS; i++) {
        goose_apdu_t decoded;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        goose_decode_apdu(buf, encoded, &decoded);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        latencies[i] = timespec_diff_us(&t0, &t1);
    }

    return compute_stats("GOOSE BER decode", latencies,
                         GOOSE_SV_ITERATIONS);
}

/*
 * Benchmark 3: SV BER encode latency (4-channel)
 */
static bench_stats_t bench_sv_encode(void)
{
    static double latencies[GOOSE_SV_ITERATIONS];
    uint8_t buf[SV_MAX_APDU_SIZE];
    sv_apdu_t apdu;
    size_t encoded;
    struct timespec t0, t1;

    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_asdu_init(&apdu.asdu[0]);
    sv_set_svid(&apdu.asdu[0], "MU01");
    apdu.asdu[0].confRev = 1;
    apdu.asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;

    sv_quality_t good_q = {0};
    sv_add_sample(&apdu.asdu[0], 1000,  good_q);
    sv_add_sample(&apdu.asdu[0], -500,  good_q);
    sv_add_sample(&apdu.asdu[0], 750,   good_q);
    sv_add_sample(&apdu.asdu[0], -1200, good_q);

    for (int i = 0; i < GOOSE_SV_ITERATIONS; i++) {
        apdu.asdu[0].smpCnt = (uint16_t)(i & 0xFFFF);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        latencies[i] = timespec_diff_us(&t0, &t1);
    }

    return compute_stats("SV BER encode (4-ch)", latencies,
                         GOOSE_SV_ITERATIONS);
}

/*
 * Benchmark 4: SV BER decode latency
 */
static bench_stats_t bench_sv_decode(void)
{
    static double latencies[GOOSE_SV_ITERATIONS];
    uint8_t buf[SV_MAX_APDU_SIZE];
    sv_apdu_t apdu;
    size_t encoded;
    struct timespec t0, t1;

    /* Encode a reference frame */
    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_asdu_init(&apdu.asdu[0]);
    sv_set_svid(&apdu.asdu[0], "MU01");
    apdu.asdu[0].smpCnt = 0;
    apdu.asdu[0].confRev = 1;
    apdu.asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;

    sv_quality_t good_q = {0};
    sv_add_sample(&apdu.asdu[0], 1000,  good_q);
    sv_add_sample(&apdu.asdu[0], -500,  good_q);
    sv_add_sample(&apdu.asdu[0], 750,   good_q);
    sv_add_sample(&apdu.asdu[0], -1200, good_q);
    sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded);

    for (int i = 0; i < GOOSE_SV_ITERATIONS; i++) {
        sv_apdu_t decoded;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        sv_decode_apdu(buf, encoded, &decoded);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        latencies[i] = timespec_diff_us(&t0, &t1);
    }

    return compute_stats("SV BER decode (4-ch)", latencies,
                         GOOSE_SV_ITERATIONS);
}

/*
 * Benchmark 5: MMS request-response roundtrip
 *
 * Starts an MMS server on localhost, connects a client, and
 * loops Read requests to measure end-to-end latency.
 */

/* Server thread entry point */
static void *mms_server_thread(void *arg)
{
    iec61850_mms_server_t *server = (iec61850_mms_server_t *)arg;
    iec61850_mms_server_start(server);
    return NULL;
}

static bench_stats_t bench_mms_roundtrip(void)
{
    static double latencies[MMS_ITERATIONS];
    bench_stats_t stats;

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    /* Create a domain and variable for reads */
    iec61850_mms_ds_create_domain(&ds, "TestLD");
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;
    iec61850_mms_ds_create_variable(&ds, "TestLD", "LLN0$ST$Health$stVal",
                                    MMS_TYPE_INTEGER, &val);

    /* Configure and start server */
    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = MMS_BENCH_PORT;

    iec61850_mms_server_t server;
    iec61850_mms_server_init(&server, &cfg, &ds);

    pthread_t srv_tid;
    if (pthread_create(&srv_tid, NULL, mms_server_thread, &server) != 0) {
        fprintf(stderr, "MMS benchmark: failed to create server thread\n");
        stats.name  = "MMS Read roundtrip";
        stats.count = 0;
        stats.min_us = stats.avg_us = stats.p95_us = stats.p99_us = 0.0;
        stats.max_us = 0.0;
        iec61850_mms_ds_destroy(&ds);
        return stats;
    }

    /* Wait for server to start accepting */
    for (int i = 0; i < 100; i++) {
        if (iec61850_mms_server_is_running(&server))
            break;
        usleep(10000); /* 10 ms */
    }

    if (!iec61850_mms_server_is_running(&server)) {
        fprintf(stderr, "MMS benchmark: server did not start\n");
        stats.name  = "MMS Read roundtrip";
        stats.count = 0;
        stats.min_us = stats.avg_us = stats.p95_us = stats.p99_us = 0.0;
        stats.max_us = 0.0;
        iec61850_mms_server_stop(&server);
        pthread_join(srv_tid, NULL);
        iec61850_mms_ds_destroy(&ds);
        return stats;
    }

    /* Connect client */
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int rc = iec61850_mms_client_connect(&client, "127.0.0.1",
                                         MMS_BENCH_PORT, 5000);
    if (rc != 0) {
        fprintf(stderr, "MMS benchmark: client connect failed (%d)\n", rc);
        stats.name  = "MMS Read roundtrip";
        stats.count = 0;
        stats.min_us = stats.avg_us = stats.p95_us = stats.p99_us = 0.0;
        stats.max_us = 0.0;
        iec61850_mms_server_stop(&server);
        pthread_join(srv_tid, NULL);
        iec61850_mms_ds_destroy(&ds);
        return stats;
    }

    /* Benchmark read roundtrips */
    struct timespec t0, t1;
    for (int i = 0; i < MMS_ITERATIONS; i++) {
        mms_value_t read_val;
        memset(&read_val, 0, sizeof(read_val));
        clock_gettime(CLOCK_MONOTONIC, &t0);
        iec61850_mms_client_read(&client, "TestLD",
                                 "LLN0$ST$Health$stVal", &read_val);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        latencies[i] = timespec_diff_us(&t0, &t1);
    }

    stats = compute_stats("MMS Read roundtrip", latencies, MMS_ITERATIONS);

    /* Cleanup */
    iec61850_mms_client_disconnect(&client);
    iec61850_mms_server_stop(&server);
    pthread_join(srv_tid, NULL);
    iec61850_mms_ds_destroy(&ds);

    return stats;
}

/*
 * Main
 */
int main(void)
{
    bench_stats_t results[5];

    printf("\n=== IEC 61850 Performance Benchmark ===\n");
    printf("FR-006 deadline: %.0f us (4 ms)\n\n", FR006_DEADLINE_US);

    /* BER codec benchmarks */
    results[0] = bench_goose_encode();
    results[1] = bench_goose_decode();
    results[2] = bench_sv_encode();
    results[3] = bench_sv_decode();

    /* MMS roundtrip benchmark */
    results[4] = bench_mms_roundtrip();

    /* Print results table */
    print_header();
    for (int i = 0; i < 5; i++)
        print_stats(&results[i]);

    printf("\n");

    /* Always return 0 -- benchmark, not assertion-based */
    return 0;
}
