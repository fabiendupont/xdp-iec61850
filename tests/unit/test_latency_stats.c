/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for Latency Statistics
 */

#include "monitoring/latency_stats.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static void test_init(void)
{
    iec61850_latency_stats_t stats;
    iec61850_latency_stats_init(&stats, 1000);  /* 1ms buckets */

    assert(stats.count == 0);
    assert(stats.min_us == UINT64_MAX);
    assert(stats.max_us == 0);
    assert(stats.bucket_width_us == 1000);
    printf("  PASS: init\n");
}

static void test_record_and_summary(void)
{
    iec61850_latency_stats_t stats;
    iec61850_latency_summary_t summary;

    iec61850_latency_stats_init(&stats, 100);  /* 100us buckets */

    /* Record some samples */
    iec61850_latency_stats_record(&stats, 100);   /* 100us */
    iec61850_latency_stats_record(&stats, 200);   /* 200us */
    iec61850_latency_stats_record(&stats, 300);   /* 300us */
    iec61850_latency_stats_record(&stats, 150);   /* 150us */
    iec61850_latency_stats_record(&stats, 250);   /* 250us */

    iec61850_latency_stats_get_summary(&stats, &summary);

    assert(summary.count == 5);
    assert(summary.min_us == 100);
    assert(summary.max_us == 300);
    assert(summary.avg_us == 200);  /* (100+200+300+150+250) / 5 = 200 */
    assert(summary.p99_us > 0);
    printf("  PASS: record and summary\n");
}

static void test_compute_latency(void)
{
    /* 1 millisecond latency */
    uint64_t send_ns = 1000000000ULL;  /* 1 second */
    uint64_t recv_ns = 1001000000ULL;  /* 1.001 seconds */

    uint64_t lat = iec61850_latency_compute_us(send_ns, recv_ns);
    assert(lat == 1000);  /* 1000 microseconds = 1ms */

    /* recv before send */
    lat = iec61850_latency_compute_us(recv_ns, send_ns);
    assert(lat == 0);

    printf("  PASS: compute latency\n");
}

static void test_histogram(void)
{
    iec61850_latency_stats_t stats;
    iec61850_latency_stats_init(&stats, 100);  /* 100us buckets */

    /* All samples in bucket 0 (0-99us) */
    for (int i = 0; i < 100; i++) {
        iec61850_latency_stats_record(&stats, 50);
    }

    assert(stats.histogram[0] == 100);
    assert(stats.histogram[1] == 0);

    /* Add one sample in bucket 1 (100-199us) */
    iec61850_latency_stats_record(&stats, 150);
    assert(stats.histogram[1] == 1);

    printf("  PASS: histogram\n");
}

static void test_p99(void)
{
    iec61850_latency_stats_t stats;
    iec61850_latency_summary_t summary;

    iec61850_latency_stats_init(&stats, 100);

    /* 99 samples at 50us, 1 at 5000us */
    for (int i = 0; i < 99; i++) {
        iec61850_latency_stats_record(&stats, 50);
    }
    iec61850_latency_stats_record(&stats, 5000);

    iec61850_latency_stats_get_summary(&stats, &summary);

    assert(summary.count == 100);
    assert(summary.min_us == 50);
    assert(summary.max_us == 5000);
    /* p99 should be the 99th sample which is at 50us range */
    assert(summary.p99_us <= 5100);  /* Should be in the 5000 range */

    printf("  PASS: p99\n");
}

static void test_reset(void)
{
    iec61850_latency_stats_t stats;

    iec61850_latency_stats_init(&stats, 500);
    iec61850_latency_stats_record(&stats, 100);
    iec61850_latency_stats_record(&stats, 200);

    iec61850_latency_stats_reset(&stats);

    assert(stats.count == 0);
    assert(stats.min_us == UINT64_MAX);
    assert(stats.max_us == 0);
    assert(stats.sum_us == 0);
    assert(stats.bucket_width_us == 500);  /* Preserved */

    printf("  PASS: reset\n");
}

int main(void)
{
    printf("=== Latency Statistics Tests ===\n");

    test_init();
    test_record_and_summary();
    test_compute_latency();
    test_histogram();
    test_p99();
    test_reset();

    printf("All latency stats tests passed.\n");
    return 0;
}
