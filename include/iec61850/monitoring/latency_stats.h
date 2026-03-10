/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Per-Subscriber Latency Statistics for IEC 61850
 *
 * Tracks end-to-end latency (send timestamp to receive timestamp)
 * with min/max/avg/p99 computation.
 */

#ifndef IEC61850_LATENCY_STATS_H
#define IEC61850_LATENCY_STATS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Histogram configuration */
#define IEC61850_LATENCY_HIST_BUCKETS  64
#define IEC61850_LATENCY_MAX_US    1000000  /* 1 second max tracked */

/* Latency statistics */
typedef struct {
    uint64_t count;          /* Total samples */
    uint64_t sum_us;         /* Sum of latencies (microseconds) */
    uint64_t min_us;         /* Minimum latency */
    uint64_t max_us;         /* Maximum latency */
    uint64_t histogram[IEC61850_LATENCY_HIST_BUCKETS];
    uint32_t bucket_width_us;  /* Width of each histogram bucket */
} iec61850_latency_stats_t;

/* Latency snapshot for reporting */
typedef struct {
    uint64_t count;
    uint64_t min_us;
    uint64_t max_us;
    uint64_t avg_us;
    uint64_t p99_us;
} iec61850_latency_summary_t;

/**
 * Initialize latency statistics.
 *
 * @param stats            Latency stats
 * @param bucket_width_us  Width of each histogram bucket in microseconds
 *                         (0 = auto: 1000000 / BUCKETS = ~15625 us)
 */
void iec61850_latency_stats_init(iec61850_latency_stats_t *stats,
                                   uint32_t bucket_width_us);

/**
 * Record a latency sample.
 *
 * @param stats      Latency stats
 * @param latency_us Latency in microseconds
 */
void iec61850_latency_stats_record(iec61850_latency_stats_t *stats,
                                     uint64_t latency_us);

/**
 * Compute latency from send and receive timestamps.
 * Both timestamps must be in the same epoch (e.g., both nanoseconds
 * since CLOCK_REALTIME epoch).
 *
 * @param send_time_ns  Send timestamp (nanoseconds)
 * @param recv_time_ns  Receive timestamp (nanoseconds)
 * @return Latency in microseconds (0 if recv < send)
 */
uint64_t iec61850_latency_compute_us(uint64_t send_time_ns,
                                       uint64_t recv_time_ns);

/**
 * Get latency summary (min/max/avg/p99).
 */
void iec61850_latency_stats_get_summary(const iec61850_latency_stats_t *stats,
                                          iec61850_latency_summary_t *summary);

/**
 * Reset latency statistics.
 */
void iec61850_latency_stats_reset(iec61850_latency_stats_t *stats);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_LATENCY_STATS_H */
