/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Per-Subscriber Latency Statistics Implementation
 *
 * Tracks min/max/avg/p99 latency with histogram buckets.
 */

#include "monitoring/latency_stats.h"
#include <string.h>

void iec61850_latency_stats_init(iec61850_latency_stats_t *stats,
                                   uint32_t bucket_width_us)
{
    if (stats == NULL) { return; }
    (void)memset(stats, 0, sizeof(*stats));
    stats->min_us = UINT64_MAX;

    if (bucket_width_us > 0) {
        stats->bucket_width_us = bucket_width_us;
    } else {
        /* Auto: distribute IEC61850_LATENCY_MAX_US across buckets */
        stats->bucket_width_us =
            (uint32_t)(IEC61850_LATENCY_MAX_US / IEC61850_LATENCY_HIST_BUCKETS);
    }
}

void iec61850_latency_stats_record(iec61850_latency_stats_t *stats,
                                     uint64_t latency_us)
{
    uint32_t bucket;

    if (stats == NULL) { return; }

    stats->count++;
    stats->sum_us += latency_us;

    if (latency_us < stats->min_us) {
        stats->min_us = latency_us;
    }
    if (latency_us > stats->max_us) {
        stats->max_us = latency_us;
    }

    /* Histogram bucket */
    if (stats->bucket_width_us > 0) {
        bucket = (uint32_t)(latency_us / stats->bucket_width_us);
        if (bucket >= IEC61850_LATENCY_HIST_BUCKETS) {
            bucket = IEC61850_LATENCY_HIST_BUCKETS - 1;
        }
        stats->histogram[bucket]++;
    }
}

uint64_t iec61850_latency_compute_us(uint64_t send_time_ns,
                                       uint64_t recv_time_ns)
{
    if (recv_time_ns <= send_time_ns) {
        return 0;
    }
    return (recv_time_ns - send_time_ns) / 1000ULL;
}

void iec61850_latency_stats_get_summary(const iec61850_latency_stats_t *stats,
                                          iec61850_latency_summary_t *summary)
{
    if (stats == NULL || summary == NULL) { return; }
    (void)memset(summary, 0, sizeof(*summary));

    summary->count = stats->count;

    if (stats->count == 0) {
        return;
    }

    summary->min_us = stats->min_us;
    summary->max_us = stats->max_us;
    summary->avg_us = stats->sum_us / stats->count;

    /* Compute p99 from histogram */
    uint64_t p99_threshold = (stats->count * 99ULL + 99ULL) / 100ULL;
    uint64_t cumulative = 0;

    for (uint32_t i = 0; i < IEC61850_LATENCY_HIST_BUCKETS; i++) {
        cumulative += stats->histogram[i];
        if (cumulative >= p99_threshold) {
            /* p99 is at the upper edge of this bucket */
            summary->p99_us =
                (uint64_t)(i + 1U) * (uint64_t)stats->bucket_width_us;
            return;
        }
    }

    /* If we get here, p99 is beyond the last bucket */
    summary->p99_us = stats->max_us;
}

void iec61850_latency_stats_reset(iec61850_latency_stats_t *stats)
{
    uint32_t bucket_width;

    if (stats == NULL) { return; }

    bucket_width = stats->bucket_width_us;
    (void)memset(stats, 0, sizeof(*stats));
    stats->min_us = UINT64_MAX;
    stats->bucket_width_us = bucket_width;
}
