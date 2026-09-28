/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * System Monitor and Metrics Exporter Implementation
 *
 * License: BSD-3-Clause
 */


#include "monitoring/system_monitor.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t get_time_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void iec61850_monitor_init(iec61850_system_monitor_t *mon)
{
    if (mon == NULL) { return; }
    (void)memset(mon, 0, sizeof(*mon));
    mon->last_check_time_ns = get_time_ns();
}

void iec61850_monitor_set_mempool(iec61850_system_monitor_t *mon,
                                   uint64_t total, uint64_t available)
{
    if (mon == NULL) { return; }
    mon->mempool.total_capacity = total;
    mon->mempool.available = available;
    mon->mempool.in_use = (total > available) ? (total - available) : 0;
    mon->mempool.usage_percent = (total > 0)
        ? ((float)mon->mempool.in_use / (float)total) * 100.0f
        : 0.0f;
}

void iec61850_monitor_update_pub(iec61850_system_monitor_t *mon,
                                  const iec61850_pub_stats_t *stats)
{
    if (mon == NULL || stats == NULL) { return; }
    mon->pub_sent = stats->sent;
    mon->pub_errors = stats->errors;
}

void iec61850_monitor_update_sub(iec61850_system_monitor_t *mon,
                                  const iec61850_sub_stats_t *stats)
{
    if (mon == NULL || stats == NULL) { return; }
    mon->sub_received = stats->received;
    mon->sub_duplicates = stats->duplicates;
    mon->sub_timeouts = stats->timeouts;
}

iec61850_system_health_t iec61850_monitor_get_health(
    iec61850_system_monitor_t *mon)
{
    iec61850_system_health_t h;
    uint64_t now;
    double elapsed_sec;

    (void)memset(&h, 0, sizeof(h));

    if (mon == NULL) {
        h.status = IEC61850_HEALTH_CRITICAL;
        return h;
    }

    /* Copy current stats */
    h.mempool = mon->mempool;
    h.pub_total_sent = mon->pub_sent;
    h.pub_total_errors = mon->pub_errors;
    h.sub_total_received = mon->sub_received;
    h.sub_total_duplicates = mon->sub_duplicates;
    h.sub_total_timeouts = mon->sub_timeouts;

    /* Calculate error rates */
    now = get_time_ns();
    elapsed_sec = (double)(now - mon->last_check_time_ns) / 1e9;
    if (elapsed_sec > 0.001) {
        uint64_t new_pub_errors = mon->pub_errors - mon->last_pub_errors;
        uint64_t new_sub_timeouts = mon->sub_timeouts - mon->last_sub_timeouts;

        h.tx_error_rate = (float)((double)new_pub_errors / elapsed_sec);
        h.rx_error_rate = (float)((double)new_sub_timeouts / elapsed_sec);

        mon->last_check_time_ns = now;
        mon->last_pub_errors = mon->pub_errors;
        mon->last_sub_timeouts = mon->sub_timeouts;
    }

    /* Component health */
    h.memory_healthy = (h.mempool.usage_percent <= 80.0f);
    h.publisher_healthy = (h.tx_error_rate < 1.0f);
    h.subscriber_healthy = (h.rx_error_rate < 1.0f);

    /* Overall assessment */
    if (!h.memory_healthy) {
        h.status = IEC61850_HEALTH_CRITICAL;
    } else if (!h.publisher_healthy || !h.subscriber_healthy) {
        h.status = IEC61850_HEALTH_DEGRADED;
    } else if (h.mempool.usage_percent > 60.0f ||
               h.pub_total_errors > 0 || h.sub_total_timeouts > 0) {
        h.status = IEC61850_HEALTH_WARNING;
    } else {
        h.status = IEC61850_HEALTH_HEALTHY;
    }

    return h;
}

const char *iec61850_health_status_to_string(iec61850_health_status_t status)
{
    switch (status) {
        case IEC61850_HEALTH_HEALTHY:  return "HEALTHY";
        case IEC61850_HEALTH_WARNING:  return "WARNING";
        case IEC61850_HEALTH_DEGRADED: return "DEGRADED";
        case IEC61850_HEALTH_CRITICAL: return "CRITICAL";
        default:                       return "UNKNOWN";
    }
}

/* ========================================================================
 * Metrics Exporter
 * ======================================================================== */

int iec61850_metrics_to_json(const iec61850_system_health_t *health,
                              char *buf, size_t buf_size)
{
    if (health == NULL || buf == NULL || buf_size < 64) {
        return -1;
    }

    int n = snprintf(buf, buf_size,
        "{\n"
        "  \"status\": \"%s\",\n"
        "  \"memory\": {\n"
        "    \"total\": %llu,\n"
        "    \"available\": %llu,\n"
        "    \"in_use\": %llu,\n"
        "    \"usage_percent\": %.1f\n"
        "  },\n"
        "  \"publisher\": {\n"
        "    \"total_sent\": %llu,\n"
        "    \"total_errors\": %llu,\n"
        "    \"error_rate\": %.3f\n"
        "  },\n"
        "  \"subscriber\": {\n"
        "    \"total_received\": %llu,\n"
        "    \"total_duplicates\": %llu,\n"
        "    \"total_timeouts\": %llu,\n"
        "    \"timeout_rate\": %.3f\n"
        "  }\n"
        "}",
        iec61850_health_status_to_string(health->status),
        (unsigned long long)health->mempool.total_capacity,
        (unsigned long long)health->mempool.available,
        (unsigned long long)health->mempool.in_use,
        (double)health->mempool.usage_percent,
        (unsigned long long)health->pub_total_sent,
        (unsigned long long)health->pub_total_errors,
        (double)health->tx_error_rate,
        (unsigned long long)health->sub_total_received,
        (unsigned long long)health->sub_total_duplicates,
        (unsigned long long)health->sub_total_timeouts,
        (double)health->rx_error_rate);

    return (n >= 0 && (size_t)n < buf_size) ? n : -1;
}

int iec61850_metrics_to_csv(const iec61850_system_health_t *health,
                             char *buf, size_t buf_size)
{
    if (health == NULL || buf == NULL) { return -1; }

    struct timespec ts;
    (void)clock_gettime(CLOCK_REALTIME, &ts);

    int n = snprintf(buf, buf_size,
        "%lld,%s,%.1f,%llu,%llu,%llu,%llu",
        (long long)ts.tv_sec,
        iec61850_health_status_to_string(health->status),
        (double)health->mempool.usage_percent,
        (unsigned long long)health->pub_total_sent,
        (unsigned long long)health->pub_total_errors,
        (unsigned long long)health->sub_total_received,
        (unsigned long long)health->sub_total_timeouts);

    return (n >= 0 && (size_t)n < buf_size) ? n : -1;
}

int iec61850_metrics_csv_header(char *buf, size_t buf_size)
{
    if (buf == NULL) { return -1; }

    int n = snprintf(buf, buf_size,
        "timestamp,status,memory_pct,pub_sent,pub_errors,sub_received,sub_timeouts");

    return (n >= 0 && (size_t)n < buf_size) ? n : -1;
}
