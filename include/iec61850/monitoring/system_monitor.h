/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * System Monitor and Metrics Exporter for IEC 61850
 *
 * Tracks system health, aggregates statistics from GOOSE/SV/MMS,
 * and exports metrics in JSON format.
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_SYSTEM_MONITOR_H
#define IEC61850_SYSTEM_MONITOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* System health status */
typedef enum {
    IEC61850_HEALTH_HEALTHY  = 0,
    IEC61850_HEALTH_WARNING  = 1,
    IEC61850_HEALTH_DEGRADED = 2,
    IEC61850_HEALTH_CRITICAL = 3
} iec61850_health_status_t;

/* Memory pool statistics (generic, not DPDK-specific) */
typedef struct {
    uint64_t total_capacity;
    uint64_t available;
    uint64_t in_use;
    float usage_percent;
} iec61850_mempool_stats_t;

/* Aggregate system health */
typedef struct {
    iec61850_health_status_t status;

    /* Component health */
    bool memory_healthy;
    bool publisher_healthy;
    bool subscriber_healthy;

    /* Memory */
    iec61850_mempool_stats_t mempool;

    /* Publisher counters */
    uint64_t pub_total_sent;
    uint64_t pub_total_errors;

    /* Subscriber counters */
    uint64_t sub_total_received;
    uint64_t sub_total_duplicates;
    uint64_t sub_total_timeouts;

    /* Error rates (per second, over last window) */
    float tx_error_rate;
    float rx_error_rate;
} iec61850_system_health_t;

/* System monitor */
typedef struct {
    /* Memory stats (set externally) */
    iec61850_mempool_stats_t mempool;

    /* Publisher stats (updated externally) */
    uint64_t pub_sent;
    uint64_t pub_errors;

    /* Subscriber stats (updated externally) */
    uint64_t sub_received;
    uint64_t sub_duplicates;
    uint64_t sub_timeouts;

    /* Rate calculation baseline */
    uint64_t last_check_time_ns;
    uint64_t last_pub_errors;
    uint64_t last_sub_timeouts;
} iec61850_system_monitor_t;

/**
 * Initialize system monitor.
 */
void iec61850_monitor_init(iec61850_system_monitor_t *mon);

/**
 * Update memory pool statistics.
 */
void iec61850_monitor_set_mempool(iec61850_system_monitor_t *mon,
                                   uint64_t total, uint64_t available);

/**
 * Update publisher statistics.
 */
void iec61850_monitor_update_pub(iec61850_system_monitor_t *mon,
                                  uint64_t total_sent, uint64_t total_errors);

/**
 * Update subscriber statistics.
 */
void iec61850_monitor_update_sub(iec61850_system_monitor_t *mon,
                                  uint64_t total_received,
                                  uint64_t total_duplicates,
                                  uint64_t total_timeouts);

/**
 * Get current system health assessment.
 */
iec61850_system_health_t iec61850_monitor_get_health(
    iec61850_system_monitor_t *mon);

/**
 * Get health status as string.
 */
const char *iec61850_health_status_to_string(iec61850_health_status_t status);

/* ========================================================================
 * Metrics Exporter
 * ======================================================================== */

/**
 * Export system health as JSON into buffer.
 *
 * @param health  Health data
 * @param buf     Output buffer
 * @param buf_size Buffer size
 * @return Number of bytes written (excluding nul), or -1 on error
 */
int iec61850_metrics_to_json(const iec61850_system_health_t *health,
                              char *buf, size_t buf_size);

/**
 * Export as CSV row.
 * Format: timestamp,status,memory_pct,pub_sent,pub_errors,sub_received,sub_timeouts
 */
int iec61850_metrics_to_csv(const iec61850_system_health_t *health,
                             char *buf, size_t buf_size);

/**
 * Get CSV header.
 */
int iec61850_metrics_csv_header(char *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_SYSTEM_MONITOR_H */
