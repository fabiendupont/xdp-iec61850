/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * HSR/PRP Redundancy Wrapper for IEC 61850
 *
 * Wraps the xdp-hsr-prp library to provide seamless HSR/PRP redundancy
 * for GOOSE and SV traffic.  When compiled without xdp-hsr-prp (i.e.
 * enable_hsr_prp=false), all functions return -ENOTSUP.
 */

#ifndef IEC61850_HSR_PRP_WRAPPER_H
#define IEC61850_HSR_PRP_WRAPPER_H

#include <stdint.h>
#include <stdbool.h>

/* Maximum interface name length (POSIX IFNAMSIZ) */
#define IEC61850_HSR_PRP_IFNAMSIZ 16

/*
 * Redundancy mode.
 */
enum iec61850_hsr_prp_mode {
    IEC61850_HSR_PRP_MODE_HSR = 0,
    IEC61850_HSR_PRP_MODE_PRP = 1,
};

/*
 * Configuration for HSR/PRP redundancy.
 */
typedef struct iec61850_hsr_prp_config {
    enum iec61850_hsr_prp_mode mode;
    char port_a[IEC61850_HSR_PRP_IFNAMSIZ];
    char port_b[IEC61850_HSR_PRP_IFNAMSIZ];
    uint32_t supervision_interval_ms;  /* default: 2000 */
    uint32_t node_timeout_ms;          /* default: 60000 */
} iec61850_hsr_prp_config_t;

/*
 * Statistics from the HSR/PRP subsystem.
 */
typedef struct iec61850_hsr_prp_stats {
    uint64_t rx_count;
    uint64_t rx_bytes;
    uint64_t tx_count;
    uint64_t tx_bytes;
    uint64_t dup_drops;
    uint64_t errors;
} iec61850_hsr_prp_stats_t;

/*
 * Initialize config with defaults.
 * Returns 0 on success, negative errno on error.
 */
int iec61850_hsr_prp_config_init(iec61850_hsr_prp_config_t *cfg,
                                 enum iec61850_hsr_prp_mode mode,
                                 const char *port_a,
                                 const char *port_b);

/*
 * Validate configuration (non-empty port names, etc.).
 * Returns 0 on success, negative errno on error.
 */
int iec61850_hsr_prp_config_validate(const iec61850_hsr_prp_config_t *cfg);

/*
 * Initialize the HSR/PRP subsystem with the given config.
 * Returns 0 on success, -ENOTSUP if xdp-hsr-prp not available,
 * negative errno on other errors.
 */
int iec61850_hsr_prp_init(const iec61850_hsr_prp_config_t *cfg);

/*
 * Attach BPF programs and start redundancy processing.
 * Returns 0 on success, negative errno on error.
 */
int iec61850_hsr_prp_start(void);

/*
 * Stop redundancy processing and detach BPF programs.
 */
void iec61850_hsr_prp_stop(void);

/*
 * Query duplicate-drop and traffic statistics.
 * Returns 0 on success, negative errno on error.
 */
int iec61850_hsr_prp_get_stats(iec61850_hsr_prp_stats_t *stats);

/*
 * Returns true if HSR/PRP support was compiled in.
 */
bool iec61850_hsr_prp_available(void);

#endif /* IEC61850_HSR_PRP_WRAPPER_H */
