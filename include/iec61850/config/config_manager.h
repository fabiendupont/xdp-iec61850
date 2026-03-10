/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Configuration Management for IEC 61850
 *
 * Provides:
 * - Application config structures (iec61850_app_config_t)
 * - CLI argument parsing (iec61850_cli_parse)
 * - Config manager with YAML + CLI merge (iec61850_config_manager_load)
 * - Utility parsers (core list, PCI list)
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_CONFIG_MANAGER_H
#define IEC61850_CONFIG_MANAGER_H

#include "logging/logger.h"  /* iec61850_log_level_t */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define IEC61850_MAX_CORES          32
#define IEC61850_MAX_PCI_DEVICES    8
#define IEC61850_PCI_ADDR_LEN       64
#define IEC61850_MAX_CONTROL_BLOCKS 16
#define IEC61850_MAX_PATH_LEN       256

/* ========================================================================
 * Configuration Structures
 * ======================================================================== */

typedef struct {
    char file[IEC61850_MAX_PATH_LEN];
    char ied_name[IEC61850_MAX_PATH_LEN];
    char control_blocks[IEC61850_MAX_CONTROL_BLOCKS][IEC61850_MAX_PATH_LEN];
    size_t control_blocks_count;
} iec61850_scl_config_t;

typedef struct {
    unsigned cores[IEC61850_MAX_CORES];
    size_t cores_count;
    unsigned memory_mb;
    char pci_devices[IEC61850_MAX_PCI_DEVICES][IEC61850_PCI_ADDR_LEN];
    size_t pci_devices_count;
    bool no_huge;
    char file_prefix[64];
} iec61850_dpdk_config_t;

typedef struct {
    iec61850_log_level_t level;
    char output[IEC61850_MAX_PATH_LEN];
    bool use_syslog;
} iec61850_logging_config_t;

typedef struct {
    bool enabled;
    unsigned export_interval_sec;
    char output[IEC61850_MAX_PATH_LEN];
} iec61850_metrics_config_t;

typedef struct {
    bool enabled;
    char private_key[IEC61850_MAX_PATH_LEN];
    char certificate[IEC61850_MAX_PATH_LEN];
    char trusted_certs[IEC61850_MAX_PATH_LEN];
} iec61850_security_config_t;

typedef struct {
    char gocbref[130];
    uint16_t appid;
    uint16_t vlan;
} iec61850_subscriber_filter_config_t;

typedef struct {
    iec61850_scl_config_t scl;
    iec61850_dpdk_config_t dpdk;
    iec61850_logging_config_t logging;
    iec61850_metrics_config_t metrics;
    iec61850_security_config_t security;
    iec61850_subscriber_filter_config_t subscriber_filter;
} iec61850_app_config_t;

/* ========================================================================
 * Config Lifecycle
 * ======================================================================== */

/**
 * Initialize config with default values.
 */
void iec61850_app_config_init(iec61850_app_config_t *cfg);

/**
 * Free config resources (no-op for fixed-size fields, provided for symmetry).
 */
void iec61850_app_config_free(iec61850_app_config_t *cfg);

/* ========================================================================
 * Utility Parsers
 * ======================================================================== */

/**
 * Parse comma-separated core list (e.g., "2,3,4" or "2-4").
 *
 * @param str       Input string
 * @param cores     Output array
 * @param max_cores Maximum number of cores
 * @param count     Output: number of cores parsed
 * @return 0 on success, -1 on error
 */
int iec61850_parse_core_list(const char *str, unsigned *cores,
                              size_t max_cores, size_t *count);

/**
 * Parse comma-separated PCI device list.
 *
 * @param str         Input string
 * @param pci         Output array of PCI address strings
 * @param max_devices Maximum number of devices
 * @param count       Output: number of devices parsed
 * @return 0 on success, -1 on error
 */
int iec61850_parse_pci_list(const char *str,
                             char pci[][IEC61850_PCI_ADDR_LEN],
                             size_t max_devices, size_t *count);

/* ========================================================================
 * CLI Parser
 * ======================================================================== */

/**
 * Parse command-line arguments into config.
 * Only sets fields that are explicitly provided on the CLI.
 *
 * @param argc  Argument count
 * @param argv  Argument values
 * @param cfg   Config to populate (should be initialized first)
 * @return 0 on success, 1 if --help/--version requested, -1 on error
 */
int iec61850_cli_parse(int argc, char *argv[], iec61850_app_config_t *cfg);

/**
 * Get the config file path from the last CLI parse (--config argument).
 * Returns NULL if no config file was specified.
 */
const char *iec61850_cli_get_config_file(void);

/* ========================================================================
 * Config Manager
 * ======================================================================== */

/**
 * Load configuration with precedence: CLI > YAML > defaults.
 *
 * 1. Initialize defaults
 * 2. If --config is provided, load YAML
 * 3. Apply CLI overrides
 *
 * @param argc  CLI argument count
 * @param argv  CLI argument values
 * @param cfg   Output config (initialized by this function)
 * @return 0 on success, 1 if --help/--version requested, -1 on error
 */
int iec61850_config_manager_load(int argc, char *argv[],
                                  iec61850_app_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_CONFIG_MANAGER_H */
