/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Configuration Manager Implementation
 *
 * Handles: defaults, YAML loading, CLI parsing, and precedence merge.
 *
 * License: BSD-3-Clause
 */

#include "config/config_manager.h"
#include "config/yaml_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================
 * Config Lifecycle
 * ======================================================================== */

void iec61850_app_config_init(iec61850_app_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    (void)memset(cfg, 0, sizeof(*cfg));

    /* DPDK defaults */
    cfg->dpdk.memory_mb = 1024;

    /* Logging defaults */
    cfg->logging.level = IEC61850_LOG_INFO;

    /* Metrics defaults */
    cfg->metrics.export_interval_sec = 60;
}

void iec61850_app_config_free(iec61850_app_config_t *cfg)
{
    /* All fields are fixed-size, nothing to free */
    (void)cfg;
}

/* ========================================================================
 * Utility Parsers
 * ======================================================================== */

int iec61850_parse_core_list(const char *str, unsigned *cores,
                              size_t max_cores, size_t *count)
{
    char buf[256];
    char *token;
    char *saveptr;

    if (str == NULL || cores == NULL || count == NULL) {
        return -1;
    }

    *count = 0;
    (void)strncpy(buf, str, sizeof(buf) - 1U);
    buf[sizeof(buf) - 1U] = '\0';

    token = strtok_r(buf, ",", &saveptr);
    while (token != NULL) {
        /* Check for range (e.g., "2-4") */
        char *dash = strchr(token, '-');
        if (dash != NULL) {
            *dash = '\0';
            unsigned start = (unsigned)strtoul(token, NULL, 10);
            unsigned end = (unsigned)strtoul(&dash[1], NULL, 10);
            for (unsigned i = start; i <= end && *count < max_cores; i++) {
                cores[*count] = i;
                (*count)++;
            }
        } else {
            if (*count < max_cores) {
                cores[*count] = (unsigned)strtoul(token, NULL, 10);
                (*count)++;
            }
        }

        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

int iec61850_parse_pci_list(const char *str,
                             char pci[][IEC61850_PCI_ADDR_LEN],
                             size_t max_devices, size_t *count)
{
    char buf[256];
    char *saveptr;

    if (str == NULL || pci == NULL || count == NULL) {
        return -1;
    }

    *count = 0;
    (void)strncpy(buf, str, sizeof(buf) - 1U);
    buf[sizeof(buf) - 1U] = '\0';

    const char *token = strtok_r(buf, ",", &saveptr);
    while (token != NULL && *count < max_devices) {
        /* Strip leading whitespace */
        while (*token == ' ') { token++; }

        (void)strncpy(pci[*count], token, IEC61850_PCI_ADDR_LEN - 1);
        pci[*count][IEC61850_PCI_ADDR_LEN - 1] = '\0';
        (*count)++;

        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

/* ========================================================================
 * Config Manager - Load with precedence
 * ======================================================================== */

/* Forward declaration from cli_parser.c */
const char *iec61850_cli_get_config_file(void);

/* Apply YAML values to config (only sets non-empty values) */
static void apply_yaml(const iec61850_yaml_doc_t *doc,
                        iec61850_app_config_t *cfg)
{
    const char *val;
    size_t list_count;
    const char **list;

    /* SCL */
    val = iec61850_yaml_get_string(doc, "scl.file");
    if (val != NULL && val[0] != '\0') {
        (void)strncpy(cfg->scl.file, val, IEC61850_MAX_PATH_LEN - 1);
        cfg->scl.file[IEC61850_MAX_PATH_LEN - 1] = '\0';
    }

    val = iec61850_yaml_get_string(doc, "scl.ied");
    if (val != NULL && val[0] != '\0') {
        (void)strncpy(cfg->scl.ied_name, val, IEC61850_MAX_PATH_LEN - 1);
        cfg->scl.ied_name[IEC61850_MAX_PATH_LEN - 1] = '\0';
    }

    list = iec61850_yaml_get_list(doc, "scl.control_blocks", &list_count);
    if (list != NULL && list_count > 0U) {
        cfg->scl.control_blocks_count = 0;
        for (size_t i = 0U; i < list_count && i < (size_t)IEC61850_MAX_CONTROL_BLOCKS; i++) {
            (void)strncpy(cfg->scl.control_blocks[i], list[i],
                          IEC61850_MAX_PATH_LEN - 1);
            cfg->scl.control_blocks[i][IEC61850_MAX_PATH_LEN - 1] = '\0';
            cfg->scl.control_blocks_count++;
        }
    }

    /* DPDK */
    int mem = iec61850_yaml_get_int(doc, "dpdk.memory_mb", -1);
    if (mem >= 0) {
        cfg->dpdk.memory_mb = (unsigned)mem;
    }

    val = iec61850_yaml_get_string(doc, "dpdk.no_huge");
    if (val != NULL) {
        cfg->dpdk.no_huge = iec61850_yaml_get_bool(doc, "dpdk.no_huge", false);
    }

    val = iec61850_yaml_get_string(doc, "dpdk.file_prefix");
    if (val != NULL && val[0] != '\0') {
        (void)strncpy(cfg->dpdk.file_prefix, val, sizeof(cfg->dpdk.file_prefix) - 1U);
        cfg->dpdk.file_prefix[sizeof(cfg->dpdk.file_prefix) - 1U] = '\0';
    }

    /* Logging */
    val = iec61850_yaml_get_string(doc, "logging.level");
    if (val != NULL && val[0] != '\0') {
        cfg->logging.level = iec61850_log_level_from_string(val);
    }

    val = iec61850_yaml_get_string(doc, "logging.output");
    if (val != NULL && val[0] != '\0') {
        (void)strncpy(cfg->logging.output, val, IEC61850_MAX_PATH_LEN - 1);
        cfg->logging.output[IEC61850_MAX_PATH_LEN - 1] = '\0';
    }

    val = iec61850_yaml_get_string(doc, "logging.use_syslog");
    if (val != NULL) {
        cfg->logging.use_syslog = iec61850_yaml_get_bool(doc, "logging.use_syslog", false);
    }

    /* Metrics */
    val = iec61850_yaml_get_string(doc, "metrics.enabled");
    if (val != NULL) {
        cfg->metrics.enabled = iec61850_yaml_get_bool(doc, "metrics.enabled", false);
    }

    int interval = iec61850_yaml_get_int(doc, "metrics.export_interval_sec", -1);
    if (interval >= 0) {
        cfg->metrics.export_interval_sec = (unsigned)interval;
    }

    val = iec61850_yaml_get_string(doc, "metrics.output");
    if (val != NULL && val[0] != '\0') {
        (void)strncpy(cfg->metrics.output, val, IEC61850_MAX_PATH_LEN - 1);
        cfg->metrics.output[IEC61850_MAX_PATH_LEN - 1] = '\0';
    }

    /* Security */
    val = iec61850_yaml_get_string(doc, "security.enabled");
    if (val != NULL) {
        cfg->security.enabled = iec61850_yaml_get_bool(doc, "security.enabled", false);
    }

    val = iec61850_yaml_get_string(doc, "security.private_key");
    if (val != NULL && val[0] != '\0') {
        (void)strncpy(cfg->security.private_key, val, IEC61850_MAX_PATH_LEN - 1);
        cfg->security.private_key[IEC61850_MAX_PATH_LEN - 1] = '\0';
    }

    val = iec61850_yaml_get_string(doc, "security.certificate");
    if (val != NULL && val[0] != '\0') {
        (void)strncpy(cfg->security.certificate, val, IEC61850_MAX_PATH_LEN - 1);
        cfg->security.certificate[IEC61850_MAX_PATH_LEN - 1] = '\0';
    }

    val = iec61850_yaml_get_string(doc, "security.trusted_certs");
    if (val != NULL && val[0] != '\0') {
        (void)strncpy(cfg->security.trusted_certs, val, IEC61850_MAX_PATH_LEN - 1);
        cfg->security.trusted_certs[IEC61850_MAX_PATH_LEN - 1] = '\0';
    }
}

int iec61850_config_manager_load(int argc, char *argv[],
                                  iec61850_app_config_t *cfg)
{
    int ret;

    if (cfg == NULL) {
        return -1;
    }

    /* Step 1: Initialize with defaults */
    iec61850_app_config_init(cfg);

    /* Step 2: Parse CLI into a separate config to track what was set */
    iec61850_app_config_t cli_cfg;
    iec61850_app_config_init(&cli_cfg);

    /* Mark CLI config with distinguishable defaults for merge detection */
    cli_cfg.logging.level = IEC61850_LOG_INFO;  /* Same as default */
    cli_cfg.dpdk.memory_mb = 1024;              /* Same as default */

    ret = iec61850_cli_parse(argc, argv, &cli_cfg);
    if (ret != 0) {
        return ret;  /* 1 = help/version, -1 = error */
    }

    /* Step 3: If --config was specified, load YAML first (base layer) */
    const char *config_file = iec61850_cli_get_config_file();
    if (config_file != NULL) {
        iec61850_yaml_doc_t doc;
        iec61850_yaml_doc_init(&doc);

        ret = iec61850_yaml_parse_file(config_file, &doc);
        if (ret != 0) {
            (void)fprintf(stderr, "ERROR: Failed to parse config file: %s\n",
                          config_file);
            iec61850_yaml_doc_free(&doc);
            return -1;
        }

        apply_yaml(&doc, cfg);
        iec61850_yaml_doc_free(&doc);
    }

    /* Step 4: Apply CLI overrides (CLI > YAML > defaults) */
    /* We apply CLI values on top of whatever YAML set.
     * For simplicity, we re-parse CLI directly into cfg.
     * This means CLI always wins over YAML. */
    ret = iec61850_cli_parse(argc, argv, cfg);
    if (ret != 0) {
        return ret;
    }

    return 0;
}
