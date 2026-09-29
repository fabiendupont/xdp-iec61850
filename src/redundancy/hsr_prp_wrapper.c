/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * HSR/PRP Redundancy Wrapper — IEC 61850
 *
 * When IEC61850_HSR_PRP_ENABLED is defined (by meson when enable_hsr_prp=true),
 * this wraps the real xdp-hsr-prp instance API.  Otherwise, all functions
 * return -ENOTSUP.
 */

#include "redundancy/hsr_prp_wrapper.h"

#include <errno.h>
#include <string.h>

#ifdef IEC61850_HSR_PRP_ENABLED
#include <hsr_prp/hsr_prp_userspace.h>

static struct hsr_prp_instance *s_instance;
static struct hsr_prp_config    s_hsr_cfg;
static bool                     s_initialized;
#endif

int iec61850_hsr_prp_config_init(iec61850_hsr_prp_config_t *cfg,
                                 enum iec61850_hsr_prp_mode mode,
                                 const char *port_a,
                                 const char *port_b)
{
    if (!cfg) {
        return -EINVAL;
    }

    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->mode = mode;
    cfg->supervision_interval_ms = 2000;
    cfg->node_timeout_ms = 60000;

    if (port_a) {
        size_t len = strlen(port_a);
        if (len >= (size_t)IEC61850_HSR_PRP_IFNAMSIZ) {
            return -ENAMETOOLONG;
        }
        (void)memcpy(cfg->port_a, port_a, len + 1U);
    }

    if (port_b) {
        size_t len = strlen(port_b);
        if (len >= (size_t)IEC61850_HSR_PRP_IFNAMSIZ) {
            return -ENAMETOOLONG;
        }
        (void)memcpy(cfg->port_b, port_b, len + 1U);
    }

    return 0;
}

int iec61850_hsr_prp_config_validate(const iec61850_hsr_prp_config_t *cfg)
{
    if (!cfg) {
        return -EINVAL;
    }

    if (cfg->port_a[0] == '\0') {
        return -EINVAL;
    }

    if (cfg->port_b[0] == '\0') {
        return -EINVAL;
    }

    if (cfg->mode != IEC61850_HSR_PRP_MODE_HSR &&
        cfg->mode != IEC61850_HSR_PRP_MODE_PRP) {
        return -EINVAL;
    }

    if (cfg->supervision_interval_ms == 0U) {
        return -EINVAL;
    }

    if (cfg->node_timeout_ms == 0U) {
        return -EINVAL;
    }

    return 0;
}

#ifdef IEC61850_HSR_PRP_ENABLED

int iec61850_hsr_prp_init(const iec61850_hsr_prp_config_t *cfg)
{
    int ret;

    if (!cfg) {
        return -EINVAL;
    }

    ret = iec61850_hsr_prp_config_validate(cfg);
    if (ret < 0) {
        return ret;
    }

    if (s_initialized) {
        iec61850_hsr_prp_stop();
    }

    enum hsr_prp_mode hsr_mode = (cfg->mode == IEC61850_HSR_PRP_MODE_HSR)
                                     ? HSR_PRP_MODE_HSR
                                     : HSR_PRP_MODE_PRP;

    ret = hsr_prp_config_init(&s_hsr_cfg, hsr_mode, cfg->port_a, cfg->port_b);
    if (ret < 0) {
        return ret;
    }

    s_hsr_cfg.supervision_interval_ms = cfg->supervision_interval_ms;
    s_hsr_cfg.node_timeout_ms = cfg->node_timeout_ms;

    ret = hsr_prp_config_validate(&s_hsr_cfg);
    if (ret < 0) {
        return ret;
    }

    s_instance = hsr_prp_instance_create(&s_hsr_cfg, NULL);
    if (!s_instance) {
        return -ENOMEM;
    }

    s_initialized = true;
    return 0;
}

int iec61850_hsr_prp_start(void)
{
    if (!s_initialized || !s_instance) {
        return -EINVAL;
    }

    int ret = hsr_prp_instance_attach(s_instance);
    if (ret < 0) {
        return ret;
    }

    return hsr_prp_instance_start(s_instance);
}

void iec61850_hsr_prp_stop(void)
{
    if (s_instance) {
        hsr_prp_instance_stop(s_instance);
        hsr_prp_instance_destroy(s_instance);
        s_instance = NULL;
    }
    s_initialized = false;
}

int iec61850_hsr_prp_get_stats(iec61850_hsr_prp_stats_t *stats)
{
    if (!stats) {
        return -EINVAL;
    }

    (void)memset(stats, 0, sizeof(*stats));

    if (!s_initialized || !s_instance) {
        return -EINVAL;
    }

    struct hsr_prp_stats hsr_stats;
    int ret = hsr_prp_instance_get_stats(s_instance, 0, &hsr_stats);
    if (ret < 0) {
        return ret;
    }

    stats->rx_count  = hsr_stats.rx_count;
    stats->rx_bytes  = hsr_stats.rx_bytes;
    stats->tx_count  = hsr_stats.tx_count;
    stats->tx_bytes  = hsr_stats.tx_bytes;
    stats->dup_drops = hsr_stats.dup_drops;
    stats->errors    = hsr_stats.errors;

    return 0;
}

bool iec61850_hsr_prp_available(void)
{
    return true;
}

#else /* !IEC61850_HSR_PRP_ENABLED */

int iec61850_hsr_prp_init(const iec61850_hsr_prp_config_t *cfg)
{
    (void)cfg;
    return -ENOTSUP;
}

int iec61850_hsr_prp_start(void)
{
    return -ENOTSUP;
}

void iec61850_hsr_prp_stop(void)
{
    /* Nothing to do */
}

int iec61850_hsr_prp_get_stats(iec61850_hsr_prp_stats_t *stats)
{
    if (!stats) {
        return -EINVAL;
    }
    (void)memset(stats, 0, sizeof(*stats));
    return -ENOTSUP;
}

bool iec61850_hsr_prp_available(void)
{
    return false;
}

#endif /* IEC61850_HSR_PRP_ENABLED */
