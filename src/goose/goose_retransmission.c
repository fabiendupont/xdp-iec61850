/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Retransmission Scheduler Implementation
 *
 * License: BSD-3-Clause
 */

#include "goose/goose_retransmission.h"
#include <time.h>

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

void iec61850_retransmit_init(iec61850_retransmit_t *rt,
                               const iec61850_retransmit_config_t *cfg)
{
    if (rt == NULL) { return; }

    if (cfg != NULL) {
        rt->config = *cfg;
    } else {
        rt->config.t0_ms = 2;
        rt->config.t_max_ms = 1000;
    }

    rt->current_interval_ms = rt->config.t_max_ms;
    rt->next_tx_time_ns = monotonic_ns();
    rt->state_changed = false;
}

void iec61850_retransmit_on_state_change(iec61850_retransmit_t *rt)
{
    if (rt == NULL) { return; }

    rt->current_interval_ms = rt->config.t0_ms;
    rt->next_tx_time_ns = monotonic_ns();
    rt->state_changed = true;
}

bool iec61850_retransmit_is_due(iec61850_retransmit_t *rt)
{
    uint64_t now;

    if (rt == NULL) { return false; }

    now = monotonic_ns();
    if (now < rt->next_tx_time_ns) {
        return false;
    }

    /* Schedule next transmission with exponential backoff */
    rt->next_tx_time_ns = now + (uint64_t)rt->current_interval_ms * 1000000ULL;

    if (rt->current_interval_ms < rt->config.t_max_ms) {
        rt->current_interval_ms *= 2;
        if (rt->current_interval_ms > rt->config.t_max_ms) {
            rt->current_interval_ms = rt->config.t_max_ms;
        }
    }

    return true;
}

uint32_t iec61850_retransmit_get_interval_ms(const iec61850_retransmit_t *rt)
{
    if (rt == NULL) { return 0; }
    return rt->current_interval_ms;
}

bool iec61850_retransmit_is_rapid(const iec61850_retransmit_t *rt)
{
    if (rt == NULL) { return false; }
    return rt->current_interval_ms < rt->config.t_max_ms;
}
