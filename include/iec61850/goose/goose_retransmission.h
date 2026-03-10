/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Retransmission Scheduler (IEC 61850-8-1 clause 15.2.2)
 *
 * Exponential backoff: T0, 2*T0, 4*T0, ..., Tmax
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_GOOSE_RETRANSMISSION_H
#define IEC61850_GOOSE_RETRANSMISSION_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t t0_ms;      /* Initial interval (default 2ms) */
    uint32_t t_max_ms;   /* Maximum interval (default 1000ms) */
} iec61850_retransmit_config_t;

typedef struct {
    iec61850_retransmit_config_t config;
    uint32_t current_interval_ms;
    uint64_t next_tx_time_ns;  /* CLOCK_MONOTONIC */
    bool state_changed;
} iec61850_retransmit_t;

void iec61850_retransmit_init(iec61850_retransmit_t *rt,
                               const iec61850_retransmit_config_t *cfg);

void iec61850_retransmit_on_state_change(iec61850_retransmit_t *rt);

bool iec61850_retransmit_is_due(iec61850_retransmit_t *rt);

uint32_t iec61850_retransmit_get_interval_ms(const iec61850_retransmit_t *rt);

bool iec61850_retransmit_is_rapid(const iec61850_retransmit_t *rt);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_GOOSE_RETRANSMISSION_H */
