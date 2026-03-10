/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for GOOSE Retransmission Scheduler
 */

#define _POSIX_C_SOURCE 199309L

#include "goose/goose_retransmission.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

static void test_init_with_config(void)
{
    iec61850_retransmit_t rt;
    iec61850_retransmit_config_t cfg = { .t0_ms = 4, .t_max_ms = 500 };

    iec61850_retransmit_init(&rt, &cfg);
    assert(rt.config.t0_ms == 4);
    assert(rt.config.t_max_ms == 500);
    assert(rt.current_interval_ms == 500);
    assert(!rt.state_changed);
    printf("  PASS: init_with_config\n");
}

static void test_init_default_config(void)
{
    iec61850_retransmit_t rt;

    iec61850_retransmit_init(&rt, NULL);
    assert(rt.config.t0_ms == 2);
    assert(rt.config.t_max_ms == 1000);
    assert(rt.current_interval_ms == 1000);
    printf("  PASS: init_default_config\n");
}

static void test_init_null(void)
{
    iec61850_retransmit_init(NULL, NULL);
    printf("  PASS: init_null\n");
}

static void test_state_change(void)
{
    iec61850_retransmit_t rt;
    iec61850_retransmit_config_t cfg = { .t0_ms = 2, .t_max_ms = 1000 };

    iec61850_retransmit_init(&rt, &cfg);
    assert(rt.current_interval_ms == 1000);

    iec61850_retransmit_on_state_change(&rt);
    assert(rt.current_interval_ms == 2);
    assert(rt.state_changed);
    printf("  PASS: state_change\n");
}

static void test_state_change_null(void)
{
    iec61850_retransmit_on_state_change(NULL);
    printf("  PASS: state_change_null\n");
}

static void test_is_due_and_backoff(void)
{
    iec61850_retransmit_t rt;
    iec61850_retransmit_config_t cfg = { .t0_ms = 2, .t_max_ms = 16 };

    iec61850_retransmit_init(&rt, &cfg);
    iec61850_retransmit_on_state_change(&rt);

    /* Should be due immediately after state change */
    assert(iec61850_retransmit_is_due(&rt));
    assert(rt.current_interval_ms == 4);  /* 2 * 2 */

    /* Not due yet (just scheduled) */
    assert(!iec61850_retransmit_is_due(&rt));

    /* Force next_tx_time_ns to past to trigger */
    rt.next_tx_time_ns = 0;
    assert(iec61850_retransmit_is_due(&rt));
    assert(rt.current_interval_ms == 8);  /* 4 * 2 */

    rt.next_tx_time_ns = 0;
    assert(iec61850_retransmit_is_due(&rt));
    assert(rt.current_interval_ms == 16);  /* 8 * 2, capped at t_max */

    /* Verify cap — should stay at t_max */
    rt.next_tx_time_ns = 0;
    assert(iec61850_retransmit_is_due(&rt));
    assert(rt.current_interval_ms == 16);  /* stays at t_max */

    printf("  PASS: is_due_and_backoff\n");
}

static void test_is_due_null(void)
{
    assert(!iec61850_retransmit_is_due(NULL));
    printf("  PASS: is_due_null\n");
}

static void test_get_interval_ms(void)
{
    iec61850_retransmit_t rt;
    iec61850_retransmit_config_t cfg = { .t0_ms = 5, .t_max_ms = 100 };

    iec61850_retransmit_init(&rt, &cfg);
    assert(iec61850_retransmit_get_interval_ms(&rt) == 100);

    iec61850_retransmit_on_state_change(&rt);
    assert(iec61850_retransmit_get_interval_ms(&rt) == 5);

    assert(iec61850_retransmit_get_interval_ms(NULL) == 0);
    printf("  PASS: get_interval_ms\n");
}

static void test_is_rapid(void)
{
    iec61850_retransmit_t rt;
    iec61850_retransmit_config_t cfg = { .t0_ms = 2, .t_max_ms = 8 };

    iec61850_retransmit_init(&rt, &cfg);
    assert(!iec61850_retransmit_is_rapid(&rt));  /* at t_max */

    iec61850_retransmit_on_state_change(&rt);
    assert(iec61850_retransmit_is_rapid(&rt));  /* at t0 < t_max */

    /* Drive to t_max */
    rt.next_tx_time_ns = 0;
    (void)iec61850_retransmit_is_due(&rt);  /* 2→4 */
    rt.next_tx_time_ns = 0;
    (void)iec61850_retransmit_is_due(&rt);  /* 4→8 */
    assert(!iec61850_retransmit_is_rapid(&rt));  /* at t_max */

    assert(!iec61850_retransmit_is_rapid(NULL));
    printf("  PASS: is_rapid\n");
}

int main(void)
{
    printf("=== GOOSE Retransmission Tests ===\n");

    test_init_with_config();
    test_init_default_config();
    test_init_null();
    test_state_change();
    test_state_change_null();
    test_is_due_and_backoff();
    test_is_due_null();
    test_get_interval_ms();
    test_is_rapid();

    printf("All GOOSE retransmission tests passed.\n");
    return 0;
}
