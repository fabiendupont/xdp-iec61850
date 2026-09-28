/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Publisher Example
 *
 * Demonstrates GOOSE message publication using the xdp-iec61850 stack.
 * Publishes GOOSE messages with retransmission scheduling.
 *
 * Usage: goose_publisher [interface]
 */


#include "goose/goose_publisher.h"
#include "logging/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

static volatile int running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    iec61850_logger_set_level(IEC61850_LOG_INFO);
    IEC61850_LOG_INFO_MSG("EXAMPLE", "GOOSE Publisher starting");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Configure publisher */
    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);
    cfg.app_id = 0x0001;
    (void)strncpy(cfg.gocb_ref, "IED1LD0/LLN0$GO$gcb01",
                  GOOSE_MAX_GOCBREF_LEN - 1);
    (void)strncpy(cfg.dataset, "IED1LD0/LLN0$DS1",
                  GOOSE_MAX_DATSET_LEN - 1);

    /* Create publisher */
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &cfg);

    /* Set initial data values */
    iec61850_goose_publisher_set_boolean(&pub, 0, false);
    iec61850_goose_publisher_set_int32(&pub, 1, 0);
    iec61850_goose_publisher_set_uint32(&pub, 2, 1000);

    /* Enable retransmission */
    iec61850_retransmit_config_t rt_cfg = { .t0_ms = 2, .t_max_ms = 1000 };
    iec61850_goose_publisher_enable_retransmit(&pub, &rt_cfg);

    IEC61850_LOG_INFO_MSG("EXAMPLE", "Publishing GOOSE messages...");

    uint8_t buf[1518];
    size_t encoded = 0;
    int cycle = 0;

    while (running) {
        /* Simulate data change every 5 seconds */
        if (cycle > 0 && (cycle % 50) == 0) {
            iec61850_goose_publisher_set_boolean(&pub, 0,
                !pub.data[0].value.boolean);
            iec61850_goose_publisher_state_change(&pub);

            char msg[128];
            (void)snprintf(msg, sizeof(msg),
                          "State change: stNum=%u, sqNum=%u",
                          iec61850_goose_publisher_get_st_num(&pub),
                          iec61850_goose_publisher_get_sq_num(&pub));
            IEC61850_LOG_INFO_MSG("GOOSE", msg);
        }

        /* Prepare packet */
        int ret = iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf),
                                                    &encoded);
        if (ret == 0) {
            /* In a real application, send via packet_io */
            char msg[128];
            (void)snprintf(msg, sizeof(msg),
                          "Encoded %zu bytes, stNum=%u sqNum=%u",
                          encoded,
                          iec61850_goose_publisher_get_st_num(&pub),
                          iec61850_goose_publisher_get_sq_num(&pub));
            IEC61850_LOG_DEBUG_MSG("GOOSE", msg);
        }

        usleep(100000);  /* 100ms */
        cycle++;
    }

    iec61850_goose_publisher_destroy(&pub);
    IEC61850_LOG_INFO_MSG("EXAMPLE", "GOOSE Publisher stopped");

    return 0;
}
