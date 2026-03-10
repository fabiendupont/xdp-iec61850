/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Sampled Values Subscriber Example
 *
 * Demonstrates SV message subscription using the xdp-iec61850 stack.
 * Receives SV samples and detects gaps.
 *
 * Usage: sv_subscriber [interface]
 */

#define _POSIX_C_SOURCE 200809L

#include "sv/sv_subscriber.h"
#include "logging/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

static volatile int running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void on_sv_received(const iec61850_sv_message_t *msg, void *user_data)
{
    (void)user_data;

    if (msg->has_gap) {
        char log_msg[256];
        (void)snprintf(log_msg, sizeof(log_msg),
                      "GAP detected from %s: smpCnt=%u, gap=%u",
                      msg->asdu.svID,
                      msg->asdu.smpCnt,
                      msg->gap_count);
        IEC61850_LOG_WARNING_MSG("SV", log_msg);
    }
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    iec61850_logger_set_level(IEC61850_LOG_INFO);
    IEC61850_LOG_INFO_MSG("EXAMPLE", "SV Subscriber starting");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Configure subscriber */
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    cfg.timeout_ms = 5000;

    /* Create subscriber */
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);
    iec61850_sv_subscriber_set_callback(&sub, on_sv_received, NULL);

    IEC61850_LOG_INFO_MSG("EXAMPLE", "Waiting for SV samples...");

    while (running) {
        /* In a real application, receive via packet_io and decode */
        usleep(100000);  /* 100ms */
    }

    char stats[128];
    (void)snprintf(stats, sizeof(stats),
                  "Total: %lu samples, %lu gaps",
                  (unsigned long)sub.total_messages,
                  (unsigned long)sub.total_gaps);
    IEC61850_LOG_INFO_MSG("STATS", stats);

    iec61850_sv_subscriber_destroy(&sub);
    IEC61850_LOG_INFO_MSG("EXAMPLE", "SV Subscriber stopped");

    return 0;
}
