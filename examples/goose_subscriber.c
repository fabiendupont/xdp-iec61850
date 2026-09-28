/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Subscriber Example
 *
 * Demonstrates GOOSE message subscription using the xdp-iec61850 stack.
 * Processes received GOOSE messages and detects state changes.
 *
 * Usage: goose_subscriber [interface]
 */


#include "goose/goose_subscriber.h"
#include "logging/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static volatile int running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void on_goose_received(const iec61850_goose_message_t *msg,
                               void *user_data)
{
    (void)user_data;
    char log_msg[256];

    if (msg->is_new_state) {
        (void)snprintf(log_msg, sizeof(log_msg),
                      "NEW STATE from %s: stNum=%u sqNum=%u "
                      "entries=%u",
                      msg->apdu.gocbRef,
                      msg->apdu.stNum, msg->apdu.sqNum,
                      msg->apdu.numDatSetEntries);
        IEC61850_LOG_INFO_MSG("GOOSE", log_msg);
    } else if (msg->is_retransmission) {
        (void)snprintf(log_msg, sizeof(log_msg),
                      "Retransmission from %s: stNum=%u sqNum=%u",
                      msg->apdu.gocbRef,
                      msg->apdu.stNum, msg->apdu.sqNum);
        IEC61850_LOG_DEBUG_MSG("GOOSE", log_msg);
    }
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    iec61850_logger_set_level(IEC61850_LOG_INFO);
    IEC61850_LOG_INFO_MSG("EXAMPLE", "GOOSE Subscriber starting");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Configure subscriber */
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);
    cfg.timeout_ms = 5000;

    /* Create subscriber */
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);
    iec61850_goose_subscriber_set_callback(&sub, on_goose_received, NULL);

    IEC61850_LOG_INFO_MSG("EXAMPLE", "Waiting for GOOSE messages...");

    while (running) {
        /* In a real application, receive via packet_io and decode */
        struct timespec ts;
        (void)clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
                          (uint64_t)ts.tv_nsec;

        iec61850_goose_subscriber_check_timeouts(&sub, now_ns);

        usleep(100000);  /* 100ms */
    }

    char stats[128];
    (void)snprintf(stats, sizeof(stats),
                  "Total: %lu messages, %lu duplicates, %lu timeouts",
                  (unsigned long)sub.total_messages,
                  (unsigned long)sub.total_duplicates,
                  (unsigned long)sub.total_timeouts);
    IEC61850_LOG_INFO_MSG("STATS", stats);

    iec61850_goose_subscriber_destroy(&sub);
    IEC61850_LOG_INFO_MSG("EXAMPLE", "GOOSE Subscriber stopped");

    return 0;
}
