/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Sampled Values Publisher Example
 *
 * Demonstrates SV message publication using the xdp-iec61850 stack.
 * Generates 3-phase AC samples at 4000 samples/second (80 samples @ 50Hz).
 *
 * Usage: sv_publisher [interface]
 */

#define _POSIX_C_SOURCE 200809L

#include "sv/sv_publisher.h"
#include "logging/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <math.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

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
    IEC61850_LOG_INFO_MSG("EXAMPLE", "SV Publisher starting");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Configure publisher */
    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.app_id = 0x4000;
    cfg.smp_rate = 80;

    /* Create publisher */
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);

    IEC61850_LOG_INFO_MSG("EXAMPLE",
                          "Publishing SV samples at 4000 sps...");

    double phase_angle = 0.0;
    double amplitude = 10000.0;  /* Peak amplitude */
    double phase_step = 2.0 * M_PI / 80.0;  /* 80 samples per cycle */
    uint64_t sample_count = 0;

    while (running) {
        /* Generate 3-phase AC samples */
        int32_t samples[4];
        samples[0] = (int32_t)(amplitude * sin(phase_angle));
        samples[1] = (int32_t)(amplitude * sin(phase_angle - 2.0 * M_PI / 3.0));
        samples[2] = (int32_t)(amplitude * sin(phase_angle + 2.0 * M_PI / 3.0));
        samples[3] = 0;  /* Neutral */

        for (int i = 0; i < 4; i++) {
            iec61850_sv_publisher_set_sample(&pub, (size_t)i, samples[i]);
        }

        /* Encode */
        uint8_t buf[1518];
        size_t encoded = 0;
        int ret = iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf),
                                                 &encoded);
        if (ret == 0) {
            sample_count++;
        }

        phase_angle += phase_step;
        if (phase_angle >= 2.0 * M_PI) {
            phase_angle -= 2.0 * M_PI;
        }

        usleep(250);  /* 250us = 4000 sps */
    }

    char msg[128];
    (void)snprintf(msg, sizeof(msg),
                  "Published %lu samples", (unsigned long)sample_count);
    IEC61850_LOG_INFO_MSG("STATS", msg);

    iec61850_sv_publisher_destroy(&pub);
    IEC61850_LOG_INFO_MSG("EXAMPLE", "SV Publisher stopped");

    return 0;
}
