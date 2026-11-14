/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Latency Measurement Tool
 *
 * Measures end-to-end GOOSE message latency from publish to receive.
 * Requires two interfaces (veth pair or physical ports).
 *
 * Usage: goose_latency <tx_interface> <rx_interface> [count]
 */


#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "containers/ring_buffer.h"
#include "logging/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

/* Ring buffer for latency samples */
IEC61850_DEFINE_RING_BUFFER(latency_ring, uint64_t, 10000)

static volatile int running = 1;
static latency_ring_t latency_samples;

static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void print_latency_stats(void)
{
    if (latency_ring_empty(&latency_samples)) {
        printf("No latency samples collected\n");
        return;
    }

    size_t count = latency_ring_size(&latency_samples);
    uint64_t sum = 0;
    uint64_t min_val = UINT64_MAX;
    uint64_t max_val = 0;

    for (size_t i = 0; i < count; i++) {
        const uint64_t *val = latency_ring_at(&latency_samples, i);
        if (val == NULL) { break; }
        sum += *val;
        if (*val < min_val) { min_val = *val; }
        if (*val > max_val) { max_val = *val; }
    }

    uint64_t avg = sum / count;

    printf("\n=== Latency Statistics (%zu samples) ===\n", count);
    printf("  Min:  %lu ns (%.3f us)\n", (unsigned long)min_val,
           (double)min_val / 1000.0);
    printf("  Max:  %lu ns (%.3f us)\n", (unsigned long)max_val,
           (double)max_val / 1000.0);
    printf("  Avg:  %lu ns (%.3f us)\n", (unsigned long)avg,
           (double)avg / 1000.0);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    iec61850_logger_set_level(IEC61850_LOG_INFO);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    latency_ring_init(&latency_samples);

    printf("GOOSE Latency Measurement Tool\n");
    printf("Press Ctrl+C to stop and display results\n\n");

    /* In a real application, this would use packet_io to
     * publish and receive GOOSE messages on different interfaces,
     * measuring the time delta between send and receive timestamps. */

    iec61850_logger_log(IEC61850_LOG_INFO, "LATENCY",
                        "Tool ready (requires packet_io)");

    while (running) {
        usleep(100000);
    }

    print_latency_stats();

    return 0;
}
