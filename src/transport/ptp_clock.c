/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEEE 1588 PTP Clock Implementation
 *
 * SYSTEM_CLOCK: clock_gettime(CLOCK_REALTIME), smpSynch=0.
 * PTP_DEVICE:   opens /dev/ptpN, reads via FD_TO_CLOCKID, smpSynch=2.
 * Graceful fallback to system clock if PTP device unavailable.
 *
 * License: BSD-3-Clause
 */


#include "transport/ptp_clock.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* FD_TO_CLOCKID may not be defined in older glibc headers */
#ifndef FD_TO_CLOCKID
#define FD_TO_CLOCKID(fd) ((clockid_t) ((((unsigned int) ~(fd)) << 3) | 3))
#endif

int iec61850_ptp_clock_init(iec61850_ptp_clock_t *clock,
                            enum iec61850_ptp_clock_source source,
                            const char *device_path)
{
    if (clock == NULL) {
        return -EINVAL;
    }

    clock->source = source;
    clock->sync_status = IEC61850_PTP_SYNC_UNKNOWN;
    clock->ptp_fd = -1;
    clock->initialized = false;

    if (source == IEC61850_PTP_SOURCE_SYSTEM_CLOCK || device_path == NULL) {
        clock->source = IEC61850_PTP_SOURCE_SYSTEM_CLOCK;
        clock->sync_status = IEC61850_PTP_SYNC_UNSYNC;
        clock->initialized = true;
        return 0;
    }

    /* PTP_DEVICE mode */
    if (device_path[0] == '\0') {
        return -EINVAL;
    }

    int fd = open(device_path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    clock->ptp_fd = fd;
    clock->sync_status = IEC61850_PTP_SYNC_SYNCING;
    clock->initialized = true;
    return 0;
}

uint64_t iec61850_ptp_clock_get_time_ns(const iec61850_ptp_clock_t *clock)
{
    struct timespec ts;

    if (clock == NULL || !clock->initialized) {
        return 0;
    }

    if (clock->source == IEC61850_PTP_SOURCE_PTP_DEVICE && clock->ptp_fd >= 0) {
        if (clock_gettime(FD_TO_CLOCKID(clock->ptp_fd), &ts) == 0) {
            return (uint64_t)ts.tv_sec * 1000000000ULL +
                   (uint64_t)ts.tv_nsec;
        }
        /* Fall through to system clock on error */
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL +
           (uint64_t)ts.tv_nsec;
}

uint8_t iec61850_ptp_clock_get_smp_synch(const iec61850_ptp_clock_t *clock)
{
    if (clock == NULL || !clock->initialized) {
        return 0;
    }

    switch (clock->sync_status) {
    case IEC61850_PTP_SYNC_LOCKED:
        return 2;  /* Global synchronization (PTP) */
    case IEC61850_PTP_SYNC_SYNCING:
        return 1;  /* Local synchronization */
    case IEC61850_PTP_SYNC_UNSYNC:
    case IEC61850_PTP_SYNC_UNKNOWN:
    default:
        return 0;  /* No synchronization */
    }
}

void iec61850_ptp_clock_update_sync(iec61850_ptp_clock_t *clock)
{
    if (clock == NULL || !clock->initialized) {
        return;
    }

    switch (clock->source) {
    case IEC61850_PTP_SOURCE_SYSTEM_CLOCK:
        clock->sync_status = IEC61850_PTP_SYNC_UNSYNC;
        break;

    case IEC61850_PTP_SOURCE_PTP_DEVICE:
        if (clock->ptp_fd >= 0) {
            struct timespec ts;
            if (clock_gettime(FD_TO_CLOCKID(clock->ptp_fd), &ts) == 0) {
                clock->sync_status = IEC61850_PTP_SYNC_LOCKED;
            } else {
                clock->sync_status = IEC61850_PTP_SYNC_UNSYNC;
            }
        } else {
            clock->sync_status = IEC61850_PTP_SYNC_UNSYNC;
        }
        break;
    }
}

void iec61850_ptp_clock_destroy(iec61850_ptp_clock_t *clock)
{
    if (clock == NULL) {
        return;
    }

    if (clock->ptp_fd >= 0) {
        close(clock->ptp_fd);
        clock->ptp_fd = -1;
    }

    clock->initialized = false;
    clock->sync_status = IEC61850_PTP_SYNC_UNKNOWN;
}
