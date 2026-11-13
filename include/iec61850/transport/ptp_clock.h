/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEEE 1588 PTP Clock Interface for IEC 61850
 *
 * Provides PTP-synchronized timestamps for GOOSE and SV publishers.
 * Can read from Linux PTP hardware clock (/dev/ptp*) or system clock.
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_PTP_CLOCK_H
#define IEC61850_PTP_CLOCK_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PTP clock source type.
 */
enum iec61850_ptp_clock_source {
    IEC61850_PTP_SOURCE_SYSTEM_CLOCK = 0,  /**< Use system clock (no PTP) */
    IEC61850_PTP_SOURCE_PTP_DEVICE   = 1,  /**< Use /dev/ptpX device */
};

/**
 * PTP synchronization status.
 */
enum iec61850_ptp_sync_status {
    IEC61850_PTP_SYNC_UNKNOWN = 0,  /**< Status not determined */
    IEC61850_PTP_SYNC_UNSYNC  = 1,  /**< Not synchronized */
    IEC61850_PTP_SYNC_SYNCING = 2,  /**< Synchronization in progress */
    IEC61850_PTP_SYNC_LOCKED  = 3,  /**< Locked to PTP grandmaster */
};

/* Ed.2 TimeQuality byte (IEC 61850-8-1 §8.1.3.6, carried in the
 * GOOSE t timestamp and Timestamp data attributes):
 *   bit 7 leapKnown, bit 6 clockFailure, bit 5 clockNotSynchronized,
 *   bits 0-3 timeAccuracy (10 => 1 ms class, the 9-3 power
 *   profile target). */
#define IEC61850_TQ_LEAP_KNOWN           0x80U
#define IEC61850_TQ_CLOCK_FAILURE        0x40U
#define IEC61850_TQ_CLOCK_NOT_SYNCED     0x20U
#define IEC61850_TQ_ACCURACY_1MS         0x0AU
#define IEC61850_TQ_ACCURACY_UNSPECIFIED 0x0FU

/**
 * Derive the Ed.2 TimeQuality byte from the PTP clock sync
 * status — the wiring between the 9-3 time sync and published
 * GOOSE/SV timestamp quality.
 */
uint8_t iec61850_time_quality_from_ptp(
    enum iec61850_ptp_sync_status status);

/**
 * PTP clock instance.
 *
 * Reads PTP-synchronized timestamps when available.
 * Falls back to system clock if PTP is not configured.
 */
typedef struct iec61850_ptp_clock {
    enum iec61850_ptp_clock_source source;
    enum iec61850_ptp_sync_status  sync_status;
    int                            ptp_fd;
    bool                           initialized;
} iec61850_ptp_clock_t;

/**
 * Initialize a PTP clock instance.
 *
 * @param clock        Clock instance to initialize.
 * @param source       Clock source (SYSTEM_CLOCK or PTP_DEVICE).
 * @param device_path  Path to PTP device (e.g. "/dev/ptp0").
 *                     NULL selects system clock regardless of source.
 *
 * @return 0 on success, negative errno on error.
 *         -EINVAL if clock is NULL or PTP_DEVICE with NULL/empty path.
 *         -ENOENT if PTP device does not exist.
 *         -EACCES if permission denied on PTP device.
 */
int iec61850_ptp_clock_init(iec61850_ptp_clock_t *clock,
                            enum iec61850_ptp_clock_source source,
                            const char *device_path);

/**
 * Get current timestamp in nanoseconds since epoch.
 *
 * Uses PTP hardware clock if available, otherwise system clock.
 *
 * @param clock  Initialized clock instance.
 * @return UTC nanoseconds, or 0 if clock is NULL or not initialized.
 */
uint64_t iec61850_ptp_clock_get_time_ns(const iec61850_ptp_clock_t *clock);

/**
 * Get SV smpSynch value per IEC 61850-9-2.
 *
 * @param clock  Initialized clock instance.
 * @return 0 = no synchronization (system clock / unsync),
 *         1 = local synchronization (syncing),
 *         2 = global synchronization (PTP locked).
 */
uint8_t iec61850_ptp_clock_get_smp_synch(const iec61850_ptp_clock_t *clock);

/**
 * Update synchronization status by probing the clock.
 *
 * For PTP_DEVICE, reads the clock to verify it is working.
 * Call periodically to keep sync_status current.
 *
 * @param clock  Initialized clock instance.
 */
void iec61850_ptp_clock_update_sync(iec61850_ptp_clock_t *clock);

/**
 * Destroy a PTP clock instance and release resources.
 *
 * Closes any open PTP device file descriptor.
 *
 * @param clock  Clock instance to destroy. NULL is a no-op.
 */
void iec61850_ptp_clock_destroy(iec61850_ptp_clock_t *clock);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_PTP_CLOCK_H */
