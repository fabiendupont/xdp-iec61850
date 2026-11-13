/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client Async Core for IEC 61850
 *
 * Single-threaded, poll-driven event core for MMS client associations.
 * The blocking client (mms_client.h) is a thin wrapper over this core;
 * applications embedding the core directly get non-blocking request
 * correlation and unsolicited-report dispatch.
 *
 * FROZEN INTERFACE (WP-S1). Implementations change; signatures do not.
 * Change requests go to the orchestrator, not the implementing WP.
 */

#ifndef IEC61850_MMS_CLIENT_CORE_H
#define IEC61850_MMS_CLIENT_CORE_H

#include "transport/iso_stack.h"
#include "asn1/mms_ber.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum concurrently outstanding (submitted, undelivered) requests */
#define IEC61850_CLIENT_CORE_MAX_PENDING 8

/*
 * Response delivery callback. Invoked from the polling context
 * (core_poll / core_wait) when the response or error PDU for a
 * submitted request arrives, or when the request fails.
 *
 * @param status    0 when a PDU was decoded; negative errno otherwise
 *                  (-ETIMEDOUT, -ECONNRESET, -EBADMSG, ...).
 * @param response  Decoded confirmed response; NULL if none.
 * @param error     Decoded confirmed error PDU; NULL if none.
 *                  Exactly one of response/error is non-NULL when
 *                  status == 0.
 * @param user_data Caller context from submit().
 */
typedef void (*iec61850_mms_core_response_cb)(
    int status,
    const mms_confirmed_response_t *response,
    const mms_confirmed_error_t *error,
    void *user_data);

/*
 * Unsolicited InformationReport callback (server-initiated reports).
 * @param report Decoded report; never NULL when invoked.
 */
typedef void (*iec61850_mms_core_report_cb)(
    const mms_information_report_t *report, void *user_data);

typedef struct {
    uint32_t invoke_id;
    bool in_use;
    bool delivered;
    int status;                               /* final delivery status */
    iec61850_mms_core_response_cb cb;
    void *user_data;
} iec61850_mms_core_pending_t;

typedef struct {
    iec61850_iso_conn_t *iso;                 /* attached; not owned */
    bool attached;

    iec61850_mms_core_pending_t pending[IEC61850_CLIENT_CORE_MAX_PENDING];

    iec61850_mms_core_report_cb report_cb;
    void *report_user_data;
} iec61850_mms_client_core_t;

/**
 * Initialize the core (no association attached).
 */
void iec61850_mms_client_core_init(iec61850_mms_client_core_t *core);

/**
 * Set the unsolicited-report handler (may be changed at any time).
 */
void iec61850_mms_client_core_set_report_handler(
    iec61850_mms_client_core_t *core,
    iec61850_mms_core_report_cb cb, void *user_data);

/**
 * Attach the core to an established ISO association. The connection
 * is not owned by the core; the caller keeps it alive until detach.
 * @return 0, or -EINVAL on bad arguments, -EBUSY when already attached.
 */
int iec61850_mms_client_core_attach(iec61850_mms_client_core_t *core,
                                     iec61850_iso_conn_t *iso);

/**
 * Detach: drops all pending requests (callbacks are invoked with
 * -ECANCELED) and forgets the association.
 */
void iec61850_mms_client_core_detach(iec61850_mms_client_core_t *core);

/**
 * @return The underlying socket fd for external poll()/epoll
 *         integration, or -ENOTCONN when detached.
 */
int iec61850_mms_client_core_fd(const iec61850_mms_client_core_t *core);

/**
 * Send an encoded MMS request PDU and register its correlation.
 *
 * @param req       Encoded ConfirmedRequest PDU bytes.
 * @param req_len   PDU length.
 * @param invoke_id InvokeID the PDU carries (caller-allocated).
 * @param cb        Delivery callback (required).
 * @return 0, or negative errno (-EINVAL, -ENOTCONN, -EAGAIN when the
 *         pending table is full, transport errors).
 */
int iec61850_mms_client_core_submit(iec61850_mms_client_core_t *core,
                                     const uint8_t *req, size_t req_len,
                                     uint32_t invoke_id,
                                     iec61850_mms_core_response_cb cb,
                                     void *user_data);

/**
 * Poll for PDU(s) and dispatch callbacks. Non-blocking when
 * timeout_ms == 0. Handles responses, error PDUs, and unsolicited
 * InformationReports. Each call processes at most one PDU (TPKT
 * framing atomicity); callers loop to drain.
 *
 * A delivered pending entry remains in its slot (a "tombstone")
 * until wait() reaps it or detach() drops it; submit() recycles
 * tombstone slots.
 *
 * @return Number of events dispatched (>= 0), or negative errno.
 */
int iec61850_mms_client_core_poll(iec61850_mms_client_core_t *core,
                                   int timeout_ms);

/**
 * Blocking convenience: poll until the given invoke_id has been
 * delivered or the timeout expires.
 * @return The delivery status of the pending entry (0 = PDU decoded),
 *         or -ETIMEDOUT, or -EINVAL for an unknown/reaped invoke_id.
 */
int iec61850_mms_client_core_wait(iec61850_mms_client_core_t *core,
                                   uint32_t invoke_id, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_CLIENT_CORE_H */
