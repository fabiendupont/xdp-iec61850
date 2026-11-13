/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client Async Core for IEC 61850
 *
 * Single-threaded, poll-driven event core implementing the frozen
 * interface in include/iec61850/mms/mms_client_core.h (WP-S1).
 *
 * Design notes (WP-1a):
 *
 * Pending table
 *   Fixed capacity, no allocation. submit() allocates the first truly
 *   free slot (in_use == false); when none is free it recycles the
 *   first delivered-but-unreaped slot ("tombstone"). A tombstone is
 *   NOT an outstanding request: MAX_PENDING counts submitted,
 *   undelivered requests, so recycling keeps submit() from returning
 *   -EAGAIN while only tombstones occupy the table.
 *
 * Delivery lifecycle
 *   poll() decodes one PDU, marks the matching entry delivered and
 *   invokes its callback. The entry then stays readable (tombstone)
 *   until wait() reaps it (returning the recorded status) or detach()
 *   drops it. Applications that embed the core without wait() should
 *   reap entries via wait(id, 0) from their callback context, or clear
 *   entry->in_use directly (the pending table is public).
 *
 * poll() granularity
 *   Exactly one PDU per call. Draining the socket with a zero timeout
 *   could split a partially received TPKT frame and corrupt the
 *   stream, so callers loop (wait() does) when more events are due.
 *
 * Error policy
 *   A transport read timeout is "no data" (return 0 events). Any other
 *   transport or framing error is fatal for the association: every
 *   outstanding entry is failed with the mapped errno through its
 *   callback, and the errno is returned from poll(). A malformed MMS
 *   PDU (-EBADMSG) fails no entry; the caller may keep polling.
 */

#include "mms/mms_client_core.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <time.h>

/* ========================================================================
 * Internal helpers
 * ======================================================================== */

/* Map iec61850 transport error codes to negative errnos. Values that
 * are already negative errnos (from the ISO/BER layers) pass through. */
static int transport_to_errno(int ret)
{
    switch (ret) {
    case IEC61850_TRANSPORT_ERR_ARGS:
        return -EINVAL;
    case IEC61850_TRANSPORT_ERR_CONNECT:
        return -ECONNREFUSED;
    case IEC61850_TRANSPORT_ERR_SEND:
    case IEC61850_TRANSPORT_ERR_RECV:
    case IEC61850_TRANSPORT_ERR_ACCEPT:
        return -EIO;
    case IEC61850_TRANSPORT_ERR_TIMEOUT:
        return -ETIMEDOUT;
    case IEC61850_TRANSPORT_ERR_CLOSED:
        return -ECONNRESET;
    case IEC61850_TRANSPORT_ERR_BIND:
    case IEC61850_TRANSPORT_ERR_LISTEN:
        return -EACCES;
    default:
        return ret;
    }
}

/* First slot that can hold a new submission: unused, or holding a
 * delivered-but-unreaped tombstone. */
static iec61850_mms_core_pending_t *pending_slot_free(
    iec61850_mms_client_core_t *core)
{
    size_t i;

    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        if (!core->pending[i].in_use) {
            return &core->pending[i];
        }
    }
    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        if (core->pending[i].delivered) {
            return &core->pending[i];
        }
    }
    return NULL;
}

/* First in-use, undelivered entry matching invoke_id. */
static iec61850_mms_core_pending_t *pending_find_undelivered(
    iec61850_mms_client_core_t *core, uint32_t invoke_id)
{
    size_t i;

    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        iec61850_mms_core_pending_t *entry = &core->pending[i];
        if ((entry->in_use) && (!entry->delivered) &&
            (entry->invoke_id == invoke_id)) {
            return entry;
        }
    }
    return NULL;
}

/* First in-use entry matching invoke_id, delivered or not. */
static iec61850_mms_core_pending_t *pending_find_any(
    iec61850_mms_client_core_t *core, uint32_t invoke_id)
{
    size_t i;

    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        iec61850_mms_core_pending_t *entry = &core->pending[i];
        if ((entry->in_use) && (entry->invoke_id == invoke_id)) {
            return entry;
        }
    }
    return NULL;
}

/* Fail every outstanding entry with err (fatal transport error). */
static void pending_fail_all(iec61850_mms_client_core_t *core, int err)
{
    size_t i;

    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        iec61850_mms_core_pending_t *entry = &core->pending[i];
        iec61850_mms_core_response_cb cb = entry->cb;

        if ((entry->in_use) && (!entry->delivered)) {
            entry->status = err;
            entry->delivered = true;
            if (cb != NULL) {
                cb(err, NULL, NULL, entry->user_data);
            }
        }
        if (!core->attached) {
            /* A callback detached the core; the rest are gone. */
            break;
        }
    }
}

static int64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return ((int64_t)ts.tv_sec * 1000) +
           ((int64_t)ts.tv_nsec / (int64_t)1000000);
}

/* Decode one received MMS PDU and dispatch it. Returns the number of
 * callbacks dispatched (0 or 1) or a negative errno. */
static int dispatch_pdu(iec61850_mms_client_core_t *core,
                         const uint8_t *pdu, size_t pdu_len)
{
    if ((pdu == NULL) || (pdu_len == 0)) {
        return 0;
    }

    switch (pdu[0]) {
    case MMS_TAG_CONFIRMED_RESPONSE: {
        mms_confirmed_response_t response;
        iec61850_mms_core_pending_t *entry;

        (void)memset(&response, 0, sizeof(response));
        if (mms_decode_confirmed_response(pdu, pdu_len, &response) < 0) {
            return -EBADMSG;
        }
        entry = pending_find_undelivered(core, response.invoke_id);
        if (entry == NULL) {
            return 0; /* stale or unmatched response */
        }
        entry->status = 0;
        entry->delivered = true;
        if (entry->cb != NULL) {
            entry->cb(0, &response, NULL, entry->user_data);
        }
        return 1;
    }

    case MMS_TAG_CONFIRMED_ERROR: {
        mms_confirmed_error_t error;
        iec61850_mms_core_pending_t *entry;

        (void)memset(&error, 0, sizeof(error));
        if (mms_decode_confirmed_error(pdu, pdu_len, &error) < 0) {
            return -EBADMSG;
        }
        entry = pending_find_undelivered(core, error.invoke_id);
        if (entry == NULL) {
            return 0; /* stale or unmatched error PDU */
        }
        entry->status = 0;
        entry->delivered = true;
        if (entry->cb != NULL) {
            entry->cb(0, NULL, &error, entry->user_data);
        }
        return 1;
    }

    case MMS_TAG_UNCONFIRMED: {
        mms_information_report_t report;

        if (core->report_cb == NULL) {
            return 0; /* no handler: report discarded */
        }
        (void)memset(&report, 0, sizeof(report));
        if (mms_decode_information_report(pdu, pdu_len, &report) < 0) {
            /* Fall back to the full IEC 61850-7-2 report format
             * (mms_encode_iec61850_report wire format): the generic
             * decoder rejects its different listOfAccessResult tag. */
            (void)memset(&report, 0, sizeof(report));
            if (mms_decode_iec61850_report(pdu, pdu_len, &report) < 0) {
                return -EBADMSG;
            }
        }
        core->report_cb(&report, core->report_user_data);
        return 1;
    }

    default:
        /* Reject, conclude, initiate... not handled by the core. */
        return 0;
    }
}

/* ========================================================================
 * Frozen interface (WP-S1)
 * ======================================================================== */

void iec61850_mms_client_core_init(iec61850_mms_client_core_t *core)
{
    if (core == NULL) { return; }
    (void)memset(core, 0, sizeof(*core));
}

void iec61850_mms_client_core_set_report_handler(
    iec61850_mms_client_core_t *core,
    iec61850_mms_core_report_cb cb, void *user_data)
{
    if (core == NULL) { return; }
    core->report_cb = cb;
    core->report_user_data = user_data;
}

int iec61850_mms_client_core_attach(iec61850_mms_client_core_t *core,
                                     iec61850_iso_conn_t *iso)
{
    if ((core == NULL) || (iso == NULL)) { return -EINVAL; }
    if (core->attached) { return -EBUSY; }
    core->iso = iso;
    core->attached = true;
    return 0;
}

void iec61850_mms_client_core_detach(iec61850_mms_client_core_t *core)
{
    size_t i;

    if (core == NULL) { return; }

    /* Forget the association first so callbacks observe a detached
     * core if they call back into it. */
    core->iso = NULL;
    core->attached = false;

    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        iec61850_mms_core_pending_t *entry = &core->pending[i];
        iec61850_mms_core_response_cb cb = entry->cb;

        if (entry->in_use) {
            entry->status = -ECANCELED;
            entry->delivered = true;
            entry->in_use = false;
            entry->cb = NULL;
            if (cb != NULL) {
                cb(-ECANCELED, NULL, NULL, entry->user_data);
            }
        }
    }
}

int iec61850_mms_client_core_fd(const iec61850_mms_client_core_t *core)
{
    if (core == NULL) { return -EINVAL; }
    if (!core->attached) { return -ENOTCONN; }
    return core->iso->tcp.sockfd;
}

int iec61850_mms_client_core_submit(iec61850_mms_client_core_t *core,
                                     const uint8_t *req, size_t req_len,
                                     uint32_t invoke_id,
                                     iec61850_mms_core_response_cb cb,
                                     void *user_data)
{
    iec61850_mms_core_pending_t *entry;
    int ret;

    if ((core == NULL) || (req == NULL) || (cb == NULL) || (req_len == 0)) {
        return -EINVAL;
    }
    if (!core->attached) { return -ENOTCONN; }

    /* Reserve the slot before sending so a full table never strands a
     * request PDU that could never be correlated. */
    entry = pending_slot_free(core);
    if (entry == NULL) { return -EAGAIN; }

    ret = iec61850_iso_send(core->iso, req, req_len);
    if (ret < 0) { return transport_to_errno(ret); }

    entry->invoke_id = invoke_id;
    entry->in_use = true;
    entry->delivered = false;
    entry->status = 0;
    entry->cb = cb;
    entry->user_data = user_data;
    return 0;
}

int iec61850_mms_client_core_poll(iec61850_mms_client_core_t *core,
                                   int timeout_ms)
{
    uint8_t pdu[IEC61850_ISO_MAX_PDU];
    size_t pdu_len = 0;
    int ret;

    if (core == NULL) { return -EINVAL; }
    if (timeout_ms < 0) { return -EINVAL; }
    if (!core->attached) { return -ENOTCONN; }

    ret = iec61850_iso_recv(core->iso, pdu, sizeof(pdu), &pdu_len,
                             timeout_ms);
    if (ret == 0) {
        return dispatch_pdu(core, pdu, pdu_len);
    }
    if (ret == IEC61850_TRANSPORT_ERR_TIMEOUT) {
        return 0; /* no data within the timeout: zero events */
    }

    ret = transport_to_errno(ret);
    pending_fail_all(core, ret);
    return ret;
}

int iec61850_mms_client_core_wait(iec61850_mms_client_core_t *core,
                                   uint32_t invoke_id, int timeout_ms)
{
    int64_t deadline;
    bool polled = false;

    if ((core == NULL) || (timeout_ms < 0)) { return -EINVAL; }
    deadline = now_ms() + (int64_t)timeout_ms;

    for (;;) {
        iec61850_mms_core_pending_t *entry = pending_find_any(core, invoke_id);
        int ret;

        if (entry == NULL) { return -EINVAL; }
        if (entry->delivered) {
            int status = entry->status;
            entry->in_use = false; /* reap the tombstone */
            return status;
        }

        {
            int64_t remaining = deadline - now_ms();
            int poll_ms;

            if (polled && (remaining <= 0)) { return -ETIMEDOUT; }
            poll_ms = (remaining < 0) ? 0 : ((remaining > (int64_t)INT_MAX)
                                              ? INT_MAX : (int)remaining);
            ret = iec61850_mms_client_core_poll(core, poll_ms);
        }
        polled = true;

        if (ret < 0) {
            /* Fatal transport errors deliver a status to every pending
             * entry; re-check before deciding. -EBADMSG (malformed
             * PDU) leaves the entry pending, so keep waiting. */
            entry = pending_find_any(core, invoke_id);
            if ((entry != NULL) && (entry->delivered)) {
                int status = entry->status;
                entry->in_use = false;
                return status;
            }
            if ((ret == -EINVAL) || (ret == -ENOTCONN)) {
                return ret; /* core detached under us */
            }
        }
    }
}
