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
#include "mms/mms_client.h"

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
static int ct_try_deliver(const uint8_t *pdu, size_t pdu_len);

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
        /* A decoded confirmed response is DELIVERED (status 0) even
         * when it carries an in-band service failure — e.g. a
         * Read-Response failure AccessResult or a Write-Response
         * failure CHOICE (WP-1f, BUG-R2/R3): those are valid MMS
         * PDUs, not malformed ones. Only an undecodable PDU is
         * -EBADMSG (which fails no entry). */
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

        if (core->report_cb != NULL) {
            (void)memset(&report, 0, sizeof(report));
            if (mms_decode_information_report(pdu, pdu_len, &report) < 0) {
                /* Fall back to the full IEC 61850-7-2 report format
                 * (mms_encode_iec61850_report wire format): the generic
                 * decoder rejects its different listOfAccessResult tag. */
                (void)memset(&report, 0, sizeof(report));
                if (mms_decode_iec61850_report(pdu, pdu_len, &report) < 0) {
                    /* WP-2w: neither report decoder matches — the PDU
                     * may be an IEC 61850-8-1 CommandTermination (an
                     * InformationReport on the operated "$Oper" object
                     * whose listOfAccessResult is tagged [0]). */
                    if (ct_try_deliver(pdu, pdu_len) == 1) {
                        return 1;
                    }
                    return -EBADMSG;
                }
            }
            core->report_cb(&report, core->report_user_data);
            return 1;
        }

        /* No report handler: a CommandTermination still delivers
         * (WP-2w); anything else is discarded as before. */
        return (ct_try_deliver(pdu, pdu_len) == 1) ? 1 : 0;
    }

    default:
        /* Reject, conclude, initiate... not handled by the core. */
        return 0;
    }
}

/* ========================================================================
 * WP-2w: unsolicited CommandTermination dispatch
 * ======================================================================== */

/* Process-global delivery hook (the core header is a frozen
 * interface, so the hook lives in the implementation and is declared
 * in mms_client.h). See the limitation note on
 * iec61850_mms_client_set_command_termination_handler(). */
static iec61850_mms_client_command_termination_cb_t g_ct_cb;
static void *g_ct_user_data;

void iec61850_mms_client_core_set_command_termination_handler(
    iec61850_mms_client_command_termination_cb_t cb, void *user_data)
{
    g_ct_cb = cb;
    g_ct_user_data = user_data;
}

/* Read one BER TLV header (bounded; long-form lengths up to 4). */
static int ct_read_tlv(const uint8_t *buf, size_t len, size_t *pos,
                        uint8_t *tag, const uint8_t **content,
                        size_t *content_len)
{
    size_t p = *pos;
    size_t vlen = 0U;
    uint8_t b;
    uint32_t i;

    if ((p + 2U) > len) { return -EINVAL; }
    *tag = buf[p++];
    b = buf[p++];
    if ((b & 0x80U) == 0U) {
        vlen = b;
    } else {
        uint32_t n = (uint32_t)(b & 0x7FU);

        if ((n == 0U) || (n > 4U) || ((p + n) > len)) { return -EINVAL; }
        for (i = 0U; i < n; i++) {
            vlen = (vlen << 8) | (uint32_t)buf[p++];
        }
    }
    if ((p + vlen) > len) { return -EINVAL; }
    *content = &buf[p];
    *content_len = vlen;
    *pos = p + vlen;
    return 0;
}

static uint64_t ct_be_uint(const uint8_t *b, size_t len)
{
    uint64_t v = 0U;
    size_t i;

    for (i = 0U; i < len; i++) {
        v = (v << 8) | (uint64_t)b[i];
    }
    return v;
}

/* IEC 61850-8-1 UTC-Time (4-byte seconds + 3-byte binary fraction +
 * 1-byte time quality) to UTC milliseconds. */
static uint64_t ct_utc_time_ms(const uint8_t *b)
{
    uint64_t sec = ct_be_uint(b, 4U);
    uint32_t frac = (uint32_t)ct_be_uint(b + 4, 3U);

    return (sec * 1000ULL) + (((uint64_t)frac * 1000ULL) / 16777216ULL);
}

/*
 * Parse the IEC 61850-8-1 CommandTermination PDU: an unconfirmed-PDU
 * [3] wrapping an informationReport [0] on the operated "$Oper"
 * object whose single AccessResult echoes the Oper structure. Both
 * variableAccessSpecification CHOICE spellings seen on the wire
 * (listOfVariable [0] and variableListName [1]) are accepted.
 */
static int ct_parse(const uint8_t *pdu, size_t pdu_len,
                     iec61850_mms_client_command_termination_t *out)
{
    const uint8_t *content;
    const uint8_t *vas;
    const uint8_t *vas_body;
    const uint8_t *echo;
    size_t content_len;
    size_t vas_len;
    size_t vas_body_len;
    size_t echo_len;
    size_t pos = 0U;
    size_t rpos = 0U;
    uint8_t tag;

    (void)memset(out, 0, sizeof(*out));

    if ((pdu == NULL) || (pdu_len < 2U)) { return -EINVAL; }

    /* unconfirmed-PDU [3] { informationReport [0] } */
    if (ct_read_tlv(pdu, pdu_len, &pos, &tag, &content, &content_len) != 0) {
        return -EINVAL;
    }
    if (tag != (uint8_t)MMS_TAG_UNCONFIRMED) { return -EINVAL; }

    /* informationReport [0] { VAS, listOfAccessResult } — remember
     * where the results start (rpos) before parsing the VAS. */
    pos = 0U;
    if (ct_read_tlv(content, content_len, &rpos, &tag, &vas,
                    &vas_len) != 0) {
        return -EINVAL;
    }
    if (tag != 0xA0U) { return -EINVAL; }   /* informationReport [0] */
    if (ct_read_tlv(vas, vas_len, &pos, &tag, &vas_body,
                    &vas_body_len) != 0) {
        return -EINVAL;
    }
    /* pos = offset just past the VAS TLV (start of the results) */

    /* variableAccessSpecification -> domain-specific name */
    {
        const uint8_t *ds = vas_body;
        size_t ds_len = vas_body_len;
        const uint8_t *dom;
        size_t dom_len;
        const uint8_t *item;
        size_t item_len;
        size_t dpos = 0U;

        if (tag == 0xA0U) {
            /* listOfVariable [0] { SEQUENCE { name [0] { ... } } } */
            if (ct_read_tlv(ds, ds_len, &dpos, &tag, &ds,
                            &ds_len) != 0) {
                return -EINVAL;
            }
            if (tag != 0x30U) { return -EINVAL; }
            dpos = 0U;
            if (ct_read_tlv(ds, ds_len, &dpos, &tag, &ds, &ds_len) != 0) {
                return -EINVAL;
            }
            if (tag != 0xA0U) { return -EINVAL; }
            dpos = 0U;
            if (ct_read_tlv(ds, ds_len, &dpos, &tag, &ds, &ds_len) != 0) {
                return -EINVAL;
            }
            if (tag != 0xA1U) { return -EINVAL; }
        } else if (tag == 0xA1U) {
            /* variableListName [1] { domain-specific [1] { ... } } */
            dpos = 0U;
            if (ct_read_tlv(ds, ds_len, &dpos, &tag, &ds, &ds_len) != 0) {
                return -EINVAL;
            }
            if (tag != 0xA1U) { return -EINVAL; }
        } else {
            return -EINVAL;
        }

        dpos = 0U;
        if (ct_read_tlv(ds, ds_len, &dpos, &tag, &dom, &dom_len) != 0) {
            return -EINVAL;
        }
        if ((tag != 0x1AU) || (dom_len >= MMS_MAX_DOMAIN_NAME)) {
            return -EINVAL;
        }
        (void)memcpy(out->domain, dom, dom_len);
        if (ct_read_tlv(ds, ds_len, &dpos, &tag, &item, &item_len) != 0) {
            return -EINVAL;
        }
        if ((tag != 0x1AU) || (item_len >= MMS_MAX_VARIABLE_NAME)) {
            return -EINVAL;
        }
        (void)memcpy(out->item_id, item, item_len);
    }

    /* listOfAccessResult [0] { AccessResult: structure (the echoed
     * Oper) } — parsed positionally like cw_parse_oper() on the
     * server side. */
    if (ct_read_tlv(vas, vas_len, &pos, &tag, &echo, &echo_len) != 0) {
        return -EINVAL;
    }
    if (tag != 0xA0U) { return -EINVAL; }
    pos = 0U;
    if (ct_read_tlv(echo, echo_len, &pos, &tag, &content,
                    &content_len) != 0) {
        return -EINVAL;
    }
    if (tag != (uint8_t)MMS_DATA_STRUCTURE) { return -EINVAL; }

    {
        const uint8_t *body = content;
        size_t body_len = content_len;
        size_t bpos = 0U;

        /* ctlVal */
        if (ct_read_tlv(body, body_len, &bpos, &tag, &content,
                        &content_len) != 0) {
            return -EINVAL;
        }
        if (tag == (uint8_t)MMS_DATA_BOOLEAN) {
            out->ctl_val = (content_len > 0U) && (content[0] != 0U);
        } else if (tag == (uint8_t)MMS_DATA_BIT_STRING) {
            out->ctl_val = (content_len > 1U) && (content[1] != 0U);
        } else {
            return -EINVAL;
        }

        /* operTm (time-activated form) or origin */
        if (ct_read_tlv(body, body_len, &bpos, &tag, &content,
                        &content_len) != 0) {
            return -EINVAL;
        }
        if (tag == (uint8_t)MMS_DATA_UTC_TIME) {
            if (ct_read_tlv(body, body_len, &bpos, &tag, &content,
                            &content_len) != 0) {
                return -EINVAL;
            }
        }
        if (tag == (uint8_t)MMS_DATA_STRUCTURE) {
            const uint8_t *org = content;
            size_t org_len = content_len;
            size_t opos = 0U;

            if (ct_read_tlv(org, org_len, &opos, &tag, &content,
                            &content_len) == 0) {
                if (tag == (uint8_t)MMS_DATA_INTEGER) {
                    out->origin_cat = (content_len > 0U)
                                          ? (int32_t)content[content_len - 1U]
                                          : 0;
                }
            }
            if (ct_read_tlv(org, org_len, &opos, &tag, &content,
                            &content_len) == 0) {
                if ((tag == (uint8_t)MMS_DATA_OCTET_STRING) &&
                    (content_len <= sizeof(out->origin_ident))) {
                    if (content_len > 0U) {
                        (void)memcpy(out->origin_ident, content,
                                     content_len);
                    }
                    out->origin_ident_len = content_len;
                }
            }
        }

        /* ctlNum, T (both optional in a degraded echo) */
        if (ct_read_tlv(body, body_len, &bpos, &tag, &content,
                        &content_len) == 0) {
            if (tag == (uint8_t)MMS_DATA_UNSIGNED) {
                out->ctl_num = (uint32_t)ct_be_uint(content, content_len);
            }
            if (ct_read_tlv(body, body_len, &bpos, &tag, &content,
                            &content_len) == 0) {
                if ((tag == (uint8_t)MMS_DATA_UTC_TIME) &&
                    (content_len == 8U)) {
                    out->timestamp_ms = ct_utc_time_ms(content);
                }
            }
        }
    }
    return 0;
}

/*
 * WP-2w: try delivering an unconfirmed PDU as a CommandTermination.
 * Returns 1 when delivered to the hook, 0 when no hook is installed
 * or the PDU does not parse as one.
 */
static int ct_try_deliver(const uint8_t *pdu, size_t pdu_len)
{
    iec61850_mms_client_command_termination_t ct;

    if (g_ct_cb == NULL) { return 0; }
    if (ct_parse(pdu, pdu_len, &ct) != 0) { return 0; }
    g_ct_cb(&ct, g_ct_user_data);
    return 1;
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
