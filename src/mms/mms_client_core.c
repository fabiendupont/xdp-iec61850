/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client Async Core for IEC 61850
 *
 * WP-S1 scaffold: lifecycle operations are implemented; the event
 * loop, request submission, and dispatch are implemented by WP-1a
 * (client-core) against the frozen interface in
 * include/iec61850/mms/mms_client_core.h.
 */

#include "mms/mms_client_core.h"

#include <errno.h>
#include <string.h>

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
    if (core == NULL) { return; }
    /* Cancel any pending entries (callbacks fire with -ECANCELED once
     * WP-1a implements submission; the scaffold has none). */
    (void)memset(core->pending, 0, sizeof(core->pending));
    core->iso = NULL;
    core->attached = false;
}

int iec61850_mms_client_core_fd(const iec61850_mms_client_core_t *core)
{
    if (core == NULL) { return -EINVAL; }
    if (!core->attached) { return -ENOTCONN; }
    return -ENOSYS; /* implemented by WP-1a */
}

int iec61850_mms_client_core_submit(iec61850_mms_client_core_t *core,
                                     const uint8_t *req, size_t req_len,
                                     uint32_t invoke_id,
                                     iec61850_mms_core_response_cb cb,
                                     void *user_data)
{
    (void)req;
    (void)req_len;
    (void)invoke_id;
    (void)cb;
    (void)user_data;
    if (core == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-1a */
}

int iec61850_mms_client_core_poll(iec61850_mms_client_core_t *core,
                                   int timeout_ms)
{
    (void)timeout_ms;
    if (core == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-1a */
}

int iec61850_mms_client_core_wait(iec61850_mms_client_core_t *core,
                                   uint32_t invoke_id, int timeout_ms)
{
    (void)invoke_id;
    (void)timeout_ms;
    if (core == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-1a */
}
