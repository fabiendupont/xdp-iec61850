/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client Implementation
 *
 * Blocking MMS client: a thin wrapper over the async client core
 * (mms_client_core.c). Every confirmed service encodes a request,
 * submits it to the core, and blocks in core wait() until the
 * response, error PDU, or a timeout is delivered.
 */


#include "mms/mms_client.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

void iec61850_mms_client_init(iec61850_mms_client_t *client)
{
    if (client == NULL) { return; }

    (void)memset(client, 0, sizeof(*client));
    iec61850_iso_conn_init(&client->iso);
    iec61850_mms_client_core_init(&client->core);
    client->connected = false;
    client->max_pdu_size = 65000;
    client->invoke_id = 0;
    client->request_timeout_ms = 30000;
}

int iec61850_mms_client_connect(iec61850_mms_client_t *client,
                                  const char *host, uint16_t port,
                                  int timeout_ms)
{
    uint8_t mms_init[256];
    mms_initiate_request_t req;
    int ret;

    if ((client == NULL) || (host == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&req, 0, sizeof(req));
    req.proposed_max_pdu_size = client->max_pdu_size;
    req.proposed_data_structure_nesting_level = 4;
    req.proposed_version_number = 1;

    ret = mms_encode_initiate_request(&req, mms_init, sizeof(mms_init));
    if (ret <= 0) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }

#ifdef IEC61850_SECURITY_ENABLED
    if (client->tls_enabled) {
        /* WP-3b: TLS association (IEC 62351-4) — handshake per the
         * configured certificate-policy mode, then the ISO
         * negotiation over the TLS layer. */
        ret = iec61850_iso_connect_tls(&client->iso, host, port,
                                         mms_init, (size_t)ret, timeout_ms,
                                         client->tls_provider,
                                         client->tls_mode);
        if (ret != 0) {
            return IEC61850_MMS_CLIENT_ERR_CONNECT;
        }
    } else
#endif
    {
        ret = iec61850_iso_connect(&client->iso, host, port,
                                     mms_init, (size_t)ret, timeout_ms);
        if (ret != 0) {
            return IEC61850_MMS_CLIENT_ERR_CONNECT;
        }
    }

    ret = iec61850_mms_client_core_attach(&client->core, &client->iso);
    if (ret != 0) {
        (void)iec61850_iso_disconnect(&client->iso);
        return IEC61850_MMS_CLIENT_ERR_CONNECT;
    }

    client->connected = true;
    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_set_tls(iec61850_mms_client_t *client,
                                  const iec61850_cert_provider_t *provider,
                                  iec61850_tls_mode_t mode)
{
#ifdef IEC61850_SECURITY_ENABLED
    if (client == NULL) { return -EINVAL; }
    if (client->connected) { return -EINVAL; }
    if ((mode != IEC61850_TLS_MODE_COMPATIBLE) &&
        (mode != IEC61850_TLS_MODE_STRICT_62351) &&
        (mode != IEC61850_TLS_MODE_SPIFFE)) {
        return -EINVAL;
    }

    client->tls_provider = provider;
    client->tls_mode = mode;
    client->tls_enabled = true;
    return 0;
#else
    (void)client;
    (void)provider;
    (void)mode;
    return -ENOTSUP;
#endif
}

int iec61850_mms_client_disconnect(iec61850_mms_client_t *client)
{
    if (client == NULL) { return IEC61850_MMS_CLIENT_ERR_ARGS; }

    /* Cancel any outstanding core request before tearing down the
     * association the pending entries point at. */
    iec61850_mms_client_core_detach(&client->core);
    (void)iec61850_iso_disconnect(&client->iso);
    client->connected = false;
    return IEC61850_MMS_CLIENT_OK;
}

bool iec61850_mms_client_is_connected(const iec61850_mms_client_t *client)
{
    return (client != NULL) && (client->connected);
}

/* Map a core (negative errno) result to a client error code. */
static int core_err_to_client(int err)
{
    switch (err) {
    case 0:
        return IEC61850_MMS_CLIENT_OK;
    case -EINVAL:
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    case -ENOTCONN:
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    case -EAGAIN:
        return IEC61850_MMS_CLIENT_ERR_BUFFER;
    case -ETIMEDOUT:
        return IEC61850_MMS_CLIENT_ERR_TIMEOUT;
    case -EBADMSG:
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    default:
        return IEC61850_MMS_CLIENT_ERR_TRANSPORT;
    }
}

int iec61850_mms_client_poll(iec61850_mms_client_t *client, int timeout_ms)
{
    int ret;

    if ((client == NULL) || (!client->connected) || (timeout_ms < 0)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    ret = iec61850_mms_client_core_poll(&client->core, timeout_ms);
    if (ret < 0) {
        return core_err_to_client(ret);
    }
    return ret;
}

/* Context handed to the core delivery callback from transact(). */
typedef struct {
    mms_confirmed_response_t *resp;
    bool got_response;
    bool got_error;
} transact_ctx_t;

/* Core delivery callback: copies the decoded PDU into the transact()
 * caller's response buffer before returning (the core's decode buffer
 * is only valid for the duration of the callback). */
static void transact_cb(int status,
                         const mms_confirmed_response_t *response,
                         const mms_confirmed_error_t *error,
                         void *user_data)
{
    transact_ctx_t *ctx = (transact_ctx_t *)user_data;

    if (status != 0) {
        return; /* transport failure: transact maps it from wait() */
    }
    if (response != NULL) {
        *ctx->resp = *response;
        ctx->got_response = true;
    } else if (error != NULL) {
        ctx->got_error = true;
    }
}

/* Silently drop a still-pending entry (no callback) so a timed-out
 * transact() never leaves a callback pointing at dead stack memory. */
static void core_cancel_pending(iec61850_mms_client_core_t *core,
                                 uint32_t invoke_id)
{
    uint32_t i;

    for (i = 0; i < (uint32_t)IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        iec61850_mms_core_pending_t *entry = &core->pending[i];
        if ((entry->in_use) && (!entry->delivered) &&
            (entry->invoke_id == invoke_id)) {
            entry->in_use = false;
            entry->cb = NULL;
        }
    }
}

/* Send confirmed request and receive confirmed response via the core */
static int transact(iec61850_mms_client_t *client,
                      const mms_confirmed_request_t *req,
                      mms_confirmed_response_t *resp)
{
    uint8_t req_buf[4096];
    transact_ctx_t ctx;
    int ret;

    ret = mms_encode_confirmed_request(req, req_buf, sizeof(req_buf));
    if (ret <= 0) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }

    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.resp = resp;

    ret = iec61850_mms_client_core_submit(&client->core, req_buf,
                                            (size_t)ret, req->invoke_id,
                                            transact_cb, &ctx);
    if (ret != 0) { return core_err_to_client(ret); }

    ret = iec61850_mms_client_core_wait(&client->core, req->invoke_id,
                                          client->request_timeout_ms);
    if (ret != 0) {
        /* On timeout (or any abnormal end) the entry may still hold
         * the transact_cb / &ctx pair; drop it before returning. */
        core_cancel_pending(&client->core, req->invoke_id);
        return core_err_to_client(ret);
    }

    if (ctx.got_error) {
        /* ConfirmedError PDU: server rejected the service. */
        return IEC61850_MMS_CLIENT_ERR_MMS;
    }
    if (!ctx.got_response) {
        return IEC61850_MMS_CLIENT_ERR_MMS;
    }

    return IEC61850_MMS_CLIENT_OK;
}

/*
 * WP-2x: the detail variants are public API (mms_client.h). The
 * plain read/write wrappers delegate with a NULL access_error.
 */
int iec61850_mms_client_read_detail(iec61850_mms_client_t *client,
                                      const char *domain,
                                      const char *item_id,
                                      mms_value_t *value,
                                      int32_t *access_error)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    int ret;

    if (access_error != NULL) {
        *access_error = -1;
    }

    if ((client == NULL) || (!client->connected) || (item_id == NULL) ||
        (value == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++;
    req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_READ;
    if (domain != NULL) {
        (void)strncpy(req.params.read.variable_spec.domain, domain,
                        MMS_MAX_DOMAIN_NAME - 1);
    }
    (void)strncpy(req.params.read.variable_spec.item_id, item_id,
                    (size_t)MMS_MAX_VARIABLE_NAME - 1U);

    ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_READ) {
        if (resp.params.read.failure) {
            /* Valid MMS Read-Response carrying a failure AccessResult
             * (WP-1f, BUG-R2): the read was rejected in-band; surface
             * the DataAccessError code to detail callers. */
            if (access_error != NULL) {
                *access_error = resp.params.read.access_error;
            }
            return IEC61850_MMS_CLIENT_ERR_MMS;
        }
        *value = resp.params.read.value;
        return IEC61850_MMS_CLIENT_OK;
    }

    return IEC61850_MMS_CLIENT_ERR_MMS;
}

int iec61850_mms_client_read(iec61850_mms_client_t *client,
                               const char *domain, const char *item_id,
                               mms_value_t *value)
{
    return iec61850_mms_client_read_detail(client, domain, item_id,
                                             value, NULL);
}

int iec61850_mms_client_write(iec61850_mms_client_t *client,
                                const char *domain, const char *item_id,
                                const mms_value_t *value)
{
    return iec61850_mms_client_write_detail(client, domain, item_id,
                                             value, NULL);
}

int iec61850_mms_client_write_detail(iec61850_mms_client_t *client,
                                      const char *domain, const char *item_id,
                                      const mms_value_t *value,
                                      int32_t *access_error)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    int ret;

    if (access_error != NULL) {
        *access_error = -1;
    }

    if ((client == NULL) || (!client->connected) || (item_id == NULL) ||
        (value == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++;
    req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_WRITE;
    if (domain != NULL) {
        (void)strncpy(req.params.write.variable_spec.domain, domain,
                       MMS_MAX_DOMAIN_NAME - 1);
    }
    (void)strncpy(req.params.write.variable_spec.item_id, item_id,
                   (size_t)MMS_MAX_VARIABLE_NAME - 1U);
    req.params.write.value = *value;

    ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_WRITE) {
        if (resp.params.write.failure) {
            /* Write-Response failure CHOICE (WP-1f, BUG-R3): the
             * server rejected the write in-band; surface the
             * DataAccessError code to detail callers. */
            if (access_error != NULL) {
                *access_error = resp.params.write.access_error;
            }
            return IEC61850_MMS_CLIENT_ERR_MMS;
        }
        return IEC61850_MMS_CLIENT_OK;
    }

    return IEC61850_MMS_CLIENT_ERR_MMS;
}

int iec61850_mms_client_get_name_list(iec61850_mms_client_t *client,
                                        mms_object_class_t obj_class,
                                        const char *domain,
                                        char names[][MMS_MAX_VARIABLE_NAME],
                                        uint32_t *count, uint32_t max_count)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    int ret;

    if ((client == NULL) || (!client->connected) || (names == NULL) ||
        (count == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    *count = 0;
    bool has_more = true;
    char continue_after_id[MMS_MAX_VARIABLE_NAME] = {0};
    bool use_continue = false;

    while ((has_more) && (*count < max_count)) {
        (void)memset(&req, 0, sizeof(req));
        client->invoke_id++;
        req.invoke_id = client->invoke_id;
        req.service = MMS_SERVICE_TYPE_GET_NAMELIST;
        req.params.getnamelist.object_class = obj_class;
        if (domain != NULL) {
            (void)strncpy(req.params.getnamelist.domain, domain,
                           MMS_MAX_DOMAIN_NAME - 1);
        }
        if (use_continue) {
            req.params.getnamelist.continue_after = true;
            (void)strncpy(req.params.getnamelist.continue_after_id,
                           continue_after_id, (size_t)MMS_MAX_VARIABLE_NAME - 1U);
        }

        ret = transact(client, &req, &resp);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

        if (resp.service != MMS_SERVICE_TYPE_GET_NAMELIST) {
            return IEC61850_MMS_CLIENT_ERR_MMS;
        }

        for (uint32_t i = 0; (i < resp.params.getnamelist.num_identifiers) &&
             (*count < max_count); i++) {
            (void)strncpy(names[*count], resp.params.getnamelist.identifiers[i],
                           (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            names[*count][(size_t)MMS_MAX_VARIABLE_NAME - 1U] = '\0';
            (*count)++;
        }

        has_more = resp.params.getnamelist.more_follows;
        if ((has_more) && (resp.params.getnamelist.num_identifiers > 0U)) {
            /* Set continue token to last identifier received */
            uint32_t last = resp.params.getnamelist.num_identifiers - 1U;
            (void)strncpy(continue_after_id,
                           resp.params.getnamelist.identifiers[last],
                           (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            use_continue = true;
        } else {
            has_more = false;
        }
    }

    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_get_var_attrs(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *item_id,
                                        mms_variable_access_attrs_t *attrs)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    int ret;

    if ((client == NULL) || (!client->connected) || (item_id == NULL) ||
        (attrs == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++;
    req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS;
    if (domain != NULL) {
        (void)strncpy(req.params.getvariableattrs.variable_spec.domain,
                       domain, MMS_MAX_DOMAIN_NAME - 1);
    }
    (void)strncpy(req.params.getvariableattrs.variable_spec.item_id,
                   item_id, (size_t)MMS_MAX_VARIABLE_NAME - 1U);

    ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS) {
        *attrs = resp.params.getvariableattrs.attributes;
        return IEC61850_MMS_CLIENT_OK;
    }

    return IEC61850_MMS_CLIENT_ERR_MMS;
}

int iec61850_mms_client_identify(iec61850_mms_client_t *client,
                                   char *vendor, char *model, char *revision,
                                   size_t buf_size)
{
    if ((client == NULL) || (!client->connected)) {
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    }

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++; req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_IDENTIFY;

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_IDENTIFY) {
        if (vendor != NULL)
            (void)strncpy(vendor, resp.params.identify.vendor_name, buf_size - 1U);
        if (model != NULL)
            (void)strncpy(model, resp.params.identify.model_name, buf_size - 1U);
        if (revision != NULL)
            (void)strncpy(revision, resp.params.identify.revision, buf_size - 1U);
        return IEC61850_MMS_CLIENT_OK;
    }
    return IEC61850_MMS_CLIENT_ERR_MMS;
}

int iec61850_mms_client_define_named_varlist(
    iec61850_mms_client_t *client,
    const char *domain, const char *list_name,
    const mms_variable_spec_t *vars, uint32_t num_vars)
{
    if ((client == NULL) || (!client->connected)) {
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    }

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++; req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_DEFINE_NAMED_VARLIST;
    (void)strncpy(req.params.definenamedvarlist.domain, domain,
                   MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.definenamedvarlist.list_name, list_name,
                   (size_t)MMS_MAX_VARIABLE_NAME - 1U);
    req.params.definenamedvarlist.num_variables = num_vars;
    for (uint32_t i = 0U; (i < num_vars) && (i < (uint32_t)MMS_MAX_NAMED_VARIABLES); i++) {
        req.params.definenamedvarlist.variables[i] = vars[i];
    }

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_delete_named_varlist(
    iec61850_mms_client_t *client,
    const char *domain, const char *list_name)
{
    if ((client == NULL) || (!client->connected)) {
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    }

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++; req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_DELETE_NAMED_VARLIST;
    (void)strncpy(req.params.deletenamedvarlist.domain, domain,
                   MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.deletenamedvarlist.list_name, list_name,
                   (size_t)MMS_MAX_VARIABLE_NAME - 1U);

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_read_named_varlist(
    iec61850_mms_client_t *client,
    const char *domain, const char *list_name,
    mms_value_t *values, uint32_t *num_values, uint32_t max_values)
{
    if ((client == NULL) || (!client->connected)) {
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    }

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++; req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_READ_NAMED_VARLIST;
    (void)strncpy(req.params.readnamedvarlist.domain, domain,
                   MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.readnamedvarlist.list_name, list_name,
                   (size_t)MMS_MAX_VARIABLE_NAME - 1U);

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_READ_NAMED_VARLIST) {
        if (resp.params.readnamedvarlist.failure) {
            /* A dataset member was answered with a failure
             * AccessResult in-band (WP-1f, BUG-R2). */
            return IEC61850_MMS_CLIENT_ERR_MMS;
        }
        uint32_t n = resp.params.readnamedvarlist.num_values;
        if (n > max_values) { n = max_values; }
        for (uint32_t i = 0; i < n; i++) {
            values[i] = resp.params.readnamedvarlist.values[i];
        }
        *num_values = n;
        return IEC61850_MMS_CLIENT_OK;
    }
    return IEC61850_MMS_CLIENT_ERR_MMS;
}

int iec61850_mms_client_file_directory(
    iec61850_mms_client_t *client,
    const char *file_spec,
    mms_file_entry_t *entries, uint32_t *num_entries,
    uint32_t max_entries)
{
    if ((client == NULL) || (!client->connected)) {
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    }

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++; req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_FILE_DIRECTORY;
    if (file_spec != NULL) {
        (void)strncpy(req.params.filedirectory.file_specification, file_spec,
                       (size_t)MMS_MAX_VARIABLE_NAME - 1U);
    }

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_FILE_DIRECTORY) {
        uint32_t n = resp.params.filedirectory.num_entries;
        if (n > max_entries) { n = max_entries; }
        for (uint32_t i = 0; i < n; i++) {
            entries[i] = resp.params.filedirectory.entries[i];
        }
        *num_entries = n;
        return IEC61850_MMS_CLIENT_OK;
    }
    return IEC61850_MMS_CLIENT_ERR_MMS;
}

int iec61850_mms_client_file_open(
    iec61850_mms_client_t *client,
    const char *filename, uint32_t *file_handle, uint32_t *file_size) /* NOLINT(bugprone-easily-swappable-parameters) */
{
    if ((client == NULL) || (!client->connected)) {
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    }

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++; req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_FILE_OPEN;
    (void)strncpy(req.params.fileopen.filename, filename,
                   (size_t)MMS_MAX_VARIABLE_NAME - 1U);

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_FILE_OPEN) {
        *file_handle = resp.params.fileopen.file_handle;
        *file_size = (uint32_t)resp.params.fileopen.file_size;
        return IEC61850_MMS_CLIENT_OK;
    }
    return IEC61850_MMS_CLIENT_ERR_MMS;
}

int iec61850_mms_client_file_read(
    iec61850_mms_client_t *client,
    uint32_t file_handle, uint8_t *data, uint32_t *data_len,
    uint32_t max_len, bool *more_follows)
{
    if ((client == NULL) || (!client->connected)) {
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    }

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++; req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_FILE_READ;
    req.params.fileread.file_handle = file_handle;

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_FILE_READ) {
        uint32_t n = resp.params.fileread.bytes_read;
        if (n > max_len) { n = max_len; }
        (void)memcpy(data, resp.params.fileread.data, n);
        *data_len = n;
        *more_follows = resp.params.fileread.more_follows;
        return IEC61850_MMS_CLIENT_OK;
    }
    return IEC61850_MMS_CLIENT_ERR_MMS;
}

int iec61850_mms_client_file_close(
    iec61850_mms_client_t *client, uint32_t file_handle)
{
    if ((client == NULL) || (!client->connected)) {
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    }

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++; req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_FILE_CLOSE;
    req.params.fileclose.file_handle = file_handle;

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    return IEC61850_MMS_CLIENT_OK;
}

/* ========================================================================
 * WP-2w: IEC 61850-8-1 Ed.2 control-object helpers
 * ======================================================================== */

/* Append a TLV (bounded; long-form lengths up to 2 length bytes). */
static size_t cw_cli_put_tlv(uint8_t *buf, size_t cap, size_t pos,
                              uint8_t tag, const uint8_t *content,
                              size_t len)
{
    size_t need;

    if (len < 128U) {
        need = 1U + 1U + len;
    } else if (len < 256U) {
        need = 1U + 2U + len;
    } else {
        need = 1U + 3U + len;
    }
    if ((pos + need) > cap) { return 0U; }
    buf[pos++] = tag;
    if (len < 128U) {
        buf[pos++] = (uint8_t)len;
    } else if (len < 256U) {
        buf[pos++] = 0x81U;
        buf[pos++] = (uint8_t)len;
    } else {
        buf[pos++] = 0x82U;
        buf[pos++] = (uint8_t)(len >> 8);
        buf[pos++] = (uint8_t)(len & 0xFFU);
    }
    if (len > 0U) {
        (void)memcpy(buf + pos, content, len);
        pos += len;
    }
    return pos;
}

/* Current UTC time in milliseconds (the Oper structure's T). */
static uint64_t cw_cli_now_utc_ms(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) +
           ((uint64_t)ts.tv_nsec / 1000000ULL);
}

/*
 * IEC 61850-8-1 UTC-Time (MMS UtcTime): 4-byte seconds since the Unix
 * epoch, 3-byte binary fraction of a second, 1-byte time quality
 * (0 = clock OK, not synchronized, full accuracy).
 */
static void cw_cli_put_utc_time(uint8_t *out, uint64_t utc_ms)
{
    uint32_t sec = (uint32_t)(utc_ms / 1000ULL);
    uint32_t frac =
        (uint32_t)(((utc_ms % 1000ULL) * 16777216ULL) / 1000ULL);

    out[0] = (uint8_t)(sec >> 24);
    out[1] = (uint8_t)(sec >> 16);
    out[2] = (uint8_t)(sec >> 8);
    out[3] = (uint8_t)sec;
    out[4] = (uint8_t)(frac >> 16);
    out[5] = (uint8_t)(frac >> 8);
    out[6] = (uint8_t)frac;
    out[7] = 0U;   /* TimeQuality */
}

/*
 * Build the 8-1 originator-controlled Oper structure as a raw BER TLV
 * stashed in an mms_value_t (MMS_TYPE_STRUCTURE — see
 * mms_encode_value()/mms_decode_value()).
 *
 * Immediate form (6 elements): ctlVal, origin, ctlNum, T, Test, Check.
 * Time-activated form (7 elements, operTm second) when
 * params->oper_tm_utc_ms != 0.
 */
static int cw_cli_build_oper(const iec61850_mms_client_operate_params_t *p,
                              bool cancel_form,
                              mms_value_t *out)
{
    uint8_t ctl_val_buf[4];
    uint8_t origin_buf[96];
    uint8_t ctl_num_buf[8];
    uint8_t t_buf[8];
    uint8_t test_buf[4];
    uint8_t check_buf[4];
    uint8_t body[192];
    size_t body_len = 0U;
    size_t origin_len = 0U;
    size_t ctl_val_len;
    size_t ctl_num_len;
    size_t check_len;
    uint32_t ctl_num = p->ctl_num;
    uint8_t check_bits = (uint8_t)((p->check_interlock ? 0x40U : 0U) |
                                   (p->check_synchro ? 0x80U : 0U));

    (void)memset(out, 0, sizeof(*out));

    /* ctlVal — BOOLEAN (FALSE for the cancel form) */
    ctl_val_buf[0] = (cancel_form || !p->ctl_val) ? 0x00U : 0xFFU;
    ctl_val_len = 1U;

    /* origin: SEQUENCE { orCat INTEGER, orIdent OCTET STRING } */
    {
        uint8_t cat_buf[4];
        size_t cat_len = 0U;
        const char *ident = (p->origin_ident != NULL) ? p->origin_ident : "";
        size_t ident_len = strlen(ident);

        if (ident_len > 64U) { ident_len = 64U; }
        cat_buf[cat_len++] =
            (uint8_t)((uint32_t)p->origin_cat & 0xFFU);
        origin_len = cw_cli_put_tlv(origin_buf, sizeof(origin_buf),
                                     origin_len, 0x85U, cat_buf, cat_len);
        if (origin_len == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }
        origin_len = cw_cli_put_tlv(origin_buf, sizeof(origin_buf),
                                     origin_len, 0x89U,
                                     (const uint8_t *)ident, ident_len);
        if (origin_len == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }
    }

    /* ctlNum — UNSIGNED */
    ctl_num_len = 0U;
    if ((ctl_num == 0U) || (ctl_num > 0xFFFFFFU)) {
        ctl_num_buf[ctl_num_len++] = (uint8_t)(ctl_num & 0xFFU);
    } else {
        uint8_t tmp[4];
        size_t n = 0U;

        while (ctl_num > 0U) {
            tmp[n++] = (uint8_t)(ctl_num & 0xFFU);
            ctl_num >>= 8;
        }
        while (n > 0U) {
            ctl_num_buf[ctl_num_len++] = tmp[--n];
        }
    }

    /* T — UTC_TIME (8 bytes) */
    cw_cli_put_utc_time(t_buf, cw_cli_now_utc_ms());

    /* Test — BOOLEAN */
    test_buf[0] = p->test ? 0xFFU : 0x00U;

    /* Check — BIT STRING (2 bits: synchrocheck, interlock-check) */
    check_buf[0] = 6U;   /* unused bits */
    check_buf[1] = check_bits;
    check_len = 2U;

    /* Assemble the structure body positionally per 8-1. */
    body_len = cw_cli_put_tlv(body, sizeof(body), body_len,
                               (uint8_t)MMS_DATA_BOOLEAN, ctl_val_buf,
                               ctl_val_len);
    if (body_len == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }
    if (p->oper_tm_utc_ms != 0ULL) {
        uint8_t oper_tm_buf[8];

        cw_cli_put_utc_time(oper_tm_buf, p->oper_tm_utc_ms);
        body_len = cw_cli_put_tlv(body, sizeof(body), body_len,
                                   (uint8_t)MMS_DATA_UTC_TIME, oper_tm_buf,
                                   8U);
        if (body_len == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }
    }
    body_len = cw_cli_put_tlv(body, sizeof(body), body_len,
                               (uint8_t)MMS_DATA_STRUCTURE, origin_buf,
                               origin_len);
    if (body_len == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }
    body_len = cw_cli_put_tlv(body, sizeof(body), body_len,
                               (uint8_t)MMS_DATA_UNSIGNED, ctl_num_buf,
                               ctl_num_len);
    if (body_len == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }
    body_len = cw_cli_put_tlv(body, sizeof(body), body_len,
                               (uint8_t)MMS_DATA_UTC_TIME, t_buf, 8U);
    if (body_len == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }
    body_len = cw_cli_put_tlv(body, sizeof(body), body_len,
                               (uint8_t)MMS_DATA_BOOLEAN, test_buf, 1U);
    if (body_len == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }
    body_len = cw_cli_put_tlv(body, sizeof(body), body_len,
                               (uint8_t)MMS_DATA_BIT_STRING, check_buf,
                               check_len);
    if (body_len == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }

    /* Stash the full structure TLV (tag + length + body). */
    out->type = MMS_TYPE_STRUCTURE;
    if ((body_len + 4U) > MMS_MAX_STRING_LENGTH) {
        return IEC61850_MMS_CLIENT_ERR_ENCODE;
    }
    {
        size_t pos = cw_cli_put_tlv(out->value.octet_string.data,
                                     MMS_MAX_STRING_LENGTH, 0U,
                                     (uint8_t)MMS_DATA_STRUCTURE, body,
                                     body_len);

        if (pos == 0U) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }
        out->value.octet_string.len = pos;
    }
    return IEC61850_MMS_CLIENT_OK;
}

/* Bounded "base + suffix" item-name builder (no truncation: fails
 * when the composed name does not fit). */
static int cw_cli_item_suffix(char *out, size_t out_size,
                               const char *base, const char *suffix)
{
    size_t bl = strlen(base);
    size_t sl = strlen(suffix);

    if ((bl + sl + 1U) > out_size) { return -EINVAL; }
    (void)memcpy(out, base, bl);
    (void)memcpy(out + bl, suffix, sl + 1U);
    return 0;
}

/* Write an mms_value_t to "<item_id><suffix>". */
static int cw_cli_write_component(iec61850_mms_client_t *client,
                                   const char *domain, const char *item_id,
                                   const char *suffix,
                                   const mms_value_t *value)
{
    char item[MMS_MAX_VARIABLE_NAME];

    if (cw_cli_item_suffix(item, sizeof(item), item_id, suffix) != 0) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }
    return iec61850_mms_client_write(client, domain, item, value);
}

int iec61850_mms_client_select(iec61850_mms_client_t *client,
                                const char *domain, const char *item_id)
{
    char item[MMS_MAX_VARIABLE_NAME];
    mms_value_t v;
    int ret;

    if ((client == NULL) || (!client->connected) || (domain == NULL) ||
        (item_id == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }
    if (cw_cli_item_suffix(item, sizeof(item), item_id, "$SBO") != 0) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    /* 8-1 sbo-with-normal-security: the select is a Read of the SBO
     * attribute; the server answers with the selected object's
     * reference ("<domain>/<LN>$CO$<DO>") on success. */
    (void)memset(&v, 0, sizeof(v));
    ret = iec61850_mms_client_read(client, domain, item, &v);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if ((v.type != MMS_TYPE_VISIBLE_STRING) ||
        (v.value.visible_string.len == 0U)) {
        return IEC61850_MMS_CLIENT_ERR_MMS;
    }
    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_select_with_value(
    iec61850_mms_client_t *client, const char *domain,
    const char *item_id, bool ctl_val)
{
    iec61850_mms_client_operate_params_t params;
    mms_value_t v;
    int ret;

    if ((client == NULL) || (!client->connected) || (domain == NULL) ||
        (item_id == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&params, 0, sizeof(params));
    params.ctl_val = ctl_val;
    ret = cw_cli_build_oper(&params, false, &v);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    return cw_cli_write_component(client, domain, item_id, "$SBOw", &v);
}

int iec61850_mms_client_operate(
    iec61850_mms_client_t *client, const char *domain,
    const char *item_id,
    const iec61850_mms_client_operate_params_t *params)
{
    mms_value_t v;
    int ret;

    if ((client == NULL) || (!client->connected) || (domain == NULL) ||
        (item_id == NULL) || (params == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    ret = cw_cli_build_oper(params, false, &v);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    return cw_cli_write_component(client, domain, item_id, "$Oper", &v);
}

int iec61850_mms_client_cancel(iec61850_mms_client_t *client,
                                const char *domain, const char *item_id)
{
    iec61850_mms_client_operate_params_t params;
    mms_value_t v;
    int ret;

    if ((client == NULL) || (!client->connected) || (domain == NULL) ||
        (item_id == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&params, 0, sizeof(params));
    ret = cw_cli_build_oper(&params, true, &v);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    return cw_cli_write_component(client, domain, item_id, "$Cancel", &v);
}

/* CF-first / CO-fallback attribute read (helper for ctlModel /
 * sboTimeout; suffix carries the attribute name). */
static int cw_cli_read_attribute(iec61850_mms_client_t *client,
                                  const char *domain, const char *item_id,
                                  const char *attr, mms_value_t *out)
{
    char item[MMS_MAX_VARIABLE_NAME];
    const char *co = strstr(item_id, "$CO$");
    int ret;

    if (co != NULL) {
        size_t head = (size_t)(co - item_id);
        size_t tail_len = strlen(co + 4);
        size_t attr_len = strlen(attr);

        /* "<head>$CF$<rest><attr>" — built manually (bounded). */
        if ((head + 4U + tail_len + attr_len + 1U) <= sizeof(item)) {
            (void)memcpy(item, item_id, head);
            (void)memcpy(item + head, "$CF$", 4U);
            (void)memcpy(item + head + 4U, co + 4, tail_len);
            (void)memcpy(item + head + 4U + tail_len, attr, attr_len + 1U);
            ret = iec61850_mms_client_read(client, domain, item, out);
            if (ret == (int)IEC61850_MMS_CLIENT_OK) { return ret; }
        }
    }
    if (cw_cli_item_suffix(item, sizeof(item), item_id, attr) != 0) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }
    return iec61850_mms_client_read(client, domain, item, out);
}

int iec61850_mms_client_read_ctl_model(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *item_id,
                                        int32_t *ctl_model)
{
    mms_value_t v;
    int ret;

    if ((client == NULL) || (ctl_model == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }
    (void)memset(&v, 0, sizeof(v));
    ret = cw_cli_read_attribute(client, domain, item_id, "$ctlModel", &v);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (v.type != MMS_TYPE_INTEGER) {
        return IEC61850_MMS_CLIENT_ERR_MMS;
    }
    *ctl_model = v.value.integer;
    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_read_sbo_timeout(iec61850_mms_client_t *client,
                                          const char *domain,
                                          const char *item_id,
                                          uint32_t *sbo_timeout_ms)
{
    mms_value_t v;
    int ret;

    if ((client == NULL) || (sbo_timeout_ms == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }
    (void)memset(&v, 0, sizeof(v));
    ret = cw_cli_read_attribute(client, domain, item_id, "$sboTimeout", &v);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (v.type != MMS_TYPE_UNSIGNED) {
        return IEC61850_MMS_CLIENT_ERR_MMS;
    }
    *sbo_timeout_ms = v.value.unsigned_val;
    return IEC61850_MMS_CLIENT_OK;
}

/* Core-hook shim: routes the core-level CommandTermination delivery
 * to this client's handler. */
static void cw_cli_termination_shim(
    const iec61850_mms_client_command_termination_t *termination,
    void *user_data)
{
    /* MISRA 11.5: callback context is the client, deviation Cat. 3 */
    iec61850_mms_client_t *client =
        (iec61850_mms_client_t *)user_data;

    if ((client != NULL) && (client->command_termination_cb != NULL)) {
        client->command_termination_cb(termination,
                                       client->command_termination_user_data);
    }
}

void iec61850_mms_client_set_command_termination_handler(
    iec61850_mms_client_t *client,
    iec61850_mms_client_command_termination_cb_t cb, void *user_data)
{
    if (client == NULL) { return; }
    client->command_termination_cb = cb;
    client->command_termination_user_data = user_data;
    iec61850_mms_client_core_set_command_termination_handler(
        cw_cli_termination_shim, (void *)client);
}
