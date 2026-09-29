/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client Implementation
 *
 * Blocking MMS client using ISO stack transport.
 */


#include "mms/mms_client.h"
#include <string.h>
#include <errno.h>

void iec61850_mms_client_init(iec61850_mms_client_t *client)
{
    if (client == NULL) { return; }

    (void)memset(client, 0, sizeof(*client));
    iec61850_iso_conn_init(&client->iso);
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

    ret = iec61850_iso_connect(&client->iso, host, port,
                                 mms_init, (size_t)ret, timeout_ms);
    if (ret != 0) {
        return IEC61850_MMS_CLIENT_ERR_CONNECT;
    }

    client->connected = true;
    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_disconnect(iec61850_mms_client_t *client)
{
    if (client == NULL) { return IEC61850_MMS_CLIENT_ERR_ARGS; }

    iec61850_iso_disconnect(&client->iso);
    client->connected = false;
    return IEC61850_MMS_CLIENT_OK;
}

bool iec61850_mms_client_is_connected(const iec61850_mms_client_t *client)
{
    return (client != NULL) && (client->connected);
}

/* Send confirmed request and receive confirmed response */
static int transact(iec61850_mms_client_t *client,
                      const mms_confirmed_request_t *req,
                      mms_confirmed_response_t *resp)
{
    uint8_t req_buf[4096];
    uint8_t resp_buf[IEC61850_ISO_MAX_PDU];
    size_t resp_len;
    int ret;

    ret = mms_encode_confirmed_request(req, req_buf, sizeof(req_buf));
    if (ret <= 0) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }

    ret = iec61850_iso_send(&client->iso, req_buf, (size_t)ret);
    if (ret < 0) { return IEC61850_MMS_CLIENT_ERR_TRANSPORT; }

    ret = iec61850_iso_recv(&client->iso, resp_buf, sizeof(resp_buf),
                              &resp_len, client->request_timeout_ms);
    if (ret != 0) { return IEC61850_MMS_CLIENT_ERR_TRANSPORT; }

    ret = mms_decode_confirmed_response(resp_buf, resp_len, resp);
    if (ret < 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_read(iec61850_mms_client_t *client,
                               const char *domain, const char *item_id,
                               mms_value_t *value)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    int ret;

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
        *value = resp.params.read.value;
        return IEC61850_MMS_CLIENT_OK;
    }

    return IEC61850_MMS_CLIENT_ERR_MMS;
}

int iec61850_mms_client_write(iec61850_mms_client_t *client,
                                const char *domain, const char *item_id,
                                const mms_value_t *value)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    int ret;

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
    req.invoke_id = ++client->invoke_id;
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
    req.invoke_id = ++client->invoke_id;
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
    req.invoke_id = ++client->invoke_id;
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
    req.invoke_id = ++client->invoke_id;
    req.service = MMS_SERVICE_TYPE_READ_NAMED_VARLIST;
    (void)strncpy(req.params.readnamedvarlist.domain, domain,
                   MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.readnamedvarlist.list_name, list_name,
                   (size_t)MMS_MAX_VARIABLE_NAME - 1U);

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_READ_NAMED_VARLIST) {
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
    req.invoke_id = ++client->invoke_id;
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
    const char *filename, uint32_t *file_handle, uint32_t *file_size)
{
    if ((client == NULL) || (!client->connected)) {
        return IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED;
    }

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    req.invoke_id = ++client->invoke_id;
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
    req.invoke_id = ++client->invoke_id;
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
    req.invoke_id = ++client->invoke_id;
    req.service = MMS_SERVICE_TYPE_FILE_CLOSE;
    req.params.fileclose.file_handle = file_handle;

    int ret = transact(client, &req, &resp);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    return IEC61850_MMS_CLIENT_OK;
}
