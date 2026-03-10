/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client Implementation
 *
 * Blocking MMS client using ISO stack transport.
 */

#define _POSIX_C_SOURCE 200809L

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

    if (client == NULL || host == NULL) {
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
    return client != NULL && client->connected;
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
    if (ret < 0) { return IEC61850_MMS_CLIENT_ERR_DECODE; }

    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_read(iec61850_mms_client_t *client,
                               const char *domain, const char *item_id,
                               mms_value_t *value)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    int ret;

    if (client == NULL || !client->connected || item_id == NULL ||
        value == NULL) {
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
                   MMS_MAX_VARIABLE_NAME - 1);

    ret = transact(client, &req, &resp);
    if (ret != IEC61850_MMS_CLIENT_OK) { return ret; }

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

    if (client == NULL || !client->connected || item_id == NULL ||
        value == NULL) {
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
                   MMS_MAX_VARIABLE_NAME - 1);
    req.params.write.value = *value;

    ret = transact(client, &req, &resp);
    if (ret != IEC61850_MMS_CLIENT_OK) { return ret; }

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

    if (client == NULL || !client->connected || names == NULL ||
        count == NULL) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++;
    req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_GET_NAMELIST;
    req.params.getnamelist.object_class = obj_class;
    if (domain != NULL) {
        (void)strncpy(req.params.getnamelist.domain, domain,
                       MMS_MAX_DOMAIN_NAME - 1);
    }

    ret = transact(client, &req, &resp);
    if (ret != IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service != MMS_SERVICE_TYPE_GET_NAMELIST) {
        return IEC61850_MMS_CLIENT_ERR_MMS;
    }

    *count = 0;
    for (uint32_t i = 0; i < resp.params.getnamelist.num_identifiers &&
         i < max_count; i++) {
        (void)strncpy(names[i], resp.params.getnamelist.identifiers[i],
                       MMS_MAX_VARIABLE_NAME - 1);
        names[i][MMS_MAX_VARIABLE_NAME - 1] = '\0';
        (*count)++;
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

    if (client == NULL || !client->connected || item_id == NULL ||
        attrs == NULL) {
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
                   item_id, MMS_MAX_VARIABLE_NAME - 1);

    ret = transact(client, &req, &resp);
    if (ret != IEC61850_MMS_CLIENT_OK) { return ret; }

    if (resp.service == MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS) {
        *attrs = resp.params.getvariableattrs.attributes;
        return IEC61850_MMS_CLIENT_OK;
    }

    return IEC61850_MMS_CLIENT_ERR_MMS;
}
