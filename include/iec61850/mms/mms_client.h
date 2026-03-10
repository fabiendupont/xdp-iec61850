/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client for IEC 61850
 *
 * Blocking MMS client: connect to server, read/write variables,
 * get name lists, manage data sets.
 */

#ifndef IEC61850_MMS_CLIENT_H
#define IEC61850_MMS_CLIENT_H

#include "transport/iso_stack.h"
#include "asn1/mms_ber.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Client result codes */
typedef enum {
    IEC61850_MMS_CLIENT_OK = 0,
    IEC61850_MMS_CLIENT_ERR_ARGS = -1,
    IEC61850_MMS_CLIENT_ERR_NOT_CONNECTED = -2,
    IEC61850_MMS_CLIENT_ERR_CONNECT = -3,
    IEC61850_MMS_CLIENT_ERR_TRANSPORT = -4,
    IEC61850_MMS_CLIENT_ERR_TIMEOUT = -5,
    IEC61850_MMS_CLIENT_ERR_MMS = -6,
    IEC61850_MMS_CLIENT_ERR_ENCODE = -7,
    IEC61850_MMS_CLIENT_ERR_DECODE = -8,
    IEC61850_MMS_CLIENT_ERR_BUFFER = -9
} iec61850_mms_client_result_t;

typedef struct {
    iec61850_iso_conn_t iso;
    bool connected;
    uint32_t max_pdu_size;
    uint32_t invoke_id;
    int request_timeout_ms;
} iec61850_mms_client_t;

/**
 * Initialize MMS client.
 */
void iec61850_mms_client_init(iec61850_mms_client_t *client);

/**
 * Connect to MMS server.
 */
int iec61850_mms_client_connect(iec61850_mms_client_t *client,
                                  const char *host, uint16_t port,
                                  int timeout_ms);

/**
 * Disconnect from MMS server.
 */
int iec61850_mms_client_disconnect(iec61850_mms_client_t *client);

/**
 * Check if connected.
 */
bool iec61850_mms_client_is_connected(const iec61850_mms_client_t *client);

/**
 * Read a variable.
 */
int iec61850_mms_client_read(iec61850_mms_client_t *client,
                               const char *domain, const char *item_id,
                               mms_value_t *value);

/**
 * Write a variable.
 */
int iec61850_mms_client_write(iec61850_mms_client_t *client,
                                const char *domain, const char *item_id,
                                const mms_value_t *value);

/**
 * Get name list (domain names or variable names).
 */
int iec61850_mms_client_get_name_list(iec61850_mms_client_t *client,
                                        mms_object_class_t obj_class,
                                        const char *domain,
                                        char names[][MMS_MAX_VARIABLE_NAME],
                                        uint32_t *count, uint32_t max_count);

/**
 * Get variable access attributes.
 */
int iec61850_mms_client_get_var_attrs(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *item_id,
                                        mms_variable_access_attrs_t *attrs);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_CLIENT_H */
