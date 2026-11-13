/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client for IEC 61850
 *
 * Blocking MMS client: connect to server, read/write variables,
 * get name lists, manage data sets.
 *
 * Thin wrapper over the async core (mms_client_core.h): each public
 * operation submits a confirmed request and blocks in core wait().
 */

#ifndef IEC61850_MMS_CLIENT_H
#define IEC61850_MMS_CLIENT_H

#include "transport/iso_stack.h"
#include "asn1/mms_ber.h"
#include "mms/mms_client_core.h"

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
    iec61850_mms_client_core_t core;  /* async core attached to iso */
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

/**
 * Identify server (get vendor, model, revision).
 */
int iec61850_mms_client_identify(iec61850_mms_client_t *client,
                                   char *vendor, char *model, char *revision,
                                   size_t buf_size);

/**
 * Define a named variable list.
 */
int iec61850_mms_client_define_named_varlist(
    iec61850_mms_client_t *client,
    const char *domain, const char *list_name,
    const mms_variable_spec_t *vars, uint32_t num_vars);

/**
 * Delete a named variable list.
 */
int iec61850_mms_client_delete_named_varlist(
    iec61850_mms_client_t *client,
    const char *domain, const char *list_name);

/**
 * Read all variables in a named variable list.
 */
int iec61850_mms_client_read_named_varlist(
    iec61850_mms_client_t *client,
    const char *domain, const char *list_name,
    mms_value_t *values, uint32_t *num_values, uint32_t max_values);

/**
 * Get file directory listing.
 */
int iec61850_mms_client_file_directory(
    iec61850_mms_client_t *client,
    const char *file_spec,
    mms_file_entry_t *entries, uint32_t *num_entries,
    uint32_t max_entries);

/**
 * Open a file for reading.
 */
int iec61850_mms_client_file_open(
    iec61850_mms_client_t *client,
    const char *filename, uint32_t *file_handle, uint32_t *file_size);

/**
 * Read from an open file.
 */
int iec61850_mms_client_file_read(
    iec61850_mms_client_t *client,
    uint32_t file_handle, uint8_t *data, uint32_t *data_len,
    uint32_t max_len, bool *more_follows);

/**
 * Close an open file.
 */
int iec61850_mms_client_file_close(
    iec61850_mms_client_t *client, uint32_t file_handle);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_CLIENT_H */
