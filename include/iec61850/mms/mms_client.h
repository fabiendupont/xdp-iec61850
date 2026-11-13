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
    IEC61850_MMS_CLIENT_ERR_BUFFER = -9,
    /* WP-1c: RCB reservation held by another client (Ed.2 Owner check
     * on a failed Resv write). Additive value; source-compatible. */
    IEC61850_MMS_CLIENT_ERR_RCB_OWNER = -10
} iec61850_mms_client_result_t;

/*
 * WP-2w: unsolicited CommandTermination (IEC 61850-8-1 Ed.2).
 *
 * Delivered through an unsolicited MMS InformationReport on the
 * operated control object ("<LN>$CO$<DO>$Oper") whose AccessResult
 * echoes the operated structure. The callback fires from the polling
 * context (iec61850_mms_client_poll / any blocking helper waiting for
 * a response); install it with
 * iec61850_mms_client_set_command_termination_handler().
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];
    char item_id[MMS_MAX_VARIABLE_NAME];  /* "<LN>$CO$<DO>$Oper" */
    bool ctl_val;                         /* echoed ctlVal */
    int32_t origin_cat;                   /* echoed origin orCat */
    uint8_t origin_ident[64];             /* echoed origin orIdent */
    size_t origin_ident_len;
    uint32_t ctl_num;                     /* echoed ctlNum */
    uint64_t timestamp_ms;                /* echoed T (UTC ms) */
} iec61850_mms_client_command_termination_t;

typedef void (*iec61850_mms_client_command_termination_cb_t)(
    const iec61850_mms_client_command_termination_t *termination,
    void *user_data);

/*
 * WP-2w: core-level CommandTermination delivery hook (implemented in
 * mms_client_core.c; declared here because the async-core header is a
 * frozen interface). Installs the process-global hook the core's
 * unconfirmed-PDU dispatch calls when a CommandTermination arrives.
 * The blocking client registers its shim through
 * iec61850_mms_client_set_command_termination_handler().
 */
void iec61850_mms_client_core_set_command_termination_handler(
    iec61850_mms_client_command_termination_cb_t cb, void *user_data);

/*
 * WP-2w: Operate parameters (the IEC 61850-8-1 originator-controlled
 * Oper structure built by iec61850_mms_client_operate()).
 */
typedef struct {
    bool ctl_val;              /* ctlVal */
    int32_t origin_cat;        /* origin.orCat (0 = not-supported, 1 = bay-level, ...) */
    const char *origin_ident;  /* origin.orIdent (NULL = empty octet string) */
    uint32_t ctl_num;          /* ctlNum */
    uint64_t oper_tm_utc_ms;   /* operTm: 0 = immediate, else time-activated (UTC ms) */
    bool test;                 /* Test */
    bool check_interlock;      /* Check.interlock-check */
    bool check_synchro;        /* Check.synchrocheck */
} iec61850_mms_client_operate_params_t;

typedef struct {
    iec61850_iso_conn_t iso;
    bool connected;
    uint32_t max_pdu_size;
    uint32_t invoke_id;
    int request_timeout_ms;
    iec61850_mms_client_core_t core;  /* async core attached to iso */
    /* WP-2w: unsolicited CommandTermination handler */
    iec61850_mms_client_command_termination_cb_t command_termination_cb;
    void *command_termination_user_data;
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
 * Poll the association for unsolicited PDUs without issuing a request.
 * Dispatches at most one PDU per call (a report handler installed via
 * iec61850_mms_client_set_report_handler fires from this context).
 * Reports arrive between transactions on the blocking client; call
 * this to drain them without issuing a confirmed service.
 *
 * @return Number of events dispatched (>= 0), or negative
 *         IEC61850_MMS_CLIENT_ERR_*.
 */
int iec61850_mms_client_poll(iec61850_mms_client_t *client, int timeout_ms);

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
 * Read a variable, reporting the in-band failure code.
 *
 * Same as iec61850_mms_client_read(), but when the server returns a
 * valid MMS Read-Response whose AccessResult is a failure CHOICE
 * (DataAccessError), *access_error receives that code; it is set to
 * -1 when the response carried no in-band failure (success, or a
 * ConfirmedError PDU, which surfaces as ERR_MMS without a code).
 *
 * @return IEC61850_MMS_CLIENT_OK on success, negative
 *         IEC61850_MMS_CLIENT_ERR_* on failure.
 */
int iec61850_mms_client_read_detail(iec61850_mms_client_t *client,
                                     const char *domain,
                                     const char *item_id,
                                     mms_value_t *value,
                                     int32_t *access_error);

/**
 * Write a variable, reporting the in-band failure code.
 *
 * Same as iec61850_mms_client_write(), but when the server rejects
 * the write in-band (Write-Response failure CHOICE [0],
 * DataAccessError — the IEC 61850-8-1 mapping for rejected RCB
 * component writes, e.g. a Resv write on a URCB held by another
 * client), *access_error receives that code; it is set to -1 when
 * the response carried no in-band failure (success, or a
 * ConfirmedError PDU, which surfaces as ERR_MMS without a code).
 *
 * @return IEC61850_MMS_CLIENT_OK on success, negative
 *         IEC61850_MMS_CLIENT_ERR_* on failure.
 */
int iec61850_mms_client_write_detail(iec61850_mms_client_t *client,
                                      const char *domain,
                                      const char *item_id,
                                      const mms_value_t *value,
                                      int32_t *access_error);

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

/* ========================================================================
 * WP-2w: IEC 61850-8-1 Ed.2 control-object helpers
 *
 * Controls are driven as ordinary Reads/Writes on the control
 * object's component data attributes ("<LN>$CO$<DO>$SBO" / "$Oper" /
 * "$Cancel"), the wire mapping conformant clients and servers use.
 * item_id is the control-object reference including the "$CO$"
 * functional constraint (e.g. "GGIO1$CO$SPCSO1").
 * ======================================================================== */

/**
 * Select a control object (sbo-with-normal-security): reads
 * "<item_id>$SBO" — the 8-1 select form — and succeeds when the
 * server answers with the selected object's reference string.
 */
int iec61850_mms_client_select(iec61850_mms_client_t *client,
                                const char *domain, const char *item_id);

/**
 * Select a control object with a value (sbo-with-enhanced-security):
 * writes the Oper structure to "<item_id>$SBOw".
 */
int iec61850_mms_client_select_with_value(
    iec61850_mms_client_t *client, const char *domain,
    const char *item_id, bool ctl_val);

/**
 * Operate a control object: writes the 8-1 Oper structure (ctlVal,
 * origin, ctlNum, T, Test, Check; operTm prepended when
 * params->oper_tm_utc_ms is non-zero — the time-activated form) to
 * "<item_id>$Oper".
 */
int iec61850_mms_client_operate(
    iec61850_mms_client_t *client, const char *domain,
    const char *item_id,
    const iec61850_mms_client_operate_params_t *params);

/**
 * Cancel an outstanding selection / time-activated operate: writes
 * the Cancel structure to "<item_id>$Cancel".
 */
int iec61850_mms_client_cancel(iec61850_mms_client_t *client,
                                const char *domain, const char *item_id);

/**
 * Read a control object's ctlModel (0=status-only, 1=direct-with-
 * normal-security, 2=sbo-with-normal-security, 3=direct-with-
 * enhanced-security, 4=sbo-with-enhanced-security). Reads the 7-2
 * configuration-attribute spelling "<LN>$CF$<DO>$ctlModel" first,
 * falling back to "<LN>$CO$<DO>$ctlModel".
 */
int iec61850_mms_client_read_ctl_model(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *item_id,
                                        int32_t *ctl_model);

/**
 * Read a control object's sboTimeout in milliseconds (same
 * CF-first, CO-fallback lookup as iec61850_mms_client_read_ctl_
 * model()).
 */
int iec61850_mms_client_read_sbo_timeout(iec61850_mms_client_t *client,
                                          const char *domain,
                                          const char *item_id,
                                          uint32_t *sbo_timeout_ms);

/**
 * Install the unsolicited CommandTermination handler. The handler
 * fires from the polling context while the association carries
 * command-termination InformationReports (see
 * iec61850_mms_client_command_termination_cb_t).
 *
 * NOTE: the delivery hook is process-global in the underlying async
 * core (frozen core header): the last handler installed on any
 * client in the process receives every CommandTermination. The
 * blocking client is designed for one association per process;
 * correlate by domain/item_id when embedding several.
 */
void iec61850_mms_client_set_command_termination_handler(
    iec61850_mms_client_t *client,
    iec61850_mms_client_command_termination_cb_t cb, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_CLIENT_H */
