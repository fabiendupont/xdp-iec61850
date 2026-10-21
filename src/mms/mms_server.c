/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Server Implementation
 *
 * Thread-per-connection server with ISO stack transport.
 * Handles GetNameList, Read, Write, GetVariableAccessAttributes.
 */


#include "mms/mms_server.h"
#include "mms/mms_file_service.h"
#include "mms/mms_journal.h"
#include <string.h>
#include <errno.h>

void iec61850_mms_server_config_init(iec61850_mms_server_config_t *cfg)
{
    if (cfg == NULL) { return; }
    cfg->port = 102;
    cfg->max_pdu_size = IEC61850_MMS_MAX_PDU_SIZE;
    cfg->max_sessions = IEC61850_MMS_MAX_SESSIONS;
    cfg->accept_timeout_ms = 1000;
}

void iec61850_mms_server_init(iec61850_mms_server_t *server,
                                const iec61850_mms_server_config_t *cfg,
                                iec61850_mms_data_store_t *data_store)
{
    if (server == NULL) { return; }

    (void)memset(server, 0, sizeof(*server));

    if (cfg != NULL) {
        server->config = *cfg;
    } else {
        iec61850_mms_server_config_init(&server->config);
    }

    server->data_store = data_store;
    iec61850_tcp_listener_init(&server->listener);
    atomic_store(&server->running, false);
    atomic_store(&server->stop_requested, false);
    atomic_store(&server->active_session_count, 0);
}

/* Map data store error to MMS error class + code */
static void map_ds_error(int ds_ret, mms_service_error_t *err)
{
    switch (ds_ret) {
        case IEC61850_MMS_DS_ERR_NOT_FOUND:
            err->error_class = MMS_ERROR_CLASS_ACCESS;
            err->error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
            break;
        case IEC61850_MMS_DS_ERR_EXISTS:
            err->error_class = MMS_ERROR_CLASS_ACCESS;
            err->error_code = MMS_ACCESS_ERROR_OBJECT_EXISTS;
            break;
        case IEC61850_MMS_DS_ERR_TYPE:
            err->error_class = MMS_ERROR_CLASS_ACCESS;
            err->error_code = MMS_ACCESS_ERROR_TYPE_INCONSISTENT;
            break;
        default:
            err->error_class = MMS_ERROR_CLASS_SERVICE;
            err->error_code = MMS_SERVICE_ERROR_OTHER;
            break;
    }
}

/*
 * Process a confirmed request. Returns:
 *   0  = success, resp is populated
 *   1  = error, err is populated (send ConfirmedError)
 *  -1  = conclude (terminate session)
 */
static int process_request(iec61850_mms_session_t *session,
                             const mms_confirmed_request_t *req,
                             mms_confirmed_response_t *resp,
                             mms_confirmed_error_t *err)
{
    int ds_ret;

    (void)memset(resp, 0, sizeof(*resp));
    (void)memset(err, 0, sizeof(*err));
    resp->invoke_id = req->invoke_id;
    resp->service = req->service;
    err->invoke_id = req->invoke_id;

    switch (req->service) {
        case MMS_SERVICE_TYPE_STATUS: {
            resp->params.status.vmd_logical_status = 0;   /* state-changes-allowed */
            resp->params.status.vmd_physical_status = 0;   /* operational */
            return 0;
        }

        case MMS_SERVICE_TYPE_IDENTIFY: {
            (void)strncpy(resp->params.identify.vendor_name, "xdp-iec61850",
                          (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            (void)strncpy(resp->params.identify.model_name, "IEC 61850 XDP Stack",
                          (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            (void)strncpy(resp->params.identify.revision, "1.0.0",
                          (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            return 0;
        }

        case MMS_SERVICE_TYPE_READ: {
            ds_ret = iec61850_mms_ds_read_variable(session->data_store,
                                                      req->params.read.variable_spec.domain,
                                                      req->params.read.variable_spec.item_id,
                                                      &resp->params.read.value);
            if (ds_ret == (int)IEC61850_MMS_DS_OK) {
                return 0;
            }

            /* IEC 61850-8-1 §8.8: reading a named variable list by item_id returns
             * a STRUCTURE containing the list member values as AccessResults.
             * This is how RCB objects (e.g. LLN0$RP$EventsRCB01) are read whole. */
            {
                mms_variable_spec_t list_vars[MMS_MAX_NAMED_VARIABLES];
                uint32_t list_count = 0;
                int list_ret = iec61850_mms_ds_get_list_attrs(
                    session->data_store,
                    req->params.read.variable_spec.domain,
                    req->params.read.variable_spec.item_id,
                    list_vars, &list_count, MMS_MAX_NAMED_VARIABLES);
                if (list_ret == (int)IEC61850_MMS_DS_OK && list_count > 0U) {
                    /* Encode each member value directly into the response buffer as a
                     * structure [2] IMPLICIT SEQUENCE OF AccessResult. The caller's
                     * mms_encode_response() for MMS_SERVICE_TYPE_READ wraps it in
                     * listOfAccessResult [1]; we return the inner structure value. */
                    resp->service = MMS_SERVICE_TYPE_READ_NAMED_VARLIST;
                    resp->params.readnamedvarlist.num_values = 0;
                    for (uint32_t vi = 0; vi < list_count && vi < MMS_MAX_NAMED_VARIABLES; vi++) {
                        int vr = iec61850_mms_ds_read_variable(
                            session->data_store,
                            list_vars[vi].domain,
                            list_vars[vi].item_id,
                            &resp->params.readnamedvarlist.values[vi]);
                        if (vr != (int)IEC61850_MMS_DS_OK) {
                            map_ds_error(vr, &err->error);
                            return 1;
                        }
                        resp->params.readnamedvarlist.num_values++;
                    }
                    return 0;
                }
            }

            map_ds_error(ds_ret, &err->error);
            return 1;
        }

        case MMS_SERVICE_TYPE_WRITE: {
            ds_ret = iec61850_mms_ds_write_variable(session->data_store,
                                                       req->params.write.variable_spec.domain,
                                                       req->params.write.variable_spec.item_id,
                                                       &req->params.write.value);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_GET_NAMELIST: {
            /* Get all names into a temp buffer, then apply continueAfter filter */
            char all_names[MMS_MAX_NAMELIST_ITEMS][MMS_MAX_VARIABLE_NAME];
            uint32_t total = 0;

            if (req->params.getnamelist.object_class == MMS_OBJECT_CLASS_DOMAIN) {
                (void)iec61850_mms_ds_get_domain_names(session->data_store,
                                                        all_names, &total,
                                                        MMS_MAX_NAMELIST_ITEMS);
            } else if (req->params.getnamelist.object_class == MMS_OBJECT_CLASS_NAMED_VARIABLE) {
                (void)iec61850_mms_ds_get_var_names(session->data_store,
                                                      req->params.getnamelist.domain,
                                                      all_names, &total,
                                                      MMS_MAX_NAMELIST_ITEMS);
            }

            /* Apply continueAfter: skip until we find the token, then start from next */
            uint32_t start = 0;
            if (req->params.getnamelist.continue_after) {
                for (uint32_t i = 0; i < total; i++) {
                    if (strcmp(all_names[i], req->params.getnamelist.continue_after_id) == 0) {
                        start = i + 1U;
                        break;
                    }
                }
            }

            /* Copy up to MMS_MAX_NAMELIST_ITEMS from the start position */
            uint32_t remaining = (start < total) ? (total - start) : 0U;
            uint32_t to_copy = remaining;
            if (to_copy > (uint32_t)MMS_MAX_NAMELIST_ITEMS) {
                to_copy = (uint32_t)MMS_MAX_NAMELIST_ITEMS;
            }

            resp->params.getnamelist.num_identifiers = to_copy;
            for (uint32_t i = 0; i < to_copy; i++) {
                (void)memcpy(resp->params.getnamelist.identifiers[i],
                             all_names[start + i], MMS_MAX_VARIABLE_NAME);
            }
            resp->params.getnamelist.more_follows = ((start + to_copy) < total);
            return 0;
        }

        case MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS: {
            mms_variable_access_attrs_t attrs;
            (void)memset(&attrs, 0, sizeof(attrs));
            ds_ret = iec61850_mms_ds_get_variable_attrs(
                session->data_store,
                req->params.getvariableattrs.variable_spec.domain,
                req->params.getvariableattrs.variable_spec.item_id,
                &attrs);
            if (ds_ret == (int)IEC61850_MMS_DS_OK) {
                resp->params.getvariableattrs.attributes = attrs;
            } else {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_DEFINE_NAMED_VARLIST: {
            ds_ret = iec61850_mms_ds_define_list(
                session->data_store,
                req->params.definenamedvarlist.domain,
                req->params.definenamedvarlist.list_name,
                req->params.definenamedvarlist.variables,
                req->params.definenamedvarlist.num_variables);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_DELETE_NAMED_VARLIST: {
            ds_ret = iec61850_mms_ds_delete_list(
                session->data_store,
                req->params.deletenamedvarlist.domain,
                req->params.deletenamedvarlist.list_name);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_GET_NAMED_VARLIST_ATTRS: {
            uint32_t count = 0;
            ds_ret = iec61850_mms_ds_get_list_attrs(
                session->data_store,
                req->params.getnamedvarlistattrs.domain,
                req->params.getnamedvarlistattrs.list_name,
                resp->params.getnamedvarlistattrs.variables,
                &count, MMS_MAX_NAMED_VARIABLES);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            resp->params.getnamedvarlistattrs.num_variables = count;
            return 0;
        }

        case MMS_SERVICE_TYPE_SELECT: {
            if (session->control_manager == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_control_select(
                session->control_manager,
                req->params.select.control_object.domain,
                req->params.select.control_object.item_id,
                session->session_id,
                &resp->params.select);
            if (ds_ret != 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_SELECT_WITH_VALUE: {
            if (session->control_manager == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_control_select_with_value(
                session->control_manager,
                req->params.select_with_value.control_object.domain,
                req->params.select_with_value.control_object.item_id,
                session->session_id,
                &req->params.select_with_value.control_value,
                &resp->params.select_with_value);
            if (ds_ret != 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_OPERATE: {
            if (session->control_manager == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_control_operate(
                session->control_manager,
                req->params.operate.control_object.domain,
                req->params.operate.control_object.item_id,
                (iec61850_control_ids_t){
                    .session_id   = session->session_id,
                    .selection_id = req->params.operate.selection_id,
                },
                &resp->params.operate);
            if (ds_ret != 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_CANCEL: {
            if (session->control_manager == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_control_cancel(
                session->control_manager,
                req->params.cancel.control_object.domain,
                req->params.cancel.control_object.item_id,
                (iec61850_control_ids_t){
                    .session_id   = session->session_id,
                    .selection_id = req->params.cancel.selection_id,
                });
            if (ds_ret != 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_OPEN: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            uint32_t fsize = 0;
            int fh = iec61850_mms_file_open(session->file_service,
                                              req->params.fileopen.filename,
                                              &fsize);
            if (fh < 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            resp->params.fileopen.file_handle = (uint32_t)fh;
            resp->params.fileopen.file_size = fsize;
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_READ: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            size_t read_len = 0;
            bool more = false;
            ds_ret = iec61850_mms_file_read(
                session->file_service,
                (int)req->params.fileread.file_handle,
                resp->params.fileread.data,
                sizeof(resp->params.fileread.data),
                &read_len, &more);
            if (ds_ret != (int)IEC61850_MMS_FILE_OK) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            resp->params.fileread.bytes_read = (uint32_t)read_len;
            resp->params.fileread.more_follows = more;
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_CLOSE: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_mms_file_close(
                session->file_service,
                (int)req->params.fileclose.file_handle);
            if (ds_ret != (int)IEC61850_MMS_FILE_OK) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_DELETE: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_mms_file_delete(
                session->file_service,
                req->params.filedelete.filename);
            if (ds_ret != (int)IEC61850_MMS_FILE_OK) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_DIRECTORY: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            uint32_t count = 0;
            ds_ret = iec61850_mms_file_get_directory(
                session->file_service,
                req->params.filedirectory.file_specification,
                (iec61850_mms_file_entry_t *)resp->params.filedirectory.entries,
                &count, MMS_MAX_NAMELIST_ITEMS);
            if (ds_ret != (int)IEC61850_MMS_FILE_OK) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            resp->params.filedirectory.num_entries = count;
            resp->params.filedirectory.more_follows = false;
            return 0;
        }

        case MMS_SERVICE_TYPE_READ_JOURNAL: {
            if (session->journal == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            uint32_t j_count = 0;
            iec61850_journal_entry_t j_entries[MMS_MAX_JOURNAL_ENTRIES];
            if (req->params.readjournal.start_entry_id > 0ULL) {
                (void)iec61850_journal_read_by_id(
                    session->journal,
                    req->params.readjournal.start_entry_id,
                    j_entries, &j_count,
                    (req->params.readjournal.max_entries > 0U) ?
                        req->params.readjournal.max_entries :
                        (uint32_t)MMS_MAX_JOURNAL_ENTRIES);
            } else {
                (void)iec61850_journal_read_by_time(
                    session->journal,
                    req->params.readjournal.start_time,
                    req->params.readjournal.end_time,
                    j_entries, &j_count,
                    (req->params.readjournal.max_entries > 0U) ?
                        req->params.readjournal.max_entries :
                        (uint32_t)MMS_MAX_JOURNAL_ENTRIES);
            }
            for (uint32_t ji = 0;
                 (ji < j_count) && (ji < (uint32_t)MMS_MAX_JOURNAL_ENTRIES); ji++) {
                resp->params.readjournal.entries[ji].entry_id =
                    j_entries[ji].entry_id;
                resp->params.readjournal.entries[ji].timestamp =
                    j_entries[ji].timestamp_ms;
                (void)strncpy(
                    resp->params.readjournal.entries[ji].variable_ref,
                    j_entries[ji].variable_ref,
                    (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            }
            resp->params.readjournal.num_entries = j_count;
            resp->params.readjournal.more_follows = false;
            return 0;
        }

        case MMS_SERVICE_TYPE_INITIALIZE_JOURNAL: {
            if (session->journal == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            iec61850_journal_init(session->journal,
                                   req->params.initializejournal.journal_name);
            return 0;
        }

        case MMS_SERVICE_TYPE_READ_NAMED_VARLIST: {
            /* Read all variables in a named variable list */
            mms_variable_spec_t list_vars[MMS_MAX_NAMED_VARIABLES];
            uint32_t list_count = 0;
            ds_ret = iec61850_mms_ds_get_list_attrs(
                session->data_store,
                req->params.readnamedvarlist.domain,
                req->params.readnamedvarlist.list_name,
                list_vars, &list_count, MMS_MAX_NAMED_VARIABLES);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            resp->params.readnamedvarlist.num_values = 0;
            for (uint32_t vi = 0; vi < list_count; vi++) {
                ds_ret = iec61850_mms_ds_read_variable(
                    session->data_store,
                    list_vars[vi].domain,
                    list_vars[vi].item_id,
                    &resp->params.readnamedvarlist.values[vi]);
                if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                    map_ds_error(ds_ret, &err->error);
                    return 1;
                }
                resp->params.readnamedvarlist.num_values++;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_WRITE_NAMED_VARLIST: {
            /* Write all variables in a named variable list */
            mms_variable_spec_t wl_vars[MMS_MAX_NAMED_VARIABLES];
            uint32_t wl_count = 0;
            ds_ret = iec61850_mms_ds_get_list_attrs(
                session->data_store,
                req->params.writenamedvarlist.domain,
                req->params.writenamedvarlist.list_name,
                wl_vars, &wl_count, MMS_MAX_NAMED_VARIABLES);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            if (req->params.writenamedvarlist.num_values != wl_count) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_TYPE_INCONSISTENT;
                return 1;
            }
            for (uint32_t vi = 0; vi < wl_count; vi++) {
                ds_ret = iec61850_mms_ds_write_variable(
                    session->data_store,
                    wl_vars[vi].domain,
                    wl_vars[vi].item_id,
                    &req->params.writenamedvarlist.values[vi]);
                if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                    map_ds_error(ds_ret, &err->error);
                    return 1;
                }
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE:
        case MMS_SERVICE_TYPE_DELETE_NAMED_TYPE:
        case MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS:
        case MMS_SERVICE_TYPE_COMMAND_TERMINATION: {
            /* Named type services are not used by IEC 61850 (types are
             * inferred from the data model). CommandTermination is an
             * unconfirmed service (server→client); receiving it as a
             * request is invalid. Return service error per ISO 9506-2. */
            err->error.error_class = MMS_ERROR_CLASS_SERVICE;
            err->error.error_code = MMS_SERVICE_ERROR_OTHER;
            return 1;
        }

        default:
            /* Unsupported service — send ConfirmedError */
            err->error.error_class = MMS_ERROR_CLASS_SERVICE;
            err->error.error_code = MMS_SERVICE_ERROR_OTHER;
            return 1;
    }
}

/* Session thread */
static void *session_thread(void *arg)
{
    /* MISRA 11.5: pthread arg is opaque void*, deviation Cat. 3 */
    iec61850_mms_session_t *session = (iec61850_mms_session_t *)arg;
    uint8_t recv_buf[IEC61850_MMS_MAX_PDU_SIZE];
    uint8_t resp_buf[IEC61850_MMS_MAX_PDU_SIZE];
    size_t recv_len;
    int ret;

    /* Accept ISO association */
    uint8_t mms_init_resp[256];
    mms_initiate_response_t init_resp;
    (void)memset(&init_resp, 0, sizeof(init_resp));
    init_resp.negotiated_max_pdu_size = session->max_pdu_size;
    init_resp.negotiated_data_structure_nesting_level = 4;
    init_resp.negotiated_version_number = 1;

    ret = mms_encode_initiate_response(&init_resp, mms_init_resp,
                                         sizeof(mms_init_resp));
    if (ret <= 0) { goto done; }

    uint8_t mms_init_req[4096];
    size_t mms_init_req_len = sizeof(mms_init_req);
    ret = iec61850_iso_accept(&session->iso, mms_init_resp, (size_t)ret,
                                mms_init_req, &mms_init_req_len, 30000);
    if (ret != 0) { goto done; }

    /* Main request loop */
    while (!atomic_load(&session->stop_requested)) {
        ret = iec61850_iso_recv(&session->iso, recv_buf, sizeof(recv_buf),
                                  &recv_len, 5000);
        if (ret == IEC61850_TRANSPORT_ERR_TIMEOUT) {
            continue;
        }
        if (ret != 0) {
            break;
        }

        /* Check for Conclude request */
        if ((recv_len >= 1U) && (recv_buf[0] == (uint8_t)MMS_TAG_CONCLUDE_REQUEST)) {
            /* Send Conclude response and exit */
            uint8_t conclude_resp[2] = { MMS_TAG_CONCLUDE_RESPONSE, 0x00 };
            (void)iec61850_iso_send(&session->iso, conclude_resp, 2);
            break;
        }

        /* Decode confirmed request (returns consumed bytes > 0 on success).
         * Zero-init so optional bool fields (e.g. continue_after) are false
         * when absent from the BER encoding, preventing UBSan false values. */
        mms_confirmed_request_t req = {0};
        ret = mms_decode_confirmed_request(recv_buf, recv_len, &req);
        if (ret < 0) {
            break;
        }

        /* Process and build response */
        mms_confirmed_response_t resp;
        mms_confirmed_error_t err;
        int proc_ret = process_request(session, &req, &resp, &err);

        if (proc_ret == 0) {
            /* Success — send confirmed response */
            ret = mms_encode_confirmed_response(&resp, resp_buf,
                                                  sizeof(resp_buf));
            if (ret <= 0) { break; }
            ret = iec61850_iso_send(&session->iso, resp_buf, (size_t)ret);
            if (ret < 0) { break; }
            /* Invoke post-response callback while session is still active.
             * This allows the application to send unsolicited PDUs (e.g.
             * InformationReport) immediately after a specific request, without
             * sleeping or polling. */
            if (session->after_response != NULL) {
                session->after_response(session,
                                        req.params.read.variable_spec.domain,
                                        req.params.read.variable_spec.item_id,
                                        session->after_response_user_data);
            }
        } else if (proc_ret == 1) {
            /* Error — send confirmed error */
            ret = mms_encode_confirmed_error(&err, resp_buf,
                                               sizeof(resp_buf));
            if (ret <= 0) { break; }
            ret = iec61850_iso_send(&session->iso, resp_buf, (size_t)ret);
            if (ret < 0) { break; }
        } else {
            /* Conclude or fatal — exit */
            break;
        }
    }

done:
    iec61850_iso_disconnect(&session->iso);
    atomic_store(&session->active, false);
    return NULL;
}

/* Accept thread */
static void *accept_thread(void *arg)
{
    /* MISRA 11.5: pthread arg is opaque void*, deviation Cat. 3 */
    iec61850_mms_server_t *server = (iec61850_mms_server_t *)arg;

    while (!atomic_load(&server->stop_requested)) {
        iec61850_tcp_conn_t client;
        iec61850_tcp_conn_init(&client);

        int ret = iec61850_tcp_listener_accept(&server->listener, &client,
                                                 server->config.accept_timeout_ms);
        if (ret == IEC61850_TRANSPORT_ERR_TIMEOUT) {
            continue;
        }
        if (ret != 0) {
            break;
        }

        /* Find a free session slot */
        bool assigned = false;
        for (uint32_t i = 0; (i < server->config.max_sessions) &&
             (i < (uint32_t)IEC61850_MMS_MAX_SESSIONS); i++) {
            if (!atomic_load(&server->sessions[i].active)) {
                iec61850_mms_session_t *sess = &server->sessions[i];
                iec61850_iso_conn_init(&sess->iso);
                sess->iso.tcp = client;
                sess->iso.tcp.connected = true;
                sess->data_store = server->data_store;
                sess->control_manager = server->control_manager;
                sess->file_service = server->file_service;
                sess->journal = server->journal;
                sess->max_pdu_size = server->config.max_pdu_size;
                sess->invoke_id = 0;
                sess->session_id = server->next_session_id; server->next_session_id++;
                sess->after_response = server->config.after_response;
                sess->after_response_user_data = server->config.after_response_user_data;
                atomic_store(&sess->active, true);
                atomic_store(&sess->stop_requested, false);
                atomic_fetch_add(&server->active_session_count, 1);

                ret = pthread_create(&sess->thread, NULL, session_thread, sess);
                if (ret != 0) {
                    atomic_store(&sess->active, false);
                    atomic_fetch_sub(&server->active_session_count, 1);
                    iec61850_tcp_disconnect(&client);
                }
                /* Thread is joinable — joined during server stop */
                assigned = true;
                break;
            }
        }

        if (!assigned) {
            iec61850_tcp_disconnect(&client);
        }
    }

    atomic_store(&server->running, false);
    return NULL;
}

int iec61850_mms_server_start(iec61850_mms_server_t *server)
{
    int ret;

    if (server == NULL) { return IEC61850_MMS_SERVER_ERR_ARGS; }
    if (atomic_load(&server->running)) { return IEC61850_MMS_SERVER_ERR_RUNNING; }

    ret = iec61850_tcp_listener_bind(&server->listener, server->config.port);
    if (ret != 0) { return IEC61850_MMS_SERVER_ERR_BIND; }

    ret = iec61850_tcp_listener_listen(&server->listener, 10);
    if (ret != 0) { return IEC61850_MMS_SERVER_ERR_LISTEN; }

    atomic_store(&server->stop_requested, false);
    atomic_store(&server->running, true);

    ret = pthread_create(&server->accept_thread, NULL, accept_thread, server);
    if (ret != 0) {
        iec61850_tcp_listener_close(&server->listener);
        atomic_store(&server->running, false);
        return IEC61850_MMS_SERVER_ERR_THREAD;
    }

    return IEC61850_MMS_SERVER_OK;
}

int iec61850_mms_server_stop(iec61850_mms_server_t *server)
{
    if (server == NULL) { return IEC61850_MMS_SERVER_ERR_ARGS; }

    atomic_store(&server->stop_requested, true);

    for (uint32_t i = 0; i < (uint32_t)IEC61850_MMS_MAX_SESSIONS; i++) {
        if (atomic_load(&server->sessions[i].active)) {
            atomic_store(&server->sessions[i].stop_requested, true);
        }
    }

    if (atomic_load(&server->running)) {
        (void)pthread_join(server->accept_thread, NULL);
    }

    /* Join all session threads to ensure clean shutdown */
    for (uint32_t i = 0; i < (uint32_t)IEC61850_MMS_MAX_SESSIONS; i++) {
        if (atomic_load(&server->sessions[i].active)) {
            (void)pthread_join(server->sessions[i].thread, NULL);
        }
    }

    iec61850_tcp_listener_close(&server->listener);
    atomic_store(&server->running, false);

    return IEC61850_MMS_SERVER_OK;
}

bool iec61850_mms_server_is_running(const iec61850_mms_server_t *server)
{
    if (server == NULL) { return false; }
    return atomic_load(&server->running);
}

uint32_t iec61850_mms_server_get_session_count(
    const iec61850_mms_server_t *server)
{
    if (server == NULL) { return 0; }
    return atomic_load(&server->active_session_count);
}
