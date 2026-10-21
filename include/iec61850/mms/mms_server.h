/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Server for IEC 61850
 *
 * Thread-per-connection MMS server with service dispatch.
 * Handles GetNameList, Read, Write, GetVariableAccessAttributes,
 * association management, and report generation.
 */

#ifndef IEC61850_MMS_SERVER_H
#define IEC61850_MMS_SERVER_H

#include "mms/mms_data_store.h"
#include "mms/mms_control.h"
#include "mms/mms_file_service.h"
#include "mms/mms_journal.h"
#include "transport/iso_stack.h"
#include "asn1/mms_ber.h"

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define IEC61850_MMS_MAX_SESSIONS   50
#define IEC61850_MMS_MAX_PDU_SIZE   65000

/* Server configuration */
/* Forward declaration for use in callback typedef */
struct iec61850_mms_session_s;

/* Callback invoked after the server sends each confirmed response, while the
 * session is still active. Use to send unsolicited PDUs (e.g. InformationReport)
 * immediately after a specific request is serviced — no sleep/polling needed.
 *
 * Parameters:
 *   session   — active session (use iec61850_iso_send() to push unsolicited data)
 *   req_domain, req_item — domain and item_id from the just-served request
 *   user_data — opaque pointer registered in iec61850_mms_server_config_t
 */
typedef void (*iec61850_mms_after_response_cb)(
    struct iec61850_mms_session_s *session,
    const char *req_domain,
    const char *req_item,
    void *user_data);

typedef struct {
    uint16_t port;          /* TCP port (default 102) */
    uint32_t max_pdu_size;  /* Max MMS PDU size */
    uint32_t max_sessions;  /* Max concurrent sessions */
    int accept_timeout_ms;  /* Accept timeout */
    iec61850_mms_after_response_cb after_response;  /* optional post-response hook */
    void *after_response_user_data;
} iec61850_mms_server_config_t;

/* Server result codes */
typedef enum {
    IEC61850_MMS_SERVER_OK = 0,
    IEC61850_MMS_SERVER_ERR_ARGS = -1,
    IEC61850_MMS_SERVER_ERR_RUNNING = -2,
    IEC61850_MMS_SERVER_ERR_BIND = -3,
    IEC61850_MMS_SERVER_ERR_LISTEN = -4,
    IEC61850_MMS_SERVER_ERR_THREAD = -5
} iec61850_mms_server_result_t;

/* Per-session state */
typedef struct iec61850_mms_session_s {
    iec61850_iso_conn_t iso;
    pthread_t thread;
    atomic_bool active;
    atomic_bool stop_requested;
    iec61850_mms_data_store_t *data_store;  /* shared, not owned */
    iec61850_control_manager_t *control_manager;  /* shared, not owned */
    iec61850_mms_file_service_t *file_service;    /* shared, not owned */
    iec61850_journal_t *journal;                  /* shared, not owned */
    uint32_t max_pdu_size;
    uint32_t invoke_id;
    uint32_t session_id;
    iec61850_mms_after_response_cb after_response;   /* optional, copied from config */
    void *after_response_user_data;
} iec61850_mms_session_t;

/* MMS Server */
typedef struct {
    iec61850_mms_server_config_t config;
    iec61850_mms_data_store_t *data_store;  /* shared, not owned */
    iec61850_control_manager_t *control_manager;  /* shared, not owned (optional) */
    iec61850_mms_file_service_t *file_service;    /* shared, not owned (optional) */
    iec61850_journal_t *journal;                  /* shared, not owned (optional) */
    iec61850_tcp_listener_t listener;
    pthread_t accept_thread;
    atomic_bool running;
    atomic_bool stop_requested;
    iec61850_mms_session_t sessions[IEC61850_MMS_MAX_SESSIONS];
    atomic_uint active_session_count;
    uint32_t next_session_id;
} iec61850_mms_server_t;

/**
 * Initialize server config with defaults.
 */
void iec61850_mms_server_config_init(iec61850_mms_server_config_t *cfg);

/**
 * Initialize MMS server.
 */
void iec61850_mms_server_init(iec61850_mms_server_t *server,
                                const iec61850_mms_server_config_t *cfg,
                                iec61850_mms_data_store_t *data_store);

/**
 * Start the MMS server (launches accept thread).
 */
int iec61850_mms_server_start(iec61850_mms_server_t *server);

/**
 * Stop the MMS server (waits for all sessions to finish).
 */
int iec61850_mms_server_stop(iec61850_mms_server_t *server);

/**
 * Check if server is running.
 */
bool iec61850_mms_server_is_running(const iec61850_mms_server_t *server);

/**
 * Get active session count.
 */
uint32_t iec61850_mms_server_get_session_count(
    const iec61850_mms_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_SERVER_H */
