/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Server for IEC 61850
 *
 * Thread-per-connection MMS server with service dispatch.
 * Handles GetNameList, Read, Write, GetVariableAccessAttributes,
 * association management, and report generation (via optional RCB
 * manager registration, WP-2x).
 */

#ifndef IEC61850_MMS_SERVER_H
#define IEC61850_MMS_SERVER_H

#include "mms/mms_data_store.h"
#include "mms/mms_control.h"
#include "mms/mms_file_service.h"
#include "mms/mms_journal.h"
#include "mms/mms_report.h"
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

/* WP-2x: bounded per-server RCB-manager registrations (one logical
 * device each; see iec61850_mms_server_set_rcb_manager). */
#define IEC61850_MMS_SERVER_MAX_RCB_MANAGERS 4

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

/* WP-2x: one RCB-manager registration. An iec61850_rcb_manager_t is
 * constructed for exactly one logical device (its ld_name), so the
 * registration binds the manager to the data-store domain the bridge
 * exposes its RCB component objects in. */
typedef struct iec61850_mms_server_rcb_reg_s {
    iec61850_rcb_manager_t *manager;  /* shared, not owned */
    char domain[MMS_MAX_DOMAIN_NAME];
} iec61850_mms_server_rcb_reg_t;

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
    /* WP-2x: RCB-manager registrations (array shared with the server,
     * fixed before start; not owned). Empty when no manager is set. */
    iec61850_mms_server_rcb_reg_t *rcb_regs;
    uint32_t rcb_reg_count;
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
    /* WP-2x: RCB managers wired into the server's Write dispatch,
     * post-response reconcile and session teardown. Registrations are
     * accepted only while the server is stopped and are exposed into
     * the data store at start(). */
    iec61850_mms_server_rcb_reg_t
        rcb_regs[IEC61850_MMS_SERVER_MAX_RCB_MANAGERS];
    uint32_t rcb_reg_count;
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

/**
 * WP-2x: wire an RCB manager into the server (RCB component objects,
 * Ed.2 pre-commit Write validation, report delivery, BufTm flush and
 * session-teardown ownership release).
 *
 * The manager is exposed at server start via
 * iec61850_rcb_manager_expose() into the data-store domain named by
 * the manager's own logical device (mgr->ld_name — an RCB manager is
 * constructed for exactly one LD, so it carries the domain to expose).
 * RCBs added to the manager before start are exposed with it.
 *
 * Effects while the server runs (per registered manager):
 *   - Write requests to "<ref>$<Component>" objects in the manager's
 *     domain are validated and applied by the bridge BEFORE the data
 *     store is touched (iec61850_rcb_bridge_write). Ed.2 rejections
 *     (e.g. a Resv write on a URCB held by another client) come back
 *     as real MMS Write failures; accepted writes are committed by
 *     the bridge and are not written to the store again.
 *   - every serviced request is reconciled through the bridge with
 *     the requesting session (data-change dispatch, BufTm liveness),
 *     so reports flow without an application-level hook;
 *   - the session loop's recv-timeout tick runs a periodic
 *     iec61850_rcb_bridge_sync() (closed BufTm windows flush and
 *     buffered reports deliver with no incoming request);
 *   - session teardown releases the bridge association (URCB
 *     reservation/Owner dropped; BRCBs keep buffering for resume).
 *
 * The application-level after_response callback keeps working and, if
 * installed, runs in addition to the server-owned reconcile.
 *
 * @param server  Server (must be stopped)
 * @param mgr     RCB manager (must outlive the server; not owned)
 * @return 0 on success, -EINVAL on bad arguments or an empty manager
 *         LD name, -EBUSY while the server is running, -EEXIST when
 *         the manager or its domain is already registered,
 *         -ENOSPC when the registration table is full.
 */
int iec61850_mms_server_set_rcb_manager(iec61850_mms_server_t *server,
                                         iec61850_rcb_manager_t *mgr);

/**
 * WP-2x: per-domain variant of iec61850_mms_server_set_rcb_manager()
 * for hosts that expose a manager's RCB component objects in an
 * explicitly named data-store domain (e.g. a domain name that differs
 * from the manager's ld_name, or several LDs behind one server).
 *
 * @param server  Server (must be stopped)
 * @param mgr     RCB manager (must outlive the server; not owned)
 * @param domain  Data-store domain to expose the component objects in
 * @return 0 on success, negative errno otherwise (see
 *         iec61850_mms_server_set_rcb_manager).
 */
int iec61850_mms_server_set_rcb_manager_domain(
    iec61850_mms_server_t *server, iec61850_rcb_manager_t *mgr,
    const char *domain);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_SERVER_H */
