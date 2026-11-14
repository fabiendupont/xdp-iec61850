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
#include "mms/mms_setting_groups.h"
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

/* WP-2w: per-control-object bridge state budget — one entry per
 * control object registered in the wired manager (bounded by the
 * manager's own IEC61850_CONTROL_MAX_OBJECTS). */
#define IEC61850_MMS_SERVER_MAX_CONTROL_REGS IEC61850_CONTROL_MAX_OBJECTS

/* Server configuration */
/* Forward declaration for use in callback typedef */
struct iec61850_mms_session_s;
struct iec61850_mms_server_s;

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
    /*
     * WP-3b (IEC 62351-4): TLS associations. When tls_enabled, the
     * server binds a TLS listener on tls_port (default 3782) with
     * the provider's server certificate and accepts secure MMS
     * associations (handshake + certificate policy per tls_mode).
     * With tls_only additionally set, the plain TCP listener is
     * not bound at all (secure associations only); otherwise both
     * listeners run and plain and TLS sessions are served
     * concurrently. Requires a security-enabled build
     * (iec61850_mms_server_start returns -ENOTSUP otherwise).
     * The provider pointer is borrowed and must outlive the server.
     */
    bool tls_enabled;
    const iec61850_cert_provider_t *tls_provider;  /* not owned */
    iec61850_tls_mode_t tls_mode;
    uint16_t tls_port;      /* TLS port (default 3782) */
    bool tls_only;          /* secure associations only */
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

/* WP-2w: one control-object bridge registration. Snapshotted from
 * the wired iec61850_control_manager_t (public manager struct) while
 * the server is stopped; carries the bridge's per-object wire state.
 *
 * The mutable fields (selection_id, owner_session, oper_echo) are
 * guarded by the server's control_bridge_mutex: writes happen from
 * the owning session's request path, reads from the command-
 * termination callback which may run on any session thread that
 * drives iec61850_control_process(). */
typedef struct iec61850_mms_control_reg_s {
    char domain[MMS_MAX_DOMAIN_NAME];
    char item_id[MMS_MAX_VARIABLE_NAME];  /* "<LN>$CO$<DO>" */
    uint32_t selection_id;                /* selection issued by this bridge */
    void *owner_session;                  /* session owning the selection */
    uint8_t oper_echo[MMS_MAX_STRING_LENGTH]; /* last accepted Oper body */
    size_t oper_echo_len;
    /* Application termination callback chained after the bridge's
     * CommandTermination PDU send (captured at wiring time). */
    iec61850_control_termination_cb_t app_termination_cb;
    void *app_termination_user_data;
} iec61850_mms_control_reg_t;

/* Per-session state */
typedef struct iec61850_mms_session_s {
    iec61850_iso_conn_t iso;
    pthread_t thread;
    atomic_bool active;
    atomic_bool stop_requested;
    struct iec61850_mms_server_s *server;       /* owning server (WP-2w) */
    iec61850_mms_data_store_t *data_store;  /* shared, not owned */
    iec61850_control_manager_t *control_manager;  /* shared, not owned */
    iec61850_mms_file_service_t *file_service;    /* shared, not owned */
    iec61850_journal_t *journal;                  /* shared, not owned */
    /* WP-2x: RCB-manager registrations (array shared with the server,
     * fixed before start; not owned). Empty when no manager is set. */
    iec61850_mms_server_rcb_reg_t *rcb_regs;
    uint32_t rcb_reg_count;
    iec61850_sg_manager_t *sg_manager;   /* shared, not owned (optional) */
    /* WP-2w: control-object bridge registrations (array shared with
     * the server, fixed before start; not owned). Empty when no
     * control manager is wired through the bridge API. */
    iec61850_mms_control_reg_t *control_regs;
    uint32_t control_reg_count;
    uint32_t max_pdu_size;
    uint32_t invoke_id;
    uint32_t session_id;
    iec61850_mms_after_response_cb after_response;   /* optional, copied from config */
    void *after_response_user_data;
} iec61850_mms_session_t;

/* MMS Server */
typedef struct iec61850_mms_server_s {
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
    /* SGCB (setting groups): wired into the Read/Write dispatch.
     * Set before start; shared with every session. */
    iec61850_sg_manager_t *sg_manager;
    /* WP-2w: control-object bridge — the per-object wire state of the
     * control manager wired via iec61850_mms_server_set_control_
     * manager(). The registration table is snapshotted while the
     * server is stopped; the mutex guards the mutable fields across
     * session threads (see iec61850_mms_control_reg_t). It is never
     * destroyed: the server type has no destroy API and the mutex
     * holds no allocation (same lifetime pattern as the session
     * resources released by server_stop()). */
    iec61850_mms_control_reg_t
        control_regs[IEC61850_MMS_SERVER_MAX_CONTROL_REGS];
    uint32_t control_reg_count;
    pthread_mutex_t control_bridge_mutex;
    iec61850_tcp_listener_t listener;
    /*
     * WP-3b (IEC 62351-4): TLS listener. Bound at start() when
     * config.tls_enabled; inert (and never referenced) otherwise.
     * The type exists in all builds; the implementation links only
     * in security-enabled builds.
     */
    iec61850_tls_listener_t tls_listener;
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
 * Attach a setting-group manager (SGCB). Accepted only while the
 * server is stopped. Sessions bridge SG/SE variable reads and
 * writes through it before the data store.
 */
int iec61850_mms_server_set_sg_manager(iec61850_mms_server_t *server,
                                       iec61850_sg_manager_t *mgr);

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

/**
 * WP-2w: wire a control manager into the server as IEC 61850-8-1
 * Ed.2 control objects (the CO-object wire mapping).
 *
 * The manager's registered control objects (domain +
 * "<LN>$CO$<DO>" item references) are exposed at server start as
 * data-store named variables and dispatched by the bridge:
 *
 *   - Write of TRUE / of the Oper structure to
 *     "<LN>$CO$<DO>$SBO" (or the structure to "$SBOw") performs a
 *     select with the writing session as owner
 *     (iec61850_control_select / _select_with_value);
 *   - Read of "<LN>$CO$<DO>$SBO" also performs a select (the
 *     8-1 sbo-with-normal-security form observed from conformant
 *     clients) and answers with the selected object reference
 *     "<domain>/<LN>$CO$<DO>" as a VisibleString; a rejected select
 *     answers with an in-band DataAccessError;
 *   - Write of the Oper structure to "<LN>$CO$<DO>$Oper" performs
 *     the operate (iec61850_control_operate_ed2, operTm honored when
 *     the structure carries it);
 *   - Write to "<LN>$CO$<DO>$Cancel" cancels the outstanding
 *     selection / time-activated operate;
 *   - "<LN>$CO$<DO>$ctlModel", "$sboTimeout" and "$OperTm" (plus
 *     the 7-2 configuration-attribute spellings
 *     "<LN>$CF$<DO>$ctlModel" / "$sboTimeout") are readable and
 *     serve the configured values.
 *
 * Command termination is wired: the bridge installs a termination
 * callback on every bridged object and sends the Ed.2
 * CommandTermination as an unsolicited MMS InformationReport on the
 * "<LN>$CO$<DO>$Oper" object (the 8-1 mapping) to the owning
 * association. A termination callback the application installed
 * before this call is chained after the PDU send; one installed
 * afterwards replaces the bridge's (no CommandTermination PDU).
 *
 * The session loop's recv-timeout tick and post-response hook run
 * iec61850_control_process() (selection timeout cleanup, operTm
 * firing) while a bridge registration exists.
 *
 * The house-encoded ISO 9506-2-style Select/Operate/Cancel confirmed
 * services (server->control_manager set directly) keep working
 * unchanged; wiring through this API adds the object mapping on top.
 *
 * @param server  Server (must be stopped)
 * @param mgr     Control manager (must outlive the server; not owned)
 * @return 0 on success, -EINVAL on bad arguments, -EBUSY while the
 *         server is running, -ENOSPC when the registration table is
 *         full.
 */
int iec61850_mms_server_set_control_manager(
    iec61850_mms_server_t *server, iec61850_control_manager_t *mgr);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_SERVER_H */
