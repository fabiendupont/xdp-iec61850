/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Ed.2 control wire scenario — used by wire capture tests.
 *
 * Runs the repository's own MMS server (control manager wired in,
 * strict sboClass objects) and a repository MMS client driving the
 * ISO 9506-2 control services (Select / Operate / Cancel) over real
 * TCP loopback, so the Ed.2 SBO exchange lands on the wire and can
 * be captured (tshark/tcpdump on lo) and dissected:
 *
 *   - Select (SBO) request/response on a strict control object
 *   - Operate with the selection ID -> command execution +
 *     in-process command-termination callback (Ed.2)
 *   - Cancel of an outstanding selection
 *   - Ed.2 rejection: Operate without a prior select on a strict
 *     (sboClass=STRICT) object -> ConfirmedError PDU from the
 *     server; AddCause OBJECT_NOT_SELECTED recorded server-side
 *
 * Usage: mms_control_wire [port]   (default 10611)
 *
 * Build (manual, matches the meson test link line):
 *   cc -std=c11 -I<src>/include/iec61850 -D_POSIX_C_SOURCE=200809L \
 *      -D_DEFAULT_SOURCE -o mms_control_wire mms_control_wire.c \
 *      --start-group <build>/libiec61850.a <build>/libmms_ber.a \
 *      --end-group -pthread
 */

#include "mms/mms_client.h"
#include "mms/mms_control.h"
#include "mms/mms_data_store.h"
#include "mms/mms_server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CW_PORT  10611
#define CW_LD    "LD"
#define CW_POS   "XCBR1$CO$Pos"   /* strict object: select -> operate */
#define CW_POS2  "CSWI1$CO$Pos"   /* strict object: rejection target  */
#define CW_STVAL "XCBR1$ST$Pos$stVal"

static int tests_run = 0;
static int tests_failed = 0;

#define STEP(name) do { tests_run++; printf("  [STEP] %s ... ", name); } while (0)
#define OK()       do { printf("OK\n"); } while (0)
#define BAD(msg)   do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)
#define CHECK(cond) do { if (!(cond)) { BAD(#cond); return; } } while (0)

static iec61850_mms_data_store_t g_ds;
static iec61850_control_manager_t g_ctrl;
static iec61850_mms_server_t g_srv;
static bool g_srv_up;

static int g_action_count;
static int g_termination_count;
static char g_term_item[MMS_MAX_VARIABLE_NAME];
static uint32_t g_term_selection_id;
static bool g_term_success;

static int on_action(const char *domain, const char *item_id,
                     const mms_value_t *value, void *user_data)
{
    (void)domain;
    (void)value;
    (void)user_data;
    g_action_count++;
    (void)snprintf(g_term_item, sizeof(g_term_item), "%s", item_id);
    return 0;
}

static void on_termination(const char *domain, const char *item_id,
                           uint32_t selection_id, bool success,
                           iec61850_control_addcause_t addcause,
                           uint64_t timestamp_ms, void *user_data)
{
    (void)domain;
    (void)addcause;
    (void)timestamp_ms;
    (void)user_data;
    g_termination_count++;
    g_term_selection_id = selection_id;
    g_term_success = success;
    (void)snprintf(g_term_item, sizeof(g_term_item), "%s", item_id);
}

/* ========================================================================
 * Client-side control transact: encode a confirmed request, submit it
 * to the async core and block for the response (the blocking client
 * wrapper mms_client.c has no control wrappers, so this mirrors its
 * internal transact() on public core API).
 * ======================================================================== */

typedef struct {
    mms_confirmed_response_t *resp_place;
    bool got_response;
    bool got_error;
} cw_transact_ctx_t;

static void cw_transact_cb(int status,
                           const mms_confirmed_response_t *response,
                           const mms_confirmed_error_t *error,
                           void *user_data)
{
    cw_transact_ctx_t *ctx = (cw_transact_ctx_t *)user_data;

    if (status != 0) {
        return;
    }
    if (response != NULL) {
        *ctx->resp_place = *response;
        ctx->got_response = true;
    } else if (error != NULL) {
        ctx->got_error = true;
    }
}

static int cw_transact(iec61850_mms_client_t *client,
                       const mms_confirmed_request_t *req,
                       mms_confirmed_response_t *resp, bool *got_error)
{
    uint8_t req_buf[4096];
    cw_transact_ctx_t ctx;
    int ret;

    *got_error = false;
    ret = mms_encode_confirmed_request(req, req_buf, sizeof(req_buf));
    if (ret <= 0) {
        return IEC61850_MMS_CLIENT_ERR_ENCODE;
    }

    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.resp_place = resp;

    ret = iec61850_mms_client_core_submit(&client->core, req_buf,
                                          (size_t)ret, req->invoke_id,
                                          cw_transact_cb, &ctx);
    if (ret != 0) {
        return IEC61850_MMS_CLIENT_ERR_TRANSPORT;
    }

    ret = iec61850_mms_client_core_wait(&client->core, req->invoke_id,
                                        client->request_timeout_ms);
    if (ret != 0) {
        /* Drop the still-pending entry so its callback never fires
         * into dead stack memory. */
        for (uint32_t i = 0U;
             i < (uint32_t)IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
            iec61850_mms_core_pending_t *entry = &client->core.pending[i];

            if ((entry->in_use) && (!entry->delivered) &&
                (entry->invoke_id == req->invoke_id)) {
                entry->in_use = false;
                entry->cb = NULL;
            }
        }
        return IEC61850_MMS_CLIENT_ERR_TIMEOUT;
    }

    if (ctx.got_error) {
        *got_error = true;   /* ConfirmedError PDU from the server */
        return IEC61850_MMS_CLIENT_ERR_MMS;
    }
    if (!ctx.got_response) {
        return IEC61850_MMS_CLIENT_ERR_MMS;
    }
    return IEC61850_MMS_CLIENT_OK;
}

static int cw_select(iec61850_mms_client_t *client, const char *item,
                     uint32_t *selection_id)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    bool got_error = false;
    int ret;

    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++;
    req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_SELECT;
    (void)strncpy(req.params.select.control_object.domain, CW_LD,
                  (size_t)MMS_MAX_DOMAIN_NAME - 1U);
    (void)strncpy(req.params.select.control_object.item_id, item,
                  (size_t)MMS_MAX_VARIABLE_NAME - 1U);
    req.params.select.check_value = 0U;
    req.params.select.select_timeout_ms = 0U;

    ret = cw_transact(client, &req, &resp, &got_error);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) {
        return ret;
    }
    if (resp.service != MMS_SERVICE_TYPE_SELECT) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }
    *selection_id = resp.params.select.selection_id;
    return (resp.params.select.state == MMS_CONTROL_STATE_SELECTED) ?
           IEC61850_MMS_CLIENT_OK : IEC61850_MMS_CLIENT_ERR_MMS;
}

static int cw_operate(iec61850_mms_client_t *client, const char *item,
                      uint32_t selection_id, bool value)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    bool got_error = false;
    int ret;

    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++;
    req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_OPERATE;
    (void)strncpy(req.params.operate.control_object.domain, CW_LD,
                  (size_t)MMS_MAX_DOMAIN_NAME - 1U);
    (void)strncpy(req.params.operate.control_object.item_id, item,
                  (size_t)MMS_MAX_VARIABLE_NAME - 1U);
    req.params.operate.selection_id = selection_id;
    req.params.operate.control_value.type = MMS_TYPE_BOOLEAN;
    req.params.operate.control_value.value.boolean = value;
    req.params.operate.has_control_value = true;
    req.params.operate.operation_time = 0ULL;   /* immediate */

    ret = cw_transact(client, &req, &resp, &got_error);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) {
        return ret;
    }
    if (resp.service != MMS_SERVICE_TYPE_OPERATE) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }
    return resp.params.operate.success ? IEC61850_MMS_CLIENT_OK
                                       : IEC61850_MMS_CLIENT_ERR_MMS;
}

static int cw_cancel(iec61850_mms_client_t *client, const char *item,
                     uint32_t selection_id)
{
    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    bool got_error = false;
    int ret;

    (void)memset(&req, 0, sizeof(req));
    client->invoke_id++;
    req.invoke_id = client->invoke_id;
    req.service = MMS_SERVICE_TYPE_CANCEL;
    (void)strncpy(req.params.cancel.control_object.domain, CW_LD,
                  (size_t)MMS_MAX_DOMAIN_NAME - 1U);
    (void)strncpy(req.params.cancel.control_object.item_id, item,
                  (size_t)MMS_MAX_VARIABLE_NAME - 1U);
    req.params.cancel.selection_id = selection_id;

    ret = cw_transact(client, &req, &resp, &got_error);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) {
        return ret;
    }
    return (resp.service == MMS_SERVICE_TYPE_CANCEL) ?
           IEC61850_MMS_CLIENT_OK : IEC61850_MMS_CLIENT_ERR_DECODE;
}

/* ======================================================================== */

static void setup(uint16_t port)
{
    iec61850_mms_server_config_t cfg;
    iec61850_control_config_t strict;
    mms_value_t v;

    iec61850_mms_ds_init(&g_ds);
    (void)iec61850_mms_ds_create_domain(&g_ds, CW_LD);
    v.type = MMS_TYPE_BOOLEAN;
    v.value.boolean = true;
    (void)iec61850_mms_ds_create_variable(&g_ds, CW_LD, CW_STVAL,
                                          MMS_TYPE_BOOLEAN, &v);

    iec61850_control_manager_init(&g_ctrl);
    CHECK(iec61850_control_register(&g_ctrl, CW_LD, CW_POS) == 0);
    CHECK(iec61850_control_register(&g_ctrl, CW_LD, CW_POS2) == 0);

    /* Ed.2 sboClass: both objects strict (operate requires a prior,
     * still-valid select). */
    strict.sbo_timeout_ms = 0U;
    strict.sbo_class = IEC61850_CONTROL_SBO_CLASS_STRICT;
    CHECK(iec61850_control_configure(&g_ctrl, CW_LD, CW_POS, &strict) == 0);
    CHECK(iec61850_control_configure(&g_ctrl, CW_LD, CW_POS2, &strict) == 0);

    CHECK(iec61850_control_set_action_callback(&g_ctrl, CW_LD, CW_POS,
                                               on_action, NULL) == 0);
    CHECK(iec61850_control_set_termination_callback(&g_ctrl, CW_LD, CW_POS,
                                                    on_termination, NULL) == 0);

    iec61850_mms_server_config_init(&cfg);
    cfg.port = port;
    iec61850_mms_server_init(&g_srv, &cfg, &g_ds);
    /* No setter exists for the control manager (unlike the RCB
     * manager): the public server struct field is the wiring point —
     * accept_thread copies it into every session. */
    g_srv.control_manager = &g_ctrl;
    if (iec61850_mms_server_start(&g_srv) != 0) {
        BAD("server start failed");
        return;
    }
    g_srv_up = true;
    usleep(200000);
}

static void teardown(void)
{
    if (g_srv_up) {
        (void)iec61850_mms_server_stop(&g_srv);
        g_srv_up = false;
    }
    iec61850_control_manager_destroy(&g_ctrl);
    iec61850_mms_ds_destroy(&g_ds);
}

static void step_read_status(iec61850_mms_client_t *client)
{
    mms_value_t v;

    STEP("read status point (object context)");
    (void)memset(&v, 0, sizeof(v));
    CHECK(iec61850_mms_client_read(client, CW_LD, CW_STVAL, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK((int)v.type == (int)MMS_TYPE_BOOLEAN);
    CHECK(v.value.boolean);
    OK();
}

static void step_select_operate(iec61850_mms_client_t *client)
{
    uint32_t sel_id = 0U;

    STEP("select (SBO) on strict object");
    CHECK(cw_select(client, CW_POS, &sel_id) == IEC61850_MMS_CLIENT_OK);
    CHECK(sel_id != 0U);
    printf("(selection_id=%u) ", (unsigned)sel_id);
    OK();

    STEP("operate with selection: command executes, terminates");
    CHECK(cw_operate(client, CW_POS, sel_id, true) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(g_action_count == 1);
    CHECK(g_termination_count == 1);
    CHECK(g_term_success);
    CHECK(g_term_selection_id == sel_id);
    CHECK(strcmp(g_term_item, CW_POS) == 0);
    OK();
}

static void step_select_cancel(iec61850_mms_client_t *client)
{
    uint32_t sel_id = 0U;

    STEP("select then cancel an outstanding selection");
    CHECK(cw_select(client, CW_POS2, &sel_id) == IEC61850_MMS_CLIENT_OK);
    CHECK(sel_id != 0U);
    CHECK(cw_cancel(client, CW_POS2, sel_id) == IEC61850_MMS_CLIENT_OK);
    OK();
}

static void step_ed2_reject_operate_without_select(iec61850_mms_client_t *client)
{
    iec61850_control_addcause_t addcause = IEC61850_ADDCAUSE_UNKNOWN;

    STEP("Ed.2 rejection: operate without select on strict object");
    /* The cancel above released the selection; a strict object must
     * refuse the bare operate. On the wire this is a ConfirmedError
     * PDU from the server (the scenario asserts the in-process Ed.2
     * AddCause separately). */
    CHECK(cw_operate(client, CW_POS2, 0U, true) ==
          IEC61850_MMS_CLIENT_ERR_MMS);
    CHECK(iec61850_control_get_last_addcause(&g_ctrl, CW_LD, CW_POS2,
                                             &addcause) == 0);
    CHECK(addcause == IEC61850_ADDCAUSE_OBJECT_NOT_SELECTED);
    CHECK(g_action_count == 1);   /* the rejected command never ran */
    OK();
}

int main(int argc, char **argv)
{
    uint16_t port = (argc > 1) ? (uint16_t)atoi(argv[1]) : (uint16_t)CW_PORT;
    iec61850_mms_client_t client;

    printf("=== MMS Ed.2 control wire scenario (port %u) ===\n",
           (unsigned)port);
    setup(port);
    if (g_srv_up) {
        iec61850_mms_client_init(&client);
        if (iec61850_mms_client_connect(&client, "127.0.0.1", port,
                                        5000) != IEC61850_MMS_CLIENT_OK) {
            BAD("client connect failed");
        } else {
            step_read_status(&client);
            step_select_operate(&client);
            step_select_cancel(&client);
            step_ed2_reject_operate_without_select(&client);
            (void)iec61850_mms_client_disconnect(&client);
        }
    }
    teardown();

    printf("\n=== Scenario summary: %d steps, %d failed ===\n",
           tests_run, tests_failed);
    return (tests_failed > 0) ? 1 : 0;
}
