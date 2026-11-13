/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Ed.2 control wire scenario — used by wire capture tests.
 *
 * Runs the repository's own MMS server (control manager wired through
 * the WP-2w control-object bridge) and a repository MMS client driving
 * the control over the IEC 61850-8-1 Ed.2 CO-object mapping on real
 * TCP loopback, so the exchange lands on the wire as ordinary MMS
 * Reads/Writes the neutral tshark dissector decodes cleanly:
 *
 *   - status Read (object context)
 *   - ctlModel Read (the 7-2 "$CF$" configuration-attribute spelling)
 *   - Select: Read of "<LN>$CO$<DO>$SBO" (sbo-with-normal-security),
 *     answered with the selected object reference string
 *   - Operate: Write of the 8-1 Oper structure { ctlVal, origin,
 *     ctlNum, T, Test, Check } to "<LN>$CO$<DO>$Oper" -> command
 *     executes and the CommandTermination arrives as an unsolicited
 *     InformationReport on the "$Oper" object (received by the client)
 *   - Cancel: Write of the Cancel structure to "<LN>$CO$<DO>$Cancel"
 *     after a fresh select
 *   - Ed.2 rejection: Operate without a prior select on a strict
 *     (sboClass=STRICT) object -> in-band Write-Response failure
 *     (DataAccessError); AddCause OBJECT_NOT_SELECTED recorded
 *     server-side
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
static int g_ct_count;
static iec61850_mms_client_command_termination_t g_last_ct;

static int on_action(const char *domain, const char *item_id,
                     const mms_value_t *value, void *user_data)
{
    (void)domain;
    (void)item_id;
    (void)value;
    (void)user_data;
    g_action_count++;
    return 0;
}

static void on_command_termination(
    const iec61850_mms_client_command_termination_t *termination,
    void *user_data)
{
    (void)user_data;
    g_ct_count++;
    g_last_ct = *termination;
}

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
    CHECK(iec61850_control_set_action_callback(&g_ctrl, CW_LD, CW_POS2,
                                                on_action, NULL) == 0);

    iec61850_mms_server_config_init(&cfg);
    cfg.port = port;
    iec61850_mms_server_init(&g_srv, &cfg, &g_ds);
    /* WP-2w: wire the control manager through the control-object
     * bridge (CO variables + Read/Write dispatch + unsolicited
     * CommandTermination on the owning association). */
    CHECK(iec61850_mms_server_set_control_manager(&g_srv, &g_ctrl) == 0);
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

static void step_read_ctl_model(iec61850_mms_client_t *client)
{
    int32_t ctl_model = -1;

    STEP("read ctlModel (7-2 CF spelling)");
    CHECK(iec61850_mms_client_read_ctl_model(client, CW_LD, CW_POS,
                                              &ctl_model) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(ctl_model == 2);   /* strict = sbo-with-normal-security */
    OK();
}

static void step_select_operate(iec61850_mms_client_t *client)
{
    iec61850_mms_client_operate_params_t params;

    STEP("select (SBO read) on strict object");
    CHECK(iec61850_mms_client_select(client, CW_LD, CW_POS) ==
          IEC61850_MMS_CLIENT_OK);
    OK();

    STEP("operate with the Oper structure: command executes");
    (void)memset(&params, 0, sizeof(params));
    params.ctl_val = true;
    params.origin_cat = 1;      /* bay-level */
    params.origin_ident = "wire-client";
    params.ctl_num = 1U;
    CHECK(iec61850_mms_client_operate(client, CW_LD, CW_POS, &params) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(g_action_count == 1);
    OK();

    STEP("CommandTermination received (unsolicited InformationReport)");
    for (int i = 0; (i < 40) && (g_ct_count == 0); i++) {
        (void)iec61850_mms_client_poll(client, 200);
    }
    CHECK(g_ct_count == 1);
    CHECK(strcmp(g_last_ct.domain, CW_LD) == 0);
    CHECK(strcmp(g_last_ct.item_id, "XCBR1$CO$Pos$Oper") == 0);
    CHECK(g_last_ct.ctl_val);
    CHECK((int)g_last_ct.origin_cat == 1);
    CHECK(g_last_ct.ctl_num == 1U);
    CHECK(g_last_ct.timestamp_ms > 0ULL);
    OK();
}

static void step_select_cancel(iec61850_mms_client_t *client)
{
    STEP("select then cancel an outstanding selection");
    CHECK(iec61850_mms_client_select(client, CW_LD, CW_POS2) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(iec61850_mms_client_cancel(client, CW_LD, CW_POS2) ==
          IEC61850_MMS_CLIENT_OK);
    OK();
}

static void step_ed2_reject_operate_without_select(iec61850_mms_client_t *client)
{
    iec61850_mms_client_operate_params_t params;
    iec61850_control_addcause_t addcause = IEC61850_ADDCAUSE_UNKNOWN;

    STEP("Ed.2 rejection: operate without select on strict object");
    /* The cancel above released the selection; a strict object must
     * refuse the bare operate. On the wire this is a Write-Response
     * failure CHOICE (DataAccessError) — an ordinary, cleanly
     * dissected MMS PDU (the scenario asserts the in-process Ed.2
     * AddCause separately). */
    (void)memset(&params, 0, sizeof(params));
    params.ctl_val = true;
    CHECK(iec61850_mms_client_operate(client, CW_LD, CW_POS2, &params) ==
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
            iec61850_mms_client_set_command_termination_handler(
                &client, on_command_termination, NULL);
            step_read_status(&client);
            step_read_ctl_model(&client);
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
