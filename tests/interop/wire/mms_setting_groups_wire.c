/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS setting-groups (SGCB) wire scenario — used by wire capture
 * tests.
 *
 * Runs the repository's own MMS server (SG manager wired in, SE
 * attributes configured programmatically) and the repository's own
 * MMS client in one process over real TCP loopback, so the whole
 * IEC 61850-7-2 §14 setting-group exchange lands on the wire and
 * can be captured (tshark/tcpdump on lo) and dissected:
 *
 *   - read the SGCB attributes (NumOfSG / ActSG / EditSG / ResvTms)
 *   - read the read-only $SG$ active-group view
 *   - SE read outside an edit session is rejected (SE is the
 *     edit-session view; the store produces the object error)
 *   - SelectEditSG (EditSG=2), reservation visible in ResvTms
 *   - write an SE value into the edit group, read it back from
 *     the edit session, $SG$ view still untouched
 *   - SelectActiveSG (ActSG=2) — activation copies the edited
 *     group into the live model, $SG$ view follows
 *   - release the edit session (EditSG=0)
 *
 * Usage: mms_setting_groups_wire [port]   (default 10612)
 *
 * The wire names follow the 8-1 mapping wire-verified against the
 * libiec61850 reference server (WP-6x): LLN0$SP$SGCB$<attr> and
 * <LN>$SE$ / <LN>$SG$ value views.
 */

#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
#include "mms/mms_server.h"
#include "mms/mms_setting_groups.h"
#include "ied/ied_data_model.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SGW_PORT   10612
#define SGW_LD     "LD0"
#define SGW_NUM_SG 3

static int tests_run = 0;
static int tests_failed = 0;

#define STEP(name) do { tests_run++; printf("  [STEP] %s ... ", name); } while (0)
#define OK()       do { printf("OK\n"); } while (0)
#define BAD(msg)   do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)
#define CHECK(cond) do { if (!(cond)) { BAD(#cond); return; } } while (0)

static iec61850_mms_data_store_t g_ds;
static iec61850_ied_model_t *g_model;
static iec61850_sg_manager_t *g_mgr;
static iec61850_mms_server_t g_srv;
static bool g_srv_up;
static int g_activated;

static void on_activated(void *user, uint8_t act, uint8_t prev)
{
    (void)user;
    g_activated = (int)act * 10 + (int)prev;
}

static mms_value_t sgw_uint(uint32_t v)
{
    mms_value_t out;

    (void)memset(&out, 0, sizeof(out));
    out.type = MMS_TYPE_UNSIGNED;
    out.value.unsigned_val = v;
    return out;
}

static mms_value_t sgw_int(int32_t v)
{
    mms_value_t out;

    (void)memset(&out, 0, sizeof(out));
    out.type = MMS_TYPE_INTEGER;
    out.value.integer = v;
    return out;
}

static uint32_t read_uint(iec61850_mms_client_t *c, const char *item)
{
    mms_value_t v;

    if (iec61850_mms_client_read(c, SGW_LD, item, &v) !=
        IEC61850_MMS_CLIENT_OK) {
        return 0xFFFFFFFFU;
    }
    if (v.type != MMS_TYPE_UNSIGNED) {
        return 0xFFFFFFFFU;
    }
    return v.value.unsigned_val;
}

static void setup(uint16_t port)
{
    iec61850_mms_server_config_t cfg;
    iec61850_logical_device_t *ld;
    iec61850_logical_node_t *ln;
    iec61850_data_object_t *dobj;
    iec61850_data_attribute_t *setval;

    iec61850_mms_ds_init(&g_ds);
    (void)iec61850_mms_ds_create_domain(&g_ds, SGW_LD);

    /* IED model with one FC=SE setting (PTOC1.Mod.setVal). */
    g_model = calloc(1, sizeof(*g_model));
    ld = iec61850_ld_create(SGW_LD);
    ln = iec61850_ln_create("PTOC", "1");
    dobj = iec61850_do_create("Mod", IEC61850_CDC_DPC);
    (void)iec61850_do_add_attribute(dobj, "setVal", IEC61850_FC_SE,
                                     IEC61850_BTYPE_INT32);
    (void)iec61850_ln_add_data_object(ln, dobj);
    (void)iec61850_ld_add_logical_node(ld, ln);
    (void)iec61850_ied_model_add_ld(g_model, ld);

    setval = iec61850_ln_find_attribute(ln, "Mod.setVal", IEC61850_FC_SE);
    setval->value.type = MMS_TYPE_INTEGER;
    setval->value.value.integer = 100;

    if (iec61850_sg_manager_init(&g_mgr, g_model, SGW_NUM_SG, 1, 30) != 0) {
        BAD("sg manager init failed");
        return;
    }
    iec61850_sg_set_activation_callback(g_mgr, on_activated, NULL);

    iec61850_mms_server_config_init(&cfg);
    cfg.port = port;
    iec61850_mms_server_init(&g_srv, &cfg, &g_ds);
    if (iec61850_mms_server_set_sg_manager(&g_srv, g_mgr) != 0) {
        BAD("set_sg_manager failed");
        return;
    }
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
    iec61850_sg_manager_destroy(g_mgr);
    iec61850_mms_ds_destroy(&g_ds);
}

static void step_sgcb_reads(iec61850_mms_client_t *client)
{
    STEP("SGCB attribute reads (NumOfSG/ActSG/EditSG/ResvTms)");
    CHECK(read_uint(client, "LLN0$SP$SGCB$NumOfSG") == SGW_NUM_SG);
    CHECK(read_uint(client, "LLN0$SP$SGCB$ActSG") == 1U);
    CHECK(read_uint(client, "LLN0$SP$SGCB$EditSG") == 0U);
    CHECK(read_uint(client, "LLN0$SP$SGCB$ResvTms") == 0U);
    OK();
}

static void step_active_view(iec61850_mms_client_t *client)
{
    mms_value_t v;

    STEP("read the $SG$ active-group view");
    CHECK(iec61850_mms_client_read(client, SGW_LD,
                                   "PTOC1$SG$Mod$setVal", &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK((v.type == MMS_TYPE_INTEGER) && (v.value.integer == 100));
    OK();
}

static void step_se_invisible(iec61850_mms_client_t *client)
{
    mms_value_t v;

    STEP("SE read outside an edit session is rejected");
    CHECK(iec61850_mms_client_read(client, SGW_LD,
                                   "PTOC1$SE$Mod$setVal", &v) ==
          IEC61850_MMS_CLIENT_ERR_MMS);
    OK();
}

static void step_edit_flow(iec61850_mms_client_t *client)
{
    mms_value_t v;
    mms_value_t w;

    STEP("SelectEditSG (EditSG=2), reservation visible");
    v = sgw_uint(2);
    CHECK(iec61850_mms_client_write(client, SGW_LD,
                                    "LLN0$SP$SGCB$EditSG", &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(read_uint(client, "LLN0$SP$SGCB$EditSG") == 2U);
    CHECK(read_uint(client, "LLN0$SP$SGCB$ResvTms") == 30U);
    OK();

    STEP("write SE value into the edit group, read back");
    w = sgw_int(200);
    CHECK(iec61850_mms_client_write(client, SGW_LD,
                                    "PTOC1$SE$Mod$setVal", &w) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(iec61850_mms_client_read(client, SGW_LD,
                                   "PTOC1$SE$Mod$setVal", &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK((v.type == MMS_TYPE_INTEGER) && (v.value.integer == 200));

    STEP("$SG$ view untouched before activation");
    CHECK(iec61850_mms_client_read(client, SGW_LD,
                                   "PTOC1$SG$Mod$setVal", &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK((v.type == MMS_TYPE_INTEGER) && (v.value.integer == 100));
    OK();
}

static void step_activate(iec61850_mms_client_t *client)
{
    mms_value_t v;

    STEP("SelectActiveSG (ActSG=2) activates the edited group");
    v = sgw_uint(2);
    CHECK(iec61850_mms_client_write(client, SGW_LD,
                                    "LLN0$SP$SGCB$ActSG", &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(read_uint(client, "LLN0$SP$SGCB$ActSG") == 2U);
    CHECK(g_activated == 21);   /* callback: act 2, prev 1 */
    CHECK(iec61850_mms_client_read(client, SGW_LD,
                                   "PTOC1$SG$Mod$setVal", &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK((v.type == MMS_TYPE_INTEGER) && (v.value.integer == 200));
    OK();
}

static void step_release(iec61850_mms_client_t *client)
{
    mms_value_t v;

    STEP("release the edit session (EditSG=0)");
    v = sgw_uint(0);
    CHECK(iec61850_mms_client_write(client, SGW_LD,
                                    "LLN0$SP$SGCB$EditSG", &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(read_uint(client, "LLN0$SP$SGCB$EditSG") == 0U);
    CHECK(read_uint(client, "LLN0$SP$SGCB$ResvTms") == 0U);
    OK();
}

int main(int argc, char **argv)
{
    uint16_t port = (argc > 1) ? (uint16_t)atoi(argv[1]) : (uint16_t)SGW_PORT;
    iec61850_mms_client_t client;

    printf("=== MMS SGCB wire scenario (port %u) ===\n", (unsigned)port);
    setup(port);
    if (g_srv_up) {
        iec61850_mms_client_init(&client);
        if (iec61850_mms_client_connect(&client, "127.0.0.1", port,
                                        5000) !=
            IEC61850_MMS_CLIENT_OK) {
            BAD("client connect failed");
        }
        step_sgcb_reads(&client);
        step_active_view(&client);
        step_se_invisible(&client);
        step_edit_flow(&client);
        step_activate(&client);
        step_release(&client);
        (void)iec61850_mms_client_disconnect(&client);
    }
    teardown();

    printf("\n=== Scenario summary: %d steps, %d failed ===\n",
           tests_run, tests_failed);
    return (tests_failed > 0) ? 1 : 0;
}
