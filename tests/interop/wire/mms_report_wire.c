/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Ed.2 reporting wire scenario — used by wire capture tests.
 *
 * Runs the repository's own MMS server (RCB manager wired in, RCBs
 * auto-configured from SCL) and the repository's own MMS client
 * (mms_client_rcb.h) in one process over real TCP loopback, so the
 * whole Ed.2 reporting exchange lands on the wire and can be
 * captured (tshark/tcpdump on lo) and dissected:
 *
 *   - discover RCBs (GetNameList, $-separated component naming)
 *   - read RCB components (Read on LLN0$RP$..$RptEna & friends)
 *   - Ed.2 rejection: RptEna=TRUE on an unreserved URCB comes back
 *     as a real MMS Write failure (in-band DataAccessError)
 *   - enroll (Resv=TRUE, RptID/DatSet/OptFlds/TrgOps, RptEna=TRUE)
 *   - trigger a data change and receive the InformationReport
 *   - general interrogation (GI component write -> snapshot report)
 *   - BRCB: enroll, live buffered reports with EntryIDs, client loss
 *     (disconnect), host-side buffering while detached, EntryID
 *     read-back, resume after reconnect, live report, PurgeBuf
 *
 * Usage: mms_report_wire [port]   (default 10610)
 *
 * Build (manual, matches the meson test link line):
 *   cc -std=c11 -I<src>/include/iec61850 -D_POSIX_C_SOURCE=200809L \
 *      -D_DEFAULT_SOURCE -o mms_report_wire mms_report_wire.c \
 *      --start-group <build>/libiec61850.a <build>/libmms_ber.a \
 *      --end-group -pthread $(pkg-config --libs libxml-2.0 openssl)
 */

#include "mms/mms_client_rcb.h"
#include "mms/mms_data_store.h"
#include "mms/mms_report.h"
#include "mms/mms_server.h"
#include "scl/scl_parser.h"
#include "scl/scl_ied_builder.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RW_PORT     10610
#define RW_LD       "LD"    /* RCB component objects  */
#define RW_LDD      "LDD"   /* monitored data points  */
#define RW_URCB_REF "LLN0$RP$URCB01"  /* SCL-configured URCB */
#define RW_BRCB_REF "LLN0$BR$BRCB01"  /* SCL-configured BRCB */
#define RW_STVAL    "XCBR1$ST$Pos$stVal"
#define RW_HZ       "MMXU1$MX$Hz$mag$f"

static int tests_run = 0;
static int tests_failed = 0;

#define STEP(name) do { tests_run++; printf("  [STEP] %s ... ", name); } while (0)
#define OK()       do { printf("OK\n"); } while (0)
#define BAD(msg)   do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)
#define CHECK(cond) do { if (!(cond)) { BAD(#cond); return; } } while (0)

static iec61850_mms_data_store_t g_ds;
static iec61850_rcb_manager_t g_mgr;
static iec61850_mms_server_t g_srv;
static bool g_srv_up;

static int g_report_count;
static mms_information_report_t g_reports[8];
static mms_information_report_t g_last;

static void on_report(const mms_information_report_t *report, void *user_data)
{
    (void)user_data;
    if (g_report_count < 8) {
        g_reports[g_report_count] = *report;
    }
    g_last = *report;
    g_report_count++;
}

static mms_value_t rw_bool(bool b)
{
    mms_value_t v;

    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BOOLEAN;
    v.value.boolean = b;
    return v;
}

static mms_value_t rw_int(int32_t i)
{
    mms_value_t v;

    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_INTEGER;
    v.value.integer = i;
    return v;
}

/* Pump the client association until want reports arrived (or timeout). */
static int pump(iec61850_mms_client_t *client, int timeout_ms, int want_reports)
{
    int waited = 0;

    while ((g_report_count < want_reports) && (waited < timeout_ms)) {
        int ret = iec61850_mms_client_poll(client, 50);

        if (ret < 0) {
            return ret;
        }
        waited += 50;
    }
    return (g_report_count >= want_reports) ? 0 : -1;
}

/* Wait for the server's session-teardown wiring to release the RCB
 * bridge association so the next connection starts detached. */
static void detach_wait(void)
{
    int waited = 0;

    while ((g_mgr.bridge.association != NULL) && (waited < 5000)) {
        usleep(10 * 1000);
        waited += 10;
    }
}

static int scl_path(char *path, size_t len)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    static const char *tries[] = {
        "tests/data/test.scd", "../tests/data/test.scd",
        "../../tests/data/test.scd", NULL
    };

    if (root != NULL) {
        (void)snprintf(path, len, "%s/tests/data/test.scd", root);
        return (access(path, R_OK) == 0) ? 0 : -1;
    }
    for (size_t i = 0U; tries[i] != NULL; i++) {
        (void)snprintf(path, len, "%s", tries[i]);
        if (access(path, R_OK) == 0) {
            return 0;
        }
    }
    return -1;
}

static void setup(uint16_t port)
{
    iec61850_mms_server_config_t cfg;
    iec61850_scl_doc_t doc;
    mms_variable_spec_t members[2];
    mms_value_t v;
    char path[512];
    int added;

    iec61850_mms_ds_init(&g_ds);
    (void)iec61850_mms_ds_create_domain(&g_ds, RW_LD);
    (void)iec61850_mms_ds_create_domain(&g_ds, RW_LDD);

    v = rw_bool(true);
    (void)iec61850_mms_ds_create_variable(&g_ds, RW_LDD, RW_STVAL,
                                          MMS_TYPE_BOOLEAN, &v);
    v = rw_int(50);
    (void)iec61850_mms_ds_create_variable(&g_ds, RW_LDD, RW_HZ,
                                          MMS_TYPE_INTEGER, &v);

    (void)strncpy(members[0].domain, RW_LDD, MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(members[0].item_id, RW_STVAL, MMS_MAX_VARIABLE_NAME - 1);
    (void)strncpy(members[1].domain, RW_LDD, MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(members[1].item_id, RW_HZ, MMS_MAX_VARIABLE_NAME - 1);
    (void)iec61850_mms_ds_define_list(&g_ds, RW_LDD, "ds1", members, 2);

    /* RCBs from SCL (tests/data/test.scd: IED1 with URCB01 + BRCB01). */
    if (scl_path(path, sizeof(path)) != 0) {
        BAD("test.scd not found (set MESON_SOURCE_ROOT)");
        return;
    }
    iec61850_scl_doc_init(&doc);
    if (iec61850_scl_parse_file(path, "IED1", &doc) != 0) {
        BAD("SCL parse failed");
        return;
    }
    iec61850_rcb_manager_init(&g_mgr, RW_LD);
    added = iec61850_scl_auto_configure_rcbs(&doc, &g_mgr);
    if (added < 2) {
        BAD("SCL auto-config added < 2 RCBs");
        return;
    }

    iec61850_mms_server_config_init(&cfg);
    cfg.port = port;
    iec61850_mms_server_init(&g_srv, &cfg, &g_ds);
    if (iec61850_mms_server_set_rcb_manager(&g_srv, &g_mgr) != 0) {
        BAD("set_rcb_manager failed");
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
    iec61850_rcb_manager_destroy(&g_mgr);
    iec61850_mms_ds_destroy(&g_ds);
}

static void connect_client(iec61850_mms_client_t *client, uint16_t port)
{
    iec61850_mms_client_init(client);
    CHECK(iec61850_mms_client_connect(client, "127.0.0.1", port, 5000) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(iec61850_mms_client_set_report_handler(client, on_report, NULL) ==
          IEC61850_MMS_CLIENT_OK);
}

static void disconnect_client(iec61850_mms_client_t *client)
{
    (void)iec61850_mms_client_disconnect(client);
    detach_wait();
    CHECK(g_mgr.bridge.association == NULL);
}

/* Host-side data change while no client is associated. */
static void host_write(const char *item, const mms_value_t *v)
{
    CHECK(iec61850_mms_ds_write_variable(&g_ds, RW_LDD, item, v) ==
          (int)IEC61850_MMS_DS_OK);
    iec61850_rcb_bridge_on_write(&g_mgr, RW_LDD, item, NULL);
}

static void step_discover(iec61850_mms_client_t *client)
{
    char names[8][IEC61850_RCB_MAX_NAME];
    uint32_t count = 0U;
    bool urcb = false;
    bool brcb = false;

    STEP("discover: RCB list ($-separated component naming)");
    CHECK(iec61850_mms_client_rcb_list(client, RW_LD, names, &count, 8U) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK((int)count == 2);
    for (uint32_t i = 0U; i < count; i++) {
        if (strcmp(names[i], RW_URCB_REF) == 0) { urcb = true; }
        if (strcmp(names[i], RW_BRCB_REF) == 0) { brcb = true; }
    }
    CHECK(urcb);
    CHECK(brcb);
    OK();
}

static void step_read_components(iec61850_mms_client_t *client)
{
    iec61850_mms_client_rcb_values_t values;

    STEP("read components: URCB initial state (SCL attributes)");
    (void)memset(&values, 0, sizeof(values));
    CHECK(iec61850_mms_client_rcb_get_values(client, RW_LD, RW_URCB_REF,
                                             &values) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(!values.buffered);
    CHECK(!values.attrs.rpt_ena);
    CHECK(!values.resv);
    CHECK(strcmp(values.attrs.dat_set, "DS1") == 0);  /* from SCL */
    OK();
}

static void step_ed2_reject_enable_without_resv(iec61850_mms_client_t *client)
{
    STEP("Ed.2 rejection: RptEna=TRUE on unreserved URCB (MMS Write failure)");
    CHECK(iec61850_mms_client_rcb_enable(client, RW_LD, RW_URCB_REF) ==
          IEC61850_MMS_CLIENT_ERR_MMS);
    /* Still disabled and unreserved. */
    {
        iec61850_mms_client_rcb_values_t values;

        (void)memset(&values, 0, sizeof(values));
        CHECK(iec61850_mms_client_rcb_get_values(client, RW_LD, RW_URCB_REF,
                                                 &values) ==
              IEC61850_MMS_CLIENT_OK);
        CHECK(!values.attrs.rpt_ena);
        CHECK(!values.resv);
    }
    OK();
}

static void step_urcb_enroll(iec61850_mms_client_t *client)
{
    iec61850_mms_client_rcb_values_t values;
    iec61850_mms_client_rcb_values_t readback;
    uint32_t mask;

    STEP("enroll URCB: Resv, RptID, DatSet, OptFlds, TrgOps, RptEna");
    (void)memset(&values, 0, sizeof(values));
    values.resv = true;
    (void)strncpy(values.attrs.rpt_id, "R1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    (void)strncpy(values.attrs.dat_set, RW_LDD "/ds1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    values.attrs.opt_flds.sequence_number = true;
    values.attrs.opt_flds.reason_for_inclusion = true;
    values.attrs.trg_ops.data_change = true;
    values.attrs.trg_ops.general_interrogation = true;
    values.attrs.rpt_ena = true;

    mask = (uint32_t)IEC61850_RCB_FIELD_RPT_ID |
           (uint32_t)IEC61850_RCB_FIELD_RESV |
           (uint32_t)IEC61850_RCB_FIELD_DAT_SET |
           (uint32_t)IEC61850_RCB_FIELD_OPT_FLDS |
           (uint32_t)IEC61850_RCB_FIELD_TRG_OPS |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;
    CHECK(iec61850_mms_client_rcb_set_values(client, RW_LD, RW_URCB_REF,
                                             &values, mask) ==
          IEC61850_MMS_CLIENT_OK);

    (void)memset(&readback, 0, sizeof(readback));
    CHECK(iec61850_mms_client_rcb_get_values(client, RW_LD, RW_URCB_REF,
                                             &readback) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(readback.resv);
    CHECK(readback.attrs.rpt_ena);
    CHECK(strcmp(readback.attrs.rpt_id, "R1") == 0);
    CHECK(strcmp(readback.attrs.dat_set, RW_LDD "/ds1") == 0);
    CHECK(readback.owner_present && (readback.owner[0] != '\0'));
    OK();
}

static void step_data_change_report(iec61850_mms_client_t *client)
{
    mms_value_t v;

    STEP("data change: write monitored point, receive InformationReport");
    g_report_count = 0;
    v = rw_bool(false);
    CHECK(iec61850_mms_client_write(client, RW_LDD, RW_STVAL, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(pump(client, 5000, 1) == 0);
    CHECK(g_report_count == 1);
    CHECK(strcmp(g_last.variable_list_name, "R1") == 0);
    CHECK((int)g_last.num_values == 1);
    CHECK((int)g_last.values[0].type == (int)MMS_TYPE_BOOLEAN);
    CHECK(!g_last.values[0].value.boolean);
    CHECK(g_last.sq_num_present && ((int)g_last.sq_num == 1));
    CHECK(g_last.reasons_present);
    CHECK((int)g_last.reasons[0] == (int)IEC61850_REASON_DCHG);
    OK();
}

static void step_gi_report(iec61850_mms_client_t *client)
{
    iec61850_mms_client_rcb_values_t values;

    STEP("general interrogation: GI write, snapshot report");
    g_report_count = 0;
    (void)memset(&values, 0, sizeof(values));
    values.attrs.gi = true;
    CHECK(iec61850_mms_client_rcb_set_values(client, RW_LD, RW_URCB_REF,
                                             &values,
                                             (uint32_t)IEC61850_RCB_FIELD_GI) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(pump(client, 5000, 1) == 0);
    CHECK(g_report_count == 1);
    CHECK((int)g_last.num_values == 2);
    CHECK(g_last.reasons_present);
    CHECK((int)g_last.reasons[0] == (int)IEC61850_REASON_GI);
    CHECK((int)g_last.reasons[1] == (int)IEC61850_REASON_GI);
    OK();
}

static void step_brcb_enroll(iec61850_mms_client_t *client)
{
    iec61850_mms_client_rcb_values_t values;
    mms_value_t v;
    uint32_t mask;

    STEP("enroll BRCB: RptID, DatSet, OptFlds, TrgOps, BufTm=0, RptEna");
    /* Disable the URCB first (releases its reservation). */
    CHECK(iec61850_mms_client_rcb_disable(client, RW_LD, RW_URCB_REF) ==
          IEC61850_MMS_CLIENT_OK);

    (void)memset(&values, 0, sizeof(values));
    (void)strncpy(values.attrs.rpt_id, "B1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    (void)strncpy(values.attrs.dat_set, RW_LDD "/ds1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    values.attrs.opt_flds.sequence_number = true;
    values.attrs.opt_flds.reason_for_inclusion = true;
    values.attrs.opt_flds.entry_id = true;
    values.attrs.trg_ops.data_change = true;
    values.attrs.buf_tm = 0U;   /* immediate dispatch (SCL had 500 ms) */
    values.attrs.rpt_ena = true;

    mask = (uint32_t)IEC61850_RCB_FIELD_RPT_ID |
           (uint32_t)IEC61850_RCB_FIELD_DAT_SET |
           (uint32_t)IEC61850_RCB_FIELD_OPT_FLDS |
           (uint32_t)IEC61850_RCB_FIELD_TRG_OPS |
           (uint32_t)IEC61850_RCB_FIELD_BUF_TM |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;
    CHECK(iec61850_mms_client_rcb_set_values(client, RW_LD, RW_BRCB_REF,
                                             &values, mask) ==
          IEC61850_MMS_CLIENT_OK);
    OK();

    STEP("live buffered reports: EntryIDs 1, 2");
    g_report_count = 0;
    v = rw_bool(true);
    CHECK(iec61850_mms_client_write(client, RW_LDD, RW_STVAL, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(pump(client, 5000, 1) == 0);
    v = rw_int(60);
    CHECK(iec61850_mms_client_write(client, RW_LDD, RW_HZ, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(pump(client, 5000, 2) == 0);
    CHECK(g_report_count == 2);
    CHECK(g_reports[0].entry_id_present && (g_reports[0].entry_id == 1U));
    CHECK(g_reports[1].entry_id_present && (g_reports[1].entry_id == 2U));
    OK();

    STEP("EntryID read-back: last delivered entry visible in the BRCB");
    (void)memset(&values, 0, sizeof(values));
    CHECK(iec61850_mms_client_rcb_get_values(client, RW_LD, RW_BRCB_REF,
                                             &values) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(values.buffered);
    CHECK(values.attrs.entry_id == 2U);   /* visible marker */
    OK();
}

static void step_brcb_buffer_and_resume(iec61850_mms_client_t *client,
                                        uint16_t port)
{
    iec61850_mms_client_rcb_values_t values;
    mms_value_t v;

    STEP("client loss: BRCB stays enabled, buffers while detached");
    disconnect_client(client);
    CHECK(g_mgr.rcbs[1].attrs.rpt_ena);
    g_report_count = 0;   /* nothing may be delivered while detached */
    {
        mms_value_t w = rw_bool(false);

        host_write(RW_STVAL, &w);
    }
    {
        mms_value_t w = rw_int(61);

        host_write(RW_HZ, &w);
    }
    CHECK(g_report_count == 0);
    OK();

    STEP("resume after reconnect: arm EntryID=2, enable, entries 3+4");
    connect_client(client, port);
    CHECK(iec61850_mms_client_rcb_set_entry_id(client, RW_LD, RW_BRCB_REF,
                                               2U) ==
          IEC61850_MMS_CLIENT_OK);
    g_report_count = 0;
    CHECK(iec61850_mms_client_rcb_enable(client, RW_LD, RW_BRCB_REF) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(pump(client, 5000, 2) == 0);
    CHECK(g_report_count == 2);
    CHECK(g_reports[0].entry_id_present && (g_reports[0].entry_id == 3U));
    CHECK(g_reports[1].entry_id_present && (g_reports[1].entry_id == 4U));
    OK();

    STEP("live reporting continues after resume (EntryID=5)");
    g_report_count = 0;
    v = rw_bool(true);
    CHECK(iec61850_mms_client_write(client, RW_LDD, RW_STVAL, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(pump(client, 5000, 1) == 0);
    CHECK(g_last.entry_id_present && (g_last.entry_id == 5U));
    OK();

    STEP("purge: PurgeBuf=TRUE resets the buffer and marker");
    CHECK(iec61850_mms_client_rcb_purge_buffer(client, RW_LD, RW_BRCB_REF) ==
          IEC61850_MMS_CLIENT_OK);
    (void)memset(&values, 0, sizeof(values));
    CHECK(iec61850_mms_client_rcb_get_values(client, RW_LD, RW_BRCB_REF,
                                             &values) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(values.attrs.entry_id == 0U);
    OK();
}

int main(int argc, char **argv)
{
    uint16_t port = (argc > 1) ? (uint16_t)atoi(argv[1]) : (uint16_t)RW_PORT;
    iec61850_mms_client_t client;

    printf("=== MMS Ed.2 report wire scenario (port %u) ===\n", (unsigned)port);
    setup(port);
    if (g_srv_up) {
        connect_client(&client, port);
        step_discover(&client);
        step_read_components(&client);
        step_ed2_reject_enable_without_resv(&client);
        step_urcb_enroll(&client);
        step_data_change_report(&client);
        step_gi_report(&client);
        step_brcb_enroll(&client);
        step_brcb_buffer_and_resume(&client, port);
        disconnect_client(&client);
    }
    teardown();

    printf("\n=== Scenario summary: %d steps, %d failed ===\n",
           tests_run, tests_failed);
    return (tests_failed > 0) ? 1 : 0;
}
