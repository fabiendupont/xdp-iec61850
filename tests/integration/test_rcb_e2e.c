/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * RCB End-to-End Integration Tests
 *
 * Tests Report Control Blocks (URCB and BRCB) end-to-end:
 * 1. URCB data change report with value verification
 * 2. URCB disabled -- no report on any trigger
 * 3. BRCB buffered reports -- multiple data changes accumulate
 * 4. General interrogation with data store snapshot
 * 5. Enable/disable lifecycle -- no report after disable
 *
 * No MMS server needed -- tests RCB directly with data store.
 */

#include "mms/mms_report.h"
#include "mms/mms_data_store.h"
#include "mms/mms_server.h"
#include "mms/mms_client_rcb.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)

#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)
#define ASSERT_STR(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAIL: %s == %s (\"%s\" != \"%s\")\n", #a, #b, (a), (b)); \
        tests_failed++; return; } } while (0)

/* Captured report state */
static int g_report_count;
static mms_information_report_t g_last_report;

static void capture_report(const mms_information_report_t *report,
                           void *user_data)
{
    (void)user_data;
    g_report_count++;
    g_last_report = *report;
}

/* ========================================================================
 * Test 1: URCB data change report -- enable, trigger, verify values
 * ======================================================================== */

static void test_urcb_data_change_report(void)
{
    TEST("urcb_data_change_report");

    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;
    rcb.attrs.opt_flds.reason_for_inclusion = true;

    g_report_count = 0;
    memset(&g_last_report, 0, sizeof(g_last_report));
    iec61850_rcb_set_report_sender(&rcb, capture_report, NULL);

    ASSERT_EQ(iec61850_rcb_enable(&rcb), 0);
    ASSERT_TRUE(rcb.attrs.rpt_ena);

    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_BOOLEAN;
    old_val.value.boolean = false;
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal",
                                &old_val, &new_val);

    /* Verify report generated */
    ASSERT_EQ(g_report_count, 1);

    /* Verify report ID matches RCB */
    ASSERT_EQ(strcmp(g_last_report.variable_list_name, "URCB01"), 0);

    /* Verify report contains the new value */
    ASSERT_EQ((int)g_last_report.num_values, 1);
    ASSERT_EQ((int)g_last_report.values[0].type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(g_last_report.values[0].value.boolean);

    /* Verify sequence number incremented */
    ASSERT_EQ((int)rcb.attrs.sq_num, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

/* ========================================================================
 * Test 2: URCB disabled -- no report on any trigger type
 * ======================================================================== */

static void test_urcb_disabled_no_report(void)
{
    TEST("urcb_disabled_no_report");

    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB02", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;
    rcb.attrs.trg_ops.data_update = true;
    rcb.attrs.trg_ops.general_interrogation = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, capture_report, NULL);
    /* Intentionally NOT enabling the RCB */

    /* Data change -- should be suppressed */
    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_INTEGER;
    old_val.value.integer = 0;
    new_val.type = MMS_TYPE_INTEGER;
    new_val.value.integer = 42;

    iec61850_rcb_on_data_change(&rcb, "MMXU1$MX$Hz$mag$f",
                                &old_val, &new_val);
    ASSERT_EQ(g_report_count, 0);

    /* Data update -- should be suppressed */
    mms_value_t upd_val;
    memset(&upd_val, 0, sizeof(upd_val));
    upd_val.type = MMS_TYPE_INTEGER;
    upd_val.value.integer = 50;
    iec61850_rcb_on_data_update(&rcb, "MMXU1$MX$Hz$mag$f", &upd_val);
    ASSERT_EQ(g_report_count, 0);

    /* GI -- should be suppressed */
    iec61850_rcb_trigger_gi(&rcb);
    ASSERT_EQ(g_report_count, 0);

    /* Sequence number should not have changed */
    ASSERT_EQ((int)rcb.attrs.sq_num, 0);

    iec61850_rcb_destroy(&rcb);
    PASS();
}

/* ========================================================================
 * Test 3: BRCB buffered reports -- multiple data changes accumulate
 * ======================================================================== */

static void test_brcb_buffered_reports(void)
{
    TEST("brcb_buffered_reports");

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int idx = iec61850_rcb_manager_add_rcb(&mgr, "BRCB01",
                                            IEC61850_RCB_BUFFERED, 16);
    ASSERT_TRUE(idx >= 0);

    iec61850_rcb_t *rcb = &mgr.rcbs[(uint32_t)idx];
    rcb->attrs.trg_ops.data_change = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(rcb, capture_report, NULL);
    iec61850_rcb_enable(rcb);

    /* Generate 5 data changes through the manager */
    for (int i = 0; i < 5; i++) {
        mms_value_t old_val, new_val;
        memset(&old_val, 0, sizeof(old_val));
        memset(&new_val, 0, sizeof(new_val));
        old_val.type = MMS_TYPE_INTEGER;
        old_val.value.integer = (int32_t)i;
        new_val.type = MMS_TYPE_INTEGER;
        new_val.value.integer = (int32_t)(i + 100);

        iec61850_rcb_manager_on_data_change(&mgr, "XCBR1$ST$Pos$stVal",
                                             &old_val, &new_val);
    }

    /* All 5 reports should have fired via callback */
    ASSERT_EQ(g_report_count, 5);

    /* The report buffer should have accumulated all 5 entries */
    iec61850_report_buffer_t *buf =
        iec61850_rcb_manager_get_buffer(&mgr, (uint32_t)idx);
    ASSERT_TRUE(buf != NULL);
    ASSERT_EQ((int)buf->count, 5);

    /* Verify buffer entries */
    iec61850_report_entry_t entries[16];
    uint32_t count = 0;
    int ret = iec61850_report_buffer_get_entries(buf, 0, entries,
                                                 &count, 16);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 5);

    /* All entries should be DCHG reason with correct values */
    for (uint32_t i = 0; i < count; i++) {
        ASSERT_EQ((int)entries[i].reason, (int)IEC61850_REASON_DCHG);
        ASSERT_EQ(entries[i].value.value.integer, (int32_t)(i + 100));
    }

    /* Entry IDs should be strictly increasing */
    for (uint32_t i = 1; i < count; i++) {
        ASSERT_TRUE(entries[i].entry_id > entries[i - 1].entry_id);
    }

    /* RCB entry_id should have incremented for each buffered report */
    ASSERT_EQ((int)rcb->attrs.entry_id, 5);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Test 4: General interrogation -- snapshot all data store values
 * ======================================================================== */

static void test_general_interrogation(void)
{
    TEST("general_interrogation");

    /* Set up a data store with a domain and variables */
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "LD0");

    mms_value_t v1 = {0};
    v1.type = MMS_TYPE_BOOLEAN;
    v1.value.boolean = true;
    iec61850_mms_ds_create_variable(&ds, "LD0", "XCBR1$ST$Pos$stVal",
                                    MMS_TYPE_BOOLEAN, &v1);

    mms_value_t v2 = {0};
    v2.type = MMS_TYPE_INTEGER;
    v2.value.integer = 60;
    iec61850_mms_ds_create_variable(&ds, "LD0", "MMXU1$MX$Hz$mag$f",
                                    MMS_TYPE_INTEGER, &v2);

    mms_value_t v3 = {0};
    v3.type = MMS_TYPE_FLOATING_POINT;
    v3.value.floating_point = 230.5f;
    iec61850_mms_ds_create_variable(&ds, "LD0", "MMXU1$MX$PhV$phsA",
                                    MMS_TYPE_FLOATING_POINT, &v3);

    /* Set up RCB with data store for GI snapshot */
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB_GI", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.general_interrogation = true;
    rcb.attrs.opt_flds.sequence_number = true;
    rcb.attrs.opt_flds.report_timestamp = true;
    rcb.attrs.opt_flds.reason_for_inclusion = true;
    rcb.data_store = &ds;
    strncpy(rcb.attrs.dat_set, "LD0/DS1", IEC61850_RCB_MAX_NAME - 1);

    g_report_count = 0;
    memset(&g_last_report, 0, sizeof(g_last_report));
    iec61850_rcb_set_report_sender(&rcb, capture_report, NULL);
    iec61850_rcb_enable(&rcb);

    /* Trigger GI */
    iec61850_rcb_trigger_gi(&rcb);

    /* Verify one report was generated */
    ASSERT_EQ(g_report_count, 1);

    /* Report should contain all 3 variables from the data store */
    ASSERT_EQ((int)g_last_report.num_values, 3);

    /* Optional fields should be present */
    ASSERT_TRUE(g_last_report.sq_num_present);
    ASSERT_TRUE(g_last_report.report_timestamp_present);
    ASSERT_TRUE(g_last_report.report_timestamp > 0);
    ASSERT_TRUE(g_last_report.reasons_present);

    /* Each reason should be GI */
    for (uint32_t i = 0; i < g_last_report.num_values; i++) {
        ASSERT_EQ((int)g_last_report.reasons[i],
                  (int)IEC61850_REASON_GI);
    }

    /* Sequence number should have incremented */
    ASSERT_EQ((int)rcb.attrs.sq_num, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    iec61850_mms_ds_destroy(&ds);
    PASS();
}

/* ========================================================================
 * Test 5: Enable/disable lifecycle -- no report after disable
 * ======================================================================== */

static void test_enable_disable_lifecycle(void)
{
    TEST("enable_disable_lifecycle");

    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB03", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, capture_report, NULL);

    /* Phase 1: enable and trigger -- should generate report */
    ASSERT_EQ(iec61850_rcb_enable(&rcb), 0);
    ASSERT_TRUE(rcb.attrs.rpt_ena);

    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_BOOLEAN;
    old_val.value.boolean = false;
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal",
                                &old_val, &new_val);
    ASSERT_EQ(g_report_count, 1);

    /* Phase 2: disable and trigger -- should NOT generate report */
    ASSERT_EQ(iec61850_rcb_disable(&rcb), 0);
    ASSERT_TRUE(!rcb.attrs.rpt_ena);

    new_val.value.boolean = false;
    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal",
                                &old_val, &new_val);
    ASSERT_EQ(g_report_count, 1);  /* Still 1 -- no new report */

    /* GI should also be suppressed when disabled */
    rcb.attrs.trg_ops.general_interrogation = true;
    iec61850_rcb_trigger_gi(&rcb);
    ASSERT_EQ(g_report_count, 1);

    /* Phase 3: re-enable and trigger -- should generate report again */
    ASSERT_EQ(iec61850_rcb_enable(&rcb), 0);
    ASSERT_TRUE(rcb.attrs.rpt_ena);

    new_val.value.boolean = true;
    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal",
                                &old_val, &new_val);
    ASSERT_EQ(g_report_count, 2);

    /* Sequence number should reflect both reports sent */
    ASSERT_EQ((int)rcb.attrs.sq_num, 2);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

/* ======================================================================== */

/* ========================================================================
 * WP-2a: Ed.2 RCB <-> data-store bridge (unit level, no server)
 * ======================================================================== */

#define BR_LD   "LD"
#define BR_LDD  "LDD"
#define BR_STVAL "XCBR1$ST$Pos$stVal"
#define BR_HZ    "MMXU1$MX$Hz$mag$f"
/* Exposed RCB references (WP-1f DIV-1: LN0 "$"-separated naming,
 * built by the bridge from the RCB name/type). */
#define BR_URCB_REF "LLN0$RP$u1"
#define BR_BRCB_REF "LLN0$BR$b1"

static mms_value_t br_bool(bool b)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BOOLEAN;
    v.value.boolean = b;
    return v;
}

static mms_value_t br_int(int32_t i)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_INTEGER;
    v.value.integer = i;
    return v;
}

static mms_value_t br_str(const char *s)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_VISIBLE_STRING;
    v.value.visible_string.len = strlen(s);
    (void)memcpy(v.value.visible_string.data, s, v.value.visible_string.len);
    v.value.visible_string.data[v.value.visible_string.len] = '\0';
    return v;
}

/* Fixture: one URCB (u1) + one BRCB (b1) exposed in LD, one monitored
 * data point in LDD collected in dataset LDD/ds1. */
static void bridge_fixture(iec61850_rcb_manager_t *mgr,
                           iec61850_mms_data_store_t *ds)
{
    mms_variable_spec_t members[2];
    mms_value_t v;

    iec61850_mms_ds_init(ds);
    (void)iec61850_mms_ds_create_domain(ds, BR_LD);
    (void)iec61850_mms_ds_create_domain(ds, BR_LDD);

    v = br_bool(true);
    (void)iec61850_mms_ds_create_variable(ds, BR_LDD, BR_STVAL,
                                           MMS_TYPE_BOOLEAN, &v);
    v = br_int(50);
    (void)iec61850_mms_ds_create_variable(ds, BR_LDD, BR_HZ,
                                           MMS_TYPE_INTEGER, &v);

    (void)strncpy(members[0].domain, BR_LDD, MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(members[0].item_id, BR_STVAL, MMS_MAX_VARIABLE_NAME - 1);
    (void)strncpy(members[1].domain, BR_LDD, MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(members[1].item_id, BR_HZ, MMS_MAX_VARIABLE_NAME - 1);
    (void)iec61850_mms_ds_define_list(ds, BR_LDD, "ds1", members, 2);

    iec61850_rcb_manager_init(mgr, BR_LD);
    (void)iec61850_rcb_manager_add_rcb(mgr, "u1", IEC61850_RCB_UNBUFFERED, 0);
    (void)iec61850_rcb_manager_add_rcb(mgr, "b1", IEC61850_RCB_BUFFERED, 16);
    ASSERT_EQ(iec61850_rcb_manager_expose(mgr, ds, BR_LD), 0);
}

/* Write a component as a client would (store commit) and reconcile. */
static void bridge_write_comp(iec61850_rcb_manager_t *mgr, const char *item,
                              const mms_value_t *v)
{
    ASSERT_EQ(iec61850_mms_ds_write_variable(mgr->bridge.store, BR_LD,
                                              item, v),
              (int)IEC61850_MMS_DS_OK);
    iec61850_rcb_bridge_on_write(mgr, BR_LD, item, NULL);
}

static mms_value_t bridge_read_comp(iec61850_rcb_manager_t *mgr,
                                    const char *item)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    (void)iec61850_mms_ds_read_variable(mgr->bridge.store, BR_LD, item, &v);
    return v;
}

/* Simulate a host-side monitored data-point write while detached. */
static void bridge_data_write(iec61850_rcb_manager_t *mgr, const char *item,
                              const mms_value_t *v)
{
    ASSERT_EQ(iec61850_mms_ds_write_variable(mgr->bridge.store, BR_LDD,
                                              item, v),
              (int)IEC61850_MMS_DS_OK);
    iec61850_rcb_bridge_on_write(mgr, BR_LDD, item, NULL);
}

static void test_bridge_expose_components(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_mms_data_store_t ds;
    mms_value_t v;

    TEST("bridge_expose_components");
    bridge_fixture(&mgr, &ds);

    /* Re-expose is rejected. */
    ASSERT_EQ(iec61850_rcb_manager_expose(&mgr, &ds, BR_LD), -EBUSY);

    /* URCB components (Resv, no EntryID/PurgeBuf). */
    const char *urcb_comps[] = {
        BR_URCB_REF "$RptID", BR_URCB_REF "$RptEna", BR_URCB_REF "$Resv", BR_URCB_REF "$DatSet", BR_URCB_REF "$ConfRev",
        BR_URCB_REF "$OptFlds", BR_URCB_REF "$BufTm", BR_URCB_REF "$TrgOps", BR_URCB_REF "$IntgPd", BR_URCB_REF "$GI",
        BR_URCB_REF "$SqNum", BR_URCB_REF "$Owner"
    };
    for (size_t i = 0; i < sizeof(urcb_comps) / sizeof(urcb_comps[0]); i++) {
        ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, BR_LD, urcb_comps[i]));
    }
    ASSERT_TRUE(!iec61850_mms_ds_variable_exists(&ds, BR_LD, BR_URCB_REF "$EntryID"));
    ASSERT_TRUE(!iec61850_mms_ds_variable_exists(&ds, BR_LD, BR_URCB_REF "$PurgeBuf"));

    /* BRCB components (EntryID + PurgeBuf, no Resv). */
    const char *brcb_comps[] = {
        BR_BRCB_REF "$RptID", BR_BRCB_REF "$RptEna", BR_BRCB_REF "$DatSet", BR_BRCB_REF "$ConfRev", BR_BRCB_REF "$OptFlds",
        BR_BRCB_REF "$BufTm", BR_BRCB_REF "$TrgOps", BR_BRCB_REF "$IntgPd", BR_BRCB_REF "$GI", BR_BRCB_REF "$SqNum", BR_BRCB_REF "$Owner",
        BR_BRCB_REF "$EntryID", BR_BRCB_REF "$PurgeBuf"
    };
    for (size_t i = 0; i < sizeof(brcb_comps) / sizeof(brcb_comps[0]); i++) {
        ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, BR_LD, brcb_comps[i]));
    }
    ASSERT_TRUE(!iec61850_mms_ds_variable_exists(&ds, BR_LD, BR_BRCB_REF "$Resv"));

    /* Component types (IEC 61850-8-1 Ed.2 wire types). */
    v = bridge_read_comp(&mgr, BR_URCB_REF "$RptEna");
    ASSERT_EQ((int)v.type, (int)MMS_TYPE_BOOLEAN);
    v = bridge_read_comp(&mgr, BR_URCB_REF "$RptID");
    ASSERT_EQ((int)v.type, (int)MMS_TYPE_VISIBLE_STRING);
    v = bridge_read_comp(&mgr, BR_URCB_REF "$ConfRev");
    ASSERT_EQ((int)v.type, (int)MMS_TYPE_UNSIGNED);
    v = bridge_read_comp(&mgr, BR_URCB_REF "$OptFlds");
    ASSERT_EQ((int)v.type, (int)MMS_TYPE_BIT_STRING);
    ASSERT_EQ((int)v.value.bit_string.bit_count, 10);
    v = bridge_read_comp(&mgr, BR_URCB_REF "$TrgOps");
    ASSERT_EQ((int)v.type, (int)MMS_TYPE_BIT_STRING);
    ASSERT_EQ((int)v.value.bit_string.bit_count, 6);
    v = bridge_read_comp(&mgr, BR_BRCB_REF "$EntryID");
    ASSERT_EQ((int)v.type, (int)MMS_TYPE_OCTET_STRING);
    ASSERT_EQ((int)v.value.octet_string.len, 8);

    /* Data-store attachment (GI snapshots) and sender takeover. */
    ASSERT_TRUE(mgr.rcbs[0].data_store == &ds);
    ASSERT_TRUE(mgr.rcbs[0].report_sender != NULL);

    iec61850_rcb_manager_destroy(&mgr);
    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_bridge_component_validation(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_mms_data_store_t ds;
    mms_value_t v;

    TEST("bridge_component_validation");
    bridge_fixture(&mgr, &ds);

    /* Configuration while disabled is accepted. */
    v = br_str(BR_LDD "/ds1");
    bridge_write_comp(&mgr, BR_URCB_REF "$DatSet", &v);
    ASSERT_STR(mgr.rcbs[0].attrs.dat_set, BR_LDD "/ds1");

    /* Ed.2: URCB RptEna=TRUE requires a prior reservation. */
    v = br_bool(true);
    bridge_write_comp(&mgr, BR_URCB_REF "$RptEna", &v);
    ASSERT_TRUE(!mgr.rcbs[0].attrs.rpt_ena);
    v = bridge_read_comp(&mgr, BR_URCB_REF "$RptEna");
    ASSERT_TRUE(!v.value.boolean);   /* reverted */

    /* Reservation, then enable succeeds. */
    v = br_bool(true);
    bridge_write_comp(&mgr, BR_URCB_REF "$Resv", &v);
    ASSERT_TRUE(mgr.rcbs[0].resv);
    v = br_bool(true);
    bridge_write_comp(&mgr, BR_URCB_REF "$RptEna", &v);
    ASSERT_TRUE(mgr.rcbs[0].attrs.rpt_ena);

    /* Configuration and read-only components are rejected while
     * enabled (reverted in the store). */
    v = br_str("somewhere/else");
    bridge_write_comp(&mgr, BR_URCB_REF "$DatSet", &v);
    ASSERT_STR(mgr.rcbs[0].attrs.dat_set, BR_LDD "/ds1");
    v = bridge_read_comp(&mgr, BR_URCB_REF "$DatSet");
    ASSERT_STR(v.value.visible_string.data, BR_LDD "/ds1");

    v = bridge_read_comp(&mgr, BR_URCB_REF "$SqNum");
    ASSERT_EQ((int)v.value.unsigned_val, 0);
    v.value.unsigned_val = 99U;
    bridge_write_comp(&mgr, BR_URCB_REF "$SqNum", &v);
    v = bridge_read_comp(&mgr, BR_URCB_REF "$SqNum");
    ASSERT_EQ((int)v.value.unsigned_val, 0);   /* read-only, reverted */

    /* Disable releases the reservation and the Owner. */
    v = br_bool(false);
    bridge_write_comp(&mgr, BR_URCB_REF "$RptEna", &v);
    ASSERT_TRUE(!mgr.rcbs[0].attrs.rpt_ena);
    ASSERT_TRUE(!mgr.rcbs[0].resv);
    ASSERT_TRUE(mgr.rcbs[0].owner[0] == '\0');

    iec61850_rcb_manager_destroy(&mgr);
    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_bridge_brcb_persistence_and_purge(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_mms_data_store_t ds;
    iec61850_report_buffer_t *buf;
    mms_value_t v;

    TEST("bridge_brcb_persistence_and_purge");
    bridge_fixture(&mgr, &ds);

    buf = iec61850_rcb_manager_get_buffer(&mgr, 1);
    ASSERT_TRUE(buf != NULL);

    /* Arm the BRCB (no reservation required). */
    v = br_str(BR_LDD "/ds1");
    bridge_write_comp(&mgr, BR_BRCB_REF "$DatSet", &v);
    v = br_bool(true);
    bridge_write_comp(&mgr, BR_BRCB_REF "$RptEna", &v);
    ASSERT_TRUE(mgr.rcbs[1].attrs.rpt_ena);

    /* Data changes with no association: buffered only, the visible
     * EntryID marker stays frozen (nothing was delivered). */
    v = br_bool(false);
    bridge_data_write(&mgr, BR_STVAL, &v);
    v = br_int(60);
    bridge_data_write(&mgr, BR_HZ, &v);
    ASSERT_EQ((int)buf->count, 2);
    ASSERT_TRUE(mgr.rcbs[1].attrs.entry_id == 0U);
    ASSERT_EQ((int)mgr.rcbs[1].attrs.sq_num, 0);

    /* Client loss: the BRCB stays enabled and keeps buffering. */
    iec61850_rcb_bridge_clear_association(&mgr);
    ASSERT_TRUE(mgr.rcbs[1].attrs.rpt_ena);
    ASSERT_EQ((int)buf->count, 2);
    v = br_bool(true);
    bridge_data_write(&mgr, BR_STVAL, &v);
    ASSERT_EQ((int)buf->count, 3);

    /* PurgeBuf clears the buffer and resets the visible marker. */
    v = br_bool(true);
    bridge_write_comp(&mgr, BR_BRCB_REF "$PurgeBuf", &v);
    ASSERT_EQ((int)buf->count, 0);
    v = bridge_read_comp(&mgr, BR_BRCB_REF "$EntryID");
    ASSERT_EQ((int)v.value.octet_string.len, 8);
    {
        uint64_t marker = 0U;
        for (int i = 0; i < 8; i++) {
            marker = (marker << 8) |
                     (uint64_t)v.value.octet_string.data[i];
        }
        ASSERT_TRUE(marker == 0U);
    }

    /* Entry IDs continue monotonically after the purge. */
    v = br_bool(false);
    bridge_data_write(&mgr, BR_STVAL, &v);
    ASSERT_EQ((int)buf->count, 1);
    ASSERT_TRUE(buf->entries[buf->head == 0U ? 0U : buf->head - 1U].entry_id > 3U);

    iec61850_rcb_manager_destroy(&mgr);
    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_bridge_clear_association_urcb(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_mms_data_store_t ds;
    mms_value_t v;

    TEST("bridge_clear_association_urcb");
    bridge_fixture(&mgr, &ds);

    /* Reserve + enable. */
    v = br_bool(true);
    bridge_write_comp(&mgr, BR_URCB_REF "$Resv", &v);
    v = br_bool(true);
    bridge_write_comp(&mgr, BR_URCB_REF "$RptEna", &v);
    ASSERT_TRUE(mgr.rcbs[0].attrs.rpt_ena);
    ASSERT_TRUE(mgr.rcbs[0].resv);

    /* Client loss: URCB is disabled and its reservation released. */
    iec61850_rcb_bridge_clear_association(&mgr);
    ASSERT_TRUE(!mgr.rcbs[0].attrs.rpt_ena);
    ASSERT_TRUE(!mgr.rcbs[0].resv);
    ASSERT_TRUE(mgr.rcbs[0].owner[0] == '\0');
    v = bridge_read_comp(&mgr, BR_URCB_REF "$RptEna");
    ASSERT_TRUE(!v.value.boolean);

    iec61850_rcb_manager_destroy(&mgr);
    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_bridge_write_prevalidation(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_mms_data_store_t ds;
    mms_value_t v;

    TEST("bridge_write_prevalidation");
    bridge_fixture(&mgr, &ds);

    v = br_bool(true);

    /* Not an RCB component: the server handles it normally. */
    ASSERT_EQ(iec61850_rcb_bridge_write(&mgr, BR_LDD, BR_STVAL, &v, NULL),
              -ENOENT);
    ASSERT_EQ(iec61850_rcb_bridge_write(&mgr, BR_LD, "zzz$RptEna", &v, NULL),
              -ENOENT);

    /* Ed.2 validation rejects enabling an unreserved URCB and leaves
     * the store untouched (pre-commit wiring can fail the Write). */
    ASSERT_EQ(iec61850_rcb_bridge_write(&mgr, BR_LD, BR_URCB_REF "$RptEna", &v, NULL),
              -EACCES);
    v = bridge_read_comp(&mgr, BR_URCB_REF "$RptEna");
    ASSERT_TRUE(!v.value.boolean);

    /* Reservation then enable succeed and are published. */
    v = br_bool(true);
    ASSERT_EQ(iec61850_rcb_bridge_write(&mgr, BR_LD, BR_URCB_REF "$Resv", &v, NULL), 0);
    ASSERT_EQ(iec61850_rcb_bridge_write(&mgr, BR_LD, BR_URCB_REF "$RptEna", &v, NULL), 0);
    ASSERT_TRUE(mgr.rcbs[0].attrs.rpt_ena);
    v = bridge_read_comp(&mgr, BR_URCB_REF "$RptEna");
    ASSERT_TRUE(v.value.boolean);

    iec61850_rcb_manager_destroy(&mgr);
    iec61850_mms_ds_destroy(&ds);
    PASS();
}

/* ========================================================================
 * WP-2a: client <-> server closed loop (real MMS server + the repo's
 * own WP-1c client, bridged through the RCB component objects)
 * ======================================================================== */

#define LOOP_PORT   11821
#define LOOP_LD     "LD"      /* RCB component objects  */
#define LOOP_URCB_REF "LLN0$RP$u1"   /* exposed URCB reference */
#define LOOP_BRCB_REF "LLN0$BR$b1"   /* exposed BRCB reference */
#define LOOP_LDD    "LDD"     /* monitored data points  */
#define LOOP_STVAL  "XCBR1$ST$Pos$stVal"
#define LOOP_HZ     "MMXU1$MX$Hz$mag$f"
#define LOOP_Q      "XCBR1$ST$Pos$q"

static iec61850_mms_data_store_t g_loop_ds;
static iec61850_rcb_manager_t g_loop_mgr;
static iec61850_mms_server_t g_loop_srv;
static bool g_loop_srv_up;

static int g_loop_report_count;
static mms_information_report_t g_loop_reports[8];
static mms_information_report_t g_loop_last;

static void loop_report_cb(const mms_information_report_t *report,
                            void *user_data)
{
    (void)user_data;
    if (g_loop_report_count < 8) {
        g_loop_reports[g_loop_report_count] = *report;
    }
    g_loop_last = *report;
    g_loop_report_count++;
}

/*
 * Server after_response hook — this stands in for the (frozen)
 * mms_server.c wiring a later WP will add: every client request is
 * reconciled through the bridge with the requesting session.
 */
static void loop_after_response(iec61850_mms_session_t *session,
                                 const char *req_domain,
                                 const char *req_item,
                                 void *user_data)
{
    (void)user_data;
    iec61850_rcb_bridge_on_write(&g_loop_mgr, req_domain, req_item, session);
}

static void loop_setup(void)
{
    iec61850_mms_server_config_t cfg;
    mms_variable_spec_t members[2];
    mms_value_t v;

    iec61850_mms_ds_init(&g_loop_ds);
    (void)iec61850_mms_ds_create_domain(&g_loop_ds, LOOP_LD);
    (void)iec61850_mms_ds_create_domain(&g_loop_ds, LOOP_LDD);

    v = br_bool(true);
    (void)iec61850_mms_ds_create_variable(&g_loop_ds, LOOP_LDD, LOOP_STVAL,
                                           MMS_TYPE_BOOLEAN, &v);
    v = br_int(50);
    (void)iec61850_mms_ds_create_variable(&g_loop_ds, LOOP_LDD, LOOP_HZ,
                                           MMS_TYPE_INTEGER, &v);
    v.value.unsigned_val = 0U;
    v.type = MMS_TYPE_UNSIGNED;
    (void)iec61850_mms_ds_create_variable(&g_loop_ds, LOOP_LDD, LOOP_Q,
                                           MMS_TYPE_UNSIGNED, &v);

    (void)strncpy(members[0].domain, LOOP_LDD, MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(members[0].item_id, LOOP_STVAL, MMS_MAX_VARIABLE_NAME - 1);
    (void)strncpy(members[1].domain, LOOP_LDD, MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(members[1].item_id, LOOP_HZ, MMS_MAX_VARIABLE_NAME - 1);
    (void)iec61850_mms_ds_define_list(&g_loop_ds, LOOP_LDD, "ds1",
                                       members, 2);

    iec61850_rcb_manager_init(&g_loop_mgr, LOOP_LD);
    (void)iec61850_rcb_manager_add_rcb(&g_loop_mgr, "u1",
                                        IEC61850_RCB_UNBUFFERED, 0);
    (void)iec61850_rcb_manager_add_rcb(&g_loop_mgr, "b1",
                                        IEC61850_RCB_BUFFERED,
                                        IEC61850_RCB_MAX_BUFFER);
    ASSERT_EQ(iec61850_rcb_manager_expose(&g_loop_mgr, &g_loop_ds, LOOP_LD), 0);

    iec61850_mms_server_config_init(&cfg);
    cfg.port = LOOP_PORT;
    cfg.after_response = loop_after_response;
    iec61850_mms_server_init(&g_loop_srv, &cfg, &g_loop_ds);
    ASSERT_EQ(iec61850_mms_server_start(&g_loop_srv), 0);
    g_loop_srv_up = true;

    g_loop_report_count = 0;
    usleep(200000);
}

static void loop_teardown(void)
{
    if (g_loop_srv_up) {
        (void)iec61850_mms_server_stop(&g_loop_srv);
        g_loop_srv_up = false;
    }
    iec61850_rcb_manager_destroy(&g_loop_mgr);
    iec61850_mms_ds_destroy(&g_loop_ds);
}

static void loop_connect(iec61850_mms_client_t *client)
{
    iec61850_mms_client_init(client);
    ASSERT_EQ(iec61850_mms_client_connect(client, "127.0.0.1",
                                           LOOP_PORT, 5000),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(iec61850_mms_client_set_report_handler(client,
                                                      loop_report_cb, NULL),
              IEC61850_MMS_CLIENT_OK);
}

static int loop_pump(iec61850_mms_client_t *client, int timeout_ms,
                     int want_reports)
{
    int waited = 0;

    while ((g_loop_report_count < want_reports) && (waited < timeout_ms)) {
        int ret = iec61850_mms_client_poll(client, 50);
        if (ret < 0) {
            return ret;
        }
        waited += 50;
    }
    return (g_loop_report_count >= want_reports) ? 0 : -1;
}

static void test_loop_rcb_list(void)
{
    iec61850_mms_client_t client;
    char names[8][IEC61850_RCB_MAX_NAME];
    uint32_t count = 0U;
    bool found_u1 = false;
    bool found_b1 = false;

    TEST("loop_rcb_list");
    loop_connect(&client);

    ASSERT_EQ(iec61850_mms_client_rcb_list(&client, LOOP_LD, names,
                                            &count, 8U),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)count, 2);
    for (uint32_t i = 0U; i < count; i++) {
        if (strcmp(names[i], LOOP_URCB_REF) == 0) { found_u1 = true; }
        if (strcmp(names[i], LOOP_BRCB_REF) == 0) { found_b1 = true; }
    }
    ASSERT_TRUE(found_u1);
    ASSERT_TRUE(found_b1);

    /* Data points are not RCBs. */
    count = 0U;
    ASSERT_EQ(iec61850_mms_client_rcb_list(&client, LOOP_LDD, names,
                                            &count, 8U),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)count, 0);

    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_loop_urcb_enroll_report(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t values;
    iec61850_mms_client_rcb_values_t readback;
    mms_value_t v;
    uint32_t mask;
    int ret;

    TEST("loop_urcb_enroll_report");
    loop_connect(&client);

    /* Initial state through the component objects. */
    (void)memset(&values, 0, sizeof(values));
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, LOOP_LD, LOOP_URCB_REF,
                                                  &values),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(!values.buffered);
    ASSERT_TRUE(!values.attrs.rpt_ena);
    ASSERT_TRUE(!values.resv);
    ASSERT_TRUE(values.owner_present);
    ASSERT_TRUE(values.owner[0] == '\0');

    /* Enroll (Ed.2 client procedure order via set_values). */
    (void)memset(&values, 0, sizeof(values));
    values.resv = true;
    (void)strncpy(values.attrs.rpt_id, "R1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    (void)strncpy(values.attrs.dat_set, LOOP_LDD "/ds1",
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

    ret = iec61850_mms_client_rcb_set_values(&client, LOOP_LD, LOOP_URCB_REF,
                                              &values, mask);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    (void)memset(&readback, 0, sizeof(readback));
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, LOOP_LD, LOOP_URCB_REF,
                                                  &readback),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(readback.resv);
    ASSERT_TRUE(readback.attrs.rpt_ena);
    ASSERT_STR(readback.attrs.rpt_id, "R1");
    ASSERT_STR(readback.attrs.dat_set, LOOP_LDD "/ds1");
    ASSERT_TRUE(readback.owner_present);
    ASSERT_TRUE(readback.owner[0] != '\0');   /* synthetic identity */

    /* Trigger a report by writing the monitored data point. */
    g_loop_report_count = 0;
    v = br_bool(false);
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(loop_pump(&client, 5000, 1), 0);
    ASSERT_EQ(g_loop_report_count, 1);

    ASSERT_STR(g_loop_last.variable_list_name, "R1");
    ASSERT_EQ((int)g_loop_last.num_values, 1);
    ASSERT_EQ((int)g_loop_last.values[0].type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(!g_loop_last.values[0].value.boolean);
    ASSERT_TRUE(g_loop_last.sq_num_present);
    ASSERT_EQ((int)g_loop_last.sq_num, 1);
    ASSERT_TRUE(g_loop_last.reasons_present);
    ASSERT_EQ((int)g_loop_last.reasons[0], (int)IEC61850_REASON_DCHG);

    /* Idempotent rewrite: no change, no report. */
    g_loop_report_count = 0;
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(loop_pump(&client, 300, 1), -1);
    ASSERT_EQ(g_loop_report_count, 0);

    /* Reading a monitored point must not trigger a report. */
    ASSERT_EQ(iec61850_mms_client_read(&client, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(loop_pump(&client, 300, 1), -1);
    ASSERT_EQ(g_loop_report_count, 0);

    /* Disable: reservation and Owner released, no further reports. */
    ASSERT_EQ(iec61850_mms_client_rcb_disable(&client, LOOP_LD, LOOP_URCB_REF),
              IEC61850_MMS_CLIENT_OK);
    (void)memset(&readback, 0, sizeof(readback));
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, LOOP_LD, LOOP_URCB_REF,
                                                  &readback),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(!readback.attrs.rpt_ena);
    ASSERT_TRUE(!readback.resv);
    ASSERT_TRUE(readback.owner[0] == '\0');

    g_loop_report_count = 0;
    v = br_bool(true);
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(loop_pump(&client, 300, 1), -1);
    ASSERT_EQ(g_loop_report_count, 0);

    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_loop_brcb_buffered_resume(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t values;
    iec61850_report_buffer_t *buf =
        iec61850_rcb_manager_get_buffer(&g_loop_mgr, 1);
    mms_value_t v;
    uint32_t mask;
    int ret;

    TEST("loop_brcb_buffered_resume");
    ASSERT_TRUE(buf != NULL);
    loop_connect(&client);

    /* Enroll the BRCB. */
    (void)memset(&values, 0, sizeof(values));
    (void)strncpy(values.attrs.rpt_id, "B1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    (void)strncpy(values.attrs.dat_set, LOOP_LDD "/ds1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    values.attrs.opt_flds.sequence_number = true;
    values.attrs.opt_flds.reason_for_inclusion = true;
    values.attrs.opt_flds.entry_id = true;
    values.attrs.trg_ops.data_change = true;
    values.attrs.rpt_ena = true;

    mask = (uint32_t)IEC61850_RCB_FIELD_RPT_ID |
           (uint32_t)IEC61850_RCB_FIELD_DAT_SET |
           (uint32_t)IEC61850_RCB_FIELD_OPT_FLDS |
           (uint32_t)IEC61850_RCB_FIELD_TRG_OPS |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;

    ret = iec61850_mms_client_rcb_set_values(&client, LOOP_LD, LOOP_BRCB_REF,
                                              &values, mask);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Two live buffered reports with strictly increasing EntryIDs. */
    g_loop_report_count = 0;
    v = br_bool(false);
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(loop_pump(&client, 5000, 1), 0);
    ASSERT_EQ(g_loop_report_count, 1);
    ASSERT_TRUE(g_loop_last.entry_id_present);
    ASSERT_TRUE(g_loop_last.entry_id == 1U);
    ASSERT_EQ((int)g_loop_last.reasons[0], (int)IEC61850_REASON_DCHG);

    v = br_int(60);
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_HZ, &v),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(loop_pump(&client, 5000, 2), 0);
    ASSERT_EQ(g_loop_report_count, 2);
    ASSERT_TRUE(g_loop_last.entry_id == 2U);

    (void)iec61850_mms_client_disconnect(&client);

    /* Client loss (the wiring WP will call this from the server's
     * session teardown): the BRCB stays enabled and buffers on. */
    iec61850_rcb_bridge_clear_association(&g_loop_mgr);
    ASSERT_TRUE(g_loop_mgr.rcbs[1].attrs.rpt_ena);
    ASSERT_EQ((int)buf->count, 2);

    /* Host-side data changes while detached: buffered, marker frozen. */
    v = br_bool(true);
    ASSERT_EQ(iec61850_mms_ds_write_variable(&g_loop_ds, LOOP_LDD,
                                              LOOP_STVAL, &v),
              (int)IEC61850_MMS_DS_OK);
    iec61850_rcb_bridge_on_write(&g_loop_mgr, LOOP_LDD, LOOP_STVAL, NULL);
    v = br_int(61);
    ASSERT_EQ(iec61850_mms_ds_write_variable(&g_loop_ds, LOOP_LDD,
                                              LOOP_HZ, &v),
              (int)IEC61850_MMS_DS_OK);
    iec61850_rcb_bridge_on_write(&g_loop_mgr, LOOP_LDD, LOOP_HZ, NULL);

    ASSERT_EQ((int)buf->count, 4);
    ASSERT_TRUE(g_loop_mgr.rcbs[1].attrs.entry_id == 2U);  /* frozen */
    ASSERT_EQ((int)g_loop_mgr.rcbs[1].attrs.sq_num, 2);

    /* Re-associate and resume after EntryID 2. */
    loop_connect(&client);
    ASSERT_EQ(iec61850_mms_client_rcb_set_entry_id(&client, LOOP_LD, LOOP_BRCB_REF, 2U),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(iec61850_mms_client_rcb_enable(&client, LOOP_LD, LOOP_BRCB_REF),
              IEC61850_MMS_CLIENT_OK);

    g_loop_report_count = 0;
    ASSERT_EQ(loop_pump(&client, 5000, 2), 0);
    ASSERT_EQ(g_loop_report_count, 2);

    /* Reports resume from the entry AFTER the stored EntryID. */
    ASSERT_TRUE(g_loop_reports[0].entry_id_present);
    ASSERT_TRUE(g_loop_reports[0].entry_id == 3U);
    ASSERT_EQ((int)g_loop_reports[0].values[0].type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(g_loop_reports[0].values[0].value.boolean);
    ASSERT_TRUE(g_loop_reports[1].entry_id == 4U);
    ASSERT_EQ((int)g_loop_reports[1].values[0].type, (int)MMS_TYPE_INTEGER);
    ASSERT_EQ((int)g_loop_reports[1].values[0].value.integer, 61);

    /* Live reporting continues with the next EntryID. */
    g_loop_report_count = 0;
    v = br_bool(false);
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(loop_pump(&client, 5000, 1), 0);
    ASSERT_EQ(g_loop_report_count, 1);
    ASSERT_TRUE(g_loop_last.entry_id == 5U);

    (void)iec61850_mms_client_disconnect(&client);
    iec61850_rcb_bridge_clear_association(&g_loop_mgr);
    PASS();
}

static void test_loop_brcb_purge(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t v;
    iec61850_report_buffer_t *buf =
        iec61850_rcb_manager_get_buffer(&g_loop_mgr, 1);
    mms_value_t w;

    TEST("loop_brcb_purge");
    ASSERT_TRUE(buf != NULL);
    loop_connect(&client);

    /* Re-adopt the (still enabled) BRCB, then purge. */
    ASSERT_EQ(iec61850_mms_client_rcb_enable(&client, LOOP_LD, LOOP_BRCB_REF),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(iec61850_mms_client_rcb_purge_buffer(&client, LOOP_LD, LOOP_BRCB_REF),
              IEC61850_MMS_CLIENT_OK);

    ASSERT_EQ((int)buf->count, 0);
    (void)memset(&v, 0, sizeof(v));
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, LOOP_LD, LOOP_BRCB_REF, &v),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(v.buffered);
    ASSERT_TRUE(v.attrs.entry_id == 0U);   /* marker reset by purge */

    /* New entries get fresh, still-monotonic EntryIDs. */
    g_loop_report_count = 0;
    w = br_bool(true);
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_STVAL, &w),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(loop_pump(&client, 5000, 1), 0);
    ASSERT_EQ(g_loop_report_count, 1);
    ASSERT_TRUE(g_loop_last.entry_id_present);
    ASSERT_TRUE(g_loop_last.entry_id > 5U);   /* monotonic across purge */

    (void)iec61850_mms_client_disconnect(&client);
    iec61850_rcb_bridge_clear_association(&g_loop_mgr);
    PASS();
}

static void test_loop_buftm_aggregation(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t values;
    mms_value_t v;
    uint32_t mask;
    int ret;

    TEST("loop_buftm_aggregation");
    loop_connect(&client);

    /* Reconfigure BufTm (requires RptEna=FALSE), then re-enable. */
    ASSERT_EQ(iec61850_mms_client_rcb_disable(&client, LOOP_LD, LOOP_BRCB_REF),
              IEC61850_MMS_CLIENT_OK);

    (void)memset(&values, 0, sizeof(values));
    values.attrs.buf_tm = 400U;
    values.attrs.rpt_ena = true;
    mask = (uint32_t)IEC61850_RCB_FIELD_BUF_TM |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;
    ret = iec61850_mms_client_rcb_set_values(&client, LOOP_LD, LOOP_BRCB_REF,
                                              &values, mask);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Three changes within the window (stVal twice, Hz once): all
     * held back by BufTm. */
    g_loop_report_count = 0;
    v = br_bool(false);
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);
    v = br_bool(true);
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);
    v = br_int(70);
    ASSERT_EQ(iec61850_mms_client_write(&client, LOOP_LDD, LOOP_HZ, &v),
              IEC61850_MMS_CLIENT_OK);

    ASSERT_EQ(loop_pump(&client, 300, 1), -1);
    ASSERT_EQ(g_loop_report_count, 0);   /* window open, nothing sent */

    /* Window elapses; any request (here: a data-point Read) flushes
     * the closed window as ONE aggregated, deduplicated report. */
    usleep(450 * 1000);
    v = br_bool(true);
    ASSERT_EQ(iec61850_mms_client_read(&client, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);

    ASSERT_EQ(loop_pump(&client, 5000, 1), 0);
    ASSERT_EQ(g_loop_report_count, 1);

    ASSERT_EQ((int)g_loop_last.num_values, 2);         /* stVal + Hz */
    ASSERT_EQ((int)g_loop_last.values[0].type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(g_loop_last.values[0].value.boolean);  /* last stVal */
    ASSERT_EQ((int)g_loop_last.values[1].value.integer, 70);
    ASSERT_TRUE(g_loop_last.entry_id_present);
    ASSERT_TRUE(g_loop_last.reasons_present);

    /* Sequence number advanced by exactly one (single report). */
    (void)memset(&values, 0, sizeof(values));
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, LOOP_LD, LOOP_BRCB_REF,
                                                  &values),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)values.attrs.sq_num, 7);   /* 5 (resume) + 1 (purge) + 1 */

    (void)iec61850_mms_client_disconnect(&client);
    iec61850_rcb_bridge_clear_association(&g_loop_mgr);
    PASS();
}

static void test_loop_ownership_conflict(void)
{
    iec61850_mms_client_t client_a;
    iec61850_mms_client_t client_b;
    iec61850_mms_client_rcb_values_t values;
    iec61850_mms_client_rcb_values_t readback;
    mms_value_t v;
    char owner_a[IEC61850_RCB_MAX_NAME];
    uint32_t mask;
    int ret;

    TEST("loop_ownership_conflict");

    /* Client A enrolls the URCB. */
    loop_connect(&client_a);
    (void)memset(&values, 0, sizeof(values));
    values.resv = true;
    (void)strncpy(values.attrs.rpt_id, "RA",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    (void)strncpy(values.attrs.dat_set, LOOP_LDD "/ds1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    values.attrs.trg_ops.data_change = true;
    values.attrs.rpt_ena = true;
    mask = (uint32_t)IEC61850_RCB_FIELD_RPT_ID |
           (uint32_t)IEC61850_RCB_FIELD_RESV |
           (uint32_t)IEC61850_RCB_FIELD_DAT_SET |
           (uint32_t)IEC61850_RCB_FIELD_TRG_OPS |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;
    ret = iec61850_mms_client_rcb_set_values(&client_a, LOOP_LD, LOOP_URCB_REF,
                                              &values, mask);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    (void)memset(&readback, 0, sizeof(readback));
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client_a, LOOP_LD, LOOP_URCB_REF,
                                                  &readback),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(readback.owner[0] != '\0');
    (void)strncpy(owner_a, readback.owner, (size_t)IEC61850_RCB_MAX_NAME - 1U);
    owner_a[IEC61850_RCB_MAX_NAME - 1U] = '\0';

    /* Client B cannot take the reservation or the enable (state-level
     * check: with the post-commit after_response wiring the Write
     * succeeds at the MMS level and the bridge reverts it). */
    loop_connect(&client_b);
    (void)memset(&values, 0, sizeof(values));
    values.resv = true;
    ret = iec61850_mms_client_rcb_set_values(&client_b, LOOP_LD, LOOP_URCB_REF,
                                              &values,
                                              (uint32_t)IEC61850_RCB_FIELD_RESV);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);   /* accepted by the store */

    (void)memset(&readback, 0, sizeof(readback));
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client_b, LOOP_LD, LOOP_URCB_REF,
                                                  &readback),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_STR(readback.owner, owner_a);      /* still A's */

    ASSERT_EQ(iec61850_mms_client_rcb_enable(&client_b, LOOP_LD, LOOP_URCB_REF),
              IEC61850_MMS_CLIENT_OK);
    (void)memset(&readback, 0, sizeof(readback));
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client_b, LOOP_LD, LOOP_URCB_REF,
                                                  &readback),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_STR(readback.owner, owner_a);      /* B could not take over */

    /* A report triggered by B is still routed to the owner A. */
    g_loop_report_count = 0;
    v = br_bool(false);
    ASSERT_EQ(iec61850_mms_client_write(&client_b, LOOP_LDD, LOOP_STVAL, &v),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(loop_pump(&client_b, 300, 1), -1);
    ASSERT_EQ(g_loop_report_count, 0);        /* B receives nothing */
    ASSERT_EQ(loop_pump(&client_a, 5000, 1), 0);
    ASSERT_EQ(g_loop_report_count, 1);        /* A receives it */

    /* Owner releases. */
    ASSERT_EQ(iec61850_mms_client_rcb_disable(&client_a, LOOP_LD, LOOP_URCB_REF),
              IEC61850_MMS_CLIENT_OK);

    (void)iec61850_mms_client_disconnect(&client_b);
    (void)iec61850_mms_client_disconnect(&client_a);
    PASS();
}

static void test_loop_gi_report(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t values;
    uint32_t mask;
    int ret;

    TEST("loop_gi_report");
    loop_connect(&client);

    /* Enroll with the GI trigger armed, then request a general
     * interrogation through the GI component write. */
    (void)memset(&values, 0, sizeof(values));
    values.resv = true;
    (void)strncpy(values.attrs.rpt_id, "RGI",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    (void)strncpy(values.attrs.dat_set, LOOP_LDD "/ds1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    values.attrs.opt_flds.sequence_number = true;
    values.attrs.opt_flds.reason_for_inclusion = true;
    values.attrs.trg_ops.general_interrogation = true;
    values.attrs.rpt_ena = true;

    mask = (uint32_t)IEC61850_RCB_FIELD_RPT_ID |
           (uint32_t)IEC61850_RCB_FIELD_RESV |
           (uint32_t)IEC61850_RCB_FIELD_DAT_SET |
           (uint32_t)IEC61850_RCB_FIELD_OPT_FLDS |
           (uint32_t)IEC61850_RCB_FIELD_TRG_OPS |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;

    ret = iec61850_mms_client_rcb_set_values(&client, LOOP_LD, LOOP_URCB_REF,
                                              &values, mask);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* GI is armed by a dedicated component write after enrollment
     * (the Ed.2 client procedure writes configuration, then RptEna,
     * then triggers GI). */
    g_loop_report_count = 0;
    (void)memset(&values, 0, sizeof(values));
    values.attrs.gi = true;
    ret = iec61850_mms_client_rcb_set_values(&client, LOOP_LD, LOOP_URCB_REF,
                                              &values,
                                              (uint32_t)IEC61850_RCB_FIELD_GI);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* The GI write fires one report snapshotting the dataset. */
    ASSERT_EQ(loop_pump(&client, 5000, 1), 0);
    ASSERT_EQ(g_loop_report_count, 1);
    ASSERT_STR(g_loop_last.variable_list_name, "RGI");
    ASSERT_EQ((int)g_loop_last.num_values, 2);
    ASSERT_EQ((int)g_loop_last.values[0].type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(!g_loop_last.values[0].value.boolean);
    ASSERT_EQ((int)g_loop_last.values[1].value.integer, 70);
    ASSERT_TRUE(g_loop_last.reasons_present);
    ASSERT_EQ((int)g_loop_last.reasons[0], (int)IEC61850_REASON_GI);
    ASSERT_EQ((int)g_loop_last.reasons[1], (int)IEC61850_REASON_GI);

    (void)iec61850_mms_client_rcb_disable(&client, LOOP_LD, LOOP_URCB_REF);
    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

/* ======================================================================== */

int main(void)
{
    printf("\n=== RCB End-to-End Integration Tests ===\n");

    test_urcb_data_change_report();
    test_urcb_disabled_no_report();
    test_brcb_buffered_reports();
    test_general_interrogation();
    test_enable_disable_lifecycle();

    printf("\n--- WP-2a: Ed.2 bridge (unit level) ---\n");
    test_bridge_expose_components();
    test_bridge_component_validation();
    test_bridge_brcb_persistence_and_purge();
    test_bridge_clear_association_urcb();
    test_bridge_write_prevalidation();

    printf("\n--- WP-2a: client <-> server closed loop ---\n");
    loop_setup();
    test_loop_rcb_list();
    test_loop_urcb_enroll_report();
    test_loop_brcb_buffered_resume();
    test_loop_brcb_purge();
    test_loop_buftm_aggregation();
    test_loop_ownership_conflict();
    test_loop_gi_report();
    loop_teardown();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
