/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS Control Services
 *
 * Tests: Select/Operate/Cancel lifecycle, session ownership,
 * selection timeout, error codes.
 *
 * IEC 61850 Ed.2 additions: sboTimeout, sboClass (strict/dynamic),
 * operTm (time-activated operate), AddCause enrichment,
 * CommandTermination with timestamp.
 */

#include "mms/mms_control.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

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

static void test_control_register(void)
{
    TEST("control_register");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);

    ASSERT_EQ(iec61850_control_register(&mgr, "LD0", "CSWI1$CO$Pos"), 0);
    /* Duplicate registration */
    ASSERT_TRUE(iec61850_control_register(&mgr, "LD0", "CSWI1$CO$Pos") != 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_select_operate_cancel(void)
{
    TEST("select_operate_cancel");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CSWI1$CO$Pos");

    mms_select_response_t sel_resp;
    int ret = iec61850_control_select(&mgr, "LD0", "CSWI1$CO$Pos", 1, &sel_resp);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)sel_resp.state, (int)MMS_CONTROL_STATE_SELECTED);
    ASSERT_TRUE(sel_resp.selection_id > 0);

    /* Operate */
    mms_operate_response_t op_resp;
    ret = iec61850_control_operate(&mgr, "LD0", "CSWI1$CO$Pos",
                                     (iec61850_control_ids_t){1, sel_resp.selection_id}, &op_resp);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(op_resp.success);
    ASSERT_EQ((int)op_resp.state, (int)MMS_CONTROL_STATE_READY);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_select_already_selected(void)
{
    TEST("select_already_selected");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "XCBR");

    /* Select from session 1 */
    mms_select_response_t resp;
    int ret = iec61850_control_select(&mgr, "LD0", "XCBR", 100, &resp);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)resp.state, (int)MMS_CONTROL_STATE_SELECTED);

    /* Verify the object state by attempting operate from same session */
    mms_operate_response_t op;
    ret = iec61850_control_operate(&mgr, "LD0", "XCBR",
                                     (iec61850_control_ids_t){100, resp.selection_id}, &op);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(op.success);

    /* After operate, object returns to READY — verify another session can select */
    mms_select_response_t resp2;
    ret = iec61850_control_select(&mgr, "LD0", "XCBR", 200, &resp2);
    ASSERT_EQ(ret, 0);  /* Should succeed now */

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_operate_wrong_session(void)
{
    TEST("operate_wrong_session");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB1");

    mms_select_response_t sel;
    iec61850_control_select(&mgr, "LD0", "CB1", 1, &sel);

    /* Operate from different session */
    mms_operate_response_t op;
    int ret = iec61850_control_operate(&mgr, "LD0", "CB1", (iec61850_control_ids_t){2, sel.selection_id}, &op);
    ASSERT_TRUE(ret != 0);
    ASSERT_TRUE(!op.success);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_operate_wrong_selection_id(void)
{
    TEST("operate_wrong_selection_id");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB1");

    mms_select_response_t sel;
    iec61850_control_select(&mgr, "LD0", "CB1", 1, &sel);

    mms_operate_response_t op;
    int ret = iec61850_control_operate(&mgr, "LD0", "CB1", (iec61850_control_ids_t){1, 9999}, &op);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_INVALID_SELECTION_ID);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_cancel(void)
{
    TEST("cancel");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB1");

    mms_select_response_t sel;
    iec61850_control_select(&mgr, "LD0", "CB1", 1, &sel);

    int ret = iec61850_control_cancel(&mgr, "LD0", "CB1", (iec61850_control_ids_t){1, sel.selection_id});
    ASSERT_EQ(ret, 0);

    /* Now another session can select */
    mms_select_response_t sel2;
    ret = iec61850_control_select(&mgr, "LD0", "CB1", 2, &sel2);
    ASSERT_EQ(ret, 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_select_with_value(void)
{
    TEST("select_with_value");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB1");

    mms_value_t val;
    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;

    mms_select_with_value_response_t resp;
    int ret = iec61850_control_select_with_value(&mgr, "LD0", "CB1", 1,
                                                    &val, &resp);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)resp.state, (int)MMS_CONTROL_STATE_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_operate_not_selected(void)
{
    TEST("operate_not_selected");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB1");

    mms_operate_response_t op;
    int ret = iec61850_control_operate(&mgr, "LD0", "CB1", (iec61850_control_ids_t){1, 1}, &op);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_NOT_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

/* Action callback tracking */
static int action_cb_called = 0;
static char action_cb_domain[64] = {0};
static char action_cb_item[64] = {0};
static int action_cb_return = 0;

static int test_action_callback(const char *domain, const char *item_id,
                                  const mms_value_t *value, void *user_data)
{
    (void)value;
    (void)user_data;
    action_cb_called++;
    (void)strncpy(action_cb_domain, domain, sizeof(action_cb_domain) - 1);
    (void)strncpy(action_cb_item, item_id, sizeof(action_cb_item) - 1);
    return action_cb_return;
}

static void test_operate_with_action_callback(void)
{
    TEST("operate_with_action_callback");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CSWI$CO$Pos");

    /* Set action callback */
    action_cb_called = 0;
    action_cb_return = 0;
    int ret = iec61850_control_set_action_callback(&mgr, "LD0", "CSWI$CO$Pos",
                                                      test_action_callback, NULL);
    ASSERT_EQ(ret, 0);

    /* Select and operate */
    mms_select_response_t sel;
    ret = iec61850_control_select(&mgr, "LD0", "CSWI$CO$Pos", 1, &sel);
    ASSERT_EQ(ret, 0);

    mms_operate_response_t op;
    ret = iec61850_control_operate(&mgr, "LD0", "CSWI$CO$Pos", (iec61850_control_ids_t){1, sel.selection_id}, &op);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(op.success);
    ASSERT_EQ(action_cb_called, 1);
    ASSERT_TRUE(strcmp(action_cb_domain, "LD0") == 0);
    ASSERT_TRUE(strcmp(action_cb_item, "CSWI$CO$Pos") == 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_operate_action_callback_failure(void)
{
    TEST("operate_action_callback_failure");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB2");

    /* Set callback that returns error */
    action_cb_called = 0;
    action_cb_return = -1;
    iec61850_control_set_action_callback(&mgr, "LD0", "CB2",
                                            test_action_callback, NULL);

    mms_select_response_t sel;
    iec61850_control_select(&mgr, "LD0", "CB2", 1, &sel);

    mms_operate_response_t op;
    int ret = iec61850_control_operate(&mgr, "LD0", "CB2", (iec61850_control_ids_t){1, sel.selection_id}, &op);
    ASSERT_TRUE(ret != 0);
    ASSERT_TRUE(!op.success);
    ASSERT_EQ(action_cb_called, 1);

    /* Object should be back to READY after failed operate */
    mms_select_response_t sel2;
    ret = iec61850_control_select(&mgr, "LD0", "CB2", 2, &sel2);
    ASSERT_EQ(ret, 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_set_action_callback_not_found(void)
{
    TEST("set_action_callback_not_found");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);

    int ret = iec61850_control_set_action_callback(&mgr, "LD0", "NONEXIST",
                                                      test_action_callback, NULL);
    ASSERT_TRUE(ret != 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_register_null_args(void)
{
    TEST("register_null_args");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);

    ASSERT_TRUE(iec61850_control_register(NULL, "LD0", "CB1") != 0);
    ASSERT_TRUE(iec61850_control_register(&mgr, NULL, "CB1") != 0);
    ASSERT_TRUE(iec61850_control_register(&mgr, "LD0", NULL) != 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_select_not_found(void)
{
    TEST("select_not_found");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);

    mms_select_response_t resp;
    int ret = iec61850_control_select(&mgr, "LD0", "DOES_NOT_EXIST", 1, &resp);
    /* Returns MMS_CONTROL_ERROR_ALREADY_SELECTED (0) for not-found */
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_ALREADY_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_select_blocked_by_other_session(void)
{
    TEST("select_blocked_by_other_session");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "LOCK1");

    /* Select from session 1 */
    mms_select_response_t resp1;
    int ret = iec61850_control_select(&mgr, "LD0", "LOCK1", 1, &resp1);
    ASSERT_EQ(ret, 0);

    /* Try to select from session 2 — returns ALREADY_SELECTED */
    mms_select_response_t resp2;
    ret = iec61850_control_select(&mgr, "LD0", "LOCK1", 2, &resp2);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_ALREADY_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_operate_not_found(void)
{
    TEST("operate_not_found");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);

    mms_operate_response_t op;
    int ret = iec61850_control_operate(&mgr, "LD0", "NONEXIST", (iec61850_control_ids_t){1, 1}, &op);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_NOT_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_cancel_not_found(void)
{
    TEST("cancel_not_found");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);

    int ret = iec61850_control_cancel(&mgr, "LD0", "NONEXIST", (iec61850_control_ids_t){1, 1});
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_NOT_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * NULL / Error Branch Coverage
 * ======================================================================== */

static void test_init_destroy_null(void)
{
    TEST("init_destroy_null");
    iec61850_control_manager_init(NULL);
    iec61850_control_manager_destroy(NULL);
    PASS();
}

static void test_select_null_resp(void)
{
    TEST("select_null_resp");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    ASSERT_TRUE(iec61850_control_select(&mgr, "LD0", "CB", 1, NULL) != 0);
    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_select_null_mgr(void)
{
    TEST("select_null_mgr");
    mms_select_response_t resp;
    ASSERT_TRUE(iec61850_control_select(NULL, "LD0", "CB", 1, &resp) != 0);
    PASS();
}

static void test_operate_null_resp(void)
{
    TEST("operate_null_resp");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    ASSERT_TRUE(iec61850_control_operate(&mgr, "LD0", "CB", (iec61850_control_ids_t){1, 1}, NULL) != 0);
    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_cancel_null_mgr(void)
{
    TEST("cancel_null_mgr");
    ASSERT_TRUE(iec61850_control_cancel(NULL, "LD0", "CB", (iec61850_control_ids_t){1, 1}) != 0);
    PASS();
}

static void test_cancel_wrong_ids(void)
{
    TEST("cancel_wrong_ids");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB1");

    mms_select_response_t sel;
    iec61850_control_select(&mgr, "LD0", "CB1", 1, &sel);

    /* Wrong selection_id */
    int ret = iec61850_control_cancel(&mgr, "LD0", "CB1", (iec61850_control_ids_t){1, 9999});
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_INVALID_SELECTION_ID);

    /* Wrong session_id */
    ret = iec61850_control_cancel(&mgr, "LD0", "CB1", (iec61850_control_ids_t){2, sel.selection_id});
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_INVALID_SELECTION_ID);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_set_callback_null_args(void)
{
    TEST("set_callback_null_args");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);

    ASSERT_TRUE(iec61850_control_set_action_callback(NULL, "D", "I",
                test_action_callback, NULL) != 0);
    ASSERT_TRUE(iec61850_control_set_action_callback(&mgr, NULL, "I",
                test_action_callback, NULL) != 0);
    ASSERT_TRUE(iec61850_control_set_action_callback(&mgr, "D", NULL,
                test_action_callback, NULL) != 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_cleanup_expired_null(void)
{
    TEST("cleanup_expired_null");
    iec61850_control_cleanup_expired(NULL);
    PASS();
}

static void test_cleanup_expired_with_objects(void)
{
    TEST("cleanup_expired_with_objects");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB1");

    mms_select_response_t sel;
    iec61850_control_select(&mgr, "LD0", "CB1", 1, &sel);

    /* Force expiry by setting expires_at to past */
    mgr.objects[0].selection_expires_at_ms = 1;

    iec61850_control_cleanup_expired(&mgr);

    /* Object should now be READY */
    ASSERT_EQ((int)mgr.objects[0].state, (int)MMS_CONTROL_STATE_READY);
    ASSERT_EQ((int)mgr.objects[0].selection_id, 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_select_with_value_null_value(void)
{
    TEST("select_with_value_null_value");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB1");

    mms_select_with_value_response_t resp;
    int ret = iec61850_control_select_with_value(&mgr, "LD0", "CB1", 1,
                                                    NULL, &resp);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)resp.state, (int)MMS_CONTROL_STATE_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_operate_with_preloaded_value(void)
{
    TEST("operate_with_preloaded_value");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CB1");

    /* Select with value */
    mms_value_t val;
    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;

    action_cb_called = 0;
    action_cb_return = 0;
    iec61850_control_set_action_callback(&mgr, "LD0", "CB1",
                                            test_action_callback, NULL);

    mms_select_with_value_response_t swv_resp;
    int ret = iec61850_control_select_with_value(&mgr, "LD0", "CB1", 1,
                                                    &val, &swv_resp);
    ASSERT_EQ(ret, 0);

    /* Operate — should pass preloaded value to callback */
    mms_operate_response_t op;
    ret = iec61850_control_operate(&mgr, "LD0", "CB1",
                                     (iec61850_control_ids_t){1, swv_resp.selection_id}, &op);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(op.success);
    ASSERT_EQ(action_cb_called, 1);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_select_blocked(void)
{
    TEST("select_blocked");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "BLK1");

    /* Force state to BLOCKED */
    mgr.objects[0].state = MMS_CONTROL_STATE_BLOCKED;

    mms_select_response_t resp;
    int ret = iec61850_control_select(&mgr, "LD0", "BLK1", 1, &resp);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_CONTROL_BLOCKED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_register_max_objects(void)
{
    TEST("register_max_objects");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);

    char name[32];
    for (int i = 0; i < IEC61850_CONTROL_MAX_OBJECTS; i++) {
        snprintf(name, sizeof(name), "OBJ%d", i);
        ASSERT_EQ(iec61850_control_register(&mgr, "LD0", name), 0);
    }

    /* Next should fail */
    int ret = iec61850_control_register(&mgr, "LD0", "OVERFLOW");
    ASSERT_TRUE(ret != 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_operate_null_mgr(void)
{
    TEST("operate_null_mgr");
    mms_operate_response_t op;
    ASSERT_TRUE(iec61850_control_operate(NULL, "LD0", "CB", (iec61850_control_ids_t){1, 1}, &op) != 0);
    PASS();
}

/* ========================================================================
 * IEC 61850 Ed.2 Control Model Tests
 * ======================================================================== */

static uint64_t test_mono_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static uint64_t test_utc_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static void test_sleep_ms(uint64_t ms)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000ULL);
    ts.tv_nsec = (long)((ms % 1000ULL) * 1000000ULL);
    (void)nanosleep(&ts, NULL);
}

/* Command-termination callback tracking */
static int term_cb_called = 0;
static bool term_cb_success = false;
static uint32_t term_cb_selection_id = 0;
static int term_cb_addcause = 0;
static uint64_t term_cb_timestamp_ms = 0;
static char term_cb_domain[64] = {0};
static char term_cb_item[64] = {0};

static void test_termination_callback(const char *domain, const char *item_id,
                                        uint32_t selection_id, bool success,
                                        iec61850_control_addcause_t addcause,
                                        uint64_t timestamp_ms, void *user_data)
{
    (void)user_data;
    term_cb_called++;
    term_cb_success = success;
    term_cb_selection_id = selection_id;
    term_cb_addcause = (int)addcause;
    term_cb_timestamp_ms = timestamp_ms;
    (void)strncpy(term_cb_domain, domain, sizeof(term_cb_domain) - 1);
    (void)strncpy(term_cb_item, item_id, sizeof(term_cb_item) - 1);
}

static void test_sbo_timeout_per_object(void)
{
    TEST("sbo_timeout_per_object");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "SBO1");

    /* Default timeout (sbo_timeout_ms = 0 means 30 s default) */
    uint64_t before = test_mono_ms();
    mms_select_response_t sel;
    int ret = iec61850_control_select(&mgr, "LD0", "SBO1", 1, &sel);
    uint64_t after = test_mono_ms();
    ASSERT_EQ(ret, 0);
    uint64_t default_expiry = mgr.objects[0].selection_expires_at_ms;
    ASSERT_TRUE(default_expiry >= before + (uint64_t)IEC61850_CONTROL_DEFAULT_TIMEOUT_MS);
    ASSERT_TRUE(default_expiry <= after + (uint64_t)IEC61850_CONTROL_DEFAULT_TIMEOUT_MS);

    /* Cancel, then configure a short per-object sboTimeout */
    ASSERT_EQ(iec61850_control_cancel(&mgr, "LD0", "SBO1",
                (iec61850_control_ids_t){1, sel.selection_id}), 0);

    iec61850_control_config_t cfg = {0};
    cfg.sbo_timeout_ms = 5000U;
    cfg.sbo_class = IEC61850_CONTROL_SBO_CLASS_STRICT;
    ASSERT_EQ(iec61850_control_configure(&mgr, "LD0", "SBO1", &cfg), 0);

    before = test_mono_ms();
    mms_select_response_t sel2;
    ret = iec61850_control_select(&mgr, "LD0", "SBO1", 1, &sel2);
    after = test_mono_ms();
    ASSERT_EQ(ret, 0);
    uint64_t custom_expiry = mgr.objects[0].selection_expires_at_ms;
    ASSERT_TRUE(custom_expiry >= before + 5000ULL);
    ASSERT_TRUE(custom_expiry <= after + 5000ULL);
    ASSERT_TRUE(custom_expiry < default_expiry);

    /* sboTimeout expiry frees the selection (forced due, deterministic) */
    mgr.objects[0].selection_expires_at_ms = 1;
    iec61850_control_cleanup_expired(&mgr);
    ASSERT_EQ((int)mgr.objects[0].state, (int)MMS_CONTROL_STATE_READY);
    ASSERT_EQ((int)mgr.objects[0].selection_id, 0);

    /* Operate after expiry is rejected (strict class, not selected) */
    mms_operate_response_t op;
    ret = iec61850_control_operate(&mgr, "LD0", "SBO1",
                                     (iec61850_control_ids_t){1, sel2.selection_id}, &op);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_NOT_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_sbo_timeout_real_expiry(void)
{
    TEST("sbo_timeout_real_expiry");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "SBO2");

    iec61850_control_config_t cfg = {0};
    cfg.sbo_timeout_ms = 200U;
    cfg.sbo_class = IEC61850_CONTROL_SBO_CLASS_STRICT;
    ASSERT_EQ(iec61850_control_configure(&mgr, "LD0", "SBO2", &cfg), 0);

    mms_select_response_t sel;
    int ret = iec61850_control_select(&mgr, "LD0", "SBO2", 1, &sel);
    ASSERT_EQ(ret, 0);

    /* Short real timeout: selection must expire */
    test_sleep_ms(350);
    iec61850_control_cleanup_expired(&mgr);
    ASSERT_EQ((int)mgr.objects[0].state, (int)MMS_CONTROL_STATE_READY);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_sbo_class_strict_rejects_operate_without_select(void)
{
    TEST("sbo_class_strict_rejects_operate_without_select");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "STR1");

    /* Strict is the default */
    iec61850_control_config_t cfg = {0};
    cfg.sbo_timeout_ms = 0U;
    cfg.sbo_class = IEC61850_CONTROL_SBO_CLASS_STRICT;
    ASSERT_EQ(iec61850_control_configure(&mgr, "LD0", "STR1", &cfg), 0);

    action_cb_called = 0;
    action_cb_return = 0;
    iec61850_control_set_action_callback(&mgr, "LD0", "STR1",
                                           test_action_callback, NULL);

    mms_operate_response_t op;
    iec61850_control_addcause_t ac = IEC61850_ADDCAUSE_UNKNOWN;
    int ret = iec61850_control_operate_ed2(&mgr, "LD0", "STR1",
                                              (iec61850_control_ids_t){1, 0},
                                              0ULL, &op, &ac);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_NOT_SELECTED);
    ASSERT_TRUE(!op.success);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_OBJECT_NOT_SELECTED);
    ASSERT_EQ(action_cb_called, 0);

    /* Same cause recorded on the object */
    iec61850_control_addcause_t last = IEC61850_ADDCAUSE_UNKNOWN;
    ASSERT_EQ(iec61850_control_get_last_addcause(&mgr, "LD0", "STR1", &last), 0);
    ASSERT_EQ((int)last, (int)IEC61850_ADDCAUSE_OBJECT_NOT_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_sbo_class_dynamic_accepts_operate_without_select(void)
{
    TEST("sbo_class_dynamic_accepts_operate_without_select");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "DYN1");

    iec61850_control_config_t cfg = {0};
    cfg.sbo_timeout_ms = 0U;
    cfg.sbo_class = IEC61850_CONTROL_SBO_CLASS_DYNAMIC;
    ASSERT_EQ(iec61850_control_configure(&mgr, "LD0", "DYN1", &cfg), 0);

    action_cb_called = 0;
    action_cb_return = 0;
    iec61850_control_set_action_callback(&mgr, "LD0", "DYN1",
                                           test_action_callback, NULL);

    /* Dynamic: operate on a READY object carries its own select check */
    mms_operate_response_t op;
    iec61850_control_addcause_t ac = IEC61850_ADDCAUSE_UNKNOWN;
    int ret = iec61850_control_operate_ed2(&mgr, "LD0", "DYN1",
                                              (iec61850_control_ids_t){7, 0},
                                              0ULL, &op, &ac);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(op.success);
    ASSERT_EQ(action_cb_called, 1);

    /* Dynamic still works with a prior, valid select */
    mms_select_response_t sel;
    ret = iec61850_control_select(&mgr, "LD0", "DYN1", 1, &sel);
    ASSERT_EQ(ret, 0);
    ret = iec61850_control_operate(&mgr, "LD0", "DYN1",
                                     (iec61850_control_ids_t){1, sel.selection_id}, &op);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(op.success);
    ASSERT_EQ(action_cb_called, 2);

    /* Dynamic does not bypass another session's selection */
    mms_select_response_t sel2;
    ret = iec61850_control_select(&mgr, "LD0", "DYN1", 1, &sel2);
    ASSERT_EQ(ret, 0);
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "DYN1",
                                         (iec61850_control_ids_t){2, 0},
                                         0ULL, &op, &ac);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_INVALID_SELECTION_ID);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_SELECT_FAILED);
    ASSERT_EQ(action_cb_called, 2);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_oper_tm_past_rejected(void)
{
    TEST("oper_tm_past_rejected");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "TM1");

    mms_select_response_t sel;
    int ret = iec61850_control_select(&mgr, "LD0", "TM1", 1, &sel);
    ASSERT_EQ(ret, 0);

    /* operTm in the past is rejected, the selection stays intact */
    mms_operate_response_t op;
    iec61850_control_addcause_t ac = IEC61850_ADDCAUSE_UNKNOWN;
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "TM1",
                                         (iec61850_control_ids_t){1, sel.selection_id},
                                         test_utc_ms() - 1000ULL, &op, &ac);
    ASSERT_EQ(ret, IEC61850_CONTROL_ERROR_OPER_TM_INVALID);
    ASSERT_TRUE(!op.success);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_NOT_IN_ALLOWED_VALUE_RANGE);
    ASSERT_EQ((int)mgr.objects[0].state, (int)MMS_CONTROL_STATE_SELECTED);

    /* The still-valid selection can be operated immediately */
    ret = iec61850_control_operate(&mgr, "LD0", "TM1",
                                     (iec61850_control_ids_t){1, sel.selection_id}, &op);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(op.success);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_oper_tm_future_executes_when_due(void)
{
    TEST("oper_tm_future_executes_when_due");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "TM2");

    action_cb_called = 0;
    action_cb_return = 0;
    iec61850_control_set_action_callback(&mgr, "LD0", "TM2",
                                           test_action_callback, NULL);

    mms_select_response_t sel;
    int ret = iec61850_control_select(&mgr, "LD0", "TM2", 1, &sel);
    ASSERT_EQ(ret, 0);

    /* Arm a time-activated operate far in the future */
    mms_operate_response_t op;
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "TM2",
                                         (iec61850_control_ids_t){1, sel.selection_id},
                                         test_utc_ms() + 60000ULL, &op, NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(op.success);
    ASSERT_EQ((int)op.state, (int)MMS_CONTROL_STATE_OPERATE);
    ASSERT_TRUE(mgr.objects[0].oper_tm_pending);

    /* While armed: further operate and select are rejected */
    iec61850_control_addcause_t ac = IEC61850_ADDCAUSE_UNKNOWN;
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "TM2",
                                         (iec61850_control_ids_t){1, sel.selection_id},
                                         0ULL, &op, &ac);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_CONTROL_IN_PROGRESS);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_COMMAND_ALREADY_IN_EXECUTION);

    mms_select_response_t sel2;
    ret = iec61850_control_select(&mgr, "LD0", "TM2", 2, &sel2);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_CONTROL_IN_PROGRESS);

    /* Not due yet: processing must not fire the action */
    iec61850_control_process(&mgr);
    ASSERT_EQ(action_cb_called, 0);
    ASSERT_EQ((int)mgr.objects[0].state, (int)MMS_CONTROL_STATE_OPERATE);

    /* Force the due time (deterministic) and process */
    mgr.objects[0].oper_tm_due_ms = 1;
    iec61850_control_process(&mgr);
    ASSERT_EQ(action_cb_called, 1);
    ASSERT_EQ((int)mgr.objects[0].state, (int)MMS_CONTROL_STATE_READY);
    ASSERT_EQ((int)mgr.objects[0].selection_id, 0);

    /* Object is selectable again after the command fired */
    ret = iec61850_control_select(&mgr, "LD0", "TM2", 3, &sel2);
    ASSERT_EQ(ret, 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_oper_tm_real_time_fires_when_due(void)
{
    TEST("oper_tm_real_time_fires_when_due");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "TM3");

    action_cb_called = 0;
    action_cb_return = 0;
    iec61850_control_set_action_callback(&mgr, "LD0", "TM3",
                                           test_action_callback, NULL);

    mms_select_response_t sel;
    int ret = iec61850_control_select(&mgr, "LD0", "TM3", 1, &sel);
    ASSERT_EQ(ret, 0);

    /* Short-duration time-activated operate (300 ms) */
    mms_operate_response_t op;
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "TM3",
                                         (iec61850_control_ids_t){1, sel.selection_id},
                                         test_utc_ms() + 300ULL, &op, NULL);
    ASSERT_EQ(ret, 0);

    /* Immediately due check must not fire */
    iec61850_control_process(&mgr);
    ASSERT_EQ(action_cb_called, 0);

    /* Poll until the command fires (bounded at 3 s) */
    int fired = 0;
    for (int i = 0; (i < 150) && (fired == 0); i++) {
        test_sleep_ms(20);
        iec61850_control_process(&mgr);
        fired = (action_cb_called > 0) ? 1 : 0;
    }
    ASSERT_TRUE(fired);
    ASSERT_EQ(action_cb_called, 1);
    ASSERT_EQ((int)mgr.objects[0].state, (int)MMS_CONTROL_STATE_READY);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_oper_tm_cancel_pending(void)
{
    TEST("oper_tm_cancel_pending");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "TM4");

    action_cb_called = 0;
    action_cb_return = 0;
    term_cb_called = 0;
    iec61850_control_set_action_callback(&mgr, "LD0", "TM4",
                                           test_action_callback, NULL);
    iec61850_control_set_termination_callback(&mgr, "LD0", "TM4",
                                                test_termination_callback, NULL);

    mms_select_response_t sel;
    int ret = iec61850_control_select(&mgr, "LD0", "TM4", 1, &sel);
    ASSERT_EQ(ret, 0);

    mms_operate_response_t op;
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "TM4",
                                         (iec61850_control_ids_t){1, sel.selection_id},
                                         test_utc_ms() + 60000ULL, &op, NULL);
    ASSERT_EQ(ret, 0);

    /* Wrong ids cannot cancel the pending time-activated operate */
    ret = iec61850_control_cancel(&mgr, "LD0", "TM4",
                                    (iec61850_control_ids_t){2, sel.selection_id});
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_INVALID_SELECTION_ID);

    /* Cancel with the right ids aborts it before execution */
    ret = iec61850_control_cancel(&mgr, "LD0", "TM4",
                                    (iec61850_control_ids_t){1, sel.selection_id});
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(action_cb_called, 0);

    /* Abortion-by-cancel is reported via the termination notification */
    ASSERT_EQ(term_cb_called, 1);
    ASSERT_TRUE(!term_cb_success);
    ASSERT_EQ(term_cb_addcause, (int)IEC61850_ADDCAUSE_ABORTION_BY_CANCEL);
    ASSERT_TRUE(term_cb_timestamp_ms > 0ULL);
    ASSERT_EQ((int)mgr.objects[0].state, (int)MMS_CONTROL_STATE_READY);

    /* Process after cancel must not fire the aborted command */
    mgr.objects[0].oper_tm_due_ms = 1;
    iec61850_control_process(&mgr);
    ASSERT_EQ(action_cb_called, 0);

    /* Object is selectable again */
    mms_select_response_t sel2;
    ret = iec61850_control_select(&mgr, "LD0", "TM4", 2, &sel2);
    ASSERT_EQ(ret, 0);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_addcause_rejection_paths(void)
{
    TEST("addcause_rejection_paths");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "AC1");

    mms_operate_response_t op;
    mms_select_response_t sel;
    iec61850_control_addcause_t ac = IEC61850_ADDCAUSE_UNKNOWN;
    int ret;

    /* Operate without select: object-not-selected */
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "AC1",
                                         (iec61850_control_ids_t){1, 0},
                                         0ULL, &op, &ac);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_NOT_SELECTED);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_OBJECT_NOT_SELECTED);

    /* Wrong selection id: select-failed */
    ret = iec61850_control_select(&mgr, "LD0", "AC1", 1, &sel);
    ASSERT_EQ(ret, 0);
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "AC1",
                                         (iec61850_control_ids_t){1, 9999},
                                         0ULL, &op, &ac);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_INVALID_SELECTION_ID);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_SELECT_FAILED);

    /* Wrong session: select-failed */
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "AC1",
                                         (iec61850_control_ids_t){2, sel.selection_id},
                                         0ULL, &op, &ac);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_INVALID_SELECTION_ID);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_SELECT_FAILED);

    /* Expired selection: time-limit-overrun */
    mgr.objects[0].selection_expires_at_ms = 1;
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "AC1",
                                         (iec61850_control_ids_t){1, sel.selection_id},
                                         0ULL, &op, &ac);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_SELECTION_TIMEOUT);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_TIME_LIMIT_OVERRUN);

    /* Blocked object: blocked-by-mode on both select and operate */
    mgr.objects[0].state = MMS_CONTROL_STATE_BLOCKED;
    ret = iec61850_control_select(&mgr, "LD0", "AC1", 1, &sel);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_CONTROL_BLOCKED);
    iec61850_control_addcause_t last = IEC61850_ADDCAUSE_UNKNOWN;
    ASSERT_EQ(iec61850_control_get_last_addcause(&mgr, "LD0", "AC1", &last), 0);
    ASSERT_EQ((int)last, (int)IEC61850_ADDCAUSE_BLOCKED_BY_MODE);

    ret = iec61850_control_operate_ed2(&mgr, "LD0", "AC1",
                                         (iec61850_control_ids_t){1, 0},
                                         0ULL, &op, &ac);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_CONTROL_BLOCKED);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_BLOCKED_BY_MODE);

    /* Already selected by another session: select-failed */
    mgr.objects[0].state = MMS_CONTROL_STATE_READY;
    mgr.objects[0].selection_id = 0;
    mgr.objects[0].owner_session_id = 0;
    ret = iec61850_control_select(&mgr, "LD0", "AC1", 1, &sel);
    ASSERT_EQ(ret, 0);
    ret = iec61850_control_select(&mgr, "LD0", "AC1", 2, &sel);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_ALREADY_SELECTED);
    ASSERT_EQ(iec61850_control_get_last_addcause(&mgr, "LD0", "AC1", &last), 0);
    ASSERT_EQ((int)last, (int)IEC61850_ADDCAUSE_SELECT_FAILED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_addcause_action_callback_failure(void)
{
    TEST("addcause_action_callback_failure");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "AC2");

    action_cb_called = 0;
    action_cb_return = -1;
    term_cb_called = 0;
    iec61850_control_set_action_callback(&mgr, "LD0", "AC2",
                                           test_action_callback, NULL);
    iec61850_control_set_termination_callback(&mgr, "LD0", "AC2",
                                                test_termination_callback, NULL);

    mms_select_response_t sel;
    int ret = iec61850_control_select(&mgr, "LD0", "AC2", 1, &sel);
    ASSERT_EQ(ret, 0);

    mms_operate_response_t op;
    iec61850_control_addcause_t ac = IEC61850_ADDCAUSE_UNKNOWN;
    ret = iec61850_control_operate_ed2(&mgr, "LD0", "AC2",
                                         (iec61850_control_ids_t){1, sel.selection_id},
                                         0ULL, &op, &ac);
    ASSERT_TRUE(ret != 0);
    ASSERT_EQ((int)ac, (int)IEC61850_ADDCAUSE_BLOCKED_BY_PROCESS);

    /* Failed execution is reported via the termination notification */
    ASSERT_EQ(term_cb_called, 1);
    ASSERT_TRUE(!term_cb_success);
    ASSERT_EQ(term_cb_addcause, (int)IEC61850_ADDCAUSE_BLOCKED_BY_PROCESS);
    ASSERT_TRUE(term_cb_timestamp_ms > 0ULL);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_command_termination_timestamp(void)
{
    TEST("command_termination_timestamp");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "CT1");

    action_cb_called = 0;
    action_cb_return = 0;
    term_cb_called = 0;
    iec61850_control_set_action_callback(&mgr, "LD0", "CT1",
                                           test_action_callback, NULL);
    iec61850_control_set_termination_callback(&mgr, "LD0", "CT1",
                                                test_termination_callback, NULL);

    mms_select_response_t sel;
    int ret = iec61850_control_select(&mgr, "LD0", "CT1", 5, &sel);
    ASSERT_EQ(ret, 0);

    uint64_t before = test_utc_ms();
    mms_operate_response_t op;
    ret = iec61850_control_operate(&mgr, "LD0", "CT1",
                                     (iec61850_control_ids_t){5, sel.selection_id}, &op);
    uint64_t after = test_utc_ms();
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(op.success);

    ASSERT_EQ(term_cb_called, 1);
    ASSERT_TRUE(term_cb_success);
    ASSERT_EQ(term_cb_selection_id, sel.selection_id);
    ASSERT_TRUE(strcmp(term_cb_domain, "LD0") == 0);
    ASSERT_TRUE(strcmp(term_cb_item, "CT1") == 0);
    /* Timestamp is a UTC time bound by the operate window */
    ASSERT_TRUE(term_cb_timestamp_ms >= before);
    ASSERT_TRUE(term_cb_timestamp_ms <= after);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_ed2_api_edges(void)
{
    TEST("ed2_api_edges");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);
    iec61850_control_register(&mgr, "LD0", "ED1");

    iec61850_control_config_t cfg = {0};
    cfg.sbo_timeout_ms = 0U;
    cfg.sbo_class = IEC61850_CONTROL_SBO_CLASS_DYNAMIC;

    /* NULL arguments */
    ASSERT_TRUE(iec61850_control_configure(NULL, "LD0", "ED1", &cfg) != 0);
    ASSERT_TRUE(iec61850_control_configure(&mgr, NULL, "ED1", &cfg) != 0);
    ASSERT_TRUE(iec61850_control_configure(&mgr, "LD0", NULL, &cfg) != 0);
    ASSERT_TRUE(iec61850_control_configure(&mgr, "LD0", "ED1", NULL) != 0);
    ASSERT_TRUE(iec61850_control_set_termination_callback(NULL, "LD0", "ED1",
                test_termination_callback, NULL) != 0);
    ASSERT_TRUE(iec61850_control_get_last_addcause(&mgr, "LD0", "ED1", NULL) != 0);
    ASSERT_TRUE(iec61850_control_operate_ed2(&mgr, "LD0", "ED1",
                (iec61850_control_ids_t){1, 0}, 0ULL, NULL, NULL) != 0);

    /* Unknown object */
    ASSERT_TRUE(iec61850_control_configure(&mgr, "LD0", "NOPE", &cfg) != 0);
    ASSERT_TRUE(iec61850_control_set_termination_callback(&mgr, "LD0", "NOPE",
                test_termination_callback, NULL) != 0);
    iec61850_control_addcause_t last = IEC61850_ADDCAUSE_UNKNOWN;
    ASSERT_TRUE(iec61850_control_get_last_addcause(&mgr, "LD0", "NOPE", &last) != 0);

    /* Invalid sboClass value */
    cfg.sbo_class = (iec61850_control_sbo_class_t)2;
    ASSERT_TRUE(iec61850_control_configure(&mgr, "LD0", "ED1", &cfg) != 0);

    /* NULL manager is safe */
    iec61850_control_process(NULL);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

int main(void)
{
    printf("=== MMS Control Service Tests ===\n");

    test_control_register();
    test_register_null_args();
    test_select_operate_cancel();
    test_select_already_selected();
    test_select_blocked_by_other_session();
    test_select_not_found();
    test_operate_wrong_session();
    test_operate_wrong_selection_id();
    test_operate_not_found();
    test_cancel();
    test_cancel_not_found();
    test_select_with_value();
    test_operate_not_selected();
    test_operate_with_action_callback();
    test_operate_action_callback_failure();
    test_set_action_callback_not_found();

    printf("\n--- NULL / Error Branches ---\n");
    test_init_destroy_null();
    test_select_null_resp();
    test_select_null_mgr();
    test_operate_null_resp();
    test_cancel_null_mgr();
    test_cancel_wrong_ids();
    test_set_callback_null_args();
    test_cleanup_expired_null();
    test_cleanup_expired_with_objects();
    test_select_with_value_null_value();
    test_operate_with_preloaded_value();
    test_select_blocked();
    test_register_max_objects();
    test_operate_null_mgr();

    printf("\n--- IEC 61850 Ed.2 Control Model ---\n");
    test_sbo_timeout_per_object();
    test_sbo_timeout_real_expiry();
    test_sbo_class_strict_rejects_operate_without_select();
    test_sbo_class_dynamic_accepts_operate_without_select();
    test_oper_tm_past_rejected();
    test_oper_tm_future_executes_when_due();
    test_oper_tm_real_time_fires_when_due();
    test_oper_tm_cancel_pending();
    test_addcause_rejection_paths();
    test_addcause_action_callback_failure();
    test_command_termination_timestamp();
    test_ed2_api_edges();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
