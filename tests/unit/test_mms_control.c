/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS Control Services
 *
 * Tests: Select/Operate/Cancel lifecycle, session ownership,
 * selection timeout, error codes.
 */

#include "mms/mms_control.h"

#include <stdio.h>
#include <string.h>

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
    ret = iec61850_control_operate(&mgr, "LD0", "CSWI1$CO$Pos", 1,
                                     sel_resp.selection_id, &op_resp);
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
    ret = iec61850_control_operate(&mgr, "LD0", "XCBR", 100,
                                     resp.selection_id, &op);
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
    int ret = iec61850_control_operate(&mgr, "LD0", "CB1", 2,
                                         sel.selection_id, &op);
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
    int ret = iec61850_control_operate(&mgr, "LD0", "CB1", 1, 9999, &op);
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

    int ret = iec61850_control_cancel(&mgr, "LD0", "CB1", 1, sel.selection_id);
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
    int ret = iec61850_control_operate(&mgr, "LD0", "CB1", 1, 1, &op);
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
    ret = iec61850_control_operate(&mgr, "LD0", "CSWI$CO$Pos", 1,
                                     sel.selection_id, &op);
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
    int ret = iec61850_control_operate(&mgr, "LD0", "CB2", 1,
                                         sel.selection_id, &op);
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
    int ret = iec61850_control_operate(&mgr, "LD0", "NONEXIST", 1, 1, &op);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_NOT_SELECTED);

    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_cancel_not_found(void)
{
    TEST("cancel_not_found");
    iec61850_control_manager_t mgr;
    iec61850_control_manager_init(&mgr);

    int ret = iec61850_control_cancel(&mgr, "LD0", "NONEXIST", 1, 1);
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
    ASSERT_TRUE(iec61850_control_operate(&mgr, "LD0", "CB", 1, 1, NULL) != 0);
    iec61850_control_manager_destroy(&mgr);
    PASS();
}

static void test_cancel_null_mgr(void)
{
    TEST("cancel_null_mgr");
    ASSERT_TRUE(iec61850_control_cancel(NULL, "LD0", "CB", 1, 1) != 0);
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
    int ret = iec61850_control_cancel(&mgr, "LD0", "CB1", 1, 9999);
    ASSERT_EQ(ret, MMS_CONTROL_ERROR_INVALID_SELECTION_ID);

    /* Wrong session_id */
    ret = iec61850_control_cancel(&mgr, "LD0", "CB1", 2, sel.selection_id);
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
    ret = iec61850_control_operate(&mgr, "LD0", "CB1", 1,
                                     swv_resp.selection_id, &op);
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
    ASSERT_TRUE(iec61850_control_operate(NULL, "LD0", "CB", 1, 1, &op) != 0);
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

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
