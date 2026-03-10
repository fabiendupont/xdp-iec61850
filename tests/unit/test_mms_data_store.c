/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS Data Store
 *
 * Tests: domain CRUD, variable CRUD, named variable lists,
 * concurrent access (thread safety).
 *
 * License: BSD-3-Clause
 */

#include "mms/mms_data_store.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>

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

/* ========================================================================
 * Domain Management
 * ======================================================================== */

static void test_create_domain(void)
{
    TEST("create_domain");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    ASSERT_EQ(iec61850_mms_ds_create_domain(&ds, "IED1LD0"), IEC61850_MMS_DS_OK);
    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&ds, "IED1LD0"));
    ASSERT_TRUE(!iec61850_mms_ds_domain_exists(&ds, "IED2LD0"));

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_create_domain_idempotent(void)
{
    TEST("create_domain_idempotent");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    ASSERT_EQ(iec61850_mms_ds_create_domain(&ds, "IED1LD0"), IEC61850_MMS_DS_OK);
    /* Second create succeeds or returns exists */
    int ret = iec61850_mms_ds_create_domain(&ds, "IED1LD0");
    ASSERT_TRUE(ret == IEC61850_MMS_DS_OK || ret == IEC61850_MMS_DS_ERR_EXISTS);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_multiple_domains(void)
{
    TEST("multiple_domains");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    iec61850_mms_ds_create_domain(&ds, "IED1LD0");
    iec61850_mms_ds_create_domain(&ds, "IED1LD1");
    iec61850_mms_ds_create_domain(&ds, "IED2LD0");

    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&ds, "IED1LD0"));
    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&ds, "IED1LD1"));
    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&ds, "IED2LD0"));

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

/* ========================================================================
 * Variable CRUD
 * ======================================================================== */

static void test_create_read_variable(void)
{
    TEST("create_read_variable");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t initial;
    memset(&initial, 0, sizeof(initial));
    initial.type = MMS_TYPE_INTEGER;
    initial.value.integer = 42;

    ASSERT_EQ(iec61850_mms_ds_create_variable(&ds, "IED1LD0", "XCBR1$ST$Pos$stVal",
              MMS_TYPE_INTEGER, &initial), IEC61850_MMS_DS_OK);
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IED1LD0", "XCBR1$ST$Pos$stVal"));

    mms_value_t read_val;
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "IED1LD0", "XCBR1$ST$Pos$stVal",
              &read_val), IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)read_val.type, (int)MMS_TYPE_INTEGER);
    ASSERT_EQ((int)read_val.value.integer, 42);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_write_variable(void)
{
    TEST("write_variable");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t initial;
    memset(&initial, 0, sizeof(initial));
    initial.type = MMS_TYPE_BOOLEAN;
    initial.value.boolean = false;
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "LLN0$ST$Beh$stVal",
                                      MMS_TYPE_BOOLEAN, &initial);

    /* Write new value */
    mms_value_t new_val;
    memset(&new_val, 0, sizeof(new_val));
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;
    ASSERT_EQ(iec61850_mms_ds_write_variable(&ds, "IED1LD0", "LLN0$ST$Beh$stVal",
              &new_val), IEC61850_MMS_DS_OK);

    /* Read back */
    mms_value_t read_val;
    iec61850_mms_ds_read_variable(&ds, "IED1LD0", "LLN0$ST$Beh$stVal", &read_val);
    ASSERT_TRUE(read_val.value.boolean == true);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_read_nonexistent_variable(void)
{
    TEST("read_nonexistent_variable");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t val;
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "IED1LD0", "nonexistent", &val),
              IEC61850_MMS_DS_ERR_NOT_FOUND);

    /* Non-existent domain */
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "NOPE", "var1", &val),
              IEC61850_MMS_DS_ERR_NOT_FOUND);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_variable_attrs(void)
{
    TEST("variable_attrs");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t initial;
    memset(&initial, 0, sizeof(initial));
    initial.type = MMS_TYPE_FLOATING_POINT;
    initial.value.floating_point = 3.14f;
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "MMXU1$MX$W$mag$f",
                                      MMS_TYPE_FLOATING_POINT, &initial);

    mms_variable_access_attrs_t attrs;
    ASSERT_EQ(iec61850_mms_ds_get_variable_attrs(&ds, "IED1LD0", "MMXU1$MX$W$mag$f",
              &attrs), IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)attrs.type, (int)MMS_TYPE_FLOATING_POINT);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_get_variable_names(void)
{
    TEST("get_variable_names");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "var1", MMS_TYPE_INTEGER, &val);
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "var2", MMS_TYPE_INTEGER, &val);
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "var3", MMS_TYPE_INTEGER, &val);

    char names[10][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    ASSERT_EQ(iec61850_mms_ds_get_var_names(&ds, "IED1LD0", names, &count, 10),
              IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)count, 3);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

/* ========================================================================
 * Named Variable Lists
 * ======================================================================== */

static void test_define_named_list(void)
{
    TEST("define_named_list");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_variable_spec_t vars[2];
    memset(vars, 0, sizeof(vars));
    strncpy(vars[0].domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(vars[0].item_id, "XCBR1$ST$Pos$stVal", MMS_MAX_VARIABLE_NAME - 1);
    strncpy(vars[1].domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(vars[1].item_id, "XCBR1$ST$Pos$q", MMS_MAX_VARIABLE_NAME - 1);

    ASSERT_EQ(iec61850_mms_ds_define_list(&ds, "IED1LD0", "DS1", vars, 2),
              IEC61850_MMS_DS_OK);

    /* Get list attrs */
    mms_variable_spec_t out_vars[10];
    uint32_t num = 0;
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(&ds, "IED1LD0", "DS1",
              out_vars, &num, 10), IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)num, 2);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_delete_named_list(void)
{
    TEST("delete_named_list");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_variable_spec_t vars[1];
    memset(vars, 0, sizeof(vars));
    strncpy(vars[0].domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(vars[0].item_id, "var1", MMS_MAX_VARIABLE_NAME - 1);

    iec61850_mms_ds_define_list(&ds, "IED1LD0", "DS1", vars, 1);
    ASSERT_EQ(iec61850_mms_ds_delete_list(&ds, "IED1LD0", "DS1"),
              IEC61850_MMS_DS_OK);

    /* Should fail to get deleted list */
    uint32_t num = 0;
    ASSERT_TRUE(iec61850_mms_ds_get_list_attrs(&ds, "IED1LD0", "DS1",
                vars, &num, 1) != IEC61850_MMS_DS_OK);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

/* ========================================================================
 * NULL / Error Branch Coverage
 * ======================================================================== */

static void test_null_args(void)
{
    TEST("null_args");
    iec61850_mms_data_store_t ds;
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    /* init/destroy NULL */
    iec61850_mms_ds_init(NULL);
    iec61850_mms_ds_destroy(NULL);

    /* create_domain NULL args */
    ASSERT_EQ(iec61850_mms_ds_create_domain(NULL, "D"), IEC61850_MMS_DS_ERR_ARGS);
    iec61850_mms_ds_init(&ds);
    ASSERT_EQ(iec61850_mms_ds_create_domain(&ds, NULL), IEC61850_MMS_DS_ERR_ARGS);

    /* domain_exists NULL args */
    ASSERT_TRUE(!iec61850_mms_ds_domain_exists(NULL, "D"));
    ASSERT_TRUE(!iec61850_mms_ds_domain_exists(&ds, NULL));

    /* create_variable NULL args */
    ASSERT_EQ(iec61850_mms_ds_create_variable(NULL, "D", "V", MMS_TYPE_INTEGER, &val),
              IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_create_variable(&ds, NULL, "V", MMS_TYPE_INTEGER, &val),
              IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_create_variable(&ds, "D", NULL, MMS_TYPE_INTEGER, &val),
              IEC61850_MMS_DS_ERR_ARGS);

    /* read_variable NULL args */
    ASSERT_EQ(iec61850_mms_ds_read_variable(NULL, "D", "V", &val), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, NULL, "V", &val), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "D", NULL, &val), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "D", "V", NULL), IEC61850_MMS_DS_ERR_ARGS);

    /* write_variable NULL args */
    ASSERT_EQ(iec61850_mms_ds_write_variable(NULL, "D", "V", &val), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_write_variable(&ds, NULL, "V", &val), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_write_variable(&ds, "D", NULL, &val), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_write_variable(&ds, "D", "V", NULL), IEC61850_MMS_DS_ERR_ARGS);

    /* get_variable_attrs NULL args */
    mms_variable_access_attrs_t attrs;
    ASSERT_EQ(iec61850_mms_ds_get_variable_attrs(NULL, "D", "V", &attrs), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_variable_attrs(&ds, NULL, "V", &attrs), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_variable_attrs(&ds, "D", NULL, &attrs), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_variable_attrs(&ds, "D", "V", NULL), IEC61850_MMS_DS_ERR_ARGS);

    /* variable_exists NULL args */
    ASSERT_TRUE(!iec61850_mms_ds_variable_exists(NULL, "D", "V"));
    ASSERT_TRUE(!iec61850_mms_ds_variable_exists(&ds, NULL, "V"));
    ASSERT_TRUE(!iec61850_mms_ds_variable_exists(&ds, "D", NULL));

    /* get_var_names NULL args */
    char names[1][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    ASSERT_EQ(iec61850_mms_ds_get_var_names(NULL, "D", names, &count, 1), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_var_names(&ds, NULL, names, &count, 1), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_var_names(&ds, "D", NULL, &count, 1), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_var_names(&ds, "D", names, NULL, 1), IEC61850_MMS_DS_ERR_ARGS);

    /* define_list NULL args */
    ASSERT_EQ(iec61850_mms_ds_define_list(NULL, "D", "L", NULL, 0), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_define_list(&ds, NULL, "L", NULL, 0), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_define_list(&ds, "D", NULL, NULL, 0), IEC61850_MMS_DS_ERR_ARGS);

    /* delete_list NULL args */
    ASSERT_EQ(iec61850_mms_ds_delete_list(NULL, "D", "L"), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_delete_list(&ds, NULL, "L"), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_delete_list(&ds, "D", NULL), IEC61850_MMS_DS_ERR_ARGS);

    /* get_list_attrs NULL args */
    mms_variable_spec_t vars[1];
    uint32_t num = 0;
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(NULL, "D", "L", vars, &num, 1), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(&ds, NULL, "L", vars, &num, 1), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(&ds, "D", NULL, vars, &num, 1), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(&ds, "D", "L", NULL, &num, 1), IEC61850_MMS_DS_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(&ds, "D", "L", vars, NULL, 1), IEC61850_MMS_DS_ERR_ARGS);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_nonexistent_domain_ops(void)
{
    TEST("nonexistent_domain_ops");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    /* Operations on non-existent domain */
    ASSERT_EQ(iec61850_mms_ds_create_variable(&ds, "NOPE", "V", MMS_TYPE_INTEGER, &val),
              IEC61850_MMS_DS_ERR_NOT_FOUND);
    ASSERT_EQ(iec61850_mms_ds_write_variable(&ds, "NOPE", "V", &val),
              IEC61850_MMS_DS_ERR_NOT_FOUND);

    mms_variable_access_attrs_t attrs;
    ASSERT_EQ(iec61850_mms_ds_get_variable_attrs(&ds, "NOPE", "V", &attrs),
              IEC61850_MMS_DS_ERR_NOT_FOUND);
    ASSERT_TRUE(!iec61850_mms_ds_variable_exists(&ds, "NOPE", "V"));

    char names[1][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    ASSERT_EQ(iec61850_mms_ds_get_var_names(&ds, "NOPE", names, &count, 1),
              IEC61850_MMS_DS_ERR_NOT_FOUND);

    ASSERT_EQ(iec61850_mms_ds_define_list(&ds, "NOPE", "L", NULL, 0),
              IEC61850_MMS_DS_ERR_NOT_FOUND);
    ASSERT_EQ(iec61850_mms_ds_delete_list(&ds, "NOPE", "L"),
              IEC61850_MMS_DS_ERR_NOT_FOUND);

    mms_variable_spec_t vars[1];
    uint32_t num = 0;
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(&ds, "NOPE", "L", vars, &num, 1),
              IEC61850_MMS_DS_ERR_NOT_FOUND);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_duplicate_variable(void)
{
    TEST("duplicate_variable");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 1;

    ASSERT_EQ(iec61850_mms_ds_create_variable(&ds, "IED1LD0", "dup_var",
              MMS_TYPE_INTEGER, &val), IEC61850_MMS_DS_OK);
    ASSERT_EQ(iec61850_mms_ds_create_variable(&ds, "IED1LD0", "dup_var",
              MMS_TYPE_INTEGER, &val), IEC61850_MMS_DS_ERR_EXISTS);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_create_variable_null_initial(void)
{
    TEST("create_variable_null_initial");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    ASSERT_EQ(iec61850_mms_ds_create_variable(&ds, "IED1LD0", "no_init",
              MMS_TYPE_BOOLEAN, NULL), IEC61850_MMS_DS_OK);

    mms_value_t read_val;
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "IED1LD0", "no_init", &read_val),
              IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)read_val.type, (int)MMS_TYPE_BOOLEAN);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_write_nonexistent_variable(void)
{
    TEST("write_nonexistent_variable");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    ASSERT_EQ(iec61850_mms_ds_write_variable(&ds, "IED1LD0", "no_such_var", &val),
              IEC61850_MMS_DS_ERR_NOT_FOUND);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_get_attrs_nonexistent(void)
{
    TEST("get_attrs_nonexistent");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_variable_access_attrs_t attrs;
    ASSERT_EQ(iec61850_mms_ds_get_variable_attrs(&ds, "IED1LD0", "nope", &attrs),
              IEC61850_MMS_DS_ERR_NOT_FOUND);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_get_var_names_truncation(void)
{
    TEST("get_var_names_truncation");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "a", MMS_TYPE_INTEGER, &val);
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "b", MMS_TYPE_INTEGER, &val);
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "c", MMS_TYPE_INTEGER, &val);

    /* max_count < var_count → truncation */
    char names[2][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    ASSERT_EQ(iec61850_mms_ds_get_var_names(&ds, "IED1LD0", names, &count, 2),
              IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)count, 2);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_duplicate_named_list(void)
{
    TEST("duplicate_named_list");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    ASSERT_EQ(iec61850_mms_ds_define_list(&ds, "IED1LD0", "DS1", NULL, 0),
              IEC61850_MMS_DS_OK);
    ASSERT_EQ(iec61850_mms_ds_define_list(&ds, "IED1LD0", "DS1", NULL, 0),
              IEC61850_MMS_DS_ERR_EXISTS);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_delete_nonexistent_list(void)
{
    TEST("delete_nonexistent_list");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    ASSERT_EQ(iec61850_mms_ds_delete_list(&ds, "IED1LD0", "nope"),
              IEC61850_MMS_DS_ERR_NOT_FOUND);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_get_list_attrs_truncation(void)
{
    TEST("get_list_attrs_truncation");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_variable_spec_t vars[3];
    memset(vars, 0, sizeof(vars));
    strncpy(vars[0].item_id, "v1", MMS_MAX_VARIABLE_NAME - 1);
    strncpy(vars[1].item_id, "v2", MMS_MAX_VARIABLE_NAME - 1);
    strncpy(vars[2].item_id, "v3", MMS_MAX_VARIABLE_NAME - 1);

    iec61850_mms_ds_define_list(&ds, "IED1LD0", "BigList", vars, 3);

    /* max_variables < actual → truncation */
    mms_variable_spec_t out[2];
    uint32_t num = 0;
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(&ds, "IED1LD0", "BigList",
              out, &num, 2), IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)num, 2);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_get_list_attrs_nonexistent(void)
{
    TEST("get_list_attrs_nonexistent");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_variable_spec_t out[1];
    uint32_t num = 0;
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(&ds, "IED1LD0", "nope",
              out, &num, 1), IEC61850_MMS_DS_ERR_NOT_FOUND);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_define_list_empty_vars(void)
{
    TEST("define_list_empty_vars");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    /* Define list with NULL variables and 0 count */
    ASSERT_EQ(iec61850_mms_ds_define_list(&ds, "IED1LD0", "EmptyList", NULL, 0),
              IEC61850_MMS_DS_OK);

    mms_variable_spec_t out[1];
    uint32_t num = 99;
    ASSERT_EQ(iec61850_mms_ds_get_list_attrs(&ds, "IED1LD0", "EmptyList",
              out, &num, 1), IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)num, 0);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

/* ========================================================================
 * Concurrent Access (Thread Safety)
 * ======================================================================== */

typedef struct {
    iec61850_mms_data_store_t *ds;
    int thread_id;
    int iterations;
} thread_arg_t;

static void *writer_thread(void *arg)
{
    thread_arg_t *ta = (thread_arg_t *)arg;
    for (int i = 0; i < ta->iterations; i++) {
        mms_value_t val;
        memset(&val, 0, sizeof(val));
        val.type = MMS_TYPE_INTEGER;
        val.value.integer = (int32_t)(ta->thread_id * 1000 + i);
        iec61850_mms_ds_write_variable(ta->ds, "IED1LD0", "shared_var", &val);
    }
    return NULL;
}

static void *reader_thread(void *arg)
{
    thread_arg_t *ta = (thread_arg_t *)arg;
    for (int i = 0; i < ta->iterations; i++) {
        mms_value_t val;
        iec61850_mms_ds_read_variable(ta->ds, "IED1LD0", "shared_var", &val);
    }
    return NULL;
}

static void test_concurrent_read_write(void)
{
    TEST("concurrent_read_write");
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t initial;
    memset(&initial, 0, sizeof(initial));
    initial.type = MMS_TYPE_INTEGER;
    initial.value.integer = 0;
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "shared_var",
                                      MMS_TYPE_INTEGER, &initial);

    pthread_t threads[10];
    thread_arg_t args[10];

    for (int i = 0; i < 10; i++) {
        args[i].ds = &ds;
        args[i].thread_id = i;
        args[i].iterations = 100;
        if (i < 5) {
            pthread_create(&threads[i], NULL, writer_thread, &args[i]);
        } else {
            pthread_create(&threads[i], NULL, reader_thread, &args[i]);
        }
    }

    for (int i = 0; i < 10; i++) {
        pthread_join(threads[i], NULL);
    }

    /* If we get here without deadlock/crash, test passes */
    mms_value_t final_val;
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "IED1LD0", "shared_var",
              &final_val), IEC61850_MMS_DS_OK);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

int main(void)
{
    printf("\n=== MMS Data Store Tests ===\n");

    printf("\n--- Domain Management ---\n");
    test_create_domain();
    test_create_domain_idempotent();
    test_multiple_domains();

    printf("\n--- Variable CRUD ---\n");
    test_create_read_variable();
    test_write_variable();
    test_read_nonexistent_variable();
    test_variable_attrs();
    test_get_variable_names();

    printf("\n--- Named Variable Lists ---\n");
    test_define_named_list();
    test_delete_named_list();

    printf("\n--- NULL / Error Branches ---\n");
    test_null_args();
    test_nonexistent_domain_ops();
    test_duplicate_variable();
    test_create_variable_null_initial();
    test_write_nonexistent_variable();
    test_get_attrs_nonexistent();
    test_get_var_names_truncation();
    test_duplicate_named_list();
    test_delete_nonexistent_list();
    test_get_list_attrs_truncation();
    test_get_list_attrs_nonexistent();
    test_define_list_empty_vars();

    printf("\n--- Thread Safety ---\n");
    test_concurrent_read_write();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
