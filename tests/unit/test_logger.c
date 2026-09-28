/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for Logger
 */


#include "logging/logger.h"
#include <stdio.h>
#include <string.h>
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

static void test_level_set_get(void)
{
    TEST("level_set_get");
    iec61850_logger_set_level(IEC61850_LOG_DEBUG);
    ASSERT_EQ((int)iec61850_logger_get_level(), (int)IEC61850_LOG_DEBUG);
    iec61850_logger_set_level(IEC61850_LOG_ERROR);
    ASSERT_EQ((int)iec61850_logger_get_level(), (int)IEC61850_LOG_ERROR);
    iec61850_logger_close();
    PASS();
}

static void test_is_enabled(void)
{
    TEST("is_enabled");
    iec61850_logger_set_level(IEC61850_LOG_WARNING);
    ASSERT_TRUE(!iec61850_logger_is_enabled(IEC61850_LOG_DEBUG));
    ASSERT_TRUE(!iec61850_logger_is_enabled(IEC61850_LOG_INFO));
    ASSERT_TRUE(iec61850_logger_is_enabled(IEC61850_LOG_WARNING));
    ASSERT_TRUE(iec61850_logger_is_enabled(IEC61850_LOG_ERROR));
    ASSERT_TRUE(iec61850_logger_is_enabled(IEC61850_LOG_CRITICAL));
    iec61850_logger_close();
    PASS();
}

static void test_level_to_string(void)
{
    TEST("level_to_string");
    ASSERT_TRUE(strcmp(iec61850_log_level_to_string(IEC61850_LOG_TRACE), "TRACE") == 0);
    ASSERT_TRUE(strcmp(iec61850_log_level_to_string(IEC61850_LOG_DEBUG), "DEBUG") == 0);
    ASSERT_TRUE(strcmp(iec61850_log_level_to_string(IEC61850_LOG_INFO), "INFO") == 0);
    ASSERT_TRUE(strcmp(iec61850_log_level_to_string(IEC61850_LOG_WARNING), "WARNING") == 0);
    ASSERT_TRUE(strcmp(iec61850_log_level_to_string(IEC61850_LOG_ERROR), "ERROR") == 0);
    ASSERT_TRUE(strcmp(iec61850_log_level_to_string(IEC61850_LOG_CRITICAL), "CRITICAL") == 0);
    ASSERT_TRUE(strcmp(iec61850_log_level_to_string((iec61850_log_level_t)99), "UNKNOWN") == 0);
    PASS();
}

static void test_level_from_string(void)
{
    TEST("level_from_string");
    ASSERT_EQ((int)iec61850_log_level_from_string("trace"), (int)IEC61850_LOG_TRACE);
    ASSERT_EQ((int)iec61850_log_level_from_string("DEBUG"), (int)IEC61850_LOG_DEBUG);
    ASSERT_EQ((int)iec61850_log_level_from_string("Info"), (int)IEC61850_LOG_INFO);
    ASSERT_EQ((int)iec61850_log_level_from_string("WARNING"), (int)IEC61850_LOG_WARNING);
    ASSERT_EQ((int)iec61850_log_level_from_string("error"), (int)IEC61850_LOG_ERROR);
    ASSERT_EQ((int)iec61850_log_level_from_string("CRITICAL"), (int)IEC61850_LOG_CRITICAL);
    ASSERT_EQ((int)iec61850_log_level_from_string("bogus"), (int)IEC61850_LOG_INFO);
    ASSERT_EQ((int)iec61850_log_level_from_string(NULL), (int)IEC61850_LOG_INFO);
    PASS();
}

static void test_open_file(void)
{
    TEST("open_file");
    char path[256];
    (void)snprintf(path, sizeof(path), "/tmp/iec61850_log_test_%d.log", (int)getpid());

    int ret = iec61850_logger_open_file(path);
    ASSERT_EQ(ret, 0);

    /* Log a message — should appear in the file */
    iec61850_logger_set_level(IEC61850_LOG_TRACE);
    iec61850_logger_log(IEC61850_LOG_INFO, "TEST", "hello from test");

    iec61850_logger_close();

    /* Verify file was written */
    FILE *f = fopen(path, "r");
    ASSERT_TRUE(f != NULL);
    char buf[1024] = {0};
    (void)fgets(buf, sizeof(buf), f);
    (void)fclose(f);
    ASSERT_TRUE(strstr(buf, "hello from test") != NULL);
    ASSERT_TRUE(strstr(buf, "TEST") != NULL);

    (void)unlink(path);
    PASS();
}

static void test_open_file_null(void)
{
    TEST("open_file_null");
    ASSERT_EQ(iec61850_logger_open_file(NULL), -1);
    PASS();
}

static void test_log_filtering(void)
{
    TEST("log_filtering");
    char path[256];
    (void)snprintf(path, sizeof(path), "/tmp/iec61850_log_filt_%d.log", (int)getpid());

    iec61850_logger_set_level(IEC61850_LOG_ERROR);
    int ret = iec61850_logger_open_file(path);
    ASSERT_EQ(ret, 0);

    /* This should be filtered out (INFO < ERROR) */
    iec61850_logger_log(IEC61850_LOG_INFO, "TEST", "should not appear");
    /* This should appear */
    iec61850_logger_log(IEC61850_LOG_ERROR, "TEST", "should appear");

    iec61850_logger_close();

    FILE *f = fopen(path, "r");
    ASSERT_TRUE(f != NULL);
    char buf[2048] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    (void)fclose(f);
    buf[n] = '\0';

    ASSERT_TRUE(strstr(buf, "should not appear") == NULL);
    ASSERT_TRUE(strstr(buf, "should appear") != NULL);

    (void)unlink(path);
    PASS();
}

static void test_log_null_component(void)
{
    TEST("log_null_component");
    /* Should not crash — uses "UNKNOWN" as component */
    iec61850_logger_set_level(IEC61850_LOG_TRACE);
    iec61850_logger_log(IEC61850_LOG_INFO, NULL, "null component");
    iec61850_logger_log(IEC61850_LOG_INFO, "TEST", NULL);
    iec61850_logger_close();
    PASS();
}

static void test_close_resets(void)
{
    TEST("close_resets");
    iec61850_logger_set_level(IEC61850_LOG_CRITICAL);
    iec61850_logger_close();
    /* close should reset level to INFO */
    ASSERT_EQ((int)iec61850_logger_get_level(), (int)IEC61850_LOG_INFO);
    PASS();
}

int main(void)
{
    printf("=== Logger Tests ===\n");

    test_level_set_get();
    test_is_enabled();
    test_level_to_string();
    test_level_from_string();
    test_open_file();
    test_open_file_null();
    test_log_filtering();
    test_log_null_component();
    test_close_resets();

    printf("\nTests: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
