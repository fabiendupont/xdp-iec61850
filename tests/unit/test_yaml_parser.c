/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for YAML Parser
 */


#include "config/yaml_parser.h"
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

static char test_yaml_path[256];

static void create_test_yaml(void)
{
    (void)snprintf(test_yaml_path, sizeof(test_yaml_path),
                    "/tmp/iec61850_yaml_test_%d.yml", (int)getpid());
    FILE *f = fopen(test_yaml_path, "w");
    if (f == NULL) { return; }
    fprintf(f,
        "# Test config\n"
        "scl:\n"
        "  file: /etc/iec61850/test.scd\n"
        "  ied: IED1\n"
        "  control_blocks:\n"
        "    - gcb01\n"
        "    - gcb02\n"
        "\n"
        "logging:\n"
        "  level: DEBUG\n"
        "  output: /var/log/iec61850.log\n"
        "  use_syslog: false\n"
        "\n"
        "dpdk:\n"
        "  memory_mb: 2048\n"
        "  no_huge: true\n"
        "  file_prefix: iec61850\n"
        "\n"
        "metrics:\n"
        "  enabled: yes\n"
        "  export_interval_sec: 30\n"
        "\n"
        "security:\n"
        "  enabled: true\n"
        "  private_key: /etc/iec61850/key.pem\n"
    );
    (void)fclose(f);
}

static void test_doc_init_free(void)
{
    TEST("doc_init_free");
    iec61850_yaml_doc_t doc;
    iec61850_yaml_doc_init(&doc);
    ASSERT_EQ((int)doc.count, 0);
    iec61850_yaml_doc_free(&doc);
    ASSERT_EQ((int)doc.count, 0);
    PASS();
}

static void test_parse_file(void)
{
    TEST("parse_file");
    iec61850_yaml_doc_t doc;
    iec61850_yaml_doc_init(&doc);

    int ret = iec61850_yaml_parse_file(test_yaml_path, &doc);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(doc.count > 0);

    iec61850_yaml_doc_free(&doc);
    PASS();
}

static void test_parse_nonexistent(void)
{
    TEST("parse_nonexistent");
    iec61850_yaml_doc_t doc;
    iec61850_yaml_doc_init(&doc);

    int ret = iec61850_yaml_parse_file("/nonexistent/file.yml", &doc);
    ASSERT_EQ(ret, -1);

    iec61850_yaml_doc_free(&doc);
    PASS();
}

static void test_parse_null(void)
{
    TEST("parse_null");
    iec61850_yaml_doc_t doc;
    iec61850_yaml_doc_init(&doc);

    ASSERT_EQ(iec61850_yaml_parse_file(NULL, &doc), -1);
    ASSERT_EQ(iec61850_yaml_parse_file(test_yaml_path, NULL), -1);
    PASS();
}

static void test_get_string(void)
{
    TEST("get_string");
    iec61850_yaml_doc_t doc;
    iec61850_yaml_doc_init(&doc);
    iec61850_yaml_parse_file(test_yaml_path, &doc);

    const char *val = iec61850_yaml_get_string(&doc, "scl.file");
    ASSERT_TRUE(val != NULL);
    ASSERT_TRUE(strcmp(val, "/etc/iec61850/test.scd") == 0);

    val = iec61850_yaml_get_string(&doc, "scl.ied");
    ASSERT_TRUE(val != NULL);
    ASSERT_TRUE(strcmp(val, "IED1") == 0);

    val = iec61850_yaml_get_string(&doc, "logging.level");
    ASSERT_TRUE(val != NULL);
    ASSERT_TRUE(strcmp(val, "DEBUG") == 0);

    /* Non-existent key returns default */
    val = iec61850_yaml_get_string(&doc, "nonexistent.key");
    val = (val != NULL) ? val : "fallback";
    ASSERT_TRUE(val != NULL);
    ASSERT_TRUE(strcmp(val, "fallback") == 0);

    iec61850_yaml_doc_free(&doc);
    PASS();
}

static void test_get_int(void)
{
    TEST("get_int");
    iec61850_yaml_doc_t doc;
    iec61850_yaml_doc_init(&doc);
    iec61850_yaml_parse_file(test_yaml_path, &doc);

    int val = iec61850_yaml_get_int(&doc, "dpdk.memory_mb", -1);
    ASSERT_EQ(val, 2048);

    val = iec61850_yaml_get_int(&doc, "metrics.export_interval_sec", -1);
    ASSERT_EQ(val, 30);

    /* Non-existent key */
    val = iec61850_yaml_get_int(&doc, "nonexistent", 42);
    ASSERT_EQ(val, 42);

    iec61850_yaml_doc_free(&doc);
    PASS();
}

static void test_get_bool(void)
{
    TEST("get_bool");
    iec61850_yaml_doc_t doc;
    iec61850_yaml_doc_init(&doc);
    iec61850_yaml_parse_file(test_yaml_path, &doc);

    bool val = iec61850_yaml_get_bool(&doc, "dpdk.no_huge", false);
    ASSERT_TRUE(val == true);

    val = iec61850_yaml_get_bool(&doc, "logging.use_syslog", true);
    ASSERT_TRUE(val == false);

    val = iec61850_yaml_get_bool(&doc, "metrics.enabled", false);
    ASSERT_TRUE(val == true);  /* "yes" */

    val = iec61850_yaml_get_bool(&doc, "security.enabled", false);
    ASSERT_TRUE(val == true);

    /* Non-existent key */
    val = iec61850_yaml_get_bool(&doc, "nonexistent", true);
    ASSERT_TRUE(val == true);

    iec61850_yaml_doc_free(&doc);
    PASS();
}

static void test_get_list(void)
{
    TEST("get_list");
    iec61850_yaml_doc_t doc;
    iec61850_yaml_doc_init(&doc);
    iec61850_yaml_parse_file(test_yaml_path, &doc);

    size_t count = 0;
    const char **list = iec61850_yaml_get_list(&doc, "scl.control_blocks", &count);
    ASSERT_TRUE(list != NULL);
    ASSERT_EQ((int)count, 2);
    ASSERT_TRUE(strcmp(list[0], "gcb01") == 0);
    ASSERT_TRUE(strcmp(list[1], "gcb02") == 0);

    /* Non-existent list */
    list = iec61850_yaml_get_list(&doc, "nonexistent", &count);
    ASSERT_TRUE(list == NULL);

    iec61850_yaml_doc_free(&doc);
    PASS();
}

static void test_get_string_empty_doc(void)
{
    TEST("get_string_empty_doc");
    iec61850_yaml_doc_t doc;
    iec61850_yaml_doc_init(&doc);
    /* Empty doc, key not found — should return default */
    const char *raw = iec61850_yaml_get_string(&doc, "nonexistent");
    const char *val = (raw != NULL) ? raw : "default";
    ASSERT_TRUE(val != NULL);
    ASSERT_TRUE(strcmp(val, "default") == 0);

    int ival = iec61850_yaml_get_int(&doc, "nonexistent", 99);
    ASSERT_EQ(ival, 99);

    bool bval = iec61850_yaml_get_bool(&doc, "nonexistent", true);
    ASSERT_TRUE(bval == true);

    iec61850_yaml_doc_free(&doc);
    PASS();
}

int main(void)
{
    printf("=== YAML Parser Tests ===\n");

    create_test_yaml();

    test_doc_init_free();
    test_parse_file();
    test_parse_nonexistent();
    test_parse_null();
    test_get_string();
    test_get_int();
    test_get_bool();
    test_get_list();
    test_get_string_empty_doc();

    (void)unlink(test_yaml_path);

    printf("\nTests: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
