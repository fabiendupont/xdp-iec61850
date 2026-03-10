/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for Config Manager
 */

#define _POSIX_C_SOURCE 200809L

#include "config/config_manager.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Stub for iec61850_cli_parse (not implemented yet) */
int iec61850_cli_parse(int argc, char *argv[], iec61850_app_config_t *cfg)
{
    (void)argc; (void)argv; (void)cfg;
    return 0;
}

static const char *cli_config_file = NULL;
const char *iec61850_cli_get_config_file(void)
{
    return cli_config_file;
}

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

static void test_config_init_defaults(void)
{
    TEST("config_init_defaults");
    iec61850_app_config_t cfg;
    iec61850_app_config_init(&cfg);

    ASSERT_EQ((int)cfg.dpdk.memory_mb, 1024);
    ASSERT_EQ((int)cfg.logging.level, (int)IEC61850_LOG_INFO);
    ASSERT_EQ((int)cfg.metrics.export_interval_sec, 60);
    ASSERT_TRUE(cfg.scl.file[0] == '\0');
    ASSERT_TRUE(!cfg.security.enabled);

    /* NULL should not crash */
    iec61850_app_config_init(NULL);
    PASS();
}

static void test_config_free(void)
{
    TEST("config_free");
    iec61850_app_config_t cfg;
    iec61850_app_config_init(&cfg);
    iec61850_app_config_free(&cfg);
    iec61850_app_config_free(NULL);
    PASS();
}

static void test_parse_core_list_single(void)
{
    TEST("parse_core_list_single");
    unsigned cores[16] = {0};
    size_t count = 0;

    int ret = iec61850_parse_core_list("2,5,8", cores, 16, &count);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 3);
    ASSERT_EQ((int)cores[0], 2);
    ASSERT_EQ((int)cores[1], 5);
    ASSERT_EQ((int)cores[2], 8);
    PASS();
}

static void test_parse_core_list_range(void)
{
    TEST("parse_core_list_range");
    unsigned cores[16] = {0};
    size_t count = 0;

    int ret = iec61850_parse_core_list("2-4", cores, 16, &count);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 3);
    ASSERT_EQ((int)cores[0], 2);
    ASSERT_EQ((int)cores[1], 3);
    ASSERT_EQ((int)cores[2], 4);
    PASS();
}

static void test_parse_core_list_mixed(void)
{
    TEST("parse_core_list_mixed");
    unsigned cores[16] = {0};
    size_t count = 0;

    int ret = iec61850_parse_core_list("0,2-4,7", cores, 16, &count);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 5);
    ASSERT_EQ((int)cores[0], 0);
    ASSERT_EQ((int)cores[1], 2);
    ASSERT_EQ((int)cores[2], 3);
    ASSERT_EQ((int)cores[3], 4);
    ASSERT_EQ((int)cores[4], 7);
    PASS();
}

static void test_parse_core_list_null(void)
{
    TEST("parse_core_list_null");
    unsigned cores[16] = {0};
    size_t count = 0;

    ASSERT_EQ(iec61850_parse_core_list(NULL, cores, 16, &count), -1);
    ASSERT_EQ(iec61850_parse_core_list("1", NULL, 16, &count), -1);
    ASSERT_EQ(iec61850_parse_core_list("1", cores, 16, NULL), -1);
    PASS();
}

static void test_parse_pci_list(void)
{
    TEST("parse_pci_list");
    char pci[4][IEC61850_PCI_ADDR_LEN];
    size_t count = 0;

    int ret = iec61850_parse_pci_list("0000:01:00.0,0000:02:00.0",
                                        pci, 4, &count);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 2);
    ASSERT_TRUE(strcmp(pci[0], "0000:01:00.0") == 0);
    ASSERT_TRUE(strcmp(pci[1], "0000:02:00.0") == 0);
    PASS();
}

static void test_parse_pci_list_null(void)
{
    TEST("parse_pci_list_null");
    char pci[4][IEC61850_PCI_ADDR_LEN];
    size_t count = 0;

    ASSERT_EQ(iec61850_parse_pci_list(NULL, pci, 4, &count), -1);
    ASSERT_EQ(iec61850_parse_pci_list("x", NULL, 4, &count), -1);
    ASSERT_EQ(iec61850_parse_pci_list("x", pci, 4, NULL), -1);
    PASS();
}

static void test_parse_core_list_overflow(void)
{
    TEST("parse_core_list_overflow");
    unsigned cores[2] = {0};
    size_t count = 0;

    int ret = iec61850_parse_core_list("1,2,3,4,5", cores, 2, &count);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 2);
    PASS();
}

static void test_config_manager_load_null(void)
{
    TEST("config_manager_load_null");
    ASSERT_EQ(iec61850_config_manager_load(0, NULL, NULL), -1);
    PASS();
}

static void test_config_manager_load_no_yaml(void)
{
    TEST("config_manager_load_no_yaml");
    /* cli_config_file is NULL, so no YAML loaded — just defaults + CLI */
    iec61850_app_config_t cfg;
    cli_config_file = NULL;
    char *argv[] = { "test", NULL };
    int ret = iec61850_config_manager_load(1, argv, &cfg);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)cfg.dpdk.memory_mb, 1024);
    ASSERT_EQ((int)cfg.logging.level, (int)IEC61850_LOG_INFO);
    PASS();
}

static void test_config_manager_load_bad_yaml(void)
{
    TEST("config_manager_load_bad_yaml");
    iec61850_app_config_t cfg;
    cli_config_file = "/nonexistent/file.yml";
    char *argv[] = { "test", NULL };
    int ret = iec61850_config_manager_load(1, argv, &cfg);
    ASSERT_EQ(ret, -1);
    cli_config_file = NULL;
    PASS();
}

static void write_test_yaml(const char *path)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) { return; }
    fprintf(f,
        "scl:\n"
        "  file: /tmp/test.scd\n"
        "  ied: IED1\n"
        "  control_blocks:\n"
        "    - GoCB1\n"
        "    - GoCB2\n"
        "dpdk:\n"
        "  memory_mb: 2048\n"
        "  no_huge: true\n"
        "  file_prefix: test_prefix\n"
        "logging:\n"
        "  level: debug\n"
        "  output: /tmp/test.log\n"
        "  use_syslog: false\n"
        "metrics:\n"
        "  enabled: true\n"
        "  export_interval_sec: 30\n"
        "  output: /tmp/metrics.csv\n"
        "security:\n"
        "  enabled: true\n"
        "  private_key: /tmp/key.pem\n"
        "  certificate: /tmp/cert.pem\n"
        "  trusted_certs: /tmp/ca.pem\n");
    fclose(f);
}

static void test_config_manager_load_yaml(void)
{
    TEST("config_manager_load_yaml");

    char path[256];
    (void)snprintf(path, sizeof(path), "/tmp/iec61850_test_cfg_%d.yml",
                   (int)getpid());
    write_test_yaml(path);

    iec61850_app_config_t cfg;
    cli_config_file = path;
    char *argv[] = { "test", NULL };
    int ret = iec61850_config_manager_load(1, argv, &cfg);
    ASSERT_EQ(ret, 0);

    /* Verify YAML values were applied */
    ASSERT_TRUE(strcmp(cfg.scl.file, "/tmp/test.scd") == 0);
    ASSERT_TRUE(strcmp(cfg.scl.ied_name, "IED1") == 0);
    ASSERT_EQ((int)cfg.scl.control_blocks_count, 2);
    ASSERT_EQ((int)cfg.dpdk.memory_mb, 2048);
    ASSERT_TRUE(cfg.dpdk.no_huge);
    ASSERT_TRUE(strcmp(cfg.dpdk.file_prefix, "test_prefix") == 0);
    ASSERT_EQ((int)cfg.logging.level, (int)IEC61850_LOG_DEBUG);
    ASSERT_TRUE(strcmp(cfg.logging.output, "/tmp/test.log") == 0);
    ASSERT_TRUE(!cfg.logging.use_syslog);
    ASSERT_TRUE(cfg.metrics.enabled);
    ASSERT_EQ((int)cfg.metrics.export_interval_sec, 30);
    ASSERT_TRUE(strcmp(cfg.metrics.output, "/tmp/metrics.csv") == 0);
    ASSERT_TRUE(cfg.security.enabled);
    ASSERT_TRUE(strcmp(cfg.security.private_key, "/tmp/key.pem") == 0);
    ASSERT_TRUE(strcmp(cfg.security.certificate, "/tmp/cert.pem") == 0);
    ASSERT_TRUE(strcmp(cfg.security.trusted_certs, "/tmp/ca.pem") == 0);

    (void)unlink(path);
    cli_config_file = NULL;
    PASS();
}

int main(void)
{
    printf("=== Config Manager Tests ===\n");

    test_config_init_defaults();
    test_config_free();
    test_parse_core_list_single();
    test_parse_core_list_range();
    test_parse_core_list_mixed();
    test_parse_core_list_null();
    test_parse_pci_list();
    test_parse_pci_list_null();
    test_parse_core_list_overflow();
    test_config_manager_load_null();
    test_config_manager_load_no_yaml();
    test_config_manager_load_bad_yaml();
    test_config_manager_load_yaml();

    printf("\nTests: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
