/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: iec61850_graph — XDP graph registration
 *
 * Tests the IEC 61850 BPF node registration (GOOSE/SV filter+parse)
 * with dynamically allocated PROG_ARRAY indices and EtherType dispatch.
 *
 * Requires: root (CAP_BPF + CAP_NET_ADMIN).
 * Requires: BPF .bpf.o files built (custom_target in meson).
 * Skips gracefully when not root or BPF objects not found.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "iec61850_graph.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <xgl/xgl_graph.h>

#ifndef BPF_OBJ_DIR
#define BPF_OBJ_DIR "."
#endif

#ifndef IEC61850_BPF_DIR
#define IEC61850_BPF_DIR "."
#endif

static int tests_run;
static int tests_passed;
static int tests_skipped;
static int tests_failed;

#define TEST(name) do { tests_run++; printf("  [TEST] %-50s ", name); } while (0)
#define PASS()     do { tests_passed++; printf("PASS\n"); } while (0)
#define SKIP(msg)  do { tests_skipped++; printf("SKIP: %s\n", msg); return; } while (0)
#define FAIL(msg)  do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)

#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); } } while (0)
#define ASSERT_EQ(a, b)   do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)
#define ASSERT_GE(a, b)   do { if ((a) < (b)) { \
    printf("FAIL: %s >= %s (%d < %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

static int is_root;
static int has_dispatch;
static int has_iec_bpf;
static char dispatch_path[1024];
static char iec_bpf_dir[1024];

static void check_prerequisites(void)
{
    is_root = (geteuid() == 0);

    snprintf(dispatch_path, sizeof(dispatch_path),
             "%s/subprojects/xdp-graph-lib/xgl_dispatch.bpf.o", BPF_OBJ_DIR);
    has_dispatch = (access(dispatch_path, R_OK) == 0);

    snprintf(iec_bpf_dir, sizeof(iec_bpf_dir), "%s", IEC61850_BPF_DIR);
    char check[1024];
    snprintf(check, sizeof(check), "%s/node_goose_filter.bpf.o", iec_bpf_dir);
    has_iec_bpf = (access(check, R_OK) == 0);
}

/* ===== Error path tests (no root needed) ===== */

static void test_register_null_args(void)
{
    TEST("graph_register_null_args");
    ASSERT_TRUE(iec61850_graph_register(NULL, "/tmp", NULL) < 0);
    PASS();
}

static void test_dispatch_null_args(void)
{
    TEST("graph_setup_dispatch_invalid_args");
    struct iec61850_graph_indices idx = { .goose_filter = 1, .sv_filter = 2 };
    ASSERT_TRUE(iec61850_graph_setup_dispatch(-1, &idx) < 0);
    ASSERT_TRUE(iec61850_graph_setup_dispatch(0, NULL) < 0);
    PASS();
}

/* ===== Privileged tests ===== */

static void test_graph_register_nodes(void)
{
    TEST("graph_register_dynamic_indices");
    if (!is_root) { SKIP("not root"); }
    if (!has_dispatch) { SKIP("xgl_dispatch.bpf.o not found"); }
    if (!has_iec_bpf) { SKIP("IEC 61850 .bpf.o not found"); }

    struct xgl_graph *g = xgl_graph_create("iec61850-test", 0);
    ASSERT_TRUE(g != NULL);

    /* Load dispatch node first (creates PROG_ARRAY) */
    int ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        printf("SKIP: dispatch add_node failed (%d: %s)\n", ret, strerror(-ret));
        tests_skipped++;
        xgl_graph_destroy(g);
        return;
    }

    /* Register IEC 61850 nodes with dynamic index allocation */
    struct iec61850_graph_indices indices;
    ret = iec61850_graph_register(g, iec_bpf_dir, &indices);
    ASSERT_EQ(ret, 0);

    /* Indices must be valid (>= 0) and distinct */
    ASSERT_GE(indices.goose_filter, 0);
    ASSERT_GE(indices.goose_parse, 0);
    ASSERT_GE(indices.sv_filter, 0);
    ASSERT_GE(indices.sv_parse, 0);
    ASSERT_TRUE(indices.goose_filter != indices.goose_parse);
    ASSERT_TRUE(indices.goose_filter != indices.sv_filter);
    ASSERT_TRUE(indices.goose_filter != indices.sv_parse);

    /* Verify nodes are in PROG_ARRAY by looking up their indices */
    int pa_fd = xgl_graph_get_prog_array_fd(g);
    ASSERT_GE(pa_fd, 0);

    __u32 key;
    __u32 val;

    key = (__u32)indices.goose_filter;
    ASSERT_EQ(bpf_map_lookup_elem(pa_fd, &key, &val), 0);

    key = (__u32)indices.goose_parse;
    ASSERT_EQ(bpf_map_lookup_elem(pa_fd, &key, &val), 0);

    key = (__u32)indices.sv_filter;
    ASSERT_EQ(bpf_map_lookup_elem(pa_fd, &key, &val), 0);

    key = (__u32)indices.sv_parse;
    ASSERT_EQ(bpf_map_lookup_elem(pa_fd, &key, &val), 0);

    xgl_graph_destroy(g);
    PASS();
}

static void test_graph_register_bad_dir(void)
{
    TEST("graph_register_nonexistent_dir");
    if (!is_root) { SKIP("not root"); }
    if (!has_dispatch) { SKIP("xgl_dispatch.bpf.o not found"); }

    struct xgl_graph *g = xgl_graph_create("iec61850-baddir", 0);
    ASSERT_TRUE(g != NULL);

    int ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        tests_skipped++;
        printf("SKIP: dispatch failed\n");
        xgl_graph_destroy(g);
        return;
    }

    /* Register with nonexistent directory should fail */
    ret = iec61850_graph_register(g, "/nonexistent/path/to/bpf", NULL);
    ASSERT_TRUE(ret != 0);

    xgl_graph_destroy(g);
    PASS();
}

static void test_setup_dispatch_map(void)
{
    TEST("graph_setup_dispatch_map");
    if (!is_root) { SKIP("not root"); }
    if (!has_dispatch) { SKIP("xgl_dispatch.bpf.o not found"); }
    if (!has_iec_bpf) { SKIP("IEC 61850 .bpf.o not found"); }

    struct xgl_graph *g = xgl_graph_create("iec61850-dispatch", 0);
    ASSERT_TRUE(g != NULL);

    int ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        tests_skipped++;
        printf("SKIP: dispatch failed\n");
        xgl_graph_destroy(g);
        return;
    }

    /* Register IEC 61850 nodes to get dynamic indices */
    struct iec61850_graph_indices indices;
    ret = iec61850_graph_register(g, iec_bpf_dir, &indices);
    ASSERT_EQ(ret, 0);

    /* Get dispatch map fd */
    int dispatch_fd = xgl_graph_get_map_fd(g, "xgl_ext_dispatch");
    if (dispatch_fd < 0) {
        dispatch_fd = xgl_graph_get_map_fd(g, "ext_dispatch");
    }
    ASSERT_GE(dispatch_fd, 0);

    /* Set up dispatch with allocated indices */
    ret = iec61850_graph_setup_dispatch(dispatch_fd, &indices);
    ASSERT_EQ(ret, 0);

    /* Verify GOOSE EtherType 0x88B8 maps to the allocated index */
    uint16_t key = 0x88B8U;
    uint32_t val = 0;
    ASSERT_EQ(bpf_map_lookup_elem(dispatch_fd, &key, &val), 0);
    ASSERT_EQ((int)val, indices.goose_filter);

    /* Verify SV EtherType 0x88BA maps to the allocated index */
    key = 0x88BAU;
    val = 0;
    ASSERT_EQ(bpf_map_lookup_elem(dispatch_fd, &key, &val), 0);
    ASSERT_EQ((int)val, indices.sv_filter);

    xgl_graph_destroy(g);
    PASS();
}

static void test_get_filter_map_fd(void)
{
    TEST("graph_get_filter_map_fd");
    if (!is_root) { SKIP("not root"); }
    if (!has_dispatch) { SKIP("xgl_dispatch.bpf.o not found"); }
    if (!has_iec_bpf) { SKIP("IEC 61850 .bpf.o not found"); }

    struct xgl_graph *g = xgl_graph_create("iec61850-filter", 0);
    ASSERT_TRUE(g != NULL);

    int ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        tests_skipped++;
        printf("SKIP: dispatch failed\n");
        xgl_graph_destroy(g);
        return;
    }

    struct iec61850_graph_indices indices;
    ret = iec61850_graph_register(g, iec_bpf_dir, &indices);
    ASSERT_EQ(ret, 0);

    /* GOOSE and SV filter maps should be retrievable */
    int goose_fd = iec61850_graph_get_filter_map_fd(g, "goose_filter");
    ASSERT_GE(goose_fd, 0);

    int sv_fd = iec61850_graph_get_filter_map_fd(g, "sv_filter");
    ASSERT_GE(sv_fd, 0);

    /* Populate a filter entry and verify */
    uint16_t appid = 0x1000U;
    uint8_t action = 1;
    ASSERT_EQ(bpf_map_update_elem(goose_fd, &appid, &action, BPF_ANY), 0);

    uint8_t readback = 0;
    ASSERT_EQ(bpf_map_lookup_elem(goose_fd, &appid, &readback), 0);
    ASSERT_EQ((int)readback, 1);

    /* Invalid map name returns error */
    ASSERT_TRUE(iec61850_graph_get_filter_map_fd(g, "nonexistent") < 0);

    /* NULL args return error */
    ASSERT_TRUE(iec61850_graph_get_filter_map_fd(NULL, "goose_filter") < 0);
    ASSERT_TRUE(iec61850_graph_get_filter_map_fd(g, NULL) < 0);

    xgl_graph_destroy(g);
    PASS();
}

static void test_full_pipeline(void)
{
    TEST("graph_full_iec61850_pipeline");
    if (!is_root) { SKIP("not root"); }
    if (!has_dispatch) { SKIP("xgl_dispatch.bpf.o not found"); }
    if (!has_iec_bpf) { SKIP("IEC 61850 .bpf.o not found"); }

    struct xgl_graph *g = xgl_graph_create("iec61850-full", 0);
    ASSERT_TRUE(g != NULL);

    /* Load dispatch */
    int ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        tests_skipped++;
        printf("SKIP: dispatch failed (%d)\n", ret);
        xgl_graph_destroy(g);
        return;
    }

    /* Register all IEC 61850 nodes */
    struct iec61850_graph_indices indices;
    ret = iec61850_graph_register(g, iec_bpf_dir, &indices);
    ASSERT_EQ(ret, 0);

    /* Get dispatch map and set up EtherType routing */
    int dispatch_fd = xgl_graph_get_map_fd(g, "xgl_ext_dispatch");
    if (dispatch_fd < 0) {
        dispatch_fd = xgl_graph_get_map_fd(g, "ext_dispatch");
    }
    if (dispatch_fd >= 0) {
        ret = iec61850_graph_setup_dispatch(dispatch_fd, &indices);
        ASSERT_EQ(ret, 0);
    }

    /* Add edges: dispatch → GOOSE filter → GOOSE parse */
    ret = xgl_graph_add_edge(g, 0, indices.goose_filter);
    if (ret == 0) {
        (void)xgl_graph_add_edge(g, indices.goose_filter,
                                  indices.goose_parse);
    }

    /* Add edges: dispatch → SV filter → SV parse */
    ret = xgl_graph_add_edge(g, 0, indices.sv_filter);
    if (ret == 0) {
        (void)xgl_graph_add_edge(g, indices.sv_filter,
                                  indices.sv_parse);
    }

    /* Validate DAG */
    ret = xgl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0);

    /* Stats should be accessible */
    int stats_fd = xgl_graph_get_stats_map_fd(g);
    ASSERT_GE(stats_fd, 0);

    xgl_graph_destroy(g);
    PASS();
}

int main(void)
{
    check_prerequisites();

    printf("=== IEC 61850 XDP Graph Integration Tests ===\n");
    if (!is_root) {
        printf("  (not running as root — privileged tests will skip)\n");
    }
    if (!has_dispatch) {
        printf("  (xgl_dispatch.bpf.o not found at %s)\n", dispatch_path);
    }
    if (!has_iec_bpf) {
        printf("  (IEC 61850 .bpf.o not found at %s)\n", iec_bpf_dir);
    }

    test_register_null_args();
    test_dispatch_null_args();
    test_graph_register_nodes();
    test_graph_register_bad_dir();
    test_setup_dispatch_map();
    test_get_filter_map_fd();
    test_full_pipeline();

    printf("\n%d/%d passed, %d skipped, %d failed\n",
           tests_passed, tests_run, tests_skipped, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
