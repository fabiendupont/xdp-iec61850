/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the Model-Driven Publishing Binding (WP-6d)
 *
 * Covers the frozen contract in include/iec61850/ied/model_binding.h:
 *   - init/destroy lifecycle (NULL args, double init/destroy),
 *   - reference resolution (valid refs bind; any bad component —
 *     ld/ln/do/da/fc — yields -ENOENT with NOTHING bound),
 *   - GOOSE fan-out over an LN-class-library model (XCBR + MMXU),
 *     verifying dataset contents (pub->data[]), stNum/sqNum and
 *     the publish count,
 *   - multi-publisher fan-out (one DA change dirties both),
 *   - SV binding (samples + quality channels),
 *   - coexistence with a pre-registered DA-change listener and
 *     the MMS variable-binding write path.
 *
 * MMS note: the MMS data store (iec61850_mms_ds_write_variable)
 * is a registration-time SNAPSHOT of the DA values
 * (iec61850_mms_ds_create_variable copies *initial_value), so
 * data-store writes never reach the model's DAs. The live MMS
 * write path into the model is the variable binding manager
 * (iec61850_binding_on_mms_write -> iec61850_da_set_value ->
 * change callbacks) — that is the MMS path exercised here.
 *
 * This test links MMS-gated objects (mms_variable_binding.c) and
 * is registered in tests/meson.build under `if mms_enabled` —
 * the WP-6d verification configuration.
 */

#include "ied/model_binding.h"
#include "ied/ln_schema.h"
#include "mms/mms_variable_binding.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* ========================================================================
 * Mock packet I/O (counts published frames)
 * ======================================================================== */

static uint32_t g_frames_sent;

static int mock_send(struct packet_io *io, const void *pkt, uint32_t len)
{
    (void)io;
    (void)pkt;
    (void)len;
    g_frames_sent++;
    return 0;
}

static const struct packet_io_ops mock_io_ops = {
    .send = mock_send,
};

static struct packet_io mock_io = {
    .ops = &mock_io_ops,
};

/* ========================================================================
 * Helpers
 * ======================================================================== */

/* Pre-registered DA-change listener (the MMS-side observer the
 * binding must coexist with and chain below its trampoline). */
static uint32_t g_listener_calls;

static void mms_side_listener(const mms_value_t *old_val,
                               const mms_value_t *new_val,
                               void *user_data)
{
    (void)old_val;
    (void)new_val;
    (void)user_data;
    g_listener_calls++;
}

static void wr_float(iec61850_data_attribute_t *da, float value)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_FLOATING_POINT;
    v.value.floating_point = value;
    iec61850_da_set_value(da, &v);
}

static void wr_bitstring(iec61850_data_attribute_t *da,
                          const uint8_t *data, size_t bit_count)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BIT_STRING;
    v.value.bit_string.bit_count = bit_count;
    (void)memcpy(v.value.bit_string.data, data,
                 (bit_count + 7U) / 8U);
    iec61850_da_set_value(da, &v);
}

/* Build the LN-class-library fan-out model: LD0 with XCBR1 (M DOs
 * incl. DPC Pos) and MMXU1 (M DOs + optional MV TotW). Returns
 * the XCBR and MMXU LNs through the out-params. */
static void build_ln_class_model(iec61850_ied_model_t *model,
                                  iec61850_logical_node_t **xcbr,
                                  iec61850_logical_node_t **mmxu)
{
    iec61850_logical_device_t *ld;

    iec61850_ied_model_init(model, "IED1");
    ld = iec61850_ld_create("LD0");
    ASSERT_EQ(iec61850_ied_model_add_ld(model, ld), 0);

    *xcbr = iec61850_ied_model_add_ln_class(model, "LD0", "XCBR", "1", "");
    ASSERT_TRUE(*xcbr != NULL);
    *mmxu = iec61850_ied_model_add_ln_class(model, "LD0", "MMXU", "1", "");
    ASSERT_TRUE(*mmxu != NULL);
    ASSERT_EQ(iec61850_ln_add_ln_class_do(*mmxu, "MMXU", "TotW"), 0);
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

static void test_lifecycle(void)
{
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;

    TEST("lifecycle");

    iec61850_ied_model_init(&model, "IED1");

    /* NULL args */
    ASSERT_EQ(iec61850_model_binding_init(NULL, &model), -EINVAL);
    ASSERT_EQ(iec61850_model_binding_init(&b, NULL), -EINVAL);

    /* First init on a zeroed struct succeeds */
    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);
    ASSERT_TRUE(b.initialized);
    ASSERT_TRUE(b.model == &model);
    ASSERT_EQ((int)b.publisher_count, 0);
    ASSERT_EQ((int)b.watch_count, 0);

    /* Nothing bound: process is a no-op */
    ASSERT_EQ(iec61850_model_binding_process(&b), 0);

    /* Double init rejected (would leak the registered watches) */
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), -EALREADY);

    /* process NULL */
    ASSERT_EQ(iec61850_model_binding_process(NULL), -EINVAL);

    /* Destroy is idempotent; NULL is ignored */
    iec61850_model_binding_destroy(&b);
    ASSERT_TRUE(!b.initialized);
    iec61850_model_binding_destroy(&b);
    iec61850_model_binding_destroy(NULL);

    /* Re-init after destroy works (struct was zeroed) */
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);
    iec61850_model_binding_destroy(&b);

    PASS();
}

/* ========================================================================
 * Argument validation and reference resolution
 * ======================================================================== */

static void test_ref_resolution(void)
{
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_logical_device_t *ld;
    iec61850_logical_node_t *ln;
    iec61850_data_object_t *bsc;

    /* One good ref (plain model API: ln_inst holds the bare inst,
     * so the LN matches by combined class+inst "XCBR1"). */
    const iec61850_da_ref_t good = {
        .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
        .da_name = "stVal", .fc = IEC61850_FC_ST,
    };
    const iec61850_da_ref_t bad_ld = {
        .ld = "LD9", .ln = "XCBR1", .do_name = "Pos",
        .da_name = "stVal", .fc = IEC61850_FC_ST,
    };
    const iec61850_da_ref_t bad_ln = {
        .ld = "LD0", .ln = "XCBR9", .do_name = "Pos",
        .da_name = "stVal", .fc = IEC61850_FC_ST,
    };
    const iec61850_da_ref_t bad_do = {
        .ld = "LD0", .ln = "XCBR1", .do_name = "Pox",
        .da_name = "stVal", .fc = IEC61850_FC_ST,
    };
    const iec61850_da_ref_t bad_da = {
        .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
        .da_name = "stVa", .fc = IEC61850_FC_ST,
    };
    const iec61850_da_ref_t bad_fc = {
        .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
        .da_name = "stVal", .fc = IEC61850_FC_MX,
    };
    const iec61850_da_ref_t struct_ref = {
        .ld = "LD0", .ln = "XCBR1", .do_name = "Bsc",
        .da_name = "valWTr", .fc = IEC61850_FC_ST,
    };
    iec61850_da_ref_t many[IEC61850_BINDING_MAX_REFS + 1U];

    TEST("ref_resolution");

    iec61850_ied_model_init(&model, "IED1");
    ld = iec61850_ld_create("LD0");
    ASSERT_EQ(iec61850_ied_model_add_ld(&model, ld), 0);
    ln = iec61850_ln_create("XCBR", "1");
    ASSERT_TRUE(ln != NULL);
    ASSERT_EQ(iec61850_ld_add_logical_node(ld, ln), 0);
    ASSERT_EQ(iec61850_ln_add_data_object(ln, iec61850_cdc_create_dpc("Pos")), 0);
    bsc = iec61850_cdc_create_bsc("Bsc");
    ASSERT_TRUE(bsc != NULL);
    ASSERT_EQ(iec61850_ln_add_data_object(ln, bsc), 0);

    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);

    /* Argument validation */
    ASSERT_EQ(iec61850_model_binding_add_goose(NULL, NULL, &good, 1U), -EINVAL);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, NULL, &good, 1U), -EINVAL);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)1,
                                                NULL, 1U), -EINVAL);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)1,
                                                &good, 0U), -EINVAL);
    ASSERT_EQ(iec61850_model_binding_add_sv(&b, NULL, &good, 1U), -EINVAL);
    ASSERT_EQ((int)b.publisher_count, 0);

    /* Ref count beyond the dataset capacity */
    (void)memset(&many, 0, sizeof(many));
    for (uint32_t i = 0U; i <= (uint32_t)IEC61850_BINDING_MAX_REFS; i++) {
        many[i] = good;
    }
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)1,
                                                many,
                                                IEC61850_BINDING_MAX_REFS + 1U),
               -ENOSPC);
    ASSERT_EQ((int)b.publisher_count, 0);

    /* Valid ref binds (slot 0) */
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)1,
                                                &good, 1U), 0);
    ASSERT_EQ((int)b.publisher_count, 1);
    ASSERT_EQ((int)b.watch_count, 1);
    ASSERT_EQ((int)b.publishers[0].ref_count, 1);
    ASSERT_TRUE(b.publishers[0].resolved[0] != NULL);

    /* Every bad component: -ENOENT with NOTHING bound */
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)2,
                                                &bad_ld, 1U), -ENOENT);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)2,
                                                &bad_ln, 1U), -ENOENT);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)2,
                                                &bad_do, 1U), -ENOENT);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)2,
                                                &bad_da, 1U), -ENOENT);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)2,
                                                &bad_fc, 1U), -ENOENT);
    ASSERT_EQ((int)b.publisher_count, 1);
    ASSERT_EQ((int)b.watch_count, 1);

    /* Nothing dirty from the failed adds: process is a no-op */
    ASSERT_EQ(iec61850_model_binding_process(&b), 0);

    /* Struct-typed DA resolves but has no scalar mapping */
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)2,
                                                &struct_ref, 1U), -ENOTSUP);
    ASSERT_EQ((int)b.publisher_count, 1);

    /* The next good bind lands on slot 1 (failures bound nothing) */
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, (iec61850_goose_publisher_t *)2,
                                                &good, 1U), 1);
    ASSERT_EQ((int)b.publisher_count, 2);
    /* The same DA again shares the existing watch */
    ASSERT_EQ((int)b.watch_count, 1);

    /* Add before init is rejected */
    {
        iec61850_model_binding_t b2;
        (void)memset(&b2, 0, sizeof(b2));
        ASSERT_EQ(iec61850_model_binding_add_goose(&b2,
                                                    (iec61850_goose_publisher_t *)1,
                                                    &good, 1U), -EINVAL);
    }

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * GOOSE fan-out (LN class library model)
 * ======================================================================== */

static void test_goose_fanout(void)
{
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_logical_node_t *xcbr;
    iec61850_logical_node_t *mmxu;
    iec61850_data_attribute_t *stval;
    iec61850_data_attribute_t *q;
    iec61850_data_attribute_t *mag;
    iec61850_goose_publisher_t pub;
    uint32_t st_num_before;

    const iec61850_da_ref_t refs[3] = {
        { .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
          .da_name = "stVal", .fc = IEC61850_FC_ST },
        { .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
          .da_name = "q", .fc = IEC61850_FC_ST },
        { .ld = "LD0", .ln = "MMXU1", .do_name = "TotW",
          .da_name = "mag", .fc = IEC61850_FC_MX },
    };
    const uint8_t dbpos_on[1] = { 0x80 };      /* bit0 set, 2 bits */
    const uint8_t quality_bad[2] = { 0xC0, 0x80 }; /* validity=3, bit8 */

    TEST("goose_fanout_ln_class_model");

    build_ln_class_model(&model, &xcbr, &mmxu);
    if (tests_failed > 0) { return; }

    /* Direct DA pointers for model writes */
    stval = iec61850_ln_find_attribute(xcbr, "Pos.stVal", IEC61850_FC_ST);
    q = iec61850_ln_find_attribute(xcbr, "Pos.q", IEC61850_FC_ST);
    mag = iec61850_ln_find_attribute(mmxu, "TotW.mag", IEC61850_FC_MX);
    ASSERT_TRUE(stval != NULL);
    ASSERT_TRUE(q != NULL);
    ASSERT_TRUE(mag != NULL);

    iec61850_goose_publisher_init(&pub, NULL);
    iec61850_goose_publisher_set_io(&pub, &mock_io);
    g_frames_sent = 0U;

    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, &pub, refs, 3U), 0);
    ASSERT_EQ((int)b.watch_count, 3);

    /* Baseline: nothing published, empty dataset */
    ASSERT_EQ((int)pub.data_count, 0);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub), 0U);

    /* One DA change (direct model write) dirties the publisher and
     * updates the mapped slot on the change path... */
    wr_bitstring(stval, dbpos_on, 2U);
    ASSERT_TRUE(b.publishers[0].dirty);
    ASSERT_EQ((int)pub.data_count, 1);
    ASSERT_EQ((int)pub.data[0].type, (int)GOOSE_DATA_BITSTRING);
    ASSERT_EQ((int)pub.byte_storage[0].data[0], 0x80);
    ASSERT_EQ((int)pub.byte_storage[0].len, 1);

    /* ...process pushes ALL mapped slots (dataset snapshot) and
     * publishes with state-change semantics. */
    ASSERT_EQ(iec61850_model_binding_process(&b), 1);
    ASSERT_TRUE(!b.publishers[0].dirty);
    ASSERT_EQ(g_frames_sent, 1U);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub), 1U);
    ASSERT_EQ(iec61850_goose_publisher_get_sq_num(&pub), 1U);
    ASSERT_EQ((int)pub.data_count, 3);
    ASSERT_EQ((int)pub.data[1].type, (int)GOOSE_DATA_BITSTRING);
    ASSERT_EQ((int)pub.data[2].type, (int)GOOSE_DATA_FLOAT32);

    /* Idempotent: no change, no publish */
    ASSERT_EQ(iec61850_model_binding_process(&b), 0);
    ASSERT_EQ(g_frames_sent, 1U);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub), 1U);

    /* Two more DA changes coalesce into one publish (stNum++ once),
     * and the snapshot carries both new values. */
    wr_float(mag, 1234.5f);
    wr_bitstring(q, quality_bad, 13U);
    ASSERT_TRUE(b.publishers[0].dirty);
    st_num_before = iec61850_goose_publisher_get_st_num(&pub);
    ASSERT_EQ(iec61850_model_binding_process(&b), 1);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub), st_num_before + 1U);
    ASSERT_EQ(g_frames_sent, 2U);
    ASSERT_EQ((int)pub.data[1].type, (int)GOOSE_DATA_BITSTRING);
    ASSERT_EQ((int)pub.byte_storage[1].data[0], 0xC0);
    ASSERT_EQ((int)pub.byte_storage[1].len, 2);
    ASSERT_TRUE(pub.data[2].value.float32 == 1234.5f);

    /* Unpublishable publisher (no I/O): process propagates the
     * publish error. */
    {
        iec61850_goose_publisher_t pub_nio;
        iec61850_model_binding_t b2;

        iec61850_goose_publisher_init(&pub_nio, NULL);
        (void)memset(&b2, 0, sizeof(b2));
        ASSERT_EQ(iec61850_model_binding_init(&b2, &model), 0);
        ASSERT_EQ(iec61850_model_binding_add_goose(&b2, &pub_nio, refs, 1U), 0);
        wr_bitstring(stval, dbpos_on, 2U);
        ASSERT_TRUE(b2.publishers[0].dirty);
        ASSERT_EQ(iec61850_model_binding_process(&b2), -EINVAL);
        ASSERT_TRUE(!b2.publishers[0].dirty);
        iec61850_model_binding_destroy(&b2);
    }

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * Multi-publisher fan-out (overlapping refs)
 * ======================================================================== */

static void test_multi_publisher(void)
{
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_logical_node_t *xcbr;
    iec61850_logical_node_t *mmxu;
    iec61850_data_attribute_t *stval;
    iec61850_goose_publisher_t pub1;
    iec61850_goose_publisher_t pub2;

    const iec61850_da_ref_t refs1[2] = {
        { .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
          .da_name = "stVal", .fc = IEC61850_FC_ST },
        { .ld = "LD0", .ln = "MMXU1", .do_name = "TotW",
          .da_name = "mag", .fc = IEC61850_FC_MX },
    };
    /* Overlapping: pub2 also watches Pos$stVal */
    const iec61850_da_ref_t refs2[1] = {
        { .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
          .da_name = "stVal", .fc = IEC61850_FC_ST },
    };
    const uint8_t dbpos_off[1] = { 0x40 }; /* bit1 set */

    TEST("multi_publisher_fanout");

    build_ln_class_model(&model, &xcbr, &mmxu);
    if (tests_failed > 0) { return; }
    stval = iec61850_ln_find_attribute(xcbr, "Pos.stVal", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);

    iec61850_goose_publisher_init(&pub1, NULL);
    iec61850_goose_publisher_init(&pub2, NULL);
    iec61850_goose_publisher_set_io(&pub1, &mock_io);
    iec61850_goose_publisher_set_io(&pub2, &mock_io);
    g_frames_sent = 0U;

    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, &pub1, refs1, 2U), 0);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, &pub2, refs2, 1U), 1);
    /* stVal is shared across both publishers: 2 unique DAs */
    ASSERT_EQ((int)b.watch_count, 2);

    /* One DA change dirties BOTH publishers */
    wr_bitstring(stval, dbpos_off, 2U);
    ASSERT_TRUE(b.publishers[0].dirty);
    ASSERT_TRUE(b.publishers[1].dirty);

    /* process publishes both */
    ASSERT_EQ(iec61850_model_binding_process(&b), 2);
    ASSERT_TRUE(!b.publishers[0].dirty);
    ASSERT_TRUE(!b.publishers[1].dirty);
    ASSERT_EQ(g_frames_sent, 2U);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub1), 1U);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub2), 1U);

    /* Both datasets carry the changed value */
    ASSERT_EQ((int)pub1.data[0].type, (int)GOOSE_DATA_BITSTRING);
    ASSERT_EQ((int)pub1.byte_storage[0].data[0], 0x40);
    ASSERT_EQ((int)pub2.data[0].type, (int)GOOSE_DATA_BITSTRING);
    ASSERT_EQ((int)pub2.byte_storage[0].data[0], 0x40);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * SV binding
 * ======================================================================== */

static void test_sv_binding(void)
{
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_logical_node_t *xcbr;
    iec61850_logical_node_t *mmxu;
    iec61850_data_attribute_t *mag;
    iec61850_data_attribute_t *q;
    iec61850_data_attribute_t *stval;
    iec61850_sv_publisher_t pub;

    /* Slot-for-slot: mag -> channel 0 sample, q -> channel 1
     * quality (the config's num_channels=4 covers both). */
    const iec61850_da_ref_t refs[2] = {
        { .ld = "LD0", .ln = "MMXU1", .do_name = "TotW",
          .da_name = "mag", .fc = IEC61850_FC_MX },
        { .ld = "LD0", .ln = "MMXU1", .do_name = "TotW",
          .da_name = "q", .fc = IEC61850_FC_MX },
    };
    /* SV cannot carry timestamps (no sample mapping) */
    const iec61850_da_ref_t ts_ref[1] = {
        { .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
          .da_name = "t", .fc = IEC61850_FC_ST },
    };
    const uint8_t quality_bad[2] = { 0xC0, 0x80 };

    TEST("sv_binding");

    build_ln_class_model(&model, &xcbr, &mmxu);
    if (tests_failed > 0) { return; }
    mag = iec61850_ln_find_attribute(mmxu, "TotW.mag", IEC61850_FC_MX);
    q = iec61850_ln_find_attribute(mmxu, "TotW.q", IEC61850_FC_MX);
    stval = iec61850_ln_find_attribute(xcbr, "Pos.stVal", IEC61850_FC_ST);
    ASSERT_TRUE(mag != NULL);
    ASSERT_TRUE(q != NULL);
    ASSERT_TRUE(stval != NULL);

    iec61850_sv_publisher_init(&pub, NULL); /* num_channels = 4 */
    iec61850_sv_publisher_set_io(&pub, &mock_io);
    g_frames_sent = 0U;

    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);
    ASSERT_EQ(iec61850_model_binding_add_sv(&b, &pub, refs, 2U), 0);

    /* Non-sample types are rejected for SV at bind time */
    ASSERT_EQ(iec61850_model_binding_add_sv(&b, &pub, ts_ref, 1U), -ENOTSUP);
    ASSERT_EQ((int)b.publisher_count, 1);

    wr_float(mag, 220.5f);
    wr_bitstring(q, quality_bad, 13U);
    ASSERT_TRUE(b.publishers[0].dirty);

    ASSERT_EQ(iec61850_model_binding_process(&b), 1);
    ASSERT_TRUE(!b.publishers[0].dirty);
    ASSERT_EQ(g_frames_sent, 1U);

    /* Channel 0: float sample truncated to int32 counts */
    ASSERT_EQ(pub.samples[0], 220);
    /* Channel 1: quality mapped from the DA bit string
     * (bit0/bit1 -> validity, bit8 -> inconsistent) */
    ASSERT_EQ((int)pub.quality[1].validity, 3);
    ASSERT_EQ((int)pub.quality[1].inconsistent, 1);
    ASSERT_EQ((int)pub.quality[1].overflow, 0);
    /* smpCnt advanced by the publish */
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&pub), 1U);

    /* No change: process is a no-op */
    ASSERT_EQ(iec61850_model_binding_process(&b), 0);
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&pub), 1U);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * Coexistence with a pre-registered listener + MMS write path
 * ======================================================================== */

static void test_coexistence(void)
{
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_logical_node_t *xcbr;
    iec61850_logical_node_t *mmxu;
    iec61850_data_attribute_t *stval;
    iec61850_goose_publisher_t pub;
    iec61850_mms_binding_manager_t mgr;
    mms_value_t mms_val;

    const iec61850_da_ref_t ref[1] = {
        { .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
          .da_name = "stVal", .fc = IEC61850_FC_ST },
    };
    const uint8_t dbpos_on[1] = { 0x80 };

    TEST("coexistence_with_mms_listener");

    build_ln_class_model(&model, &xcbr, &mmxu);
    if (tests_failed > 0) { return; }
    stval = iec61850_ln_find_attribute(xcbr, "Pos.stVal", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);

    /* 1. A listener registered BEFORE the binding (the MMS-side
     *    observer pattern used on the DA-change path). */
    g_listener_calls = 0U;
    iec61850_da_set_change_callback(stval, mms_side_listener, NULL);

    iec61850_goose_publisher_init(&pub, NULL);
    iec61850_goose_publisher_set_io(&pub, &mock_io);
    g_frames_sent = 0U;

    /* 2. The binding chains below it (one callback slot per DA:
     *    the collection mechanism). */
    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, &pub, ref, 1U), 0);
    ASSERT_EQ((int)b.watch_count, 1);

    /* 3. Write through the MMS variable-binding path (the live
     *    MMS write route into the model — the data store is only
     *    a registration-time snapshot; see the file header). */
    ASSERT_EQ(iec61850_binding_init(&mgr), 0);
    ASSERT_EQ((int)iec61850_binding_bind_variable(&mgr, "IED1LD0",
               "XCBR1$ST$Pos$stVal", stval), (int)IEC61850_BINDING_OK);

    (void)memset(&mms_val, 0, sizeof(mms_val));
    mms_val.type = MMS_TYPE_BIT_STRING;
    mms_val.value.bit_string.bit_count = 2U;
    mms_val.value.bit_string.data[0] = dbpos_on[0];

    ASSERT_EQ((int)iec61850_binding_on_mms_write(&mgr, "IED1LD0",
               "XCBR1$ST$Pos$stVal", &mms_val), (int)IEC61850_BINDING_OK);

    /* 4. Both observers saw the change: the chained listener fired
     *    AND the publisher went dirty with the slot updated. */
    ASSERT_EQ((int)g_listener_calls, 1);
    ASSERT_TRUE(b.publishers[0].dirty);
    ASSERT_EQ((int)pub.data_count, 1);
    ASSERT_EQ((int)pub.data[0].type, (int)GOOSE_DATA_BITSTRING);

    ASSERT_EQ(iec61850_model_binding_process(&b), 1);
    ASSERT_EQ(g_frames_sent, 1U);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub), 1U);

    /* 5. Destroy restores the listener as the sole callback. */
    iec61850_model_binding_destroy(&b);

    ASSERT_EQ((int)iec61850_binding_on_mms_write(&mgr, "IED1LD0",
               "XCBR1$ST$Pos$stVal", &mms_val), (int)IEC61850_BINDING_OK);
    ASSERT_EQ((int)g_listener_calls, 2);
    /* The destroyed binding no longer touches the publisher */
    ASSERT_EQ((int)pub.byte_storage[0].data[0], 0x80);
    ASSERT_EQ(g_frames_sent, 1U);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub), 1U);

    iec61850_binding_destroy(&mgr);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * Capacity: -ENOSPC at max publishers
 * ======================================================================== */

static void test_publisher_capacity(void)
{
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_logical_node_t *xcbr;
    iec61850_logical_node_t *mmxu;
    iec61850_goose_publisher_t pubs[IEC61850_BINDING_MAX_PUBLISHERS + 1U];
    uint32_t i;

    const iec61850_da_ref_t ref[1] = {
        { .ld = "LD0", .ln = "XCBR1", .do_name = "Pos",
          .da_name = "stVal", .fc = IEC61850_FC_ST },
    };

    TEST("publisher_capacity_enospc");

    build_ln_class_model(&model, &xcbr, &mmxu);
    if (tests_failed > 0) { return; }

    for (i = 0U; i < (uint32_t)IEC61850_BINDING_MAX_PUBLISHERS + 1U; i++) {
        iec61850_goose_publisher_init(&pubs[i], NULL);
    }

    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);

    for (i = 0U; i < (uint32_t)IEC61850_BINDING_MAX_PUBLISHERS; i++) {
        ASSERT_EQ(iec61850_model_binding_add_goose(&b, &pubs[i], ref, 1U),
                  (int)i);
    }
    /* All 8 slots share one watch for the single DA */
    ASSERT_EQ((int)b.watch_count, 1);

    /* The 9th publisher does not fit */
    ASSERT_EQ(iec61850_model_binding_add_goose(
                  &b, &pubs[IEC61850_BINDING_MAX_PUBLISHERS], ref, 1U),
               -ENOSPC);
    ASSERT_EQ((int)b.publisher_count, IEC61850_BINDING_MAX_PUBLISHERS);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ======================================================================== */

int main(void)
{
    printf("=== Model Binding Unit Tests ===\n");

    printf("\n--- Lifecycle ---\n");
    test_lifecycle();

    printf("\n--- Reference Resolution ---\n");
    test_ref_resolution();

    printf("\n--- GOOSE Fan-Out (LN class library) ---\n");
    test_goose_fanout();

    printf("\n--- Multi-Publisher Fan-Out ---\n");
    test_multi_publisher();

    printf("\n--- SV Binding ---\n");
    test_sv_binding();

    printf("\n--- Coexistence (MMS listener) ---\n");
    test_coexistence();

    printf("\n--- Capacity ---\n");
    test_publisher_capacity();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
