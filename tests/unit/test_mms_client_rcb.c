/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit + loopback integration tests for MMS Client RCB Enrollment
 * (WP-1c).
 *
 * Layer 1 (no server): argument validation for every frozen entry
 * point, and the 7-2 report metadata decoder path
 * (rptID/datSet/confRev/inclusion bits).
 *
 * Layer 2 (same-process loopback, per the WP-1c plan): the repo's own
 * mms_server is started with an RCB-provisioned data store (IEC
 * 61850-8-1 component-object naming, WP-1f DIV-1: RCB <name> exposes
 * named variables "<name>$<Component>" in the LD domain).
 * The server's after_response hook mirrors client RCB writes into
 * the repo's own RCB engine (mms_report.c) and pushes the generated
 * InformationReports onto the wire, so report reception is exercised
 * through the real blocking client + async core dispatch.
 *
 * NOTE on fixture layout: the repo's GetNameList response encoder
 * writes the identifier-list length as a single BER short-form length
 * octet, so each domain's variable-name payload must stay <= 127
 * bytes (see the WP-1c report). The RCBs therefore use short names
 * and live in separate small domains.
 *
 * Test scenarios:
 *   1. rcb_list discovery + component-pattern filtering
 *   2. rcb_get_values parse of every component (URCB and BRCB)
 *   3. Enrollment (set_values): Ed.2 write order, value round-trip
 *   4. enable/disable/purge_buffer/set_entry_id wrappers
 *   5. Ownership-conflict detection (failed Resv + foreign Owner)
 *   6. URCB report reception (dchg trigger, handler dispatch)
 *   7. BRCB report reception with EntryID tracking (qchg trigger)
 *   8. 7-2 report metadata (rptID/datSet/confRev/inclBitStr) decode
 */

#include "mms/mms_client_rcb.h"
#include "mms/mms_server.h"
#include "mms/mms_data_store.h"
#include "mms/mms_report.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ========================================================================
 * Minimal test framework (repo style)
 * ======================================================================== */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)
#define FAILF(...) do { tests_failed++; printf("FAIL: "); printf(__VA_ARGS__); \
                        printf("\n"); return; } while (0)

#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)
#define ASSERT_STR(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAIL: %s == %s (\"%s\" != \"%s\")\n", #a, #b, (a), (b)); \
        tests_failed++; return; } } while (0)

/* ========================================================================
 * Server-side fixture
 * ======================================================================== */

/* Short RCB names + separate domains keep every domain's GetNameList
 * identifier payload below the encoder's 127-byte limit. */
#define DOMAIN_URCB "LDU"   /* u1 (URCB) */
#define DOMAIN_BRCB "LDB"   /* b1 (BRCB) */
#define DOMAIN_OWN  "LDO"   /* ownership-conflict RCBs */
#define DOMAIN_DATA "LDD"   /* monitored data points */

#define URCB_NAME    "u1"
#define BRCB_NAME    "b1"
#define URCB2_NAME   "u2"   /* no Resv, Owner = other client */
#define URCB3_NAME   "u3"   /* no Resv, no Owner */

#define DATA_POS_STVAL "XCBR1$ST$Pos$stVal"
#define DATA_POS_Q     "XCBR1$ST$Pos$q"
#define DATA_DECOY     "MMXU1$MX$PhV$phsA"
#define TEST_PORT    11811

static iec61850_mms_data_store_t g_ds;
static iec61850_mms_server_t g_server;
static bool g_server_up = false;

/* Repo's own RCB engines, driven by client writes through the
 * after_response hook (server side of the reporting loop). */
static iec61850_rcb_t g_urcb_engine;
static iec61850_rcb_t g_brcb_engine;

/* Write-order log (filled from the after_response hook). */
#define WRITE_LOG_MAX 32
static char g_write_log[WRITE_LOG_MAX][MMS_MAX_VARIABLE_NAME];
static uint32_t g_write_log_count;
static bool g_record_writes;

/* Client-side report capture. */
static int g_report_count;
static mms_information_report_t g_last_report;

/* Shadow of the monitored data point (dchg old value). */
static bool g_prev_pos;

static iec61850_mms_session_t *g_active_session;

/* ---- value builders (what a conforming server's data store holds) ---- */

static mms_value_t mk_bool(bool b)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BOOLEAN;
    v.value.boolean = b;
    return v;
}

static mms_value_t mk_str(const char *s)
{
    mms_value_t v;
    size_t len = strlen(s);
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_VISIBLE_STRING;
    (void)memcpy(v.value.visible_string.data, s, len);
    v.value.visible_string.data[len] = '\0';
    v.value.visible_string.len = len;
    return v;
}

static mms_value_t mk_u32(uint32_t u)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;
    v.value.unsigned_val = u;
    return v;
}

static mms_value_t mk_f32(float f)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_FLOATING_POINT;
    v.value.floating_point = f;
    return v;
}

/* OptFlds: 10-bit bit-string (b0 = seq/time/reason/datSet/dataRef/
 * bufOvfl/entryID, b1 = confRev). */
static mms_value_t mk_optflds(uint8_t b0, uint8_t b1)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BIT_STRING;
    v.value.bit_string.data[0] = b0;
    v.value.bit_string.data[1] = b1;
    v.value.bit_string.bit_count = 10u;
    return v;
}

/* TrgOps: 6-bit bit-string (b0 = dchg/qchg/dupd/period/GI). */
static mms_value_t mk_trgops(uint8_t b0)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BIT_STRING;
    v.value.bit_string.data[0] = b0;
    v.value.bit_string.bit_count = 6u;
    return v;
}

static mms_value_t mk_entry_id(uint64_t id)
{
    mms_value_t v;
    uint32_t i;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_OCTET_STRING;
    for (i = 0u; i < 8u; i++) {
        v.value.octet_string.data[i] =
            (uint8_t)((id >> ((7u - (uint64_t)i) * 8u)) & 0xFFu);
    }
    v.value.octet_string.len = 8u;
    return v;
}

static void ds_put(const char *domain, const char *item, const mms_value_t *v)
{
    int ret = iec61850_mms_ds_create_variable(&g_ds, domain, item,
                                               v->type, v);
    if (ret != (int)IEC61850_MMS_DS_OK) {
        printf("FATAL: create_variable(%s/%s) failed: %d\n", domain, item, ret);
    }
}

static void comp_name(char *out, size_t out_size,
                       const char *rcb, const char *suffix)
{
    /* IEC 61850-8-1 component naming (WP-1f DIV-1): "<ref>$<Comp>". */
    (void)snprintf(out, out_size, "%s$%s", rcb, suffix);
}

/* Provision one RCB's component objects (Ed.2 naming). */
static void create_rcb(const char *domain, const char *name, bool buffered,
                       bool with_resv, const char *owner)
{
    char item[MMS_MAX_VARIABLE_NAME];
    mms_value_t v;

    v = mk_str(buffered ? "IED1_BRCB" : "IED1_URCB");
    comp_name(item, sizeof(item), name, "RptID");
    ds_put(domain, item, &v);

    v = mk_bool(false);
    comp_name(item, sizeof(item), name, "RptEna");
    ds_put(domain, item, &v);

    if (with_resv) {
        v = mk_bool(false);
        comp_name(item, sizeof(item), name, "Resv");
        ds_put(domain, item, &v);
    }

    v = mk_str("LDD/LLN0$DS1");
    comp_name(item, sizeof(item), name, "DatSet");
    ds_put(domain, item, &v);

    v = mk_u32(buffered ? 2u : 1u);
    comp_name(item, sizeof(item), name, "ConfRev");
    ds_put(domain, item, &v);

    /* OptFlds: sequence-number + reason (+ entry-id for BRCB). */
    v = mk_optflds(0x50u | (buffered ? 0x01u : 0x00u), 0x00u);
    comp_name(item, sizeof(item), name, "OptFlds");
    ds_put(domain, item, &v);

    v = mk_u32(buffered ? 500u : 0u);
    comp_name(item, sizeof(item), name, "BufTm");
    ds_put(domain, item, &v);

    /* TrgOps: dchg + GI (+ qchg for BRCB). */
    v = mk_trgops(0x44u | (buffered ? 0x20u : 0x00u));
    comp_name(item, sizeof(item), name, "TrgOps");
    ds_put(domain, item, &v);

    v = mk_u32(0u);
    comp_name(item, sizeof(item), name, "IntgPd");
    ds_put(domain, item, &v);

    v = mk_bool(false);
    comp_name(item, sizeof(item), name, "GI");
    ds_put(domain, item, &v);

    if (!buffered) {
        /* SqNum: omitted on the BRCB (optional component). */
        v = mk_u32(0u);
        comp_name(item, sizeof(item), name, "SqNum");
        ds_put(domain, item, &v);
    }

    if (owner != NULL) {
        v = mk_str(owner);
        comp_name(item, sizeof(item), name, "Owner");
        ds_put(domain, item, &v);
    }

    if (buffered) {
        v = mk_entry_id(0u);
        comp_name(item, sizeof(item), name, "EntryID");
        ds_put(domain, item, &v);

        v = mk_bool(false);
        comp_name(item, sizeof(item), name, "PurgeBuf");
        ds_put(domain, item, &v);
    }
}

/* ---- server-side report delivery ---- */

/* RCB engine report_sender: encode and push onto the association. */
static void send_report_pdu(const mms_information_report_t *report,
                             void *user_data)
{
    uint8_t buf[4096];
    int len;

    (void)user_data;
    if (g_active_session == NULL) {
        return;
    }

    len = mms_encode_information_report(report, buf, sizeof(buf));
    if (len > 0) {
        (void)iec61850_iso_send(&g_active_session->iso, buf, (size_t)len);
    }
}

/* Mirror a client RCB-component access into the server-side engine. */
static void mirror_rcb_component(iec61850_rcb_t *engine, const char *domain,
                                  const char *rcb_name, const char *item)
{
    mms_value_t v;
    const char *suffix;
    size_t n = strlen(rcb_name);

    if (strncmp(item, rcb_name, n) != 0) {
        return;
    }
    suffix = &item[n];
    /* Component naming (WP-1f DIV-1): "<ref>$<Comp>". */
    if (suffix[0] == '$') {
        suffix++;
    }

    if (iec61850_mms_ds_read_variable(&g_ds, domain, item, &v) !=
        (int)IEC61850_MMS_DS_OK) {
        return;
    }

    if (strcmp(suffix, "RptEna") == 0) {
        if (v.type == MMS_TYPE_BOOLEAN) {
            if (v.value.boolean) {
                (void)iec61850_rcb_enable(engine);
            } else {
                (void)iec61850_rcb_disable(engine);
            }
        }
    } else if (strcmp(suffix, "RptID") == 0) {
        if (v.type == MMS_TYPE_VISIBLE_STRING) {
            (void)strncpy(engine->attrs.rpt_id, v.value.visible_string.data,
                          (size_t)IEC61850_RCB_MAX_NAME - 1U);
            engine->attrs.rpt_id[IEC61850_RCB_MAX_NAME - 1U] = '\0';
        }
    } else if (strcmp(suffix, "DatSet") == 0) {
        if (v.type == MMS_TYPE_VISIBLE_STRING) {
            (void)strncpy(engine->attrs.dat_set, v.value.visible_string.data,
                          (size_t)IEC61850_RCB_MAX_NAME - 1U);
            engine->attrs.dat_set[IEC61850_RCB_MAX_NAME - 1U] = '\0';
        }
    } else if (strcmp(suffix, "TrgOps") == 0) {
        if (v.type == MMS_TYPE_BIT_STRING) {
            uint8_t b0 = v.value.bit_string.data[0];
            engine->attrs.trg_ops.data_change           = ((b0 & 0x40u) != 0u);
            engine->attrs.trg_ops.quality_change        = ((b0 & 0x20u) != 0u);
            engine->attrs.trg_ops.data_update           = ((b0 & 0x10u) != 0u);
            engine->attrs.trg_ops.integrity             = ((b0 & 0x08u) != 0u);
            engine->attrs.trg_ops.general_interrogation = ((b0 & 0x04u) != 0u);
        }
    } else if (strcmp(suffix, "OptFlds") == 0) {
        if (v.type == MMS_TYPE_BIT_STRING) {
            uint8_t b0 = v.value.bit_string.data[0];
            uint8_t b1 = (v.value.bit_string.bit_count >= 9u)
                         ? v.value.bit_string.data[1] : 0u;
            engine->attrs.opt_flds.sequence_number      = ((b0 & 0x40u) != 0u);
            engine->attrs.opt_flds.reason_for_inclusion = ((b0 & 0x10u) != 0u);
            engine->attrs.opt_flds.data_set_name        = ((b0 & 0x08u) != 0u);
            engine->attrs.opt_flds.entry_id             = ((b0 & 0x01u) != 0u);
            engine->attrs.opt_flds.config_ref           = ((b1 & 0x80u) != 0u);
        }
    }
}

/*
 * Server after_response hook: mirrors RCB component writes into the
 * engines and turns monitored data-point writes into report triggers
 * (the repo's own RCB engine generates the report; it is then encoded
 * and pushed onto the wire).
 */
static void test_after_response(iec61850_mms_session_t *session,
                                 const char *req_domain,
                                 const char *req_item,
                                 void *user_data)
{
    mms_value_t v;

    (void)user_data;
    g_active_session = session;

    if ((req_domain == NULL) || (req_item == NULL) || (req_item[0] == '\0')) {
        return;
    }

    if (g_record_writes && (g_write_log_count < (uint32_t)WRITE_LOG_MAX)) {
        (void)strncpy(g_write_log[g_write_log_count], req_item,
                      (size_t)MMS_MAX_VARIABLE_NAME - 1U);
        g_write_log[g_write_log_count][MMS_MAX_VARIABLE_NAME - 1U] = '\0';
        g_write_log_count++;
    }

    if (strcmp(req_domain, DOMAIN_DATA) == 0) {
        /* Monitored data point: dchg trigger. */
        if (strcmp(req_item, DATA_POS_STVAL) == 0) {
            if (iec61850_mms_ds_read_variable(&g_ds, DOMAIN_DATA, req_item,
                                               &v) == (int)IEC61850_MMS_DS_OK) {
                mms_value_t old = mk_bool(g_prev_pos);
                iec61850_rcb_on_data_change(&g_urcb_engine, req_item,
                                             &old, &v);
                iec61850_rcb_on_data_change(&g_brcb_engine, req_item,
                                             &old, &v);
                if (v.type == MMS_TYPE_BOOLEAN) {
                    g_prev_pos = v.value.boolean;
                }
            }
            return;
        }

        /* Monitored data point: qchg trigger (BRCB EntryID path). */
        if (strcmp(req_item, DATA_POS_Q) == 0) {
            if (iec61850_mms_ds_read_variable(&g_ds, DOMAIN_DATA, req_item,
                                               &v) == (int)IEC61850_MMS_DS_OK) {
                iec61850_rcb_on_quality_change(&g_brcb_engine, req_item, &v);
            }
            return;
        }
    } else if (strcmp(req_domain, DOMAIN_URCB) == 0) {
        mirror_rcb_component(&g_urcb_engine, DOMAIN_URCB, URCB_NAME, req_item);
    } else if (strcmp(req_domain, DOMAIN_BRCB) == 0) {
        mirror_rcb_component(&g_brcb_engine, DOMAIN_BRCB, BRCB_NAME, req_item);
    }
    /* DOMAIN_OWN (ownership-conflict RCBs): no engine to mirror. */
}

static void setup_server(void)
{
    iec61850_mms_server_config_t cfg;
    mms_value_t v;

    iec61850_mms_ds_init(&g_ds);
    (void)iec61850_mms_ds_create_domain(&g_ds, DOMAIN_URCB);
    (void)iec61850_mms_ds_create_domain(&g_ds, DOMAIN_BRCB);
    (void)iec61850_mms_ds_create_domain(&g_ds, DOMAIN_OWN);
    (void)iec61850_mms_ds_create_domain(&g_ds, DOMAIN_DATA);

    /* Monitored data points + a non-RCB decoy for list filtering. */
    v = mk_bool(true);
    ds_put(DOMAIN_DATA, DATA_POS_STVAL, &v);
    v = mk_u32(0u);
    ds_put(DOMAIN_DATA, DATA_POS_Q, &v);
    v = mk_f32(230.5f);
    ds_put(DOMAIN_DATA, DATA_DECOY, &v);

    create_rcb(DOMAIN_URCB, URCB_NAME, false, true, "");
    create_rcb(DOMAIN_BRCB, BRCB_NAME, true, false, "");

    /* Ownership-conflict RCBs: minimal component sets (no Resv). */
    {
        char item[MMS_MAX_VARIABLE_NAME];

        v = mk_bool(false);
        comp_name(item, sizeof(item), URCB2_NAME, "RptEna");
        ds_put(DOMAIN_OWN, item, &v);
        v = mk_str("OTHER_CLIENT");
        comp_name(item, sizeof(item), URCB2_NAME, "Owner");
        ds_put(DOMAIN_OWN, item, &v);

        v = mk_bool(false);
        comp_name(item, sizeof(item), URCB3_NAME, "RptEna");
        ds_put(DOMAIN_OWN, item, &v);
    }

    iec61850_rcb_init(&g_urcb_engine, "URCB01", IEC61850_RCB_UNBUFFERED);
    iec61850_rcb_set_report_sender(&g_urcb_engine, send_report_pdu, NULL);
    iec61850_rcb_init(&g_brcb_engine, "BRCB01", IEC61850_RCB_BUFFERED);
    iec61850_rcb_set_report_sender(&g_brcb_engine, send_report_pdu, NULL);

    g_prev_pos = true;
    g_report_count = 0;
    g_record_writes = false;
    g_write_log_count = 0u;

    iec61850_mms_server_config_init(&cfg);
    cfg.port = TEST_PORT;
    cfg.after_response = test_after_response;

    iec61850_mms_server_init(&g_server, &cfg, &g_ds);
    (void)iec61850_mms_server_start(&g_server);
    g_server_up = true;

    /* Give the accept thread time to bind. */
    usleep(200000);
}

static void teardown_server(void)
{
    if (g_server_up) {
        (void)iec61850_mms_server_stop(&g_server);
        g_server_up = false;
    }
    iec61850_rcb_destroy(&g_urcb_engine);
    iec61850_rcb_destroy(&g_brcb_engine);
    iec61850_mms_ds_destroy(&g_ds);
}

/* ========================================================================
 * Client-side helpers
 * ======================================================================== */

static void client_report_cb(const mms_information_report_t *report,
                              void *user_data)
{
    (void)user_data;
    g_report_count++;
    g_last_report = *report;
}

/* Pump the association until a report reaches the handler (or the
 * timeout expires; returns -1 with g_report_count == 0). */
static int pump_for_report(iec61850_mms_client_t *client, int timeout_ms)
{
    int waited = 0;

    while ((g_report_count == 0) && (waited < timeout_ms)) {
        int ret = iec61850_mms_client_poll(client, 50);
        if (ret < 0) {
            return ret;
        }
        waited += 50;
    }

    return (g_report_count > 0) ? 0 : -1;
}

/* ========================================================================
 * Layer 1: argument validation (no server)
 * ======================================================================== */

static void test_argument_validation(void)
{
    iec61850_mms_client_t client;
    char names[4][IEC61850_RCB_MAX_NAME];
    iec61850_mms_client_rcb_values_t values;
    uint32_t count = 0u;

    TEST("rcb_argument_validation");

    iec61850_mms_client_init(&client);

    /* rcb_list */
    ASSERT_EQ(iec61850_mms_client_rcb_list(NULL, DOMAIN_URCB, names,
                                            &count, 4u),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_list(&client, NULL, names,
                                            &count, 4u),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_list(&client, DOMAIN_URCB, NULL,
                                            &count, 4u),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_list(&client, DOMAIN_URCB, names,
                                            NULL, 4u),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_list(&client, DOMAIN_URCB, names,
                                            &count, 4u),
              IEC61850_MMS_CLIENT_ERR_ARGS); /* not connected */

    /* rcb_get_values */
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(NULL, DOMAIN_URCB,
                                                  URCB_NAME, &values),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, NULL,
                                                  URCB_NAME, &values),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, DOMAIN_URCB,
                                                  NULL, &values),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, DOMAIN_URCB,
                                                  URCB_NAME, NULL),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, DOMAIN_URCB,
                                                  URCB_NAME, &values),
              IEC61850_MMS_CLIENT_ERR_ARGS); /* not connected */

    /* rcb_set_values */
    (void)memset(&values, 0, sizeof(values));
    ASSERT_EQ(iec61850_mms_client_rcb_set_values(NULL, DOMAIN_URCB,
                                                  URCB_NAME, &values,
                                                  (uint32_t)IEC61850_RCB_FIELD_RPT_ENA),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_set_values(&client, DOMAIN_URCB,
                                                  URCB_NAME, NULL,
                                                  (uint32_t)IEC61850_RCB_FIELD_RPT_ENA),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_set_values(&client, DOMAIN_URCB,
                                                  URCB_NAME, &values, 0u),
              IEC61850_MMS_CLIENT_ERR_ARGS); /* empty mask */
    ASSERT_EQ(iec61850_mms_client_rcb_set_values(&client, DOMAIN_URCB,
                                                  URCB_NAME, &values,
                                                  (uint32_t)IEC61850_RCB_FIELD_RPT_ENA),
              IEC61850_MMS_CLIENT_ERR_ARGS); /* not connected */

    /* thin wrappers */
    ASSERT_EQ(iec61850_mms_client_rcb_enable(NULL, DOMAIN_URCB, URCB_NAME),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_disable(NULL, DOMAIN_URCB, URCB_NAME),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_purge_buffer(NULL, DOMAIN_BRCB, BRCB_NAME),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_set_entry_id(NULL, DOMAIN_BRCB,
                                                    BRCB_NAME, 1u),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_enable(&client, NULL, URCB_NAME),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_rcb_set_entry_id(&client, DOMAIN_BRCB,
                                                    NULL, 1u),
              IEC61850_MMS_CLIENT_ERR_ARGS);

    /* report handler install: NULL client is an error; NULL cb clears */
    ASSERT_EQ(iec61850_mms_client_set_report_handler(NULL,
                                                       client_report_cb, NULL),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_set_report_handler(&client, NULL, NULL),
              IEC61850_MMS_CLIENT_OK);

    /* client poll: NULL / unconnected are argument errors */
    ASSERT_EQ(iec61850_mms_client_poll(NULL, 0), IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_poll(&client, 0), IEC61850_MMS_CLIENT_ERR_ARGS);

    PASS();
}

/* ========================================================================
 * Layer 2: loopback integration
 * ======================================================================== */

static void test_rcb_list_discovery(void)
{
    iec61850_mms_client_t client;
    char names[8][IEC61850_RCB_MAX_NAME];
    uint32_t count = 0u;
    int ret;

    TEST("rcb_list_discovery");

    iec61850_mms_client_init(&client);
    ASSERT_EQ(iec61850_mms_client_connect(&client, "127.0.0.1",
                                           TEST_PORT, 5000),
              IEC61850_MMS_CLIENT_OK);

    ret = iec61850_mms_client_rcb_list(&client, DOMAIN_URCB, names,
                                        &count, 8u);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)count, 1);
    ASSERT_STR(names[0], URCB_NAME);

    ret = iec61850_mms_client_rcb_list(&client, DOMAIN_BRCB, names,
                                        &count, 8u);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)count, 1);
    ASSERT_STR(names[0], BRCB_NAME);

    /* Ownership-conflict RCBs. */
    ret = iec61850_mms_client_rcb_list(&client, DOMAIN_OWN, names,
                                        &count, 8u);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)count, 2);

    /* Data points must not be mistaken for RCBs. */
    count = 0u;
    ret = iec61850_mms_client_rcb_list(&client, DOMAIN_DATA, names,
                                        &count, 8u);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)count, 0);

    /* Capacity limit honored. */
    count = 0u;
    ASSERT_EQ(iec61850_mms_client_rcb_list(&client, DOMAIN_OWN, names,
                                            &count, 1u),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)count, 1);

    /* Unknown domain: empty listing, not an error. */
    count = 0u;
    ASSERT_EQ(iec61850_mms_client_rcb_list(&client, "NOSUCHLD", names,
                                            &count, 8u),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)count, 0);

    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_rcb_get_values(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t v;
    int ret;

    TEST("rcb_get_values");

    iec61850_mms_client_init(&client);
    ASSERT_EQ(iec61850_mms_client_connect(&client, "127.0.0.1",
                                           TEST_PORT, 5000),
              IEC61850_MMS_CLIENT_OK);

    /* URCB */
    (void)memset(&v, 0, sizeof(v));
    ret = iec61850_mms_client_rcb_get_values(&client, DOMAIN_URCB,
                                              URCB_NAME, &v);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(!v.buffered);
    ASSERT_TRUE(!v.attrs.rpt_ena);
    ASSERT_TRUE(!v.resv);
    ASSERT_STR(v.attrs.rpt_id, "IED1_URCB");
    ASSERT_STR(v.attrs.dat_set, "LDD/LLN0$DS1");
    ASSERT_EQ((int)v.attrs.conf_rev, 1);
    ASSERT_EQ((int)v.attrs.buf_tm, 0);
    ASSERT_EQ((int)v.attrs.intg_pd, 0);
    ASSERT_TRUE(v.attrs.opt_flds.sequence_number);
    ASSERT_TRUE(v.attrs.opt_flds.reason_for_inclusion);
    ASSERT_TRUE(!v.attrs.opt_flds.entry_id);
    ASSERT_TRUE(!v.attrs.opt_flds.config_ref);
    ASSERT_TRUE(v.attrs.trg_ops.data_change);
    ASSERT_TRUE(v.attrs.trg_ops.general_interrogation);
    ASSERT_TRUE(!v.attrs.trg_ops.quality_change);
    ASSERT_TRUE(!v.attrs.trg_ops.data_update);
    ASSERT_TRUE(!v.attrs.trg_ops.integrity);
    ASSERT_TRUE(v.owner_present);
    ASSERT_TRUE(v.owner[0] == '\0');
    ASSERT_EQ((int)v.attrs.sq_num, 0);

    /* BRCB */
    (void)memset(&v, 0, sizeof(v));
    ret = iec61850_mms_client_rcb_get_values(&client, DOMAIN_BRCB,
                                              BRCB_NAME, &v);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(v.buffered);
    ASSERT_TRUE(!v.resv);                 /* BRCB has no Resv */
    ASSERT_EQ((int)v.attrs.conf_rev, 2);
    ASSERT_EQ((int)v.attrs.buf_tm, 500);
    ASSERT_TRUE(v.attrs.opt_flds.entry_id);
    ASSERT_TRUE(v.attrs.trg_ops.quality_change);
    ASSERT_TRUE(v.attrs.entry_id == 0u);  /* EntryID read-back */

    /* Nonexistent RCB: the RptEna read is rejected by the server. */
    ret = iec61850_mms_client_rcb_get_values(&client, DOMAIN_URCB,
                                              "nope", &v);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_ERR_MMS);

    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_enrollment_order_and_roundtrip(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t values;
    iec61850_mms_client_rcb_values_t readback;
    static const char *expected_order[] = {
        URCB_NAME "$Resv",
        URCB_NAME "$RptID",
        URCB_NAME "$DatSet",
        URCB_NAME "$ConfRev",
        URCB_NAME "$OptFlds",
        URCB_NAME "$TrgOps",
        URCB_NAME "$BufTm",
        URCB_NAME "$IntgPd",
        URCB_NAME "$RptEna",
    };
    uint32_t mask;
    uint32_t i;
    int ret;

    TEST("rcb_enrollment_order_and_roundtrip");

    iec61850_mms_client_init(&client);
    ASSERT_EQ(iec61850_mms_client_connect(&client, "127.0.0.1",
                                           TEST_PORT, 5000),
              IEC61850_MMS_CLIENT_OK);

    (void)memset(&values, 0, sizeof(values));
    values.resv = true;
    (void)strncpy(values.attrs.rpt_id, "URCB01",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    (void)strncpy(values.attrs.dat_set, "LDD/LLN0$DS2",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    values.attrs.conf_rev = 7u;
    values.attrs.opt_flds.sequence_number = true;
    values.attrs.opt_flds.reason_for_inclusion = true;
    values.attrs.opt_flds.data_set_name = true;
    values.attrs.trg_ops.data_change = true;
    values.attrs.trg_ops.quality_change = true;
    values.attrs.trg_ops.general_interrogation = true;
    values.attrs.buf_tm = 50u;
    values.attrs.intg_pd = 1000u;
    values.attrs.rpt_ena = true;

    mask = (uint32_t)IEC61850_RCB_FIELD_RPT_ID |
           (uint32_t)IEC61850_RCB_FIELD_RESV |
           (uint32_t)IEC61850_RCB_FIELD_DAT_SET |
           (uint32_t)IEC61850_RCB_FIELD_CONF_REV |
           (uint32_t)IEC61850_RCB_FIELD_OPT_FLDS |
           (uint32_t)IEC61850_RCB_FIELD_TRG_OPS |
           (uint32_t)IEC61850_RCB_FIELD_BUF_TM |
           (uint32_t)IEC61850_RCB_FIELD_INTG_PD |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;

    /* Record the server-observed write sequence. */
    g_write_log_count = 0u;
    g_record_writes = true;
    ret = iec61850_mms_client_rcb_set_values(&client, DOMAIN_URCB,
                                              URCB_NAME, &values, mask);
    g_record_writes = false;
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Ed.2 client-procedure order: reservation first, configuration
     * fields next, RptEna last. */
    ASSERT_EQ((int)g_write_log_count, 9);
    for (i = 0u; i < (uint32_t)(sizeof(expected_order) / sizeof(expected_order[0])); i++) {
        if (i >= g_write_log_count) {
            FAILF("write log too short: %u", (unsigned)g_write_log_count);
        }
        if (strcmp(g_write_log[i], expected_order[i]) != 0) {
            FAILF("write %u: got %s want %s", (unsigned)i,
                  g_write_log[i], expected_order[i]);
        }
    }

    /* Read back through get_values: parse/serialize round-trip. */
    (void)memset(&readback, 0, sizeof(readback));
    ret = iec61850_mms_client_rcb_get_values(&client, DOMAIN_URCB,
                                              URCB_NAME, &readback);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(readback.resv);
    ASSERT_TRUE(readback.attrs.rpt_ena);
    ASSERT_STR(readback.attrs.rpt_id, "URCB01");
    ASSERT_STR(readback.attrs.dat_set, "LDD/LLN0$DS2");
    ASSERT_EQ((int)readback.attrs.conf_rev, 7);
    ASSERT_EQ((int)readback.attrs.buf_tm, 50);
    ASSERT_EQ((int)readback.attrs.intg_pd, 1000);
    ASSERT_TRUE(readback.attrs.opt_flds.sequence_number);
    ASSERT_TRUE(readback.attrs.opt_flds.reason_for_inclusion);
    ASSERT_TRUE(readback.attrs.opt_flds.data_set_name);
    ASSERT_TRUE(!readback.attrs.opt_flds.entry_id);
    ASSERT_TRUE(readback.attrs.trg_ops.data_change);
    ASSERT_TRUE(readback.attrs.trg_ops.quality_change);
    ASSERT_TRUE(readback.attrs.trg_ops.general_interrogation);
    ASSERT_TRUE(!readback.attrs.trg_ops.data_update);

    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_enable_disable_wrappers(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t v;
    int ret;

    TEST("rcb_enable_disable_wrappers");

    iec61850_mms_client_init(&client);
    ASSERT_EQ(iec61850_mms_client_connect(&client, "127.0.0.1",
                                           TEST_PORT, 5000),
              IEC61850_MMS_CLIENT_OK);

    ret = iec61850_mms_client_rcb_enable(&client, DOMAIN_URCB, URCB_NAME);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ret = iec61850_mms_client_rcb_get_values(&client, DOMAIN_URCB,
                                              URCB_NAME, &v);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(v.attrs.rpt_ena);

    ret = iec61850_mms_client_rcb_disable(&client, DOMAIN_URCB, URCB_NAME);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ret = iec61850_mms_client_rcb_get_values(&client, DOMAIN_URCB,
                                              URCB_NAME, &v);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(!v.attrs.rpt_ena);

    /* Same lifecycle on the BRCB. */
    ASSERT_EQ(iec61850_mms_client_rcb_enable(&client, DOMAIN_BRCB, BRCB_NAME),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(iec61850_mms_client_rcb_disable(&client, DOMAIN_BRCB, BRCB_NAME),
              IEC61850_MMS_CLIENT_OK);

    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_purge_and_entry_id(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t v;
    mms_value_t val;
    int ret;

    TEST("rcb_purge_and_entry_id");

    iec61850_mms_client_init(&client);
    ASSERT_EQ(iec61850_mms_client_connect(&client, "127.0.0.1",
                                           TEST_PORT, 5000),
              IEC61850_MMS_CLIENT_OK);

    /* PurgeBuf = TRUE. */
    ret = iec61850_mms_client_rcb_purge_buffer(&client, DOMAIN_BRCB,
                                                BRCB_NAME);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ret = iec61850_mms_client_read(&client, DOMAIN_BRCB,
                                    BRCB_NAME "$PurgeBuf", &val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)val.type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(val.value.boolean);

    /* EntryID write + read-back (BRCB resume-after-reconnect). */
    ret = iec61850_mms_client_rcb_set_entry_id(&client, DOMAIN_BRCB,
                                                BRCB_NAME,
                                                0x1122334455667788ULL);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ret = iec61850_mms_client_rcb_get_values(&client, DOMAIN_BRCB,
                                              BRCB_NAME, &v);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(v.buffered);
    ASSERT_TRUE(v.attrs.entry_id == 0x1122334455667788ULL);

    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_ownership_conflict(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t values;
    int ret;

    TEST("rcb_ownership_conflict");

    iec61850_mms_client_init(&client);
    ASSERT_EQ(iec61850_mms_client_connect(&client, "127.0.0.1",
                                           TEST_PORT, 5000),
              IEC61850_MMS_CLIENT_OK);

    (void)memset(&values, 0, sizeof(values));
    values.resv = true;

    /* u2 has no Resv object (write fails) but a foreign Owner:
     * distinct ownership-conflict error, no retry. */
    g_write_log_count = 0u;
    g_record_writes = true;
    ret = iec61850_mms_client_rcb_set_values(&client, DOMAIN_OWN,
                                              URCB2_NAME, &values,
                                              (uint32_t)IEC61850_RCB_FIELD_RESV);
    g_record_writes = false;
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_ERR_RCB_OWNER);
    /* Server observed exactly one successful request after the failed
     * Resv write: the Owner probe (the failed write itself gets an
     * error response, which does not trigger the hook). */
    ASSERT_EQ((int)g_write_log_count, 1);
    ASSERT_STR(g_write_log[0], URCB2_NAME "$Owner");

    /* u3 has neither Resv nor Owner: plain MMS error, no retry. */
    g_write_log_count = 0u;
    g_record_writes = true;
    ret = iec61850_mms_client_rcb_set_values(&client, DOMAIN_OWN,
                                              URCB3_NAME, &values,
                                              (uint32_t)IEC61850_RCB_FIELD_RESV);
    g_record_writes = false;
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_ERR_MMS);
    ASSERT_EQ((int)g_write_log_count, 0);

    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_urcb_report_reception(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t values;
    mms_value_t new_val;
    uint32_t mask;
    int ret;

    TEST("rcb_urcb_report_reception");

    iec61850_mms_client_init(&client);
    ASSERT_EQ(iec61850_mms_client_connect(&client, "127.0.0.1",
                                           TEST_PORT, 5000),
              IEC61850_MMS_CLIENT_OK);

    ASSERT_EQ(iec61850_mms_client_set_report_handler(&client,
                                                      client_report_cb, NULL),
              IEC61850_MMS_CLIENT_OK);

    /* Enroll: reserve, point at the data set, arm dchg, enable. */
    (void)memset(&values, 0, sizeof(values));
    values.resv = true;
    (void)strncpy(values.attrs.rpt_id, "URCB01",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    (void)strncpy(values.attrs.dat_set, "LDD/LLN0$DS1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    values.attrs.trg_ops.data_change = true;
    values.attrs.rpt_ena = true;

    mask = (uint32_t)IEC61850_RCB_FIELD_RPT_ID |
           (uint32_t)IEC61850_RCB_FIELD_RESV |
           (uint32_t)IEC61850_RCB_FIELD_DAT_SET |
           (uint32_t)IEC61850_RCB_FIELD_TRG_OPS |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;

    ret = iec61850_mms_client_rcb_set_values(&client, DOMAIN_URCB,
                                              URCB_NAME, &values, mask);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Trigger a report by writing the monitored data point. */
    g_report_count = 0;
    (void)memset(&g_last_report, 0, sizeof(g_last_report));
    new_val = mk_bool(false);
    ret = iec61850_mms_client_write(&client, DOMAIN_DATA,
                                     DATA_POS_STVAL, &new_val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* The report arrives after the write response: pump the
     * association until the handler fires. */
    ret = pump_for_report(&client, 5000);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(g_report_count, 1);

    ASSERT_STR(g_last_report.variable_list_name, "URCB01");
    ASSERT_EQ((int)g_last_report.num_values, 1);
    ASSERT_EQ((int)g_last_report.values[0].type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(!g_last_report.values[0].value.boolean);

    /* Disable: no further reports. */
    ASSERT_EQ(iec61850_mms_client_rcb_disable(&client, DOMAIN_URCB,
                                               URCB_NAME),
              IEC61850_MMS_CLIENT_OK);
    g_report_count = 0;
    new_val = mk_bool(true);
    ret = iec61850_mms_client_write(&client, DOMAIN_DATA,
                                     DATA_POS_STVAL, &new_val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    (void)pump_for_report(&client, 300);
    ASSERT_EQ(g_report_count, 0);

    ASSERT_EQ(iec61850_mms_client_set_report_handler(&client, NULL, NULL),
              IEC61850_MMS_CLIENT_OK);
    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_brcb_report_entry_id(void)
{
    iec61850_mms_client_t client;
    iec61850_mms_client_rcb_values_t values;
    mms_value_t q_val;
    uint32_t mask;
    int ret;

    TEST("rcb_brcb_report_entry_id");

    iec61850_mms_client_init(&client);
    ASSERT_EQ(iec61850_mms_client_connect(&client, "127.0.0.1",
                                           TEST_PORT, 5000),
              IEC61850_MMS_CLIENT_OK);

    ASSERT_EQ(iec61850_mms_client_set_report_handler(&client,
                                                      client_report_cb, NULL),
              IEC61850_MMS_CLIENT_OK);

    /* Enroll the BRCB: rptID, seqNum + reason + entryID optional
     * fields, qchg trigger, enable last. */
    (void)memset(&values, 0, sizeof(values));
    (void)strncpy(values.attrs.rpt_id, "BRCB01",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    values.attrs.opt_flds.sequence_number = true;
    values.attrs.opt_flds.reason_for_inclusion = true;
    values.attrs.opt_flds.entry_id = true;
    values.attrs.trg_ops.quality_change = true;
    values.attrs.rpt_ena = true;

    mask = (uint32_t)IEC61850_RCB_FIELD_RPT_ID |
           (uint32_t)IEC61850_RCB_FIELD_OPT_FLDS |
           (uint32_t)IEC61850_RCB_FIELD_TRG_OPS |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;

    ret = iec61850_mms_client_rcb_set_values(&client, DOMAIN_BRCB,
                                              BRCB_NAME, &values, mask);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Buffered entries from an earlier association (resume context). */
    g_brcb_engine.attrs.entry_id = 41u;

    /* Trigger a qchg report on the monitored data point. */
    g_report_count = 0;
    (void)memset(&g_last_report, 0, sizeof(g_last_report));
    q_val = mk_u32(7u);
    ret = iec61850_mms_client_write(&client, DOMAIN_DATA,
                                     DATA_POS_Q, &q_val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    ret = pump_for_report(&client, 5000);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(g_report_count, 1);

    ASSERT_STR(g_last_report.variable_list_name, "BRCB01");
    ASSERT_TRUE(g_last_report.entry_id_present);
    ASSERT_TRUE(g_last_report.entry_id == 41u);
    ASSERT_TRUE(g_last_report.sq_num_present);
    ASSERT_TRUE(g_last_report.reasons_present);
    ASSERT_EQ((int)g_last_report.reasons[0], (int)IEC61850_REASON_QCHG);
    ASSERT_EQ((int)g_last_report.num_values, 1);
    ASSERT_EQ((int)g_last_report.values[0].type, (int)MMS_TYPE_UNSIGNED);
    ASSERT_EQ((int)g_last_report.values[0].value.unsigned_val, 7);

    ASSERT_EQ(iec61850_mms_client_rcb_disable(&client, DOMAIN_BRCB,
                                               BRCB_NAME),
              IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(iec61850_mms_client_set_report_handler(&client, NULL, NULL),
              IEC61850_MMS_CLIENT_OK);
    (void)iec61850_mms_client_disconnect(&client);
    PASS();
}

/* ========================================================================
 * 7-2 report metadata (rptID / datSet / confRev / inclBitStr)
 * ======================================================================== */

static void test_report_metadata_decoder(void)
{
    mms_iec61850_report_t rpt;
    mms_information_report_t dec;
    uint8_t buf[1024];
    int len;
    int ret;

    TEST("rcb_report_metadata_decoder");

    /* Full IEC 61850-7-2 report as a conforming Ed.2 server would
     * send it (mms_encode_iec61850_report wire format; decoded by
     * mms_decode_iec61850_report into the handler-visible struct). */
    (void)memset(&rpt, 0, sizeof(rpt));
    (void)strncpy(rpt.rpt_id, "BRCB01", sizeof(rpt.rpt_id) - 1U);
    (void)strncpy(rpt.dat_set, "LDD/LLN0$DS1", sizeof(rpt.dat_set) - 1U);
    rpt.sq_num_present = true;
    rpt.sq_num = 9u;
    rpt.conf_rev_present = true;
    rpt.conf_rev = 3u;
    /* optFlds: sequence-number + reason + data-set-name */
    rpt.opt_flds_byte = 0x40u | 0x10u | 0x08u;
    rpt.num_members = 3u;
    rpt.reason_code = (uint8_t)IEC61850_REASON_GI;
    rpt.values[0] = mk_bool(true);
    rpt.values[1] = mk_u32(42u);
    rpt.values[2] = mk_f32(230.5f);
    rpt.num_values = 3u;

    len = mms_encode_iec61850_report(&rpt, buf, sizeof(buf));
    ASSERT_TRUE(len > 0);

    (void)memset(&dec, 0, sizeof(dec));
    ret = mms_decode_iec61850_report(buf, (size_t)len, &dec);
    ASSERT_TRUE(ret > 0);

    ASSERT_STR(dec.rpt_id, "BRCB01");
    ASSERT_STR(dec.dat_set, "LDD/LLN0$DS1");
    ASSERT_TRUE(dec.conf_rev_present);
    ASSERT_EQ((int)dec.conf_rev, 3);
    ASSERT_TRUE(dec.sq_num_present);
    ASSERT_EQ((int)dec.sq_num, 9);

    /* Inclusion bit string: 3 of 8 bits set (0xE0), MSB first. */
    ASSERT_TRUE(dec.incl_bit_str_len >= 1u);
    ASSERT_EQ((int)dec.incl_bit_str[0], 0xE0);
    ASSERT_EQ((int)dec.num_values, 3);
    ASSERT_EQ((int)dec.values[0].type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(dec.values[0].value.boolean);
    ASSERT_EQ((int)dec.values[1].type, (int)MMS_TYPE_UNSIGNED);
    ASSERT_EQ((int)dec.values[1].value.unsigned_val, 42);
    ASSERT_EQ((int)dec.values[2].type, (int)MMS_TYPE_FLOATING_POINT);
    ASSERT_TRUE(dec.reasons_present);
    ASSERT_EQ((int)dec.reasons[0], (int)IEC61850_REASON_GI);

    PASS();
}

/* ======================================================================== */

int main(void)
{
    printf("\n=== MMS Client RCB Unit + Loopback Tests ===\n");

    printf("\n--- Argument validation ---\n");
    test_argument_validation();

    printf("\n--- Loopback integration (server + client in-process) ---\n");
    setup_server();

    test_rcb_list_discovery();
    test_rcb_get_values();
    test_enrollment_order_and_roundtrip();
    test_enable_disable_wrappers();
    test_purge_and_entry_id();
    test_ownership_conflict();
    test_urcb_report_reception();
    test_brcb_report_entry_id();

    teardown_server();

    printf("\n--- 7-2 report metadata ---\n");
    test_report_metadata_decoder();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
