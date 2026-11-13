/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Reporting Interop: xdp-iec61850 client vs libiec61850 server
 *
 * Cross-validates the client-side reporting stack (WP-1a/1b/1c:
 * async core, 7-2 report decoder, RCB enrollment) against the
 * reference implementation's server_example_basic_io, used strictly
 * as a black-box oracle (clean-room policy: wire observation only).
 *
 * Scenario inventory
 *   MR-01  connect + RCB discovery via rcb_list          (expects FAIL)
 *   MR-02  read RCB values via rcb_get_values            (expects FAIL)
 *   MR-02b RCB component presence/types via plain reads  (expects PASS)
 *   MR-03  URCB enrollment + report reception            (expects PASS)
 *   MR-04  BRCB enrollment + buffered report + EntryID   (expects PASS)
 *   MR-04b BRCB report w/ server-default optFlds         (expects FAIL)
 *   MR-05  BRCB resume after reconnect via EntryID       (expects PASS)
 *   MR-06  RCB ownership conflict (two connections)      (expects FAIL)
 *
 * The FAIL expectations are minimized, wire-verified bugs in OUR
 * client stack (the library sources are frozen for this WP; the
 * failures are the cross-validation signal for orchestrator fix
 * WPs). They are marked with BUG-Rx references and documented in
 * the WP-1d report:
 *
 *   BUG-R1 (mms_client_rcb.c)  rcb_list() caps its internal
 *          GetNameList sweep at 128 names. The oracle's domain
 *          "simpleIOGenericIO" exposes 304 named variables with
 *          the first "...$RptEna" component at index 141, so
 *          rcb_list() discovers 0 RCBs on a stock libiec61850
 *          server. -> MR-01
 *
 *   BUG-R2 (mms_ber.c + mms_client_core.c)  a Read-Response that
 *          carries a failure AccessResult is a valid MMS PDU, but
 *          the decoder returns an error and the core treats it as
 *          a malformed PDU: the pending request is never
 *          delivered, the client blocks for the full request
 *          timeout and returns ERR_TIMEOUT (-5) instead of
 *          ERR_MMS (-6), and the DataAccessError code is dropped.
 *          Wire (Read of LLN0$RP$EventsIndexed01$Owner, absent on
 *          the oracle):
 *            a1 0a 02 01 01 a4 05 a1 03 80 01 0a
 *          (ConfirmedResponse/read/listOfAccessResult/failure
 *          DataAccessError=10). This also stalls MC-07 of the
 *          pre-existing mms_interop_client suite for its full 30s
 *          request timeout. -> MR-02
 *
 *   BUG-R3 (mms_ber.c write-response decode)  the Write-Response
 *          failure/success CHOICE (failure [0] DataAccessError vs
 *          success [1] NULL) is skipped wholesale, so rejected
 *          writes are reported as success. Wire (Resv write on a
 *          URCB held by another client):
 *            a1 08 02 01 01 a5 03 80 01 02
 *          Our client returns OK for this write; read-back shows
 *          RptEna=false (rejected). Consequently
 *          IEC61850_MMS_CLIENT_ERR_RCB_OWNER is unreachable
 *          against servers that report write failures in-band.
 *          -> MR-06
 *
 *   BUG-R4 (mms_ber.c mms_decode_iec61850_report)  the
 *          buffer-overflow optional field (BOOLEAN [3] between
 *          datSet and confRev) is not parsed. The oracle's BRCBs
 *          default optFlds (0x7a/0x7b) include buffer-overflow, so
 *          their reports fail to decode and are dropped
 *          (poll() returns -8, handler never fires). Wire (BRCB
 *          report body): 8a 07 "Events2" 84 03 06 7a 80 86 01 00
 *          8c 06 <timeOfEntry> 8a 1d <datSet> 83 01 01 86 01 01
 *          84 02 04 f0 <values...>  — the "83 01 01" bufOvfl
 *          between datSet and confRev is the unhandled field.
 *          -> MR-04b
 *
 * Naming (WP-1f DIV-1, aligned to the IEC 61850-8-1 standard
 * convention): the oracle exposes RCB components as "$"-separated
 * structure names ("LLN0$RP$EventsRCB01$RptEna"), and so does this
 * repo's client (component item = "<rcb-reference>$<Component>") and
 * server bridge. All scenarios pass discovered RCB references
 * (e.g. "LLN0$RP$EventsIndexed01") verbatim.
 *
 * Other oracle observations (documented, not asserted):
 *   - BRCBs use Ed.2 ResvTms (no Resv); enrollment without a
 *     reservation works (EntryID/RptEna path).
 *   - No readable Owner component on any RCB (read -> failure
 *     AccessResult), so the ERR_RCB_OWNER owner-probe cannot fire.
 *   - Report sqNum restarts at 0 per enable-session; cross-reconnect
 *     sqNum continuity is not observable.
 *
 * Launches the oracle as an isolated subprocess per scenario
 * (GPL isolation per the clean-room policy). Skips when the oracle
 * is not found.
 */

#include "../interop_helpers.h"
#include "mms/mms_client.h"
#include "mms/mms_client_rcb.h"
#include "asn1/mms_ber.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static uint16_t g_port = 10600;

/* Per-scenario request timeout: loopback round-trips are
 * sub-millisecond; 2 s is generous while keeping the BUG-R2 stall
 * (one full request timeout per failed read) cheap. */
#define MR_REQUEST_TIMEOUT_MS 2000

/* Oracle model facts (observed on the wire, server_example_basic_io):
 * one domain, 304 named variables, 12 RCBs, URCB/BRCB integrity
 * period 1000 ms. */
#define MR_SCAN_MAX_VARS 600
#define MR_MAX_RCBS      16
#define MR_URCB_PREFIX   "LLN0$RP$"
#define MR_BRCB_PREFIX   "LLN0$BR$"

/* ========================================================================
 * Harness helpers
 * ======================================================================== */

/* Start the oracle server on the given port (MC-test pattern). */
static pid_t start_libiec_server(uint16_t port)
{
    char server_path[600];
    if (!interop_example_path(server_path, sizeof(server_path),
                              "server_example_basic_io",
                              "server_example_basic_io"))
        return -1;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    char *args[] = { server_path, port_str, NULL };
    pid_t pid = interop_start_bg(server_path, args, NULL);
    if (pid < 0) return -1;

    if (!interop_wait_for_port(port, 3000)) {
        interop_stop_helper(pid);
        return -1;
    }
    return pid;
}

/* Connect a client with the per-scenario request timeout. */
static int connect_client(iec61850_mms_client_t *client, uint16_t port)
{
    iec61850_mms_client_init(client);
    client->request_timeout_ms = MR_REQUEST_TIMEOUT_MS;
    return iec61850_mms_client_connect(client, "127.0.0.1", port, 5000);
}

/* Discover the oracle's (single) domain via GetNameList. */
static int discover_domain(iec61850_mms_client_t *client, char *domain,
                            size_t domain_size)
{
    char domains[8][MMS_MAX_DOMAIN_NAME];
    uint32_t count = 0;

    if (iec61850_mms_client_get_name_list(client,
                                          MMS_OBJECT_CLASS_DOMAIN,
                                          NULL, domains, &count, 8) != 0) {
        return -1;
    }
    if (count == 0) {
        return -1;
    }
    (void)snprintf(domain, domain_size, "%s", domains[0]);
    return 0;
}

/*
 * Discover RCB names with a full GetNameList sweep, filtering the
 * "...$RptEna" component pattern (the same wire observation
 * rcb_list() makes). Out names are the RCB references without the
 * trailing "$" — the client's component naming
 * (rcb_name + "$" + suffix) matches the oracle's "$"-separated
 * component objects (WP-1f DIV-1).
 *
 * prefix selects the RCB class ("LLN0$RP$" URCB / "LLN0$BR$" BRCB);
 * NULL matches any.
 */
static int discover_rcbs(iec61850_mms_client_t *client, const char *domain,
                          const char *prefix,
                          char names[][IEC61850_RCB_MAX_NAME],
                          uint32_t max_names)
{
    static char vars[MR_SCAN_MAX_VARS][MMS_MAX_VARIABLE_NAME];
    uint32_t vcount = 0;
    uint32_t found = 0;
    uint32_t i;

    if (iec61850_mms_client_get_name_list(client,
                                          MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                          domain, vars, &vcount,
                                          MR_SCAN_MAX_VARS) != 0) {
        return -1;
    }

    for (i = 0; i < vcount && found < max_names; i++) {
        size_t len = strlen(vars[i]);
        if ((len > 7U) &&
            (strcmp(&vars[i][len - 7U], "$RptEna") == 0)) {
            size_t base = len - 7U;
            if (base >= (size_t)IEC61850_RCB_MAX_NAME) {
                base = (size_t)IEC61850_RCB_MAX_NAME - 1U;
            }
            if ((prefix != NULL) &&
                (strncmp(vars[i], prefix, strlen(prefix)) != 0)) {
                continue;
            }
            (void)memcpy(names[found], vars[i], base);
            names[found][base] = '\0';
            found++;
        }
    }
    return (int)found;
}

/* Read one RCB component (rcb_name is the reference, no trailing "$"). */
static int read_component(iec61850_mms_client_t *client, const char *domain,
                           const char *rcb_name, const char *suffix,
                           mms_value_t *value)
{
    char item[MMS_MAX_VARIABLE_NAME];
    (void)snprintf(item, sizeof(item), "%s$%s", rcb_name, suffix);
    (void)memset(value, 0, sizeof(*value));
    return iec61850_mms_client_read(client, domain, item, value);
}

/* Read the BRCB EntryID component as a uint64 (big-endian octet
 * string). Returns 0 on success. */
static int read_entry_id(iec61850_mms_client_t *client, const char *domain,
                          const char *rcb_name, uint64_t *entry_id)
{
    mms_value_t value;
    int ret = read_component(client, domain, rcb_name, "EntryID", &value);
    uint32_t i;

    if (ret != 0) {
        return ret;
    }
    if ((value.type != MMS_TYPE_OCTET_STRING) ||
        (value.value.octet_string.len != 8U)) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }
    *entry_id = 0U;
    for (i = 0U; i < 8U; i++) {
        size_t idx = (size_t)i;
        *entry_id = (*entry_id << 8) |
                    (uint64_t)value.value.octet_string.data[idx];
    }
    return 0;
}

/* ========================================================================
 * Report reception context
 * ======================================================================== */

typedef struct {
    int count;                       /* reports delivered */
    char rpt_id[MMS_MAX_STRING_LENGTH];
    char dat_set[MMS_MAX_STRING_LENGTH];
    uint16_t first_sq;
    uint16_t last_sq;
    uint64_t max_ts;                 /* max timeOfEntry seen */
    uint64_t ts_barrier;             /* MR-05: reject ts <= barrier */
    bool duplicate_seen;             /* a report at/below barrier */
    bool sq_regressed;               /* sqNum decreased within stream */
    int num_values_min;              /* min num_values seen */
} report_ctx_t;

static void report_ctx_init(report_ctx_t *ctx)
{
    (void)memset(ctx, 0, sizeof(*ctx));
    ctx->num_values_min = 0x7FFFFFFF;
}

static void on_report(const mms_information_report_t *report, void *user_data)
{
    report_ctx_t *ctx = (report_ctx_t *)user_data;

    ctx->count++;
    if (ctx->count == 1) {
        (void)snprintf(ctx->rpt_id, sizeof(ctx->rpt_id), "%s",
                       report->rpt_id);
        (void)snprintf(ctx->dat_set, sizeof(ctx->dat_set), "%s",
                       report->dat_set);
        ctx->first_sq = report->sq_num;
    }
    if (report->sq_num < ctx->last_sq) {
        ctx->sq_regressed = true;
    }
    ctx->last_sq = report->sq_num;
    if ((int)report->num_values < ctx->num_values_min) {
        ctx->num_values_min = (int)report->num_values;
    }
    if (report->report_timestamp_present) {
        if (report->report_timestamp > ctx->max_ts) {
            ctx->max_ts = report->report_timestamp;
        }
        if ((ctx->ts_barrier != 0U) &&
            (report->report_timestamp <= ctx->ts_barrier)) {
            ctx->duplicate_seen = true;
        }
    }
}

static int64_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((int64_t)ts.tv_sec * 1000) +
           ((int64_t)ts.tv_nsec / 1000000);
}

/*
 * Drain reports: poll until at least `want` reports have been
 * delivered or the deadline expires. One poll dispatches at most
 * one PDU, so this loops. Returns the number of reports seen.
 */
static int drain_reports(iec61850_mms_client_t *client, report_ctx_t *ctx,
                          int want, int timeout_ms)
{
    int64_t deadline = now_ms() + (int64_t)timeout_ms;

    while ((ctx->count < want) && (now_ms() < deadline)) {
        (void)iec61850_mms_client_poll(client, 200);
    }
    return ctx->count;
}

/* Configure the standard report options (sequence number, time
 * stamp, reason-for-inclusion, data-set name, config ref — but NOT
 * buffer-overflow; see BUG-R4) and enable the RCB. */
static int enroll_rcb_with_optflds(iec61850_mms_client_t *client,
                                    const char *domain,
                                    const char *rcb_name)
{
    iec61850_mms_client_rcb_values_t values;
    (void)memset(&values, 0, sizeof(values));
    values.attrs.opt_flds.sequence_number = true;
    values.attrs.opt_flds.report_timestamp = true;
    values.attrs.opt_flds.reason_for_inclusion = true;
    values.attrs.opt_flds.data_set_name = true;
    values.attrs.opt_flds.config_ref = true;
    values.attrs.rpt_ena = true;
    return iec61850_mms_client_rcb_set_values(client, domain, rcb_name,
                                               &values,
                                               IEC61850_RCB_FIELD_OPT_FLDS |
                                               IEC61850_RCB_FIELD_RPT_ENA);
}

/* ========================================================================
 * MR-01: connect; discover RCBs via rcb_list on the server's domain
 * ======================================================================== */

static void test_mr01_rcb_discovery(void)
{
    INTEROP_TEST("MR-01: connect + RCB discovery via rcb_list");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    int ret = connect_client(&client, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    /* Domain discovery via our client's get_name_list. */
    char domain[MMS_MAX_DOMAIN_NAME];
    ret = discover_domain(&client, domain, sizeof(domain));

    /* Ground truth: full sweep proves the oracle's model has RCBs. */
    char all_rcbs[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    int rcb_total = -1;
    if (ret == 0) {
        rcb_total = discover_rcbs(&client, domain, NULL, all_rcbs,
                                   MR_MAX_RCBS);
    }

    /* The operation under test: rcb_list on the discovered domain. */
    char listed[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    uint32_t listed_count = 0;
    int list_ret = -1;
    if (ret == 0) {
        list_ret = iec61850_mms_client_rcb_list(&client, domain, listed,
                                                 &listed_count,
                                                 MR_MAX_RCBS);
    }

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(rcb_total > 0); /* oracle model provides RCBs */

    if ((list_ret != IEC61850_MMS_CLIENT_OK) || (listed_count == 0U)) {
        /*
         * BUG-R1 (mms_client_rcb.c): rcb_list()'s internal
         * GetNameList sweep is capped at 128 names (32 KiB stack
         * buffer), but the oracle's domain exposes 304 named
         * variables with the first "...$RptEna" component at index
         * 141 — beyond the cap. rcb_list() therefore reports an
         * empty model on a stock libiec61850 server while the
         * manual sweep above finds %d RCBs. Library sources are
         * frozen for WP-1d; minimized and reported for a fix WP.
         */
        printf("       (BUG-R1: manual sweep found %d RCB(s), "
               "rcb_list found %u)\n",
               rcb_total, (unsigned)listed_count);
        INTEROP_FAIL("rcb_list scan cap misses oracle RCBs (BUG-R1)");
    }

    INTEROP_ASSERT(listed_count >= 1U);
    INTEROP_PASS();
}

/* ========================================================================
 * MR-02: read RCB values (rcb_get_values)
 * ======================================================================== */

static void test_mr02_rcb_get_values(void)
{
    INTEROP_TEST("MR-02: read RCB values via rcb_get_values");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    int ret = connect_client(&client, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char domain[MMS_MAX_DOMAIN_NAME];
    char rcbs[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    ret = discover_domain(&client, domain, sizeof(domain));
    int n_urcb = -1;
    if (ret == 0) {
        n_urcb = discover_rcbs(&client, domain, MR_URCB_PREFIX, rcbs,
                                MR_MAX_RCBS);
    }

    /* The operation under test: rcb_get_values on an oracle URCB
     * (reference as discovered, verbatim). */
    int gv = -1;
    iec61850_mms_client_rcb_values_t values;
    (void)memset(&values, 0, sizeof(values));
    bool got_values = false;
    if ((ret == 0) && (n_urcb > 0)) {
        gv = iec61850_mms_client_rcb_get_values(&client, domain,
                                                 rcbs[0], &values);
        got_values = (gv == IEC61850_MMS_CLIENT_OK);
    }

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    if (n_urcb <= 0) INTEROP_SKIP("oracle model has no URCB");

    if (!got_values) {
        /*
         * BUG-R2 (mms_ber.c read-response decode + core dispatch):
         * rcb_get_values() reads all components and treats absent
         * optional components (ERR_MMS) as "not present". The
         * oracle answers the Owner read (no Owner component in its
         * model) with a Read-Response carrying a failure
         * AccessResult:
         *   a1 0a 02 01 01 a4 05 a1 03 80 01 0a
         * Our decoder rejects this valid PDU, the core leaves the
         * request pending, and the client stalls for the full
         * request timeout before returning ERR_TIMEOUT (-5)
         * instead of ERR_MMS (-6). Minimized: read of
         * LLN0$RP$EventsIndexed01$Owner alone reproduces it.
         * Frozen for WP-1d; reported for a fix WP.
         */
        printf("       (BUG-R2: rcb_get_values returned %d at the "
               "absent Owner component)\n", gv);
        INTEROP_FAIL("rcb_get_values stalls on absent component (BUG-R2)");
    }

    /* If the bug is fixed upstream, the aggregation must succeed. */
    INTEROP_ASSERT(values.buffered == false); /* URCB */
    INTEROP_ASSERT(strlen(values.attrs.rpt_id) > 0U);
    INTEROP_ASSERT(strlen(values.attrs.dat_set) > 0U);
    INTEROP_PASS();
}

/* ========================================================================
 * MR-02b: RCB component presence/types via plain reads
 * ======================================================================== */

static void test_mr02b_component_types(void)
{
    INTEROP_TEST("MR-02b: RCB component presence and types (direct reads)");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    int ret = connect_client(&client, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char domain[MMS_MAX_DOMAIN_NAME];
    char rcbs[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    ret = discover_domain(&client, domain, sizeof(domain));
    int n_urcb = -1;
    int n_brcb = -1;
    char brcbs[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    if (ret == 0) {
        n_urcb = discover_rcbs(&client, domain, MR_URCB_PREFIX, rcbs,
                                MR_MAX_RCBS);
        n_brcb = discover_rcbs(&client, domain, MR_BRCB_PREFIX, brcbs,
                                MR_MAX_RCBS);
    }

    /* Verify every component read succeeds with the expected type.
     * All of these objects exist in the oracle's model, so the
     * reads avoid the BUG-R2 failure path. */
    int failures = 0;
    mms_value_t v;

    if ((ret == 0) && (n_urcb > 0)) {
        static const struct {
            const char *suffix;
            mms_type_t type;
        } urcb_comps[] = {
            { "RptEna",   MMS_TYPE_BOOLEAN },
            { "RptID",    MMS_TYPE_VISIBLE_STRING },
            { "DatSet",   MMS_TYPE_VISIBLE_STRING },
            { "ConfRev",  MMS_TYPE_UNSIGNED },
            { "OptFlds",  MMS_TYPE_BIT_STRING },
            { "BufTm",    MMS_TYPE_UNSIGNED },
            { "TrgOps",   MMS_TYPE_BIT_STRING },
            { "IntgPd",   MMS_TYPE_UNSIGNED },
            { "GI",       MMS_TYPE_BOOLEAN },
            { "Resv",     MMS_TYPE_BOOLEAN },   /* URCB-only */
            { "SqNum",    MMS_TYPE_UNSIGNED },
        };
        for (size_t i = 0; i < sizeof(urcb_comps) / sizeof(urcb_comps[0]); i++) {
            int rc = read_component(&client, domain, rcbs[0],
                                     urcb_comps[i].suffix, &v);
            if ((rc != IEC61850_MMS_CLIENT_OK) ||
                (v.type != urcb_comps[i].type)) {
                printf("       URCB %s: rc=%d type=%d (want %d)\n",
                       urcb_comps[i].suffix, rc, (int)v.type,
                       (int)urcb_comps[i].type);
                failures++;
            }
        }
        /* Bit-string widths observed on the oracle: OptFlds 10 bits,
         * TrgOps 6 bits (IEC 61850-7-2/8-1 widths, matching our
         * client's encoding). */
        if (read_component(&client, domain, rcbs[0], "OptFlds", &v) == 0) {
            if (v.value.bit_string.bit_count != 10U) {
                printf("       URCB OptFlds bit count %zu (want 10)\n",
                       v.value.bit_string.bit_count);
                failures++;
            }
        }
        if (read_component(&client, domain, rcbs[0], "TrgOps", &v) == 0) {
            if (v.value.bit_string.bit_count != 6U) {
                printf("       URCB TrgOps bit count %zu (want 6)\n",
                       v.value.bit_string.bit_count);
                failures++;
            }
        }
    }

    if ((ret == 0) && (n_brcb > 0)) {
        static const struct {
            const char *suffix;
            mms_type_t type;
        } brcb_comps[] = {
            { "RptEna",   MMS_TYPE_BOOLEAN },
            { "RptID",    MMS_TYPE_VISIBLE_STRING },
            { "DatSet",   MMS_TYPE_VISIBLE_STRING },
            { "ConfRev",  MMS_TYPE_UNSIGNED },
            { "OptFlds",  MMS_TYPE_BIT_STRING },
            { "BufTm",    MMS_TYPE_UNSIGNED },
            { "TrgOps",   MMS_TYPE_BIT_STRING },
            { "IntgPd",   MMS_TYPE_UNSIGNED },
            { "SqNum",    MMS_TYPE_UNSIGNED },
            { "EntryID",  MMS_TYPE_OCTET_STRING }, /* BRCB-only */
            { "PurgeBuf", MMS_TYPE_BOOLEAN },      /* BRCB-only */
        };
        for (size_t i = 0; i < sizeof(brcb_comps) / sizeof(brcb_comps[0]); i++) {
            int rc = read_component(&client, domain, brcbs[0],
                                     brcb_comps[i].suffix, &v);
            if ((rc != IEC61850_MMS_CLIENT_OK) ||
                (v.type != brcb_comps[i].type)) {
                printf("       BRCB %s: rc=%d type=%d (want %d)\n",
                       brcb_comps[i].suffix, rc, (int)v.type,
                       (int)brcb_comps[i].type);
                failures++;
            }
        }
        /* EntryID is an 8-byte octet string on the wire. */
        if (read_component(&client, domain, brcbs[0], "EntryID", &v) == 0) {
            if (v.value.octet_string.len != 8U) {
                printf("       BRCB EntryID length %zu (want 8)\n",
                       v.value.octet_string.len);
                failures++;
            }
        }
    }

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    if (n_urcb <= 0) INTEROP_SKIP("oracle model has no URCB");
    INTEROP_ASSERT_EQ(failures, 0);
    INTEROP_PASS();
}

/* ========================================================================
 * MR-03: URCB enrollment (Resv + RptEna) + report reception
 * ======================================================================== */

static void test_mr03_urcb_enrollment(void)
{
    INTEROP_TEST("MR-03: URCB enrollment + report reception");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    int ret = connect_client(&client, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char domain[MMS_MAX_DOMAIN_NAME];
    char rcbs[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    ret = discover_domain(&client, domain, sizeof(domain));
    int n_urcb = -1;
    if (ret == 0) {
        n_urcb = discover_rcbs(&client, domain, MR_URCB_PREFIX, rcbs,
                                MR_MAX_RCBS);
    }
    if ((ret == 0) && (n_urcb <= 0)) {
        iec61850_mms_client_disconnect(&client);
        interop_stop_helper(srv);
        g_port++;
        INTEROP_SKIP("oracle model has no URCB");
    }

    /* Enroll: reserve + enable (the RCB keeps its preconfigured
     * datSet/OptFlds/TrgOps; the model's integrity period is
     * 1000 ms, so reports are integrity-triggered — the Events
     * dataset values are static, no dchg trigger is observable).
     * Note: set_values' return code is not trustworthy here
     * (BUG-R3 masks in-band write failures), so the scenario
     * asserts on actual report reception instead. */
    report_ctx_t ctx;
    report_ctx_init(&ctx);
    (void)iec61850_mms_client_set_report_handler(&client, on_report, &ctx);

    iec61850_mms_client_rcb_values_t values;
    (void)memset(&values, 0, sizeof(values));
    values.resv = true;
    values.attrs.rpt_ena = true;
    (void)iec61850_mms_client_rcb_set_values(&client, domain, rcbs[0],
                                              &values,
                                              IEC61850_RCB_FIELD_RESV |
                                              IEC61850_RCB_FIELD_RPT_ENA);

    /* Wait for the model's 1 s integrity reports. */
    (void)drain_reports(&client, &ctx, 2, 8000);

    (void)iec61850_mms_client_rcb_disable(&client, domain, rcbs[0]);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(ctx.count >= 2);
    INTEROP_ASSERT(strlen(ctx.rpt_id) > 0U);      /* sensible rptID */
    INTEROP_ASSERT(strlen(ctx.dat_set) > 0U);     /* sensible datSet */
    INTEROP_ASSERT(ctx.num_values_min >= 1);      /* dataset values */
    INTEROP_ASSERT(!ctx.sq_regressed);            /* sqNum monotonic */
    INTEROP_ASSERT((uint32_t)(ctx.last_sq - ctx.first_sq) + 1U ==
                   (uint32_t)ctx.count);          /* sqNum increments */
    INTEROP_PASS();
}

/* ========================================================================
 * MR-04: BRCB enrollment + buffered report + EntryID readback
 * ======================================================================== */

static void test_mr04_brcb_enrollment(void)
{
    INTEROP_TEST("MR-04: BRCB enrollment + buffered report + EntryID");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    int ret = connect_client(&client, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char domain[MMS_MAX_DOMAIN_NAME];
    char rcbs[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    ret = discover_domain(&client, domain, sizeof(domain));
    int n_brcb = -1;
    if (ret == 0) {
        n_brcb = discover_rcbs(&client, domain, MR_BRCB_PREFIX, rcbs,
                                MR_MAX_RCBS);
    }
    if ((ret == 0) && (n_brcb <= 0)) {
        iec61850_mms_client_disconnect(&client);
        interop_stop_helper(srv);
        g_port++;
        INTEROP_SKIP("oracle model has no BRCB");
    }

    /* EntryID before enrollment. */
    uint64_t entry0 = 0U;
    int eid_ret = read_entry_id(&client, domain, rcbs[0], &entry0);

    /*
     * Enroll with explicit OptFlds (standard Ed.2 client procedure:
     * configure report options, then enable). The option set
     * deliberately excludes buffer-overflow: the oracle's BRCB
     * default optFlds (0x7a) include it, and our report decoder
     * does not parse the bufOvfl field (BUG-R4, isolated in
     * MR-04b). No reservation is written — the oracle's BRCBs use
     * Ed.2 ResvTms (not Resv), and the EntryID/RptEna path works
     * unreserved.
     */
    report_ctx_t ctx;
    report_ctx_init(&ctx);
    (void)iec61850_mms_client_set_report_handler(&client, on_report, &ctx);
    (void)enroll_rcb_with_optflds(&client, domain, rcbs[0]);

    /* Buffered entries accumulated since server start are delivered
     * immediately on enable; the model's integrity period keeps
     * them coming at 1 s. */
    (void)drain_reports(&client, &ctx, 2, 8000);

    /* Read back EntryID and SqNum after reports flowed. */
    uint64_t entry1 = 0U;
    int eid_ret2 = read_entry_id(&client, domain, rcbs[0], &entry1);
    mms_value_t sq;
    int sq_ret = read_component(&client, domain, rcbs[0], "SqNum", &sq);

    (void)iec61850_mms_client_rcb_disable(&client, domain, rcbs[0]);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(eid_ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(eid_ret2, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(ctx.count >= 2);
    INTEROP_ASSERT(strlen(ctx.rpt_id) > 0U);
    INTEROP_ASSERT(strlen(ctx.dat_set) > 0U);
    INTEROP_ASSERT(ctx.num_values_min >= 1);
    INTEROP_ASSERT(!ctx.sq_regressed);
    /* EntryID advanced while reporting (new buffered entries). */
    INTEROP_ASSERT(entry1 != entry0);
    /* SqNum component readable after reports. */
    INTEROP_ASSERT_EQ(sq_ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(sq.type == MMS_TYPE_UNSIGNED);
    INTEROP_PASS();
}

/* ========================================================================
 * MR-04b: BRCB reports with the server-default optFlds (bufOvfl)
 * ======================================================================== */

static void test_mr04b_brcb_default_optflds(void)
{
    INTEROP_TEST("MR-04b: BRCB report decode w/ server-default optFlds");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    int ret = connect_client(&client, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char domain[MMS_MAX_DOMAIN_NAME];
    char rcbs[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    ret = discover_domain(&client, domain, sizeof(domain));
    int n_brcb = -1;
    if (ret == 0) {
        n_brcb = discover_rcbs(&client, domain, MR_BRCB_PREFIX, rcbs,
                                MR_MAX_RCBS);
    }
    if ((ret == 0) && (n_brcb <= 0)) {
        iec61850_mms_client_disconnect(&client);
        interop_stop_helper(srv);
        g_port++;
        INTEROP_SKIP("oracle model has no BRCB");
    }

    /* Enable without touching OptFlds: the BRCB keeps its default
     * options (0x7a = seqNum|timestamp|reason|datSet|bufOvfl). */
    report_ctx_t ctx;
    report_ctx_init(&ctx);
    (void)iec61850_mms_client_set_report_handler(&client, on_report, &ctx);
    (void)iec61850_mms_client_rcb_enable(&client, domain, rcbs[0]);

    /* Drain: watch for decode failures (-8) vs handler delivery. */
    bool saw_decode_error = false;
    int64_t deadline = now_ms() + 5000;
    while (now_ms() < deadline) {
        int pr = iec61850_mms_client_poll(&client, 300);
        if (pr == IEC61850_MMS_CLIENT_ERR_DECODE) {
            saw_decode_error = true;
        }
        if (ctx.count > 0) {
            break;
        }
    }

    /* Confirm the BRCB is actually enabled and reporting. */
    mms_value_t ena;
    int ena_ret = read_component(&client, domain, rcbs[0], "RptEna", &ena);
    bool enabled = (ena_ret == IEC61850_MMS_CLIENT_OK) &&
                   (ena.type == MMS_TYPE_BOOLEAN) && ena.value.boolean;

    (void)iec61850_mms_client_rcb_disable(&client, domain, rcbs[0]);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(enabled); /* oracle is sending reports */

    if ((ctx.count == 0) && saw_decode_error) {
        /*
         * BUG-R4 (mms_ber.c, mms_decode_iec61850_report): the
         * oracle's BRCB reports include the buffer-overflow
         * optional field (BOOLEAN [3]) between datSet and confRev:
         *   ... 8a 1d <datSet> 83 01 01 86 01 01 84 02 04 f0 ...
         * The decoder expects confRev ([6], 0x86) directly after
         * datSet, rejects the PDU, and the core drops the report;
         * poll() surfaces it as ERR_DECODE (-8) and the report
         * handler never fires. MR-04 shows the same data path
         * works when the client configures OptFlds without the
         * buffer-overflow bit. Frozen for WP-1d; reported for a
         * fix WP.
         */
        INTEROP_FAIL("BRCB report with bufOvfl field fails to decode (BUG-R4)");
    }

    /* If the reports decoded (bug fixed upstream), that is a pass. */
    INTEROP_ASSERT(ctx.count > 0);
    INTEROP_PASS();
}

/* ========================================================================
 * MR-05: BRCB resume after reconnect (EntryID)
 * ======================================================================== */

static void test_mr05_brcb_resume(void)
{
    INTEROP_TEST("MR-05: BRCB resume after reconnect via EntryID");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    /* Session 1: enroll, receive reports, note the last EntryID. */
    iec61850_mms_client_t client;
    int ret = connect_client(&client, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char domain[MMS_MAX_DOMAIN_NAME];
    char rcbs[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    ret = discover_domain(&client, domain, sizeof(domain));
    int n_brcb = -1;
    if (ret == 0) {
        n_brcb = discover_rcbs(&client, domain, MR_BRCB_PREFIX, rcbs,
                                MR_MAX_RCBS);
    }
    if ((ret == 0) && (n_brcb <= 0)) {
        iec61850_mms_client_disconnect(&client);
        interop_stop_helper(srv);
        g_port++;
        INTEROP_SKIP("oracle model has no BRCB");
    }

    report_ctx_t ctx;
    report_ctx_init(&ctx);
    (void)iec61850_mms_client_set_report_handler(&client, on_report, &ctx);
    (void)enroll_rcb_with_optflds(&client, domain, rcbs[0]);
    (void)drain_reports(&client, &ctx, 1, 8000);

    uint64_t entry1 = 0U;
    int eid_ret = read_entry_id(&client, domain, rcbs[0], &entry1);
    uint64_t ts_before = ctx.max_ts;

    iec61850_mms_client_disconnect(&client);

    /* Let the BRCB buffer accumulate while no client is attached. */
    sleep(2);

    /* Session 2: reconnect, resume from the last EntryID. */
    iec61850_mms_client_t client2;
    ret = connect_client(&client2, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("reconnect failed");
    }

    report_ctx_t ctx2;
    report_ctx_init(&ctx2);
    ctx2.ts_barrier = ts_before; /* reject pre-disconnect replays */
    (void)iec61850_mms_client_set_report_handler(&client2, on_report, &ctx2);

    /* The WP-1c resume feature under test: set the last EntryID,
     * then re-enable. (Acceptance of the EntryID write itself is
     * not observable through the client API — BUG-R3 masks the
     * in-band write result — but the resulting report stream is:
     * without the EntryID, the oracle replays pre-disconnect
     * entries; with it, only entries buffered after it.) */
    (void)iec61850_mms_client_rcb_set_entry_id(&client2, domain, rcbs[0],
                                                entry1);
    (void)iec61850_mms_client_rcb_enable(&client2, domain, rcbs[0]);
    (void)drain_reports(&client2, &ctx2, 1, 8000);

    uint64_t entry2 = 0U;
    int eid_ret2 = read_entry_id(&client2, domain, rcbs[0], &entry2);

    (void)iec61850_mms_client_rcb_disable(&client2, domain, rcbs[0]);
    iec61850_mms_client_disconnect(&client2);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(eid_ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(eid_ret2, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(ctx.count >= 1);       /* reports before disconnect */
    INTEROP_ASSERT(ctx2.count >= 1);      /* reporting resumed */
    /* All resumed reports are newer than everything received
     * before the disconnect: no duplicate replay. */
    INTEROP_ASSERT(!ctx2.duplicate_seen);
    INTEROP_ASSERT(ctx2.max_ts > ts_before);
    INTEROP_ASSERT(strlen(ctx2.rpt_id) > 0U);
    INTEROP_ASSERT(strlen(ctx2.dat_set) > 0U);
    INTEROP_ASSERT(!ctx2.sq_regressed);
    /* The buffer advanced past the resume point. */
    INTEROP_ASSERT(entry2 != entry1);
    /* sqNum continuity across the resume is not asserted: the
     * oracle restarts report sqNum at 0 per enable-session
     * (observed on the wire), so only within-stream monotonicity
     * is observable. */
    INTEROP_PASS();
}

/* ========================================================================
 * MR-06: RCB ownership (Resv on an RCB held by another client)
 * ======================================================================== */

static void test_mr06_ownership(void)
{
    INTEROP_TEST("MR-06: ownership conflict on a held URCB (two clients)");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    /* Two client connections from the same test process. */
    iec61850_mms_client_t a, b;
    int ret = connect_client(&a, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("client A connect failed");
    }
    ret = connect_client(&b, g_port);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        iec61850_mms_client_disconnect(&a);
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("client B connect failed");
    }

    char domain[MMS_MAX_DOMAIN_NAME];
    char rcbs[MR_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    ret = discover_domain(&a, domain, sizeof(domain));
    int n_urcb = -1;
    if (ret == 0) {
        n_urcb = discover_rcbs(&a, domain, MR_URCB_PREFIX, rcbs,
                                MR_MAX_RCBS);
    }
    if ((ret == 0) && (n_urcb <= 0)) {
        iec61850_mms_client_disconnect(&a);
        iec61850_mms_client_disconnect(&b);
        interop_stop_helper(srv);
        g_port++;
        INTEROP_SKIP("oracle model has no URCB");
    }

    /* A reserves the URCB. */
    iec61850_mms_client_rcb_values_t rv;
    (void)memset(&rv, 0, sizeof(rv));
    rv.resv = true;
    int a_resv = iec61850_mms_client_rcb_set_values(
        &a, domain, rcbs[0], &rv, IEC61850_RCB_FIELD_RESV);

    /* B attempts to reserve + enable the same URCB. */
    iec61850_mms_client_rcb_values_t bv;
    (void)memset(&bv, 0, sizeof(bv));
    bv.resv = true;
    bv.attrs.rpt_ena = true;
    int b_enroll = iec61850_mms_client_rcb_set_values(
        &b, domain, rcbs[0], &bv,
        IEC61850_RCB_FIELD_RESV | IEC61850_RCB_FIELD_RPT_ENA);

    /* Ground truth via read-back: the oracle enforces ownership. */
    mms_value_t ena, resv;
    int ena_ret = read_component(&b, domain, rcbs[0], "RptEna", &ena);
    int resv_ret = read_component(&b, domain, rcbs[0], "Resv", &resv);
    bool b_rejected = (ena_ret == IEC61850_MMS_CLIENT_OK) &&
                      (ena.type == MMS_TYPE_BOOLEAN) &&
                      !ena.value.boolean;
    bool held = (resv_ret == IEC61850_MMS_CLIENT_OK) &&
                (resv.type == MMS_TYPE_BOOLEAN) && resv.value.boolean;

    /* A releases. */
    (void)iec61850_mms_client_rcb_disable(&a, domain, rcbs[0]);
    iec61850_mms_client_disconnect(&a);
    iec61850_mms_client_disconnect(&b);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(a_resv, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(b_rejected); /* oracle rejected B's enrollment */
    INTEROP_ASSERT(held);       /* reservation still held (by A) */

    if (b_enroll == IEC61850_MMS_CLIENT_OK) {
        /*
         * BUG-R3 (mms_ber.c write-response decode): B's Resv and
         * RptEna writes were rejected by the oracle in-band —
         * Write-Response failure:
         *   a1 08 02 01 01 a5 03 80 01 02
         * (failure [0] DataAccessError=2) — but our decoder skips
         * the Write-Response result entirely, so set_values
         * reported success (rc=0). The read-back above proves the
         * writes did not take effect. With the write result
         * unparsed, IEC61850_MMS_CLIENT_ERR_RCB_OWNER is
         * unreachable against this oracle (its RCBs also expose no
         * readable Owner component). Frozen for WP-1d; reported
         * for a fix WP.
         */
        printf("       (BUG-R3: B's rejected enrollment returned rc=0)\n");
        INTEROP_FAIL("rejected Resv write reported as success (BUG-R3)");
    }

    /* If the rejection is surfaced (bug fixed upstream), pass. */
    INTEROP_ASSERT(b_enroll == IEC61850_MMS_CLIENT_ERR_RCB_OWNER);
    INTEROP_PASS();
}

int main(void)
{
    printf("\n=== MMS Reporting Interop: xdp client ↔ libiec61850 ===\n");

    test_mr01_rcb_discovery();
    test_mr02_rcb_get_values();
    test_mr02b_component_types();
    test_mr03_urcb_enrollment();
    test_mr04_brcb_enrollment();
    test_mr04b_brcb_default_optflds();
    test_mr05_brcb_resume();
    test_mr06_ownership();

    INTEROP_SUMMARY();
    return interop_tests_failed > 0 ? 1 : 0;
}
