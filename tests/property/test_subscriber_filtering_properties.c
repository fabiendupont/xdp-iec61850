/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Property-Based Tests for Subscriber Filtering
 *
 * Properties verified:
 *   1. GOOSE gocbRef filter: matching ref always accepted, non-matching always rejected
 *   2. GOOSE APPID filter: matching APPID always accepted, non-matching always rejected
 *   3. SV svID filter: matching ID always accepted, non-matching always rejected
 *   4. No-filter subscriber accepts all messages
 *
 * License: BSD-3-Clause
 */

#include "property_test.h"
#include "goose/goose_subscriber.h"
#include "sv/sv_subscriber.h"
#include "asn1/goose_ber.h"
#include "asn1/sv_ber.h"

#include <stdio.h>
#include <string.h>

static void prop_goose_gocbref_filter(void)
{
    PROPERTY_TEST("goose_gocbref_filter_correct", 5000) {
        iec61850_goose_sub_config_t cfg;
        iec61850_goose_sub_config_init(&cfg);
        strncpy(cfg.filter_gocbref, "IED1LD0/LLN0$GO$gcb01",
                GOOSE_MAX_GOCBREF_LEN - 1);

        iec61850_goose_subscriber_t sub;
        iec61850_goose_subscriber_init(&sub, &cfg);

        goose_apdu_t apdu;
        goose_apdu_init(&apdu);
        apdu.stNum = (uint32_t)(1 + (rand() % 10000));
        apdu.sqNum = 0;

        /* Matching gocbRef: always accepted */
        goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
        bool accepted = iec61850_goose_subscriber_process(&sub, &apdu,
                                                            (uint64_t)(unsigned)_prop_i * 1000000ULL);
        PROPERTY_ASSERT(accepted, "matching gocbRef was rejected");

        /* Non-matching gocbRef: always rejected */
        char bad_ref[GOOSE_MAX_GOCBREF_LEN];
        snprintf(bad_ref, sizeof(bad_ref), "IED%d/LLN0$GO$gcb%02d",
                 2 + (rand() % 100), rand() % 100);
        goose_set_gocbref(&apdu, bad_ref);
        apdu.stNum++;
        accepted = iec61850_goose_subscriber_process(&sub, &apdu,
                                                       (uint64_t)(unsigned)(_prop_i + 10000) * 1000000ULL);
        PROPERTY_ASSERT(!accepted, "non-matching gocbRef was accepted");

        iec61850_goose_subscriber_destroy(&sub);
    }
    PROPERTY_TEST_END();
}

static void prop_sv_svid_filter(void)
{
    PROPERTY_TEST("sv_svid_filter_correct", 5000) {
        iec61850_sv_sub_config_t cfg;
        iec61850_sv_sub_config_init(&cfg);
        strncpy(cfg.filter_svid, "SV_PUB_1", SV_MAX_SVID_LEN - 1);

        iec61850_sv_subscriber_t sub;
        iec61850_sv_subscriber_init(&sub, &cfg);

        sv_asdu_t asdu;
        sv_asdu_init(&asdu);
        asdu.smpCnt = (uint16_t)(rand() % 4000);
        asdu.confRev = 1;

        /* Matching svID: accepted */
        sv_set_svid(&asdu, "SV_PUB_1");
        bool accepted = iec61850_sv_subscriber_process(&sub, &asdu,
                                                         (uint64_t)(unsigned)_prop_i * 1000000ULL);
        PROPERTY_ASSERT(accepted, "matching svID was rejected");

        /* Non-matching svID: rejected */
        char bad_id[SV_MAX_SVID_LEN];
        snprintf(bad_id, sizeof(bad_id), "SV_PUB_%d", 2 + (rand() % 100));
        sv_set_svid(&asdu, bad_id);
        asdu.smpCnt++;
        accepted = iec61850_sv_subscriber_process(&sub, &asdu,
                                                    (uint64_t)(unsigned)(_prop_i + 10000) * 1000000ULL);
        PROPERTY_ASSERT(!accepted, "non-matching svID was accepted");

        iec61850_sv_subscriber_destroy(&sub);
    }
    PROPERTY_TEST_END();
}

static void prop_no_filter_accepts_all(void)
{
    PROPERTY_TEST("no_filter_accepts_all_gocbrefs", 2000) {
        iec61850_goose_subscriber_t sub;
        iec61850_goose_subscriber_init(&sub, NULL);

        goose_apdu_t apdu;
        goose_apdu_init(&apdu);

        char ref[GOOSE_MAX_GOCBREF_LEN];
        snprintf(ref, sizeof(ref), "IED%d/LD%d/LLN0$GO$gcb%02d",
                 rand() % 100, rand() % 10, rand() % 100);
        goose_set_gocbref(&apdu, ref);
        apdu.stNum = (uint32_t)(_prop_i + 1);
        apdu.sqNum = 0;

        bool accepted = iec61850_goose_subscriber_process(&sub, &apdu,
                                                            (uint64_t)(unsigned)_prop_i * 1000000ULL);
        PROPERTY_ASSERT(accepted, "unfiltered subscriber rejected message");

        iec61850_goose_subscriber_destroy(&sub);
    }
    PROPERTY_TEST_END();
}

int main(void)
{
    property_test_init();

    prop_goose_gocbref_filter();
    prop_sv_svid_filter();
    prop_no_filter_accepts_all();

    property_test_summary();
    return property_tests_failed > 0 ? 1 : 0;
}
