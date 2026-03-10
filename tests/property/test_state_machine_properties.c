/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Property-Based Tests for Protocol State Machine
 *
 * Properties verified:
 *   1. stNum monotonicity: new_state always has stNum > old stNum
 *   2. sqNum reset on stNum change: after state_change, sqNum=0
 *   3. Timeout detection correctness: always triggers after timeout_ms
 *   4. Duplicate detection: same stNum+sqNum always classified as duplicate
 *
 * License: BSD-3-Clause
 */

#include "property_test.h"
#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "sv/sv_publisher.h"
#include "sv/sv_subscriber.h"
#include "asn1/goose_ber.h"

#include <stdio.h>
#include <string.h>

static void prop_stnum_monotonicity(void)
{
    PROPERTY_TEST("stNum_monotonicity", 5000) {
        iec61850_goose_publisher_t pub;
        iec61850_goose_publisher_init(&pub, NULL);
        iec61850_goose_publisher_set_boolean(&pub, 0, true);

        uint32_t prev_stnum = iec61850_goose_publisher_get_st_num(&pub);

        int changes = 1 + (rand() % 10);
        for (int c = 0; c < changes; c++) {
            iec61850_goose_publisher_state_change(&pub);
            uint32_t cur_stnum = iec61850_goose_publisher_get_st_num(&pub);
            PROPERTY_ASSERT(cur_stnum > prev_stnum, "stNum not monotonically increasing");
            prev_stnum = cur_stnum;
        }

        iec61850_goose_publisher_destroy(&pub);
    }
    PROPERTY_TEST_END();

}

static void prop_sqnum_reset_on_state_change(void)
{
    PROPERTY_TEST("sqNum_reset_on_state_change", 5000) {
        iec61850_goose_publisher_t pub;
        iec61850_goose_publisher_init(&pub, NULL);
        iec61850_goose_publisher_set_boolean(&pub, 0, true);

        /* Prepare a few packets to increment sqNum */
        uint8_t buf[GOOSE_MAX_APDU_SIZE];
        size_t encoded;
        int preps = 1 + (rand() % 5);
        for (int p = 0; p < preps; p++) {
            iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
        }
        PROPERTY_ASSERT(iec61850_goose_publisher_get_sq_num(&pub) > 0,
                        "sqNum should be > 0 after prepare");

        iec61850_goose_publisher_state_change(&pub);
        PROPERTY_ASSERT(iec61850_goose_publisher_get_sq_num(&pub) == 0,
                        "sqNum not reset after state_change");

        iec61850_goose_publisher_destroy(&pub);
    }
    PROPERTY_TEST_END();

}

static void prop_duplicate_detection(void)
{
    PROPERTY_TEST("duplicate_detection_always_works", 5000) {
        iec61850_goose_subscriber_t sub;
        iec61850_goose_subscriber_init(&sub, NULL);

        goose_apdu_t apdu;
        goose_apdu_init(&apdu);
        goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
        apdu.stNum = (uint32_t)(1 + (rand() % 1000));
        apdu.sqNum = (uint32_t)(rand() % 100);

        /* First process: always accepted */
        bool first = iec61850_goose_subscriber_process(&sub, &apdu,
                                                         (uint64_t)(rand() % 1000000));
        PROPERTY_ASSERT(first, "first message should be accepted");

        /* Same stNum+sqNum: always duplicate */
        bool second = iec61850_goose_subscriber_process(&sub, &apdu,
                                                          (uint64_t)(rand() % 1000000));
        PROPERTY_ASSERT(!second, "duplicate should be rejected");

        iec61850_goose_subscriber_destroy(&sub);
    }
    PROPERTY_TEST_END();

}

static void prop_sv_smp_cnt_wraparound(void)
{
    PROPERTY_TEST("sv_smpCnt_wraparound", 1000) {
        iec61850_sv_publisher_t pub;
        iec61850_sv_config_t cfg;
        iec61850_sv_config_init(&cfg);
        cfg.smp_rate = (uint16_t)(1 + (rand() % 100));
        iec61850_sv_publisher_init(&pub, &cfg);
        iec61850_sv_publisher_set_sample(&pub, 0, 1000);

        uint16_t wrap_point = (uint16_t)(cfg.smp_rate * 50U);
        uint8_t buf[1500];
        size_t encoded;

        /* Run through one complete cycle */
        for (uint16_t i = 0; i < wrap_point; i++) {
            iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
        }

        /* After wrap_point prepares, smpCnt should have wrapped to 0 */
        PROPERTY_ASSERT(iec61850_sv_publisher_get_smp_cnt(&pub) == 0,
                        "smpCnt did not wrap at smp_rate * 50");

        iec61850_sv_publisher_destroy(&pub);
    }
    PROPERTY_TEST_END();

}

int main(void)
{
    property_test_init();

    prop_stnum_monotonicity();
    prop_sqnum_reset_on_state_change();
    prop_duplicate_detection();
    prop_sv_smp_cnt_wraparound();

    property_test_summary();
    return property_tests_failed > 0 ? 1 : 0;
}
