/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for MMS Journal Service
 */

#include "mms/mms_journal.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static void test_journal_init(void)
{
    iec61850_journal_t journal;
    iec61850_journal_init(&journal, "TestJournal");

    assert(journal.count == 0);
    assert(journal.next_entry_id == 1);
    assert(strcmp(journal.journal_name, "TestJournal") == 0);
    printf("  PASS: journal init\n");
}

static void test_journal_add_entry(void)
{
    iec61850_journal_t journal;
    mms_value_t val;

    iec61850_journal_init(&journal, "J1");

    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;

    uint64_t id1 = iec61850_journal_add_entry(&journal, "LD0/LN0$ST$val",
                                                 &val, 1000);
    assert(id1 == 1);
    assert(journal.count == 1);

    val.value.integer = 99;
    uint64_t id2 = iec61850_journal_add_entry(&journal, "LD0/LN0$ST$val",
                                                 &val, 2000);
    assert(id2 == 2);
    assert(journal.count == 2);

    printf("  PASS: add entries\n");
}

static void test_journal_read_by_time(void)
{
    iec61850_journal_t journal;
    iec61850_journal_entry_t out[16];
    uint32_t count = 0;
    mms_value_t val;

    iec61850_journal_init(&journal, "J2");

    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_FLOATING_POINT;

    for (int i = 0; i < 10; i++) {
        val.value.floating_point = (float)i * 1.5f;
        (void)iec61850_journal_add_entry(&journal, "var",
                                            &val, (uint64_t)(1000 + i * 100));
    }

    /* Read entries between 1200 and 1600 */
    int ret = iec61850_journal_read_by_time(&journal, 1200, 1600,
                                              out, &count, 16);
    assert(ret == 0);
    assert(count == 5);  /* timestamps: 1200, 1300, 1400, 1500, 1600 */

    /* All entries */
    count = 0;
    ret = iec61850_journal_read_by_time(&journal, 0, 0, out, &count, 16);
    assert(ret == 0);
    assert(count == 10);

    printf("  PASS: read by time range\n");
}

static void test_journal_read_by_id(void)
{
    iec61850_journal_t journal;
    iec61850_journal_entry_t out[16];
    uint32_t count = 0;
    mms_value_t val;

    iec61850_journal_init(&journal, "J3");

    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_BOOLEAN;

    for (int i = 0; i < 5; i++) {
        val.value.boolean = (i % 2 == 0);
        (void)iec61850_journal_add_entry(&journal, "var", &val,
                                            (uint64_t)(1000 + i * 100));
    }

    /* Read after entry 3 */
    int ret = iec61850_journal_read_by_id(&journal, 3, out, &count, 16);
    assert(ret == 0);
    assert(count == 2);  /* entries 4 and 5 */

    printf("  PASS: read by entry ID\n");
}

static void test_journal_circular_buffer(void)
{
    iec61850_journal_t journal;
    mms_value_t val;

    iec61850_journal_init(&journal, "J4");
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    /* Fill beyond capacity */
    for (int i = 0; i < IEC61850_JOURNAL_MAX_ENTRIES + 100; i++) {
        val.value.integer = i;
        (void)iec61850_journal_add_entry(&journal, "var", &val,
                                            (uint64_t)(i * 100));
    }

    assert(iec61850_journal_get_count(&journal) == IEC61850_JOURNAL_MAX_ENTRIES);

    /* Oldest entries should have been overwritten */
    iec61850_journal_entry_t out[4];
    uint32_t count = 0;
    (void)iec61850_journal_read_by_time(&journal, 0, 50,
                                           out, &count, 4);
    assert(count == 0);  /* old entries gone */

    printf("  PASS: circular buffer overflow\n");
}

static void test_null_args(void)
{
    iec61850_journal_entry_t out[1];
    uint32_t count = 0;
    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));

    /* init NULL */
    iec61850_journal_init(NULL, "test");

    /* init with NULL name */
    iec61850_journal_t journal;
    iec61850_journal_init(&journal, NULL);
    assert(journal.journal_name[0] == '\0');
    assert(journal.count == 0);

    /* add_entry NULL journal */
    assert(iec61850_journal_add_entry(NULL, "v", &val, 100) == 0);

    /* add_entry NULL variable_ref */
    iec61850_journal_init(&journal, "J");
    uint64_t id = iec61850_journal_add_entry(&journal, NULL, &val, 100);
    assert(id == 1);
    assert(journal.entries[0].variable_ref[0] == '\0');

    /* add_entry NULL value */
    id = iec61850_journal_add_entry(&journal, "v", NULL, 200);
    assert(id == 2);

    /* read_by_time NULL args */
    assert(iec61850_journal_read_by_time(NULL, 0, 0, out, &count, 1) != 0);
    assert(iec61850_journal_read_by_time(&journal, 0, 0, NULL, &count, 1) != 0);
    assert(iec61850_journal_read_by_time(&journal, 0, 0, out, NULL, 1) != 0);

    /* read_by_time on empty journal */
    iec61850_journal_t empty;
    iec61850_journal_init(&empty, "Empty");
    count = 99;
    assert(iec61850_journal_read_by_time(&empty, 0, 0, out, &count, 1) == 0);
    assert(count == 0);

    /* read_by_id NULL args */
    assert(iec61850_journal_read_by_id(NULL, 0, out, &count, 1) != 0);
    assert(iec61850_journal_read_by_id(&journal, 0, NULL, &count, 1) != 0);
    assert(iec61850_journal_read_by_id(&journal, 0, out, NULL, 1) != 0);

    /* read_by_id on empty journal */
    count = 99;
    assert(iec61850_journal_read_by_id(&empty, 0, out, &count, 1) == 0);
    assert(count == 0);

    /* get_count NULL */
    assert(iec61850_journal_get_count(NULL) == 0);

    printf("  PASS: null_args\n");
}

static void test_read_by_time_filters(void)
{
    iec61850_journal_t journal;
    iec61850_journal_entry_t out[16];
    uint32_t count = 0;
    mms_value_t val;

    iec61850_journal_init(&journal, "J5");
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    for (int i = 0; i < 5; i++) {
        val.value.integer = i;
        (void)iec61850_journal_add_entry(&journal, "var", &val,
                                            (uint64_t)(1000 + i * 100));
    }
    /* timestamps: 1000, 1100, 1200, 1300, 1400 */

    /* start_ms only (no end filter) */
    int ret = iec61850_journal_read_by_time(&journal, 1200, 0, out, &count, 16);
    assert(ret == 0);
    assert(count == 3);  /* 1200, 1300, 1400 */

    /* end_ms only (no start filter) */
    count = 0;
    ret = iec61850_journal_read_by_time(&journal, 0, 1200, out, &count, 16);
    assert(ret == 0);
    assert(count == 3);  /* 1000, 1100, 1200 */

    /* max_count truncation */
    count = 0;
    ret = iec61850_journal_read_by_time(&journal, 0, 0, out, &count, 2);
    assert(ret == 0);
    assert(count == 2);

    printf("  PASS: read_by_time_filters\n");
}

static void test_read_by_id_truncation(void)
{
    iec61850_journal_t journal;
    iec61850_journal_entry_t out[2];
    uint32_t count = 0;
    mms_value_t val;

    iec61850_journal_init(&journal, "J6");
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_BOOLEAN;

    for (int i = 0; i < 5; i++) {
        (void)iec61850_journal_add_entry(&journal, "var", &val, (uint64_t)(i * 100));
    }

    /* Read after ID 0 (all entries) with max_count=2 */
    int ret = iec61850_journal_read_by_id(&journal, 0, out, &count, 2);
    assert(ret == 0);
    assert(count == 2);

    printf("  PASS: read_by_id_truncation\n");
}

int main(void)
{
    printf("=== MMS Journal Tests ===\n");

    test_journal_init();
    test_journal_add_entry();
    test_journal_read_by_time();
    test_journal_read_by_id();
    test_journal_circular_buffer();

    printf("\n--- NULL / Error Branches ---\n");
    test_null_args();
    test_read_by_time_filters();
    test_read_by_id_truncation();

    printf("All MMS journal tests passed.\n");
    return 0;
}
