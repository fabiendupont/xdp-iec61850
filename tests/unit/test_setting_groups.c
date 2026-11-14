/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * test_setting_groups.c — SGCB unit tests.
 *
 * Exercises the IEC 61850-7-2 setting-group semantics over the
 * bridge API: group selection, edit reservation (single owner,
 * timeout, release), SE-value diversion (live model untouched
 * until activation), activation copying, read bridging, and the
 * rejection paths.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "mms/mms_setting_groups.h"
#include "asn1/mms_ber.h"

static int tests_run, tests_passed, tests_failed;

#define TEST(name) do { tests_run++; printf("  %-52s ", name); } while (0)
#define OK() do { tests_passed++; printf("PASS\n"); } while (0)
#define NO(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)

/* --- helpers ------------------------------------------------------- */

static iec61850_ied_model_t *build_model(void)
{
    iec61850_ied_model_t *model = calloc(1, sizeof(*model));
    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    iec61850_logical_node_t *ln = iec61850_ln_create("PTOC", "1");
    iec61850_data_object_t *do1 = iec61850_do_create("Mod", IEC61850_CDC_DPC);

    /* One SE attribute (the setting under group control) and one
     * MX attribute (must NOT be registered). */
    (void)iec61850_do_add_attribute(do1, "setVal", IEC61850_FC_SE,
                                    IEC61850_BTYPE_INT32);
    (void)iec61850_do_add_attribute(do1, "stVal", IEC61850_FC_MX,
                                    IEC61850_BTYPE_INT32);
    (void)iec61850_ln_add_data_object(ln, do1);
    (void)iec61850_ld_add_logical_node(ld, ln);
    (void)iec61850_ied_model_add_ld(model, ld);

    /* Initial values. */
    iec61850_data_attribute_t *setval =
        iec61850_ln_find_attribute(ln, "Mod.setVal", IEC61850_FC_SE);
    setval->value.type = MMS_TYPE_INTEGER;
    setval->value.value.integer = 100;
    return model;
}

static mms_value_t uint_val(uint32_t v)
{
    mms_value_t out;
    memset(&out, 0, sizeof(out));
    out.type = MMS_TYPE_UNSIGNED;
    out.value.unsigned_val = v;
    return out;
}

static mms_value_t int_val(int32_t v)
{
    mms_value_t out;
    memset(&out, 0, sizeof(out));
    out.type = MMS_TYPE_INTEGER;
    out.value.integer = v;
    return out;
}

static iec61850_data_attribute_t *find_setval(iec61850_ied_model_t *m)
{
    iec61850_logical_device_t *ld =
        iec61850_ied_model_find_ld(m, "LD0");
    iec61850_logical_node_t *ln =
        iec61850_ld_find_ln(ld, "PTOC1");
    return iec61850_ln_find_attribute(ln, "Mod.setVal", IEC61850_FC_SE);
}

static int activated_cb_sg;
static void on_activated(void *user, uint8_t act, uint8_t prev)
{
    (void)user;
    activated_cb_sg = (int)act * 10 + (int)prev;
}

int main(void)
{
    iec61850_sg_manager_t *mgr = NULL;
    iec61850_ied_model_t *model = build_model();
    iec61850_data_attribute_t *setval = find_setval(model);

    /* --- init ------------------------------------------------------ */
    TEST("init registers SE attributes only");
    if (iec61850_sg_manager_init(&mgr, model, 3, 1, 30) != 0) {
        NO("init failed");
    } else if (mgr->entry_count == 1) {
        OK();
    } else {
        NO("entry count wrong");
    }

    TEST("init validates num_of_sg/act_sg");
    iec61850_sg_manager_t *bad = NULL;
    if ((iec61850_sg_manager_init(&bad, model, 0, 1, 30) == 0) ||
        (iec61850_sg_manager_init(&bad, model, 3, 0, 30) == 0) ||
        (iec61850_sg_manager_init(&bad, model, 3, 4, 30) == 0) ||
        (iec61850_sg_manager_init(&bad, model, 9, 1, 30) == 0)) {
        NO("accepted invalid parameters");
    } else {
        OK();
    }

    /* --- SGCB attribute reads -------------------------------------- */
    TEST("SGCB attribute reads");
    mms_value_t v;
    if ((iec61850_sg_bridge_read(mgr, "LD0", "LLN0$SP$SGCB$NumOfSG", &v) != 0) ||
        (v.value.unsigned_val != 3)) {
        NO("NumOfSG read failed");
    } else if ((iec61850_sg_bridge_read(mgr, "LD0", "LLN0$SP$SGCB$ActSG", &v) != 0) ||
               (v.value.unsigned_val != 1)) {
        NO("ActSG read failed");
    } else if ((iec61850_sg_bridge_read(mgr, "LD0", "LLN0$SP$SGCB$EditSG", &v) != 0) ||
               (v.value.unsigned_val != 0)) {
        NO("EditSG read failed");
    } else if ((iec61850_sg_bridge_read(mgr, "LD0", "LLN0$SP$SGCB$ResvTms", &v) != 0) ||
               (v.value.unsigned_val != 0)) {
        NO("ResvTms read failed (no reservation)");
    } else {
        OK();
    }

    TEST("ordinary variables fall through the read bridge");
    if (iec61850_sg_bridge_read(mgr, "LD0", "PTOC1$MX$Mod.stVal", &v)
        != -ENOENT) {
        NO("did not return -ENOENT");
    } else {
        OK();
    }

    /* --- SE value reads/writes ------------------------------------- */
    TEST("SE read without edit session is invisible (falls through)");
    if (iec61850_sg_bridge_read(mgr, "LD0", "PTOC1$SE$Mod$setVal", &v)
        != -ENOENT) {
        NO("SE visible without selection");
    } else {
        OK();
    }

    TEST("$SG$ view serves the active group");
    if ((iec61850_sg_bridge_read(mgr, "LD0", "PTOC1$SG$Mod$setVal", &v)
         != 0) ||
        (v.type != MMS_TYPE_INTEGER) || (v.value.integer != 100)) {
        NO("active-group view wrong");
    } else {
        OK();
    }

    TEST("SE write without edit selection is rejected");
    mms_value_t w = int_val(200);
    if (iec61850_sg_bridge_write(mgr, "LD0", "PTOC1$SE$Mod$setVal",
                                 &w, (void *)0x1) != -EAGAIN) {
        NO("accepted without selection");
    } else {
        OK();
    }

    /* --- edit reservation ------------------------------------------ */
    TEST("EditSG selection takes a reservation");
    mms_value_t sel = uint_val(2);
    if (iec61850_sg_bridge_write(mgr, "LD0", "LLN0$SP$SGCB$EditSG",
                                 &sel, (void *)0x1) != 0) {
        NO("selection failed");
    } else if (iec61850_sg_get_edit(mgr) != 2) {
        NO("edit group not recorded");
    } else if (iec61850_sg_bridge_read(mgr, "LD0", "LLN0$SP$SGCB$ResvTms",
                                       &v) != 0 ||
              v.value.unsigned_val != 30) {
        NO("ResvTms not reported");
    } else {
        OK();
    }

    TEST("another association cannot steal the reservation");
    if (iec61850_sg_bridge_write(mgr, "LD0", "LLN0$SP$SGCB$EditSG",
                                 &sel, (void *)0x2) != -EPERM) {
        NO("reservation stolen");
    } else {
        OK();
    }

    TEST("owner writes SE values into the edit group");
    w = int_val(200);
    if (iec61850_sg_bridge_write(mgr, "LD0", "PTOC1$SE$Mod$setVal",
                                 &w, (void *)0x1) != 0) {
        NO("SE write rejected");
    } else if (setval->value.value.integer != 100) {
        NO("live model was touched before activation");
    } else if (iec61850_sg_bridge_read(mgr, "LD0", "PTOC1$SE$Mod$setVal",
                                       &v) != 0 ||
              v.value.integer != 200) {
        NO("edit-group read does not serve the edit copy");
    } else {
        OK();
    }

    TEST("type mismatch is rejected");
    mms_value_t wrong = uint_val(1);
    if (iec61850_sg_bridge_write(mgr, "LD0", "PTOC1$SE$Mod$setVal",
                                 &wrong, (void *)0x1) != -EINVAL) {
        NO("type mismatch accepted");
    } else {
        OK();
    }

    /* --- activation ------------------------------------------------- */
    TEST("SelectActiveSG copies the group into the live model");
    iec61850_sg_set_activation_callback(mgr, on_activated, NULL);
    mms_value_t act = uint_val(2);
    activated_cb_sg = 0;
    if (iec61850_sg_bridge_write(mgr, "LD0", "LLN0$SP$SGCB$ActSG",
                                 &act, (void *)0x1) != 0) {
        NO("activation failed");
    } else if (setval->value.value.integer != 200) {
        NO("live model not updated");
    } else if (activated_cb_sg != 21) {
        NO("activation callback missing");
    } else if (iec61850_sg_get_active(mgr) != 2) {
        NO("active group not recorded");
    } else {
        OK();
    }

    TEST("ActSG range is validated");
    act = uint_val(4);
    if (iec61850_sg_bridge_write(mgr, "LD0", "LLN0$SP$SGCB$ActSG",
                                 &act, (void *)0x1) != -EINVAL) {
        NO("out-of-range accepted");
    } else {
        OK();
    }

    TEST("re-activating the same group fires no callback");
    act = uint_val(2);
    activated_cb_sg = 0;
    if ((iec61850_sg_bridge_write(mgr, "LD0", "LLN0$SP$SGCB$ActSG",
                                  &act, (void *)0x1) != 0) ||
        (activated_cb_sg != 0)) {
        NO("spurious callback");
    } else {
        OK();
    }

    /* --- reservation lifecycle -------------------------------------- */
    TEST("EditSG=0 releases the reservation");
    mms_value_t rel = uint_val(0);
    if (iec61850_sg_bridge_write(mgr, "LD0", "LLN0$SP$SGCB$EditSG",
                                 &rel, (void *)0x1) != 0) {
        NO("release failed");
    } else if (iec61850_sg_get_edit(mgr) != 0) {
        NO("edit not released");
    } else {
        OK();
    }

    TEST("reservation expires via tick");
    (void)iec61850_sg_bridge_write(mgr, "LD0", "LLN0$SP$SGCB$EditSG",
                                   &sel, (void *)0x3);
    iec61850_sg_tick(mgr, 1000);            /* start countdown */
    iec61850_sg_tick(mgr, 1000 + 31 * 1000); /* past 30 s */
    if (iec61850_sg_get_edit(mgr) != 0) {
        NO("reservation not released");
    } else {
        OK();
    }

    TEST("owner release on disconnect");
    (void)iec61850_sg_bridge_write(mgr, "LD0", "LLN0$SP$SGCB$EditSG",
                                   &sel, (void *)0x4);
    iec61850_sg_release_owner(mgr, (void *)0x9);   /* wrong owner */
    if (iec61850_sg_get_edit(mgr) != 2) {
        NO("wrong owner released the reservation");
    } else {
        iec61850_sg_release_owner(mgr, (void *)0x4);
        if (iec61850_sg_get_edit(mgr) != 0) {
            NO("owner release failed");
        } else {
            OK();
        }
    }

    /* --- non-owner activation of another group --------------------- */
    TEST("group values are independent copies");
    act = uint_val(1);
    if ((iec61850_sg_bridge_write(mgr, "LD0", "LLN0$SP$SGCB$ActSG",
                                  &act, (void *)0x1) != 0) ||
        (setval->value.value.integer != 100)) {
        NO("group 1 value lost");
    } else {
        OK();
    }

    TEST("$SG$ view follows the active group after activation");
    if ((iec61850_sg_bridge_read(mgr, "LD0", "PTOC1$SG$Mod$setVal", &v)
         != 0) ||
        (v.value.integer != 100)) {
        NO("$SG$ view did not follow activation");
    } else {
        OK();
    }

    /* --- bounds discipline ----------------------------------------- */
    TEST("oversized SE path is rejected, not truncated");
    {
        iec61850_ied_model_t *m2 = calloc(1, sizeof(*m2));
        iec61850_logical_device_t *ld2 = iec61850_ld_create("LD0");
        iec61850_logical_node_t *ln2 = iec61850_ln_create("PTOC", "1");
        char long_a[IEC61850_MAX_NAME_LEN];
        char long_b[IEC61850_MAX_NAME_LEN];
        (void)memset(long_a, 'A', 60); long_a[60] = '\0';
        (void)memset(long_b, 'B', 60); long_b[60] = '\0';
        iec61850_data_object_t *d1 =
            iec61850_do_create(long_a, IEC61850_CDC_DPC);
        iec61850_data_object_t *d2 =
            iec61850_do_create(long_b, IEC61850_CDC_DPC);
        (void)iec61850_do_add_attribute(d1, "setVal", IEC61850_FC_SE,
                                        IEC61850_BTYPE_INT32);
        (void)iec61850_do_add_sub_object(d1, d2);
        (void)iec61850_do_add_attribute(d2, "setVal", IEC61850_FC_SE,
                                        IEC61850_BTYPE_INT32);
        (void)iec61850_ln_add_data_object(ln2, d1);
        (void)iec61850_ld_add_logical_node(ld2, ln2);
        (void)iec61850_ied_model_add_ld(m2, ld2);

        iec61850_sg_manager_t *m2mgr = NULL;
        int ret = iec61850_sg_manager_init(&m2mgr, m2, 2, 1, 30);
        if (ret == 0) {
            iec61850_sg_manager_destroy(m2mgr);
            NO("oversized path accepted");
        } else if (ret != -ENAMETOOLONG) {
            NO("wrong error for oversized path");
        } else {
            OK();
        }
        /* leak m2 (process exits) */
    }

    iec61850_sg_manager_destroy(mgr);

    /* Model cleanup is the test harness's job in production; here
     * leak it — the process exits immediately. */
    (void)model;

    printf("---\n%d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
