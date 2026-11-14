/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — group 1: common / substation
 *
 * Pilot classes (WP-6b): LLN0, LPHD, XCBR, XSWI, CSWI, CILO.
 * WP-6c appends the remaining group-1 classes.
 *
 * DO lists are the conservative common subset across 7-4 editions
 * (M = mandatory in the chosen subset, O = optional, listed for
 * iec61850_ln_add_ln_class_do()). Judgment calls and edition
 * ambiguities are flagged in comments; see the WP-6b report.
 *
 * CDCs are restricted to the factories implemented in
 * src/ied/ied_data_model.c. DOs whose CDC is a WP-S6 stub
 * (APC/ENC/ISC/CURS/CSD/SEQ/HMV/HWYE/HDEL) are omitted and
 * flagged; WP-6c's bulk generation adds them back once WP-6a
 * lands.
 */

#include "ln_schema_tables.h"

/* ------------------------------------------------------------------
 * LLN0 — Logical node zero (7-4 group 1)
 *
 * Mandatory DOs: the LN-common four. Judgment calls:
 *  - MgtLev (ING) and GrRef (ORS) are Ed.2 optionals whose CDCs
 *    are not implemented — omitted, flagged.
 *  - The SGCB "SettingControl" object is NOT a 7-4 data object:
 *    it is the ACSI server-model setting-group control block of
 *    7-2 (see src/mms/mms_setting_groups.c) and has no CDC, so it
 *    cannot appear in a CDC-driven class table. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t lln0_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * LPHD — Logical node physical device (7-4 group 1)
 *
 * Judgment call: 7-4 types PhyHealth as ENS; the SCL builder
 * (src/scl/scl_ied_builder.c) instantiates it as INS. The table
 * follows 7-4 (ENS). Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t lphd_dos[] = {
    { "Beh",       IEC61850_CDC_INS, true  },
    { "Health",    IEC61850_CDC_INS, true  },
    { "Mod",       IEC61850_CDC_INC, true  },
    { "NamPlt",    IEC61850_CDC_LPL, true  },
    { "PhyHealth", IEC61850_CDC_ENS, true  },
    { "PhyNam",    IEC61850_CDC_DPL, true  },
    { "Proxy",     IEC61850_CDC_SPS, false },
};

/* ------------------------------------------------------------------
 * XCBR — Circuit breaker (7-4 group 1)
 *
 * Judgment calls:
 *  - BlkOpn/BlkCls: M in the 7-4 Ed.2 table, O in common Ed.1
 *    engineering profiles; chosen M to match the repo's own
 *    scl_ied_builder XCBR population (Pos + BlkOpn + BlkCls).
 *  - CBOpCnt: O; typed BCR (operation counter reading).
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t xcbr_dos[] = {
    { "Beh",     IEC61850_CDC_INS, true  },
    { "BlkCls",  IEC61850_CDC_SPS, true  },
    { "BlkOpn",  IEC61850_CDC_SPS, true  },
    { "CBOpCnt", IEC61850_CDC_BCR, false },
    { "Health",  IEC61850_CDC_INS, true  },
    { "Mod",     IEC61850_CDC_INC, true  },
    { "NamPlt",  IEC61850_CDC_LPL, true  },
    { "Pos",     IEC61850_CDC_DPC, true  },
};

/* ------------------------------------------------------------------
 * XSWI — Switch (disconnector / earthing switch) (7-4 group 1)
 *
 * Judgment call: BlkOpn/BlkCls listed O (conservative; some
 * profiles instantiate them like XCBR's). Ed.2 SwTyp (ENG) is
 * omitted — CDC not implemented. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t xswi_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "BlkCls", IEC61850_CDC_SPS, false },
    { "BlkOpn", IEC61850_CDC_SPS, false },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Pos",    IEC61850_CDC_DPC, true  },
};

/* ------------------------------------------------------------------
 * CSWI — Switch control (7-4 group 1)
 *
 * Conservative: the 7-4 table is the LN-common DOs plus Pos (the
 * controlled switch position). Flagged as minimal-table choice.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t cswi_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Pos",    IEC61850_CDC_DPC, true  },
};

/* ------------------------------------------------------------------
 * CILO — Interlocking (7-4 group 1)
 *
 * EnaOpn/EnaCls are the interlock permission statuses (M).
 * No mandatory CILO DO needs a WP-S6 stub CDC, so nothing is
 * omitted here.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t cilo_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "EnaCls", IEC61850_CDC_SPS, true  },
    { "EnaOpn", IEC61850_CDC_SPS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

const iec61850_ln_class_def_t ln_group1_classes[LN_GROUP1_CLASS_COUNT] = {
    { "CILO", cilo_dos, 6U },
    { "CSWI", cswi_dos, 5U },
    { "LLN0", lln0_dos, 4U },
    { "LPHD", lphd_dos, 7U },
    { "XCBR", xcbr_dos, 8U },
    { "XSWI", xswi_dos, 7U },
};

