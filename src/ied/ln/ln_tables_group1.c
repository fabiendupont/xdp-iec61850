/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — group 1: common / substation
 *
 * Pilot classes (WP-6b): LLN0, LPHD, XCBR, XSWI, CSWI, CILO.
 * WP-6c group-1 batch 1 appends: MHAI, MFLK, MSQI, YLTC, ZBAT,
 * ZCAB, ZCON.
 *
 * DO lists are the conservative common subset across 7-4 editions
 * (M = mandatory in the chosen subset, O = optional, listed for
 * iec61850_ln_add_ln_class_do()). Judgment calls and edition
 * ambiguities are flagged in comments; see the WP-6b/6c reports.
 *
 * CDC dispatch is complete as of the WP-6c pre-step (all 33 CDC
 * factories, incl. APC/ENC/ISC/CURS/CSD/SEQ/HMV/HWYE/HDEL), so
 * classes may use any implemented CDC.
 *
 * WP-6c deferral policy (clean room: 7-4 knowledge only, no
 * external library tables): a class is registered only when its
 * existence in 7-4 is certain from clean-room knowledge, and a
 * DO is listed only when its name/CDC is reconstructible with
 * reasonable confidence — uncertain DOs are deferred per class
 * rather than guessed. Classes from the WP-6c brief NOT
 * registered here (see the WP-6c report for full reasoning):
 *   CBRK, SCBR, SARC, SWTC, BATV, DIS, ZAXN — existence as 7-4
 *       classes not confirmable from clean-room knowledge
 *       (XSWI already models disconnectors);
 *   MMXN, MHAS, MSTA, MDIF, MRDR — DO sets not reconstructible;
 *   RSYN — protection-related group, not group 1 (flagged to the
 *       group-2 batch);
 *   QFPC, TFPC, CSDS — power-quality / unknown, not group 1.
 * GGIO stays registered in group 4 (pilot placement) although
 * 7-4 groups it with the generic/common classes — left as-is per
 * the WP-6c brief; noted for TR.
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

/* ------------------------------------------------------------------
 * MHAI — Harmonic analysis (WP-6c)
 *
 * Judgment calls:
 *  - Group assignment: 7-4 lists MHAI with the measurement /
 *    power-quality classes; this repo's group 3 holds only the
 *    pilot pair (MMXU, MMTR) and the WP-6c brief assigns the
 *    remaining measurement classes to group 1. Flagged for TR.
 *  - Ha (HMV): phase-A harmonic content. DO name and CDC are
 *    from fragmentary 7-4 knowledge; listed O (likely M in 7-4)
 *    so the conservative table cannot break instantiation.
 *    Flagged.
 *  - The remaining harmonic DOs (three-phase HWYE / HDEL forms,
 *    interharmonics) are deferred — 7-4 names not reconstructible
 *    from clean-room knowledge. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mhai_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Ha",     IEC61850_CDC_HMV, false },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * MFLK — Flicker measurement (WP-6c)
 *
 * Judgment calls:
 *  - Group assignment: as MHAI above (measurement / power quality
 *    in 7-4; group 1 here per the WP-6c brief). Flagged for TR.
 *  - Pst / Plt (MV): short- and long-term flicker severity (IEC
 *    61000-4-15 quantities), commonly associated with MFLK; typed
 *    MV and listed O (conservative; likely M in 7-4). Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mflk_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Plt",    IEC61850_CDC_MV,  false },
    { "Pst",    IEC61850_CDC_MV,  false },
};

/* ------------------------------------------------------------------
 * MSQI — Sequence and imbalance measurement (WP-6c)
 *
 * Judgment calls:
 *  - Group assignment: as MHAI above. Flagged for TR.
 *  - The class-specific DO set (sequence components, imbalance
 *    quantities) could not be reconstructed with confidence from
 *    clean-room 7-4 knowledge, so only the LN-common DOs are
 *    registered and the rest are deferred. Flagged for TR.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t msqi_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * YLTC — Load tap changer supervision (WP-6c)
 *
 * Judgment calls:
 *  - TapPos (BSC): tap position with stepped control. Core DO of
 *    the class and likely M in 7-4, but the 7-4 typing could not
 *    be confirmed clean-room; listed O so the conservative table
 *    cannot break instantiation. BSC chosen because the repo's
 *    BSC factory carries the stepped-control (valWTr) form.
 *    Flagged for TR — promote to M once confirmed.
 *  - Further class DOs (tap-change in-progress status, operation
 *    counters) deferred. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t yltc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "TapPos", IEC61850_CDC_BSC, false },
};

/* ------------------------------------------------------------------
 * ZBAT — Battery supervision (WP-6c)
 *
 * Judgment calls:
 *  - Class exists in 7-4 equipment supervision; also used by the
 *    DER profile (IEC 61850-7-420). Registered per the WP-6c
 *    brief. Flagged (7-420 overlap).
 *  - The class-specific DO set (voltages, currents, charge state)
 *    could not be reconstructed with confidence from clean-room
 *    knowledge, so only the LN-common DOs are registered and the
 *    rest are deferred. Flagged for TR.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t zbat_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * ZCAB — Cable supervision (WP-6c)
 *
 * Judgment calls:
 *  - As ZBAT: 7-4 equipment-supervision class registered per the
 *    brief; the class-specific DO set (partial-discharge, thermal
 *    and loading quantities) is deferred — not reconstructible
 *    with confidence from clean-room knowledge. Flagged for TR.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t zcab_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * ZCON — Converter supervision (WP-6c)
 *
 * Judgment calls:
 *  - As ZBAT, with a stronger DER-profile overlap: ZCON is
 *    heavily used by IEC 61850-7-420 (DER converters). Registered
 *    in group 1 per the WP-6c brief; flagged for TR to confirm
 *    the 7-4 (vs 7-420) provenance.
 *  - Class-specific DO set deferred as for ZBAT/ZCAB. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t zcon_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

const iec61850_ln_class_def_t ln_group1_classes[LN_GROUP1_CLASS_COUNT] = {
    { "CILO", cilo_dos, 6U },
    { "CSWI", cswi_dos, 5U },
    { "LLN0", lln0_dos, 4U },
    { "LPHD", lphd_dos, 7U },
    { "MHAI", mhai_dos, 5U },
    { "MFLK", mflk_dos, 6U },
    { "MSQI", msqi_dos, 4U },
    { "XCBR", xcbr_dos, 8U },
    { "XSWI", xswi_dos, 7U },
    { "YLTC", yltc_dos, 5U },
    { "ZBAT", zbat_dos, 4U },
    { "ZCAB", zcab_dos, 4U },
    { "ZCON", zcon_dos, 4U },
};
