/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — group 1: common / substation
 *
 * Pilot classes (WP-6b): LLN0, LPHD, XCBR, XSWI, CSWI, CILO.
 * WP-6c group-1 batch 1 appends: YLTC, ZBAT, ZCAB, ZCON (the
 * MHAI, MFLK and MSQI named by the same WP-6c brief were
 * registered by the WP-6c group-3 batch, which owns the 7-4 M
 * family).
 * WP-6d1 appends the deferred group-1 classes under the relaxed
 * owner-directed policy (below): BATV, CALH, CBRK, SARC, SWTC,
 * YPTR, ZAXN. (WP-6e correction: MHAS/MRDR were named by the
 * WP-6d1 group-1 brief but registered by the group-3 batch, which
 * owns the 7-4 M family — group 3 carries them.)
 *
 * DO lists are the conservative common subset across 7-4 editions
 * (M = mandatory in the chosen subset, O = optional, listed for
 * iec61850_ln_add_ln_class_do()). Judgment calls and edition
 * ambiguities are flagged in comments; see the WP-6b/6c/6d1
 * reports.
 *
 * CDC dispatch is complete as of the WP-6c pre-step (all 33 CDC
 * factories, incl. APC/ENC/ISC/CURS/CSD/SEQ/HMV/HWYE/HDEL), so
 * classes may use any implemented CDC.
 *
 * WP-6d1 relaxed policy (clean room: 7-4 knowledge only, no
 * external library source or tables — the relaxation is about
 * DO-set confidence, NOT about sourcing): every class deferred by
 * the WP-6c group-1 batch is registered with its LN-common DOs
 * (Mod/Beh/Health/NamPlt) plus best-recall signature DOs; every
 * DO not recalled with confidence is listed OPTIONAL (optional
 * DOs are only added via iec61850_ln_add_ln_class_do() and can
 * never break instantiation) and flagged in the class comment for
 * TR review. A common-only shell with flagged optional DOs is the
 * accepted minimum — nothing is deferred for "DO set not
 * reconstructible" reasons anymore.
 *
 * WP-6d1 dedup against the registry: SCBR, MMXN, MSTA and MDIF
 * from the old WP-6c deferral list are already registered by the
 * WP-6c group-3 batch and are NOT re-added here; DIS stays
 * modeled by XSWI.
 *
 * WP-6d1 Q/K judgment (flagged for TR): clean-room 7-4 knowledge
 * has no Q first-letter family (the 7-4 first-letter families are
 * A, C, G, I, K, L, M, P, R, S, T, X, Y, Z), so QFPC/TFPC-style
 * classes are not confirmable as 7-4 classes and are not
 * registered. WP-6e PARTIALLY SUPERSEDES the K half of this
 * judgment: the owner directed the K family (mechanical /
 * non-electrical primary equipment) be registered as flagged
 * shells in group 4 — see ln_tables_group4.c for the outcome
 * (placement moved to group 4; registration still declined
 * there under the binding no-invention rule). The Q half stands.
 * GGIO stays registered in group 4 (pilot placement) although
 * 7-4 groups it with the generic/common classes — left as-is per
 * the WP-6c brief; noted for TR.
 *
 * WP-6e (full-breadth campaign for the L/X/C/Y/Z families, same
 * relaxed policy as WP-6d1): appends LGOS and LSVS (L-family
 * communication supervision — GOOSE / sampled-value subscription
 * supervision). Review of the families for anything else not yet
 * registered found no further class name recallable with
 * confidence (see the declined list below). Declined /
 * TR-review names (existence as 7-4 Ed.2 classes not recallable
 * with confidence clean-room — not registered, per the binding
 * policy):
 *  - YMOT (motor supervision): the name surfaces dimly (possibly
 *    a 7-4 class, possibly a 7-410/7-420 artifact); below the
 *    confidence bar. TR to confirm.
 *  - XGND / earthing-switch classes: earthing switches stay
 *    modeled by XSWI (with a SwTyp setting) per 7-4 practice; no
 *    separate X class recalled.
 *  - The X, C, Y and Z families are otherwise judged COMPLETE
 *    per clean-room recall: XCBR/XSWI, CALH/CILO/CSWI,
 *    YLTC/YPTR, ZAXN/ZBAT/ZCAB/ZCON are all the Ed.2 names this
 *    campaign can stand behind.
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

/* ------------------------------------------------------------------
 * WP-6d1 — deferred group-1 classes under the relaxed policy
 * (see the file header). Common-only shells carry only the
 * LN-common four; every inferred or uncertain DO is OPTIONAL and
 * flagged below for TR.
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------
 * BATV — Battery voltage supervision (WP-6d1)
 *
 * Registered per the WP-6d1 owner direction (previously deferred:
 * existence not confirmable). Judgment calls (all flagged for TR):
 *  - Clean-room recall cannot pin the provenance: the name reads
 *    "BATtery Voltage" (a companion to ZBAT), but the class may
 *    come from the energy-storage extensions (IEC 61850-90-9 /
 *    7-420 flavor) rather than 7-4 itself. TR to confirm the
 *    defining document.
 *  - The class-specific DO set (battery voltage/current/charge
 *    quantities) is not recallable with confidence, so none is
 *    guessed: common-only shell, the relaxed-policy minimum.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t batv_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * CALH — Alarm handling (WP-6d1)
 *
 * 7-4 group C (control) class; existence is confident from
 * clean-room knowledge. Judgment call (flagged for TR): the
 * class-specific DO set (the alarm indication/collection family)
 * is not recallable with confidence, so none is guessed — the
 * common-only shell is the relaxed-policy minimum. TR to
 * populate.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t calh_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * CBRK — Circuit breaker (WP-6d1)
 *
 * Registered per the WP-6d1 owner direction (previously deferred:
 * existence not confirmable). Judgment calls (all flagged for TR):
 *  - The name reads "CiRcuit BReaKer"; clean-room recall cannot
 *    confirm the 7-4 table, and the class is often used with a
 *    DER-profile flavor. TR to confirm provenance (7-4 vs 7-420).
 *  - Pos (DPC) is INFERRED from the standard 7-4 breaker DO
 *    vocabulary (XCBR.Pos), not recalled from a CBRK table; it is
 *    listed O so it can never break instantiation. TR to confirm
 *    before promoting to M.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t cbrk_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Pos",    IEC61850_CDC_DPC, false },
};



/* ------------------------------------------------------------------
 * SARC — Supervision of arc (WP-6d1)
 *
 * Registered per the WP-6d1 owner direction (previously deferred:
 * existence not confirmable). Judgment calls (all flagged for TR):
 *  - The name reads "Supervision of ARC" (arc-fault detection);
 *    clean-room recall cannot confirm the 7-4 table — arc
 *    protection is often profile-defined. TR to confirm.
 *  - The class-specific DO set (arc-detection indication family)
 *    is not recallable with confidence, so none is guessed —
 *    common-only shell, the relaxed-policy minimum.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t sarc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * SWTC — Switch control (WP-6d1)
 *
 * Registered per the WP-6d1 owner direction (previously deferred:
 * existence not confirmable). Judgment calls (all flagged for TR):
 *  - The name reads "SWitch Control" (a control-side switching LN
 *    like CSWI); clean-room recall cannot confirm the 7-4 table.
 *  - Pos (DPC) is INFERRED from the standard 7-4 switch-control
 *    DO vocabulary (CSWI.Pos), not recalled from an SWTC table;
 *    listed O so it can never break instantiation. If SWTC turns
 *    out to model something else (e.g. a switching-time/counter
 *    function), this DO is wrong and must be dropped — TR to
 *    confirm before promoting.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t swtc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Pos",    IEC61850_CDC_DPC, false },
};

/* ------------------------------------------------------------------
 * YPTR — Potential (voltage) transformer, Y family (WP-6d1)
 *
 * Registered per the WP-6d1 owner direction with an explicit
 * group-boundary flag: Y is the 7-4 transformer family (YLTC is
 * registered here) and the name reads "Potential TRansformer",
 * but the instrument-transformer classes (TCTR/TVTR) live in the
 * group-2 table — TR may prefer to relocate. Judgment calls (all
 * flagged for TR):
 *  - Clean-room recall cannot confirm the 7-4 table for YPTR.
 *  - The class-specific DO set (VT supervision quantities) is not
 *    recallable with confidence, so none is guessed —
 *    common-only shell, the relaxed-policy minimum.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t yptr_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * ZAXN — Supervision of axial fan (WP-6d1)
 *
 * Registered per the WP-6d1 owner direction (previously deferred:
 * existence not confirmable). Judgment calls (all flagged for TR):
 *  - The name reads "Z (equipment supervision) + AXN (axial
 *    fan)" — a cooling-auxiliary supervision class; clean-room
 *    recall cannot confirm the 7-4 table.
 *  - The class-specific DO set (fan run status / counters) is not
 *    recallable with confidence, so none is guessed —
 *    common-only shell, the relaxed-policy minimum.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t zaxn_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * WP-6e — full-breadth L/X/C/Y/Z additions under the relaxed
 * policy (see the file header).
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------
 * LGOS — GOOSE supervision (WP-6e, L family)
 *
 * Judgment calls (all flagged for TR):
 *  - Existence as an IEC 61850 Ed.2-era L-family communication-
 *    supervision LN is recalled with confidence (GOOSE-subscription
 *    supervision), but the exact defining document (7-4:2010
 *    itself vs its Ed.2.1 amendment vs a companion part) could
 *    not be pinned clean-room. TR to confirm provenance before
 *    treating LGOS as a base-7-4 class.
 *  - St (subscription status, best recall ENS) is the signature
 *    DO; listed O (mandatory=false) since neither its exact name
 *    form nor its M/O status is confirmable clean-room — it can
 *    never break instantiation.
 *  - GoCBRef (the supervised control-block reference, best recall
 *    CDC ORS) is OMITTED: ORS is not an implemented CDC (same
 *    precedent as the LLN0 GrRef omission). TR to revisit if an
 *    ORS factory is ever added.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t lgos_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "St",     IEC61850_CDC_ENS, false },
};

/* ------------------------------------------------------------------
 * LSVS — Sampled-value (SV) supervision (WP-6e, L family)
 *
 * Judgment calls (all flagged for TR):
 *  - As LGOS: SV-subscription supervision LN of the IEC 61850
 *    Ed.2-era communication-supervision additions; existence is
 *    recalled with slightly LOWER confidence than LGOS (SV
 *    subscription supervision may have arrived with a later
 *    amendment than the GOOSE twin). TR to confirm provenance —
 *    drop this class if it turns out not to be 7-4 Ed.2.
 *  - St (subscription status, best recall ENS) listed O, as for
 *    LGOS. SvCBRef (best recall CDC ORS) is OMITTED — ORS is not
 *    an implemented CDC (LLN0 GrRef precedent).
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t lsvs_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "St",     IEC61850_CDC_ENS, false },
};

const iec61850_ln_class_def_t ln_group1_classes[LN_GROUP1_CLASS_COUNT] = {
    { "BATV", batv_dos, 4U },
    { "CALH", calh_dos, 4U },
    { "CBRK", cbrk_dos, 5U },
    { "CILO", cilo_dos, 6U },
    { "CSWI", cswi_dos, 5U },
    { "LGOS", lgos_dos, 5U },
    { "LLN0", lln0_dos, 4U },
    { "LPHD", lphd_dos, 7U },
    { "LSVS", lsvs_dos, 5U },
    { "SARC", sarc_dos, 4U },
    { "SWTC", swtc_dos, 5U },
    { "XCBR", xcbr_dos, 8U },
    { "XSWI", xswi_dos, 7U },
    { "YLTC", yltc_dos, 5U },
    { "YPTR", yptr_dos, 4U },
    { "ZAXN", zaxn_dos, 4U },
    { "ZBAT", zbat_dos, 4U },
    { "ZCAB", zcab_dos, 4U },
    { "ZCON", zcon_dos, 4U },
};
