/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — group 3: measurement / metering /
 * monitoring / supervision
 *
 * Pilot classes (WP-6b): MMXU, MMTR. WP-6c appends the remaining
 * group-3 classes: the 7-4 M family (measurement extensions) and
 * the 7-4 S family (supervision / monitoring), per the WP-6c scope
 * (this repo's group 3 covers both first-letter families).
 *
 * Same conventions as ln_tables_group1.c: conservative common
 * subset across 7-4 editions, CDCs restricted to the implemented
 * factories in src/ied/ied_data_model.c.
 *
 * WP-6c clean-room provenance: every table below was written from
 * 7-4 knowledge only (no other library's source or tables were
 * consulted). Where the exact 7-4 DO names could not be recalled
 * with confidence, the DO family is DEFERRED (documented in the
 * class comment) rather than invented; classes whose specific DOs
 * are entirely deferred carry only the LN-common subset. Every
 * such judgment call is flagged for TR review.
 *
 * WP-6d1 (owner-directed relaxed policy — best-recall DO sets
 * with flags): appends the deferred group-3 classes MHAS and
 * MRDR. MFUL from the WP-6c deferral list is NOT registered: its
 * existence as a 7-4 class could not be verified from clean-room
 * knowledge — flagged in the WP-6d1 report. MFLK and MSTA were
 * already registered by WP-6c and are not re-added.
 *
 * WP-6e (full-breadth M/S campaign): this file owns the 7-4
 * first-letter M and S families. A complete clean-room sweep of
 * the 7-4 Ed.2 class list against the registry found every
 * confidently-recallable M/S class already registered:
 *  - M family (10): MDIF, MFLK, MHAI, MHAS, MMTR, MMXN, MMXU,
 *    MRDR, MSQI, MSTA — all here (MHAS/MRDR via WP-6d1);
 *  - S family (10): SCBR, SIML, SIMS, SPDC, SPTR, SQVL, SSIL,
 *    STMP here, plus SARC and SWTC in group 1 (pilot placement,
 *    recorded in the group-1 header; the 7-4 S family is complete
 *    across the two files).
 * No further 7-4 Ed.2 M/S class name is recallable with
 * confidence from clean-room knowledge, so the WP-6e batch adds
 * ZERO classes and LN_GROUP3_CLASS_COUNT stays 18. The relaxed
 * policy relaxes DO-set confidence, never name confidence, so
 * the names below stay unregistered.
 *
 * WP-6e declined / TR-review names (existence as 7-4 Ed.2
 * classes not confirmable clean-room):
 *  - MFUL (fuel monitoring): cannot be placed in the 7-4 LN
 *    list; reads like a hydro (7-410) / DER (7-420) /
 *    energy-storage (90-9) profile class. Stays declined as in
 *    WP-6d1.
 *  - SVBR (vibration supervision): the name surfaces in
 *    condition-monitoring discussions but cannot be placed in
 *    the 7-4 Ed.2 class list with confidence — possibly a class
 *    of another part/edition. TR to confirm before any
 *    registration.
 *  - SDIS (disconnector supervision): not recallable; DIS itself
 *    is the Ed.1 disconnector class, modeled by XSWI per the
 *    group-1 header note.
 * M/S-sounding classes from other IEC 61850 parts (e.g. MFLO or
 * SCWT-style hydro monitoring in 7-410) are out of scope: this
 * table is 7-4 Ed.2 only.
 *
 * WP-6e cross-file observations for the owner (no code changed
 * outside this file): the group-1 header comment still credits
 * WP-6d1 with "appending" MHAS/MRDR, but those classes live in
 * this file's array — the group-1 comment is stale; and SWRI
 * (group 4) starts with S but its family placement was accepted
 * by the group-4 owner.
 */

#include "ln_schema_tables.h"

/* ------------------------------------------------------------------
 * MDIF — Differential measurement (7-4 group 3, M family)
 *
 * Companion measurement LN for differential protection (PDIF).
 * Judgment call: the class-specific DOs (differential/restraint
 * measurement family) could not be recalled with confidence from
 * clean-room 7-4 knowledge, so the conservative table carries the
 * LN-common subset only and the differential DO family is
 * deferred pending TR verification of the 7-4 names. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mdif_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * MFLK — Flicker measurement (7-4 group 3, M family)
 *
 * Pst/Plt are the short/long-term flicker severity indicators,
 * listed O. Judgment call: whether 7-4 types the flicker
 * severities MV or CMV is edition-dependent; conservative choice
 * MV. Further flicker DOs are deferred pending TR verification.
 * Flagged.
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
 * MHAI — Harmonics and interharmonics (7-4 group 3, M family)
 *
 * HA (HMV), HPhV (HWYE) and HPPV (HDEL) mirror the MMXU harmonics
 * naming (harmonic currents / phase voltages / phase-to-phase
 * voltages). All O — the deployed harmonic subset is profile-
 * dependent. Judgment call: further harmonic/interharmonic and
 * THD-family DOs are deferred pending TR verification of the 7-4
 * names. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mhai_dos[] = {
    { "Beh",    IEC61850_CDC_INS,  true  },
    { "HA",     IEC61850_CDC_HMV,  false },
    { "Health", IEC61850_CDC_INS,  true  },
    { "HPhV",   IEC61850_CDC_HWYE, false },
    { "HPPV",   IEC61850_CDC_HDEL, false },
    { "Mod",    IEC61850_CDC_INC,  true  },
    { "NamPlt", IEC61850_CDC_LPL,  true  },
};

/* ------------------------------------------------------------------
 * MHAS — Harmonics analysis (7-4 group 3, M family)
 *
 * WP-6d1 (owner-directed relaxed policy — best-recall DO sets
 * with flags): MHAS was on the WP-6c deferral list (parked at
 * the 7-420 boundary), but it is a 7-4 harmonics class and the
 * owner directed its inclusion. Best-recall DO set: the same
 * harmonic measurement family as MHAI — HA (HMV, harmonic
 * currents), HPhV (HWYE, harmonic phase voltages), HPPV (HDEL,
 * harmonic phase-to-phase voltages) — all O. TR flags:
 *  - whether the exact 7-4 MHAS DO set differs from MHAI's
 *    (interharmonics / THD family) is not confirmable
 *    clean-room; the THD-family DOs stay deferred;
 *  - the MHAS/MHAI split (and any 7-420 overlap in scope) is
 *    edition-dependent — TR to confirm.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mhas_dos[] = {
    { "Beh",    IEC61850_CDC_INS,  true  },
    { "HA",     IEC61850_CDC_HMV,  false },
    { "Health", IEC61850_CDC_INS,  true  },
    { "HPhV",   IEC61850_CDC_HWYE, false },
    { "HPPV",   IEC61850_CDC_HDEL, false },
    { "Mod",    IEC61850_CDC_INC,  true  },
    { "NamPlt", IEC61850_CDC_LPL,  true  },
};

/* ------------------------------------------------------------------
 * MMTR — Metering (7-4 group 3)
 *
 * Judgment call: whether the energy counters TotWh/TotVArh are M or
 * C/O in MMTR is edition/profile-dependent; conservative choice is
 * O. Flagged.
 * Retro-fix (WP-6c): the Ed.2 optional harmonic DOs HA (HMV),
 * HPhV (HWYE) and HPPV (HDEL), omitted at pilot time because the
 * CDCs were WP-S6 stubs, are added back now that the WP-6a
 * factories exist (the WP-6b pilot comments recorded this plan).
 * Judgment call: whether these harmonics DOs belong to MMTR or
 * only to MHAI is a 7-4 edition question — TR to confirm. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mmtr_dos[] = {
    { "A",       IEC61850_CDC_WYE,  false },
    { "Beh",     IEC61850_CDC_INS,  true  },
    { "HA",      IEC61850_CDC_HMV,  false },
    { "Health",  IEC61850_CDC_INS,  true  },
    { "HPhV",    IEC61850_CDC_HWYE, false },
    { "HPPV",    IEC61850_CDC_HDEL, false },
    { "Hz",      IEC61850_CDC_MV,   false },
    { "Mod",     IEC61850_CDC_INC,  true  },
    { "NamPlt",  IEC61850_CDC_LPL,  true  },
    { "PPV",     IEC61850_CDC_DEL,  false },
    { "PhV",     IEC61850_CDC_WYE,  false },
    { "TotVA",   IEC61850_CDC_MV,   false },
    { "TotVAr",  IEC61850_CDC_MV,   false },
    { "TotVArh", IEC61850_CDC_BCR,  false },
    { "TotW",    IEC61850_CDC_MV,   false },
    { "TotWh",   IEC61850_CDC_BCR,  false },
    { "VA",      IEC61850_CDC_WYE,  false },
    { "VAr",     IEC61850_CDC_WYE,  false },
    { "W",       IEC61850_CDC_WYE,  false },
};

/* ------------------------------------------------------------------
 * MMXN — Measurement of disturbance-recording values (7-4 group 3)
 *
 * Judgment call: MMXN is the measurement memory for disturbance
 * recording (companion of RDRE); whether 7-4 scopes it to
 * unscaled or recorded values is edition-dependent. The table
 * carries a conservative MMXU-like measurement subset, all O.
 * Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mmxn_dos[] = {
    { "A",      IEC61850_CDC_WYE, false },
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Hz",     IEC61850_CDC_MV,  false },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "PPV",    IEC61850_CDC_DEL, false },
    { "PhV",    IEC61850_CDC_WYE, false },
    { "VA",     IEC61850_CDC_WYE, false },
    { "VAr",    IEC61850_CDC_WYE, false },
    { "W",      IEC61850_CDC_WYE, false },
};

/* ------------------------------------------------------------------
 * MMXU — Measurement (7-4 group 3)
 *
 * Judgment call: in 7-4 the measurement DOs are O/C (the deployed
 * subset is configuration-dependent; profiles require at least one
 * MX DO), so only the LN-common DOs are M and every measurement is
 * an optional DO added via iec61850_ln_add_ln_class_do(). Flagged.
 * Retro-fix (WP-6c): the Ed.2 optional harmonic DOs HA (HMV),
 * HPhV (HWYE) and HPPV (HDEL), omitted at pilot time because the
 * CDCs were WP-S6 stubs, are added back now that the WP-6a
 * factories exist (the WP-6b pilot comments recorded this plan).
 * Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mmxu_dos[] = {
    { "A",       IEC61850_CDC_WYE,  false },
    { "Beh",     IEC61850_CDC_INS,  true  },
    { "HA",      IEC61850_CDC_HMV,  false },
    { "Health",  IEC61850_CDC_INS,  true  },
    { "HPhV",    IEC61850_CDC_HWYE, false },
    { "HPPV",    IEC61850_CDC_HDEL, false },
    { "Hz",      IEC61850_CDC_MV,   false },
    { "Mod",     IEC61850_CDC_INC,  true  },
    { "NamPlt",  IEC61850_CDC_LPL,  true  },
    { "PPV",     IEC61850_CDC_DEL,  false },
    { "PhV",     IEC61850_CDC_WYE,  false },
    { "TotVA",   IEC61850_CDC_MV,   false },
    { "TotVAr",  IEC61850_CDC_MV,   false },
    { "TotVArh", IEC61850_CDC_BCR,  false },
    { "TotW",    IEC61850_CDC_MV,   false },
    { "TotWh",   IEC61850_CDC_BCR,  false },
    { "VA",      IEC61850_CDC_WYE,  false },
    { "VAr",     IEC61850_CDC_WYE,  false },
    { "W",       IEC61850_CDC_WYE,  false },
};

/* ------------------------------------------------------------------
 * MRDR — Disturbance recording measurement (7-4 group 3, M family)
 *
 * WP-6d1 (owner-directed relaxed policy — best-recall DO sets
 * with flags): MRDR was on the WP-6c deferral list (DO set not
 * reconstructible). Best recall places it as the M-family
 * disturbance-recording measurement companion of RDRE (group 2).
 * The class-specific DO family could not be recalled with
 * confidence even under the relaxed policy (RDRE's RcdMade
 * belongs to RDRE, not MRDR), so the table carries the LN-common
 * subset only — the acceptable minimum per the WP-6d1 policy. TR
 * to verify existence, name and DO set. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mrdr_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * MSQI — Sequence and imbalance (7-4 group 3)
 *
 * SeqA/SeqV are the current/voltage sequence components; ImbA/
 * ImbV the current/voltage imbalance. All O. Judgment calls
 * (flagged):
 *  - SeqA/SeqV are typed with the house SEQ CDC (built in the
 *    WP-6a harmonics batch as the sequence form); a 7-3-literal
 *    typing would be CMV (sequence values are complex). TR to
 *    confirm the intended CDC.
 *  - ImbA/ImbV DO names are best clean-room recall; TR to
 *    confirm.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t msqi_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "ImbA",   IEC61850_CDC_MV,  false },
    { "ImbV",   IEC61850_CDC_MV,  false },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "SeqA",   IEC61850_CDC_SEQ, false },
    { "SeqV",   IEC61850_CDC_SEQ, false },
};

/* ------------------------------------------------------------------
 * MSTA — Statistical and skew (7-4 group 3, M family)
 *
 * Judgment call: the statistics DO family (mean/min/max and skew
 * evaluation of measured quantities) could not be recalled with
 * confidence from clean-room 7-4 knowledge, so the conservative
 * table carries the LN-common subset only and the statistics DOs
 * are deferred pending TR verification of the 7-4 names. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t msta_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * SCBR — Supervision of circuit breaker (7-4 group 3, S family)
 *
 * Breaker condition monitoring. Judgment call: the class-specific
 * DO family (operation counters, operation times, wear/travel
 * curve data) could not be recalled with confidence from clean-
 * room 7-4 knowledge, so the conservative table carries the
 * LN-common subset only. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t scbr_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * SIML — Supervision of current imbalance (7-4 group 3, S family)
 *
 * Judgment call: the monitored-quantity and alarm DO family could
 * not be recalled with confidence from clean-room 7-4 knowledge
 * (nor could the exact 7-4 scope of the class be pinned), so the
 * conservative table carries the LN-common subset only. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t siml_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * SIMS — Supervision of insulation medium (7-4 group 3, S family)
 *
 * Insulation monitoring (e.g., SF6 gas). Judgment call: the
 * gas-density/pressure DO family could not be recalled with
 * confidence from clean-room 7-4 knowledge, so the conservative
 * table carries the LN-common subset only. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t sims_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * SPDC — Supervision of partial discharge (7-4 group 3, S family)
 *
 * Judgment call: the partial-discharge magnitude/count DO family
 * could not be recalled with confidence from clean-room 7-4
 * knowledge, so the conservative table carries the LN-common
 * subset only. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t spdc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * SPTR — Supervision of power transformer (7-4 group 3, S family)
 *
 * Judgment call: the transformer-condition DO family (thermal/
 * loading condition data) could not be recalled with confidence
 * from clean-room 7-4 knowledge, so the conservative table
 * carries the LN-common subset only. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t sptr_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * SQVL — Supervision of voltage quality (7-4 group 3, S family)
 *
 * Judgment call: the voltage-quality indication DO family could
 * not be recalled with confidence from clean-room 7-4 knowledge,
 * so the conservative table carries the LN-common subset only.
 * Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t sqvl_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * SSIL — Supervision of current level (7-4 group 3, S family)
 *
 * Judgment call: the threshold-exceedance status DO family could
 * not be recalled with confidence from clean-room 7-4 knowledge,
 * so the conservative table carries the LN-common subset only.
 * Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ssil_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * STMP — Supervision of temperature (7-4 group 3, S family)
 *
 * Tmp (MV) is the supervised temperature value, listed O.
 * Judgment call: further thermal DOs (hot-spot/winding/gradients)
 * are deferred pending TR verification of the 7-4 names. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t stmp_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Tmp",    IEC61850_CDC_MV,  false },
};

const iec61850_ln_class_def_t ln_group3_classes[LN_GROUP3_CLASS_COUNT] = {
    { "MDIF", mdif_dos, 4U  },
    { "MFLK", mflk_dos, 6U  },
    { "MHAI", mhai_dos, 7U  },
    { "MHAS", mhas_dos, 7U  },
    { "MMTR", mmtr_dos, 19U },
    { "MMXN", mmxn_dos, 11U },
    { "MMXU", mmxu_dos, 19U },
    { "MRDR", mrdr_dos, 4U  },
    { "MSQI", msqi_dos, 8U  },
    { "MSTA", msta_dos, 4U  },
    { "SCBR", scbr_dos, 4U  },
    { "SIML", siml_dos, 4U  },
    { "SIMS", sims_dos, 4U  },
    { "SPDC", spdc_dos, 4U  },
    { "SPTR", sptr_dos, 4U  },
    { "SQVL", sqvl_dos, 4U  },
    { "SSIL", ssil_dos, 4U  },
    { "STMP", stmp_dos, 5U  },
};
