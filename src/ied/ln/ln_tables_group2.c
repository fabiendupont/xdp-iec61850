/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — group 2: protection
 *
 * Pilot classes (WP-6b): PTOC, PDIS. WP-6c appends the remaining
 * group-2 classes in priority order: core distribution/transmission
 * protection first, then the protection-related R classes, then the
 * instrument transformers commonly grouped with protection.
 *
 * Same conventions as ln_tables_group1.c: conservative common
 * subset across 7-4 editions, CDCs restricted to the implemented
 * factories in src/ied/ied_data_model.c (full 33-CDC dispatch
 * after the WP-6c pre-steps). Judgment calls and edition
 * ambiguities are flagged per class below; see the WP-6c group-2
 * report for the full list.
 *
 * Batch-wide judgment calls (apply to every class below):
 *  - Protection classes carry Str (ACD) + Op (ACT) as their
 *    start/trip statuses where 7-4 defines them; simple pickup
 *    classes additionally list StrVal (ASG, pickup setting) as the
 *    common optional, mirroring the PTOC pilot.
 *  - Function-specific setting groups (ING/ENG stage counts,
 *    time/curve characteristics, ASG bias/restraint slopes) are
 *    configuration-specific and omitted — flagged per class.
 *  - WP-6c deferred the classes whose names/DO sets could not be
 *    confirmed against 7-4 from clean-room knowledge: PSCH, PNPH,
 *    PPBR, PVOC, PVPH, PVMV, RDIR, PMRI. WP-6d1 adds them under
 *    the owner-directed relaxed policy — best-recall DO sets with
 *    the uncertain DOs listed OPTIONAL (instantiation never
 *    depends on the recall) and TR-flagged per class below. The
 *    R-family extension RPSB joins them in the WP-6d1 batch. The
 *    orchestrator's PVOF/PVUF (over/underfrequency) map to the
 *    7-4 classes PTOF/PTUF implemented above.
 */

#include "ln_schema_tables.h"

/* ------------------------------------------------------------------
 * PTOC — Time overcurrent protection (7-4 group 2)
 *
 * Str (ACD) and Op (ACT) are the protection start/trip statuses.
 * Judgment call: the repo's scl_ied_builder models PTOC.Op as SPC;
 * 7-4 types it ACT. The table follows 7-4. Flagged.
 * StrVal (ASG, pickup current) is listed O; Ed.2 timing settings
 * (ING family) are omitted — CDC not implemented. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ptoc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PDIS — Distance protection (7-4 group 2)
 *
 * Conservative: Str/Op plus the LN-common DOs. Zone/reach settings
 * (ASG/ING families) are configuration-specific and not listed —
 * flagged; nothing mandatory needs a stub CDC.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pdis_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * PIOC — Instantaneous overcurrent protection (7-4 group 2)
 *
 * Same shape as the PTOC pilot: Str/Op plus the common optional
 * pickup setting StrVal (ASG). High-set stage settings (ING) are
 * configuration-specific and omitted — flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pioc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PTOV — Overvoltage protection (7-4 group 2)
 *
 * Judgment calls: stage/time-curve settings (ASG/ING families) are
 * omitted like PTOC's; StrVal (ASG, pickup voltage) is the common
 * optional. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ptov_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PTUV — Undervoltage protection (7-4 group 2)
 *
 * Judgment calls: as PTOV — stage settings omitted, StrVal (ASG,
 * pickup voltage) listed O. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ptuv_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PTOF — Overfrequency protection (7-4 group 2)
 *
 * The orchestrator brief lists this as "PVOF"; 7-4 names the class
 * PTOF — the table follows 7-4. Flagged. Stage and df/dt settings
 * omitted; StrVal (ASG, pickup frequency) listed O. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ptof_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PTUF — Underfrequency protection (7-4 group 2)
 *
 * Orchestrator brief name "PVUF" maps to 7-4's PTUF — flagged as
 * with PTOF. Same conservative shape.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ptuf_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PTTR — Thermal protection (7-4 group 2)
 *
 * Thermal-overload protection. Judgment calls: thermal replica
 * settings (ASG, e.g. thermal rating / time constants) reduced to
 * the common optional StrVal; further Ed.2 statuses omitted —
 * flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pttr_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PDIF — Differential protection (7-4 group 2)
 *
 * Conservative Str/Op like the PDIS pilot. Bias/restraint
 * characteristic settings (ASG/ING families) are configuration-
 * specific and omitted — flagged; nothing mandatory needs a stub
 * CDC.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pdif_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * PDIR — Directional protection (7-4 group 2)
 *
 * Directional-comparison protection. Judgment calls: the per-phase
 * directional statuses (ACD phased variants) are reduced to the
 * common Str; pilot-scheme settings omitted — flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pdir_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * PHAR — Harmonic restraint (differential) protection (7-4 group 2)
 *
 * Transformer inrush restraint. Judgment calls: harmonic-threshold
 * settings (ASG per harmonic) omitted — flagged; nothing mandatory
 * needs a stub CDC.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t phar_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * PTEF — Sensitive earth-fault protection (7-4 group 2)
 *
 * Judgment calls: sensitive-pickup settings (ASG) and per-phase
 * directional statuses omitted — flagged; conservative Str/Op
 * subset like PDIS.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ptef_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * PDOP — Directional overpower protection (7-4 group 2)
 *
 * Judgment calls: forward/reverse power settings (ASG) omitted —
 * flagged; conservative Str/Op subset.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pdop_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * PDUP — Directional underpower protection (7-4 group 2)
 *
 * Judgment calls: as PDOP — power settings omitted, conservative
 * Str/Op subset. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pdup_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * PTRC — Protection trip conditioning (7-4 Ed.2 group 2)
 *
 * Conditions protection trips towards the breaker. Judgment call:
 * PTRC is an Ed.2 class (absent from Ed.1) — included because every
 * Ed.2 protection profile instantiates it between the P-function
 * and XCBR; flagged as Ed.2-only.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ptrc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * PMSS — Motor starting supervision (7-4 group 2)
 *
 * Judgment calls: start counter (BCR-family) and start-time curve
 * settings (ASG/ING) are omitted — flagged; conservative Str/Op
 * subset. Included on profile evidence; the WP-6c deferred
 * candidates (PMRI and kin) were added by the WP-6d1 batch at the
 * bottom of this file.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pmss_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * RBRF — Breaker failure protection (7-4 protection-related)
 *
 * Judgment calls: Str (ACD, breaker-failure element started) and
 * Op (ACT, breaker-failure trip) both listed M; retrip/stage
 * outputs and BF timers (ING) omitted — flagged. Kept in group 2
 * per the repo's protection grouping.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t rbrf_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * RREC — Auto-reclosing (7-4 protection-related)
 *
 * Judgment calls: only Op (ACT, reclose command issued) is listed
 * M and Str (ACD, recloser started) O — the 7-4 reclose-cycle
 * statuses/counters have profile-specific shapes and are omitted —
 * flagged. Group placement (7-4 protection-related, kept with
 * group 2 per the repo convention) — flagged for the TR review.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t rrec_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, false },
};

/* ------------------------------------------------------------------
 * RSYN — Check synchronism (7-4 protection-related)
 *
 * Judgment calls: the per-phase synchro-check statuses could not
 * be confirmed from clean-room knowledge and are omitted — only
 * Op (ACT, synchronism-check output) is listed M. Flagged for the
 * TR review.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t rsyn_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
};

/* ------------------------------------------------------------------
 * RDRE — Disturbance recording (7-4 protection-related)
 *
 * RcdMade (ACT) is the recording-made status. Judgment calls:
 * trigger and channel statuses are omitted — flagged. Group
 * placement (recording, kept with group 2 per the repo
 * convention) — flagged for the TR review.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t rdre_dos[] = {
    { "Beh",     IEC61850_CDC_INS, true },
    { "Health",  IEC61850_CDC_INS, true },
    { "Mod",     IEC61850_CDC_INC, true },
    { "NamPlt",  IEC61850_CDC_LPL, true },
    { "RcdMade", IEC61850_CDC_ACT, true },
};

/* ------------------------------------------------------------------
 * RFLO — Fault locator (7-4 protection-related)
 *
 * Judgment call: the fault-distance outputs are MV-family DOs
 * whose exact 7-4 names could not be confirmed from clean-room
 * knowledge and are omitted — the class lists only the LN-common
 * DOs (same shape as LLN0). Flagged for a follow-up batch.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t rflo_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true },
    { "Health", IEC61850_CDC_INS, true },
    { "Mod",    IEC61850_CDC_INC, true },
    { "NamPlt", IEC61850_CDC_LPL, true },
};

/* ------------------------------------------------------------------
 * TCTR — Current transformer (7-4 instrument transformer,
 * grouped with protection)
 *
 * Amp (MV) is the secondary current. Judgment calls: rating and
 * harmonic-content DOs are omitted — flagged. Group placement
 * (instrument transformer kept in group 2 per the repo
 * convention) — flagged for the TR review.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t tctr_dos[] = {
    { "Amp",    IEC61850_CDC_MV,  true },
    { "Beh",    IEC61850_CDC_INS, true },
    { "Health", IEC61850_CDC_INS, true },
    { "Mod",    IEC61850_CDC_INC, true },
    { "NamPlt", IEC61850_CDC_LPL, true },
};

/* ------------------------------------------------------------------
 * TVTR — Voltage transformer (7-4 instrument transformer,
 * grouped with protection)
 *
 * Vol (MV) is the secondary voltage. Judgment calls: as TCTR —
 * rating DOs omitted, group placement flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t tvtr_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true },
    { "Health", IEC61850_CDC_INS, true },
    { "Mod",    IEC61850_CDC_INC, true },
    { "NamPlt", IEC61850_CDC_LPL, true },
    { "Vol",    IEC61850_CDC_MV,  true },
};

/* ------------------------------------------------------------------
 * WP-6d1 batch — owner-directed relaxed policy (best-recall DO
 * sets, uncertain DOs OPTIONAL + TR-flagged per class; common-only
 * shells with flagged optionals are the accepted minimum).
 * ------------------------------------------------------------------
 * PMRI — Motor restart inhibition (7-4 Ed.2 group 2)
 *
 * Blocks motor restart after a supply interruption until the
 * voltage has recovered. Judgment calls (TR): the
 * restart-inhibition operation is best-recalled as Op (ACT)
 * listed M with Str (ACD) O, mirroring RREC's operation-issued
 * shape; the supervision settings (ASG voltage-recovery
 * thresholds, restart delay times) and counting statuses are
 * omitted — flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pmri_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, false },
};

/* ------------------------------------------------------------------
 * PNPH — Negative-phase protection (WP-6c deferral, WP-6d1 add)
 *
 * TR (class-level): the class name could not be confirmed against
 * 7-4 from clean-room knowledge — it may be a profile-specific
 * name for negative-sequence (unbalance) protection, commonly
 * realized in profiles as a PTOC variant measuring the
 * negative-sequence current. Added per the owner's directive
 * under the relaxed policy: LN-common M DOs plus Str/Op listed O
 * (TR) so instantiation never depends on the recall.
 * Negative-sequence pickup/bias settings (ASG) omitted — TR.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pnph_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, false },
    { "Str",    IEC61850_CDC_ACD, false },
};

/* ------------------------------------------------------------------
 * PPBR — Phase balance/reversal protection (WP-6c deferral,
 * WP-6d1 add)
 *
 * TR (class-level): the class name could not be confirmed against
 * 7-4 from clean-room knowledge — the best recall places it in
 * the motor-protection family (phase-balance / phase-reversal,
 * alongside PMSS/PMRI). Added per the owner's directive under the
 * relaxed policy: LN-common M DOs plus Str/Op listed O (TR) so
 * instantiation never depends on the recall. Phase-balance
 * settings (ASG) omitted — TR.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ppbr_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, false },
    { "Str",    IEC61850_CDC_ACD, false },
};

/* ------------------------------------------------------------------
 * PSCH — Protection scheme coordination (7-4 Ed.2 group 2)
 *
 * Coordinates teleprotection schemes (blocking / permissive /
 * intertrip signal exchange between line ends). Judgment calls
 * (TR): the class is Ed.2; the per-scheme signal statuses
 * (per-input blocking/transfer-trip) could not be recalled from
 * clean-room knowledge and are omitted. Op (ACT, coordinated
 * scheme trip output) is listed M and Str (ACD, scheme element
 * started) O, mirroring RREC's operation-issued shape. Scheme
 * coordination settings (scheme type, receive/transmit
 * configuration) omitted — TR.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t psch_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, false },
};

/* ------------------------------------------------------------------
 * PVOC — Overcurrent protection variant (WP-6c deferral, WP-6d1
 * add)
 *
 * TR (class-level): the class name could not be confirmed against
 * 7-4 from clean-room knowledge — 7-4's overcurrent classes are
 * PTOC/PIOC (both already in the registry); this name may be a
 * profile-specific variant. Added per the owner's directive under
 * the relaxed policy: LN-common M DOs plus Str/Op/StrVal listed O
 * (TR) so instantiation never depends on the recall. Distinct
 * class name — not a registry duplicate of PTOC/PIOC.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pvoc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, false },
    { "Str",    IEC61850_CDC_ACD, false },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PVPH — Phase-voltage protection variant (WP-6c deferral,
 * WP-6d1 add)
 *
 * TR (class-level): the class name could not be confirmed against
 * 7-4 from clean-room knowledge — 7-4's voltage classes are
 * PTOV/PTUV (both already in the registry); this name may be a
 * profile-specific phase-voltage variant. Added per the owner's
 * directive under the relaxed policy: LN-common M DOs plus
 * Str/Op/StrVal listed O (TR) so instantiation never depends on
 * the recall. Distinct class name — not a registry duplicate of
 * PTOV/PTUV.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pvph_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, false },
    { "Str",    IEC61850_CDC_ACD, false },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PVMV — Motor-voltage protection variant (WP-6c deferral,
 * WP-6d1 add)
 *
 * TR (class-level): the class name could not be confirmed against
 * 7-4 from clean-room knowledge — the best recall places it in
 * the motor-protection family (supply-voltage supervision,
 * alongside PMRI). Added per the owner's directive under the
 * relaxed policy: LN-common M DOs plus Str/Op/StrVal listed O
 * (TR) so instantiation never depends on the recall. Distinct
 * class name — not a registry duplicate of PTUV/PMRI.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pvmv_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, false },
    { "Str",    IEC61850_CDC_ACD, false },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * RDIR — Directional earth-fault protection (7-4
 * protection-related; WP-6c deferral, WP-6d1 add)
 *
 * Judgment calls (TR): Str (ACD — the directional start carries
 * dirGeneral/dirNeut, exactly the ACD purpose) and Op (ACT) are
 * listed M, mirroring the PTEF/PDIR family shape; the exact 7-4
 * DO set could not be confirmed from clean-room knowledge.
 * Directional/characteristic settings (ASG, e.g. sensitive
 * directional pickup) omitted — flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t rdir_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

/* ------------------------------------------------------------------
 * RPSB — Protection supervision (7-4 protection-related)
 *
 * WP-6d1 R-family extension (the only remaining R class placeable
 * with confidence: Ed.1 protection-equipment supervision, e.g.
 * trip-circuit supervision; RBRF/RDRE/RSYN/RREC/RDIR cover the
 * rest). Judgment call (TR): the signature supervision statuses
 * could not be recalled from clean-room knowledge — common-only
 * shell (same shape as RFLO), omitted statuses flagged for a
 * follow-up batch.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t rpsb_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true },
    { "Health", IEC61850_CDC_INS, true },
    { "Mod",    IEC61850_CDC_INC, true },
    { "NamPlt", IEC61850_CDC_LPL, true },
};

const iec61850_ln_class_def_t ln_group2_classes[LN_GROUP2_CLASS_COUNT] = {
    /* pilots (WP-6b, byte-identical; the frozen test asserts
     * their DO counts) */
    { "PDIS", pdis_dos, 6U },
    { "PTOC", ptoc_dos, 7U },
    /* WP-6c batch — priority order:
     * core distribution/transmission protection */
    { "PIOC", pioc_dos, 7U },
    { "PTOV", ptov_dos, 7U },
    { "PTUV", ptuv_dos, 7U },
    { "PTOF", ptof_dos, 7U },
    { "PTUF", ptuf_dos, 7U },
    { "PTTR", pttr_dos, 7U },
    { "PDIF", pdif_dos, 6U },
    { "PDIR", pdir_dos, 6U },
    { "PHAR", phar_dos, 6U },
    { "PTEF", ptef_dos, 6U },
    { "PDOP", pdop_dos, 6U },
    { "PDUP", pdup_dos, 6U },
    { "PTRC", ptrc_dos, 6U },
    { "PMSS", pmss_dos, 6U },
    /* protection-related R classes */
    { "RBRF", rbrf_dos, 6U },
    { "RREC", rrec_dos, 6U },
    { "RSYN", rsyn_dos, 5U },
    { "RDRE", rdre_dos, 5U },
    { "RFLO", rflo_dos, 4U },
    /* instrument transformers */
    { "TCTR", tctr_dos, 6U },
    { "TVTR", tvtr_dos, 6U },
    /* WP-6d1 relaxed-policy deferred batch (owner-directed):
     * uncertain DOs are O + TR-flagged per class above; the
     * registry total moves 54 -> 63 */
    { "PMRI", pmri_dos, 6U },
    { "PNPH", pnph_dos, 6U },
    { "PPBR", ppbr_dos, 6U },
    { "PSCH", psch_dos, 6U },
    { "PVOC", pvoc_dos, 7U },
    { "PVPH", pvph_dos, 7U },
    { "PVMV", pvmv_dos, 7U },
    { "RDIR", rdir_dos, 6U },
    { "RPSB", rpsb_dos, 4U },
};
