/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — group 4: interfacing /
 * archiving / power-related (generic)
 *
 * Pilot class (WP-6b): GGIO (pilot-optional; included because all
 * of its CDCs — SPS/INS/INC/SPC/DPC/LPL — are implemented).
 * WP-6c appends the remaining group-4 classes: the 7-4 G family
 * (generic I/O and process control), the A family (archiving),
 * the I family (interfacing) and the power-related T/Y family
 * entries assigned to this group by the WP-6c scope (ATCC and
 * the instrument/equipment transformers).
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
 * with flags): appends the deferred group-4 classes GCSW, GHAB,
 * GSHE and SWRI. SGCP from the WP-6c deferral list is NOT
 * registered: its existence as a 7-4 class could not be verified
 * from clean-room knowledge — flagged in the WP-6d1 report.
 */

#include "ln_schema_tables.h"

/* ------------------------------------------------------------------
 * ACDR — Archiving (7-4 group 4, A family)
 *
 * Judgment call: existence and name per best clean-room 7-4
 * recall and the WP-6c brief ("archiving classes (A-group)");
 * the archiving-control DO family could not be recalled with
 * confidence and is deferred pending TR verification. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t acdr_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * ATCC — Automatic tap changer control (7-4)
 *
 * Grouping judgment call (flagged): 7-4 editions list ATCC with
 * the control (C) family; the WP-6c brief assigns it to group 4
 * ("power-related") and this table follows the brief.
 * TapChg (BSC) is the tap step control (raise/lower). Judgment
 * call: the exact 7-4 DO name and CDC could not be confirmed
 * clean-room — BSC (step control) chosen as the closest
 * implemented CDC; the tap-position status belongs to YLTC.TapPos
 * below. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t atcc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "TapChg", IEC61850_CDC_BSC, false },
};

/* ------------------------------------------------------------------
 * GAPC — Generic automated process control (7-4 group 4)
 *
 * Auto (SPS) is the automatic-operation status. Judgment call:
 * the Ed.2 GAPC control DOs (APC/INC-typed process controls —
 * the CDCs are now implemented) could not be recalled with
 * confidence from clean-room 7-4 knowledge, so they are deferred
 * pending TR verification of the 7-4 DO names rather than
 * invented. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t gapc_dos[] = {
    { "Auto",   IEC61850_CDC_SPS, false },
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * GCSW — Generic switching control (7-4 group 4, G family)
 *
 * WP-6d1 (owner-directed relaxed policy — best-recall DO sets
 * with flags): GCSW was on the WP-6c deferral list. Best recall
 * reads the name as a generic G-family switching-control class,
 * but neither its exact 7-4 scope nor its DO set could be
 * recalled with confidence, so the table carries the LN-common
 * subset only — the acceptable minimum per the WP-6d1 policy. TR
 * to verify existence, name, scope and DO set. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t gcsw_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * GGIO — Generic process I/O (7-4 group 4)
 *
 * The generic status/control DOs are O in 7-4 (the deployed count
 * is device-specific and instance-numbered: Ind1..IndN etc.). The
 * table lists the canonical first instance of each kind; further
 * instances are added through the model API. Flagged.
 * No GGIO DO needs a WP-S6 stub CDC, so nothing is omitted here.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ggio_dos[] = {
    { "Alm",    IEC61850_CDC_SPS, false },
    { "Beh",    IEC61850_CDC_INS, true  },
    { "DPCSO1", IEC61850_CDC_DPC, false },
    { "Health", IEC61850_CDC_INS, true  },
    { "Ind1",   IEC61850_CDC_SPS, false },
    { "IntIn1", IEC61850_CDC_INS, false },
    { "ISCSO1", IEC61850_CDC_INC, false },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "SPCSO1", IEC61850_CDC_SPC, false },
};

/* ------------------------------------------------------------------
 * GHAB — Generic alarm block (7-4 group 4, G family)
 *
 * WP-6d1 (owner-directed relaxed policy — best-recall DO sets
 * with flags): GHAB was on the WP-6c deferral list. Best recall
 * reads it as a G-family generic alarm/handling block, but
 * neither its exact 7-4 scope nor its DO set could be recalled
 * with confidence, so the table carries the LN-common subset
 * only — the acceptable minimum per the WP-6d1 policy. TR to
 * verify existence, name, scope and DO set. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ghab_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * GSHE — Generic human interface (7-4 group 4)
 *
 * WP-6d1 (owner-directed relaxed policy — best-recall DO sets
 * with flags): the WP-6c brief named GSHE for the human
 * interface; WP-6c registered IHMI instead, and the owner
 * directed GSHE be added too. Both are now registered —
 * I-family overlap flagged: whether GSHE and IHMI are distinct
 * 7-4 classes, editions of the same concept, or a naming
 * confusion is not confirmable clean-room; TR to resolve (a
 * future batch may collapse them). The HMI-specific DOs are
 * deferred pending TR verification of the 7-4 names. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t gshe_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * IHMI — Human machine interface (7-4 group 4, I family)
 *
 * Judgment call (flagged for the orchestrator): the WP-6c brief
 * names "GSHE" for the human interface; that name could not be
 * confirmed from clean-room 7-4 knowledge, while IHMI matches the
 * 7-4 I family (interfacing). IHMI is included here and GSHE is
 * deferred. The HMI-specific DOs are deferred pending TR
 * verification of the 7-4 names.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ihmi_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * SWRI — Waveform recording (7-4)
 *
 * WP-6d1 (owner-directed relaxed policy — best-recall DO sets
 * with flags): SWRI was on the WP-6c deferral list (waveform
 * recording). Judgment calls (flagged):
 *  - placement: the WP-6d1 brief assigns SWRI to group 4, and
 *    this table follows it, but the S first letter would
 *    normally park it in group 3 (the S family per this repo's
 *    grouping); TR to confirm placement;
 *  - the class-specific DO set could not be recalled with
 *    confidence (RDRE's RcdMade belongs to RDRE), so the table
 *    carries the LN-common subset only — the acceptable minimum
 *    per the WP-6d1 policy. TR to verify existence, name and DO
 *    set.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t swri_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};



const iec61850_ln_class_def_t ln_group4_classes[LN_GROUP4_CLASS_COUNT] = {
    { "ACDR", acdr_dos, 4U  },
    { "ATCC", atcc_dos, 5U  },
    { "GAPC", gapc_dos, 5U  },
    { "GCSW", gcsw_dos, 4U  },
    { "GGIO", ggio_dos, 10U },
    { "GHAB", ghab_dos, 4U  },
    { "GSHE", gshe_dos, 4U  },
    { "IHMI", ihmi_dos, 4U  },
    { "SWRI", swri_dos, 4U  },
};
