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
 * TCTR — Current transformer (7-4, T family)
 *
 * AmpSv (SAV) is the sampled current value (merging-unit /
 * sampled-value contexts). Grouping judgment call (flagged): the
 * T-family (instrument transformer) LNs were not assigned in the
 * WP-6c briefs; TCTR/TVTR are placed here per the group-4
 * "interfacing/power-related" scope.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t tctr_dos[] = {
    { "AmpSv",  IEC61850_CDC_SAV, false },
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
};

/* ------------------------------------------------------------------
 * TVTR — Voltage transformer (7-4, T family)
 *
 * VolSv (SAV) is the sampled voltage value (merging-unit /
 * sampled-value contexts). Same grouping judgment call and flag
 * as TCTR above.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t tvtr_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "VolSv",  IEC61850_CDC_SAV, false },
};

/* ------------------------------------------------------------------
 * YLTC — Load tap changer (7-4, Y family)
 *
 * TapPos (ISC) is the tap position — the classic integer status
 * control use. Judgment calls (flagged): DO name/CDC per best
 * clean-room recall, TR to confirm; Y-family placement in group 4
 * follows the brief's "power-related" scope, as with the
 * companion control ATCC above.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t yltc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "TapPos", IEC61850_CDC_ISC, false },
};

const iec61850_ln_class_def_t ln_group4_classes[LN_GROUP4_CLASS_COUNT] = {
    { "ACDR", acdr_dos, 4U  },
    { "ATCC", atcc_dos, 5U  },
    { "GAPC", gapc_dos, 5U  },
    { "GGIO", ggio_dos, 10U },
    { "IHMI", ihmi_dos, 4U  },
    { "TCTR", tctr_dos, 5U  },
    { "TVTR", tvtr_dos, 5U  },
    { "YLTC", yltc_dos, 5U  },
};
