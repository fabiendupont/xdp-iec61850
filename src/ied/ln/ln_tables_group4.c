/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — group 4: supervision / generic
 *
 * Pilot class (WP-6b): GGIO (pilot-optional; included because all
 * of its CDCs — SPS/INS/INC/SPC/DPC/LPL — are implemented).
 * WP-6c appends the remaining group-4 classes.
 *
 * Same conventions as ln_tables_group1.c: conservative common
 * subset across 7-4 editions, CDCs restricted to the implemented
 * factories in src/ied/ied_data_model.c.
 */

#include "ln_schema_tables.h"

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

const iec61850_ln_class_def_t ln_group4_classes[LN_GROUP4_CLASS_COUNT] = {
    { "GGIO", ggio_dos, 10U },
};

