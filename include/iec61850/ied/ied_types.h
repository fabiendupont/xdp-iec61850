/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 IED Type System
 *
 * Enums and constants for the ACSI data model:
 * FunctionalConstraint, BasicType, CdcType, TriggerCondition.
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_IED_TYPES_H
#define IEC61850_IED_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IEC61850_FC_ST = 0,
    IEC61850_FC_MX = 1,
    IEC61850_FC_CO = 2,
    IEC61850_FC_SP = 3,
    IEC61850_FC_SV = 4,
    IEC61850_FC_CF = 5,
    IEC61850_FC_DC = 6,
    IEC61850_FC_SG = 7,
    IEC61850_FC_SE = 8,
    IEC61850_FC_SR = 9,
    IEC61850_FC_OR = 10,
    IEC61850_FC_BL = 11,
    IEC61850_FC_EX = 12
} iec61850_fc_t;

typedef enum {
    IEC61850_BTYPE_BOOLEAN = 0,
    IEC61850_BTYPE_INT8 = 1,
    IEC61850_BTYPE_INT8U = 2,
    IEC61850_BTYPE_INT16 = 3,
    IEC61850_BTYPE_INT16U = 4,
    IEC61850_BTYPE_INT32 = 5,
    IEC61850_BTYPE_INT32U = 6,
    IEC61850_BTYPE_INT64 = 7,
    IEC61850_BTYPE_INT128 = 8,
    IEC61850_BTYPE_FLOAT32 = 9,
    IEC61850_BTYPE_FLOAT64 = 10,
    IEC61850_BTYPE_ENUMERATED = 11,
    IEC61850_BTYPE_CODED_ENUM = 12,
    IEC61850_BTYPE_OCTET_STRING = 13,
    IEC61850_BTYPE_VISIBLE_STRING = 14,
    IEC61850_BTYPE_UNICODE_STRING = 15,
    IEC61850_BTYPE_TIMESTAMP = 16,
    IEC61850_BTYPE_QUALITY = 17,
    IEC61850_BTYPE_CHECK = 18,
    IEC61850_BTYPE_STRUCT = 19,
    IEC61850_BTYPE_ENTRY_TIME = 20,
    IEC61850_BTYPE_PHYS_COMM_ADDR = 21,
    IEC61850_BTYPE_CURRENCY = 22,
    IEC61850_BTYPE_DBPOS = 23
} iec61850_btype_t;

typedef enum {
    IEC61850_CDC_SPS = 0,
    IEC61850_CDC_DPS = 1,
    IEC61850_CDC_INS = 2,
    IEC61850_CDC_ENS = 3,
    IEC61850_CDC_ACT = 4,
    IEC61850_CDC_ACD = 5,
    IEC61850_CDC_SEC = 6,
    IEC61850_CDC_BSC = 7,
    IEC61850_CDC_SPC = 10,
    IEC61850_CDC_DPC = 11,
    IEC61850_CDC_INC = 12,
    IEC61850_CDC_MV = 20,
    IEC61850_CDC_CMV = 21,
    IEC61850_CDC_SAV = 22,
    IEC61850_CDC_WYE = 23,
    IEC61850_CDC_DEL = 24,
    IEC61850_CDC_SPG = 30,
    IEC61850_CDC_ASG = 31,
    IEC61850_CDC_VSS = 32,
    IEC61850_CDC_LPL = 40,
    IEC61850_CDC_DPL = 41,
    IEC61850_CDC_BCR = 50,
    IEC61850_CDC_MX3 = 60,
    IEC61850_CDC_DEL3 = 61
} iec61850_cdc_t;

const char *iec61850_fc_to_string(iec61850_fc_t fc);
iec61850_fc_t iec61850_string_to_fc(const char *str);
const char *iec61850_btype_to_string(iec61850_btype_t btype);
const char *iec61850_cdc_to_string(iec61850_cdc_t cdc);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_IED_TYPES_H */
