/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IED Type Conversions
 *
 * License: BSD-2-Clause
 */

#include "ied/ied_types.h"
#include <string.h>
#include <strings.h>

const char *iec61850_fc_to_string(iec61850_fc_t fc)
{
    switch (fc) {
        case IEC61850_FC_ST: return "ST";
        case IEC61850_FC_MX: return "MX";
        case IEC61850_FC_CO: return "CO";
        case IEC61850_FC_SP: return "SP";
        case IEC61850_FC_SV: return "SV";
        case IEC61850_FC_CF: return "CF";
        case IEC61850_FC_DC: return "DC";
        case IEC61850_FC_SG: return "SG";
        case IEC61850_FC_SE: return "SE";
        case IEC61850_FC_SR: return "SR";
        case IEC61850_FC_OR: return "OR";
        case IEC61850_FC_BL: return "BL";
        case IEC61850_FC_EX: return "EX";
        default:             return "??";
    }
}

iec61850_fc_t iec61850_string_to_fc(const char *str)
{
    if (str == NULL) { return IEC61850_FC_ST; }
    if (strcasecmp(str, "ST") == 0) { return IEC61850_FC_ST; }
    if (strcasecmp(str, "MX") == 0) { return IEC61850_FC_MX; }
    if (strcasecmp(str, "CO") == 0) { return IEC61850_FC_CO; }
    if (strcasecmp(str, "SP") == 0) { return IEC61850_FC_SP; }
    if (strcasecmp(str, "SV") == 0) { return IEC61850_FC_SV; }
    if (strcasecmp(str, "CF") == 0) { return IEC61850_FC_CF; }
    if (strcasecmp(str, "DC") == 0) { return IEC61850_FC_DC; }
    if (strcasecmp(str, "SG") == 0) { return IEC61850_FC_SG; }
    if (strcasecmp(str, "SE") == 0) { return IEC61850_FC_SE; }
    if (strcasecmp(str, "SR") == 0) { return IEC61850_FC_SR; }
    if (strcasecmp(str, "OR") == 0) { return IEC61850_FC_OR; }
    if (strcasecmp(str, "BL") == 0) { return IEC61850_FC_BL; }
    if (strcasecmp(str, "EX") == 0) { return IEC61850_FC_EX; }
    return IEC61850_FC_ST;
}

const char *iec61850_btype_to_string(iec61850_btype_t btype)
{
    switch (btype) {
        case IEC61850_BTYPE_BOOLEAN:        return "BOOLEAN";
        case IEC61850_BTYPE_INT8:           return "INT8";
        case IEC61850_BTYPE_INT8U:          return "INT8U";
        case IEC61850_BTYPE_INT16:          return "INT16";
        case IEC61850_BTYPE_INT16U:         return "INT16U";
        case IEC61850_BTYPE_INT32:          return "INT32";
        case IEC61850_BTYPE_INT32U:         return "INT32U";
        case IEC61850_BTYPE_INT64:          return "INT64";
        case IEC61850_BTYPE_INT128:          return "INT128";
        case IEC61850_BTYPE_FLOAT32:        return "FLOAT32";
        case IEC61850_BTYPE_FLOAT64:        return "FLOAT64";
        case IEC61850_BTYPE_ENUMERATED:     return "Enum";
        case IEC61850_BTYPE_CODED_ENUM:     return "CodedEnum";
        case IEC61850_BTYPE_OCTET_STRING:   return "OctetString";
        case IEC61850_BTYPE_VISIBLE_STRING: return "VisString";
        case IEC61850_BTYPE_UNICODE_STRING: return "Unicode";
        case IEC61850_BTYPE_TIMESTAMP:      return "Timestamp";
        case IEC61850_BTYPE_QUALITY:        return "Quality";
        case IEC61850_BTYPE_CHECK:          return "Check";
        case IEC61850_BTYPE_STRUCT:         return "Struct";
        case IEC61850_BTYPE_ENTRY_TIME:     return "EntryTime";
        case IEC61850_BTYPE_PHYS_COMM_ADDR: return "PhyComAddr";
        case IEC61850_BTYPE_CURRENCY:       return "Currency";
        case IEC61850_BTYPE_DBPOS:          return "Dbpos";
        default:                            return "UNKNOWN";
    }
}

const char *iec61850_cdc_to_string(iec61850_cdc_t cdc)
{
    switch (cdc) {
        case IEC61850_CDC_SPS:  return "SPS";
        case IEC61850_CDC_DPS:  return "DPS";
        case IEC61850_CDC_INS:  return "INS";
        case IEC61850_CDC_ENS:  return "ENS";
        case IEC61850_CDC_ACT:  return "ACT";
        case IEC61850_CDC_ACD:  return "ACD";
        case IEC61850_CDC_SEC:  return "SEC";
        case IEC61850_CDC_BSC:  return "BSC";
        case IEC61850_CDC_SPC:  return "SPC";
        case IEC61850_CDC_DPC:  return "DPC";
        case IEC61850_CDC_INC:  return "INC";
        case IEC61850_CDC_MV:   return "MV";
        case IEC61850_CDC_CMV:  return "CMV";
        case IEC61850_CDC_SAV:  return "SAV";
        case IEC61850_CDC_WYE:  return "WYE";
        case IEC61850_CDC_DEL:  return "DEL";
        case IEC61850_CDC_SPG:  return "SPG";
        case IEC61850_CDC_ASG:  return "ASG";
        case IEC61850_CDC_VSS:  return "VSS";
        case IEC61850_CDC_LPL:  return "LPL";
        case IEC61850_CDC_DPL:  return "DPL";
        case IEC61850_CDC_BCR:  return "BCR";
        case IEC61850_CDC_MX3:  return "MX3";
        case IEC61850_CDC_DEL3: return "DEL3";
        case IEC61850_CDC_APC:  return "APC";
        case IEC61850_CDC_ENC:  return "ENC";
        case IEC61850_CDC_ISC:  return "ISC";
        case IEC61850_CDC_CURS: return "CURS";
        case IEC61850_CDC_CSD:  return "CSD";
        case IEC61850_CDC_SEQ:  return "SEQ";
        case IEC61850_CDC_HMV:  return "HMV";
        case IEC61850_CDC_HWYE: return "HWYE";
        case IEC61850_CDC_HDEL: return "HDEL";
        default:               return "UNKNOWN";
    }
}
