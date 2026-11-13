/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-SV Codec
 *
 * WP-S4 scaffold: implemented by WP-4a (rgoose-codec) against the
 * frozen interface in include/iec61850/asn1/r_profile.h.
 */

#include "asn1/r_profile.h"

#include <errno.h>

int iec61850_rsv_encode(const sv_apdu_t *apdu,
                         const iec61850_r_security_t *sec,
                         uint8_t *buf, size_t buflen)
{
    (void)apdu;
    (void)sec;
    (void)buf;
    (void)buflen;
    return -ENOSYS; /* implemented by WP-4a */
}

int iec61850_rsv_decode(const uint8_t *buf, size_t buflen,
                         sv_apdu_t *apdu,
                         iec61850_r_header_t *hdr)
{
    (void)buf;
    (void)buflen;
    (void)apdu;
    (void)hdr;
    return -ENOSYS; /* implemented by WP-4a */
}

bool iec61850_r_time_in_window(uint32_t tod_received, uint32_t tod_last)
{
    (void)tod_received;
    (void)tod_last;
    return false; /* implemented by WP-4a */
}
