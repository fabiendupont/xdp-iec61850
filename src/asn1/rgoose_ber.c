/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-GOOSE Codec
 *
 * WP-S4 scaffold: implemented by WP-4a (rgoose-codec) against the
 * frozen interface in include/iec61850/asn1/r_profile.h.
 */

#include "asn1/r_profile.h"

#include <errno.h>

int iec61850_rgoose_encode(const goose_apdu_t *apdu,
                            const iec61850_r_security_t *sec,
                            uint8_t *buf, size_t buflen)
{
    (void)apdu;
    (void)sec;
    (void)buf;
    (void)buflen;
    return -ENOSYS; /* implemented by WP-4a */
}

int iec61850_rgoose_decode(const uint8_t *buf, size_t buflen,
                            goose_apdu_t *apdu,
                            iec61850_r_header_t *hdr)
{
    (void)buf;
    (void)buflen;
    (void)apdu;
    (void)hdr;
    return -ENOSYS; /* implemented by WP-4a */
}
