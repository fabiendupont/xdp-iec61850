/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Shallow BER TLV Walker for BPF
 *
 * Walks BER TLV structure with a BOUNDED loop (max_iterations).
 * Returns offset of the target tag, or -1 if not found.
 *
 * CRITICAL: The loop MUST be bounded for the BPF verifier.
 *
 * All packet accesses use (ptr + N > data_end) checks so the
 * verifier can track packet pointer ranges correctly.
 */

#ifndef BER_SHALLOW_BPF_H
#define BER_SHALLOW_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define BER_MAX_ITERATIONS  15

/*
 * Parse BER length at data[offset].
 * Returns number of bytes consumed by the length field, or -1 on error.
 * Sets *length to the decoded length value.
 *
 * Uses data_end for verifier-friendly packet bounds checks.
 */
static __always_inline int ber_parse_length(const __u8 *data, void *data_end,
                                             int offset, __u32 *length)
{
    const __u8 *p = data + offset;
    if ((void *)(p + 1) > data_end)
        return -1;

    __u8 first = *p;

    if ((first & 0x80) == 0) {
        /* Short form — value 0..127 */
        *length = first;
        return 1;
    }

    __u8 num_bytes = first & 0x7F;

    if (num_bytes == 1) {
        if ((void *)(p + 2) > data_end) return -1;
        *length = p[1];
        return 2;
    }
    if (num_bytes == 2) {
        if ((void *)(p + 3) > data_end) return -1;
        *length = ((__u32)p[1] << 8) | p[2];
        /* Cap to MTU to keep verifier offset tracking bounded */
        if (*length > 1500) *length = 1500;
        return 3;
    }

    return -1;  /* Indefinite or > 2 bytes — reject */
}

/*
 * Find a BER tag in a TLV sequence.
 *
 * Walks TLV entries starting at 'offset', looking for 'target_tag'.
 * Loop is bounded by BER_MAX_ITERATIONS for BPF verifier safety.
 *
 * Returns: offset of the VALUE (after tag+length) if found, -1 if not found.
 * Sets *value_len to the length of the value.
 */
static __always_inline int ber_find_tag(const __u8 *data, void *data_end,
                                         int offset, __u8 target_tag,
                                         __u32 *value_len)
{
    for (int i = 0; i < BER_MAX_ITERATIONS; i++) {
        const __u8 *p = data + offset;
        if ((void *)(p + 1) > data_end)
            return -1;

        __u8 tag = *p;
        offset++;

        __u32 length = 0;
        int len_bytes = ber_parse_length(data, data_end, offset, &length);
        if (len_bytes < 0)
            return -1;

        offset += len_bytes;

        if (tag == target_tag) {
            *value_len = length;
            return offset;  /* Start of value */
        }

        /* Skip this TLV's value */
        offset += length;
    }

    return -1;  /* Not found within iteration limit */
}

/*
 * Find two BER tags in a single bounded loop (verifier-optimized).
 *
 * Uses simplified length parsing: only short form (<128) and 1-byte
 * long form (0x81 xx). This eliminates the 2-byte long form (0x82)
 * branch, halving verifier state space per iteration. Safe for GOOSE
 * APDU fields which are all < 256 bytes before stNum/sqNum.
 *
 * Returns 0 if at least tag1 was found, -1 if tag1 not found.
 */
static __always_inline int ber_find_two_tags(const __u8 *data, void *data_end,
                                              int offset,
                                              __u8 tag1, int *val1_offset,
                                              __u32 *val1_len,
                                              __u8 tag2, int *val2_offset,
                                              __u32 *val2_len)
{
    int found = 0;
    *val1_offset = -1;
    *val2_offset = -1;
    *val1_len = 0;
    *val2_len = 0;

    /* Use 8 iterations max — GOOSE stNum is field [5], sqNum is field [6],
     * so 7 iterations suffices with 1 margin. Using BER_MAX_ITERATIONS (15)
     * causes the verifier to exceed 1M instructions from state explosion. */
    for (int i = 0; i < 8; i++) {
        const __u8 *p = data + offset;
        if ((void *)(p + 1) > data_end)
            return -1;

        __u8 tag = *p;
        offset++;

        /* Simplified length: short form or 1-byte long form only.
         * Avoids 2-byte (0x82) branch that causes verifier explosion. */
        const __u8 *lp = data + offset;
        if ((void *)(lp + 1) > data_end)
            return -1;
        __u32 length;
        if (*lp < 0x80) {
            length = *lp;
            offset++;
        } else if (*lp == 0x81) {
            if ((void *)(lp + 2) > data_end)
                return -1;
            length = lp[1];
            offset += 2;
        } else {
            return -1;
        }

        if (tag == tag1) {
            *val1_offset = offset;
            *val1_len = length;
            found++;
        } else if (tag == tag2) {
            *val2_offset = offset;
            *val2_len = length;
            found++;
        }

        if (found >= 2)
            return 0;

        offset += length;
    }

    return (*val1_offset >= 0) ? 0 : -1;
}

/*
 * Extract a uint32 from BER integer value at given offset.
 * The value must be 1-4 bytes (BER unsigned integer encoding).
 */
static __always_inline int ber_extract_uint32(const __u8 *data, void *data_end,
                                               int offset, __u32 value_len,
                                               __u32 *result)
{
    if (value_len == 0 || value_len > 4)
        return -1;

    const __u8 *p = data + offset;
    if ((void *)(p + value_len) > data_end)
        return -1;

    *result = 0;
    if (value_len >= 1) {
        if ((void *)(p + 1) > data_end) return -1;
        *result = p[0];
    }
    if (value_len >= 2) {
        if ((void *)(p + 2) > data_end) return -1;
        *result = (*result << 8) | p[1];
    }
    if (value_len >= 3) {
        if ((void *)(p + 3) > data_end) return -1;
        *result = (*result << 8) | p[2];
    }
    if (value_len >= 4) {
        if ((void *)(p + 4) > data_end) return -1;
        *result = (*result << 8) | p[3];
    }

    return 0;
}

#endif /* BER_SHALLOW_BPF_H */
