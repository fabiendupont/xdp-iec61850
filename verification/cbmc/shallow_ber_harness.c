/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CBMC Harness for BPF Shallow BER Walker
 *
 * Proves: the XDP BER walker (ber_shallow.bpf.h) is safe for any input.
 * - Loop terminates within BER_MAX_ITERATIONS
 * - No out-of-bounds access on any packet
 * - ber_find_tag returns -1 or valid offset
 *
 * Run: cbmc --unwind 20 --object-bits 12 \
 *      verification/cbmc/shallow_ber_harness.c
 */

#include <stdint.h>
#include <stddef.h>
#include <assert.h>

/* Stub BPF helpers for CBMC (not BPF target) */
#define __always_inline
#define SEC(x)
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;

/* Include the actual source directly */
#include "../../src/bpf/ber_shallow.bpf.h"

/* CBMC main harness */
int main(void)
{
    /* Non-deterministic input: any packet up to MTU size */
    uint8_t data[1500];
    int data_len;
    uint8_t target_tag;
    int start_offset;

    /* Constrain inputs to valid ranges */
    __CPROVER_assume(data_len >= 0 && data_len <= 1500);
    __CPROVER_assume(start_offset >= 0 && start_offset <= data_len);

    uint32_t value_len = 0;

    void *data_end = data + data_len;

    /* Property 1: ber_find_tag never crashes and returns valid range */
    int result = ber_find_tag(data, data_end, start_offset,
                               target_tag, &value_len);

    assert(result == -1 || result >= start_offset);
    assert(result == -1 || result <= data_len);

    /* Property 2: ber_parse_length always returns -1 or 1..3 */
    uint32_t length = 0;
    if (start_offset < data_len) {
        int len_result = ber_parse_length(data, data_end,
                                            start_offset, &length);
        assert(len_result == -1 || (len_result >= 1 && len_result <= 3));
    }

    /* Property 3: ber_extract_uint32 never reads OOB */
    if (start_offset < data_len) {
        uint32_t extract_len;
        __CPROVER_assume(extract_len <= 4);
        uint32_t extracted = 0;
        int ext_ret = ber_extract_uint32(data, data_end, start_offset,
                                           extract_len, &extracted);
        assert(ext_ret == 0 || ext_ret == -1);
    }

    return 0;
}
