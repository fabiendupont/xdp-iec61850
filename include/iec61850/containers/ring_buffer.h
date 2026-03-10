/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fixed-Capacity Ring Buffer Types for IEC 61850
 *
 * C11 equivalent of RingBuffer<T, N> from static_containers.h.
 * Circular buffer that overwrites oldest entries when full.
 *
 * Concrete types provided:
 *   iec61850_uint64_ring8_t     - 8 x uint64_t (small test buffer)
 *   iec61850_uint64_ring1000_t  - 1000 x uint64_t (latency stats)
 */

#ifndef IEC61850_RING_BUFFER_H
#define IEC61850_RING_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Macro to define a ring buffer type and its functions.
 *
 * Usage:
 *   IEC61850_DEFINE_RING_BUFFER(iec61850_uint64_ring8, uint64_t, 8)
 *
 * Generates:
 *   - typedef struct { uint64_t data[8]; size_t head, tail, count; }
 *   - init, enqueue, dequeue, peek, at, clear, size, capacity, empty, full
 *
 * MISRA-C Advisory Deviation: Rule 20.10 (## token pasting)
 * ======================================================================== */

#define IEC61850_DEFINE_RING_BUFFER(NAME, ELEM_TYPE, CAPACITY)                \
                                                                               \
typedef struct NAME {                                                          \
    ELEM_TYPE data[(CAPACITY)];                                                \
    size_t head;                                                               \
    size_t tail;                                                               \
    size_t count;                                                              \
} NAME##_t;                                                                    \
                                                                               \
/*@ requires \valid(rb);                                                       \
  @ assigns rb->head, rb->tail, rb->count;                                     \
  @ ensures rb->head == 0 && rb->tail == 0 && rb->count == 0;                  \
  @*/                                                                          \
static inline void NAME##_init(NAME##_t *rb)                                   \
{                                                                              \
    rb->head = 0;                                                              \
    rb->tail = 0;                                                              \
    rb->count = 0;                                                             \
}                                                                              \
                                                                               \
/*@ requires \valid(rb);                                                       \
  @ assigns rb->data[rb->tail], rb->tail, rb->count, rb->head;                \
  @*/                                                                          \
static inline void NAME##_enqueue(NAME##_t *rb, ELEM_TYPE value)               \
{                                                                              \
    rb->data[rb->tail] = value;                                                \
    rb->tail = (rb->tail + 1U) % (size_t)(CAPACITY);                           \
    if (rb->count < (size_t)(CAPACITY)) {                                      \
        rb->count++;                                                           \
    } else {                                                                   \
        rb->head = (rb->head + 1U) % (size_t)(CAPACITY);                       \
    }                                                                          \
}                                                                              \
                                                                               \
/*@ requires \valid(rb);                                                       \
  @ requires rb->count > 0;                                                    \
  @ assigns *out, rb->head, rb->count;                                         \
  @ ensures \result == 0 ==> rb->count == \old(rb->count) - 1;                 \
  @*/                                                                          \
static inline int NAME##_dequeue(NAME##_t *rb, ELEM_TYPE *out)                 \
{                                                                              \
    if (rb->count == 0U) {                                                     \
        return -1;                                                             \
    }                                                                          \
    if (out != NULL) {                                                         \
        *out = rb->data[rb->head];                                             \
    }                                                                          \
    rb->head = (rb->head + 1U) % (size_t)(CAPACITY);                           \
    rb->count--;                                                               \
    return 0;                                                                  \
}                                                                              \
                                                                               \
/*@ requires \valid_read(rb);                                                  \
  @ requires rb->count > 0;                                                    \
  @ assigns \nothing;                                                          \
  @*/                                                                          \
static inline const ELEM_TYPE *NAME##_peek(const NAME##_t *rb)                 \
{                                                                              \
    if (rb->count == 0U) {                                                     \
        return NULL;                                                           \
    }                                                                          \
    return &rb->data[rb->head];                                                \
}                                                                              \
                                                                               \
/*@ requires \valid_read(rb);                                                  \
  @ requires idx < rb->count;                                                  \
  @ assigns \nothing;                                                          \
  @*/                                                                          \
static inline const ELEM_TYPE *NAME##_at(const NAME##_t *rb, size_t idx)       \
{                                                                              \
    if (idx >= rb->count) {                                                    \
        return NULL;                                                           \
    }                                                                          \
    return &rb->data[(rb->head + idx) % (size_t)(CAPACITY)];                   \
}                                                                              \
                                                                               \
static inline void NAME##_clear(NAME##_t *rb)                                  \
{                                                                              \
    rb->head = 0;                                                              \
    rb->tail = 0;                                                              \
    rb->count = 0;                                                             \
}                                                                              \
                                                                               \
static inline size_t NAME##_size(const NAME##_t *rb)                           \
{                                                                              \
    return rb->count;                                                          \
}                                                                              \
                                                                               \
static inline size_t NAME##_capacity(const NAME##_t *rb)                       \
{                                                                              \
    (void)rb;                                                                  \
    return (size_t)(CAPACITY);                                                 \
}                                                                              \
                                                                               \
static inline bool NAME##_empty(const NAME##_t *rb)                            \
{                                                                              \
    return rb->count == 0U;                                                    \
}                                                                              \
                                                                               \
static inline bool NAME##_full(const NAME##_t *rb)                             \
{                                                                              \
    return rb->count >= (size_t)(CAPACITY);                                    \
}

/* ========================================================================
 * Concrete type instantiations
 * ======================================================================== */

IEC61850_DEFINE_RING_BUFFER(iec61850_uint64_ring8, uint64_t, 8)
IEC61850_DEFINE_RING_BUFFER(iec61850_uint64_ring1000, uint64_t, 1000)

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_RING_BUFFER_H */
