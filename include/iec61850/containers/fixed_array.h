/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fixed-Capacity Array Types for IEC 61850
 *
 * C11 equivalent of StaticVector<T, N> from static_containers.h.
 * Stack-allocated arrays with a size counter and fixed maximum capacity.
 *
 * Concrete types provided:
 *   iec61850_int32_array64_t     - 64 x int32_t  (SV samples)
 *   iec61850_uint64_array1000_t  - 1000 x uint64_t (latency samples)
 */

#ifndef IEC61850_FIXED_ARRAY_H
#define IEC61850_FIXED_ARRAY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Macro to define a fixed-capacity array type and its functions.
 *
 * Usage:
 *   IEC61850_DEFINE_FIXED_ARRAY(iec61850_int32_array64, int32_t, 64)
 *
 * Generates:
 *   - typedef struct { int32_t data[64]; size_t size; } iec61850_int32_array64_t;
 *   - init, push, pop, get, clear, size, capacity, empty, full, data
 *
 * MISRA-C Advisory Deviation: Rule 20.10 (## token pasting)
 * ======================================================================== */

#define IEC61850_DEFINE_FIXED_ARRAY(NAME, ELEM_TYPE, CAPACITY)                \
                                                                               \
typedef struct NAME {                                                          \
    ELEM_TYPE data[(CAPACITY)];                                                \
    size_t size;                                                               \
} NAME##_t;                                                                    \
                                                                               \
/*@ requires \valid(arr);                                                      \
  @ assigns arr->size;                                                         \
  @ ensures arr->size == 0;                                                    \
  @*/                                                                          \
static inline void NAME##_init(NAME##_t *arr)                                  \
{                                                                              \
    arr->size = 0;                                                             \
}                                                                              \
                                                                               \
/*@ requires \valid(arr);                                                      \
  @ requires arr->size < CAPACITY;                                             \
  @ assigns arr->data[arr->size], arr->size;                                   \
  @ ensures \result == 0 ==> arr->size == \old(arr->size) + 1;                 \
  @*/                                                                          \
static inline int NAME##_push(NAME##_t *arr, ELEM_TYPE value)                  \
{                                                                              \
    if (arr->size >= (size_t)(CAPACITY)) {                                     \
        return -1;                                                             \
    }                                                                          \
    arr->data[arr->size] = value;                                              \
    arr->size++;                                                               \
    return 0;                                                                  \
}                                                                              \
                                                                               \
/*@ requires \valid(arr);                                                      \
  @ requires arr->size > 0;                                                    \
  @ assigns *out, arr->size;                                                   \
  @ ensures \result == 0 ==> arr->size == \old(arr->size) - 1;                 \
  @*/                                                                          \
static inline int NAME##_pop(NAME##_t *arr, ELEM_TYPE *out)                    \
{                                                                              \
    if (arr->size == 0U) {                                                     \
        return -1;                                                             \
    }                                                                          \
    arr->size--;                                                               \
    if (out != NULL) {                                                         \
        *out = arr->data[arr->size];                                           \
    }                                                                          \
    return 0;                                                                  \
}                                                                              \
                                                                               \
/*@ requires \valid_read(arr);                                                 \
  @ requires idx < arr->size;                                                  \
  @ assigns \nothing;                                                          \
  @ ensures \result != \null ==> \valid(\result);                              \
  @*/                                                                          \
static inline ELEM_TYPE *NAME##_get(NAME##_t *arr, size_t idx)                 \
{                                                                              \
    if (idx >= arr->size) {                                                    \
        return NULL;                                                           \
    }                                                                          \
    return &arr->data[idx];                                                    \
}                                                                              \
                                                                               \
static inline const ELEM_TYPE *NAME##_get_const(const NAME##_t *arr,           \
                                                 size_t idx)                   \
{                                                                              \
    if (idx >= arr->size) {                                                    \
        return NULL;                                                           \
    }                                                                          \
    return &arr->data[idx];                                                    \
}                                                                              \
                                                                               \
static inline void NAME##_clear(NAME##_t *arr)                                 \
{                                                                              \
    arr->size = 0;                                                             \
}                                                                              \
                                                                               \
static inline size_t NAME##_size(const NAME##_t *arr)                          \
{                                                                              \
    return arr->size;                                                          \
}                                                                              \
                                                                               \
static inline size_t NAME##_capacity(const NAME##_t *arr)                      \
{                                                                              \
    (void)arr;                                                                 \
    return (size_t)(CAPACITY);                                                 \
}                                                                              \
                                                                               \
static inline bool NAME##_empty(const NAME##_t *arr)                           \
{                                                                              \
    return arr->size == 0U;                                                    \
}                                                                              \
                                                                               \
static inline bool NAME##_full(const NAME##_t *arr)                            \
{                                                                              \
    return arr->size >= (size_t)(CAPACITY);                                    \
}                                                                              \
                                                                               \
static inline ELEM_TYPE *NAME##_data(NAME##_t *arr)                            \
{                                                                              \
    return arr->data;                                                          \
}

/* ========================================================================
 * Concrete type instantiations
 * ======================================================================== */

IEC61850_DEFINE_FIXED_ARRAY(iec61850_int32_array64, int32_t, 64)
IEC61850_DEFINE_FIXED_ARRAY(iec61850_uint64_array1000, uint64_t, 1000)

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_FIXED_ARRAY_H */
