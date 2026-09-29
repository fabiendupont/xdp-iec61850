/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fixed-Capacity String Types for IEC 61850
 *
 * C11 equivalents of FixedString<N> from static_containers.h.
 * Null-terminated, stack-allocated strings with known maximum size.
 *
 * Concrete types provided:
 *   iec61850_str32_t   - 32-char strings (short identifiers)
 *   iec61850_str129_t  - 129-char strings (gocbRef, datSet, goID, svID)
 *   iec61850_str256_t  - 256-char strings (file paths, security paths)
 */

#ifndef IEC61850_FIXED_STRING_H
#define IEC61850_FIXED_STRING_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Macro to define a fixed-string type and its inline accessor functions.
 *
 * Usage:
 *   IEC61850_DEFINE_FIXED_STRING(iec61850_str129, 129U)
 *
 * Generates:
 *   - typedef struct { char data[130]; size_t len; } iec61850_str129_t;
 *   - void    iec61850_str129_init(iec61850_str129_t *s);
 *   - int     iec61850_str129_assign(iec61850_str129_t *s, const char *str);
 *   - int     iec61850_str129_assign_n(iec61850_str129_t *s, const char *str, size_t n);
 *   - void    iec61850_str129_clear(iec61850_str129_t *s);
 *   - const char* iec61850_str129_cstr(const iec61850_str129_t *s);
 *   - size_t  iec61850_str129_len(const iec61850_str129_t *s);
 *   - size_t  iec61850_str129_capacity(const iec61850_str129_t *s);
 *   - bool    iec61850_str129_empty(const iec61850_str129_t *s);
 *   - bool    iec61850_str129_equal(const iec61850_str129_t *a, const iec61850_str129_t *b);
 *   - bool    iec61850_str129_equal_cstr(const iec61850_str129_t *s, const char *cstr);
 *   - int     iec61850_str129_compare(const iec61850_str129_t *a, const iec61850_str129_t *b);
 *
 * MISRA-C Advisory Deviation: Rule 20.10 (## token pasting) - used here
 * for type-safe container generation. Each instantiation produces concrete,
 * verifiable types.
 * ======================================================================== */

/* Internal helper declarations (implemented in fixed_string.c) */
void iec61850_fixed_string_init_raw(char *data, size_t *len);
int  iec61850_fixed_string_assign_raw(char *data, size_t *len, size_t capacity,
                                       const char *str);
int  iec61850_fixed_string_assign_n_raw(char *data, size_t *len, size_t capacity,
                                         const char *str, size_t n);
void iec61850_fixed_string_clear_raw(char *data, size_t *len);
bool iec61850_fixed_string_equal_raw(const char *data1, size_t len1,
                                      const char *data2, size_t len2);
int  iec61850_fixed_string_compare_raw(const char *data1, size_t len1,
                                        const char *data2, size_t len2);
bool iec61850_fixed_string_equal_cstr_raw(const char *data, size_t len,
                                           const char *cstr);

/* cppcheck-suppress misra-c2012-20.7 -- NAME is a type name, not an expression */
/* cppcheck-suppress misra-c2012-20.10 -- ## required for typed container macro pattern */
/* cppcheck-suppress misra-c2012-20.12 -- ## required for typed container macro pattern */
#define IEC61850_DEFINE_FIXED_STRING(NAME, CAPACITY)                          \
                                                                               \
typedef struct NAME {                                                          \
    char data[(CAPACITY) + 1U];                                                \
    size_t len;                                                                \
} NAME##_t;                                                                    \
                                                                               \
static inline void NAME##_init(NAME##_t *s)                                    \
{                                                                              \
    iec61850_fixed_string_init_raw(s->data, &s->len);                          \
}                                                                              \
                                                                               \
static inline int NAME##_assign(NAME##_t *s, const char *str)                  \
{                                                                              \
    return iec61850_fixed_string_assign_raw(s->data, &s->len,                  \
                                            (CAPACITY), str);                  \
}                                                                              \
                                                                               \
static inline int NAME##_assign_n(NAME##_t *s, const char *str, size_t n)      \
{                                                                              \
    return iec61850_fixed_string_assign_n_raw(s->data, &s->len,                \
                                              (CAPACITY), str, n);             \
}                                                                              \
                                                                               \
static inline void NAME##_clear(NAME##_t *s)                                   \
{                                                                              \
    iec61850_fixed_string_clear_raw(s->data, &s->len);                         \
}                                                                              \
                                                                               \
static inline const char *NAME##_cstr(const NAME##_t *s)                       \
{                                                                              \
    return s->data;                                                            \
}                                                                              \
                                                                               \
static inline size_t NAME##_len(const NAME##_t *s)                             \
{                                                                              \
    return s->len;                                                             \
}                                                                              \
                                                                               \
static inline size_t NAME##_capacity(const NAME##_t *s)                        \
{                                                                              \
    (void)s;                                                                   \
    return (CAPACITY);                                                         \
}                                                                              \
                                                                               \
static inline bool NAME##_empty(const NAME##_t *s)                             \
{                                                                              \
    return s->len == 0U;                                                       \
}                                                                              \
                                                                               \
static inline bool NAME##_equal(const NAME##_t *a, const NAME##_t *b)          \
{                                                                              \
    return iec61850_fixed_string_equal_raw(a->data, a->len,                    \
                                            b->data, b->len);                 \
}                                                                              \
                                                                               \
static inline bool NAME##_equal_cstr(const NAME##_t *s, const char *cstr)      \
{                                                                              \
    return iec61850_fixed_string_equal_cstr_raw(s->data, s->len, cstr);        \
}                                                                              \
                                                                               \
static inline int NAME##_compare(const NAME##_t *a, const NAME##_t *b)         \
{                                                                              \
    if ((a == NULL) || (b == NULL)) { return (a == b) ? 0 : (a == NULL) ? -1 : 1; }\
    return iec61850_fixed_string_compare_raw(a->data, a->len,                  \
                                              b->data, b->len);               \
}

/* ========================================================================
 * Concrete type instantiations
 * ======================================================================== */

IEC61850_DEFINE_FIXED_STRING(iec61850_str32, 32U)
IEC61850_DEFINE_FIXED_STRING(iec61850_str129, 129U)
IEC61850_DEFINE_FIXED_STRING(iec61850_str256, 256U)

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_FIXED_STRING_H */
