/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ACSL String Logic Definitions
 *
 * Provides logic functions for string operations used in formal verification.
 */

#ifndef ACSL_STRING_H
#define ACSL_STRING_H

#include <stddef.h>

/*@
  @ logic integer c_strlen(char *s) =
  @   s[0] == '\0' ? 0 : 1 + c_strlen(s + 1);
  @
  @ predicate valid_string(char *s) =
  @   \exists integer i; 0 <= i && \valid(s + (0..i)) && s[i] == '\0' &&
  @     \forall integer j; 0 <= j < i ==> s[j] != '\0';
  @
  @ predicate valid_read_string(char *s) =
  @   \exists integer i; 0 <= i && \valid_read(s + (0..i)) && s[i] == '\0' &&
  @     \forall integer j; 0 <= j < i ==> s[j] != '\0';
  @*/

#endif /* ACSL_STRING_H */
