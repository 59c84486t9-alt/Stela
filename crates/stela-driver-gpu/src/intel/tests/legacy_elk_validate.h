/* SPDX-License-Identifier: MIT */
#ifndef STELA_LEGACY_ELK_VALIDATE_H
#define STELA_LEGACY_ELK_VALIDATE_H
#include <stdbool.h>
struct elk_compiler;
bool stela_legacy_elk_code_valid(const struct elk_compiler *, const void *, unsigned);
#endif
