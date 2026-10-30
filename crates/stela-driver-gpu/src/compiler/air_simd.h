/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_SIMD_H
#define STELA_AIR_SIMD_H
/* Compiler implementation only: AIR's SIMD-group and quad-group functions in
 * NIR subgroup operations. */
#include "air_call.h"

/* Lowers a call of `callee`, named `name`, to *result. */
enum stela_air_call_status stela_air_simd_call(const struct stela_air_call_context *context,
                                               LLVMValueRef call, LLVMValueRef callee,
                                               const char *name, size_t name_bytes,
                                               nir_def **result);
#endif
