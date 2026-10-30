/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_MATRIX_H
#define STELA_AIR_MATRIX_H
/* Compiler implementation only: AIR's SIMD-group matrix functions in NIR
 * subgroup operations. */
#include "air_call.h"

/* Whether `type` is a SIMD-group matrix, 64 floats, halves or bfloats, whose
 * value in NIR is the two of `bits` its lane holds. */
bool stela_air_matrix_type(LLVMTypeRef type, unsigned *bits);

/* Lowers a call of `callee`, named `name`, to *result, which stays NULL for
 * a store. */
enum stela_air_call_status stela_air_matrix_call(const struct stela_air_call_context *context,
                                                 LLVMValueRef call, LLVMValueRef callee,
                                                 const char *name, size_t name_bytes,
                                                 nir_def **result);
#endif
