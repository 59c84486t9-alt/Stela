/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_MATH_H
#define STELA_AIR_MATH_H
/* Compiler implementation only: AIR's math, integer, conversion, derivative
 * and discard functions and LLVM's math intrinsics in NIR. */
#include "air_call.h"

/* Lowers a call of `callee`, named `name`. *result is the call's value, NULL
 * for void functions. */
enum stela_air_call_status stela_air_math_call(const struct stela_air_call_context *context,
                                               LLVMValueRef call, LLVMValueRef callee,
                                               const char *name, size_t name_bytes,
                                               nir_def **result);
#endif
