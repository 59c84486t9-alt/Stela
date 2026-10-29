/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_MATH_H
#define STELA_AIR_MATH_H
/* Compiler implementation only: AIR's math, integer, conversion, derivative
 * and discard functions and LLVM's math intrinsics in NIR. */
#include "air_to_nir.h"
#include "llvm-c/Core.h"

/* The translator's view of one call. */
struct stela_air_math_context {
   nir_builder *b;
   struct stela_air_error *error;
   void *translator;
   /* Derivatives and discard exist only in fragment functions. */
   bool fragment;
   /* An operand's NIR value, or NULL after reporting why. */
   nir_def *(*operand)(void *translator, LLVMValueRef value);
   /* Admits the function's floating-point environment before an FP result;
    * false after reporting why. */
   bool (*fp_environment)(void *translator);
};

enum stela_air_math_status {
   STELA_AIR_MATH_OTHER, /* Not one of these functions; nothing was emitted. */
   STELA_AIR_MATH_LOWERED,
   STELA_AIR_MATH_FAILED, /* Reported in the context's error. */
};

/* Lowers a call of `callee`, named `name`. *result is the call's value, NULL
 * for void functions. */
enum stela_air_math_status stela_air_math_call(const struct stela_air_math_context *context,
                                               LLVMValueRef call, LLVMValueRef callee,
                                               const char *name, size_t name_bytes,
                                               nir_def **result);
#endif
