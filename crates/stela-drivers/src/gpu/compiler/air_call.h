/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_CALL_H
#define STELA_AIR_CALL_H
/* Compiler implementation only: the translator's view of one call of an AIR
 * function library, and the checks those libraries share. */
#include "air_to_nir.h"
#include "llvm-c/Core.h"

struct stela_air_call_context {
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

enum stela_air_call_status {
   STELA_AIR_CALL_OTHER, /* Not one of the library's functions; nothing was emitted. */
   STELA_AIR_CALL_LOWERED,
   STELA_AIR_CALL_FAILED, /* Reported in the context's error. */
};

/* Reports the first error; always false. */
bool stela_air_call_fail(const struct stela_air_call_context *context,
                         enum stela_air_error_kind kind, const char *format, ...);

/* A direct call of a plain declaration with `operands` operands, or false
 * after reporting why. */
bool stela_air_call_plain(const struct stela_air_call_context *context, LLVMValueRef call,
                          LLVMValueRef callee, unsigned operands);

/* Whether `name` (`bytes` long) is `expected`. */
bool stela_air_call_named(const char *name, size_t bytes, const char *expected);

/* A scalar's or vector's element type and lanes (1 for a scalar). */
LLVMTypeRef stela_air_call_element(LLVMTypeRef type, unsigned *lanes);

/* A half or float scalar, or a vector of 2 to 4 of them. */
bool stela_air_call_floating(LLVMTypeRef type);

/* An 8-, 16-, 32- or 64-bit integer scalar, or a vector of 2 to 4 of them. */
bool stela_air_call_integer(LLVMTypeRef type);

/* A type's AIR overload: "f32", "v4f16", "i32". */
void stela_air_call_overload(LLVMTypeRef type, char *name, size_t size);
#endif
