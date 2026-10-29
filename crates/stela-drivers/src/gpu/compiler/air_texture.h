/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_TEXTURE_H
#define STELA_AIR_TEXTURE_H
/* Compiler implementation only: AIR's texture functions in NIR. */
#include "air_to_nir.h"
#include "llvm-c/Core.h"

/* The translator's view of one call. */
struct stela_air_texture_context {
   nir_builder *b;
   const struct stela_air_options *options;
   struct stela_air_error *error;
   void *translator;
   /* An operand's NIR value, or NULL after reporting why. */
   nir_def *(*operand)(void *translator, LLVMValueRef value);
   /* The texture or sampler argument an operand names, or NULL. */
   const struct stela_air_texture *(*texture)(void *translator, LLVMValueRef value);
   const struct stela_air_sampler *(*sampler)(void *translator, LLVMValueRef value);
};

enum stela_air_texture_status {
   STELA_AIR_TEXTURE_OTHER, /* Not a texture function; nothing was emitted. */
   STELA_AIR_TEXTURE_LOWERED,
   STELA_AIR_TEXTURE_FAILED, /* Reported in the context's error. */
};

/* Lowers a call whose first operand is a texture argument. *result is the
 * call's value, NULL for void functions. Sample, read and gather functions
 * return AIR's {texel, residency} pair, of which *result is the texel and
 * *pair is set; the residency member is sparse texture feedback, which is
 * not lowered. */
enum stela_air_texture_status stela_air_texture_call(const struct stela_air_texture_context *context,
                                                     LLVMValueRef call, const char *name,
                                                     size_t name_bytes, nir_def **result, bool *pair);
#endif
