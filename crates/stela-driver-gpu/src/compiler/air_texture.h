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
   /* The texture or sampler argument an operand names, or NULL; *id is its
    * MTLResourceID when an argument buffer holds it, otherwise NULL. A
    * constexpr sampler names no argument and gives only its *id, which is
    * NULL after reporting why. */
   const struct stela_air_texture *(*texture)(void *translator, LLVMValueRef value, nir_def **id);
   const struct stela_air_sampler *(*sampler)(void *translator, LLVMValueRef value, nir_def **id);
   /* Loads or stores the 32-bit word a read-write pointer operand addresses;
    * NULL or false after reporting why. */
   nir_def *(*load_word)(void *translator, LLVMValueRef pointer);
   bool (*store_word)(void *translator, LLVMValueRef pointer, nir_def *value);
};

enum stela_air_texture_status {
   STELA_AIR_TEXTURE_OTHER, /* Not a texture function; nothing was emitted. */
   STELA_AIR_TEXTURE_LOWERED,
   STELA_AIR_TEXTURE_FAILED, /* Reported in the context's error. */
};

/* Lowers a call whose first operand is a texture argument. *result is the
 * call's value, NULL for void functions. Sample, read and gather functions
 * return AIR's {texel, residency} pair, of which *result is the texel and
 * *pair is set. *residency is the i8 sparse texture feedback, whose bit 0 is
 * set when a texel is not resident; NULL when only the texel is read. */
enum stela_air_texture_status stela_air_texture_call(const struct stela_air_texture_context *context,
                                                     LLVMValueRef call, const char *name,
                                                     size_t name_bytes, nir_def **result, bool *pair,
                                                     nir_def **residency);
#endif
