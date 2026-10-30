/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_COMMANDS_H
#define STELA_AIR_COMMANDS_H
/* Compiler implementation only: AIR's indirect command functions.
 * Includers define STELA_AIR_METADATA_INTERNAL. */
#include "air_call.h"

/* The translator's view of one call. */
struct stela_air_command_context {
   struct stela_air_call_context call;
   /* The gpuResourceID an operand loaded from an argument buffer field of
    * kind, or NULL after reporting why. */
   nir_def *(*resource_id)(void *translator, LLVMValueRef value, enum stela_air_field_kind kind);
   /* A device or constant buffer pointer operand's 64-bit address, or NULL
    * after reporting why. */
   nir_def *(*address)(void *translator, LLVMValueRef value);
};

/* Reads a call of one of AIR's command functions into *command, or, for
 * command_buffer::size(), sets *size and only command->buffer. A function
 * this compiler does not lower is refused, never taken for another. */
enum stela_air_call_status stela_air_command_call(const struct stela_air_command_context *context,
                                                  LLVMValueRef call, LLVMValueRef callee,
                                                  const char *name, size_t bytes,
                                                  struct stela_air_command *command, bool *size);
#endif
