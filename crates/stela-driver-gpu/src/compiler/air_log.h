/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_LOG_H
#define STELA_AIR_LOG_H
/* Compiler implementation only: os_log. Includers define
 * STELA_AIR_METADATA_INTERNAL. */
#include "air_call.h"

struct stela_air_log_context {
   struct stela_air_call_context call;
   /* The log buffer's address, zero for none, or NULL after reporting why. */
   nir_def *(*buffer)(void *translator);
   /* Code between these runs only when `condition` holds. False after
    * reporting why. */
   bool (*guard_begin)(void *translator, nir_def *condition, nir_block *guard[3]);
   void (*guard_end)(void *translator, nir_block *const guard[3]);
};

/* Whether an instruction's value is a float's promotion to double for os_log
 * calls alone, which take the float. */
bool stela_air_log_promotion(LLVMValueRef inst);

/* Lowers a call of one of os_log's methods. */
enum stela_air_call_status stela_air_log_call(const struct stela_air_log_context *context,
                                              LLVMValueRef call, LLVMValueRef callee);
#endif
