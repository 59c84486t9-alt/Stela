/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_CALLS_H
#define STELA_AIR_CALLS_H
/* Compiler implementation only: calls between the module's functions.
 * Includers define STELA_AIR_METADATA_INTERNAL. */
#include "air_metadata.h"

/* Whether the module defines fn as one of its own functions. AIR's are
 * declarations: a definition in their namespace is not, and translation
 * refuses its calls as AIR's. */
bool stela_air_defined_function(LLVMValueRef fn);

/* Inlines each call to a function the module defines into its caller, so a
 * function's calls reach only AIR's. A call that can reach recursion stays,
 * for translation to refuse. */
bool stela_air_inline_calls(struct stela_air_metadata *m);
#endif
