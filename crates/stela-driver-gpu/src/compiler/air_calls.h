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

/* Whether module has a direct call to one of its defined AIR functions. */
bool stela_air_has_defined_calls(LLVMModuleRef module);

/* Links modules into m's, after checking each is AIR compiled as m's was,
 * so one profile translates them, and specializing each with its own
 * function constant values. m's own are specialized first, since linking
 * merges the modules' function constant metadata. */
bool stela_air_link_modules(struct stela_air_metadata *m, const struct stela_air_module *modules,
                            unsigned count);

/* Lowers air.get_size_visible_function_table to a load of the table's count,
 * air.get_function_pointer_visible_function_table to a load of the table's
 * handle, and each call through the pointer to a dispatcher that calls the
 * linked function of that handle with the call's type: handle i + 1 calls
 * functions[i]. */
bool stela_air_dispatch_tables(struct stela_air_metadata *m,
                               const struct stela_air_linked_function *functions, unsigned count);

/* Inlines each call to a function the module defines into its caller, so a
 * function's calls reach only AIR's. Recursion entry's calls reach through
 * function tables unrolls into entry to max_call_stack_depth nested calls
 * through tables, within max_instructions; a call nested deeper calls none.
 * Other recursion is refused. Without an entry, calls that can reach
 * recursion stay. */
bool stela_air_inline_calls(struct stela_air_metadata *m, LLVMValueRef entry,
                            unsigned max_call_stack_depth, unsigned max_instructions);
/* The first inlining pass with an optional specialized entry. After checking
 * the original graph, it folds constants in an acyclic entry before expanding
 * its calls, setting *folded when that pass runs. */
bool stela_air_inline_specialized_calls(struct stela_air_metadata *m, LLVMValueRef entry,
                                        bool *folded);
#endif
