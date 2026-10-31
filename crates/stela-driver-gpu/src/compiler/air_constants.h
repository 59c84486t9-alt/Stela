/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_CONSTANTS_H
#define STELA_AIR_CONSTANTS_H
/* Compiler implementation only: function constant specialization. Includers
 * define STELA_AIR_METADATA_INTERNAL. */
#include "air_metadata.h"

/* Defines each function constant of the module with its value, or zero
 * without one, folds the loads of its whole value and its definedness tests,
 * and refuses a required constant without a value. */
bool stela_air_specialize_constants(struct stela_air_metadata *m,
                                    const struct stela_air_constant_value *values,
                                    unsigned count);

/* Evaluates the specialized module's air.static_init constructors, making the
 * program-scope constants they compute constant data, and removes them;
 * refuses constructors that depend on more than function constants. */
bool stela_air_construct_constants(struct stela_air_metadata *m);

/* Folds what the constructed module's function constants decide in fn, its
 * entry with its callees inlined: the loads of constant data, the branches
 * they decide and the blocks those leave unreachable. */
bool stela_air_fold_constants(struct stela_air_metadata *m, LLVMValueRef fn);
#endif
