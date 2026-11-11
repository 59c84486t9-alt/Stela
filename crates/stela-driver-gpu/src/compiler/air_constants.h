/* SPDX-License-Identifier: GPL-2.0-or-later */
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

/* Initializers captured from a compact copy of a module before reflection
 * inlines its shader functions. LLVM constants belong to the shared context.
 * A module may construct hundreds of globals, so both arrays are allocated
 * to its count; zero-initialize before use and release after. */
struct stela_air_constructed_constants {
   unsigned count;
   LLVMValueRef *globals, *values;
};

void stela_air_release_constructed_constants(struct stela_air_constructed_constants *constants);

/* Prepares initialization when inlining cannot change the constructors. */
bool stela_air_prepare_constants(struct stela_air_metadata *m,
                                 const struct stela_air_constants *constants,
                                 struct stela_air_constructed_constants *prepared);

/* Evaluates the specialized module's air.static_init constructors, making the
 * program-scope constants they compute constant data, and removes them;
 * refuses constructors that depend on more than function constants. */
bool stela_air_construct_constants(struct stela_air_metadata *m);
bool stela_air_construct_prepared_constants(struct stela_air_metadata *m,
                                           const struct stela_air_constructed_constants *prepared);

/* Folds what the constructed module's function constants decide in fn, its
 * entry with its callees inlined: the loads of constant data, the branches
 * they decide and the blocks those leave unreachable. */
bool stela_air_fold_constants(struct stela_air_metadata *m, LLVMValueRef fn);

/* Makes the buffers of count arguments their false function constants leave
 * out null in fn, and removes the paths that must then access null, as Metal's
 * compiler removes what an absent argument leaves undefined. */
bool stela_air_fold_absent(struct stela_air_metadata *m, LLVMValueRef fn,
                           const struct stela_air_argument *arguments, unsigned count);
#endif
