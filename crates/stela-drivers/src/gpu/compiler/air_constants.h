/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_CONSTANTS_H
#define STELA_AIR_CONSTANTS_H
/* Compiler implementation only: function constant specialization. Includers
 * define STELA_AIR_METADATA_INTERNAL. */
#include "air_to_nir.h"

/* Defines each function constant of the module with its value, or zero
 * without one, folds the loads of its whole value and its definedness tests,
 * and refuses a required constant without a value. */
bool stela_air_specialize_constants(struct stela_air_metadata *m,
                                    const struct stela_air_constant_value *values,
                                    unsigned count);
#endif
