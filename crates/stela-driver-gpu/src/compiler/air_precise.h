/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_PRECISE_H
#define STELA_AIR_PRECISE_H
/* Compiler implementation only: Metal's precise single-precision functions
 * and division in NIR. */
#include "compiler/nir/nir_builder.h"

/* A function of one lane. Those of one argument leave y unused. */
typedef nir_def *stela_air_precise_function(nir_builder *b, nir_def *x, nir_def *y);

/* `function` of each lane of x and y, of 32 bits, y possibly NULL. */
nir_def *stela_air_precise(nir_builder *b, stela_air_precise_function *function, nir_def *x,
                           nir_def *y);

stela_air_precise_function stela_air_precise_sin, stela_air_precise_cos, stela_air_precise_tan,
   stela_air_precise_sinpi, stela_air_precise_cospi, stela_air_precise_tanpi,
   stela_air_precise_asin, stela_air_precise_acos, stela_air_precise_atan,
   stela_air_precise_atan2, stela_air_precise_sinh, stela_air_precise_cosh,
   stela_air_precise_tanh, stela_air_precise_asinh, stela_air_precise_acosh,
   stela_air_precise_atanh, stela_air_precise_exp, stela_air_precise_exp2,
   stela_air_precise_exp10, stela_air_precise_log, stela_air_precise_log2,
   stela_air_precise_log10, stela_air_precise_pow, stela_air_precise_powr,
   stela_air_precise_sqrt, stela_air_precise_rsqrt, stela_air_precise_divide,
   stela_air_precise_fmod;

/* The length of x, or of x - y, as one lane. */
nir_def *stela_air_precise_length(nir_builder *b, nir_def *x, nir_def *y);
nir_def *stela_air_precise_normalize(nir_builder *b, nir_def *x);
#endif
