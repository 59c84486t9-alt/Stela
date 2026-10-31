/* SPDX-License-Identifier: MIT */
/* air_precise.c's accuracy: each function, folded at sampled arguments, against
 * the host's double-precision library rounded once. */
#include "../air_precise.h"
#include "util/macros.h"
#include "util/ralloc.h"
#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NDEBUG
#error "These tests require active assertions"
#endif

static const nir_shader_compiler_options options = {.max_unroll_iterations = 32};

static uint64_t state = 0x9e3779b97f4a7c15ull;

/* xorshift64*, so failures reproduce. */
static uint32_t
random_word(void)
{
   state ^= state >> 12;
   state ^= state << 25;
   state ^= state >> 27;
   return (state * 0x2545f4914f6cdd1dull) >> 32;
}

static float
from_bits(uint32_t bits)
{
   float value;
   memcpy(&value, &bits, sizeof(value));
   return value;
}

static uint32_t
to_bits(float value)
{
   uint32_t bits;
   memcpy(&bits, &value, sizeof(bits));
   return bits;
}

/* Values every function meets at its edges. */
static const float edges[] = {
   0.0f, -0.0f, 1.0f, -1.0f, 0.5f, -0.5f, 2.0f, -2.0f, 3.0f, -3.0f, 1.5f, 0.25f, 10.0f, 100.0f,
   1.17549435e-38f, FLT_MAX, -FLT_MAX, FLT_EPSILON, 1.0f - FLT_EPSILON / 2, 1.0f + FLT_EPSILON,
   0x1p24f, 0x1p25f, 0x1.fffffep24f, 3.14159274f, 1.57079637f, 0.785398185f, 6.28318548f,
   INFINITY, -INFINITY, NAN,
};

/* An argument: an edge, any float, or one of moderate size. */
static float
sample(void)
{
   uint32_t pick = random_word() % 8;
   if (pick == 0)
      return edges[random_word() % ARRAY_SIZE(edges)];
   if (pick < 4)
      return from_bits(random_word());
   float unit = (float)random_word() / 0x1p32f - 0.5f;
   return unit * (pick < 6 ? 4.0f : 200.0f);
}

/* The floats between a and b; NaNs match each other only. */
static uint64_t
ulps(float a, float b)
{
   if (isnan(a) || isnan(b))
      return isnan(a) && isnan(b) ? 0 : UINT64_MAX;
   int64_t x = to_bits(a), y = to_bits(b);
   x = x >> 31 ? 0x80000000ll - x : x;
   y = y >> 31 ? 0x80000000ll - y : y;
   return x > y ? x - y : y - x;
}

static float
evaluate(stela_air_precise_function *function, float x, float y)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, &options, "precise");
   b.constant_fold_alu = true;
   nir_def *value = stela_air_precise(&b, function, nir_imm_float(&b, x), nir_imm_float(&b, y));
   assert(nir_src_is_const(nir_src_for_ssa(value)));
   float result = nir_src_as_float(nir_src_for_ssa(value));
   ralloc_free(b.shader);
   return result;
}

/* pi * x's sine and cosine stop at a rounded pi, so their zeros are written out. */
static double
host_sinpi(double x)
{
   double turn = fmod(x, 2.0);
   return fmod(turn, 1.0) == 0.0 ? 0.0 : sin(M_PI * turn);
}

static double
host_cospi(double x)
{
   double turn = fmod(x, 2.0);
   return fmod(turn + 0.5, 1.0) == 0.0 ? 0.0 : cos(M_PI * turn);
}

static double
host_tanpi(double x)
{
   return host_sinpi(x) / host_cospi(x);
}

static double host_exp10(double x) { return pow(10.0, x); }
static double host_rsqrt(double x) { return 1.0 / sqrt(x); }
static double host_powr(double x, double y) { return x < 0.0 ? NAN : pow(x, y); }
static double host_divide(double x, double y) { return x / y; }

static const struct {
   const char *name;
   stela_air_precise_function *function;
   double (*one)(double);
   double (*two)(double, double);
} functions[] = {
   {"sin", stela_air_precise_sin, sin},
   {"cos", stela_air_precise_cos, cos},
   {"tan", stela_air_precise_tan, tan},
   {"sinpi", stela_air_precise_sinpi, host_sinpi},
   {"cospi", stela_air_precise_cospi, host_cospi},
   {"tanpi", stela_air_precise_tanpi, host_tanpi},
   {"asin", stela_air_precise_asin, asin},
   {"acos", stela_air_precise_acos, acos},
   {"atan", stela_air_precise_atan, atan},
   {"sinh", stela_air_precise_sinh, sinh},
   {"cosh", stela_air_precise_cosh, cosh},
   {"tanh", stela_air_precise_tanh, tanh},
   {"asinh", stela_air_precise_asinh, asinh},
   {"acosh", stela_air_precise_acosh, acosh},
   {"atanh", stela_air_precise_atanh, atanh},
   {"exp", stela_air_precise_exp, exp},
   {"exp2", stela_air_precise_exp2, exp2},
   {"exp10", stela_air_precise_exp10, host_exp10},
   {"log", stela_air_precise_log, log},
   {"log2", stela_air_precise_log2, log2},
   {"log10", stela_air_precise_log10, log10},
   {"sqrt", stela_air_precise_sqrt, sqrt},
   {"rsqrt", stela_air_precise_rsqrt, host_rsqrt},
   {"atan2", stela_air_precise_atan2, NULL, atan2},
   {"pow", stela_air_precise_pow, NULL, pow},
   {"powr", stela_air_precise_powr, NULL, host_powr},
   {"divide", stela_air_precise_divide, NULL, host_divide},
   {"fmod", stela_air_precise_fmod, NULL, fmod},
};

/* Every function stays within a unit of the host's, which is itself within
 * half of the true value; Metal allows 3 or more, and division none. */
static void
functions_match_the_host(unsigned samples)
{
   for (unsigned i = 0; i < ARRAY_SIZE(functions); i++) {
      uint64_t worst = 0;
      float worst_x = 0, worst_y = 0;
      for (unsigned n = 0; n < samples; n++) {
         float x = sample(), y = sample();
         /* Powers near one reach further into their exponents. */
         if (functions[i].function == stela_air_precise_pow && (random_word() & 1))
            x = 0.5f + fabsf(fmodf(x, 2.0f));
         double host = functions[i].one ? functions[i].one(x) : functions[i].two(x, y);
         uint64_t distance = ulps(evaluate(functions[i].function, x, y), (float)host);
         if (distance > worst) {
            worst = distance;
            worst_x = x;
            worst_y = y;
         }
      }
      if (worst > 1)
         fprintf(stderr, "%s(%a, %a): %llu units\n", functions[i].name, worst_x, worst_y,
                 (unsigned long long)worst);
      assert(worst <= 1);
   }
}

/* Division rounds correctly, and a remainder is exact. */
static void
division_is_exact(unsigned samples)
{
   for (unsigned n = 0; n < samples; n++) {
      float x = sample(), y = sample();
      assert(ulps(evaluate(stela_air_precise_divide, x, y), x / y) == 0);
      assert(ulps(evaluate(stela_air_precise_fmod, x, y), fmodf(x, y)) == 0);
   }
}

static void
quarter_turns_are_exact(void)
{
   assert(evaluate(stela_air_precise_sinpi, 1.0f, 0.0f) == 0.0f);
   assert(evaluate(stela_air_precise_cospi, 0.5f, 0.0f) == 0.0f);
   assert(evaluate(stela_air_precise_sinpi, 0.5f, 0.0f) == 1.0f);
   assert(evaluate(stela_air_precise_cospi, 1.0f, 0.0f) == -1.0f);
   assert(evaluate(stela_air_precise_tanpi, 0.25f, 0.0f) == 1.0f);
   assert(evaluate(stela_air_precise_sinpi, 0x1p30f, 0.0f) == 0.0f);
}

/* Zeros keep their signs through odd functions. */
static void
zeros_keep_their_signs(void)
{
   stela_air_precise_function *odd[] = {
      stela_air_precise_sin, stela_air_precise_tan, stela_air_precise_asin, stela_air_precise_atan,
      stela_air_precise_sinh, stela_air_precise_tanh, stela_air_precise_asinh, stela_air_precise_atanh,
      stela_air_precise_sqrt,
   };
   for (unsigned i = 0; i < ARRAY_SIZE(odd); i++)
      assert(to_bits(evaluate(odd[i], -0.0f, 0.0f)) == 0x80000000);
}

static void
vectors_measure_without_overflow(void)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, &options, "precise");
   b.constant_fold_alu = true;
   const float big = 0x1p100f;
   nir_def *x = nir_imm_vec3(&b, 3.0f * big, 4.0f * big, 0.0f);
   nir_def *y = nir_imm_vec3(&b, 0.0f, 0.0f, 0.0f);
   assert(nir_src_as_float(nir_src_for_ssa(stela_air_precise_length(&b, x, NULL))) == 5.0f * big);
   assert(nir_src_as_float(nir_src_for_ssa(stela_air_precise_length(&b, x, y))) == 5.0f * big);
   nir_def *unit = stela_air_precise_normalize(&b, x);
   assert(nir_src_comp_as_float(nir_src_for_ssa(unit), 0) == 0.6f);
   assert(nir_src_comp_as_float(nir_src_for_ssa(unit), 1) == 0.8f);
   assert(nir_src_comp_as_float(nir_src_for_ssa(unit), 2) == 0.0f);
   assert(isnan(nir_src_comp_as_float(nir_src_for_ssa(stela_air_precise_normalize(&b, y)), 0)));
   ralloc_free(b.shader);
}

int
main(int argc, char **argv)
{
   unsigned samples = argc > 1 ? (unsigned)atoi(argv[1]) : 2000;
   functions_match_the_host(samples);
   division_is_exact(samples);
   quarter_turns_are_exact();
   zeros_keep_their_signs();
   vectors_measure_without_overflow();
   return 0;
}
