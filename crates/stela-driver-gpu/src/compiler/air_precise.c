/* SPDX-License-Identifier: MIT */
/* Metal's precise single-precision functions and division, which NIR's Vulkan
 * accuracy does not reach. Every NVIDIA GPU Stela drives computes doubles in
 * every stage, and Metal's accuracy leaves them ample room, so each function
 * evaluates in double precision and rounds once: within about half a unit in
 * the last place, against the 3 to 16 Metal allows, and correctly rounded for
 * division, as Metal asks. Doubles have a fraction of single precision's
 * throughput, which only functions that asked for accuracy pay.
 *
 * Series are Taylor series, which need no fitted coefficients, taken one term
 * past what their reduced ranges need. Reciprocals and inverse square roots
 * refine the hardware's single-precision estimates twice, each step doubling
 * their 21 good bits, rather than use NIR's double lowerings. Large angles
 * reduce by Payne and Hanek's method, multiplying the significand by the bits
 * of 2/pi that matter at its exponent. */
#include "air_precise.h"
#include "compiler/nir/nir_builtin_builder.h"
#include "util/macros.h"
#include <math.h>

/* Below this magnitude, odd functions round to their argument. */
#define TINY 0x1p-12f
/* Above this magnitude, x + sqrt(x * x +- 1) rounds to 2x. */
#define LARGE 0x1p13f

/* M_PI_2 and M_LN2 less the values they round from, for Cody and Waite's
 * reductions, in which FMA keeps every bit. */
#define PI_2_REST 6.123233995736766e-17
#define LN2_REST 2.3190468138462996e-17

/* The fractional bits of 2/pi, enough for any float's exponent. */
static const uint32_t two_over_pi[] = {
   0xa2f9836e, 0x4e441529, 0xfc2757d1, 0xf534ddc0, 0xdb629599, 0x3c439041, 0xfe5163ab,
};

static nir_def *
imm(nir_builder *b, double value)
{
   return nir_imm_double(b, value);
}

static nir_def *
high(nir_builder *b, nir_def *x)
{
   return nir_unpack_64_2x32_split_y(b, x);
}

/* x with its high word replaced. */
static nir_def *
with_high(nir_builder *b, nir_def *x, nir_def *word)
{
   return nir_pack_64_2x32_split(b, nir_unpack_64_2x32_split_x(b, x), word);
}

/* 2^k, for k in a double's normal range. */
static nir_def *
power(nir_builder *b, nir_def *k)
{
   return nir_pack_64_2x32_split(b, nir_imm_int(b, 0), nir_ishl_imm(b, nir_iadd_imm(b, k, 1023), 20));
}

/* A nonzero finite double's binary exponent. */
static nir_def *
exponent(nir_builder *b, nir_def *x)
{
   return nir_iadd_imm(b, nir_iand_imm(b, nir_ushr_imm(b, high(b, x), 20), 0x7ff), -1023);
}

/* c[0] + c[1] * x + ... */
static nir_def *
series(nir_builder *b, nir_def *x, const double *c, unsigned count)
{
   nir_def *sum = imm(b, c[count - 1]);
   for (unsigned i = count - 1; i-- > 0;)
      sum = nir_ffma(b, sum, x, imm(b, c[i]));
   return sum;
}

static nir_def *
reciprocal(nir_builder *b, nir_def *x)
{
   nir_def *k = exponent(b, x);
   nir_def *m = with_high(b, x, nir_isub(b, high(b, x), nir_ishl_imm(b, k, 20)));
   nir_def *y = nir_f2f64(b, nir_frcp(b, nir_f2f32(b, m)));
   for (unsigned i = 0; i < 2; i++)
      y = nir_fadd(b, y, nir_fmul(b, y, nir_ffma(b, nir_fneg(b, m), y, imm(b, 1.0))));
   return nir_fmul(b, y, power(b, nir_ineg(b, k)));
}

/* 1 / sqrt(x) of a positive finite double. */
static nir_def *
inverse_root(nir_builder *b, nir_def *x)
{
   nir_def *k = nir_ishr_imm(b, exponent(b, x), 1);
   nir_def *m = with_high(b, x, nir_isub(b, high(b, x), nir_ishl_imm(b, k, 21)));
   nir_def *half = nir_fmul_imm(b, m, 0.5);
   nir_def *y = nir_f2f64(b, nir_frsq(b, nir_f2f32(b, m)));
   for (unsigned i = 0; i < 2; i++)
      y = nir_fmul(b, y, nir_fsub(b, imm(b, 1.5), nir_fmul(b, nir_fmul(b, half, y), y)));
   return nir_fmul(b, y, power(b, nir_ineg(b, k)));
}

/* sqrt(x) of a nonnegative finite double. */
static nir_def *
root(nir_builder *b, nir_def *x)
{
   return nir_bcsel(b, nir_feq(b, x, imm(b, 0.0)), x, nir_fmul(b, x, inverse_root(b, x)));
}

/* Whether a float is negative, zeros and NaNs by their sign. */
static nir_def *
sign_bit(nir_builder *b, nir_def *x)
{
   return nir_ilt_imm(b, x, 0);
}

static nir_def *
negate_if(nir_builder *b, nir_def *condition, nir_def *x)
{
   return nir_bcsel(b, condition, nir_fneg(b, x), x);
}

static nir_def *
unless_nan(nir_builder *b, nir_def *x, nir_def *value)
{
   return nir_bcsel(b, nir_fneu(b, x, x), x, value);
}

static nir_def *
infinite(nir_builder *b, nir_def *x)
{
   return nir_feq(b, nir_fabs(b, x), nir_imm_float(b, INFINITY));
}

static nir_def *
positive_finite(nir_builder *b, nir_def *x)
{
   return nir_iand(b, nir_flt(b, nir_imm_float(b, 0.0f), x), nir_inot(b, infinite(b, x)));
}

static nir_def *
not_a_number(nir_builder *b)
{
   return nir_imm_float(b, NAN);
}

/* sin and cos of r + quadrant * pi / 2, for |r| <= pi / 4. */
static void
trigonometric(nir_builder *b, nir_def *r, nir_def *quadrant, nir_def **sine, nir_def **cosine)
{
   static const double odd[] = {-1.0 / 6, 1.0 / 120, -1.0 / 5040, 1.0 / 362880, -1.0 / 39916800};
   static const double even[] = {-0.5,           1.0 / 24,        -1.0 / 720,
                                 1.0 / 40320,    -1.0 / 3628800,  1.0 / 479001600};
   nir_def *z = nir_fmul(b, r, r);
   nir_def *s = nir_fmul(b, r, nir_fadd_imm(b, nir_fmul(b, z, series(b, z, odd, ARRAY_SIZE(odd))), 1.0));
   nir_def *c = nir_fadd_imm(b, nir_fmul(b, z, series(b, z, even, ARRAY_SIZE(even))), 1.0);
   nir_def *swap = nir_i2b(b, nir_iand_imm(b, quadrant, 1));
   *sine = negate_if(b, nir_i2b(b, nir_iand_imm(b, quadrant, 2)), nir_bcsel(b, swap, c, s));
   *cosine = negate_if(b, nir_i2b(b, nir_iand_imm(b, nir_iadd_imm(b, quadrant, 1), 2)),
                       nir_bcsel(b, swap, s, c));
}

/* The table's words from `index` plus `word`, for an index of at most 3. */
static nir_def *
table_word(nir_builder *b, nir_def *index, unsigned word)
{
   nir_def *value = nir_imm_int(b, two_over_pi[word]);
   for (unsigned i = 1; i < 4; i++)
      value = nir_bcsel(b, nir_uge_imm(b, index, i), nir_imm_int(b, two_over_pi[word + i]), value);
   return value;
}

/* A float's magnitude, 2^25 or above, as r + quadrant * pi / 2. Its significand
 * m is an integer of unit 2^(e - 150), so bits of 2/pi of weight above
 * 2^(151 - e) multiply it to multiples of 4, which turn nothing. The next 96
 * bits give the quadrant and 62 fractional bits. */
static void
reduce_far(nir_builder *b, nir_def *m, nir_def *e, nir_def **r, nir_def **quadrant)
{
   nir_def *offset = nir_iadd_imm(b, e, -152);
   nir_def *index = nir_ushr_imm(b, offset, 5), *shift = nir_iand_imm(b, offset, 31);
   nir_def *words[3];
   for (unsigned i = 0; i < 3; i++) {
      nir_def *next = nir_ushr_imm(b, table_word(b, index, i + 1), 1);
      words[i] = nir_ior(b, nir_ishl(b, table_word(b, index, i), shift),
                         nir_ushr(b, next, nir_isub_imm(b, 31, shift)));
   }
   nir_def *turns = nir_iadd(b, nir_umul_2x32_64(b, m, words[1]),
                             nir_u2u64(b, nir_umul_high(b, m, words[2])));
   turns = nir_iadd(b, turns, nir_pack_64_2x32_split(b, nir_imm_int(b, 0), nir_imul(b, m, words[0])));
   /* Round to the nearest quadrant. */
   turns = nir_iadd_imm(b, turns, 1ull << 61);
   nir_def *top = high(b, turns);
   *quadrant = nir_ushr_imm(b, top, 30);
   nir_def *rest = nir_iadd_imm(b, nir_iand_imm(b, top, 0x3fffffff), -(1 << 29));
   nir_def *fraction = nir_fadd(b, nir_fmul_imm(b, nir_i2f64(b, rest), 0x1p32),
                                nir_u2f64(b, nir_unpack_64_2x32_split_x(b, turns)));
   *r = nir_fmul_imm(b, fraction, M_PI_2 * 0x1p-62);
}

/* A finite x as r + quadrant * pi / 2, for |r| <= pi / 4. */
static void
reduce(nir_builder *b, nir_def *x, nir_def **r, nir_def **quadrant)
{
   nir_def *magnitude = nir_f2f64(b, nir_fabs(b, x));
   nir_def *k = nir_f2i32(b, nir_fadd_imm(b, nir_fmul_imm(b, magnitude, M_2_PI), 0.5));
   nir_def *whole = nir_fneg(b, nir_i2f64(b, k));
   nir_def *near = nir_ffma(b, whole, imm(b, M_PI_2), magnitude);
   near = nir_ffma(b, whole, imm(b, PI_2_REST), near);

   nir_def *e = nir_iand_imm(b, nir_ushr_imm(b, x, 23), 0xff);
   nir_def *m = nir_ior_imm(b, nir_iand_imm(b, x, 0x7fffff), 0x800000);
   nir_def *far, *turn;
   reduce_far(b, m, e, &far, &turn);

   nir_def *distant = nir_uge_imm(b, e, 152);
   nir_def *negative = sign_bit(b, x);
   *r = negate_if(b, negative, nir_bcsel(b, distant, far, near));
   k = nir_bcsel(b, distant, turn, k);
   *quadrant = nir_bcsel(b, negative, nir_ineg(b, k), k);
}

/* A finite x, a multiple of pi, as r + quadrant * pi / 2 with |r| <= pi / 4;
 * whole quarters of x stay exact. */
static void
reduce_turns(nir_builder *b, nir_def *x, nir_def **r, nir_def **quadrant)
{
   nir_def *half = nir_fmul_imm(b, nir_f2f64(b, nir_fabs(b, x)), 0.5);
   nir_def *rest = nir_fsub(b, half, nir_ffloor(b, half));
   nir_def *k = nir_f2i32(b, nir_fadd_imm(b, nir_fmul_imm(b, rest, 4.0), 0.5));
   nir_def *turn = nir_fsub(b, nir_fmul_imm(b, rest, 2.0), nir_fmul_imm(b, nir_i2f64(b, k), 0.5));
   nir_def *negative = sign_bit(b, x);
   *r = negate_if(b, negative, nir_fmul_imm(b, turn, M_PI));
   *quadrant = nir_bcsel(b, negative, nir_ineg(b, k), k);
}

static nir_def *
finite_or_nan(nir_builder *b, nir_def *x, nir_def *value)
{
   return nir_bcsel(b, nir_ior(b, infinite(b, x), nir_fneu(b, x, x)), not_a_number(b),
                    nir_f2f32(b, value));
}

nir_def *
stela_air_precise_sin(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce(b, x, &r, &quadrant);
   trigonometric(b, r, quadrant, &sine, &cosine);
   return finite_or_nan(b, x, sine);
}

nir_def *
stela_air_precise_cos(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce(b, x, &r, &quadrant);
   trigonometric(b, r, quadrant, &sine, &cosine);
   return finite_or_nan(b, x, cosine);
}

/* sine / cosine, infinite with sine's sign where cosine is exactly zero. */
static nir_def *
tangent(nir_builder *b, nir_def *r, nir_def *quadrant)
{
   nir_def *sine, *cosine;
   trigonometric(b, r, quadrant, &sine, &cosine);
   return nir_bcsel(b, nir_feq(b, cosine, imm(b, 0.0)),
                    nir_fmul_imm(b, sine, INFINITY),
                    nir_fmul(b, sine, reciprocal(b, cosine)));
}

nir_def *
stela_air_precise_tan(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant;
   reduce(b, x, &r, &quadrant);
   return finite_or_nan(b, x, tangent(b, r, quadrant));
}

nir_def *
stela_air_precise_sinpi(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce_turns(b, x, &r, &quadrant);
   trigonometric(b, r, quadrant, &sine, &cosine);
   return finite_or_nan(b, x, sine);
}

nir_def *
stela_air_precise_cospi(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce_turns(b, x, &r, &quadrant);
   trigonometric(b, r, quadrant, &sine, &cosine);
   return finite_or_nan(b, x, cosine);
}

nir_def *
stela_air_precise_tanpi(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant;
   reduce_turns(b, x, &r, &quadrant);
   return finite_or_nan(b, x, tangent(b, r, quadrant));
}

/* e^x, of a non-NaN double. Beyond +-200 a float's result stops changing. */
static nir_def *
exponential(nir_builder *b, nir_def *x)
{
   static const double c[] = {1.0,           1.0,           1.0 / 2,        1.0 / 6,
                              1.0 / 24,      1.0 / 120,     1.0 / 720,      1.0 / 5040,
                              1.0 / 40320,   1.0 / 362880,  1.0 / 3628800,  1.0 / 39916800};
   x = nir_fmax(b, nir_fmin(b, x, imm(b, 200.0)), imm(b, -200.0));
   nir_def *half = nir_bcsel(b, nir_flt(b, x, imm(b, 0.0)), imm(b, -0.5), imm(b, 0.5));
   nir_def *k = nir_f2i32(b, nir_fadd(b, nir_fmul_imm(b, x, 1.0 / M_LN2), half));
   nir_def *whole = nir_fneg(b, nir_i2f64(b, k));
   nir_def *r = nir_ffma(b, whole, imm(b, M_LN2), x);
   r = nir_ffma(b, whole, imm(b, LN2_REST), r);
   return nir_fmul(b, series(b, r, c, ARRAY_SIZE(c)), power(b, k));
}

/* The natural logarithm of a positive finite double. */
static nir_def *
logarithm(nir_builder *b, nir_def *x)
{
   static const double c[] = {1.0, 1.0 / 3, 1.0 / 5, 1.0 / 7, 1.0 / 9, 1.0 / 11, 1.0 / 13, 1.0 / 15};
   /* m is in [sqrt(1/2), sqrt(2)). */
   nir_def *top = nir_iadd_imm(b, high(b, x), 0x3ff00000 - 0x3fe6a09e);
   nir_def *k = nir_iadd_imm(b, nir_ushr_imm(b, top, 20), -1023);
   nir_def *m = with_high(b, x, nir_iadd_imm(b, nir_iand_imm(b, top, 0xfffff), 0x3fe6a09e));
   nir_def *s = nir_fmul(b, nir_fadd_imm(b, m, -1.0), reciprocal(b, nir_fadd_imm(b, m, 1.0)));
   nir_def *z = nir_fmul(b, s, s);
   return nir_fadd(b, nir_fmul_imm(b, nir_i2f64(b, k), M_LN2),
                   nir_fmul(b, nir_fmul_imm(b, s, 2.0), series(b, z, c, ARRAY_SIZE(c))));
}

/* A float's logarithm, in units of `unit` natural ones. */
static nir_def *
logarithm_of(nir_builder *b, nir_def *x, double unit)
{
   nir_def *value = nir_f2f32(b, nir_fmul_imm(b, logarithm(b, nir_f2f64(b, x)), 1.0 / unit));
   return nir_bcsel(b, positive_finite(b, x), value,
                    nir_bcsel(b, nir_feq_imm(b, x, 0.0), nir_imm_float(b, -INFINITY),
                              nir_bcsel(b, nir_flt_imm(b, x, 0.0), not_a_number(b), x)));
}

nir_def *
stela_air_precise_exp(nir_builder *b, nir_def *x, nir_def *y)
{
   return unless_nan(b, x, nir_f2f32(b, exponential(b, nir_f2f64(b, x))));
}

nir_def *
stela_air_precise_exp2(nir_builder *b, nir_def *x, nir_def *y)
{
   return unless_nan(b, x, nir_f2f32(b, exponential(b, nir_fmul_imm(b, nir_f2f64(b, x), M_LN2))));
}

nir_def *
stela_air_precise_exp10(nir_builder *b, nir_def *x, nir_def *y)
{
   return unless_nan(b, x, nir_f2f32(b, exponential(b, nir_fmul_imm(b, nir_f2f64(b, x), M_LN10))));
}

nir_def *
stela_air_precise_log(nir_builder *b, nir_def *x, nir_def *y)
{
   return logarithm_of(b, x, 1.0);
}

nir_def *
stela_air_precise_log2(nir_builder *b, nir_def *x, nir_def *y)
{
   return logarithm_of(b, x, M_LN2);
}

nir_def *
stela_air_precise_log10(nir_builder *b, nir_def *x, nir_def *y)
{
   return logarithm_of(b, x, M_LN10);
}

nir_def *
stela_air_precise_pow(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *magnitude = nir_fabs(b, x), *reach = nir_fabs(b, y);
   nir_def *one = nir_imm_float(b, 1.0f), *zero = nir_imm_float(b, 0.0f);
   nir_def *infinity = nir_imm_float(b, INFINITY);
   nir_def *whole = nir_feq(b, y, nir_ftrunc(b, y));
   nir_def *odd = nir_iand(b, nir_iand(b, whole, nir_flt_imm(b, reach, 0x1p24f)),
                           nir_i2b(b, nir_iand_imm(b, nir_f2i32(b, y), 1)));
   nir_def *flips = nir_iand(b, odd, sign_bit(b, x));
   nir_def *inverse = sign_bit(b, y);
   nir_def *scaled = nir_fmul(b, logarithm(b, nir_f2f64(b, magnitude)), nir_f2f64(b, y));

   nir_def *value = negate_if(b, flips, nir_f2f32(b, exponential(b, scaled)));
   value = nir_bcsel(b, nir_iand(b, nir_flt_imm(b, x, 0.0), nir_inot(b, whole)), not_a_number(b), value);
   /* x past one to an infinite y runs away, or to zero. */
   nir_def *beyond = nir_bcsel(b, nir_feq(b, magnitude, one), one,
                               nir_bcsel(b, nir_ieq(b, nir_flt(b, magnitude, one), inverse), infinity, zero));
   value = nir_bcsel(b, infinite(b, y), beyond, value);
   value = nir_bcsel(b, infinite(b, x), negate_if(b, flips, nir_bcsel(b, inverse, zero, infinity)), value);
   value = nir_bcsel(b, nir_feq_imm(b, x, 0.0), negate_if(b, flips, nir_bcsel(b, inverse, infinity, zero)), value);
   value = unless_nan(b, x, unless_nan(b, y, value));
   return nir_bcsel(b, nir_ior(b, nir_feq_imm(b, y, 0.0), nir_feq(b, x, one)), one, value);
}

nir_def *
stela_air_precise_powr(nir_builder *b, nir_def *x, nir_def *y)
{
   return nir_bcsel(b, nir_flt_imm(b, x, 0.0), not_a_number(b), stela_air_precise_pow(b, x, y));
}

/* atan(y / x) of positive finite doubles. */
static nir_def *
angle(nir_builder *b, nir_def *y, nir_def *x)
{
   static const double c[] = {1.0,      -1.0 / 3,  1.0 / 5,  -1.0 / 7,  1.0 / 9,
                              -1.0 / 11, 1.0 / 13, -1.0 / 15, 1.0 / 17, -1.0 / 19,
                              1.0 / 21,  -1.0 / 23, 1.0 / 25};
   nir_def *steep = nir_flt(b, x, y);
   nir_def *t = nir_fmul(b, nir_bcsel(b, steep, x, y), reciprocal(b, nir_bcsel(b, steep, y, x)));
   /* tan(pi / 8), which leaves atan(t) a pi / 4 from a shorter series. */
   nir_def *wide = nir_flt(b, imm(b, 0.41421356237309503), t);
   nir_def *r = nir_bcsel(b, wide,
                          nir_fmul(b, nir_fadd_imm(b, t, -1.0), reciprocal(b, nir_fadd_imm(b, t, 1.0))), t);
   nir_def *value = nir_fmul(b, r, series(b, nir_fmul(b, r, r), c, ARRAY_SIZE(c)));
   value = nir_bcsel(b, wide, nir_fadd_imm(b, value, M_PI_4), value);
   return nir_bcsel(b, steep, nir_fsub(b, imm(b, M_PI_2), value), value);
}

/* atan2(y, x) of doubles that are not NaN, as C's libraries give it. */
static nir_def *
arctangent(nir_builder *b, nir_def *y, nir_def *x)
{
   nir_def *rise = nir_fabs(b, y), *run = nir_fabs(b, x), *endless = imm(b, INFINITY);
   nir_def *vertical = nir_feq(b, rise, endless), *level = nir_feq(b, run, endless);
   nir_def *value = angle(b, rise, run);
   value = nir_bcsel(b, nir_ior(b, vertical, nir_feq(b, run, imm(b, 0.0))), imm(b, M_PI_2), value);
   value = nir_bcsel(b, nir_ior(b, level, nir_feq(b, rise, imm(b, 0.0))), imm(b, 0.0), value);
   value = nir_bcsel(b, nir_iand(b, vertical, level), imm(b, M_PI_4), value);
   value = nir_bcsel(b, nir_ilt_imm(b, high(b, x), 0), nir_fsub(b, imm(b, M_PI), value), value);
   return negate_if(b, nir_ilt_imm(b, high(b, y), 0), value);
}

nir_def *
stela_air_precise_atan2(nir_builder *b, nir_def *y, nir_def *x)
{
   return unless_nan(b, x, unless_nan(b, y, nir_f2f32(b, arctangent(b, nir_f2f64(b, y), nir_f2f64(b, x)))));
}

nir_def *
stela_air_precise_atan(nir_builder *b, nir_def *x, nir_def *y)
{
   return stela_air_precise_atan2(b, x, nir_imm_float(b, 1.0f));
}

/* sqrt(1 - x * x) of a float within [-1, 1]. */
static nir_def *
cofunction(nir_builder *b, nir_def *x)
{
   nir_def *wide = nir_f2f64(b, x);
   return root(b, nir_fmul(b, nir_fsub(b, imm(b, 1.0), wide), nir_fadd_imm(b, wide, 1.0)));
}

nir_def *
stela_air_precise_asin(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *value = nir_f2f32(b, arctangent(b, nir_f2f64(b, x), cofunction(b, x)));
   return nir_bcsel(b, nir_fgt_imm(b, nir_fabs(b, x), 1.0), not_a_number(b), unless_nan(b, x, value));
}

nir_def *
stela_air_precise_acos(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *value = nir_f2f32(b, arctangent(b, cofunction(b, x), nir_f2f64(b, x)));
   return nir_bcsel(b, nir_fgt_imm(b, nir_fabs(b, x), 1.0), not_a_number(b), unless_nan(b, x, value));
}

nir_def *
stela_air_precise_sinh(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *e = exponential(b, nir_f2f64(b, nir_fabs(b, x)));
   nir_def *value = nir_f2f32(b, nir_fmul_imm(b, nir_fsub(b, e, reciprocal(b, e)), 0.5));
   return unless_nan(b, x, nir_bcsel(b, nir_flt_imm(b, nir_fabs(b, x), TINY), x,
                                     negate_if(b, sign_bit(b, x), value)));
}

nir_def *
stela_air_precise_cosh(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *e = exponential(b, nir_f2f64(b, nir_fabs(b, x)));
   return unless_nan(b, x, nir_f2f32(b, nir_fmul_imm(b, nir_fadd(b, e, reciprocal(b, e)), 0.5)));
}

nir_def *
stela_air_precise_tanh(nir_builder *b, nir_def *x, nir_def *y)
{
   /* e^40 leaves a float's tanh at one. */
   nir_def *e = exponential(b, nir_fmin(b, nir_fmul_imm(b, nir_f2f64(b, nir_fabs(b, x)), 2.0), imm(b, 40.0)));
   nir_def *value = nir_f2f32(b, nir_fmul(b, nir_fadd_imm(b, e, -1.0), reciprocal(b, nir_fadd_imm(b, e, 1.0))));
   return unless_nan(b, x, nir_bcsel(b, nir_flt_imm(b, nir_fabs(b, x), TINY), x,
                                     negate_if(b, sign_bit(b, x), value)));
}

nir_def *
stela_air_precise_asinh(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *magnitude = nir_fabs(b, x), *wide = nir_f2f64(b, magnitude);
   nir_def *near = nir_fadd(b, wide, root(b, nir_fadd_imm(b, nir_fmul(b, wide, wide), 1.0)));
   nir_def *inner = nir_bcsel(b, nir_fge_imm(b, magnitude, LARGE), nir_fmul_imm(b, wide, 2.0), near);
   nir_def *value = negate_if(b, sign_bit(b, x), nir_f2f32(b, logarithm(b, inner)));
   value = nir_bcsel(b, nir_flt_imm(b, magnitude, TINY), x, value);
   return unless_nan(b, x, nir_bcsel(b, infinite(b, x), x, value));
}

nir_def *
stela_air_precise_acosh(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *wide = nir_f2f64(b, x);
   nir_def *rest = nir_fmul(b, nir_fadd_imm(b, wide, -1.0), nir_fadd_imm(b, wide, 1.0));
   nir_def *near = nir_fadd(b, wide, root(b, rest));
   nir_def *inner = nir_bcsel(b, nir_fge_imm(b, x, LARGE), nir_fmul_imm(b, wide, 2.0), near);
   nir_def *value = nir_f2f32(b, logarithm(b, inner));
   value = nir_bcsel(b, nir_flt_imm(b, x, 1.0), not_a_number(b), value);
   return unless_nan(b, x, nir_bcsel(b, nir_feq(b, x, nir_imm_float(b, INFINITY)), x, value));
}

nir_def *
stela_air_precise_atanh(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *magnitude = nir_fabs(b, x), *wide = nir_f2f64(b, magnitude);
   nir_def *ratio = nir_fmul(b, nir_fadd_imm(b, wide, 1.0), reciprocal(b, nir_fsub(b, imm(b, 1.0), wide)));
   nir_def *value = nir_f2f32(b, nir_fmul_imm(b, logarithm(b, ratio), 0.5));
   value = nir_bcsel(b, nir_feq_imm(b, magnitude, 1.0), nir_imm_float(b, INFINITY), value);
   value = nir_bcsel(b, nir_flt_imm(b, magnitude, TINY), magnitude, value);
   value = negate_if(b, sign_bit(b, x), value);
   return unless_nan(b, x, nir_bcsel(b, nir_fgt_imm(b, magnitude, 1.0), not_a_number(b), value));
}

nir_def *
stela_air_precise_sqrt(nir_builder *b, nir_def *x, nir_def *y)
{
   return nir_bcsel(b, positive_finite(b, x), nir_f2f32(b, root(b, nir_f2f64(b, x))),
                    nir_bcsel(b, nir_flt_imm(b, x, 0.0), not_a_number(b), x));
}

nir_def *
stela_air_precise_rsqrt(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *edge = nir_bcsel(b, nir_feq_imm(b, x, 0.0),
                             negate_if(b, sign_bit(b, x), nir_imm_float(b, INFINITY)),
                             nir_bcsel(b, nir_flt_imm(b, x, 0.0), not_a_number(b),
                                       nir_bcsel(b, infinite(b, x), nir_imm_float(b, 0.0f), x)));
   return nir_bcsel(b, positive_finite(b, x), nir_f2f32(b, inverse_root(b, nir_f2f64(b, x))), edge);
}

nir_def *
stela_air_precise_divide(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *n = nir_f2f64(b, x), *d = nir_f2f64(b, y);
   nir_def *inverse = reciprocal(b, d);
   nir_def *q = nir_fmul(b, n, inverse);
   q = nir_ffma(b, nir_ffma(b, nir_fneg(b, d), q, n), inverse, q);
   nir_def *ordinary = nir_iand(b, positive_finite(b, nir_fabs(b, x)), positive_finite(b, nir_fabs(b, y)));
   /* Zeros, infinities and NaNs have exact quotients. */
   return nir_bcsel(b, ordinary, nir_f2f32(b, q), nir_fdiv(b, x, y));
}

/* x modulo y takes off whole multiples of y scaled by 2^(23 * i), from the
 * largest of the 13 steps a float's exponents can need. Each remainder spans
 * 47 bits, so a double holds it exactly. */
nir_def *
stela_air_precise_fmod(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *divisor = nir_f2f64(b, nir_fabs(b, y)), *inverse = reciprocal(b, divisor);
   nir_def *rest = nir_f2f64(b, nir_fabs(b, x));
   for (int step = 12; step >= 0; step--) {
      double scale = ldexp(1.0, 23 * step);
      nir_def *w = nir_fmul_imm(b, divisor, scale);
      nir_def *q = nir_i2f64(b, nir_f2i32(b, nir_fmul_imm(b, nir_fmul(b, rest, inverse), 1.0 / scale)));
      nir_def *less = nir_ffma(b, nir_fneg(b, q), w, rest);
      less = nir_bcsel(b, nir_flt(b, less, imm(b, 0.0)), nir_fadd(b, less, w), less);
      less = nir_bcsel(b, nir_fge(b, less, w), nir_fsub(b, less, w), less);
      rest = nir_bcsel(b, nir_fge(b, rest, w), less, rest);
   }
   nir_def *value = negate_if(b, sign_bit(b, x), nir_f2f32(b, rest));
   nir_def *undefined = nir_ior(b, infinite(b, x), nir_ior(b, nir_feq_imm(b, y, 0.0), nir_fneu(b, y, y)));
   value = nir_bcsel(b, nir_fneu(b, x, x), x, nir_bcsel(b, undefined, not_a_number(b), value));
   return nir_bcsel(b, nir_iand(b, infinite(b, y), nir_inot(b, infinite(b, x))), x, value);
}

nir_def *
stela_air_precise(nir_builder *b, stela_air_precise_function *function, nir_def *x, nir_def *y)
{
   uint32_t control = b->fp_math_ctrl;
   b->fp_math_ctrl = nir_fp_no_fast_math;
   nir_def *lanes[NIR_MAX_VEC_COMPONENTS];
   for (unsigned i = 0; i < x->num_components; i++)
      lanes[i] = function(b, nir_channel(b, x, i), y ? nir_channel(b, y, i) : NULL);
   b->fp_math_ctrl = control;
   return nir_vec(b, lanes, x->num_components);
}

/* x - y's squared length, or x's without y. */
static nir_def *
squared_length(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *sum = imm(b, 0.0);
   for (unsigned i = 0; i < x->num_components; i++) {
      nir_def *lane = nir_f2f64(b, nir_channel(b, x, i));
      if (y)
         lane = nir_fsub(b, lane, nir_f2f64(b, nir_channel(b, y, i)));
      sum = nir_ffma(b, lane, lane, sum);
   }
   return sum;
}

nir_def *
stela_air_precise_length(nir_builder *b, nir_def *x, nir_def *y)
{
   uint32_t control = b->fp_math_ctrl;
   b->fp_math_ctrl = nir_fp_no_fast_math;
   nir_def *sum = squared_length(b, x, y);
   nir_def *value = nir_bcsel(b, nir_feq(b, sum, imm(b, INFINITY)), sum, root(b, sum));
   value = nir_f2f32(b, value);
   b->fp_math_ctrl = control;
   return value;
}

nir_def *
stela_air_precise_normalize(nir_builder *b, nir_def *x)
{
   uint32_t control = b->fp_math_ctrl;
   b->fp_math_ctrl = nir_fp_no_fast_math;
   nir_def *sum = squared_length(b, x, NULL);
   nir_def *inverse = inverse_root(b, sum);
   nir_def *usable = nir_iand(b, nir_flt(b, imm(b, 0.0), sum), nir_fneu(b, sum, imm(b, INFINITY)));
   nir_def *lanes[NIR_MAX_VEC_COMPONENTS];
   for (unsigned i = 0; i < x->num_components; i++) {
      nir_def *lane = nir_fmul(b, nir_f2f64(b, nir_channel(b, x, i)), inverse);
      lanes[i] = nir_bcsel(b, usable, nir_f2f32(b, lane), not_a_number(b));
   }
   b->fp_math_ctrl = control;
   return nir_vec(b, lanes, x->num_components);
}
