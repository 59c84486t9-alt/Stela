/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Metal's precise single-precision functions and division, which NIR's Vulkan
 * accuracy does not reach, in single precision: consumer GPUs run doubles at
 * a small fraction of the float rate, so no float function takes them. Each
 * stays within Metal's precise bounds (4 ulp for sines, cosines,
 * exponentials and logarithms, 5 to 6 for tangents and arctangents, 16 for
 * powers), with division and square roots correctly rounded and remainders
 * exact.
 *
 * Arguments reduce with Cody and Waite's split constants, in which FMA keeps
 * every bit, or for large angles with Payne and Hanek's method, multiplying
 * the significand by the bits of 2/pi that matter at its exponent. Reduced
 * arguments take Taylor series, which need no fitted coefficients, taken past
 * what a float needs. Where a value needs more than a float's precision on
 * the way, a pair of floats hi + lo carries it: FMA gives a product's exact
 * error, and Dekker's sum a sum's. The hardware's reciprocal and inverse
 * square root estimates only seed Newton steps, so their last bits never
 * reach a result. */
#include "air_precise.h"
#include "compiler/nir/nir_builtin_builder.h"
#include "util/macros.h"
#include <float.h>
#include <math.h>

/* Below this magnitude, odd functions round to their argument. */
#define TINY 0x1p-12f
/* Above this magnitude, x + sqrt(x * x +- 1) rounds to 2x. */
#define LARGE 0x1p13f
/* Below this magnitude, Cody and Waite's three parts of pi / 2 reduce an
 * angle within a float's precision. */
#define NEAR_ANGLE 105615.0f

/* Constants as a float and the float nearest the rest. */
#define PI_HI 3.14159274f
#define PI_LO -8.74227766e-08f
#define PI_2_HI 1.57079637f
#define PI_2_LO -4.37113883e-08f
#define PI_4_HI 0.785398185f
#define PI_4_LO -2.18556941e-08f
#define LN2_HI 0.693147182f
#define LN2_LO -1.90465421e-09f
#define LN10_HI 2.30258512f
#define LN10_LO -3.19754356e-08f
#define LOG2E_HI 1.44269502f
#define LOG2E_LO 1.92596303e-08f
#define LOG10E_HI 0.434294492f
#define LOG10E_LO -1.01030500e-08f
/* ln(2) and log10(2) in 15 significant bits and the rest, so that their
 * product with an exponent of at most 8 bits is exact. */
#define LN2_SPLIT 0.693145752f
#define LN2_SPLIT_REST 1.42860677e-06f
#define LOG10_2_SPLIT 0.301025391f
#define LOG10_2_SPLIT_REST 4.60503907e-06f
/* pi / 2 in three parts (CUDA's), the first two short enough for FMA to
 * subtract a quadrant count's multiples exactly below NEAR_ANGLE. */
#define PI_2_PART1 1.57079601f
#define PI_2_PART2 3.13916473e-07f
#define PI_2_PART3 5.39030253e-15f

/* The fractional bits of 2/pi, after a zero word for the integer part,
 * enough for any float's exponent. */
static const uint32_t two_over_pi[] = {
   0x00000000, 0xa2f9836e, 0x4e441529, 0xfc2757d1, 0xf534ddc0, 0xdb629599, 0x3c439041, 0xfe5163ab,
};

static nir_def *
imm(nir_builder *b, float value)
{
   return nir_imm_float(b, value);
}

/* c[0] + c[1] * x + ... */
static nir_def *
series(nir_builder *b, nir_def *x, const float *c, unsigned count)
{
   nir_def *sum = imm(b, c[count - 1]);
   for (unsigned i = count - 1; i-- > 0;)
      sum = nir_ffma(b, sum, x, imm(b, c[i]));
   return sum;
}

/* 2^k, for k in a float's normal range. */
static nir_def *
power(nir_builder *b, nir_def *k)
{
   return nir_ishl_imm(b, nir_iadd_imm(b, k, 127), 23);
}

/* x * 2^k for k in [-252, 254], rounded once where x is normal. */
static nir_def *
scale(nir_builder *b, nir_def *x, nir_def *k)
{
   nir_def *first = nir_ishr_imm(b, k, 1);
   return nir_fmul(b, nir_fmul(b, x, power(b, first)), power(b, nir_isub(b, k, first)));
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
   return nir_feq(b, nir_fabs(b, x), imm(b, INFINITY));
}

static nir_def *
positive_finite(nir_builder *b, nir_def *x)
{
   return nir_iand(b, nir_flt(b, imm(b, 0.0f), x), nir_inot(b, infinite(b, x)));
}

static nir_def *
not_a_number(nir_builder *b)
{
   return imm(b, NAN);
}

/* A value as hi + lo. */
struct pair {
   nir_def *hi, *lo;
};

/* a + c exactly, for |a| >= |c| or a zero a (Dekker). */
static struct pair
quick_sum(nir_builder *b, nir_def *a, nir_def *c)
{
   nir_def *s = nir_fadd(b, a, c);
   return (struct pair){s, nir_fsub(b, c, nir_fsub(b, s, a))};
}

/* a * c exactly. */
static struct pair
product(nir_builder *b, nir_def *a, nir_def *c)
{
   nir_def *p = nir_fmul(b, a, c);
   return (struct pair){p, nir_ffma(b, a, c, nir_fneg(b, p))};
}

/* x * (hi + lo) for a constant's parts, as a pair. */
static struct pair
times_constant(nir_builder *b, struct pair x, float hi, float lo)
{
   struct pair p = product(b, x.hi, imm(b, hi));
   nir_def *rest = nir_ffma(b, x.hi, imm(b, lo), nir_fmul_imm(b, x.lo, hi));
   return (struct pair){p.hi, nir_fadd(b, p.lo, rest)};
}

/* 1 / d within an ulp, for |d| in [2^-125, 2^125]: the hardware's estimate
 * after a Newton step. */
static nir_def *
reciprocal(nir_builder *b, nir_def *d)
{
   nir_def *y = nir_frcp(b, d);
   return nir_ffma(b, y, nir_ffma(b, nir_fneg(b, d), y, imm(b, 1.0f)), y);
}

/* n / d of finite floats, n nonnegative and d positive, correctly rounded
 * where the quotient is normal and within an ulp where it is subnormal: the
 * quotient from a Newton reciprocal, then corrected by its exact residual.
 * Scaling both keeps the reciprocal and the residual in range. */
static nir_def *
quotient(nir_builder *b, nir_def *n, nir_def *d)
{
   nir_def *small = nir_iand(b, nir_flt_imm(b, nir_fmin(b, n, d), 0x1p-100f),
                             nir_flt_imm(b, d, 0x1p90f));
   nir_def *factor = nir_bcsel(b, nir_fge_imm(b, d, 0x1p122f), imm(b, 0x1p-4f),
                               nir_bcsel(b, small, imm(b, 0x1p32f), imm(b, 1.0f)));
   n = nir_fmul(b, n, factor);
   d = nir_fmul(b, d, factor);
   nir_def *inverse = reciprocal(b, d);
   nir_def *q = nir_fmul(b, n, inverse);
   nir_def *refined = nir_ffma(b, nir_ffma(b, nir_fneg(b, d), q, n), inverse, q);
   return nir_bcsel(b, infinite(b, q), q, refined);
}

/* 1 / sqrt(x) of a positive finite float, within an ulp: the hardware's
 * estimate after a Newton step whose residual keeps x * y's rounding. */
static nir_def *
inverse_root(nir_builder *b, nir_def *x)
{
   nir_def *tiny = nir_flt_imm(b, x, 0x1p-100f);
   x = nir_bcsel(b, tiny, nir_fmul_imm(b, x, 0x1p64f), x);
   nir_def *y = nir_frsq(b, x);
   struct pair t = product(b, x, y);
   nir_def *e = nir_ffma(b, nir_fneg(b, t.lo), y, nir_ffma(b, nir_fneg(b, t.hi), y, imm(b, 1.0f)));
   y = nir_ffma(b, nir_fmul_imm(b, y, 0.5f), e, y);
   return nir_bcsel(b, tiny, nir_fmul_imm(b, y, 0x1p32f), y);
}

/* sqrt(x) of a positive finite float, correctly rounded: the hardware's
 * inverse square root, a coupled Newton step on the root and its half
 * inverse, then a correction by the root's exact residual (Markstein). */
static nir_def *
root(nir_builder *b, nir_def *x)
{
   nir_def *tiny = nir_flt_imm(b, x, 0x1p-100f);
   x = nir_bcsel(b, tiny, nir_fmul_imm(b, x, 0x1p64f), x);
   nir_def *y = nir_frsq(b, x);
   nir_def *g = nir_fmul(b, x, y), *h = nir_fmul_imm(b, y, 0.5f);
   nir_def *r = nir_ffma(b, nir_fneg(b, g), h, imm(b, 0.5f));
   g = nir_ffma(b, g, r, g);
   h = nir_ffma(b, h, r, h);
   g = nir_ffma(b, nir_ffma(b, nir_fneg(b, g), g, x), h, g);
   return nir_bcsel(b, tiny, nir_fmul_imm(b, g, 0x1p-32f), g);
}

/* sqrt(x) of a nonnegative finite float. */
static nir_def *
root_or_zero(nir_builder *b, nir_def *x)
{
   return nir_bcsel(b, nir_feq_imm(b, x, 0.0f), x, root(b, x));
}

/* sin and cos of r + quadrant * pi / 2, for |r| <= pi / 4. The series' next
 * terms are under a twentieth of an ulp. */
static void
trigonometric(nir_builder *b, nir_def *r, nir_def *quadrant, nir_def **sine, nir_def **cosine)
{
   static const float odd[] = {-1.0f / 6, 1.0f / 120, -1.0f / 5040, 1.0f / 362880};
   static const float even[] = {-0.5f, 1.0f / 24, -1.0f / 720, 1.0f / 40320, -1.0f / 3628800};
   nir_def *z = nir_fmul(b, r, r);
   nir_def *s = nir_ffma(b, nir_fmul(b, r, z), series(b, z, odd, ARRAY_SIZE(odd)), r);
   nir_def *c = nir_ffma(b, z, series(b, z, even, ARRAY_SIZE(even)), imm(b, 1.0f));
   nir_def *swap = nir_i2b(b, nir_iand_imm(b, quadrant, 1));
   *sine = negate_if(b, nir_i2b(b, nir_iand_imm(b, quadrant, 2)), nir_bcsel(b, swap, c, s));
   *cosine = negate_if(b, nir_i2b(b, nir_iand_imm(b, nir_iadd_imm(b, quadrant, 1), 2)),
                       nir_bcsel(b, swap, s, c));
}

/* The table's words from `index` plus `word`, for an index of at most 4. */
static nir_def *
table_word(nir_builder *b, nir_def *index, unsigned word)
{
   nir_def *value = nir_imm_int(b, two_over_pi[word]);
   for (unsigned i = 1; i < 5; i++)
      value = nir_bcsel(b, nir_uge_imm(b, index, i), nir_imm_int(b, two_over_pi[word + i]), value);
   return value;
}

/* A float's magnitude, 2^-7 or above, as r + quadrant * pi / 2. Its
 * significand m is an integer of unit 2^(e - 150), so bits of 2/pi of
 * weight above 2^(151 - e) multiply it to multiples of 4, which turn
 * nothing. The next 96 bits give the quadrant and 62 fractional bits. */
static void
reduce_far(nir_builder *b, nir_def *m, nir_def *e, nir_def **r, nir_def **quadrant)
{
   nir_def *offset = nir_iadd_imm(b, e, 32 - 152);
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
   nir_def *top = nir_unpack_64_2x32_split_y(b, turns);
   *quadrant = nir_ushr_imm(b, top, 30);
   nir_def *rest = nir_iadd_imm(b, nir_iand_imm(b, top, 0x3fffffff), -(1 << 29));
   nir_def *fraction = nir_ffma(b, nir_i2f32(b, rest), imm(b, 0x1p32f),
                                nir_u2f32(b, nir_unpack_64_2x32_split_x(b, turns)));
   *r = nir_ffma(b, fraction, imm(b, PI_2_HI * 0x1p-62f), nir_fmul_imm(b, fraction, PI_2_LO * 0x1p-62f));
}

/* A finite x as r + quadrant * pi / 2, for |r| <= pi / 4. */
static void
reduce(nir_builder *b, nir_def *x, nir_def **r, nir_def **quadrant)
{
   nir_def *magnitude = nir_fabs(b, x);
   nir_def *turn = nir_fround_even(b, nir_fmul_imm(b, magnitude, (float)M_2_PI));
   nir_def *near = nir_ffma(b, nir_fneg(b, turn), imm(b, PI_2_PART1), magnitude);
   near = nir_ffma(b, nir_fneg(b, turn), imm(b, PI_2_PART2), near);
   near = nir_ffma(b, nir_fneg(b, turn), imm(b, PI_2_PART3), near);

   nir_def *e = nir_iand_imm(b, nir_ushr_imm(b, x, 23), 0xff);
   nir_def *m = nir_ior_imm(b, nir_iand_imm(b, x, 0x7fffff), 0x800000);
   nir_def *far, *count;
   reduce_far(b, m, e, &far, &count);

   nir_def *distant = nir_fge_imm(b, magnitude, NEAR_ANGLE);
   nir_def *negative = sign_bit(b, x);
   nir_def *k = nir_bcsel(b, distant, count, nir_f2i32(b, nir_fmin(b, turn, imm(b, NEAR_ANGLE))));
   *r = negate_if(b, negative, nir_bcsel(b, distant, far, near));
   *quadrant = nir_bcsel(b, negative, nir_ineg(b, k), k);
}

/* A finite x, a multiple of pi, as r + quadrant * pi / 2 with |r| <= pi / 4;
 * whole quarters of x stay exact. */
static void
reduce_turns(nir_builder *b, nir_def *x, nir_def **r, nir_def **quadrant)
{
   nir_def *magnitude = nir_fabs(b, x);
   /* |x| modulo 2, exactly. */
   nir_def *t = nir_ffma(b, nir_ffloor(b, nir_fmul_imm(b, magnitude, 0.5f)), imm(b, -2.0f), magnitude);
   nir_def *quarters = nir_fround_even(b, nir_fmul_imm(b, t, 2.0f));
   nir_def *turn = nir_ffma(b, quarters, imm(b, -0.5f), t);
   nir_def *k = nir_f2i32(b, quarters);
   nir_def *negative = sign_bit(b, x);
   nir_def *angle = nir_ffma(b, turn, imm(b, PI_HI), nir_fmul_imm(b, turn, PI_LO));
   *r = negate_if(b, negative, angle);
   *quadrant = nir_bcsel(b, negative, nir_ineg(b, k), k);
}

static nir_def *
finite_or_nan(nir_builder *b, nir_def *x, nir_def *value)
{
   return nir_bcsel(b, nir_ior(b, infinite(b, x), nir_fneu(b, x, x)), not_a_number(b), value);
}

/* An odd function's value, which keeps a zero's sign. */
static nir_def *
odd_or_zero(nir_builder *b, nir_def *x, nir_def *value)
{
   return nir_bcsel(b, nir_feq_imm(b, x, 0.0f), x, finite_or_nan(b, x, value));
}

nir_def *
stela_air_precise_sin(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce(b, x, &r, &quadrant);
   trigonometric(b, r, quadrant, &sine, &cosine);
   return odd_or_zero(b, x, sine);
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
   nir_def *inverse = reciprocal(b, cosine);
   nir_def *t = nir_fmul(b, sine, inverse);
   t = nir_ffma(b, nir_ffma(b, nir_fneg(b, cosine), t, sine), inverse, t);
   return nir_bcsel(b, nir_feq_imm(b, cosine, 0.0f), nir_fmul_imm(b, sine, INFINITY), t);
}

nir_def *
stela_air_precise_tan(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant;
   reduce(b, x, &r, &quadrant);
   return odd_or_zero(b, x, tangent(b, r, quadrant));
}

nir_def *
stela_air_precise_sinpi(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce_turns(b, x, &r, &quadrant);
   trigonometric(b, r, quadrant, &sine, &cosine);
   return odd_or_zero(b, x, sine);
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
   /* Odd quarter turns, whose sine and cosine series differ in their last
    * bits, have a tangent of exactly one. */
   nir_def *unit = negate_if(b, nir_ine(b, sign_bit(b, r), nir_i2b(b, nir_iand_imm(b, quadrant, 1))),
                             imm(b, 1.0f));
   nir_def *value = nir_bcsel(b, nir_feq_imm(b, nir_fabs(b, r), PI_4_HI), unit, tangent(b, r, quadrant));
   return odd_or_zero(b, x, value);
}

/* e^(r + lo) for |r| <= ln(2) / 2 and a small lo; the series' next term is
 * under a tenth of an ulp. */
static nir_def *
exponential_core(nir_builder *b, nir_def *r, nir_def *lo)
{
   static const float c[] = {1.0f,       1.0f,        1.0f / 2,   1.0f / 6,
                             1.0f / 24,  1.0f / 120,  1.0f / 720, 1.0f / 5040};
   nir_def *p = series(b, r, c, ARRAY_SIZE(c));
   return lo ? nir_ffma(b, p, lo, p) : p;
}

/* e^x * 2^shift, of a non-NaN float. Beyond +-104 a float's e^x stops
 * changing. */
static nir_def *
exponential(nir_builder *b, nir_def *x, int shift)
{
   x = nir_fmax(b, nir_fmin(b, x, imm(b, 104.0f)), imm(b, -104.0f));
   nir_def *turn = nir_fround_even(b, nir_fmul_imm(b, x, LOG2E_HI));
   nir_def *r = nir_ffma(b, nir_fneg(b, turn), imm(b, LN2_SPLIT), x);
   r = nir_ffma(b, nir_fneg(b, turn), imm(b, LN2_SPLIT_REST), r);
   return scale(b, exponential_core(b, r, NULL), nir_iadd_imm(b, nir_f2i32(b, turn), shift));
}

/* 2^(hi + lo) for |hi| at most 200, lo small. */
static nir_def *
binary_power(nir_builder *b, struct pair x)
{
   nir_def *turn = nir_fround_even(b, x.hi);
   nir_def *f = nir_fadd(b, nir_fsub(b, x.hi, turn), x.lo);
   struct pair r = product(b, f, imm(b, LN2_HI));
   nir_def *lo = nir_ffma(b, f, imm(b, LN2_LO), r.lo);
   return scale(b, exponential_core(b, r.hi, lo), nir_f2i32(b, turn));
}

nir_def *
stela_air_precise_exp(nir_builder *b, nir_def *x, nir_def *y)
{
   return unless_nan(b, x, exponential(b, x, 0));
}

nir_def *
stela_air_precise_exp2(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *clamped = nir_fmax(b, nir_fmin(b, x, imm(b, 160.0f)), imm(b, -160.0f));
   return unless_nan(b, x, binary_power(b, (struct pair){clamped, imm(b, 0.0f)}));
}

nir_def *
stela_air_precise_exp10(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *clamped = nir_fmax(b, nir_fmin(b, x, imm(b, 46.0f)), imm(b, -46.0f));
   nir_def *turn = nir_fround_even(b, nir_fmul_imm(b, clamped, (float)(M_LN10 / M_LN2)));
   /* x - turn * log10(2), exactly to the split's rest. */
   nir_def *t = nir_ffma(b, nir_fneg(b, turn), imm(b, LOG10_2_SPLIT), clamped);
   t = nir_ffma(b, nir_fneg(b, turn), imm(b, LOG10_2_SPLIT_REST), t);
   struct pair r = product(b, t, imm(b, LN10_HI));
   nir_def *lo = nir_ffma(b, t, imm(b, LN10_LO), r.lo);
   nir_def *value = scale(b, exponential_core(b, r.hi, lo), nir_f2i32(b, turn));
   return unless_nan(b, x, value);
}

/* A positive finite x as 2^e * m with m in [sqrt(1/2), sqrt(2)), and ln(m)
 * as a pair: ln(m) = 2 atanh(s), s = f / (2 + f), f = m - 1 exact. The
 * pair carries s past a float's precision; its series' next term is under
 * 2^-34 of the result. */
static struct pair
logarithm_parts(nir_builder *b, nir_def *x, nir_def **e)
{
   static const float c[] = {2.0f / 3, 2.0f / 5, 2.0f / 7, 2.0f / 9, 2.0f / 11, 2.0f / 13};
   nir_def *subnormal = nir_flt_imm(b, x, 0x1p-126f);
   x = nir_bcsel(b, subnormal, nir_fmul_imm(b, x, 0x1p24f), x);
   nir_def *k = nir_ishr_imm(b, nir_iadd_imm(b, x, -0x3f3504f3), 23);
   *e = nir_iadd(b, k, nir_bcsel(b, subnormal, nir_imm_int(b, -24), nir_imm_int(b, 0)));
   nir_def *m = nir_isub(b, x, nir_ishl_imm(b, k, 23));
   nir_def *f = nir_fadd_imm(b, m, -1.0f);
   struct pair u = quick_sum(b, imm(b, 2.0f), f);
   nir_def *inverse = reciprocal(b, u.hi);
   nir_def *s = nir_fmul(b, f, inverse);
   nir_def *residual = nir_ffma(b, nir_fneg(b, s), u.lo, nir_ffma(b, nir_fneg(b, s), u.hi, f));
   nir_def *s_lo = nir_fmul(b, residual, inverse);
   nir_def *z = nir_fmul(b, s, s);
   nir_def *tail = nir_fmul(b, nir_fmul(b, s, z), series(b, z, c, ARRAY_SIZE(c)));
   return quick_sum(b, nir_fmul_imm(b, s, 2.0f), nir_ffma(b, s_lo, imm(b, 2.0f), tail));
}

/* ln(x) of a positive finite float, as a pair. */
static struct pair
natural_logarithm(nir_builder *b, nir_def *x)
{
   nir_def *e;
   struct pair l = logarithm_parts(b, x, &e);
   nir_def *whole = nir_i2f32(b, e);
   struct pair s = quick_sum(b, nir_fmul_imm(b, whole, LN2_SPLIT), l.hi);
   nir_def *rest = nir_ffma(b, whole, imm(b, LN2_SPLIT_REST), nir_fadd(b, s.lo, l.lo));
   return (struct pair){s.hi, rest};
}

/* log2(x) of a positive finite float, as a pair. */
static struct pair
binary_logarithm(nir_builder *b, nir_def *x)
{
   nir_def *e;
   struct pair l = times_constant(b, logarithm_parts(b, x, &e), LOG2E_HI, LOG2E_LO);
   struct pair s = quick_sum(b, nir_i2f32(b, e), l.hi);
   return (struct pair){s.hi, nir_fadd(b, s.lo, l.lo)};
}

/* log10(x) of a positive finite float. */
static nir_def *
decimal_logarithm(nir_builder *b, nir_def *x)
{
   nir_def *e;
   struct pair l = times_constant(b, logarithm_parts(b, x, &e), LOG10E_HI, LOG10E_LO);
   nir_def *whole = nir_i2f32(b, e);
   struct pair s = quick_sum(b, nir_fmul_imm(b, whole, LOG10_2_SPLIT), l.hi);
   return nir_fadd(b, s.hi, nir_ffma(b, whole, imm(b, LOG10_2_SPLIT_REST), nir_fadd(b, s.lo, l.lo)));
}

/* A logarithm's value at every other float: -infinity at zeros, NaN below. */
static nir_def *
logarithm_of(nir_builder *b, nir_def *x, nir_def *value)
{
   return nir_bcsel(b, positive_finite(b, x), value,
                    nir_bcsel(b, nir_feq_imm(b, x, 0.0f), imm(b, -INFINITY),
                              nir_bcsel(b, nir_flt_imm(b, x, 0.0f), not_a_number(b), x)));
}

static nir_def *
sum(nir_builder *b, struct pair x)
{
   return nir_fadd(b, x.hi, x.lo);
}

nir_def *
stela_air_precise_log(nir_builder *b, nir_def *x, nir_def *y)
{
   return logarithm_of(b, x, sum(b, natural_logarithm(b, x)));
}

nir_def *
stela_air_precise_log2(nir_builder *b, nir_def *x, nir_def *y)
{
   return logarithm_of(b, x, sum(b, binary_logarithm(b, x)));
}

nir_def *
stela_air_precise_log10(nir_builder *b, nir_def *x, nir_def *y)
{
   return logarithm_of(b, x, decimal_logarithm(b, x));
}

nir_def *
stela_air_precise_pow(nir_builder *b, nir_def *x, nir_def *y)
{
   /* y * log2|x| keeps a pair: its rounding alone would take a result of
    * 2^100 nearly a hundred ulps away. */
   struct pair t = binary_logarithm(b, nir_fabs(b, x));
   struct pair p = product(b, y, t.hi);
   p.lo = nir_ffma(b, y, t.lo, p.lo);
   nir_def *beyond = nir_inot(b, nir_flt_imm(b, nir_fabs(b, p.hi), 200.0f));
   p.hi = nir_fmax(b, nir_fmin(b, p.hi, imm(b, 200.0f)), imm(b, -200.0f));
   p.lo = nir_bcsel(b, beyond, imm(b, 0.0f), p.lo);
   return stela_air_pow_of(b, x, y, binary_power(b, p));
}

nir_def *
stela_air_pow_of(nir_builder *b, nir_def *x, nir_def *y, nir_def *power)
{
   nir_def *magnitude = nir_fabs(b, x), *reach = nir_fabs(b, y);
   nir_def *one = imm(b, 1.0f), *zero = imm(b, 0.0f);
   nir_def *infinity = imm(b, INFINITY);
   nir_def *whole = nir_feq(b, y, nir_ftrunc(b, y));
   nir_def *odd = nir_iand(b, nir_iand(b, whole, nir_flt_imm(b, reach, 0x1p24f)),
                           nir_i2b(b, nir_iand_imm(b, nir_f2i32(b, y), 1)));
   nir_def *flips = nir_iand(b, odd, sign_bit(b, x));
   nir_def *inverse = sign_bit(b, y);
   nir_def *value = negate_if(b, flips, power);
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

/* atan(y / x) of nonnegative finite floats, not both zero. */
static nir_def *
angle(nir_builder *b, nir_def *y, nir_def *x)
{
   static const float c[] = {-1.0f / 3,  1.0f / 5,  -1.0f / 7,  1.0f / 9,  -1.0f / 11,
                             1.0f / 13,  -1.0f / 15, 1.0f / 17, -1.0f / 19};
   nir_def *steep = nir_flt(b, x, y);
   nir_def *t = quotient(b, nir_bcsel(b, steep, x, y), nir_bcsel(b, steep, y, x));
   /* tan(pi / 8), which leaves atan(t) a pi / 4 from a shorter series. */
   nir_def *wide = nir_flt(b, imm(b, 0.414213562f), t);
   nir_def *r = nir_bcsel(b, wide,
                          nir_fneg(b, quotient(b, nir_fsub(b, imm(b, 1.0f), t), nir_fadd_imm(b, t, 1.0f))),
                          t);
   nir_def *z = nir_fmul(b, r, r);
   nir_def *value = nir_ffma(b, nir_fmul(b, r, z), series(b, z, c, ARRAY_SIZE(c)), r);
   value = nir_bcsel(b, wide, nir_fadd(b, imm(b, PI_4_HI), nir_fadd_imm(b, value, PI_4_LO)), value);
   return nir_bcsel(b, steep, nir_fadd_imm(b, nir_fsub(b, imm(b, PI_2_HI), value), PI_2_LO), value);
}

/* atan2(y, x) of floats that are not NaN, as C's libraries give it. */
static nir_def *
arctangent(nir_builder *b, nir_def *y, nir_def *x)
{
   nir_def *rise = nir_fabs(b, y), *run = nir_fabs(b, x), *endless = imm(b, INFINITY);
   nir_def *vertical = nir_feq(b, rise, endless), *level = nir_feq(b, run, endless);
   nir_def *value = angle(b, rise, run);
   value = nir_bcsel(b, nir_ior(b, vertical, nir_feq_imm(b, run, 0.0f)), imm(b, PI_2_HI), value);
   value = nir_bcsel(b, nir_ior(b, level, nir_feq_imm(b, rise, 0.0f)), imm(b, 0.0f), value);
   value = nir_bcsel(b, nir_iand(b, vertical, level), imm(b, PI_4_HI), value);
   value = nir_bcsel(b, sign_bit(b, x), nir_fadd_imm(b, nir_fsub(b, imm(b, PI_HI), value), PI_LO), value);
   return negate_if(b, sign_bit(b, y), value);
}

nir_def *
stela_air_precise_atan2(nir_builder *b, nir_def *y, nir_def *x)
{
   return unless_nan(b, x, unless_nan(b, y, arctangent(b, y, x)));
}

nir_def *
stela_air_precise_atan(nir_builder *b, nir_def *x, nir_def *y)
{
   return stela_air_precise_atan2(b, x, imm(b, 1.0f));
}

/* sqrt(1 - x * x) of a float within [-1, 1], rounded twice. */
static nir_def *
cofunction(nir_builder *b, nir_def *x)
{
   return root_or_zero(b, nir_fmax(b, nir_ffma(b, nir_fneg(b, x), x, imm(b, 1.0f)), imm(b, 0.0f)));
}

nir_def *
stela_air_precise_asin(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *value = arctangent(b, x, cofunction(b, x));
   return nir_bcsel(b, nir_fgt_imm(b, nir_fabs(b, x), 1.0), not_a_number(b), unless_nan(b, x, value));
}

nir_def *
stela_air_precise_acos(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *value = arctangent(b, cofunction(b, x), x);
   return nir_bcsel(b, nir_fgt_imm(b, nir_fabs(b, x), 1.0), not_a_number(b), unless_nan(b, x, value));
}

nir_def *
stela_air_precise_sinh(nir_builder *b, nir_def *x, nir_def *y)
{
   static const float c[] = {1.0f / 6, 1.0f / 120, 1.0f / 5040, 1.0f / 362880, 1.0f / 39916800};
   nir_def *magnitude = nir_fabs(b, x);
   /* Below one, the odd series, whose next term is under 2^-32. */
   nir_def *z = nir_fmul(b, magnitude, magnitude);
   nir_def *near = nir_ffma(b, nir_fmul(b, magnitude, z), series(b, z, c, ARRAY_SIZE(c)), magnitude);
   /* Above, e^|x| / 2 - e^-|x| / 2, whose second part is at most e^-2 of
    * the first. */
   nir_def *half = exponential(b, magnitude, -1);
   nir_def *far = nir_ffma(b, reciprocal(b, nir_fmin(b, half, imm(b, 0x1p120f))), imm(b, -0.25f), half);
   nir_def *value = nir_bcsel(b, nir_flt_imm(b, magnitude, 1.0f), near, far);
   return unless_nan(b, x, nir_bcsel(b, nir_flt_imm(b, magnitude, TINY), x,
                                     negate_if(b, sign_bit(b, x), value)));
}

nir_def *
stela_air_precise_cosh(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *half = exponential(b, nir_fabs(b, x), -1);
   nir_def *value = nir_ffma(b, reciprocal(b, nir_fmin(b, half, imm(b, 0x1p120f))), imm(b, 0.25f), half);
   return unless_nan(b, x, value);
}

nir_def *
stela_air_precise_tanh(nir_builder *b, nir_def *x, nir_def *y)
{
   /* e^t - 1 for t below 1.1, whose next term is under 2^-27. */
   static const float c[] = {1.0f,          1.0f / 2,       1.0f / 6,         1.0f / 24,
                             1.0f / 120,    1.0f / 720,     1.0f / 5040,      1.0f / 40320,
                             1.0f / 362880, 1.0f / 3628800, 1.0f / 39916800,  1.0f / 479001600};
   nir_def *magnitude = nir_fabs(b, x);
   nir_def *t = nir_fmul_imm(b, magnitude, 2.0f);
   /* Below 0.55, (e^2x - 1) / (e^2x + 1) from e^2x - 1's series. */
   nir_def *rise = nir_fmul(b, t, series(b, t, c, ARRAY_SIZE(c)));
   nir_def *near = quotient(b, rise, nir_fadd_imm(b, rise, 2.0f));
   /* Above, 1 - 2 / (e^2x + 1), at least a half. e^40 leaves a float's
    * tanh at one. */
   nir_def *e = exponential(b, nir_fmin(b, t, imm(b, 40.0f)), 0);
   nir_def *far = nir_ffma(b, reciprocal(b, nir_fadd_imm(b, e, 1.0f)), imm(b, -2.0f), imm(b, 1.0f));
   nir_def *value = nir_bcsel(b, nir_flt_imm(b, magnitude, 0.55f), near, far);
   return unless_nan(b, x, nir_bcsel(b, nir_flt_imm(b, magnitude, TINY), x,
                                     negate_if(b, sign_bit(b, x), value)));
}

/* ln(hi + lo) of a positive finite pair, plus ln(2) where `doubled`. */
static nir_def *
logarithm_of_pair(nir_builder *b, struct pair u, nir_def *doubled)
{
   struct pair l = natural_logarithm(b, u.hi);
   nir_def *rest = nir_ffma(b, u.lo, reciprocal(b, u.hi), l.lo);
   rest = nir_fadd(b, rest, nir_bcsel(b, doubled, imm(b, LN2_HI), imm(b, 0.0f)));
   return nir_fadd(b, l.hi, rest);
}

/* 1 + t as a pair, for a nonnegative finite t. */
static struct pair
one_plus(nir_builder *b, nir_def *t)
{
   nir_def *one = imm(b, 1.0f), *large = nir_flt(b, one, t);
   return quick_sum(b, nir_bcsel(b, large, t, one), nir_bcsel(b, large, one, t));
}

nir_def *
stela_air_precise_asinh(nir_builder *b, nir_def *x, nir_def *y)
{
   /* ln(|x| + sqrt(x^2 + 1)): below a half as 1 + t, t = |x| + x^2 / (1 +
    * sqrt(1 + x^2)), and from LARGE as ln(|x|) + ln(2). */
   nir_def *magnitude = nir_fabs(b, x);
   nir_def *large = nir_fge_imm(b, magnitude, LARGE);
   nir_def *bounded = nir_fmin(b, magnitude, imm(b, LARGE));
   nir_def *z = nir_fmul(b, bounded, bounded);
   nir_def *hypotenuse = root(b, nir_fadd_imm(b, z, 1.0f));
   struct pair near = one_plus(b, nir_fadd(b, bounded, quotient(b, z, nir_fadd_imm(b, hypotenuse, 1.0f))));
   nir_def *small = nir_flt_imm(b, magnitude, 0.5f);
   nir_def *far = nir_bcsel(b, large, nir_fmin(b, magnitude, imm(b, FLT_MAX)), nir_fadd(b, bounded, hypotenuse));
   struct pair u = {nir_bcsel(b, small, near.hi, far), nir_bcsel(b, small, near.lo, imm(b, 0.0f))};
   nir_def *value = negate_if(b, sign_bit(b, x), logarithm_of_pair(b, u, large));
   value = nir_bcsel(b, nir_flt_imm(b, magnitude, TINY), x, value);
   return unless_nan(b, x, nir_bcsel(b, infinite(b, x), x, value));
}

nir_def *
stela_air_precise_acosh(nir_builder *b, nir_def *x, nir_def *y)
{
   /* ln(x + sqrt(x^2 - 1)): below two as 1 + t, t = d + sqrt(d * (d + 2)),
    * d = x - 1, and from LARGE as ln(x) + ln(2). */
   nir_def *large = nir_fge_imm(b, x, LARGE);
   nir_def *bounded = nir_fmin(b, nir_fmax(b, x, imm(b, 1.0f)), imm(b, LARGE));
   nir_def *d = nir_fadd_imm(b, bounded, -1.0f);
   struct pair near = one_plus(b, nir_fadd(b, d, root_or_zero(b, nir_fmul(b, d, nir_fadd_imm(b, d, 2.0f)))));
   nir_def *middle = nir_fadd(b, bounded, root(b, nir_ffma(b, bounded, bounded, imm(b, -1.0f))));
   nir_def *small = nir_flt_imm(b, x, 2.0f);
   nir_def *far = nir_bcsel(b, large, nir_fmin(b, x, imm(b, FLT_MAX)), middle);
   struct pair u = {nir_bcsel(b, small, near.hi, far), nir_bcsel(b, small, near.lo, imm(b, 0.0f))};
   nir_def *value = logarithm_of_pair(b, u, large);
   value = nir_bcsel(b, nir_flt_imm(b, x, 1.0), not_a_number(b), value);
   return unless_nan(b, x, nir_bcsel(b, nir_feq(b, x, imm(b, INFINITY)), x, value));
}

nir_def *
stela_air_precise_atanh(nir_builder *b, nir_def *x, nir_def *y)
{
   /* ln((1 + x) / (1 - x)) / 2 = ln(1 + 2x / (1 - x)) / 2. */
   nir_def *magnitude = nir_fabs(b, x);
   nir_def *rest = nir_fmax(b, nir_fsub(b, imm(b, 1.0f), magnitude), imm(b, 0x1p-24f));
   nir_def *t = quotient(b, nir_fmul_imm(b, magnitude, 2.0f), rest);
   nir_def *value = nir_fmul_imm(b, logarithm_of_pair(b, one_plus(b, t), nir_imm_false(b)), 0.5f);
   value = nir_bcsel(b, nir_feq_imm(b, magnitude, 1.0), imm(b, INFINITY), value);
   value = nir_bcsel(b, nir_flt_imm(b, magnitude, TINY), magnitude, value);
   value = negate_if(b, sign_bit(b, x), value);
   return unless_nan(b, x, nir_bcsel(b, nir_fgt_imm(b, magnitude, 1.0), not_a_number(b), value));
}

nir_def *
stela_air_precise_sqrt(nir_builder *b, nir_def *x, nir_def *y)
{
   return nir_bcsel(b, positive_finite(b, x), root(b, x),
                    nir_bcsel(b, nir_flt_imm(b, x, 0.0), not_a_number(b), x));
}

nir_def *
stela_air_precise_rsqrt(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *edge = nir_bcsel(b, nir_feq_imm(b, x, 0.0),
                             negate_if(b, sign_bit(b, x), imm(b, INFINITY)),
                             nir_bcsel(b, nir_flt_imm(b, x, 0.0), not_a_number(b),
                                       nir_bcsel(b, infinite(b, x), imm(b, 0.0f), x)));
   return nir_bcsel(b, positive_finite(b, x), inverse_root(b, x), edge);
}

nir_def *
stela_air_precise_divide(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *n = nir_fabs(b, x), *d = nir_fabs(b, y);
   nir_def *value = negate_if(b, nir_ine(b, sign_bit(b, x), sign_bit(b, y)), quotient(b, n, d));
   nir_def *ordinary = nir_iand(b, positive_finite(b, n), positive_finite(b, d));
   /* Zeros, infinities and NaNs have exact quotients. */
   return nir_bcsel(b, ordinary, value, nir_fdiv(b, x, y));
}

/* A positive float's exponent and significand in [1, 2). */
static nir_def *
unit_significand(nir_builder *b, nir_def *x, nir_def **e)
{
   nir_def *subnormal = nir_flt_imm(b, x, 0x1p-126f);
   x = nir_bcsel(b, subnormal, nir_fmul_imm(b, x, 0x1p24f), x);
   *e = nir_iadd(b, nir_iadd_imm(b, nir_ushr_imm(b, x, 23), -127),
                 nir_bcsel(b, subnormal, nir_imm_int(b, -24), nir_imm_int(b, 0)));
   return nir_ior_imm(b, nir_iand_imm(b, x, 0x7fffff), 0x3f800000);
}

/* rest less a whole multiple q of w = |y| * 2^k, k leaving q under 2^20.
 * q's estimate is never below the true quotient and less than one above,
 * so the remainder lies within (-w, w), on w's grid, and FMA forms it
 * exactly; one w more makes it nonnegative. */
static nir_def *
remainder_step(nir_builder *b, nir_def *rest, nir_def *divisor, nir_def *md, nir_def *inverse,
               nir_def *ed)
{
   nir_def *er;
   nir_def *m = unit_significand(b, rest, &er);
   nir_def *difference = nir_isub(b, er, ed);
   nir_def *k = nir_imax(b, nir_iadd_imm(b, difference, -19), nir_imm_int(b, 0));
   nir_def *reach = nir_imax(b, nir_isub(b, difference, k), nir_imm_int(b, -30));
   nir_def *estimate = nir_fmul(b, nir_fmul(b, m, inverse), power(b, reach));
   nir_def *q = nir_ftrunc(b, nir_fmul_imm(b, estimate, 1.0f + 0x1p-21f));
   /* w from y's significand where it is normal, else the subnormal y times
    * 2^k, k then under 23. */
   nir_def *we = nir_iadd(b, ed, k);
   nir_def *w = nir_bcsel(b, nir_ige_imm(b, we, -126), nir_fmul(b, md, power(b, nir_imax(b, we, nir_imm_int(b, -126)))),
                          nir_fmul(b, divisor, power(b, nir_imin(b, k, nir_imm_int(b, 23)))));
   nir_def *less = nir_ffma(b, nir_fneg(b, q), w, rest);
   less = nir_bcsel(b, nir_flt_imm(b, less, 0.0f), nir_fadd(b, less, w), less);
   return nir_bcsel(b, nir_fge(b, rest, divisor), less, rest);
}

/* x modulo y, exactly, a step at a time: a float's exponents need 15. The
 * steps stay straight-line code, as functions translate into unstructured
 * control flow. */
nir_def *
stela_air_precise_fmod(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *divisor = nir_fabs(b, y), *ed;
   nir_def *md = unit_significand(b, divisor, &ed), *inverse = reciprocal(b, md);
   nir_def *rest = nir_fabs(b, x);
   for (unsigned step = 0; step < 15; step++)
      rest = remainder_step(b, rest, divisor, md, inverse, ed);
   nir_def *value = negate_if(b, sign_bit(b, x), rest);
   nir_def *undefined = nir_ior(b, infinite(b, x), nir_ior(b, nir_feq_imm(b, y, 0.0), nir_fneu(b, y, y)));
   value = nir_bcsel(b, nir_fneu(b, x, x), x, nir_bcsel(b, undefined, not_a_number(b), value));
   return nir_bcsel(b, nir_iand(b, infinite(b, y), nir_inot(b, infinite(b, x))), x, value);
}

/* Sine and cosine of a half angle held in a float: below NEAR_ANGLE, the
 * reduction's three parts of pi / 2 leave r within a float's precision, and
 * the hardware's sine and cosine of |r| <= pi / 4 are within about 2^-21.
 * Below 2^-5, r - r^3 / 6 is a half's sine. */
static void
half_trigonometric(nir_builder *b, nir_def *r, nir_def *quadrant, nir_def **sine, nir_def **cosine)
{
   nir_def *small = nir_flt_imm(b, nir_fabs(b, r), 0x1p-5f);
   nir_def *s = nir_bcsel(b, small, nir_ffma(b, nir_fmul(b, r, nir_fmul(b, r, r)), imm(b, -1.0f / 6), r),
                          nir_fsin(b, r));
   nir_def *c = nir_fcos(b, r);
   nir_def *swap = nir_i2b(b, nir_iand_imm(b, quadrant, 1));
   *sine = negate_if(b, nir_i2b(b, nir_iand_imm(b, quadrant, 2)), nir_bcsel(b, swap, c, s));
   *cosine = negate_if(b, nir_i2b(b, nir_iand_imm(b, nir_iadd_imm(b, quadrant, 1), 2)),
                       nir_bcsel(b, swap, s, c));
}

/* A half angle held in a float as r + quadrant * pi / 2, |r| <= pi / 4. */
static void
reduce_half(nir_builder *b, nir_def *x, nir_def **r, nir_def **quadrant)
{
   nir_def *turn = nir_fround_even(b, nir_fmul_imm(b, x, (float)M_2_PI));
   nir_def *near = nir_ffma(b, nir_fneg(b, turn), imm(b, PI_2_PART1), x);
   near = nir_ffma(b, nir_fneg(b, turn), imm(b, PI_2_PART2), near);
   *r = nir_ffma(b, nir_fneg(b, turn), imm(b, PI_2_PART3), near);
   *quadrant = nir_f2i32(b, nir_fmax(b, nir_fmin(b, turn, imm(b, NEAR_ANGLE)), imm(b, -NEAR_ANGLE)));
}

/* sine / cosine in single precision, within an ulp of a half, infinite with
 * sine's sign where cosine is exactly zero. */
static nir_def *
half_tangent(nir_builder *b, nir_def *r, nir_def *quadrant)
{
   nir_def *sine, *cosine;
   half_trigonometric(b, r, quadrant, &sine, &cosine);
   return nir_bcsel(b, nir_feq_imm(b, cosine, 0.0f), nir_fmul_imm(b, sine, INFINITY),
                    nir_fmul(b, sine, nir_frcp(b, cosine)));
}

nir_def *
stela_air_half_sin(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce_half(b, x, &r, &quadrant);
   half_trigonometric(b, r, quadrant, &sine, &cosine);
   return odd_or_zero(b, x, sine);
}

nir_def *
stela_air_half_cos(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce_half(b, x, &r, &quadrant);
   half_trigonometric(b, r, quadrant, &sine, &cosine);
   return finite_or_nan(b, x, cosine);
}

nir_def *
stela_air_half_tan(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant;
   reduce_half(b, x, &r, &quadrant);
   return odd_or_zero(b, x, half_tangent(b, r, quadrant));
}

nir_def *
stela_air_half_sinpi(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce_turns(b, x, &r, &quadrant);
   half_trigonometric(b, r, quadrant, &sine, &cosine);
   return odd_or_zero(b, x, sine);
}

nir_def *
stela_air_half_cospi(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant, *sine, *cosine;
   reduce_turns(b, x, &r, &quadrant);
   half_trigonometric(b, r, quadrant, &sine, &cosine);
   return finite_or_nan(b, x, cosine);
}

nir_def *
stela_air_half_tanpi(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *r, *quadrant;
   reduce_turns(b, x, &r, &quadrant);
   return odd_or_zero(b, x, half_tangent(b, r, quadrant));
}

/* x / y for halves held in floats: the hardware's reciprocal, within
 * 2^-22 of the quotient, which rounds to the nearest half but where the
 * quotient lies that close to a halfway point. */
nir_def *
stela_air_half_divide(nir_builder *b, nir_def *x, nir_def *y)
{
   return nir_fmul(b, x, nir_frcp(b, y));
}

/* x modulo y for halves held in floats, exactly. As for floats, whole
 * multiples of y scaled by 2^(12 * i) come off from the largest of the 4
 * steps a half's exponents can need: each quotient has at most 13 bits and
 * y 11, and each remainder at most one bit more than the value it came
 * from, so every product and difference is exact in single precision. */
nir_def *
stela_air_half_fmod(nir_builder *b, nir_def *x, nir_def *y)
{
   nir_def *divisor = nir_fabs(b, y), *inverse = nir_frcp(b, divisor);
   nir_def *rest = nir_fabs(b, x);
   for (int step = 3; step >= 0; step--) {
      float factor = ldexpf(1.0f, 12 * step);
      nir_def *w = nir_fmul_imm(b, divisor, factor);
      nir_def *q = nir_i2f32(b, nir_f2i32(b, nir_fmul_imm(b, nir_fmul(b, rest, inverse), 1.0 / factor)));
      nir_def *less = nir_ffma(b, nir_fneg(b, q), w, rest);
      less = nir_bcsel(b, nir_flt_imm(b, less, 0.0), nir_fadd(b, less, w), less);
      less = nir_bcsel(b, nir_fge(b, less, w), nir_fsub(b, less, w), less);
      rest = nir_bcsel(b, nir_fge(b, rest, w), less, rest);
   }
   nir_def *value = negate_if(b, sign_bit(b, x), rest);
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

/* x - y's lanes, or x's, scaled by 2^k so the largest lies in [1, 2) and
 * neither the squares nor their sum overflow or underflow; k back. */
static nir_def *
scaled_lanes(nir_builder *b, nir_def *x, nir_def *y, nir_def **lanes, nir_def **k)
{
   nir_def *largest = imm(b, 0.0f);
   for (unsigned i = 0; i < x->num_components; i++) {
      lanes[i] = nir_channel(b, x, i);
      if (y)
         lanes[i] = nir_fsub(b, lanes[i], nir_channel(b, y, i));
      largest = nir_fmax(b, largest, nir_fabs(b, lanes[i]));
   }
   nir_def *e = nir_iadd_imm(b, nir_ushr_imm(b, largest, 23), -127);
   *k = nir_imin(b, nir_imax(b, nir_ineg(b, e), nir_imm_int(b, -126)), nir_imm_int(b, 126));
   nir_def *sum = imm(b, 0.0f);
   for (unsigned i = 0; i < x->num_components; i++) {
      lanes[i] = nir_fmul(b, lanes[i], power(b, *k));
      sum = nir_ffma(b, lanes[i], lanes[i], sum);
   }
   return sum;
}

nir_def *
stela_air_precise_length(nir_builder *b, nir_def *x, nir_def *y)
{
   uint32_t control = b->fp_math_ctrl;
   b->fp_math_ctrl = nir_fp_no_fast_math;
   nir_def *lanes[NIR_MAX_VEC_COMPONENTS], *k;
   nir_def *sum = scaled_lanes(b, x, y, lanes, &k);
   nir_def *value = nir_fmul(b, root(b, sum), power(b, nir_ineg(b, k)));
   value = nir_bcsel(b, nir_feq_imm(b, sum, 0.0f), sum, value);
   value = nir_bcsel(b, nir_ior(b, infinite(b, sum), nir_fneu(b, sum, sum)), sum, value);
   b->fp_math_ctrl = control;
   return value;
}

nir_def *
stela_air_precise_normalize(nir_builder *b, nir_def *x)
{
   uint32_t control = b->fp_math_ctrl;
   b->fp_math_ctrl = nir_fp_no_fast_math;
   nir_def *lanes[NIR_MAX_VEC_COMPONENTS], *k;
   nir_def *sum = scaled_lanes(b, x, NULL, lanes, &k);
   nir_def *inverse = inverse_root(b, sum);
   nir_def *usable = positive_finite(b, sum);
   for (unsigned i = 0; i < x->num_components; i++)
      lanes[i] = nir_bcsel(b, usable, nir_fmul(b, lanes[i], inverse), not_a_number(b));
   b->fp_math_ctrl = control;
   return nir_vec(b, lanes, x->num_components);
}
