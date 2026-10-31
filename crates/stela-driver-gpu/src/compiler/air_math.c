/* SPDX-License-Identifier: MIT */
/* AIR's math, integer, relational, conversion, packing, derivative and
 * discard functions, and LLVM's math intrinsics. AIR names a function after
 * its MSL builtin and its overload, as Apple's compiler emits them:
 *
 *   air.[fast_]<function>.<type>   floating-point functions
 *   air.<function>.<s|u>.<type>    signed or unsigned integer functions
 *   air.<function>.<type>          sign-agnostic integer and bool functions
 *   air.convert.<to>.<from>        conversions; each type is prefixed "f.",
 *                                  "s." or "u."
 *   air.[un]pack.<format>.<type>   packing, <type> naming the float vector
 *
 * A type is "f32", "f16" or "iN", prefixed "vN" for vectors. Apple's compiler
 * leaves frexp and ilogb to its function library, named in that library's
 * spelling: ___metal_frexp_v2half_pthreadv2int32, ___metal_ilogb_float. This
 * file rebuilds each name, LLVM's intrinsics' included, from the call's own
 * types, so a call whose name and types disagree is refused rather than
 * guessed.
 *
 * NIR computes approximate functions at the accuracy Vulkan requires, which
 * matches Metal's fast variants, not its precise ones. AIR's "fast_" variants
 * and LLVM intrinsics that allow approximation (afn) lower to NIR's; the
 * others to air_precise.c. Half-precision approximate functions evaluate in
 * single precision. */
#include "air_math.h"
#include "air_precise.h"
#include "compiler/nir/nir_builtin_builder.h"
#include "compiler/nir/nir_format_convert.h"
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

enum operation {
   /* Floating-point functions of their operands' type. */
   SATURATE, LOG2, EXP2, SQRT, RSQRT, FRACT, RINT, FLOOR, CEIL, TRUNC, ROUND, COS, SIN, TAN,
   FABS, ACOS, ASIN, ATAN, COSH, SINH, TANH, ACOSH, ASINH, ATANH, EXP, EXP10, LOG, LOG10,
   COSPI, SINPI, TANPI, FMAX, FMIN, POW, POWR, ATAN2, FMOD, COPYSIGN, FDIM, FMA, FCLAMP, MIX,
   FMAX3, FMIN3, FMEDIAN3, NORMALIZE, CROSS, DFDX, DFDY, FWIDTH, SIGN, NEXTAFTER,
   /* ldexp takes an i32 exponent per lane; ilogb returns one. */
   LDEXP, ILOGB,
   /* Functions storing a second result through a thread pointer: sincos its
    * cosine, frexp its i32 exponents. */
   SINCOS, FREXP,
   /* Floating-point reductions to the element type. */
   DOT, LENGTH, DISTANCE,
   /* Integer functions. */
   POPCOUNT, REVERSE_BITS, CLZ, CTZ, IABS, IMAX, IMIN, MUL_HI, ADD_SAT, SUB_SAT, ICLAMP,
   ABS_DIFF, HADD, RHADD, MAD_HI, MAD_SAT, IMAX3, IMIN3, IMEDIAN3, MUL24, MAD24, ROTATE,
   /* Bit fields at i32 offsets and widths. */
   EXTRACT_BITS, INSERT_BITS,
};

enum signature {
   SIGN_NONE, /* No sign in the name. */
   SIGNED,
   UNSIGNED,
};

struct function {
   const char *name;
   enum operation operation;
   unsigned operands;
};

/* Floating-point functions, which also take a "fast_" prefix. */
static const struct function floating[] = {
   {"saturate", SATURATE, 1}, {"log2", LOG2, 1}, {"exp2", EXP2, 1}, {"sqrt", SQRT, 1},
   {"rsqrt", RSQRT, 1}, {"fract", FRACT, 1}, {"rint", RINT, 1}, {"floor", FLOOR, 1},
   {"ceil", CEIL, 1}, {"trunc", TRUNC, 1}, {"round", ROUND, 1}, {"cos", COS, 1},
   {"sin", SIN, 1}, {"tan", TAN, 1}, {"fabs", FABS, 1}, {"acos", ACOS, 1}, {"asin", ASIN, 1},
   {"atan", ATAN, 1}, {"cosh", COSH, 1}, {"sinh", SINH, 1}, {"tanh", TANH, 1},
   {"acosh", ACOSH, 1}, {"asinh", ASINH, 1}, {"atanh", ATANH, 1}, {"exp", EXP, 1},
   {"exp10", EXP10, 1}, {"log", LOG, 1}, {"log10", LOG10, 1}, {"cospi", COSPI, 1},
   {"sinpi", SINPI, 1}, {"tanpi", TANPI, 1}, {"fmax", FMAX, 2}, {"fmin", FMIN, 2},
   {"pow", POW, 2}, {"powr", POWR, 2}, {"atan2", ATAN2, 2}, {"fmod", FMOD, 2},
   {"copysign", COPYSIGN, 2}, {"fdim", FDIM, 2}, {"fma", FMA, 3}, {"clamp", FCLAMP, 3},
   {"mix", MIX, 3}, {"fmax3", FMAX3, 3}, {"fmin3", FMIN3, 3}, {"fmedian3", FMEDIAN3, 3},
   {"normalize", NORMALIZE, 1}, {"cross", CROSS, 2}, {"dot", DOT, 2}, {"length", LENGTH, 1},
   {"distance", DISTANCE, 2}, {"sign", SIGN, 1}, {"nextafter", NEXTAFTER, 2},
   {"ldexp", LDEXP, 2}, {"sincos", SINCOS, 2},
};

/* Derivatives, which have no fast variant. */
static const struct function derivatives[] = {
   {"dfdx", DFDX, 1}, {"dfdy", DFDY, 1}, {"fwidth", FWIDTH, 1},
};

/* Integer functions named with their operands' sign. */
static const struct function signed_integer[] = {
   {"abs", IABS, 1}, {"max", IMAX, 2}, {"min", IMIN, 2}, {"mul_hi", MUL_HI, 2},
   {"add_sat", ADD_SAT, 2}, {"sub_sat", SUB_SAT, 2}, {"clamp", ICLAMP, 3},
   {"abs_diff", ABS_DIFF, 2}, {"hadd", HADD, 2}, {"rhadd", RHADD, 2}, {"mad_hi", MAD_HI, 3},
   {"mad_sat", MAD_SAT, 3}, {"max3", IMAX3, 3}, {"min3", IMIN3, 3}, {"median3", IMEDIAN3, 3},
   {"mul24", MUL24, 2}, {"mad24", MAD24, 3}, {"extract_bits", EXTRACT_BITS, 3},
   {"insert_bits", INSERT_BITS, 4},
};

/* Integer functions named without a sign. clz and ctz also take an i1. */
static const struct function unsigned_integer[] = {
   {"popcount", POPCOUNT, 1}, {"reverse_bits", REVERSE_BITS, 1}, {"clz", CLZ, 2},
   {"ctz", CTZ, 2}, {"rotate", ROTATE, 2},
};

/* The formats air.pack and air.unpack convert, named as Metal names pixel
 * formats: the first component in the least significant bits. */
static const struct format {
   const char *name;
   unsigned components, bits[4];
   bool snorm, srgb;
} formats[] = {
   {"unorm4x8", 4, {8, 8, 8, 8}}, {"snorm4x8", 4, {8, 8, 8, 8}, .snorm = true},
   {"unorm2x16", 2, {16, 16}}, {"snorm2x16", 2, {16, 16}, .snorm = true},
   {"unorm4x8.srgb", 4, {8, 8, 8, 8}, .srgb = true}, {"unorm.rgb10a2", 4, {10, 10, 10, 2}},
   {"unorm.rgb565", 3, {5, 6, 5}},
};

/* LLVM's intrinsics with these semantics. */
static const struct {
   const char *name;
   enum operation operation;
   enum signature sign;
   unsigned operands;
} intrinsics[] = {
   {"llvm.fabs", FABS, SIGN_NONE, 1}, {"llvm.sqrt", SQRT, SIGN_NONE, 1},
   {"llvm.floor", FLOOR, SIGN_NONE, 1}, {"llvm.ceil", CEIL, SIGN_NONE, 1},
   {"llvm.trunc", TRUNC, SIGN_NONE, 1}, {"llvm.rint", RINT, SIGN_NONE, 1},
   {"llvm.nearbyint", RINT, SIGN_NONE, 1}, {"llvm.roundeven", RINT, SIGN_NONE, 1},
   {"llvm.round", ROUND, SIGN_NONE, 1}, {"llvm.sin", SIN, SIGN_NONE, 1},
   {"llvm.cos", COS, SIGN_NONE, 1}, {"llvm.exp", EXP, SIGN_NONE, 1},
   {"llvm.exp2", EXP2, SIGN_NONE, 1}, {"llvm.log", LOG, SIGN_NONE, 1},
   {"llvm.log2", LOG2, SIGN_NONE, 1}, {"llvm.log10", LOG10, SIGN_NONE, 1},
   {"llvm.pow", POW, SIGN_NONE, 2}, {"llvm.fma", FMA, SIGN_NONE, 3},
   {"llvm.fmuladd", FMA, SIGN_NONE, 3}, {"llvm.minnum", FMIN, SIGN_NONE, 2},
   {"llvm.maxnum", FMAX, SIGN_NONE, 2}, {"llvm.copysign", COPYSIGN, SIGN_NONE, 2},
   /* llvm.abs's i1 says whether INT_MIN is poison; either way abs wraps. */
   {"llvm.abs", IABS, SIGNED, 2}, {"llvm.sadd.sat", ADD_SAT, SIGNED, 2},
   {"llvm.uadd.sat", ADD_SAT, UNSIGNED, 2}, {"llvm.ssub.sat", SUB_SAT, SIGNED, 2},
   {"llvm.usub.sat", SUB_SAT, UNSIGNED, 2},
};

static nir_def *
imm(nir_builder *b, double value, unsigned bits)
{
   return nir_imm_floatN_t(b, value, bits);
}

/* Operations NIR approximates, which half operands evaluate in single
 * precision. */
static bool
approximate(enum operation operation)
{
   switch (operation) {
   case LOG2: case EXP2: case SQRT: case RSQRT: case COS: case SIN: case TAN: case ACOS:
   case ASIN: case ATAN: case COSH: case SINH: case TANH: case ACOSH: case ASINH: case ATANH:
   case EXP: case EXP10: case LOG: case LOG10: case COSPI: case SINPI: case TANPI: case POW:
   case POWR: case ATAN2: case FMOD: case NORMALIZE: case LENGTH: case DISTANCE: case SINCOS:
      return true;
   default:
      return false;
   }
}

static nir_def *
length(nir_builder *b, nir_def *x)
{
   return nir_fsqrt(b, nir_fdot(b, x, x));
}

/* x's i32 binary exponents as frexp gives them, with its significands in
 * [0.5, 1) in `significand`. Zero, infinities and NaN keep their value with
 * exponent 0, as C's libraries give them. */
static nir_def *
exponent(nir_builder *b, nir_def *x, nir_def **significand)
{
   unsigned bits = x->bit_size, mantissa = bits == 16 ? 10 : 23;
   /* NIR's frexp reads the exponent field, so subnormals first scale exactly
    * into the normal range. */
   nir_def *subnormal = nir_iand(b, nir_fneu_imm(b, x, 0.0),
                                 nir_flt_imm(b, nir_fabs(b, x), bits == 16 ? 0x1p-14 : 0x1p-126));
   nir_def *scaled = nir_bcsel(b, subnormal, nir_fmul_imm(b, x, ldexp(1.0, (int)mantissa)), x);
   *significand = nir_frexp_sig(b, scaled);
   nir_def *e = nir_isub(b, nir_frexp_exp(b, scaled),
                         nir_bcsel(b, subnormal, nir_imm_int(b, (int)mantissa), nir_imm_int(b, 0)));
   return nir_bcsel(b, nir_fisfinite(b, x), e, nir_imm_int(b, 0));
}

/* The value after x toward y, stepping x's bits; zero steps to the least
 * subnormal of y's sign. */
static nir_def *
next_after(nir_builder *b, nir_def *x, nir_def *y)
{
   unsigned bits = x->bit_size;
   nir_def *toward_zero = nir_ieq(b, nir_flt(b, x, y), nir_flt_imm(b, x, 0.0));
   nir_def *stepped = nir_bcsel(b, toward_zero, nir_iadd_imm(b, x, -1), nir_iadd_imm(b, x, 1));
   nir_def *least = nir_ior_imm(b, nir_iand_imm(b, y, 1ull << (bits - 1)), 1);
   nir_def *next = nir_bcsel(b, nir_feq(b, x, y), y,
                             nir_bcsel(b, nir_feq_imm(b, x, 0.0), least, stepped));
   return nir_bcsel(b, nir_ior(b, nir_fisnan(b, x), nir_fisnan(b, y)), nir_fadd(b, x, y), next);
}

/* `operation`'s value; `second` receives a second result's. */
static nir_def *
floating_value(nir_builder *b, enum operation operation, nir_def **s, nir_def **second)
{
   nir_def *x = s[0];
   unsigned bits = x->bit_size;
   switch (operation) {
   case SATURATE: return nir_fsat(b, x);
   case LOG2: return nir_flog2(b, x);
   case EXP2: return nir_fexp2(b, x);
   case SQRT: return nir_fsqrt(b, x);
   case RSQRT: return nir_frsq(b, x);
   /* Metal's fract stays below 1. */
   case FRACT: return nir_fmin(b, nir_ffract(b, x), imm(b, bits == 16 ? 0x1.ffcp-1 : 0x1.fffffep-1, bits));
   case RINT: return nir_fround_even(b, x);
   case FLOOR: return nir_ffloor(b, x);
   case CEIL: return nir_fceil(b, x);
   case TRUNC: return nir_ftrunc(b, x);
   case ROUND: {
      /* Halfway cases round away from zero. */
      nir_def *whole = nir_ftrunc(b, x);
      nir_def *away = nir_fge(b, nir_fabs(b, nir_fsub(b, x, whole)), imm(b, 0.5, bits));
      return nir_fadd(b, whole, nir_bcsel(b, away, nir_copysign(b, imm(b, 1.0, bits), x),
                                          imm(b, 0.0, bits)));
   }
   case COS: return nir_fcos(b, x);
   case SIN: return nir_fsin(b, x);
   case TAN: return nir_ftan(b, x);
   case FABS: return nir_fabs(b, x);
   case ACOS: return nir_acos(b, x);
   case ASIN: return nir_asin(b, x);
   case ATAN: return nir_atan(b, x);
   case COSH:
   case SINH: {
      nir_def *up = nir_fexp(b, x), *down = nir_fexp(b, nir_fneg(b, x));
      nir_def *sum = operation == COSH ? nir_fadd(b, up, down) : nir_fsub(b, up, down);
      return nir_fmul_imm(b, sum, 0.5);
   }
   case TANH: {
      /* tanh is +-1 to single precision beyond |x| = 10. */
      nir_def *e = nir_fexp(b, nir_fmul_imm(b, nir_fclamp(b, x, imm(b, -10.0, bits), imm(b, 10.0, bits)), 2.0));
      return nir_fdiv(b, nir_fadd_imm(b, e, -1.0), nir_fadd_imm(b, e, 1.0));
   }
   case ACOSH:
      return nir_flog(b, nir_fadd(b, x, nir_fsqrt(b, nir_fadd_imm(b, nir_fmul(b, x, x), -1.0))));
   case ASINH: {
      nir_def *magnitude = nir_fabs(b, x);
      nir_def *value = nir_flog(b, nir_fadd(b, magnitude,
                                            nir_fsqrt(b, nir_fadd_imm(b, nir_fmul(b, x, x), 1.0))));
      return nir_copysign(b, value, x);
   }
   case ATANH:
      return nir_fmul_imm(b, nir_flog(b, nir_fdiv(b, nir_fadd_imm(b, x, 1.0),
                                                  nir_fsub(b, imm(b, 1.0, bits), x))), 0.5);
   case EXP: return nir_fexp(b, x);
   case EXP10: return nir_fexp2(b, nir_fmul_imm(b, x, M_LN10 / M_LN2));
   case LOG: return nir_flog(b, x);
   case LOG10: return nir_fmul_imm(b, nir_flog2(b, x), M_LN2 / M_LN10);
   case COSPI: return nir_fcos(b, nir_fmul_imm(b, x, M_PI));
   case SINPI: return nir_fsin(b, nir_fmul_imm(b, x, M_PI));
   case TANPI: return nir_ftan(b, nir_fmul_imm(b, x, M_PI));
   case FMAX: return nir_fmax(b, x, s[1]);
   case FMIN: return nir_fmin(b, x, s[1]);
   case POW:
   case POWR: return nir_fpow(b, x, s[1]);
   case ATAN2: return nir_atan2(b, x, s[1]);
   /* C's fmod: the remainder takes the dividend's sign. */
   case FMOD: return nir_frem(b, x, s[1]);
   case COPYSIGN: return nir_copysign(b, x, s[1]);
   case FDIM: return nir_fdim(b, x, s[1]);
   case FMA: return nir_ffma(b, x, s[1], s[2]);
   case FCLAMP: return nir_fmin(b, nir_fmax(b, x, s[1]), s[2]);
   case MIX: return nir_flrp(b, x, s[1], s[2]);
   case FMAX3: return nir_fmax(b, nir_fmax(b, x, s[1]), s[2]);
   case FMIN3: return nir_fmin(b, nir_fmin(b, x, s[1]), s[2]);
   case FMEDIAN3:
      return nir_fmax(b, nir_fmin(b, x, s[1]), nir_fmin(b, nir_fmax(b, x, s[1]), s[2]));
   case NORMALIZE: return nir_fmul(b, x, nir_frsq(b, nir_fdot(b, x, x)));
   case CROSS: return nir_cross3(b, x, s[1]);
   case DFDX: return nir_ddx(b, x);
   case DFDY: return nir_ddy(b, x);
   case FWIDTH: return nir_fadd(b, nir_fabs(b, nir_ddx(b, x)), nir_fabs(b, nir_ddy(b, x)));
   /* Zeros keep their sign; NaN is 0. */
   case SIGN:
      return nir_bcsel(b, nir_fgt_imm(b, x, 0.0), imm(b, 1.0, bits),
                       nir_bcsel(b, nir_flt_imm(b, x, 0.0), imm(b, -1.0, bits),
                                 nir_bcsel(b, nir_fisnan(b, x), imm(b, 0.0, bits), x)));
   case NEXTAFTER: return next_after(b, x, s[1]);
   case LDEXP: return nir_ldexp(b, x, s[1]);
   /* Darwin's FP_ILOGB0 and FP_ILOGBNAN are INT_MIN. */
   case ILOGB: {
      nir_def *significand, *e = exponent(b, x, &significand);
      return nir_bcsel(b, nir_fisfinite(b, x),
                       nir_bcsel(b, nir_feq_imm(b, x, 0.0), nir_imm_int(b, INT_MIN), nir_iadd_imm(b, e, -1)),
                       nir_bcsel(b, nir_fisnan(b, x), nir_imm_int(b, INT_MIN), nir_imm_int(b, INT_MAX)));
   }
   case SINCOS:
      *second = nir_fcos(b, x);
      return nir_fsin(b, x);
   case FREXP: {
      nir_def *significand;
      *second = exponent(b, x, &significand);
      return significand;
   }
   case DOT: return nir_fdot(b, x, s[1]);
   case LENGTH: return length(b, x);
   case DISTANCE: return length(b, nir_fsub(b, x, s[1]));
   default: UNREACHABLE("floating-point operation");
   }
}

/* An approximate function at Metal's precise accuracy. */
static nir_def *
precise_value(nir_builder *b, enum operation operation, unsigned count, nir_def **s, nir_def **second)
{
   static stela_air_precise_function *const functions[] = {
      [LOG2] = stela_air_precise_log2, [EXP2] = stela_air_precise_exp2,
      [SQRT] = stela_air_precise_sqrt, [RSQRT] = stela_air_precise_rsqrt,
      [COS] = stela_air_precise_cos, [SIN] = stela_air_precise_sin,
      [TAN] = stela_air_precise_tan, [ACOS] = stela_air_precise_acos,
      [ASIN] = stela_air_precise_asin, [ATAN] = stela_air_precise_atan,
      [COSH] = stela_air_precise_cosh, [SINH] = stela_air_precise_sinh,
      [TANH] = stela_air_precise_tanh, [ACOSH] = stela_air_precise_acosh,
      [ASINH] = stela_air_precise_asinh, [ATANH] = stela_air_precise_atanh,
      [EXP] = stela_air_precise_exp, [EXP10] = stela_air_precise_exp10,
      [LOG] = stela_air_precise_log, [LOG10] = stela_air_precise_log10,
      [COSPI] = stela_air_precise_cospi, [SINPI] = stela_air_precise_sinpi,
      [TANPI] = stela_air_precise_tanpi, [POW] = stela_air_precise_pow,
      [POWR] = stela_air_precise_powr, [ATAN2] = stela_air_precise_atan2,
      [FMOD] = stela_air_precise_fmod,
   };
   switch (operation) {
   case NORMALIZE: return stela_air_precise_normalize(b, s[0]);
   case LENGTH: return stela_air_precise_length(b, s[0], NULL);
   case DISTANCE: return stela_air_precise_length(b, s[0], s[1]);
   case SINCOS:
      *second = stela_air_precise(b, stela_air_precise_cos, s[0], NULL);
      return stela_air_precise(b, stela_air_precise_sin, s[0], NULL);
   default:
      return stela_air_precise(b, functions[operation], s[0], count > 1 ? s[1] : NULL);
   }
}

/* x's bits counted from the least significant end of its lanes' width. */
static nir_def *
reverse_bits(nir_builder *b, nir_def *x)
{
   unsigned bits = x->bit_size;
   if (bits == 64) {
      nir_def *low = nir_bitfield_reverse(b, nir_unpack_64_2x32_split_x(b, x));
      nir_def *high = nir_bitfield_reverse(b, nir_unpack_64_2x32_split_y(b, x));
      return nir_pack_64_2x32_split(b, high, low);
   }
   nir_def *reversed = nir_bitfield_reverse(b, nir_u2u32(b, x));
   return nir_u2uN(b, nir_ushr_imm(b, reversed, 32 - bits), bits);
}

static nir_def *
leading_zeros(nir_builder *b, nir_def *x)
{
   unsigned bits = x->bit_size;
   if (bits == 64) {
      nir_def *low = nir_unpack_64_2x32_split_x(b, x), *high = nir_unpack_64_2x32_split_y(b, x);
      nir_def *count = nir_bcsel(b, nir_ieq_imm(b, high, 0), nir_iadd_imm(b, nir_uclz(b, low), 32),
                                 nir_uclz(b, high));
      return nir_u2u64(b, count);
   }
   nir_def *count = nir_iadd_imm(b, nir_uclz(b, nir_u2u32(b, x)), -(int)(32 - bits));
   return nir_u2uN(b, count, bits);
}

static nir_def *
trailing_zeros(nir_builder *b, nir_def *x)
{
   unsigned bits = x->bit_size;
   nir_def *count;
   if (bits == 64) {
      nir_def *low = nir_unpack_64_2x32_split_x(b, x), *high = nir_unpack_64_2x32_split_y(b, x);
      count = nir_bcsel(b, nir_ieq_imm(b, low, 0), nir_iadd_imm(b, nir_find_lsb(b, high), 32),
                        nir_find_lsb(b, low));
   } else {
      count = nir_find_lsb(b, nir_u2u32(b, x));
   }
   /* find_lsb is -1 for zero, which has `bits` trailing zeros. */
   count = nir_bcsel(b, nir_ieq_imm(b, nir_u2uN(b, x, bits), 0), nir_imm_int(b, (int)bits),
                     nir_u2u32(b, count));
   return nir_u2uN(b, count, bits);
}

static nir_def *
maximum(nir_builder *b, bool sign, nir_def *x, nir_def *y)
{
   return sign ? nir_imax(b, x, y) : nir_umax(b, x, y);
}

static nir_def *
minimum(nir_builder *b, bool sign, nir_def *x, nir_def *y)
{
   return sign ? nir_imin(b, x, y) : nir_umin(b, x, y);
}

static nir_def *
halve(nir_builder *b, bool sign, nir_def *x)
{
   return sign ? nir_ishr_imm(b, x, 1) : nir_ushr_imm(b, x, 1);
}

/* x * y + z, saturated to x's type. The product's high and low halves take
 * z with its carry and, when signed, its sign extension; the sum fits when
 * the high half only extends the low one. */
static nir_def *
mad_saturated(nir_builder *b, bool sign, nir_def *x, nir_def *y, nir_def *z)
{
   unsigned bits = x->bit_size;
   nir_def *low = nir_imul(b, x, y);
   nir_def *high = sign ? nir_imul_high(b, x, y) : nir_umul_high(b, x, y);
   nir_def *sum = nir_iadd(b, low, z);
   high = nir_iadd(b, high, nir_b2iN(b, nir_ult(b, sum, low), bits));
   if (sign)
      high = nir_iadd(b, high, nir_ishr_imm(b, z, bits - 1));
   nir_def *fits = sign ? nir_ieq(b, high, nir_ishr_imm(b, sum, bits - 1)) : nir_ieq_imm(b, high, 0);
   nir_def *limit = sign ? nir_bcsel(b, nir_ilt_imm(b, high, 0), nir_imm_intN_t(b, u_intN_min(bits), bits),
                                     nir_imm_intN_t(b, u_intN_max(bits), bits)) :
                           nir_imm_intN_t(b, -1, bits);
   return nir_bcsel(b, fits, sum, limit);
}

/* x's `count` bits from `offset`, sign-extended when signed; none when
 * count is 0. */
static nir_def *
extract_bits(nir_builder *b, bool sign, nir_def *x, nir_def *offset, nir_def *count)
{
   unsigned bits = x->bit_size;
   nir_def *top = nir_ishl(b, x, nir_isub(b, nir_isub_imm(b, bits, offset), count));
   nir_def *field = sign ? nir_ishr(b, top, nir_isub_imm(b, bits, count)) :
                           nir_ushr(b, top, nir_isub_imm(b, bits, count));
   return nir_bcsel(b, nir_ieq_imm(b, count, 0), nir_imm_intN_t(b, 0, bits), field);
}

/* base with its `count` bits from `offset` replaced by insert's lowest. */
static nir_def *
insert_bits(nir_builder *b, nir_def *base, nir_def *insert, nir_def *offset, nir_def *count)
{
   unsigned bits = base->bit_size;
   nir_def *ones = nir_ushr(b, nir_imm_intN_t(b, -1, bits), nir_isub_imm(b, bits, count));
   nir_def *mask = nir_bcsel(b, nir_ieq_imm(b, count, 0), nir_imm_intN_t(b, 0, bits),
                             nir_ishl(b, ones, offset));
   return nir_ior(b, nir_iand(b, base, nir_inot(b, mask)), nir_iand(b, nir_ishl(b, insert, offset), mask));
}

static nir_def *
integer_value(nir_builder *b, enum operation operation, bool sign, nir_def **s)
{
   nir_def *x = s[0];
   switch (operation) {
   case POPCOUNT: {
      nir_def *count = x->bit_size == 64 ? nir_bit_count(b, x) : nir_bit_count(b, nir_u2u32(b, x));
      return nir_u2uN(b, count, x->bit_size);
   }
   case REVERSE_BITS: return reverse_bits(b, x);
   case CLZ: return leading_zeros(b, x);
   case CTZ: return trailing_zeros(b, x);
   case IABS: return sign ? nir_iabs(b, x) : x;
   case IMAX: return maximum(b, sign, x, s[1]);
   case IMIN: return minimum(b, sign, x, s[1]);
   case MUL_HI: return sign ? nir_imul_high(b, x, s[1]) : nir_umul_high(b, x, s[1]);
   case ADD_SAT: return sign ? nir_iadd_sat(b, x, s[1]) : nir_uadd_sat(b, x, s[1]);
   case SUB_SAT: return sign ? nir_isub_sat(b, x, s[1]) : nir_usub_sat(b, x, s[1]);
   case ICLAMP: return minimum(b, sign, maximum(b, sign, x, s[1]), s[2]);
   /* The difference wraps into the unsigned result. */
   case ABS_DIFF: {
      nir_def *less = sign ? nir_ilt(b, x, s[1]) : nir_ult(b, x, s[1]);
      return nir_bcsel(b, less, nir_isub(b, s[1], x), nir_isub(b, x, s[1]));
   }
   /* Halved sums without the overflowing sum: (x + y) >> 1 and
    * (x + y + 1) >> 1. */
   case HADD: return nir_iadd(b, nir_iand(b, x, s[1]), halve(b, sign, nir_ixor(b, x, s[1])));
   case RHADD: return nir_isub(b, nir_ior(b, x, s[1]), halve(b, sign, nir_ixor(b, x, s[1])));
   case MAD_HI:
      return nir_iadd(b, sign ? nir_imul_high(b, x, s[1]) : nir_umul_high(b, x, s[1]), s[2]);
   case MAD_SAT: return mad_saturated(b, sign, x, s[1], s[2]);
   case IMAX3: return maximum(b, sign, maximum(b, sign, x, s[1]), s[2]);
   case IMIN3: return minimum(b, sign, minimum(b, sign, x, s[1]), s[2]);
   case IMEDIAN3:
      return maximum(b, sign, minimum(b, sign, x, s[1]),
                     minimum(b, sign, maximum(b, sign, x, s[1]), s[2]));
   /* Metal defines mul24 and mad24 only for 24-bit operands, which a full
    * multiply computes exactly. */
   case MUL24: return nir_imul(b, x, s[1]);
   case MAD24: return nir_iadd(b, nir_imul(b, x, s[1]), s[2]);
   /* NIR masks shift counts to the lane width, so a rotation by a multiple
    * of it shifts by zero both ways. */
   case ROTATE: {
      nir_def *count = nir_u2u32(b, s[1]);
      return nir_ior(b, nir_ishl(b, x, count), nir_ushr(b, x, nir_ineg(b, count)));
   }
   case EXTRACT_BITS: return extract_bits(b, sign, x, s[1], s[2]);
   case INSERT_BITS: return insert_bits(b, x, s[1], s[2], s[3]);
   default: UNREACHABLE("integer operation");
   }
}

/* `element` with `lanes` lanes. */
static LLVMTypeRef
lanes_of(LLVMTypeRef element, unsigned lanes)
{
   return lanes > 1 ? LLVMVectorType(element, lanes) : element;
}

/* The type of `operation`'s operand `i`, given its first operand's type:
 * that type, or an i32 scalar or per-lane, an i1 or a thread pointer. */
static LLVMTypeRef
operand_type(LLVMTypeRef type, enum operation operation, unsigned i)
{
   LLVMContextRef context = LLVMGetTypeContext(type);
   LLVMTypeRef i32 = LLVMInt32TypeInContext(context);
   unsigned lanes;
   stela_air_call_element(type, &lanes);
   switch (operation) {
   /* clz's, ctz's and llvm.abs's i1 say whether zero or INT_MIN is poison. */
   case CLZ: case CTZ: case IABS: return i ? LLVMInt1TypeInContext(context) : type;
   case LDEXP: return i ? lanes_of(i32, lanes) : type;
   case ILOGB: return i ? i32 : type;
   case SINCOS: case FREXP: return i ? LLVMPointerTypeInContext(context, 0) : type;
   case EXTRACT_BITS: return i >= 1 ? i32 : type;
   case INSERT_BITS: return i >= 2 ? i32 : type;
   default: return type;
   }
}

/* `operation`'s result type, given its first operand's type. */
static LLVMTypeRef
result_type(LLVMTypeRef type, enum operation operation)
{
   unsigned lanes;
   LLVMTypeRef element = stela_air_call_element(type, &lanes);
   switch (operation) {
   case DOT: case LENGTH: case DISTANCE: return lanes > 1 ? element : NULL;
   case ILOGB: return lanes_of(LLVMInt32TypeInContext(LLVMGetTypeContext(type)), lanes);
   case CROSS: return lanes == 3 ? type : NULL;
   case NORMALIZE: return lanes > 1 ? type : NULL;
   default: return type;
   }
}

/* The call's `count` operands' values, NULL for pointers, after checking
 * each is of the type `operation` gives it. */
static bool
operands(const struct stela_air_call_context *c, LLVMValueRef call, enum operation operation,
         unsigned count, nir_def **values)
{
   LLVMTypeRef type = LLVMTypeOf(LLVMGetOperand(call, 0));
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef operand = LLVMGetOperand(call, i);
      if (LLVMTypeOf(operand) != operand_type(type, operation, i))
         return stela_air_call_fail(c, STELA_AIR_TYPE, "math function operand types differ");
      values[i] = NULL;
      if (LLVMGetTypeKind(LLVMTypeOf(operand)) != LLVMPointerTypeKind &&
          !(values[i] = c->operand(c->translator, operand)))
         return false;
   }
   return true;
}

static enum stela_air_call_status
lower(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
      enum operation operation, enum signature sign, unsigned count, bool fast, nir_def **result)
{
   if (!stela_air_call_plain(c, call, callee, count))
      return STELA_AIR_CALL_FAILED;
   nir_builder *b = c->b;
   LLVMTypeRef type = LLVMTypeOf(call);
   LLVMTypeRef operand = LLVMTypeOf(LLVMGetOperand(call, 0));
   nir_def *s[4];
   if (operation >= POPCOUNT) {
      if (!stela_air_call_integer(type) || operand != type)
         return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported integer function types"), STELA_AIR_CALL_FAILED;
      if (!operands(c, call, operation, count, s))
         return STELA_AIR_CALL_FAILED;
      *result = integer_value(b, operation, sign == SIGNED, s);
      return STELA_AIR_CALL_LOWERED;
   }
   if (!stela_air_call_floating(operand) || type != result_type(operand, operation))
      return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported floating-point function types"), STELA_AIR_CALL_FAILED;
   if ((operation == DFDX || operation == DFDY || operation == FWIDTH) && !c->fragment)
      return stela_air_call_fail(c, STELA_AIR_INSTRUCTION, "derivatives exist only in fragment functions"),
             STELA_AIR_CALL_FAILED;
   if (!c->fp_environment(c->translator) || !operands(c, call, operation, count, s))
      return STELA_AIR_CALL_FAILED;
   nir_def *second = NULL;
   bool narrow = s[0]->bit_size == 16 && approximate(operation);
   if (narrow) {
      for (unsigned i = 0; i < count; i++)
         s[i] = s[i] ? nir_f2f32(b, s[i]) : NULL;
   }
   *result = approximate(operation) && !fast ? precise_value(b, operation, count, s, &second) :
                                               floating_value(b, operation, s, &second);
   if (narrow) {
      *result = nir_f2f16(b, *result);
      second = second ? nir_f2f16(b, second) : NULL;
   }
   if (second && !c->store(c->translator, LLVMGetOperand(call, count - 1), NULL, second))
      return STELA_AIR_CALL_FAILED;
   return STELA_AIR_CALL_LOWERED;
}

/* Whether a type is a bool or a vector of bools. */
static bool
boolean(LLVMTypeRef type)
{
   unsigned lanes;
   LLVMTypeRef element = stela_air_call_element(type, &lanes);
   return lanes <= 4 && LLVMGetTypeKind(element) == LLVMIntegerTypeKind &&
          LLVMGetIntTypeWidth(element) == 1;
}

/* "air.convert.<to>.<from>": each type is "f." with a float type, or "s."
 * or "u." with an integer type; a bool is "u.i1", true converting to one. */
static enum stela_air_call_status
convert(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
        const char *name, size_t bytes, nir_def **result)
{
   if (!stela_air_call_plain(c, call, callee, 1))
      return STELA_AIR_CALL_FAILED;
   LLVMTypeRef to = LLVMTypeOf(call), from = LLVMTypeOf(LLVMGetOperand(call, 0));
   unsigned to_lanes, from_lanes;
   stela_air_call_element(to, &to_lanes);
   stela_air_call_element(from, &from_lanes);
   bool to_float = stela_air_call_floating(to), from_float = stela_air_call_floating(from);
   bool to_bool = boolean(to), from_bool = boolean(from);
   if ((!to_float && !to_bool && !stela_air_call_integer(to)) ||
       (!from_float && !from_bool && !stela_air_call_integer(from)) || to_lanes != from_lanes)
      return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported conversion types"), STELA_AIR_CALL_FAILED;
   char to_name[16], from_name[16];
   stela_air_call_overload(to, to_name, sizeof(to_name));
   stela_air_call_overload(from, from_name, sizeof(from_name));
   const char *signs = "su";
   int to_sign = -1, from_sign = -1;
   for (unsigned t = 0; t < (to_float ? 1u : 2u) && to_sign < 0; t++) {
      for (unsigned f = 0; f < (from_float ? 1u : 2u); f++) {
         char expected[64];
         snprintf(expected, sizeof(expected), "air.convert.%c.%s.%c.%s", to_float ? 'f' : signs[t],
                  to_name, from_float ? 'f' : signs[f], from_name);
         if (stela_air_call_named(name, bytes, expected)) {
            to_sign = (int)t;
            from_sign = (int)f;
            break;
         }
      }
   }
   if (to_sign < 0)
      return stela_air_call_fail(c, STELA_AIR_INSTRUCTION, "conversion name disagrees with its types"),
             STELA_AIR_CALL_FAILED;
   if ((to_float || from_float) && !c->fp_environment(c->translator))
      return STELA_AIR_CALL_FAILED;
   nir_def *x = c->operand(c->translator, LLVMGetOperand(call, 0));
   if (!x)
      return STELA_AIR_CALL_FAILED;
   unsigned to_bits = to_float ? (LLVMGetTypeKind(stela_air_call_element(to, &to_lanes)) == LLVMHalfTypeKind ? 16 : 32) :
                      LLVMGetIntTypeWidth(stela_air_call_element(to, &to_lanes));
   nir_builder *b = c->b;
   if (from_bool)
      *result = to_bool ? x : to_float ? nir_b2fN(b, x, to_bits) : nir_b2iN(b, x, to_bits);
   else if (to_bool)
      *result = from_float ? nir_fneu_imm(b, x, 0.0) : nir_ine_imm(b, x, 0);
   else if (to_float && from_float)
      *result = to_bits == 16 ? nir_f2f16_rtne(b, x) : nir_f2fN(b, x, to_bits);
   else if (to_float)
      *result = from_sign == 0 ? nir_i2fN(b, x, to_bits) : nir_u2fN(b, x, to_bits);
   else if (from_float)
      *result = to_sign == 0 ? nir_f2iN(b, x, to_bits) : nir_f2uN(b, x, to_bits);
   else
      *result = from_sign == 0 ? nir_i2iN(b, x, to_bits) : nir_u2uN(b, x, to_bits);
   return STELA_AIR_CALL_LOWERED;
}

/* An AIR function from one table, named "air.[fast_]<name>[.<sign>].<type>". */
static const struct function *
air_function(const struct function *table, size_t size, const char *name, size_t bytes,
             const char *prefix, const char *sign, const char *type)
{
   for (size_t i = 0; i < size; i++) {
      char expected[96];
      snprintf(expected, sizeof(expected), "air.%s%s%s.%s", prefix, table[i].name, sign, type);
      if (stela_air_call_named(name, bytes, expected))
         return &table[i];
   }
   return NULL;
}

/* c with its color channels converted by `convert` and its alpha kept. */
static nir_def *
color(nir_builder *b, nir_def *c, nir_def *(*convert)(nir_builder *, nir_def *))
{
   nir_def *rgb = convert(b, nir_trim_vector(b, c, 3));
   return nir_vec4(b, nir_channel(b, rgb, 0), nir_channel(b, rgb, 1), nir_channel(b, rgb, 2),
                   nir_channel(b, c, 3));
}

/* "air.pack.<format>.<type>" and "air.unpack.<format>.<type>": a format's
 * normalized components to and from an integer of their bits, <type> naming
 * the float vector. NaN packs as zero. */
static enum stela_air_call_status
pack(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
     const char *name, size_t bytes, bool unpack, nir_def **result)
{
   if (LLVMGetNumArgOperands(call) != 1)
      return STELA_AIR_CALL_OTHER;
   LLVMTypeRef operand = LLVMTypeOf(LLVMGetOperand(call, 0));
   LLVMTypeRef packed = unpack ? operand : LLVMTypeOf(call);
   LLVMTypeRef vector = unpack ? LLVMTypeOf(call) : operand;
   if (!stela_air_call_floating(vector))
      return STELA_AIR_CALL_OTHER;
   char type[16];
   stela_air_call_overload(vector, type, sizeof(type));
   const struct format *format = NULL;
   for (unsigned i = 0; i < ARRAY_SIZE(formats) && !format; i++) {
      char expected[64];
      snprintf(expected, sizeof(expected), "air.%s.%s.%s", unpack ? "unpack" : "pack",
               formats[i].name, type);
      if (stela_air_call_named(name, bytes, expected))
         format = &formats[i];
   }
   if (!format)
      return STELA_AIR_CALL_OTHER;
   if (!stela_air_call_plain(c, call, callee, 1))
      return STELA_AIR_CALL_FAILED;
   unsigned lanes, width = 0;
   LLVMTypeRef element = stela_air_call_element(vector, &lanes);
   for (unsigned i = 0; i < format->components; i++)
      width += format->bits[i];
   if (lanes != format->components || LLVMGetTypeKind(packed) != LLVMIntegerTypeKind ||
       LLVMGetIntTypeWidth(packed) != width)
      return stela_air_call_fail(c, STELA_AIR_TYPE, "packing types disagree with their format"),
             STELA_AIR_CALL_FAILED;
   nir_def *x;
   if (!c->fp_environment(c->translator) || !(x = c->operand(c->translator, LLVMGetOperand(call, 0))))
      return STELA_AIR_CALL_FAILED;
   nir_builder *b = c->b;
   if (unpack) {
      nir_def *fields = format->snorm ?
         nir_format_unpack_sint(b, nir_u2u32(b, x), format->bits, format->components) :
         nir_format_unpack_uint(b, nir_u2u32(b, x), format->bits, format->components);
      nir_def *f = format->snorm ? nir_format_snorm_to_float(b, fields, format->bits) :
                                   nir_format_unorm_to_float(b, fields, format->bits);
      if (format->srgb)
         f = color(b, f, nir_format_srgb_to_linear);
      *result = nir_f2fN(b, f, LLVMGetTypeKind(element) == LLVMHalfTypeKind ? 16 : 32);
      return STELA_AIR_CALL_LOWERED;
   }
   x = nir_f2f32(b, x);
   x = nir_bcsel(b, nir_fisnan(b, x), nir_imm_float(b, 0.0f), x);
   if (format->srgb)
      x = color(b, x, nir_format_linear_to_srgb);
   nir_def *fields = format->snorm ? nir_format_float_to_snorm(b, x, format->bits) :
                                     nir_format_float_to_unorm(b, x, format->bits);
   *result = nir_u2uN(b, nir_format_pack_uint(b, fields, format->bits, format->components), width);
   return STELA_AIR_CALL_LOWERED;
}

/* "air.all.<type>" and "air.any.<type>": whether all or any lanes of a bool
 * vector are true. */
static enum stela_air_call_status
reduce_bools(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
             const char *name, size_t bytes, nir_def **result)
{
   LLVMTypeRef operand = LLVMTypeOf(LLVMGetOperand(call, 0));
   char type[16], all[32], any[32];
   stela_air_call_overload(operand, type, sizeof(type));
   snprintf(all, sizeof(all), "air.all.%s", type);
   snprintf(any, sizeof(any), "air.any.%s", type);
   bool every = stela_air_call_named(name, bytes, all);
   if (!every && !stela_air_call_named(name, bytes, any))
      return STELA_AIR_CALL_OTHER;
   if (!stela_air_call_plain(c, call, callee, 1))
      return STELA_AIR_CALL_FAILED;
   if (LLVMTypeOf(call) != LLVMInt1TypeInContext(LLVMGetTypeContext(operand)))
      return stela_air_call_fail(c, STELA_AIR_TYPE, "bool reductions return a bool"), STELA_AIR_CALL_FAILED;
   nir_def *x = c->operand(c->translator, LLVMGetOperand(call, 0));
   if (!x)
      return STELA_AIR_CALL_FAILED;
   *result = x->num_components == 1 ? x : every ? nir_ball(c->b, x) : nir_bany(c->b, x);
   return STELA_AIR_CALL_LOWERED;
}

/* A type as Apple's function library spells it: "float", "v2half",
 * "v3int32". */
static void
library_type(LLVMTypeRef type, char *name, size_t size)
{
   unsigned lanes;
   LLVMTypeRef element = stela_air_call_element(type, &lanes);
   char base[16];
   if (LLVMGetTypeKind(element) == LLVMIntegerTypeKind)
      snprintf(base, sizeof(base), "int%u", LLVMGetIntTypeWidth(element));
   else
      snprintf(base, sizeof(base), LLVMGetTypeKind(element) == LLVMHalfTypeKind ? "half" : "float");
   if (lanes > 1)
      snprintf(name, size, "v%u%s", lanes, base);
   else
      snprintf(name, size, "%s", base);
}

/* Apple's library functions: "___metal_frexp_<type>_pthread<exponents>"
 * and "___metal_ilogb_<type>", whose i32 operand says whether fast math is
 * on, which its exact result ignores. */
static enum stela_air_call_status
library_call(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
             const char *name, size_t bytes, nir_def **result)
{
   if (LLVMGetNumArgOperands(call) != 2)
      return STELA_AIR_CALL_OTHER;
   LLVMTypeRef x = LLVMTypeOf(LLVMGetOperand(call, 0));
   if (!stela_air_call_floating(x))
      return STELA_AIR_CALL_OTHER;
   unsigned lanes;
   stela_air_call_element(x, &lanes);
   char value[16], exponents[16], expected[64];
   library_type(x, value, sizeof(value));
   library_type(lanes_of(LLVMInt32TypeInContext(LLVMGetTypeContext(x)), lanes), exponents,
                sizeof(exponents));
   snprintf(expected, sizeof(expected), "___metal_frexp_%s_pthread%s", value, exponents);
   if (stela_air_call_named(name, bytes, expected))
      return lower(c, call, callee, FREXP, SIGN_NONE, 2, false, result);
   snprintf(expected, sizeof(expected), "___metal_ilogb_%s", value);
   if (stela_air_call_named(name, bytes, expected))
      return lower(c, call, callee, ILOGB, SIGN_NONE, 2, false, result);
   return STELA_AIR_CALL_OTHER;
}

enum stela_air_call_status
stela_air_math_call(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
                    const char *name, size_t bytes, nir_def **result)
{
   *result = NULL;
   unsigned intrinsic = LLVMIsAFunction(callee) ? LLVMGetIntrinsicID(callee) : 0;
   for (unsigned i = 0; intrinsic && i < ARRAY_SIZE(intrinsics); i++) {
      if (intrinsic != LLVMLookupIntrinsicID(intrinsics[i].name, strlen(intrinsics[i].name)))
         continue;
      /* Each of these intrinsics is overloaded on its first operand's type. */
      char type[16], expected[64];
      LLVMTypeRef first = LLVMGetNumArgOperands(call) ? LLVMTypeOf(LLVMGetOperand(call, 0)) : NULL;
      if (!first || (!stela_air_call_floating(first) && !stela_air_call_integer(first)))
         return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported intrinsic types"), STELA_AIR_CALL_FAILED;
      stela_air_call_overload(first, type, sizeof(type));
      snprintf(expected, sizeof(expected), "%s.%s", intrinsics[i].name, type);
      if (!stela_air_call_named(name, bytes, expected))
         return stela_air_call_fail(c, STELA_AIR_INSTRUCTION, "intrinsic name disagrees with its types"),
                STELA_AIR_CALL_FAILED;
      bool fast = LLVMCanValueUseFastMathFlags(call) &&
                  (LLVMGetFastMathFlags(call) & LLVMFastMathApproxFunc);
      return lower(c, call, callee, intrinsics[i].operation, intrinsics[i].sign,
                   intrinsics[i].operands, fast, result);
   }
   if (bytes > strlen("___metal_") && !memcmp(name, "___metal_", strlen("___metal_")))
      return library_call(c, call, callee, name, bytes, result);
   if (bytes < 4 || memcmp(name, "air.", 4))
      return STELA_AIR_CALL_OTHER;
   if (stela_air_call_named(name, bytes, "air.discard_fragment")) {
      if (!stela_air_call_plain(c, call, callee, 0) || LLVMGetTypeKind(LLVMTypeOf(call)) != LLVMVoidTypeKind)
         return STELA_AIR_CALL_FAILED;
      if (!c->fragment)
         return stela_air_call_fail(c, STELA_AIR_INSTRUCTION, "discard exists only in fragment functions"),
                STELA_AIR_CALL_FAILED;
      /* Discarded fragments still help their quad's derivatives. */
      nir_demote(c->b);
      return STELA_AIR_CALL_LOWERED;
   }
   if (bytes > strlen("air.convert.") && !memcmp(name, "air.convert.", strlen("air.convert.")))
      return convert(c, call, callee, name, bytes, result);
   if (bytes > strlen("air.pack.") && !memcmp(name, "air.pack.", strlen("air.pack.")))
      return pack(c, call, callee, name, bytes, false, result);
   if (bytes > strlen("air.unpack.") && !memcmp(name, "air.unpack.", strlen("air.unpack.")))
      return pack(c, call, callee, name, bytes, true, result);
   if (LLVMGetNumArgOperands(call) == 0)
      return STELA_AIR_CALL_OTHER;
   if (boolean(LLVMTypeOf(LLVMGetOperand(call, 0))))
      return reduce_bools(c, call, callee, name, bytes, result);
   /* Every other function's overload is its first operand's type. */
   char type[16];
   LLVMTypeRef first = LLVMTypeOf(LLVMGetOperand(call, 0));
   if (!stela_air_call_floating(first) && !stela_air_call_integer(first))
      return STELA_AIR_CALL_OTHER;
   stela_air_call_overload(first, type, sizeof(type));
   const struct function *function;
   if ((function = air_function(floating, ARRAY_SIZE(floating), name, bytes, "fast_", "", type)))
      return lower(c, call, callee, function->operation, SIGN_NONE, function->operands, true, result);
   if ((function = air_function(floating, ARRAY_SIZE(floating), name, bytes, "", "", type)) ||
       (function = air_function(derivatives, ARRAY_SIZE(derivatives), name, bytes, "", "", type)) ||
       (function = air_function(unsigned_integer, ARRAY_SIZE(unsigned_integer), name, bytes, "", "",
                                type)))
      return lower(c, call, callee, function->operation, SIGN_NONE, function->operands, false,
                   result);
   if ((function = air_function(signed_integer, ARRAY_SIZE(signed_integer), name, bytes, "", ".s",
                                type)))
      return lower(c, call, callee, function->operation, SIGNED, function->operands, false, result);
   if ((function = air_function(signed_integer, ARRAY_SIZE(signed_integer), name, bytes, "", ".u",
                                type)))
      return lower(c, call, callee, function->operation, UNSIGNED, function->operands, false, result);
   return STELA_AIR_CALL_OTHER;
}
