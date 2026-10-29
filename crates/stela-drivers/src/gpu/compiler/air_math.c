/* SPDX-License-Identifier: MIT */
/* AIR's math, integer, conversion, derivative and discard functions, and
 * LLVM's math intrinsics. AIR names a function after its MSL builtin and its
 * overload, as DXMT's AIR builder (src/airconv/nt/air_builder.cpp) records:
 *
 *   air.[fast_]<function>.<type>   floating-point functions
 *   air.<function>.<s|u>.<type>    signed or unsigned integer functions
 *   air.<function>.<type>          sign-agnostic integer functions
 *   air.convert.<to>.<from>        conversions; each type is prefixed "f.",
 *                                  "s." or "u."
 *
 * A type is "f32", "f16" or "iN", prefixed "vN" for vectors. This file
 * rebuilds each name, LLVM's intrinsics' included, from the call's own types,
 * so a call whose name and types disagree is refused rather than guessed.
 *
 * NIR computes approximate functions at the accuracy Vulkan requires, which
 * matches Metal's fast variants, not its precise ones. Single-precision
 * approximate functions therefore lower only as AIR's "fast_" variants or as
 * LLVM intrinsics that allow approximation (afn); precise ones are refused.
 * Half-precision approximate functions evaluate in single precision. */
#include "air_math.h"
#include "compiler/nir/nir_builtin_builder.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

enum operation {
   /* Floating-point functions of their operands' type. */
   SATURATE, LOG2, EXP2, SQRT, RSQRT, FRACT, RINT, FLOOR, CEIL, TRUNC, ROUND, COS, SIN, TAN,
   FABS, ACOS, ASIN, ATAN, COSH, SINH, TANH, ACOSH, ASINH, ATANH, EXP, EXP10, LOG, LOG10,
   COSPI, SINPI, TANPI, FMAX, FMIN, POW, POWR, ATAN2, FMOD, COPYSIGN, FDIM, FMA, FCLAMP, MIX,
   FMAX3, FMIN3, FMEDIAN3, NORMALIZE, CROSS, DFDX, DFDY, FWIDTH,
   /* Floating-point reductions to the element type. */
   DOT, LENGTH, DISTANCE,
   /* Integer functions. */
   POPCOUNT, REVERSE_BITS, CLZ, CTZ, IABS, IMAX, IMIN, MUL_HI, ADD_SAT, SUB_SAT, ICLAMP,
   CONVERT, DISCARD,
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
   {"distance", DISTANCE, 2},
};

/* Derivatives, which have no fast variant. */
static const struct function derivatives[] = {
   {"dfdx", DFDX, 1}, {"dfdy", DFDY, 1}, {"fwidth", FWIDTH, 1},
};

/* Integer functions named with their operands' sign. */
static const struct function signed_integer[] = {
   {"abs", IABS, 1}, {"max", IMAX, 2}, {"min", IMIN, 2}, {"mul_hi", MUL_HI, 2},
   {"add_sat", ADD_SAT, 2}, {"sub_sat", SUB_SAT, 2}, {"clamp", ICLAMP, 3},
};

/* Integer functions named without a sign. clz and ctz also take an i1. */
static const struct function unsigned_integer[] = {
   {"popcount", POPCOUNT, 1}, {"reverse_bits", REVERSE_BITS, 1}, {"clz", CLZ, 2},
   {"ctz", CTZ, 2},
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
   case POWR: case ATAN2: case FMOD: case NORMALIZE: case LENGTH: case DISTANCE:
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

static nir_def *
floating_value(nir_builder *b, enum operation operation, nir_def **s)
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
   case DOT: return nir_fdot(b, x, s[1]);
   case LENGTH: return length(b, x);
   case DISTANCE: return length(b, nir_fsub(b, x, s[1]));
   default: UNREACHABLE("floating-point operation");
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
   case IMAX: return sign ? nir_imax(b, x, s[1]) : nir_umax(b, x, s[1]);
   case IMIN: return sign ? nir_imin(b, x, s[1]) : nir_umin(b, x, s[1]);
   case MUL_HI: return sign ? nir_imul_high(b, x, s[1]) : nir_umul_high(b, x, s[1]);
   case ADD_SAT: return sign ? nir_iadd_sat(b, x, s[1]) : nir_uadd_sat(b, x, s[1]);
   case SUB_SAT: return sign ? nir_isub_sat(b, x, s[1]) : nir_usub_sat(b, x, s[1]);
   case ICLAMP:
      return sign ? nir_imin(b, nir_imax(b, x, s[1]), s[2]) : nir_umin(b, nir_umax(b, x, s[1]), s[2]);
   default: UNREACHABLE("integer operation");
   }
}

/* The call's operands, each of the result's type unless `mixed`. */
static bool
operands(const struct stela_air_call_context *c, LLVMValueRef call, unsigned count, bool mixed,
         nir_def **values)
{
   LLVMTypeRef type = LLVMTypeOf(LLVMGetOperand(call, 0));
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef operand = LLVMGetOperand(call, i);
      if (!mixed && LLVMTypeOf(operand) != type)
         return stela_air_call_fail(c, STELA_AIR_TYPE, "math function operand types differ");
      if (!(values[i] = c->operand(c->translator, operand)))
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
   nir_def *s[3];
   if (operation >= POPCOUNT) {
      /* clz, ctz and llvm.abs take a trailing constant i1. */
      unsigned values = operation == CLZ || operation == CTZ || (operation == IABS && count == 2) ?
                        1 : count;
      if (!stela_air_call_integer(type) || operand != type || !operands(c, call, values, false, s))
         return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported integer function types"), STELA_AIR_CALL_FAILED;
      *result = integer_value(b, operation, sign == SIGNED, s);
      return STELA_AIR_CALL_LOWERED;
   }
   bool reduction = operation == DOT || operation == LENGTH || operation == DISTANCE;
   unsigned lanes;
   LLVMTypeRef scalar = stela_air_call_element(operand, &lanes);
   if (!stela_air_call_floating(operand) ||
       (reduction ? lanes < 2 || type != scalar : type != operand) ||
       (operation == CROSS && lanes != 3) || (operation == NORMALIZE && lanes < 2))
      return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported floating-point function types"), STELA_AIR_CALL_FAILED;
   if ((operation == DFDX || operation == DFDY || operation == FWIDTH) && !c->fragment)
      return stela_air_call_fail(c, STELA_AIR_INSTRUCTION, "derivatives exist only in fragment functions"),
             STELA_AIR_CALL_FAILED;
   if (approximate(operation) && !fast && LLVMGetTypeKind(scalar) == LLVMFloatTypeKind)
      return stela_air_call_fail(c, STELA_AIR_INSTRUCTION, "precise single-precision function accuracy is unqualified"),
             STELA_AIR_CALL_FAILED;
   if (!c->fp_environment(c->translator) || !operands(c, call, count, false, s))
      return STELA_AIR_CALL_FAILED;
   unsigned bits = s[0]->bit_size;
   if (bits == 16 && approximate(operation)) {
      for (unsigned i = 0; i < count; i++)
         s[i] = nir_f2f32(b, s[i]);
      *result = nir_f2f16(b, floating_value(b, operation, s));
   } else {
      *result = floating_value(b, operation, s);
   }
   return STELA_AIR_CALL_LOWERED;
}

/* "air.convert.<to>.<from>": each type is "f." with a float type, or "s."
 * or "u." with an integer type. */
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
   if ((!to_float && !stela_air_call_integer(to)) || (!from_float && !stela_air_call_integer(from)) ||
       to_lanes != from_lanes)
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
   if (to_float && from_float)
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
   if (LLVMGetNumArgOperands(call) == 0)
      return STELA_AIR_CALL_OTHER;
   /* Every function's overload is its first operand's type. */
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
