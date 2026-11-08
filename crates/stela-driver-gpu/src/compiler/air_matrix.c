/* SPDX-License-Identifier: MIT */
/* AIR's SIMD-group matrix functions, as Apple's compiler names them:
 *
 *   air.simdgroup_matrix_8x8_init_filled.<m>.<t>(t value)
 *   air.simdgroup_matrix_8x8_init_diag.<m>.<t>(t value)
 *   air.simdgroup_matrix_8x8_load.<m>.p<space><t>(ptr, <2 x i64> extent,
 *                                                 <2 x i64> strides, <2 x i64> origin)
 *   air.simdgroup_matrix_8x8_store.<m>.p<space><t>(<m>, ptr, <2 x i64> extent,
 *                                                  <2 x i64> strides, <2 x i64> origin)
 *   air.simdgroup_matrix_8x8_multiply_accumulate.<d>.<a>.<b>.<c>(a, b, c)
 *
 * Earlier compilers spelled a load's and store's last three operands
 * (i64 elements_per_row, <2 x i64> origin, i1 transpose), which are strides
 * (1, elements_per_row) and that origin, or transposed strides
 * (elements_per_row, 1) and the origin's swapped coordinates.
 *
 * <m> is "v64f32", "v64f16" or "v64bf16" and <t> its element. An AIR matrix
 * is opaque storage whose elements 0 and 1 are the thread's
 * thread_elements(). Each of a SIMD-group's 32 lanes holds two, as on Apple
 * GPUs: lane l those of row 4 (l / 16) + (l / 2) % 4 at columns
 * 4 ((l / 8) % 2) + 2 (l % 2) and the next. Memory holds
 * column c and row r at element (origin.x + c) strides.x + (origin.y + r)
 * strides.y; the extent, the elements a row and the matrix's rows in that
 * order, bounds nothing. A product gathers each row of a and column of b by shuffles and
 * accumulates in single precision, rounding once to its result's type. */
#include "air_matrix.h"
#include "compiler/nir/nir_builtin_builder.h"
#include <stdio.h>
#include <string.h>

#define PREFIX "air.simdgroup_matrix_8x8_"

/* A matrix element type's AIR name, or NULL. */
static const char *
element_name(LLVMTypeRef element)
{
   switch (LLVMGetTypeKind(element)) {
   case LLVMFloatTypeKind: return "f32";
   case LLVMHalfTypeKind: return "f16";
   case LLVMBFloatTypeKind: return "bf16";
   default: return NULL;
   }
}

bool
stela_air_matrix_type(LLVMTypeRef type, unsigned *bits)
{
   if (LLVMGetTypeKind(type) != LLVMVectorTypeKind || LLVMGetVectorSize(type) != 64 ||
       !element_name(LLVMGetElementType(type)))
      return false;
   *bits = LLVMGetTypeKind(LLVMGetElementType(type)) == LLVMFloatTypeKind ? 32 : 16;
   return true;
}

static LLVMTypeKind
element_kind(LLVMTypeRef matrix)
{
   return LLVMGetTypeKind(LLVMGetElementType(matrix));
}

/* This lane's row and first column. */
static void
position(nir_builder *b, nir_def **row, nir_def **column)
{
   nir_def *lane = nir_load_subgroup_invocation(b);
   *row = nir_iadd(b, nir_ishl_imm(b, nir_ushr_imm(b, lane, 4), 2),
                   nir_iand_imm(b, nir_ushr_imm(b, lane, 1), 3));
   *column = nir_iadd(b, nir_ishl_imm(b, nir_iand_imm(b, nir_ushr_imm(b, lane, 3), 1), 2),
                      nir_ishl_imm(b, nir_iand_imm(b, lane, 1), 1));
}

/* The lane holding a row's columns 2 pair and 2 pair + 1. */
static nir_def *
lane_of(nir_builder *b, nir_def *row, nir_def *pair)
{
   nir_def *lane = nir_iadd(b, nir_ishl_imm(b, nir_ushr_imm(b, row, 2), 4),
                            nir_ishl_imm(b, nir_ushr_imm(b, pair, 1), 3));
   lane = nir_iadd(b, lane, nir_ishl_imm(b, nir_iand_imm(b, row, 3), 1));
   return nir_iadd(b, lane, nir_iand_imm(b, pair, 1));
}

/* A pair of `element`s in single precision. */
static nir_def *
widen(nir_builder *b, nir_def *pair, LLVMTypeKind element)
{
   switch (element) {
   case LLVMHalfTypeKind: return nir_f2f32(b, pair);
   case LLVMBFloatTypeKind: return stela_air_bfloat_to_float(b, pair);
   default: return pair;
   }
}

/* A single-precision pair rounded to `element`s, to nearest even. */
static nir_def *
narrow(nir_builder *b, nir_def *pair, LLVMTypeKind element)
{
   switch (element) {
   case LLVMHalfTypeKind: return nir_f2f16_rtne(b, pair);
   case LLVMBFloatTypeKind: return stela_air_float_to_bfloat(b, pair);
   default: return pair;
   }
}

/* `pair` from SIMD lane `source`, moved in 32-bit words. */
static nir_def *
from_lane(nir_builder *b, nir_def *pair, nir_def *source)
{
   if (pair->bit_size == 16)
      return nir_unpack_32_2x16(b, nir_shuffle(b, nir_pack_32_2x16(b, pair), source));
   return nir_vec2(b, nir_shuffle(b, nir_channel(b, pair, 0), source),
                   nir_shuffle(b, nir_channel(b, pair, 1), source));
}

/* a * x + c: this lane's row of a meets its two columns of x, each pair of
 * a's row and x's row k at this lane's columns from the lane holding it. */
static nir_def *
multiply_accumulate(nir_builder *b, LLVMTypeRef result, LLVMValueRef call, nir_def *a, nir_def *x,
                    nir_def *c)
{
   nir_def *row, *column;
   position(b, &row, &column);
   nir_def *quad = nir_ushr_imm(b, column, 1);
   LLVMTypeKind a_kind = element_kind(LLVMTypeOf(LLVMGetOperand(call, 0)));
   LLVMTypeKind x_kind = element_kind(LLVMTypeOf(LLVMGetOperand(call, 1)));
   nir_def *sum = widen(b, c, element_kind(LLVMTypeOf(LLVMGetOperand(call, 2))));
   for (unsigned j = 0; j < 4; j++) {
      nir_def *pair = widen(b, from_lane(b, a, lane_of(b, row, nir_imm_int(b, j))), a_kind);
      for (unsigned h = 0; h < 2; h++) {
         nir_def *columns = widen(b, from_lane(b, x, lane_of(b, nir_imm_int(b, 2 * j + h), quad)), x_kind);
         sum = nir_ffma(b, nir_channel(b, pair, h), columns, sum);
      }
   }
   return narrow(b, sum, element_kind(result));
}

/* The byte offset of this lane's element `e` in memory holding the matrix's
 * column c and row r at element (origin.x + c) strides.x + (origin.y + r)
 * strides.y. */
static nir_def *
element_offset(nir_builder *b, unsigned e, unsigned bytes, nir_def *strides, nir_def *origin)
{
   nir_def *row, *column;
   position(b, &row, &column);
   nir_def *x = nir_iadd(b, nir_channel(b, origin, 0), nir_u2u64(b, nir_iadd_imm(b, column, e)));
   nir_def *y = nir_iadd(b, nir_channel(b, origin, 1), nir_u2u64(b, row));
   nir_def *index = nir_iadd(b, nir_imul(b, x, nir_channel(b, strides, 0)),
                             nir_imul(b, y, nir_channel(b, strides, 1)));
   return nir_imul_imm(b, index, bytes);
}

enum addressing { ADDRESSING_NONE, ADDRESSING_STRIDES, ADDRESSING_TRANSPOSE };

/* How a memory function's last three operands, from operand `first`,
 * address its matrix: an extent, strides and an origin, or an earlier
 * compiler's i64 elements a row, origin and i1 transpose. */
static enum addressing
addressing(LLVMValueRef call, unsigned first)
{
   LLVMContextRef context = LLVMGetTypeContext(LLVMTypeOf(call));
   LLVMTypeRef i64 = LLVMInt64TypeInContext(context), pair = LLVMVectorType(i64, 2);
   LLVMTypeRef a = LLVMTypeOf(LLVMGetOperand(call, first));
   LLVMTypeRef origin = LLVMTypeOf(LLVMGetOperand(call, first + 1));
   LLVMTypeRef last = LLVMTypeOf(LLVMGetOperand(call, first + 2));
   if (a == pair && origin == pair && last == pair)
      return ADDRESSING_STRIDES;
   if (a == i64 && origin == pair && last == LLVMInt1TypeInContext(context))
      return ADDRESSING_TRANSPOSE;
   return ADDRESSING_NONE;
}

/* A load's or store's matrix, its memory at `pointer`: device, constant or
 * threadgroup memory of its elements. */
static enum stela_air_call_status
memory(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee, bool store,
       LLVMTypeRef matrix, nir_def **result)
{
   unsigned first = store ? 2 : 1, bits;
   LLVMValueRef pointer = LLVMGetOperand(call, first - 1);
   LLVMTypeRef pointer_type = LLVMTypeOf(pointer);
   unsigned space = LLVMGetTypeKind(pointer_type) == LLVMPointerTypeKind ?
                    LLVMGetPointerAddressSpace(pointer_type) : 0;
   if (!stela_air_call_plain(c, call, callee, first + 3))
      return STELA_AIR_CALL_FAILED;
   enum addressing form = addressing(call, first);
   if (!stela_air_matrix_type(matrix, &bits) || form == ADDRESSING_NONE ||
       (space != 1 && space != 3 && (store || space != 2)))
      return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported SIMD-group matrix memory types"),
             STELA_AIR_CALL_FAILED;
   nir_builder *b = c->b;
   nir_def *strides, *origin;
   if (form == ADDRESSING_STRIDES) {
      strides = c->operand(c->translator, LLVMGetOperand(call, first + 1));
      origin = strides ? c->operand(c->translator, LLVMGetOperand(call, first + 2)) : NULL;
   } else {
      nir_def *row = c->operand(c->translator, LLVMGetOperand(call, first));
      nir_def *at = row ? c->operand(c->translator, LLVMGetOperand(call, first + 1)) : NULL;
      nir_def *transpose = at ? c->operand(c->translator, LLVMGetOperand(call, first + 2)) : NULL;
      if (!transpose)
         return STELA_AIR_CALL_FAILED;
      nir_def *one = nir_imm_int64(b, 1);
      strides = nir_bcsel(b, transpose, nir_vec2(b, row, one), nir_vec2(b, one, row));
      origin = nir_bcsel(b, transpose, nir_swizzle(b, at, (unsigned[]){1, 0}, 2), at);
   }
   nir_def *value = origin && store ? c->operand(c->translator, LLVMGetOperand(call, 0)) : NULL;
   if (!origin || (store && !value))
      return STELA_AIR_CALL_FAILED;
   nir_def *elements[2];
   for (unsigned e = 0; e < 2; e++) {
      nir_def *offset = element_offset(b, e, bits / 8, strides, origin);
      if (store ? !c->store(c->translator, pointer, offset, nir_channel(b, value, e)) :
                  !(elements[e] = c->load(c->translator, pointer, offset, bits)))
         return STELA_AIR_CALL_FAILED;
   }
   if (!store)
      *result = nir_vec(b, elements, 2);
   return STELA_AIR_CALL_LOWERED;
}

enum stela_air_call_status
stela_air_matrix_call(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
                      const char *name, size_t bytes, nir_def **result)
{
   *result = NULL;
   if (bytes <= strlen(PREFIX) || memcmp(name, PREFIX, strlen(PREFIX)) ||
       !LLVMGetNumArgOperands(call))
      return STELA_AIR_CALL_OTHER;
   LLVMTypeRef type = LLVMTypeOf(call), first = LLVMTypeOf(LLVMGetOperand(call, 0));
   unsigned bits;
   char expected[160];
   nir_builder *b = c->b;
   if (stela_air_matrix_type(type, &bits)) {
      const char *element = element_name(LLVMGetElementType(type));
      /* Fills and diagonals of an element. */
      for (unsigned diagonal = 0; diagonal < 2; diagonal++) {
         snprintf(expected, sizeof(expected), PREFIX "init_%s.v64%s.%s", diagonal ? "diag" : "filled",
                  element, element);
         if (!stela_air_call_named(name, bytes, expected))
            continue;
         nir_def *value;
         if (!stela_air_call_plain(c, call, callee, 1))
            return STELA_AIR_CALL_FAILED;
         if (first != LLVMGetElementType(type))
            return stela_air_call_fail(c, STELA_AIR_TYPE, "SIMD-group matrix fill type differs"),
                   STELA_AIR_CALL_FAILED;
         if (!(value = c->operand(c->translator, LLVMGetOperand(call, 0))))
            return STELA_AIR_CALL_FAILED;
         if (!diagonal) {
            *result = nir_vec2(b, value, value);
         } else {
            nir_def *row, *column, *zero = nir_imm_zero(b, 1, bits);
            position(b, &row, &column);
            *result = nir_vec2(b, nir_bcsel(b, nir_ieq(b, column, row), value, zero),
                               nir_bcsel(b, nir_ieq(b, nir_iadd_imm(b, column, 1), row), value, zero));
         }
         return STELA_AIR_CALL_LOWERED;
      }
      snprintf(expected, sizeof(expected), PREFIX "load.v64%s.p%u%s", element,
               LLVMGetTypeKind(first) == LLVMPointerTypeKind ? LLVMGetPointerAddressSpace(first) : 0,
               element);
      if (stela_air_call_named(name, bytes, expected))
         return memory(c, call, callee, false, type, result);
      /* The product's name spells its result's and operands' types. */
      if (LLVMGetNumArgOperands(call) == 3) {
         unsigned a_bits, x_bits, c_bits;
         LLVMTypeRef a = first, x = LLVMTypeOf(LLVMGetOperand(call, 1));
         LLVMTypeRef sum = LLVMTypeOf(LLVMGetOperand(call, 2));
         if (stela_air_matrix_type(a, &a_bits) && stela_air_matrix_type(x, &x_bits) &&
             stela_air_matrix_type(sum, &c_bits)) {
            snprintf(expected, sizeof(expected), PREFIX "multiply_accumulate.v64%s.v64%s.v64%s.v64%s",
                     element, element_name(LLVMGetElementType(a)), element_name(LLVMGetElementType(x)),
                     element_name(LLVMGetElementType(sum)));
            if (stela_air_call_named(name, bytes, expected)) {
               if (!stela_air_call_plain(c, call, callee, 3) || !c->fp_environment(c->translator))
                  return STELA_AIR_CALL_FAILED;
               nir_def *values[3];
               for (unsigned i = 0; i < 3; i++) {
                  if (!(values[i] = c->operand(c->translator, LLVMGetOperand(call, i))))
                     return STELA_AIR_CALL_FAILED;
               }
               *result = multiply_accumulate(b, type, call, values[0], values[1], values[2]);
               return STELA_AIR_CALL_LOWERED;
            }
         }
      }
      return STELA_AIR_CALL_OTHER;
   }
   if (!stela_air_matrix_type(first, &bits) || LLVMGetNumArgOperands(call) < 2)
      return STELA_AIR_CALL_OTHER;
   const char *element = element_name(LLVMGetElementType(first));
   LLVMTypeRef pointer = LLVMTypeOf(LLVMGetOperand(call, 1));
   snprintf(expected, sizeof(expected), PREFIX "store.v64%s.p%u%s", element,
            LLVMGetTypeKind(pointer) == LLVMPointerTypeKind ? LLVMGetPointerAddressSpace(pointer) : 0,
            element);
   if (!stela_air_call_named(name, bytes, expected))
      return STELA_AIR_CALL_OTHER;
   if (LLVMGetTypeKind(type) != LLVMVoidTypeKind)
      return stela_air_call_fail(c, STELA_AIR_TYPE, "SIMD-group matrix stores return nothing"),
             STELA_AIR_CALL_FAILED;
   return memory(c, call, callee, true, first, result);
}
