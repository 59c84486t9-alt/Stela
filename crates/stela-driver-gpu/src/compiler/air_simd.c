/* SPDX-License-Identifier: MIT */
/* AIR's SIMD-group and quad-group functions, as Apple's compiler names
 * them after their MSL builtins:
 *
 *   air.<simd|quad>_<function>.<type>(value[, i16 lane])
 *   air.<simd|quad>_shuffle_and_fill_<up|down>.<type>(value, fill, i16 delta,
 *                                                    i16 modulo)
 *   air.<simd|quad>_<all|any>(i1) -> i1
 *   air.<simd|quad>_ballot.<i32|i64>(i1)
 *   air.<simd|quad>_is_first() -> i1
 *
 * A floating-point type is bare ("f32", "v2f16"); an integer one carries its
 * sign ("u.i32", "s.i16"), which min, max and the widening of narrow
 * integers read.
 *
 * A quad-group is four consecutive SIMD lanes. Data moves through one 32-bit
 * shuffle from a computed lane, which every backend supports. Out-of-range
 * shuffle_up and shuffle_down lanes keep their own value, as Metal specifies. */
#include "air_simd.h"
#include <stdio.h>
#include <string.h>

enum operation {
   /* Data movement. */
   SHUFFLE, SHUFFLE_XOR, SHUFFLE_UP, SHUFFLE_DOWN, ROTATE_UP, ROTATE_DOWN, BROADCAST,
   BROADCAST_FIRST, FILL_UP, FILL_DOWN,
   /* Reductions and scans. */
   SUM, PRODUCT, MIN, MAX, AND, OR, XOR, INCLUSIVE_SUM, INCLUSIVE_PRODUCT, EXCLUSIVE_SUM,
   EXCLUSIVE_PRODUCT,
   /* Votes. */
   ALL, ANY, BALLOT, IS_FIRST,
};

/* Functions of a typed value, after "simd_" or "quad_". */
static const struct {
   const char *name;
   enum operation operation;
   bool lane; /* Also takes an i16 lane, delta or mask. */
} functions[] = {
   {"shuffle", SHUFFLE, true}, {"shuffle_xor", SHUFFLE_XOR, true},
   {"shuffle_up", SHUFFLE_UP, true}, {"shuffle_down", SHUFFLE_DOWN, true},
   {"shuffle_rotate_up", ROTATE_UP, true}, {"shuffle_rotate_down", ROTATE_DOWN, true},
   {"broadcast", BROADCAST, true}, {"broadcast_first", BROADCAST_FIRST, false},
   {"shuffle_and_fill_up", FILL_UP, true}, {"shuffle_and_fill_down", FILL_DOWN, true},
   {"sum", SUM, false}, {"product", PRODUCT, false}, {"min", MIN, false}, {"max", MAX, false},
   {"and", AND, false}, {"or", OR, false}, {"xor", XOR, false},
   {"prefix_inclusive_sum", INCLUSIVE_SUM, false},
   {"prefix_inclusive_product", INCLUSIVE_PRODUCT, false},
   {"prefix_exclusive_sum", EXCLUSIVE_SUM, false},
   {"prefix_exclusive_product", EXCLUSIVE_PRODUCT, false},
};

static const struct {
   const char *name;
   enum operation operation;
} votes[] = {
   {"all", ALL}, {"any", ANY}, {"ballot", BALLOT}, {"is_first", IS_FIRST},
};

/* The lanes a function spans: the whole SIMD-group, or the caller's quad. */
struct group {
   bool quad;
   nir_def *base;  /* The group's first SIMD lane. */
   nir_def *index; /* The caller's index in the group. */
   nir_def *size;  /* The group's lanes, a power of two. */
};

static struct group
group(nir_builder *b, bool quad)
{
   nir_def *lane = nir_load_subgroup_invocation(b);
   if (!quad)
      return (struct group){false, nir_imm_int(b, 0), lane, nir_load_subgroup_size(b)};
   return (struct group){true, nir_iand_imm(b, lane, ~3u), nir_iand_imm(b, lane, 3), nir_imm_int(b, 4)};
}

/* The group's lanes for which `predicate` holds, as bits from its first lane. */
static nir_def *
active(nir_builder *b, nir_def *predicate, const struct group *g)
{
   nir_def *lanes = nir_ballot(b, 1, 64, predicate);
   return g->quad ? nir_iand_imm(b, nir_ushr(b, lanes, g->base), 0xf) : lanes;
}

/* v from SIMD lane `source`, moved in 32-bit words. */
static nir_def *
shuffle(nir_builder *b, nir_def *v, nir_def *source)
{
   switch (v->bit_size) {
   case 1:
      return nir_ine_imm(b, nir_shuffle(b, nir_b2i32(b, v), source), 0);
   case 8:
   case 16:
      return nir_u2uN(b, nir_shuffle(b, nir_u2u32(b, v), source), v->bit_size);
   case 64:
      return nir_pack_64_2x32_split(b, nir_shuffle(b, nir_unpack_64_2x32_split_x(b, v), source),
                                    nir_shuffle(b, nir_unpack_64_2x32_split_y(b, v), source));
   default:
      return nir_shuffle(b, v, source);
   }
}

static nir_def *
move(nir_builder *b, enum operation operation, nir_def *v, nir_def *operand, const struct group *g)
{
   nir_def *last = nir_iadd_imm(b, g->size, -1);
   nir_def *delta = operand ? nir_u2u32(b, operand) : NULL;
   nir_def *source;
   switch (operation) {
   case SHUFFLE:
   case BROADCAST: source = nir_iand(b, delta, last); break;
   case SHUFFLE_XOR: source = nir_ixor(b, g->index, nir_iand(b, delta, last)); break;
   case SHUFFLE_UP:
   case ROTATE_UP: source = nir_iand(b, nir_isub(b, g->index, delta), last); break;
   case SHUFFLE_DOWN:
   case ROTATE_DOWN: source = nir_iand(b, nir_iadd(b, g->index, delta), last); break;
   default:
      source = g->quad ? nir_find_lsb(b, active(b, nir_imm_true(b), g)) :
                         nir_read_first_invocation(b, g->index);
      break;
   }
   nir_def *moved = shuffle(b, v, nir_iadd(b, g->base, source));
   if (operation == SHUFFLE_UP)
      return nir_bcsel(b, nir_uge(b, g->index, delta), moved, v);
   if (operation == SHUFFLE_DOWN)
      return nir_bcsel(b, nir_ult(b, nir_iadd(b, g->index, delta), g->size), moved, v);
   return moved;
}

/* A shuffle and fill: within each modulo lanes of the group, the value
 * delta lanes down (up), or where that passes the segment's end (start), the
 * fill delta lanes down (up) wrapped into the segment. */
static nir_def *
fill(nir_builder *b, enum operation operation, nir_def *v, nir_def *filling, nir_def *delta,
     nir_def *modulo, const struct group *g)
{
   delta = nir_u2u32(b, delta);
   modulo = nir_u2u32(b, modulo);
   nir_def *index = nir_umod(b, g->index, modulo);
   nir_def *segment = nir_iadd(b, g->base, nir_isub(b, g->index, index));
   nir_def *source = operation == FILL_DOWN ? nir_iadd(b, index, delta) :
                                              nir_isub(b, nir_iadd(b, index, modulo), delta);
   nir_def *inside = operation == FILL_DOWN ? nir_ult(b, source, modulo) : nir_uge(b, source, modulo);
   source = nir_iadd(b, segment, nir_umod(b, source, modulo));
   return nir_bcsel(b, inside, shuffle(b, v, source), shuffle(b, filling, source));
}

/* The operation combining two values of a reduction or scan. */
static nir_op
combination(enum operation operation, bool floating, bool sign)
{
   switch (operation) {
   case SUM: case INCLUSIVE_SUM: case EXCLUSIVE_SUM: return floating ? nir_op_fadd : nir_op_iadd;
   case PRODUCT: case INCLUSIVE_PRODUCT: case EXCLUSIVE_PRODUCT:
      return floating ? nir_op_fmul : nir_op_imul;
   case MIN: return floating ? nir_op_fmin : sign ? nir_op_imin : nir_op_umin;
   case MAX: return floating ? nir_op_fmax : sign ? nir_op_imax : nir_op_umax;
   case AND: return nir_op_iand;
   case OR: return nir_op_ior;
   default: return nir_op_ixor;
   }
}

/* A quad's prefix scan from the values of its lanes in order. An exclusive
 * scan's first lane is the operation's identity, `identity`. */
static nir_def *
quad_scan(nir_builder *b, nir_op op, nir_def *v, nir_def *identity, bool inclusive,
          const struct group *g)
{
   nir_def *result = inclusive ? shuffle(b, v, g->base) : identity;
   for (unsigned k = inclusive ? 1 : 0; k < (inclusive ? 4 : 3); k++) {
      nir_def *x = shuffle(b, v, nir_iadd_imm(b, g->base, k));
      nir_def *included = inclusive ? nir_uge_imm(b, g->index, k) : nir_ult(b, nir_imm_int(b, k), g->index);
      nir_def *step = inclusive || k ? nir_build_alu2(b, op, result, x) : x;
      result = nir_bcsel(b, included, step, result);
   }
   return result;
}

static nir_def *
reduce(nir_builder *b, enum operation operation, nir_def *v, bool floating, bool sign,
       const struct group *g)
{
   nir_op op = combination(operation, floating, sign);
   /* Narrow integers combine in 32 bits, extended by their sign. */
   unsigned bits = v->bit_size;
   bool widen = !floating && bits < 32;
   if (widen)
      v = sign ? nir_i2i32(b, v) : nir_u2u32(b, v);
   bool product = operation == INCLUSIVE_PRODUCT || operation == EXCLUSIVE_PRODUCT;
   nir_def *identity = nir_replicate(b, floating ? nir_imm_floatN_t(b, product, v->bit_size) :
                                               nir_imm_intN_t(b, product, v->bit_size),
                                     v->num_components);
   nir_def *result;
   switch (operation) {
   case INCLUSIVE_SUM:
   case INCLUSIVE_PRODUCT:
      result = g->quad ? quad_scan(b, op, v, identity, true, g) :
                         nir_inclusive_scan(b, v, .reduction_op = op);
      break;
   case EXCLUSIVE_SUM:
   case EXCLUSIVE_PRODUCT:
      result = g->quad ? quad_scan(b, op, v, identity, false, g) :
                         nir_exclusive_scan(b, v, .reduction_op = op);
      break;
   default:
      result = nir_reduce(b, v, .reduction_op = op, .cluster_size = g->quad ? 4 : 0);
      break;
   }
   return widen ? nir_u2uN(b, result, bits) : result;
}

static enum stela_air_call_status
typed(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
      enum operation operation, bool lane, bool quad, bool floating, bool sign, nir_def **result)
{
   /* A fill's value and fill, then its delta and modulo. */
   bool filled = operation == FILL_UP || operation == FILL_DOWN;
   unsigned values = filled ? 2 : 1, operands = values + (filled ? 2 : lane);
   if (!stela_air_call_plain(c, call, callee, operands))
      return STELA_AIR_CALL_FAILED;
   LLVMTypeRef type = LLVMTypeOf(LLVMGetOperand(call, 0));
   LLVMTypeRef i16 = LLVMInt16TypeInContext(LLVMGetTypeContext(type));
   bool shaped = LLVMTypeOf(call) == type &&
                 !(floating && (operation == AND || operation == OR || operation == XOR));
   for (unsigned i = 0; i < operands; i++)
      shaped &= LLVMTypeOf(LLVMGetOperand(call, i)) == (i < values ? type : i16);
   if (!shaped)
      return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported SIMD-group function types"),
             STELA_AIR_CALL_FAILED;
   if (floating && operation >= SUM && !c->fp_environment(c->translator))
      return STELA_AIR_CALL_FAILED;
   nir_def *v[4];
   for (unsigned i = 0; i < operands; i++) {
      if (!(v[i] = c->operand(c->translator, LLVMGetOperand(call, i))))
         return STELA_AIR_CALL_FAILED;
   }
   struct group g = group(c->b, quad);
   *result = filled ? fill(c->b, operation, v[0], v[1], v[2], v[3], &g) :
             operation < SUM ? move(c->b, operation, v[0], lane ? v[1] : NULL, &g) :
                               reduce(c->b, operation, v[0], floating, sign, &g);
   return STELA_AIR_CALL_LOWERED;
}

static enum stela_air_call_status
vote(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
     enum operation operation, bool quad, nir_def **result)
{
   bool first = operation == IS_FIRST;
   if (!stela_air_call_plain(c, call, callee, first ? 0 : 1))
      return STELA_AIR_CALL_FAILED;
   LLVMTypeRef type = LLVMTypeOf(call);
   unsigned bits = LLVMGetTypeKind(type) == LLVMIntegerTypeKind ? LLVMGetIntTypeWidth(type) : 0;
   LLVMTypeRef operand = first ? NULL : LLVMTypeOf(LLVMGetOperand(call, 0));
   if ((operation == BALLOT ? bits != 32 && bits != 64 : bits != 1) ||
       (operand && (LLVMGetTypeKind(operand) != LLVMIntegerTypeKind || LLVMGetIntTypeWidth(operand) != 1)))
      return stela_air_call_fail(c, STELA_AIR_TYPE, "unsupported SIMD-group vote types"),
             STELA_AIR_CALL_FAILED;
   nir_builder *b = c->b;
   nir_def *predicate = first ? nir_imm_true(b) : c->operand(c->translator, LLVMGetOperand(call, 0));
   if (!predicate)
      return STELA_AIR_CALL_FAILED;
   struct group g = group(b, quad);
   switch (operation) {
   case ALL:
      *result = quad ? nir_ieq(b, active(b, predicate, &g), active(b, nir_imm_true(b), &g)) :
                       nir_vote_all(b, 1, predicate);
      break;
   case ANY:
      *result = quad ? nir_ine_imm(b, active(b, predicate, &g), 0) : nir_vote_any(b, 1, predicate);
      break;
   case BALLOT:
      *result = nir_u2uN(b, active(b, predicate, &g), bits);
      break;
   default:
      *result = quad ? nir_ieq(b, nir_find_lsb(b, active(b, predicate, &g)), g.index) : nir_elect(b, 1);
      break;
   }
   return STELA_AIR_CALL_LOWERED;
}

enum stela_air_call_status
stela_air_simd_call(const struct stela_air_call_context *c, LLVMValueRef call, LLVMValueRef callee,
                    const char *name, size_t bytes, nir_def **result)
{
   *result = NULL;
   char expected[96];
   /* The SIMD-group's lanes, which a shuffle and fill without a modulo
    * wraps at. */
   if (LLVMGetTypeKind(LLVMTypeOf(call)) == LLVMIntegerTypeKind) {
      char overload[16];
      stela_air_call_overload(LLVMTypeOf(call), overload, sizeof(overload));
      snprintf(expected, sizeof(expected), "air.get_simdgroup_size.%s", overload);
      if (stela_air_call_named(name, bytes, expected)) {
         if (!stela_air_call_plain(c, call, callee, 0))
            return STELA_AIR_CALL_FAILED;
         *result = nir_u2uN(c->b, nir_load_subgroup_size(c->b), LLVMGetIntTypeWidth(LLVMTypeOf(call)));
         return STELA_AIR_CALL_LOWERED;
      }
   }
   bool quad;
   if (bytes > strlen("air.simd_") && !memcmp(name, "air.simd_", strlen("air.simd_")))
      quad = false;
   else if (bytes > strlen("air.quad_") && !memcmp(name, "air.quad_", strlen("air.quad_")))
      quad = true;
   else
      return STELA_AIR_CALL_OTHER;
   const char *prefix = quad ? "air.quad_" : "air.simd_";
   for (unsigned i = 0; i < ARRAY_SIZE(votes); i++) {
      /* A ballot is named by the mask it returns. */
      char mask[16] = "";
      if (votes[i].operation == BALLOT)
         stela_air_call_overload(LLVMTypeOf(call), mask, sizeof(mask));
      snprintf(expected, sizeof(expected), "%s%s%s%s", prefix, votes[i].name, *mask ? "." : "",
               mask);
      if (stela_air_call_named(name, bytes, expected))
         return vote(c, call, callee, votes[i].operation, quad, result);
   }
   if (!LLVMGetNumArgOperands(call))
      return STELA_AIR_CALL_OTHER;
   LLVMTypeRef type = LLVMTypeOf(LLVMGetOperand(call, 0));
   bool floating = stela_air_call_floating(type);
   if (!floating && !stela_air_call_integer(type))
      return STELA_AIR_CALL_OTHER;
   char overload[16];
   stela_air_call_overload(type, overload, sizeof(overload));
   for (unsigned i = 0; i < ARRAY_SIZE(functions); i++) {
      for (unsigned sign = 0; sign < (floating ? 1u : 2u); sign++) {
         snprintf(expected, sizeof(expected), "%s%s.%s%s", prefix, functions[i].name,
                  floating ? "" : sign ? "s." : "u.", overload);
         if (stela_air_call_named(name, bytes, expected))
            return typed(c, call, callee, functions[i].operation, functions[i].lane, quad, floating,
                         sign, result);
      }
   }
   return STELA_AIR_CALL_OTHER;
}
