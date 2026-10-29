/* SPDX-License-Identifier: MIT */
/* Function constants. Metal.jl's library builder (src/metallib/builder.jl)
 * reads Apple's AIR: each constant is an AS2 global named by
 * !air.function_constants, which functions load and test with
 *
 *   air.is_function_constant_defined(ptr addrspace(2) @storage) -> i1
 *
 * Specialization makes the storage an internal constant with its value, so
 * any remaining access reads constant data, and folds the loads of the whole
 * value and the tests into constants, so the paths a constant selects
 * against stay as dead code for NIR to remove. A constant without a value is
 * zero: Metal requires a value wherever a function reads it untested.
 * Program-scope constants derived from function constants are computed by
 * air.static_init functions, whose stores to AS2 storage remain refused. */
#define STELA_AIR_METADATA_INTERNAL
#include "air_constants.h"
#include <stdio.h>
#include <string.h>

static bool
fail(struct stela_air_metadata *m, enum stela_air_error_kind kind, const char *detail)
{
   if (m->error->kind == STELA_AIR_OK) {
      m->error->kind = kind;
      snprintf(m->error->detail, sizeof(m->error->detail), "%s", detail);
   }
   return false;
}

/* Bytes of one lane of a value: one for each bool. */
static unsigned
lane_bytes(LLVMTypeRef lane)
{
   switch (LLVMGetTypeKind(lane)) {
   case LLVMIntegerTypeKind: return MAX2(LLVMGetIntTypeWidth(lane) / 8, 1);
   case LLVMHalfTypeKind: return 2;
   default: return 4;
   }
}

static LLVMValueRef
lane_constant(LLVMTypeRef lane, const uint8_t *bytes)
{
   uint64_t bits = 0;
   for (unsigned i = 0; i < lane_bytes(lane); i++)
      bits |= (uint64_t)bytes[i] << (8 * i);
   LLVMContextRef context = LLVMGetTypeContext(lane);
   switch (LLVMGetTypeKind(lane)) {
   case LLVMIntegerTypeKind:
      return LLVMConstInt(lane, LLVMGetIntTypeWidth(lane) == 1 ? bits != 0 : bits, false);
   case LLVMHalfTypeKind:
      return LLVMConstBitCast(LLVMConstInt(LLVMInt16TypeInContext(context), bits, false), lane);
   default:
      return LLVMConstBitCast(LLVMConstInt(LLVMInt32TypeInContext(context), bits, false), lane);
   }
}

/* The constant of type a value's bytes encode: packed lanes, a three-lane
 * vector optionally padded to four. NULL when the size disagrees. */
static LLVMValueRef
value_constant(LLVMTypeRef type, const struct stela_air_constant_value *value)
{
   bool vector = LLVMGetTypeKind(type) == LLVMVectorTypeKind;
   LLVMTypeRef lane = vector ? LLVMGetElementType(type) : type;
   unsigned lanes = vector ? LLVMGetVectorSize(type) : 1;
   size_t stride = lane_bytes(lane);
   if (value->size != lanes * stride && !(lanes == 3 && value->size == 4 * stride))
      return NULL;
   const uint8_t *bytes = value->bytes;
   if (!vector)
      return lane_constant(lane, bytes);
   LLVMValueRef elements[4];
   for (unsigned i = 0; i < lanes; i++)
      elements[i] = lane_constant(lane, bytes + i * stride);
   return LLVMConstVector(elements, lanes);
}

/* A call of air.is_function_constant_defined on storage. */
static bool
defined_test(LLVMValueRef user, LLVMValueRef storage)
{
   if (!LLVMIsACallInst(user) || LLVMGetNumArgOperands(user) != 1 ||
       LLVMGetOperand(user, 0) != storage)
      return false;
   LLVMValueRef callee = LLVMGetCalledValue(user);
   size_t bytes = 0;
   const char *name = LLVMIsAFunction(callee) ? LLVMGetValueName2(callee, &bytes) : NULL;
   LLVMTypeRef type = LLVMTypeOf(user);
   return name && bytes == strlen("air.is_function_constant_defined") &&
          !memcmp(name, "air.is_function_constant_defined", bytes) &&
          LLVMGetTypeKind(type) == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type) == 1;
}

static void
specialize(LLVMValueRef storage, LLVMValueRef value, bool defined)
{
   for (LLVMUseRef use = LLVMGetFirstUse(storage), next; use; use = next) {
      next = LLVMGetNextUse(use);
      LLVMValueRef user = LLVMGetUser(use);
      LLVMValueRef folded =
         LLVMIsALoadInst(user) && LLVMTypeOf(user) == LLVMTypeOf(value) &&
               !LLVMGetVolatile(user) && LLVMGetOrdering(user) == LLVMAtomicOrderingNotAtomic ?
            value :
         defined_test(user, storage) ? LLVMConstInt(LLVMTypeOf(user), defined, false) : NULL;
      if (folded) {
         LLVMReplaceAllUsesWith(user, folded);
         LLVMInstructionEraseFromParent(user);
      }
   }
   LLVMSetInitializer(storage, value);
   LLVMSetGlobalConstant(storage, true);
   LLVMSetLinkage(storage, LLVMInternalLinkage);
   LLVMSetExternallyInitialized(storage, false);
   LLVMSetSection(storage, "");
}

bool
stela_air_specialize_constants(struct stela_air_metadata *m,
                               const struct stela_air_constant_value *values, unsigned count)
{
   for (unsigned i = 0; i < count; i++) {
      for (unsigned j = 0; j < i; j++) {
         if (values[j].index == values[i].index)
            return fail(m, STELA_AIR_INPUT, "duplicate function constant value");
      }
      if (!values[i].bytes)
         return fail(m, STELA_AIR_INPUT, "function constant value without bytes");
   }
   struct stela_air_function_constant constants[AIR_MAX_FUNCTION_CONSTANTS];
   LLVMValueRef storage[AIR_MAX_FUNCTION_CONSTANTS];
   unsigned constant_count;
   if (!stela_air_metadata_function_constants(m, constants, storage, &constant_count))
      return false;
   for (unsigned i = 0; i < constant_count; i++) {
      const struct stela_air_constant_value *value = NULL;
      for (unsigned j = 0; j < count && !value; j++)
         value = values[j].index == constants[i].index ? &values[j] : NULL;
      if (!value && constants[i].required)
         return fail(m, STELA_AIR_ARGUMENT, "a required function constant has no value");
      LLVMTypeRef type = LLVMGlobalGetValueType(storage[i]);
      LLVMValueRef constant = value ? value_constant(type, value) : LLVMConstNull(type);
      if (!constant)
         return fail(m, STELA_AIR_INPUT, "function constant value size disagrees with its type");
      specialize(storage[i], constant, value != NULL);
   }
   LLVMValueRef test = LLVMGetNamedFunction(m->module, "air.is_function_constant_defined");
   if (test && !LLVMGetFirstUse(test))
      LLVMDeleteFunction(test);
   return true;
}
