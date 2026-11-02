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
 *
 * Program-scope constants derived from function constants are AS2 globals
 * that air.static_init constructors, listed in llvm.global_ctors, store.
 * Once the function constants are specialized, LLVM's global optimizer
 * evaluates the constructors as it does C++ static initializers; it runs on a
 * clone, so only the values it computes reach the module. A
 * [[function_constant]] argument's predicate is one of them.
 *
 * What the constants then decide is folded, as Metal's compiler folds it: the
 * paths a false constant disables are removed rather than translated. */
#define STELA_AIR_METADATA_INTERNAL
#include "air_constants.h"
#include "llvm-c/Transforms/PassBuilder.h"
#include "util/macros.h"
#include "util/set.h"
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

/* air.normalize_function_constant_predicate.<type>(x), with which a
 * constructor computes a [[function_constant]] argument's predicate: x as a
 * bool of its type, 0 or 1. The global optimizer evaluates what replaces it;
 * another form stays, and the constructor's evaluation refuses it. */
static void
normalize_predicates(LLVMModuleRef module)
{
   static const char prefix[] = "air.normalize_function_constant_predicate.";
   LLVMBuilderRef builder = NULL;
   for (LLVMValueRef fn = LLVMGetFirstFunction(module), next; fn; fn = next) {
      next = LLVMGetNextFunction(fn);
      size_t bytes;
      const char *name = LLVMGetValueName2(fn, &bytes);
      if (!LLVMIsDeclaration(fn) || bytes < strlen(prefix) || memcmp(name, prefix, strlen(prefix)))
         continue;
      if (!builder)
         builder = LLVMCreateBuilderInContext(LLVMGetModuleContext(module));
      for (LLVMUseRef use = LLVMGetFirstUse(fn), after; use; use = after) {
         after = LLVMGetNextUse(use);
         LLVMValueRef call = LLVMGetUser(use);
         LLVMTypeRef type = LLVMTypeOf(call);
         if (!LLVMIsACallInst(call) || LLVMGetCalledValue(call) != fn ||
             LLVMGetNumArgOperands(call) != 1 || LLVMGetTypeKind(type) != LLVMIntegerTypeKind ||
             LLVMTypeOf(LLVMGetOperand(call, 0)) != type)
            continue;
         LLVMPositionBuilderBefore(builder, call);
         LLVMValueRef value = LLVMGetOperand(call, 0);
         LLVMValueRef truth = LLVMBuildICmp(builder, LLVMIntNE, value, LLVMConstNull(type), "");
         LLVMReplaceAllUsesWith(call, LLVMBuildZExtOrBitCast(builder, truth, type, ""));
         LLVMInstructionEraseFromParent(call);
      }
      if (!LLVMGetFirstUse(fn))
         LLVMDeleteFunction(fn);
   }
   if (builder)
      LLVMDisposeBuilder(builder);
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
   normalize_predicates(m->module);
   return true;
}

/* A constant of plain data: no global's address, at any depth. */
static bool
plain(LLVMValueRef value, unsigned depth)
{
   if (!value || depth > 8 || LLVMIsAGlobalValue(value) || LLVMIsAConstantExpr(value))
      return false;
   if (LLVMIsAConstantInt(value) || LLVMIsAConstantFP(value) || LLVMIsAConstantDataSequential(value) ||
       LLVMIsAConstantAggregateZero(value) || LLVMIsUndef(value))
      return true;
   for (int i = 0; i < LLVMGetNumOperands(value); i++) {
      if (!plain(LLVMGetOperand(value, (unsigned)i), depth + 1))
         return false;
   }
   return LLVMIsAConstantArray(value) || LLVMIsAConstantStruct(value) || LLVMIsAConstantVector(value);
}

/* AIR's conversions of the clone (air_math.c), as the casts the global
 * optimizer evaluates. */
static void
cast_conversions(LLVMModuleRef clone)
{
   static const char prefix[] = "air.convert.";
   const size_t prefix_bytes = strlen(prefix);
   LLVMBuilderRef builder = LLVMCreateBuilderInContext(LLVMGetModuleContext(clone));
   for (LLVMValueRef fn = LLVMGetFirstFunction(clone); fn; fn = LLVMGetNextFunction(fn)) {
      size_t bytes;
      const char *name = LLVMGetValueName2(fn, &bytes);
      if (bytes <= prefix_bytes || memcmp(name, prefix, prefix_bytes))
         continue;
      /* <to kind>.<to type>.<from kind>.<from type> */
      const char *to_type = strchr(name + prefix_bytes, '.');
      const char *from_kind = to_type ? strchr(to_type + 1, '.') : NULL;
      if (!from_kind)
         continue;
      bool to_signed = name[prefix_bytes] == 's', from_signed = from_kind[1] == 's';
      for (LLVMUseRef use = LLVMGetFirstUse(fn), next; use; use = next) {
         next = LLVMGetNextUse(use);
         LLVMValueRef call = LLVMGetUser(use);
         if (!LLVMIsACallInst(call) || LLVMGetNumArgOperands(call) != 1)
            continue;
         LLVMPositionBuilderBefore(builder, call);
         LLVMValueRef from = LLVMGetOperand(call, 0);
         LLVMTypeRef type = LLVMTypeOf(call);
         LLVMTypeRef to_scalar = LLVMGetTypeKind(type) == LLVMVectorTypeKind ?
                                    LLVMGetElementType(type) : type;
         LLVMTypeRef from_type = LLVMTypeOf(from);
         LLVMTypeRef from_scalar = LLVMGetTypeKind(from_type) == LLVMVectorTypeKind ?
                                      LLVMGetElementType(from_type) : from_type;
         bool to_int = LLVMGetTypeKind(to_scalar) == LLVMIntegerTypeKind;
         bool from_int = LLVMGetTypeKind(from_scalar) == LLVMIntegerTypeKind;
         /* True converting to a bool, from any nonzero value. */
         bool to_bool = to_int && LLVMGetIntTypeWidth(to_scalar) == 1;
         LLVMValueRef zero = LLVMConstNull(from_type), cast;
         if (to_bool && from_int)
            cast = LLVMBuildICmp(builder, LLVMIntNE, from, zero, "");
         else if (to_bool)
            cast = LLVMBuildFCmp(builder, LLVMRealUNE, from, zero, "");
         else if (to_int && from_int)
            cast = LLVMBuildIntCast2(builder, from, type, from_signed, "");
         else if (to_int)
            cast = to_signed ? LLVMBuildFPToSI(builder, from, type, "") :
                               LLVMBuildFPToUI(builder, from, type, "");
         else if (from_int)
            cast = from_signed ? LLVMBuildSIToFP(builder, from, type, "") :
                                 LLVMBuildUIToFP(builder, from, type, "");
         else
            cast = LLVMBuildFPCast(builder, from, type, "");
         LLVMReplaceAllUsesWith(call, cast);
         LLVMInstructionEraseFromParent(call);
      }
   }
   LLVMDisposeBuilder(builder);
}

/* Whether the global optimizer left no constructor in the clone. */
static bool
constructed(LLVMModuleRef clone)
{
   LLVMValueRef list = LLVMGetNamedGlobal(clone, "llvm.global_ctors");
   LLVMValueRef entries = list ? LLVMGetInitializer(list) : NULL;
   return !list || (entries && LLVMGetTypeKind(LLVMTypeOf(entries)) == LLVMArrayTypeKind &&
                    !LLVMGetArrayLength2(LLVMTypeOf(entries)));
}

bool
stela_air_construct_constants(struct stela_air_metadata *m)
{
   LLVMValueRef constructors = stela_air_metadata_constructors(m->module);
   if (!constructors)
      return true;
   LLVMValueRef entries = LLVMGetInitializer(constructors);
   unsigned functions = LLVMGetArrayLength2(LLVMTypeOf(entries));
   if (functions > AIR_MAX_ARGUMENTS)
      return fail(m, STELA_AIR_LIMIT, "constructor count exceeded");
   /* The globals constructors may store, paired with the clone's; those stay
    * defined there, so the optimizer keeps them and only commits their
    * values. */
   LLVMModuleRef clone = LLVMCloneModule(m->module);
   if (!clone)
      return fail(m, STELA_AIR_ALLOCATION, "module clone allocation failed");
   LLVMValueRef originals[AIR_MAX_ARGUMENTS], copies[AIR_MAX_ARGUMENTS];
   unsigned count = 0;
   bool evaluated = true;
   for (LLVMValueRef global = LLVMGetFirstGlobal(m->module), copy = LLVMGetFirstGlobal(clone);
        global && copy && evaluated; global = LLVMGetNextGlobal(global), copy = LLVMGetNextGlobal(copy)) {
      if (!stela_air_metadata_constructed(global))
         continue;
      evaluated = count < AIR_MAX_ARGUMENTS;
      originals[count] = global;
      copies[count++] = copy;
      LLVMSetLinkage(copy, LLVMExternalLinkage);
   }
   cast_conversions(clone);
   LLVMPassBuilderOptionsRef options = evaluated ? LLVMCreatePassBuilderOptions() : NULL;
   LLVMErrorRef error = options ? LLVMRunPasses(clone, "globalopt", NULL, options) : NULL;
   if (options)
      LLVMDisposePassBuilderOptions(options);
   if (error) {
      LLVMDisposeErrorMessage(LLVMGetErrorMessage(error));
      evaluated = false;
   }
   evaluated &= options && constructed(clone);
   LLVMValueRef values[AIR_MAX_ARGUMENTS];
   for (unsigned i = 0; evaluated && i < count; i++)
      evaluated = plain(values[i] = LLVMGetInitializer(copies[i]), 0);
   /* The values are the context's, which outlives the clone. */
   LLVMDisposeModule(clone);
   if (!evaluated)
      return fail(m, STELA_AIR_INSTRUCTION,
                  "program-scope constants depend on more than function constants");
   for (unsigned i = 0; i < count; i++) {
      LLVMSetInitializer(originals[i], values[i]);
      LLVMSetGlobalConstant(originals[i], true);
   }
   LLVMValueRef dropped[AIR_MAX_ARGUMENTS];
   for (unsigned i = 0; i < functions; i++)
      dropped[i] = LLVMGetOperand(LLVMGetAggregateElement(entries, i), 1);
   LLVMDeleteGlobal(constructors);
   for (unsigned i = 0; i < functions; i++) {
      bool listed = false;
      for (unsigned j = 0; j < i; j++)
         listed |= dropped[j] == dropped[i];
      if (!listed && !LLVMGetFirstUse(dropped[i]))
         LLVMDeleteFunction(dropped[i]);
   }
   return true;
}

static bool
fold(struct stela_air_metadata *m, LLVMValueRef fn)
{
   LLVMPassBuilderOptionsRef options = LLVMCreatePassBuilderOptions();
   if (!options)
      return fail(m, STELA_AIR_ALLOCATION, "LLVM pass options allocation failed");
   /* SCCP folds the loads of constant data and the branches and selects they
    * decide, leaving the paths those disable unreachable and what only they
    * read dead, such as an absent argument's load hoisted out of a branch.
    * InstSimplify removes a select SCCP decided for a value it cannot name,
    * such as a function constant's choice of a buffer over a constant.
    * Unoptimized code also leaves what must be constant computed, such as a
    * barrier's memory flags. */
   LLVMErrorRef error = LLVMRunPassesOnFunction(fn, "sccp,instsimplify,unreachableblockelim,dce", NULL, options);
   LLVMDisposePassBuilderOptions(options);
   if (error) {
      LLVMDisposeErrorMessage(LLVMGetErrorMessage(error));
      return fail(m, STELA_AIR_INSTRUCTION, "function constant folding failed");
   }
   return true;
}

bool
stela_air_fold_constants(struct stela_air_metadata *m, LLVMValueRef fn)
{
   if (!m->unoptimized && !LLVMGetNamedMetadataNumOperands(m->module, "air.function_constants"))
      return true;
   return fold(m, fn);
}

/* Whether pointer is null or off null, whichever way selects and PHIs go. */
static bool
null_rooted(LLVMValueRef pointer, unsigned depth)
{
   if (LLVMIsAConstantPointerNull(pointer))
      return true;
   if (!depth)
      return false;
   if (LLVMIsAConstantExpr(pointer))
      return LLVMGetConstOpcode(pointer) == LLVMGetElementPtr &&
             null_rooted(LLVMGetOperand(pointer, 0), depth - 1);
   if (!LLVMIsAInstruction(pointer))
      return false;
   switch (LLVMGetInstructionOpcode(pointer)) {
   case LLVMGetElementPtr:
   case LLVMBitCast:
      return null_rooted(LLVMGetOperand(pointer, 0), depth - 1);
   case LLVMSelect:
      return null_rooted(LLVMGetOperand(pointer, 1), depth - 1) &&
             null_rooted(LLVMGetOperand(pointer, 2), depth - 1);
   case LLVMPHI:
      for (unsigned i = 0; i < LLVMCountIncoming(pointer); i++) {
         if (!null_rooted(LLVMGetIncomingValue(pointer, i), depth - 1))
            return false;
      }
      return true;
   default:
      return false;
   }
}

static bool
accesses_null(LLVMBasicBlockRef block)
{
   for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst;
        inst = LLVMGetNextInstruction(inst)) {
      LLVMValueRef pointer = LLVMIsALoadInst(inst) ? LLVMGetOperand(inst, 0) :
                             LLVMIsAStoreInst(inst) ? LLVMGetOperand(inst, 1) : NULL;
      if (pointer && null_rooted(pointer, 8))
         return true;
   }
   return false;
}

/* Turns every branch toward a block that must access null, of one that may
 * not, away from it. An access no branch avoids stays, and reads zero. */
static bool
avoid_null(struct stela_air_metadata *m, LLVMValueRef fn, bool *avoided)
{
   struct set *undefined = _mesa_pointer_set_create(NULL);
   if (!undefined)
      return fail(m, STELA_AIR_ALLOCATION, "null access set allocation failed");
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block)) {
      if (accesses_null(block))
         _mesa_set_add(undefined, block);
   }
   bool grew = undefined->entries != 0;
   while (grew) {
      grew = false;
      for (LLVMBasicBlockRef block = LLVMGetLastBasicBlock(fn); block;
           block = LLVMGetPreviousBasicBlock(block)) {
         LLVMValueRef end = LLVMGetBasicBlockTerminator(block);
         unsigned successors = LLVMGetNumSuccessors(end);
         bool all = successors && !_mesa_set_search(undefined, block);
         for (unsigned i = 0; all && i < successors; i++)
            all = _mesa_set_search(undefined, LLVMGetSuccessor(end, i));
         if (all) {
            _mesa_set_add(undefined, block);
            grew = true;
         }
      }
   }
   LLVMTypeRef flag = LLVMInt1TypeInContext(LLVMGetModuleContext(m->module));
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); undefined->entries && block;
        block = LLVMGetNextBasicBlock(block)) {
      LLVMValueRef end = LLVMGetBasicBlockTerminator(block);
      if (LLVMGetInstructionOpcode(end) != LLVMCondBr)
         continue;
      bool taken = _mesa_set_search(undefined, LLVMGetSuccessor(end, 0));
      bool otherwise = _mesa_set_search(undefined, LLVMGetSuccessor(end, 1));
      if (taken != otherwise) {
         LLVMSetCondition(end, LLVMConstInt(flag, otherwise, false));
         *avoided = true;
      }
   }
   _mesa_set_destroy(undefined, NULL);
   return true;
}

bool
stela_air_fold_absent(struct stela_air_metadata *m, LLVMValueRef fn,
                      const struct stela_air_argument *arguments, unsigned count)
{
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef value = arguments[i].value;
      if (arguments[i].absent && arguments[i].is_buffer)
         LLVMReplaceAllUsesWith(value, LLVMConstPointerNull(LLVMTypeOf(value)));
   }
   bool avoided = false;
   return avoid_null(m, fn, &avoided) && (!avoided || fold(m, fn));
}
