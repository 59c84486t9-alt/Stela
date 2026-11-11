/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Calls between the module's functions. Apple's compiler inlines most
 * functions but keeps [[noinline]] and visible functions out of line, while
 * translation lowers one function. Each call to a function the module
 * defines is inlined by LLVM's always-inline pass, bottom-up, so the
 * callee's own calls are inlined first.
 *
 * Metal permits recursion only through function tables, and a pipeline's
 * maxCallStackDepth bounds how deeply those calls nest: Metal reserves each
 * thread's stack for that depth. Recursion therefore unrolls into the entry
 * one call through a table at a time, to that depth; a call nested deeper
 * calls none, as a call of an unknown handle does. Recursion that no table
 * call breaks is refused.
 *
 * A pipeline links its linked functions' libraries and its dynamic libraries
 * into the function's module. A visible function table is device memory of
 * 64-bit handles: handle i + 1 names the pipeline's linked function i, and
 * zero none. A call through a table's pointer becomes a call of a dispatcher,
 * an internal function that switches over the handle to the linked functions
 * of the call's type, which inlining then expands in place. */
#define STELA_AIR_METADATA_INTERNAL
#include "air_calls.h"
#include "air_constants.h"
#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/Linker.h"
#include "llvm-c/Transforms/PassBuilder.h"
#include "util/hash_table.h"
#include "util/set.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

/* Beyond any call chain Metal compiles, it bounds the walk of hostile input,
 * and the depth recursion unrolls to. */
#define MAX_CALL_DEPTH 256u
/* The attribute marking a dispatcher. */
#define DISPATCHER "stela.dispatcher"
/* The function types a function calls through tables. */
#define MAX_DISPATCH_TYPES 64u
#define MAX_NAME_BYTES 4096u

enum state { ACTIVE = 1, ACYCLIC, CYCLIC };

static bool
fail(struct stela_air_metadata *m, enum stela_air_error_kind kind, const char *detail)
{
   if (m->error->kind == STELA_AIR_OK) {
      m->error->kind = kind;
      snprintf(m->error->detail, sizeof(m->error->detail), "%s", detail);
   }
   return false;
}

bool
stela_air_defined_function(LLVMValueRef fn)
{
   size_t bytes;
   const char *name = LLVMIsAFunction(fn) ? LLVMGetValueName2(fn, &bytes) : NULL;
   return name && !LLVMIsDeclaration(fn) && (bytes < 4 || memcmp(name, "air.", 4));
}

/* The function inst calls, when the module defines it. */
static LLVMValueRef
defined_callee(LLVMValueRef inst)
{
   LLVMValueRef callee = LLVMIsACallInst(inst) ? LLVMGetCalledValue(inst) : NULL;
   return callee && stela_air_defined_function(callee) ? callee : NULL;
}

/* Whether fn dispatches calls through function tables. */
static bool
is_dispatcher(LLVMValueRef fn)
{
   return LLVMGetStringAttributeAtIndex(fn, LLVMAttributeFunctionIndex, DISPATCHER,
                                        strlen(DISPATCHER)) != NULL;
}

/* Records in states whether fn's calls reach a cycle, and each function's
 * they reach; *cyclic receives fn's. Calls of dispatchers count unless
 * tables is false. */
static bool
visit(struct stela_air_metadata *m, struct hash_table *states, LLVMValueRef fn, bool tables,
      unsigned depth, bool *cyclic)
{
   struct hash_entry *entry = _mesa_hash_table_search(states, fn);
   if (entry) {
      /* A function still active is its own caller. */
      *cyclic = (uintptr_t)entry->data != ACYCLIC;
      return true;
   }
   if (depth == MAX_CALL_DEPTH)
      return fail(m, STELA_AIR_LIMIT, "call depth exceeded");
   if (!_mesa_hash_table_insert(states, fn, (void *)(uintptr_t)ACTIVE))
      return fail(m, STELA_AIR_ALLOCATION, "call graph allocation failed");
   bool reaches = false;
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block)) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst;
           inst = LLVMGetNextInstruction(inst)) {
         LLVMValueRef callee = defined_callee(inst);
         if (callee && !tables && is_dispatcher(callee))
            callee = NULL;
         bool reached = false;
         if (callee && !visit(m, states, callee, tables, depth + 1, &reached))
            return false;
         reaches |= callee && reached;
      }
   }
   _mesa_hash_table_search(states, fn)->data = (void *)(uintptr_t)(reaches ? CYCLIC : ACYCLIC);
   *cyclic = reaches;
   return true;
}

/* Whether a call calls fn. */
static bool
called(LLVMValueRef fn)
{
   for (LLVMUseRef use = LLVMGetFirstUse(fn); use; use = LLVMGetNextUse(use)) {
      LLVMValueRef user = LLVMGetUser(use);
      if (LLVMIsACallInst(user) && LLVMGetCalledValue(user) == fn)
         return true;
   }
   return false;
}

bool
stela_air_has_defined_calls(LLVMModuleRef module)
{
   for (LLVMValueRef fn = LLVMGetFirstFunction(module); fn; fn = LLVMGetNextFunction(fn)) {
      if (stela_air_defined_function(fn) && called(fn))
         return true;
   }
   return false;
}

static unsigned
attribute(const char *name)
{
   return LLVMGetEnumAttributeKindForName(name, strlen(name));
}

/* Lets the inliner inline fn wherever a call allows it. */
static void
inline_always(LLVMValueRef fn)
{
   /* optnone requires noinline. */
   LLVMRemoveEnumAttributeAtIndex(fn, LLVMAttributeFunctionIndex, attribute("optnone"));
   LLVMRemoveEnumAttributeAtIndex(fn, LLVMAttributeFunctionIndex, attribute("noinline"));
   LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex,
                           LLVMCreateEnumAttribute(LLVMGetTypeContext(LLVMTypeOf(fn)),
                                                   attribute("alwaysinline"), 0));
}

static bool
run_inliner(struct stela_air_metadata *m)
{
   LLVMPassBuilderOptionsRef options = LLVMCreatePassBuilderOptions();
   if (!options)
      return fail(m, STELA_AIR_ALLOCATION, "pass options allocation failed");
   LLVMErrorRef error = LLVMRunPasses(m->module, "always-inline", NULL, options);
   LLVMDisposePassBuilderOptions(options);
   if (error) {
      LLVMDisposeErrorMessage(LLVMGetErrorMessage(error));
      return fail(m, STELA_AIR_INSTRUCTION, "LLVM refused to inline the module's calls");
   }
   return true;
}

/* Whether call may not be inlined. */
static bool
held(LLVMValueRef call)
{
   return LLVMGetCallSiteEnumAttribute(call, LLVMAttributeFunctionIndex, attribute("noinline"));
}

/* Keeps the inliner from inlining call. */
static void
hold(LLVMValueRef call)
{
   if (!held(call))
      LLVMAddCallSiteAttribute(call, LLVMAttributeFunctionIndex,
                               LLVMCreateEnumAttribute(LLVMGetTypeContext(LLVMTypeOf(call)),
                                                       attribute("noinline"), 0));
}

/* The entry's calls of defined functions: those of dispatchers or others,
 * held or released. */
struct entry_calls {
   unsigned dispatches, others, released, instructions;
};

static struct entry_calls
entry_calls(LLVMValueRef entry, unsigned limit)
{
   struct entry_calls calls = {0};
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(entry); block;
        block = LLVMGetNextBasicBlock(block)) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst && calls.instructions <= limit;
           inst = LLVMGetNextInstruction(inst)) {
         calls.instructions++;
         LLVMValueRef callee = defined_callee(inst);
         if (!callee)
            continue;
         if (is_dispatcher(callee))
            calls.dispatches++;
         else
            calls.others++;
         calls.released += !held(inst);
      }
   }
   return calls;
}

/* Releases the entry's held calls of dispatchers, or of other functions. */
static void
release(LLVMValueRef entry, bool dispatchers)
{
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(entry); block;
        block = LLVMGetNextBasicBlock(block)) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst; inst = LLVMGetNextInstruction(inst)) {
         LLVMValueRef callee = defined_callee(inst);
         if (callee && is_dispatcher(callee) == dispatchers)
            LLVMRemoveCallSiteEnumAttribute(inst, LLVMAttributeFunctionIndex, attribute("noinline"));
      }
   }
}

/* Replaces the entry's calls of dispatchers with calls of none, which
 * return zero. */
static void
drop_dispatches(LLVMValueRef entry)
{
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(entry); block;
        block = LLVMGetNextBasicBlock(block)) {
      LLVMValueRef next;
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst; inst = next) {
         next = LLVMGetNextInstruction(inst);
         LLVMValueRef callee = defined_callee(inst);
         if (!callee || !is_dispatcher(callee))
            continue;
         LLVMTypeRef type = LLVMTypeOf(inst);
         if (LLVMGetTypeKind(type) != LLVMVoidTypeKind)
            LLVMReplaceAllUsesWith(inst, LLVMConstNull(type));
         LLVMInstructionEraseFromParent(inst);
      }
   }
}

/* Unrolls the recursion the entry's calls reach to depth calls through
 * tables, within max_instructions. Every call of a defined function is held
 * and its callee inlined only where the entry releases it: first the calls
 * of one depth that are not through tables, then those through tables,
 * which bring the next depth's. */
static bool
unroll(struct stela_air_metadata *m, LLVMValueRef entry, unsigned depth, unsigned max_instructions)
{
   if (depth > MAX_CALL_DEPTH)
      return fail(m, STELA_AIR_LIMIT, "recursion's maximum call stack depth exceeded");
   struct hash_table *states = _mesa_pointer_hash_table_create(NULL);
   if (!states)
      return fail(m, STELA_AIR_ALLOCATION, "call graph allocation failed");
   bool cyclic = false, walked = visit(m, states, entry, false, 0, &cyclic);
   _mesa_hash_table_destroy(states, NULL);
   if (!walked)
      return false;
   if (cyclic)
      return fail(m, STELA_AIR_INSTRUCTION, "recursive calls outside function tables are unsupported");
   for (LLVMValueRef fn = LLVMGetFirstFunction(m->module); fn; fn = LLVMGetNextFunction(fn)) {
      for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
           block = LLVMGetNextBasicBlock(block)) {
         for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst;
              inst = LLVMGetNextInstruction(inst)) {
            LLVMValueRef callee = defined_callee(inst);
            if (callee) {
               hold(inst);
               inline_always(callee);
            }
         }
      }
   }
   for (unsigned level = 0;;) {
      struct entry_calls calls = entry_calls(entry, max_instructions);
      if (calls.instructions > max_instructions)
         return fail(m, STELA_AIR_LIMIT, "unrolled recursion exceeds the instruction budget");
      if (calls.released)
         return fail(m, STELA_AIR_INSTRUCTION, "LLVM refused to inline the module's calls");
      if (!calls.others && !calls.dispatches)
         return true;
      if (!calls.others && level == depth) {
         drop_dispatches(entry);
         return true;
      }
      level += !calls.others;
      release(entry, !calls.others);
      if (!run_inliner(m))
         return false;
   }
}

/* A branch can make a direct call unreachable after specialization. */
static bool
can_prune_calls(LLVMValueRef entry)
{
   bool branch = false, call = false;
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(entry); block;
        block = LLVMGetNextBasicBlock(block)) {
      LLVMOpcode opcode = LLVMGetInstructionOpcode(LLVMGetBasicBlockTerminator(block));
      branch |= opcode == LLVMCondBr || opcode == LLVMSwitch;
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst && !call;
           inst = LLVMGetNextInstruction(inst))
         call = defined_callee(inst) != NULL;
      if (branch && call)
         return true;
   }
   return false;
}

/* Makes each call of a defined function whose call type differs from the
 * definition's only in structs of the same layout call it with the
 * definition's type, converting its arguments and result. Linking keeps two
 * modules' copies of one struct distinct types (`T.3` and `T.127`), and a
 * call whose type is not its callee's never inlines: Core Image's stitched
 * graphs call one library's filter with the struct values another library's
 * functions build. */
static void
match_call_types(LLVMModuleRef module)
{
   LLVMContextRef context = LLVMGetModuleContext(module);
   LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
   for (LLVMValueRef fn = LLVMGetFirstFunction(module); fn; fn = LLVMGetNextFunction(fn)) {
      for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
           block = LLVMGetNextBasicBlock(block)) {
         LLVMValueRef next;
         for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst; inst = next) {
            next = LLVMGetNextInstruction(inst);
            LLVMValueRef callee = LLVMIsACallInst(inst) ? LLVMGetCalledValue(inst) : NULL;
            if (!callee || !LLVMIsAFunction(callee) || LLVMIsDeclaration(callee))
               continue;
            LLVMTypeRef want = LLVMGlobalGetValueType(callee), have = LLVMGetCalledFunctionType(inst);
            unsigned count = LLVMCountParamTypes(want);
            if (want == have || count != LLVMCountParamTypes(have) || count > 64 ||
                LLVMIsFunctionVarArg(want) != LLVMIsFunctionVarArg(have) ||
                LLVMGetNumArgOperands(inst) != count ||
                !stela_air_isomorphic(context, LLVMGetReturnType(want), LLVMGetReturnType(have)))
               continue;
            LLVMTypeRef wanted[64], had[64];
            LLVMGetParamTypes(want, wanted);
            LLVMGetParamTypes(have, had);
            bool same = true;
            for (unsigned i = 0; i < count && same; i++)
               same = stela_air_isomorphic(context, wanted[i], had[i]);
            if (!same)
               continue;
            LLVMPositionBuilderBefore(builder, inst);
            LLVMValueRef arguments[64];
            for (unsigned i = 0; i < count; i++)
               arguments[i] = stela_air_convert_layout(builder, LLVMGetOperand(inst, i), wanted[i]);
            LLVMValueRef call = LLVMBuildCall2(builder, want, callee, arguments, count, "");
            LLVMSetInstructionCallConv(call, LLVMGetInstructionCallConv(inst));
            if (LLVMGetTypeKind(LLVMGetReturnType(have)) != LLVMVoidTypeKind)
               LLVMReplaceAllUsesWith(inst, stela_air_convert_layout(builder, call,
                                                                     LLVMGetReturnType(have)));
            LLVMInstructionEraseFromParent(inst);
         }
      }
   }
   LLVMDisposeBuilder(builder);
}

/* Calls of one large function that follow each other.
 *
 * Apple's compiler keeps a [[noinline]] function's body once and calls it.
 * NAK takes no calls, so inlining copies the body to every call, and a
 * shader that calls one large function several times in a row grows by the
 * whole body per call: an interpreter applying a list of operations, or a
 * ray marcher taking several samples of a pixel. Calls of such a function
 * in one block instead share one call, run in a loop: the code before each
 * call branches to the shared call with that call's arguments and position,
 * and after the call a switch on the position continues with the code that
 * followed it. Each invocation entering the
 * block makes every call in order, so the invocations of a quad stay
 * together and derivatives and implicit-LOD samples in the body see the
 * same lanes as separate copies would. A value a later part of the block
 * reads passes through a stack slot, which SROA turns back into SSA.
 * Everything that can stop the rewrite is checked before it changes the
 * function, and what follows cannot refuse: a slot SROA leaves is thread
 * memory, which translation lowers like any other. */

/* Below this many instructions copies cost less than the loop: they keep
 * each call's constants folded, and the loop keeps the values its later
 * parts read live across every call. The size is about where an optimizing
 * inliner stops copying a function with several calls: sharing Setup's
 * 503-instruction distance function in its 4-sample normal estimate costs
 * 8 registers on NVIDIA and halves the shader's code (121 to 69 KB).
 * A function Apple's compiler keeps out of line is shared from a smaller
 * size, since its calls were not to be specialized. */
#define SHARED_CALL_MIN_INSTRUCTIONS 256u
#define SHARED_CALL_MIN_OUT_OF_LINE 64u
#define SHARED_CALL_MAX_INSTRUCTIONS (1u << 24)
#define SHARED_CALL_MAX_CALLS 64u

/* fn's instructions once its calls of defined functions are inlined. */
static uint64_t
inlined_size(struct hash_table *sizes, LLVMValueRef fn, unsigned depth)
{
   struct hash_entry *entry = _mesa_hash_table_search(sizes, fn);
   if (entry)
      return (uintptr_t)entry->data;
   uint64_t size = 0;
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block)) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst;
           inst = LLVMGetNextInstruction(inst)) {
         LLVMValueRef callee = defined_callee(inst);
         size += callee && callee != fn && depth < MAX_CALL_DEPTH ?
                    inlined_size(sizes, callee, depth + 1) : 1;
         size = MIN2(size, SHARED_CALL_MAX_INSTRUCTIONS);
      }
   }
   _mesa_hash_table_insert(sizes, fn, (void *)(uintptr_t)size);
   return size;
}

/* A block's calls of one function. The code before calls[0] is part 0 and
 * the code after calls[i] part i + 1; parts maps each instruction of the
 * block to the part it reads its operands in, plus one. A call reads them
 * at the end of the part before it, and its result exists in the next. */
struct shared_calls {
   LLVMBasicBlockRef block;
   LLVMValueRef callee;
   LLVMValueRef calls[SHARED_CALL_MAX_CALLS];
   unsigned count;
   struct hash_table *parts;
};

static bool
shared_call(const struct shared_calls *s, LLVMValueRef inst)
{
   for (unsigned i = 0; i < s->count; i++) {
      if (s->calls[i] == inst)
         return true;
   }
   return false;
}

/* Where user reads its operands; anything outside the block, after its
 * last part. */
static unsigned
reading_part(const struct shared_calls *s, LLVMValueRef user)
{
   struct hash_entry *entry = _mesa_hash_table_search(s->parts, user);
   return entry ? (uintptr_t)entry->data - 1 : s->count;
}

/* Whether a use reads a value of part `part` where that part does not
 * dominate: every part follows part 0, and only the last part comes after
 * the block. */
static bool
crosses(const struct shared_calls *s, LLVMUseRef use, unsigned part)
{
   return part && reading_part(s, LLVMGetUser(use)) != part;
}

/* Whether a value of the type is or holds a pointer. */
static bool
holds_pointer(LLVMTypeRef type, unsigned depth)
{
   switch (LLVMGetTypeKind(type)) {
   case LLVMPointerTypeKind:
      return true;
   case LLVMVectorTypeKind:
   case LLVMArrayTypeKind:
      return depth > 64 || holds_pointer(LLVMGetElementType(type), depth + 1);
   case LLVMStructTypeKind:
      for (unsigned i = 0; i < LLVMCountStructElementTypes(type); i++) {
         if (depth > 64 || holds_pointer(LLVMStructGetTypeAtIndex(type, i), depth + 1))
            return true;
      }
      return false;
   default:
      return false;
   }
}

/* Whether a pointer may be a constant or an offset or cast of one: either
 * of a select's, which specialization may fold to it. */
static bool
constant_based(LLVMValueRef pointer, unsigned depth)
{
   if (depth > 64 || LLVMIsConstant(pointer))
      return true;
   if (LLVMIsASelectInst(pointer))
      return constant_based(LLVMGetOperand(pointer, 1), depth + 1) ||
             constant_based(LLVMGetOperand(pointer, 2), depth + 1);
   if (LLVMIsAGetElementPtrInst(pointer) || LLVMIsABitCastInst(pointer) ||
       LLVMIsAAddrSpaceCastInst(pointer))
      return constant_based(LLVMGetOperand(pointer, 0), depth + 1);
   return false;
}

/* Whether a pointer is stored, or memory copied, through `address` or an
 * offset or cast of it. */
static bool
stored_pointer(LLVMValueRef address, unsigned depth)
{
   if (depth > 16)
      return true;
   for (LLVMUseRef use = LLVMGetFirstUse(address); use; use = LLVMGetNextUse(use)) {
      LLVMValueRef user = LLVMGetUser(use);
      if (LLVMIsAStoreInst(user)) {
         if (LLVMGetOperand(user, 1) == address &&
             holds_pointer(LLVMTypeOf(LLVMGetOperand(user, 0)), 0))
            return true;
      } else if (LLVMIsAGetElementPtrInst(user) || LLVMIsABitCastInst(user) ||
                 LLVMIsAAddrSpaceCastInst(user) || LLVMIsASelectInst(user) || LLVMIsAPHINode(user)) {
         if (stored_pointer(user, depth + 1))
            return true;
      } else if (LLVMIsACallInst(user)) {
         LLVMValueRef callee = LLVMGetCalledValue(user);
         unsigned id = LLVMIsAFunction(callee) ? LLVMGetIntrinsicID(callee) : 0;
         static const char *const copies[] = {"llvm.memcpy", "llvm.memmove", "llvm.memcpy.inline"};
         for (unsigned i = 0; id && i < ARRAY_SIZE(copies); i++) {
            if (id == LLVMLookupIntrinsicID(copies[i], strlen(copies[i])) &&
                LLVMGetOperand(user, 0) == address)
               return true;
         }
      }
   }
   return false;
}

/* Whether `pointer` may address thread memory that holds a pointer. A PHI
 * of the shared call's arguments would select such memory, which SROA then
 * cannot promote, and translation keeps no pointer in memory. Thread memory
 * other than a known stack slot may hold anything. */
static bool
thread_pointer_memory(LLVMValueRef pointer, unsigned depth)
{
   LLVMTypeRef type = LLVMTypeOf(pointer);
   if (LLVMGetTypeKind(type) != LLVMPointerTypeKind || LLVMGetPointerAddressSpace(type))
      return false;
   if (depth > 16)
      return true;
   if (LLVMIsConstant(pointer))
      return false;
   if (LLVMIsAAllocaInst(pointer))
      return holds_pointer(LLVMGetAllocatedType(pointer), 0) || stored_pointer(pointer, 0);
   if (LLVMIsAGetElementPtrInst(pointer) || LLVMIsABitCastInst(pointer))
      return thread_pointer_memory(LLVMGetOperand(pointer, 0), depth + 1);
   if (LLVMIsASelectInst(pointer))
      return thread_pointer_memory(LLVMGetOperand(pointer, 1), depth + 1) ||
             thread_pointer_memory(LLVMGetOperand(pointer, 2), depth + 1);
   if (LLVMIsAPHINode(pointer)) {
      for (unsigned i = 0; i < LLVMCountIncoming(pointer); i++) {
         if (thread_pointer_memory(LLVMGetIncomingValue(pointer, i), depth + 1))
            return true;
      }
      return false;
   }
   return true;
}

/* Gives each value of the block that a use in another part reads a stack
 * slot, which those uses load; with apply false, only checks that each
 * such value can have one. */
static bool
spill_crossing(LLVMBuilderRef builder, LLVMValueRef fn, const struct shared_calls *s, bool apply)
{
   LLVMValueRef next;
   for (LLVMValueRef inst = LLVMGetFirstInstruction(s->block); inst; inst = next) {
      next = LLVMGetNextInstruction(inst);
      struct hash_entry *entry = _mesa_hash_table_search(s->parts, inst);
      if (!entry)
         continue; /* A load or store this added. */
      unsigned part = (uintptr_t)entry->data - 1 + shared_call(s, inst);
      bool crossing = false;
      for (LLVMUseRef use = LLVMGetFirstUse(inst); use && !crossing; use = LLVMGetNextUse(use))
         crossing = crosses(s, use, part);
      if (!crossing)
         continue;
      LLVMTypeRef type = LLVMTypeOf(inst);
      LLVMTypeKind kind = LLVMGetTypeKind(type);
      if (kind == LLVMTokenTypeKind || kind == LLVMLabelTypeKind ||
          kind == LLVMMetadataTypeKind || !LLVMTypeIsSized(type))
         return false;
      /* Translation joins pointers in PHIs by the resource each was proven
       * to reach, which a struct or array holding one would hide. */
      bool pointer = kind == LLVMPointerTypeKind ||
                     (kind == LLVMVectorTypeKind &&
                      LLVMGetTypeKind(LLVMGetElementType(type)) == LLVMPointerTypeKind);
      if (!pointer && holds_pointer(type, 0))
         return false;
      if (!apply)
         continue;
      /* Zero before the first store, which the loop's first trip reads
       * nothing of, keeps every value defined. A pointer starts undefined:
       * a null pointer would be one more resource its PHIs join. */
      LLVMPositionBuilderBefore(builder, LLVMGetFirstInstruction(LLVMGetEntryBasicBlock(fn)));
      LLVMValueRef slot = LLVMBuildAlloca(builder, type, "");
      LLVMBuildStore(builder, pointer ? LLVMGetUndef(type) : LLVMConstNull(type), slot);
      for (LLVMUseRef use = LLVMGetFirstUse(inst); use;) {
         LLVMValueRef user = LLVMGetUser(use);
         if (!crosses(s, use, part)) {
            use = LLVMGetNextUse(use);
            continue;
         }
         /* A phi reads at the end of each incoming block of this value. */
         unsigned operands = LLVMIsAPHINode(user) ? LLVMCountIncoming(user) : LLVMGetNumOperands(user);
         for (unsigned k = 0; k < operands; k++) {
            if (LLVMGetOperand(user, k) != inst)
               continue;
            LLVMPositionBuilderBefore(builder, LLVMIsAPHINode(user) ?
               LLVMGetBasicBlockTerminator(LLVMGetIncomingBlock(user, k)) : user);
            LLVMSetOperand(user, k, LLVMBuildLoad2(builder, type, slot, ""));
         }
         use = LLVMGetFirstUse(inst);
      }
      /* After a call, its result is stored where the next part begins. */
      LLVMPositionBuilderBefore(builder, next);
      LLVMBuildStore(builder, inst, slot);
   }
   return true;
}

/* Turns the block's calls into one call in a loop (see above). The
 * block's predecessors keep branching to it, and its part 0 stays in it. */
static void
share_calls(LLVMBuilderRef builder, LLVMValueRef fn, const struct shared_calls *s)
{
   LLVMContextRef context = LLVMGetTypeContext(LLVMTypeOf(fn));
   LLVMTypeRef i32 = LLVMInt32TypeInContext(context);
   unsigned n = s->count;
   LLVMBasicBlockRef next_block = LLVMGetNextBasicBlock(s->block), parts[SHARED_CALL_MAX_CALLS + 1];
   LLVMBasicBlockRef call_block = next_block ?
      LLVMInsertBasicBlockInContext(context, next_block, "shared.call") :
      LLVMAppendBasicBlockInContext(context, fn, "shared.call");
   parts[0] = s->block;
   for (unsigned i = 1; i <= n; i++) {
      parts[i] = next_block ? LLVMInsertBasicBlockInContext(context, next_block, "shared.part") :
                              LLVMAppendBasicBlockInContext(context, fn, "shared.part");
   }
   /* The block's successors now follow its last part, and its
    * predecessors still branch to it. */
   LLVMValueRef predecessors[256];
   unsigned predecessor_count = 0;
   for (LLVMUseRef use = LLVMGetFirstUse(LLVMBasicBlockAsValue(s->block)); use; use = LLVMGetNextUse(use))
      predecessors[predecessor_count++] = LLVMGetUser(use);
   LLVMReplaceAllUsesWith(LLVMBasicBlockAsValue(s->block), LLVMBasicBlockAsValue(parts[n]));
   for (unsigned i = 0; i < predecessor_count; i++) {
      for (unsigned k = 0; k < LLVMGetNumSuccessors(predecessors[i]); k++) {
         if (LLVMGetSuccessor(predecessors[i], k) == parts[n])
            LLVMSetSuccessor(predecessors[i], k, s->block);
      }
   }
   /* Each part's code moves to its block; the calls stay to be replaced. */
   unsigned part = 0;
   LLVMValueRef next;
   for (LLVMValueRef inst = LLVMGetFirstInstruction(s->block); inst; inst = next) {
      next = LLVMGetNextInstruction(inst);
      if (shared_call(s, inst)) {
         part++;
         continue;
      }
      if (!part)
         continue;
      LLVMInstructionRemoveFromParent(inst);
      LLVMPositionBuilderAtEnd(builder, parts[part]);
      LLVMInsertIntoBuilder(builder, inst);
   }
   for (unsigned i = 0; i < n; i++) {
      LLVMPositionBuilderAtEnd(builder, parts[i]);
      LLVMBuildBr(builder, call_block);
   }
   /* The shared call takes each call's position and differing arguments. */
   LLVMPositionBuilderAtEnd(builder, call_block);
   LLVMValueRef position = LLVMBuildPhi(builder, i32, "");
   unsigned argument_count = LLVMGetNumArgOperands(s->calls[0]);
   LLVMValueRef arguments[64];
   for (unsigned a = 0; a < argument_count; a++) {
      LLVMValueRef first = LLVMGetOperand(s->calls[0], a);
      bool same = true;
      for (unsigned i = 1; i < n && same; i++)
         same = LLVMGetOperand(s->calls[i], a) == first;
      arguments[a] = same ? first : LLVMBuildPhi(builder, LLVMTypeOf(first), "");
   }
   for (unsigned i = 0; i < n; i++) {
      LLVMValueRef index = LLVMConstInt(i32, i, false);
      LLVMBasicBlockRef from = parts[i];
      LLVMAddIncoming(position, &index, &from, 1);
      for (unsigned a = 0; a < argument_count; a++) {
         if (LLVMIsAPHINode(arguments[a]) && LLVMGetInstructionParent(arguments[a]) == call_block) {
            LLVMValueRef value = LLVMGetOperand(s->calls[i], a);
            LLVMAddIncoming(arguments[a], &value, &from, 1);
         }
      }
   }
   LLVMValueRef call = LLVMBuildCall2(builder, LLVMGlobalGetValueType(s->callee), s->callee,
                                      arguments, argument_count, "");
   LLVMSetInstructionCallConv(call, LLVMGetInstructionCallConv(s->calls[0]));
   unsigned attributes = LLVMGetCallSiteAttributeCount(s->calls[0], LLVMAttributeFunctionIndex);
   LLVMAttributeRef attribute_list[64];
   if (attributes <= ARRAY_SIZE(attribute_list)) {
      LLVMGetCallSiteAttributes(s->calls[0], LLVMAttributeFunctionIndex, attribute_list);
      for (unsigned i = 0; i < attributes; i++)
         LLVMAddCallSiteAttribute(call, LLVMAttributeFunctionIndex, attribute_list[i]);
   }
   if (LLVMCanValueUseFastMathFlags(s->calls[0]))
      LLVMSetFastMathFlags(call, LLVMGetFastMathFlags(s->calls[0]));
   LLVMValueRef dispatch = LLVMBuildSwitch(builder, position, parts[n], n - 1);
   for (unsigned i = 0; i + 1 < n; i++)
      LLVMAddCase(dispatch, LLVMConstInt(i32, i, false), parts[i + 1]);
   for (unsigned i = 0; i < n; i++) {
      if (LLVMGetTypeKind(LLVMTypeOf(s->calls[i])) != LLVMVoidTypeKind)
         LLVMReplaceAllUsesWith(s->calls[i], call);
      LLVMInstructionEraseFromParent(s->calls[i]);
   }
}

/* Whether block's calls of callee may share one call: neither branches to
 * the block itself, which its last part would then reach, nor takes its
 * address. */
static bool
gather_calls(struct shared_calls *s, LLVMBasicBlockRef block, LLVMValueRef callee)
{
   LLVMValueRef term = LLVMGetBasicBlockTerminator(block);
   for (unsigned k = 0; term && k < LLVMGetNumSuccessors(term); k++) {
      if (LLVMGetSuccessor(term, k) == block)
         return false;
   }
   unsigned users = 0;
   for (LLVMUseRef use = LLVMGetFirstUse(LLVMBasicBlockAsValue(block)); use; use = LLVMGetNextUse(use)) {
      if (!LLVMIsATerminatorInst(LLVMGetUser(use)) || ++users > 256)
         return false;
   }
   s->block = block;
   s->callee = callee;
   s->count = 0;
   _mesa_hash_table_clear(s->parts, NULL);
   for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst; inst = LLVMGetNextInstruction(inst)) {
      _mesa_hash_table_insert(s->parts, inst, (void *)(uintptr_t)(s->count + 1));
      if (defined_callee(inst) == callee) {
         if (s->count == SHARED_CALL_MAX_CALLS || LLVMGetNumOperandBundles(inst) ||
             LLVMGetCalledFunctionType(inst) != LLVMGlobalGetValueType(callee) ||
             LLVMGetNumArgOperands(inst) > 64 ||
             LLVMGetTailCallKind(inst) == LLVMTailCallKindMustTail)
            return false;
         s->calls[s->count++] = inst;
      }
   }
   if (s->count < 2)
      return false;
   /* The shared call takes each differing argument through a PHI, where
    * translation joins pointers by the resource each was proven to reach.
    * A constant pointer (null: a buffer a function constant left out) and
    * offsets off it have no such proof, nor has one inside a struct or
    * array. A select may still fold to one. Nor may the PHI select thread
    * memory holding pointers (MPS kernels pass each call its own struct of
    * buffer addresses), which SROA could then not promote. */
   for (unsigned a = 0; a < LLVMGetNumArgOperands(s->calls[0]); a++) {
      LLVMValueRef first = LLVMGetOperand(s->calls[0], a);
      if (!holds_pointer(LLVMTypeOf(first), 0))
         continue;
      bool same = true;
      for (unsigned i = 1; i < s->count && same; i++)
         same = LLVMGetOperand(s->calls[i], a) == first;
      if (same)
         continue;
      if (LLVMGetTypeKind(LLVMTypeOf(first)) != LLVMPointerTypeKind)
         return false;
      for (unsigned i = 0; i < s->count; i++) {
         if (constant_based(LLVMGetOperand(s->calls[i], a), 0) ||
             thread_pointer_memory(LLVMGetOperand(s->calls[i], a), 0))
            return false;
      }
   }
   return true;
}

/* Shares the calls of each function in shareable, which maps it to its
 * least size, that one block makes more than once, then rebuilds SSA
 * values from the stack slots. */
static bool
share_repeated_calls(struct stela_air_metadata *m, struct hash_table *shareable)
{
   if (!shareable->entries)
      return true;
   struct hash_table *sizes = _mesa_pointer_hash_table_create(NULL);
   struct shared_calls s = {.parts = _mesa_pointer_hash_table_create(NULL)};
   LLVMBuilderRef builder = LLVMCreateBuilderInContext(LLVMGetModuleContext(m->module));
   bool ok = sizes && s.parts && builder;
   for (LLVMValueRef fn = LLVMGetFirstFunction(m->module); fn && ok; fn = LLVMGetNextFunction(fn)) {
      if (!stela_air_defined_function(fn) ||
          LLVMGetEnumAttributeAtIndex(fn, LLVMAttributeFunctionIndex, attribute("optnone")))
         continue;
      bool shared = false;
      for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
           block = LLVMGetNextBasicBlock(block)) {
         hash_table_foreach(shareable, entry) {
            LLVMValueRef callee = (LLVMValueRef)entry->key;
            if (callee == fn || inlined_size(sizes, callee, 0) < (uintptr_t)entry->data ||
                !gather_calls(&s, block, callee) || !spill_crossing(builder, fn, &s, false))
               continue;
            spill_crossing(builder, fn, &s, true);
            share_calls(builder, fn, &s);
            shared = true;
            /* The block now ends at the branch to the shared call. */
            break;
         }
      }
      /* Stela's LLVM (compat/llvm/passes.cpp) runs only the passes
       * translation names, SROA among them. */
      LLVMPassBuilderOptionsRef options = shared ? LLVMCreatePassBuilderOptions() : NULL;
      LLVMErrorRef error = options ? LLVMRunPassesOnFunction(fn, "sroa", NULL, options) : NULL;
      if (options)
         LLVMDisposePassBuilderOptions(options);
      if (error)
         LLVMDisposeErrorMessage(LLVMGetErrorMessage(error));
   }
   if (builder)
      LLVMDisposeBuilder(builder);
   _mesa_hash_table_destroy(sizes, NULL);
   _mesa_hash_table_destroy(s.parts, NULL);
   return ok || fail(m, STELA_AIR_ALLOCATION, "shared call allocation failed");
}

/* Promotes what inlining made promotable: a thread variable whose address
 * a call took (Apple's compiler keeps a [[noinline]] function's `thread T&`
 * argument in memory) is only loaded and stored once the call is inlined,
 * and would otherwise stay thread memory. An optimizing pipeline runs SROA
 * after its inliner for the same reason. An unoptimized module's memory is
 * the translator's to promote (promote_memory in air_to_nir.c). */
static bool
promote_inlined_memory(struct stela_air_metadata *m)
{
   if (m->unoptimized)
      return true;
   LLVMPassBuilderOptionsRef options = NULL;
   for (LLVMValueRef fn = LLVMGetFirstFunction(m->module); fn; fn = LLVMGetNextFunction(fn)) {
      LLVMBasicBlockRef entry = stela_air_defined_function(fn) ? LLVMGetEntryBasicBlock(fn) : NULL;
      bool allocates = false;
      for (LLVMValueRef inst = entry ? LLVMGetFirstInstruction(entry) : NULL; inst && !allocates;
           inst = LLVMGetNextInstruction(inst))
         allocates = LLVMIsAAllocaInst(inst) != NULL;
      if (!allocates)
         continue;
      if (!options && !(options = LLVMCreatePassBuilderOptions()))
         return fail(m, STELA_AIR_ALLOCATION, "pass options allocation failed");
      LLVMErrorRef error = LLVMRunPassesOnFunction(fn, "sroa", NULL, options);
      if (error) {
         LLVMDisposeErrorMessage(LLVMGetErrorMessage(error));
         LLVMDisposePassBuilderOptions(options);
         return fail(m, STELA_AIR_INSTRUCTION, "LLVM refused to promote inlined memory");
      }
   }
   if (options)
      LLVMDisposePassBuilderOptions(options);
   return true;
}

static bool
inline_calls(struct stela_air_metadata *m, LLVMValueRef entry, unsigned max_call_stack_depth,
             unsigned max_instructions, LLVMValueRef specialized, bool *folded)
{
   match_call_types(m->module);
   struct hash_table *states = _mesa_pointer_hash_table_create(NULL);
   if (!states)
      return fail(m, STELA_AIR_ALLOCATION, "call graph allocation failed");
   bool walked = true, inlined = false, recursive = false;
   for (LLVMValueRef fn = LLVMGetFirstFunction(m->module); fn && walked; fn = LLVMGetNextFunction(fn)) {
      m->unoptimized |= LLVMGetEnumAttributeAtIndex(fn, LLVMAttributeFunctionIndex,
                                                    attribute("optnone")) != NULL;
      if (!stela_air_defined_function(fn))
         continue;
      bool cyclic;
      walked = visit(m, states, fn, true, 0, &cyclic);
      recursive |= walked && fn == entry && cyclic;
   }
   struct hash_table *shareable = _mesa_pointer_hash_table_create(NULL);
   if (!shareable) {
      _mesa_hash_table_destroy(states, NULL);
      return fail(m, STELA_AIR_ALLOCATION, "call graph allocation failed");
   }
   for (LLVMValueRef fn = LLVMGetFirstFunction(m->module); fn && walked; fn = LLVMGetNextFunction(fn)) {
      struct hash_entry *state = _mesa_hash_table_search(states, fn);
      if (!state || (uintptr_t)state->data != ACYCLIC || !called(fn))
         continue;
      /* An unoptimized build keeps every function out of line, for no
       * reason of size, and passes leave it as it is. */
      bool noinline = LLVMGetEnumAttributeAtIndex(fn, LLVMAttributeFunctionIndex, attribute("noinline"));
      if (!LLVMGetEnumAttributeAtIndex(fn, LLVMAttributeFunctionIndex, attribute("optnone")) &&
          !is_dispatcher(fn))
         _mesa_hash_table_insert(shareable, fn, (void *)(uintptr_t)(noinline ? SHARED_CALL_MIN_OUT_OF_LINE :
                                                                     SHARED_CALL_MIN_INSTRUCTIONS));
      inline_always(fn);
      inlined = true;
   }
   /* Keep the original graph's depth and cycle checks before pruning calls. */
   struct hash_entry *state = walked && inlined && specialized && !m->unoptimized ?
      _mesa_hash_table_search(states, specialized) : NULL;
   bool fold = state && (uintptr_t)state->data == ACYCLIC && can_prune_calls(specialized);
   _mesa_hash_table_destroy(states, NULL);
   if (!walked) {
      _mesa_hash_table_destroy(shareable, NULL);
      return false;
   }
   if (fold) {
      *folded = true;
      if (!stela_air_fold_constants(m, specialized)) {
         _mesa_hash_table_destroy(shareable, NULL);
         return false;
      }
   }
   bool shared = share_repeated_calls(m, shareable);
   _mesa_hash_table_destroy(shareable, NULL);
   if (!shared || (inlined && (!run_inliner(m) || !promote_inlined_memory(m))))
      return false;
   return !recursive || unroll(m, entry, max_call_stack_depth, max_instructions);
}

bool
stela_air_inline_calls(struct stela_air_metadata *m, LLVMValueRef entry,
                       unsigned max_call_stack_depth, unsigned max_instructions)
{
   return inline_calls(m, entry, max_call_stack_depth, max_instructions, NULL, NULL);
}

bool
stela_air_inline_specialized_calls(struct stela_air_metadata *m, LLVMValueRef entry, bool *folded)
{
   return inline_calls(m, NULL, 0, 0, entry, folded);
}

/* Apple's compiler declares a visible function another module defines as
 * NAME.MTL_VISIBLE_FN_REF, and lists the NAME it means. Under that name the
 * linker resolves it as it does any declaration. */
static bool
name_references(struct stela_air_metadata *m)
{
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_named_md(m, "air.visible_function_references", nodes, &count))
      return false;
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned field_count, length;
      if (!stela_air_md_node(m, nodes[i], fields, &field_count))
         return false;
      if (field_count != 3 || !stela_air_md_string(fields[0], "air.visible_function_reference") ||
          !fields[1] || !LLVMIsAFunction(fields[1]) || !fields[2] || !LLVMIsAMDString(fields[2]))
         return fail(m, STELA_AIR_METADATA, "invalid visible function reference");
      const char *name = LLVMGetMDString(fields[2], &length);
      LLVMValueRef defined = LLVMGetNamedFunctionWithLength(m->module, name, length);
      if (!defined) {
         LLVMSetValueName2(fields[1], name, length);
      } else if (defined != fields[1]) {
         LLVMReplaceAllUsesWith(fields[1], defined);
         LLVMDeleteFunction(fields[1]);
      }
   }
   return true;
}

/* Nothing calls an entry point, so libraries may share their names. */
static bool
hide_entry_points(struct stela_air_metadata *m)
{
   static const char *const stages[] = {"air.kernel", "air.vertex", "air.fragment", "air.object",
                                        "air.mesh"};
   for (unsigned stage = 0; stage < ARRAY_SIZE(stages); stage++) {
      LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      if (!stela_air_named_md(m, stages[stage], nodes, &count))
         return false;
      for (unsigned i = 0; i < count; i++) {
         LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
         unsigned field_count;
         if (!stela_air_md_node(m, nodes[i], fields, &field_count))
            return false;
         if (!field_count || !fields[0] || !LLVMIsAFunction(fields[0]))
            return fail(m, STELA_AIR_METADATA, "invalid entry point");
         LLVMSetLinkage(fields[0], LLVMInternalLinkage);
      }
   }
   return true;
}

/* A target triple's architecture, vendor and system, past its AIR version
 * and deployment version: air64_v28-apple-macosx27.0.0 as air64, then
 * -apple-macosx. */
static void
target_parts(const char *triple, size_t *arch, const char **rest, size_t *rest_bytes)
{
   const char *dash = strchr(triple, '-');
   size_t bytes = dash ? (size_t)(dash - triple) : strlen(triple);
   size_t name = bytes;
   while (name && isdigit((unsigned char)triple[name - 1]))
      name--;
   if (name != bytes && name >= 2 && triple[name - 1] == 'v' && triple[name - 2] == '_')
      bytes = name - 2;
   *arch = bytes;
   *rest = dash ? dash : triple + strlen(triple);
   *rest_bytes = strlen(*rest);
   while (*rest_bytes && (isdigit((unsigned char)(*rest)[*rest_bytes - 1]) || (*rest)[*rest_bytes - 1] == '.'))
      (*rest_bytes)--;
}

/* Whether two target triples name one target, whatever AIR version and
 * deployment version each was compiled for: a dynamic library the system's
 * compiler builds at run time, air64_v29-apple-macosx27.2.0, links under a
 * kernel an older toolchain built, air64_v28-apple-macosx27.0.0. */
static bool
same_target(const char *a, const char *b)
{
   size_t a_arch, a_rest, b_arch, b_rest;
   const char *a_tail, *b_tail;
   target_parts(a, &a_arch, &a_tail, &a_rest);
   target_parts(b, &b_arch, &b_tail, &b_rest);
   return a_arch == b_arch && !memcmp(a, b, a_arch) && a_rest == b_rest && !memcmp(a_tail, b_tail, a_rest);
}

/* Whether module is valid AIR compiled as m's module was, after
 * specializing its function constants with values. Its llvm.ident, AIR
 * version and language version name only the compiler that made it, whose
 * metadata it is read by: an offline-built dynamic library links under a
 * kernel compiled at run time, and one the system compiles at run time
 * under an offline-built kernel. */
static bool
prepared(struct stela_air_metadata *m, LLVMModuleRef module,
         const struct stela_air_constant_value *values, unsigned count)
{
   struct stela_air_error error = {0};
   struct stela_air_metadata linked = {.module = module, .error = &error, .render = true};
   char *verification = NULL;
   bool verified = !LLVMVerifyModule(module, LLVMReturnStatusAction, &verification);
   LLVMDisposeMessage(verification);
   if (!verified || !stela_air_metadata_layout(&linked) || !stela_air_metadata_validate(&linked))
      return fail(m, STELA_AIR_INPUT, "a linked module is not valid AIR");
   const char *differs = !same_target(LLVMGetTarget(module), LLVMGetTarget(m->module)) ? "target" :
      strcmp(LLVMGetDataLayoutStr(module), LLVMGetDataLayoutStr(m->module)) ? "data layout" :
      linked.denorms_disable != m->denorms_disable ? "denormal mode" :
      linked.fast_math != m->fast_math ? "fast math" : NULL;
   if (differs) {
      char detail[256];
      if (!strcmp(differs, "target"))
         snprintf(detail, sizeof(detail), "a linked module was compiled for %s, not %s",
                  LLVMGetTarget(module), LLVMGetTarget(m->module));
      else
         snprintf(detail, sizeof(detail), "a linked module was compiled with another %s", differs);
      return fail(m, STELA_AIR_INPUT, detail);
   }
   if (!name_references(&linked) || !hide_entry_points(&linked))
      return fail(m, error.kind, error.detail);
   if (!LLVMGetNamedMetadataNumOperands(module, "air.function_constants"))
      return true;
   if (!values)
      return fail(m, STELA_AIR_INPUT, "a linked module's function constants have no values");
   if (!stela_air_specialize_constants(&linked, values, count) ||
       !stela_air_construct_constants(&linked))
      return fail(m, error.kind, error.detail);
   return true;
}

/* Renames what another specialization of a module defines for other
 * modules, its functions and globals, with the suffix ".stela.copy<copy>":
 * its own calls keep reaching its own definitions, and its declarations
 * the program's. */
static bool
rename_copy(struct stela_air_metadata *m, LLVMModuleRef module, unsigned copy)
{
   char suffix[32];
   int suffix_bytes = snprintf(suffix, sizeof(suffix), ".stela.copy%u", copy);
   LLVMValueRef values[2] = {LLVMGetFirstFunction(module), LLVMGetFirstGlobal(module)};
   for (unsigned kind = 0; kind < 2; kind++) {
      for (LLVMValueRef value = values[kind]; value;
           value = kind ? LLVMGetNextGlobal(value) : LLVMGetNextFunction(value)) {
         /* LLVM's appending lists, such as llvm.compiler.used and
          * llvm.global_ctors, merge by their names. */
         if (LLVMIsDeclaration(value) || LLVMGetLinkage(value) == LLVMInternalLinkage ||
             LLVMGetLinkage(value) == LLVMPrivateLinkage ||
             LLVMGetLinkage(value) == LLVMAppendingLinkage)
            continue;
         size_t length;
         const char *name = LLVMGetValueName2(value, &length);
         /* AIR's builtins and LLVM's intrinsics are declarations, never
          * definitions. */
         char *renamed = malloc(length + (size_t)suffix_bytes + 1);
         if (!renamed)
            return fail(m, STELA_AIR_ALLOCATION, "linked copy name allocation failed");
         memcpy(renamed, name, length);
         memcpy(renamed + length, suffix, (size_t)suffix_bytes + 1);
         LLVMSetValueName2(value, renamed, length + (size_t)suffix_bytes);
         free(renamed);
      }
   }
   return true;
}

/* The calls of visible functions by their specialized names, each with the
 * name of the definition it reaches once the modules are linked. */
struct specialized_calls {
   unsigned count, capacity;
   char **calls, **definitions;
};

static void
release_specialized_calls(struct specialized_calls *calls)
{
   for (unsigned i = 0; i < calls->count; i++) {
      free(calls->calls[i]);
      free(calls->definitions[i]);
   }
   free(calls->calls);
   free(calls->definitions);
}

/* Makes calls of `call` reach `definition` once the modules are linked. */
static bool
add_specialized_call(struct stela_air_metadata *m, struct specialized_calls *calls,
                     const char *call, const char *definition)
{
   if (calls->count == calls->capacity) {
      unsigned capacity = calls->capacity ? calls->capacity * 2 : 16;
      char **grown_calls = realloc(calls->calls, capacity * sizeof(*grown_calls));
      if (grown_calls)
         calls->calls = grown_calls;
      char **grown_definitions =
         grown_calls ? realloc(calls->definitions, capacity * sizeof(*grown_definitions)) : NULL;
      if (grown_definitions)
         calls->definitions = grown_definitions;
      if (!grown_calls || !grown_definitions)
         return fail(m, STELA_AIR_ALLOCATION, "specialized calls");
      calls->capacity = capacity;
   }
   calls->calls[calls->count] = strdup(call);
   calls->definitions[calls->count] = strdup(definition);
   if (!calls->calls[calls->count] || !calls->definitions[calls->count]) {
      free(calls->calls[calls->count]);
      free(calls->definitions[calls->count]);
      return fail(m, STELA_AIR_ALLOCATION, "specialized calls");
   }
   calls->count++;
   return true;
}

/* Notes the specialized name of each visible function `module` defines, as
 * `values` specialize it, and the name it is defined by once its copy's
 * suffix (rename_copy) is added. */
static bool
note_specialized_calls(struct stela_air_metadata *m, LLVMModuleRef module,
                       const struct stela_air_constant_value *values, unsigned count,
                       unsigned copy, struct specialized_calls *calls)
{
   if (!count)
      return true;
   struct stela_air_error error = {0};
   struct stela_air_metadata linked = {.module = module, .error = &error};
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned node_count;
   if (!stela_air_named_md(&linked, "air.visible", nodes, &node_count))
      return fail(m, error.kind, error.detail);
   for (unsigned i = 0; i < node_count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned field_count;
      if (!stela_air_md_node(&linked, nodes[i], fields, &field_count))
         return fail(m, error.kind, error.detail);
      if (!field_count || !fields[0] || !LLVMIsAFunction(fields[0]) ||
          LLVMIsDeclaration(fields[0]))
         continue;
      size_t length;
      const char *name = LLVMGetValueName2(fields[0], &length);
      char call[1024], definition[1024];
      int written = copy ? snprintf(definition, sizeof(definition), "%.*s.stela.copy%u",
                                    (int)length, name, copy) :
                           snprintf(definition, sizeof(definition), "%.*s", (int)length, name);
      if (!stela_air_specialized_name(name, length, values, count, call, sizeof(call)) ||
          written < 0 || (size_t)written >= sizeof(definition))
         return fail(m, STELA_AIR_LIMIT, "a specialized visible function's name is too long");
      if (!add_specialized_call(m, calls, call, definition))
         return false;
   }
   return true;
}

/* Notes each alias of a linked module, whose definition its copy's suffix
 * (rename_copy) renames. */
static bool
note_aliases(struct stela_air_metadata *m, const struct stela_air_module *linked,
             struct specialized_calls *calls)
{
   if (linked->alias_count && !linked->aliases)
      return fail(m, STELA_AIR_INPUT, "invalid linked function aliases");
   for (unsigned i = 0; i < linked->alias_count; i++) {
      const struct stela_air_alias *alias = &linked->aliases[i];
      if (!alias->definition || !alias->name)
         return fail(m, STELA_AIR_INPUT, "invalid linked function aliases");
      char definition[1024];
      int written = linked->copy ? snprintf(definition, sizeof(definition), "%s.stela.copy%u",
                                            alias->definition, linked->copy) :
                                   snprintf(definition, sizeof(definition), "%s", alias->definition);
      if (written < 0 || (size_t)written >= sizeof(definition))
         return fail(m, STELA_AIR_LIMIT, "a linked function's name is too long");
      if (!add_specialized_call(m, calls, alias->name, definition))
         return false;
   }
   return true;
}

/* Makes each call by a specialized name call the definition it names. */
static void
resolve_specialized_calls(struct stela_air_metadata *m, const struct specialized_calls *calls)
{
   for (unsigned i = 0; i < calls->count; i++) {
      LLVMValueRef called = LLVMGetNamedFunction(m->module, calls->calls[i]);
      LLVMValueRef defined = LLVMGetNamedFunction(m->module, calls->definitions[i]);
      if (!called || !LLVMIsDeclaration(called) || !defined || LLVMIsDeclaration(defined))
         continue;
      LLVMReplaceAllUsesWith(called, defined);
      LLVMDeleteFunction(called);
   }
}

static bool
link_modules(struct stela_air_metadata *m, const struct stela_air_constant_value *own,
             unsigned own_count, const struct stela_air_module *modules, unsigned count,
             struct specialized_calls *calls);

bool
stela_air_link_modules(struct stela_air_metadata *m, const struct stela_air_constant_value *own,
                       unsigned own_count, const struct stela_air_module *modules,
                       unsigned count)
{
   struct specialized_calls calls = {0};
   bool linked = link_modules(m, own, own_count, modules, count, &calls);
   if (linked)
      resolve_specialized_calls(m, &calls);
   release_specialized_calls(&calls);
   return linked;
}

static bool
link_modules(struct stela_air_metadata *m, const struct stela_air_constant_value *own,
             unsigned own_count, const struct stela_air_module *modules, unsigned count,
             struct specialized_calls *calls)
{
   if (count && !modules)
      return fail(m, STELA_AIR_INPUT, "invalid linked modules");
   if (!name_references(m) || !note_specialized_calls(m, m->module, own, own_count, 0, calls))
      return false;
   LLVMContextRef context = LLVMGetModuleContext(m->module);
   for (unsigned i = 0; i < count; i++) {
      const struct stela_air_module *linked = &modules[i];
      if (!linked->bitcode || linked->size < 4 || linked->size > AIR_MAX_BITCODE_BYTES ||
          memcmp(linked->bitcode, "BC\xc0\xde", 4))
         return fail(m, STELA_AIR_INPUT, "a linked module is not AIR bitcode");
      LLVMMemoryBufferRef buffer =
         LLVMCreateMemoryBufferWithMemoryRangeCopy(linked->bitcode, linked->size, "linked module");
      LLVMModuleRef module = NULL;
      bool parsed = buffer && !LLVMParseBitcodeInContext2(context, buffer, &module);
      if (buffer)
         LLVMDisposeMemoryBuffer(buffer);
      if (!parsed || m->error->kind != STELA_AIR_OK)
         return fail(m, STELA_AIR_BITCODE, "LLVM refused a linked module");
      if (!prepared(m, module, linked->constants, linked->constant_count)) {
         LLVMDisposeModule(module);
         return false;
      }
      if (!note_specialized_calls(m, module, linked->constants, linked->constant_count,
                                  linked->copy, calls) ||
          !note_aliases(m, linked, calls) ||
          (linked->copy && !rename_copy(m, module, linked->copy))) {
         LLVMDisposeModule(module);
         return false;
      }
      /* The linker consumes the module, and takes its triple, which may
       * name another AIR version: the program keeps the kernel's own, whose
       * metadata it is read by. */
      char *target = strdup(LLVMGetTarget(m->module));
      if (!target)
         return fail(m, STELA_AIR_ALLOCATION, "linked target allocation failed");
      bool twice = LLVMLinkModules2(m->module, module);
      LLVMSetTarget(m->module, target);
      free(target);
      if (twice)
         return fail(m, STELA_AIR_INPUT, "linked modules define a function twice");
   }
   return true;
}

/* The dispatchers of one module, by call type. */
struct dispatching {
   struct stela_air_metadata *m;
   LLVMBuilderRef builder;
   LLVMValueRef *functions; /* By handle less one. */
   unsigned function_count, count;
   LLVMTypeRef types[MAX_DISPATCH_TYPES];
   LLVMValueRef dispatchers[MAX_DISPATCH_TYPES];
};

/* The dispatcher of calls of type: (handle, arguments) -> result. */
static LLVMValueRef
dispatcher(struct dispatching *d, LLVMTypeRef type)
{
   for (unsigned i = 0; i < d->count; i++) {
      if (d->types[i] == type)
         return d->dispatchers[i];
   }
   unsigned params = LLVMCountParamTypes(type);
   if (d->count == MAX_DISPATCH_TYPES || params >= AIR_MAX_ARGUMENTS) {
      fail(d->m, STELA_AIR_LIMIT, "function table call types exceeded");
      return NULL;
   }
   LLVMContextRef context = LLVMGetModuleContext(d->m->module);
   LLVMTypeRef handle = LLVMInt64TypeInContext(context);
   LLVMTypeRef types[AIR_MAX_ARGUMENTS];
   types[0] = handle;
   LLVMGetParamTypes(type, types + 1);
   LLVMTypeRef result = LLVMGetReturnType(type);
   bool returns = LLVMGetTypeKind(result) != LLVMVoidTypeKind;
   LLVMValueRef fn = LLVMAddFunction(d->m->module, "stela.dispatch",
                                     LLVMFunctionType(result, types, params + 1, false));
   LLVMSetLinkage(fn, LLVMInternalLinkage);
   LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex,
                           LLVMCreateStringAttribute(context, DISPATCHER, strlen(DISPATCHER), "", 0));
   LLVMBasicBlockRef entry = LLVMAppendBasicBlockInContext(context, fn, "entry");
   LLVMBasicBlockRef none = LLVMAppendBasicBlockInContext(context, fn, "none");
   LLVMPositionBuilderAtEnd(d->builder, none);
   if (returns)
      LLVMBuildRet(d->builder, LLVMConstNull(result));
   else
      LLVMBuildRetVoid(d->builder);
   LLVMPositionBuilderAtEnd(d->builder, entry);
   LLVMValueRef cases = LLVMBuildSwitch(d->builder, LLVMGetParam(fn, 0), none, d->function_count);
   LLVMValueRef arguments[AIR_MAX_ARGUMENTS];
   for (unsigned i = 0; i < params; i++)
      arguments[i] = LLVMGetParam(fn, i + 1);
   for (unsigned i = 0; i < d->function_count; i++) {
      /* Metal leaves a call of another type undefined: it calls none. */
      if (LLVMGlobalGetValueType(d->functions[i]) != type)
         continue;
      LLVMBasicBlockRef call = LLVMAppendBasicBlockInContext(context, fn, "call");
      LLVMAddCase(cases, LLVMConstInt(handle, i + 1, false), call);
      LLVMPositionBuilderAtEnd(d->builder, call);
      LLVMValueRef value = LLVMBuildCall2(d->builder, type, d->functions[i], arguments, params, "");
      if (returns)
         LLVMBuildRet(d->builder, value);
      else
         LLVMBuildRetVoid(d->builder);
   }
   d->types[d->count] = type;
   return d->dispatchers[d->count++] = fn;
}

/* Whether call passes any argument by its type: byval, sret and the like,
 * which a dispatcher's own parameters do not carry. */
static bool
typed_arguments(LLVMValueRef call)
{
   unsigned arguments = LLVMGetNumArgOperands(call);
   for (unsigned i = 0; i <= arguments; i++) {
      unsigned index = i == arguments ? LLVMAttributeReturnIndex : i + 1;
      unsigned count = LLVMGetCallSiteAttributeCount(call, index);
      LLVMAttributeRef attributes[AIR_MAX_METADATA_OPERANDS];
      if (count > AIR_MAX_METADATA_OPERANDS)
         return true;
      LLVMGetCallSiteAttributes(call, index, attributes);
      for (unsigned a = 0; a < count; a++) {
         if (LLVMIsTypeAttribute(attributes[a]))
            return true;
      }
   }
   return false;
}

/* Replaces each call through pointer, a table's, with a dispatch of handle;
 * a bitcast of the pointer to its own type, which Apple's compiler emits
 * before the call, is the pointer. */
static bool
dispatch_calls(struct dispatching *d, LLVMValueRef pointer, LLVMValueRef handle)
{
   LLVMUseRef use;
   while ((use = LLVMGetFirstUse(pointer))) {
      LLVMValueRef call = LLVMGetUser(use);
      if (LLVMIsABitCastInst(call) && LLVMTypeOf(call) == LLVMTypeOf(pointer)) {
         LLVMReplaceAllUsesWith(call, pointer);
         LLVMInstructionEraseFromParent(call);
         continue;
      }
      unsigned arguments = LLVMIsACallInst(call) ? LLVMGetNumArgOperands(call) : 0;
      bool callee = LLVMIsACallInst(call) && LLVMGetCalledValue(call) == pointer;
      for (unsigned i = 0; callee && i < arguments; i++)
         callee = LLVMGetOperand(call, i) != pointer;
      if (!callee)
         return fail(d->m, STELA_AIR_INSTRUCTION, "a function table's pointers are only called");
      if (LLVMGetInstructionCallConv(call) != LLVMCCallConv || typed_arguments(call) ||
          arguments >= AIR_MAX_ARGUMENTS)
         return fail(d->m, STELA_AIR_INSTRUCTION, "unsupported call through a function table");
      LLVMTypeRef type = LLVMGetCalledFunctionType(call);
      LLVMValueRef fn = dispatcher(d, type);
      if (!fn)
         return false;
      LLVMValueRef operands[AIR_MAX_ARGUMENTS];
      operands[0] = handle;
      for (unsigned i = 0; i < arguments; i++)
         operands[i + 1] = LLVMGetOperand(call, i);
      LLVMPositionBuilderBefore(d->builder, call);
      LLVMValueRef dispatched =
         LLVMBuildCall2(d->builder, LLVMGlobalGetValueType(fn), fn, operands, arguments + 1, "");
      LLVMReplaceAllUsesWith(call, dispatched);
      LLVMInstructionEraseFromParent(call);
   }
   return true;
}

/* The linked functions, by handle less one: each a function the module
 * defines under its name. */
static bool
resolve(struct dispatching *d, const struct stela_air_linked_function *functions)
{
   for (unsigned i = 0; i < d->function_count; i++) {
      const struct stela_air_linked_function *function = &functions[i];
      char name[MAX_NAME_BYTES + 1];
      if (!function->name || !function->name_bytes || function->name_bytes > MAX_NAME_BYTES ||
          memchr(function->name, 0, function->name_bytes))
         return fail(d->m, STELA_AIR_INPUT, "invalid linked function name");
      memcpy(name, function->name, function->name_bytes);
      name[function->name_bytes] = 0;
      LLVMValueRef fn = LLVMGetNamedFunction(d->m->module, name);
      if (!fn || !stela_air_defined_function(fn) || LLVMGetFunctionCallConv(fn) != LLVMCCallConv ||
          LLVMIsFunctionVarArg(LLVMGlobalGetValueType(fn)))
         return fail(d->m, STELA_AIR_ARGUMENT, "a linked function is not defined");
      d->functions[i] = fn;
   }
   return true;
}

/* Lowers each table's size to a load of its first word. */
static bool
table_sizes(struct stela_air_metadata *m)
{
   LLVMValueRef size = LLVMGetNamedFunction(m->module, "air.get_size_visible_function_table");
   if (!size || !LLVMGetFirstUse(size))
      return true;
   LLVMContextRef context = LLVMGetModuleContext(m->module);
   LLVMTypeRef word = LLVMInt32TypeInContext(context), table = LLVMPointerTypeInContext(context, 1);
   if (!LLVMIsDeclaration(size) || LLVMGlobalGetValueType(size) != LLVMFunctionType(word, &table, 1, false))
      return fail(m, STELA_AIR_TYPE, "unsupported air.get_size_visible_function_table");
   LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
   if (!builder)
      return fail(m, STELA_AIR_ALLOCATION, "function table size allocation failed");
   LLVMUseRef use;
   bool lowered = true;
   while (lowered && (use = LLVMGetFirstUse(size))) {
      LLVMValueRef call = LLVMGetUser(use);
      lowered = LLVMIsACallInst(call) && LLVMGetCalledValue(call) == size;
      if (!lowered) {
         fail(m, STELA_AIR_INSTRUCTION, "air.get_size_visible_function_table is only called");
         break;
      }
      LLVMPositionBuilderBefore(builder, call);
      LLVMValueRef entries = LLVMBuildLoad2(builder, word, LLVMGetOperand(call, 0), "");
      LLVMSetAlignment(entries, 8);
      LLVMReplaceAllUsesWith(call, entries);
      LLVMInstructionEraseFromParent(call);
   }
   LLVMDisposeBuilder(builder);
   return lowered;
}

/* Lowers each null table to a null address, through which every access reads
 * zero: its size and handles. */
static bool
null_tables(struct stela_air_metadata *m)
{
   LLVMValueRef get = LLVMGetNamedFunction(m->module, "air.get_null_visible_function_table");
   if (!get || !LLVMGetFirstUse(get))
      return true;
   LLVMContextRef context = LLVMGetModuleContext(m->module);
   LLVMTypeRef table = LLVMPointerTypeInContext(context, 1);
   if (!LLVMIsDeclaration(get) || LLVMGlobalGetValueType(get) != LLVMFunctionType(table, NULL, 0, false))
      return fail(m, STELA_AIR_TYPE, "unsupported air.get_null_visible_function_table");
   LLVMUseRef use;
   while ((use = LLVMGetFirstUse(get))) {
      LLVMValueRef call = LLVMGetUser(use);
      if (!LLVMIsACallInst(call) || LLVMGetCalledValue(call) != get)
         return fail(m, STELA_AIR_INSTRUCTION, "air.get_null_visible_function_table is only called");
      LLVMReplaceAllUsesWith(call, LLVMConstPointerNull(table));
      LLVMInstructionEraseFromParent(call);
   }
   return true;
}

/* Lowers each test for a null table to a comparison of its address, which a
 * table the encoder leaves unset holds as zero. */
static bool
table_nulls(struct stela_air_metadata *m)
{
   LLVMValueRef is_null = LLVMGetNamedFunction(m->module, "air.is_null_visible_function_table");
   if (!is_null || !LLVMGetFirstUse(is_null))
      return true;
   LLVMContextRef context = LLVMGetModuleContext(m->module);
   LLVMTypeRef bit = LLVMInt1TypeInContext(context), table = LLVMPointerTypeInContext(context, 1);
   if (!LLVMIsDeclaration(is_null) ||
       LLVMGlobalGetValueType(is_null) != LLVMFunctionType(bit, &table, 1, false))
      return fail(m, STELA_AIR_TYPE, "unsupported air.is_null_visible_function_table");
   LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
   if (!builder)
      return fail(m, STELA_AIR_ALLOCATION, "function table test allocation failed");
   LLVMUseRef use;
   bool lowered = true;
   while (lowered && (use = LLVMGetFirstUse(is_null))) {
      LLVMValueRef call = LLVMGetUser(use);
      lowered = LLVMIsACallInst(call) && LLVMGetCalledValue(call) == is_null;
      if (!lowered) {
         fail(m, STELA_AIR_INSTRUCTION, "air.is_null_visible_function_table is only called");
         break;
      }
      LLVMPositionBuilderBefore(builder, call);
      LLVMValueRef test = LLVMBuildICmp(builder, LLVMIntEQ, LLVMGetOperand(call, 0),
                                        LLVMConstPointerNull(table), "");
      LLVMReplaceAllUsesWith(call, test);
      LLVMInstructionEraseFromParent(call);
   }
   LLVMDisposeBuilder(builder);
   return lowered;
}

bool
stela_air_dispatch_tables(struct stela_air_metadata *m,
                          const struct stela_air_linked_function *functions, unsigned count)
{
   if (count && !functions)
      return fail(m, STELA_AIR_INPUT, "invalid linked functions");
   if (!null_tables(m) || !table_sizes(m) || !table_nulls(m))
      return false;
   LLVMValueRef get = LLVMGetNamedFunction(m->module, "air.get_function_pointer_visible_function_table");
   if (!get || !LLVMGetFirstUse(get))
      return true;
   LLVMContextRef context = LLVMGetModuleContext(m->module);
   LLVMTypeRef handle = LLVMInt64TypeInContext(context);
   LLVMTypeRef pointer = LLVMPointerTypeInContext(context, 0), table = LLVMPointerTypeInContext(context, 1);
   LLVMTypeRef params[] = {table, LLVMInt32TypeInContext(context)};
   if (!LLVMIsDeclaration(get) || LLVMGlobalGetValueType(get) != LLVMFunctionType(pointer, params, 2, false))
      return fail(m, STELA_AIR_TYPE, "unsupported air.get_function_pointer_visible_function_table");
   struct dispatching *d = calloc(1, sizeof(*d));
   LLVMValueRef *resolved = calloc(count ? count : 1, sizeof(*resolved));
   LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
   bool dispatched = d && resolved && builder;
   if (!dispatched) {
      fail(m, STELA_AIR_ALLOCATION, "function table dispatch allocation failed");
   } else {
      *d = (struct dispatching){.m = m, .builder = builder, .functions = resolved,
                                .function_count = count};
      dispatched = resolve(d, functions);
   }
   LLVMUseRef use;
   while (dispatched && (use = LLVMGetFirstUse(get))) {
      LLVMValueRef call = LLVMGetUser(use);
      if (!LLVMIsACallInst(call) || LLVMGetCalledValue(call) != get) {
         dispatched = fail(m, STELA_AIR_INSTRUCTION, "air.get_function_pointer_visible_function_table is only called");
         break;
      }
      /* The handle of the table's element, after its count. */
      LLVMPositionBuilderBefore(builder, call);
      LLVMValueRef index = LLVMBuildZExt(builder, LLVMGetOperand(call, 1), handle, "");
      index = LLVMBuildAdd(builder, index, LLVMConstInt(handle, 1, false), "");
      LLVMValueRef slot = LLVMBuildGEP2(builder, handle, LLVMGetOperand(call, 0), &index, 1, "");
      LLVMValueRef id = LLVMBuildLoad2(builder, handle, slot, "");
      LLVMSetAlignment(id, 8);
      dispatched = dispatch_calls(d, call, id);
      if (dispatched)
         LLVMInstructionEraseFromParent(call);
   }
   if (builder)
      LLVMDisposeBuilder(builder);
   free(resolved);
   free(d);
   return dispatched;
}
