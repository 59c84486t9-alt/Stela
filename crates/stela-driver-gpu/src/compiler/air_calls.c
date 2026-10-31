/* SPDX-License-Identifier: MIT */
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
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
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

bool
stela_air_inline_calls(struct stela_air_metadata *m, LLVMValueRef entry,
                       unsigned max_call_stack_depth, unsigned max_instructions)
{
   struct hash_table *states = _mesa_pointer_hash_table_create(NULL);
   if (!states)
      return fail(m, STELA_AIR_ALLOCATION, "call graph allocation failed");
   bool walked = true, inlined = false, recursive = false;
   for (LLVMValueRef fn = LLVMGetFirstFunction(m->module); fn && walked; fn = LLVMGetNextFunction(fn)) {
      bool cyclic;
      walked = !stela_air_defined_function(fn) || visit(m, states, fn, true, 0, &cyclic);
      recursive |= walked && fn == entry && cyclic;
   }
   for (LLVMValueRef fn = LLVMGetFirstFunction(m->module); fn && walked; fn = LLVMGetNextFunction(fn)) {
      struct hash_entry *state = _mesa_hash_table_search(states, fn);
      if (!state || (uintptr_t)state->data != ACYCLIC || !called(fn))
         continue;
      inline_always(fn);
      inlined = true;
   }
   _mesa_hash_table_destroy(states, NULL);
   if (!walked || (inlined && !run_inliner(m)))
      return false;
   return !recursive || unroll(m, entry, max_call_stack_depth, max_instructions);
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

/* Whether module is valid AIR compiled as m's module was, after
 * specializing its function constants with values. */
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
   if (strcmp(LLVMGetTarget(module), LLVMGetTarget(m->module)) ||
       strcmp(LLVMGetDataLayoutStr(module), LLVMGetDataLayoutStr(m->module)) ||
       linked.air_minor != m->air_minor || linked.language_major != m->language_major ||
       linked.language_minor != m->language_minor || linked.denorms_disable != m->denorms_disable ||
       linked.fast_math != m->fast_math || linked.ident_bytes != m->ident_bytes ||
       (m->ident_bytes && memcmp(linked.ident, m->ident, m->ident_bytes)))
      return fail(m, STELA_AIR_INPUT, "a linked module was compiled differently");
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

bool
stela_air_link_modules(struct stela_air_metadata *m, const struct stela_air_module *modules,
                       unsigned count)
{
   if (count && !modules)
      return fail(m, STELA_AIR_INPUT, "invalid linked modules");
   if (!name_references(m))
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
      /* The linker consumes the module. */
      if (LLVMLinkModules2(m->module, module))
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

bool
stela_air_dispatch_tables(struct stela_air_metadata *m,
                          const struct stela_air_linked_function *functions, unsigned count)
{
   if (count && !functions)
      return fail(m, STELA_AIR_INPUT, "invalid linked functions");
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
      /* The handle of the table's element. */
      LLVMPositionBuilderBefore(builder, call);
      LLVMValueRef index = LLVMBuildZExt(builder, LLVMGetOperand(call, 1), handle, "");
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
