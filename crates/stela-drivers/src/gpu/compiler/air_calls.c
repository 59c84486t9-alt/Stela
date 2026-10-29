/* SPDX-License-Identifier: MIT */
/* Calls between the module's functions. Apple's compiler inlines most
 * functions but keeps [[noinline]] and visible functions out of line, while
 * translation lowers one function. Each call to a function the module
 * defines is inlined by LLVM's always-inline pass, bottom-up, so the
 * callee's own calls are inlined first.
 *
 * Metal permits recursion only through function tables, whose depth a
 * pipeline bounds; the inliner cannot unroll it. A function whose calls reach
 * a cycle keeps its call sites, which translation refuses. */
#define STELA_AIR_METADATA_INTERNAL
#include "air_calls.h"
#include "llvm-c/Transforms/PassBuilder.h"
#include "util/hash_table.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Beyond any call chain Metal compiles, it bounds the walk of hostile input. */
#define MAX_CALL_DEPTH 256u

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

/* Records in states whether fn's calls reach a cycle, and each function's
 * they reach; *cyclic receives fn's. */
static bool
visit(struct stela_air_metadata *m, struct hash_table *states, LLVMValueRef fn, unsigned depth,
      bool *cyclic)
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
         bool reached = false;
         if (callee && !visit(m, states, callee, depth + 1, &reached))
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

bool
stela_air_inline_calls(struct stela_air_metadata *m)
{
   struct hash_table *states = _mesa_pointer_hash_table_create(NULL);
   if (!states)
      return fail(m, STELA_AIR_ALLOCATION, "call graph allocation failed");
   bool walked = true, inlined = false;
   for (LLVMValueRef fn = LLVMGetFirstFunction(m->module); fn && walked; fn = LLVMGetNextFunction(fn)) {
      bool cyclic;
      walked = !stela_air_defined_function(fn) || visit(m, states, fn, 0, &cyclic);
   }
   for (LLVMValueRef fn = LLVMGetFirstFunction(m->module); fn && walked; fn = LLVMGetNextFunction(fn)) {
      struct hash_entry *entry = _mesa_hash_table_search(states, fn);
      if (!entry || (uintptr_t)entry->data != ACYCLIC || !called(fn))
         continue;
      /* optnone requires noinline. */
      LLVMRemoveEnumAttributeAtIndex(fn, LLVMAttributeFunctionIndex, attribute("optnone"));
      LLVMRemoveEnumAttributeAtIndex(fn, LLVMAttributeFunctionIndex, attribute("noinline"));
      LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex,
                              LLVMCreateEnumAttribute(LLVMGetModuleContext(m->module),
                                                      attribute("alwaysinline"), 0));
      inlined = true;
   }
   _mesa_hash_table_destroy(states, NULL);
   if (!walked || !inlined)
      return walked;
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
