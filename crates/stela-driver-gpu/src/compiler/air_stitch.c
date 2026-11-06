/* SPDX-License-Identifier: MIT */
/* Stitched functions: MTLFunctionStitchingGraph as a module of visible
 * functions and kernels, each of whose body calls its nodes' functions in
 * order. The functions it calls stay declarations, so a pipeline of or
 * linking a stitched function links their modules too, with their own
 * function constant values.
 *
 * Nodes follow what they use, so calling each once in order keeps every
 * dependency, control or data. An input becomes an argument of the type and
 * metadata of the parameter it feeds, a kernel's builtin or bound resource a
 * call of the Stela function that the kernel's translation answers, an early
 * return a branch to a return, and a stitched function returns what its
 * output node's function returns. */
#define STELA_AIR_METADATA_INTERNAL
#include "air_metadata.h"
#include "air_texture.h"
#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/BitWriter.h"
#include "util/macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What a pipeline's linked modules must agree on, which the stitched module
 * takes from its first source. */
static const char *const shared_metadata[] = {"air.version", "air.language_version",
                                              "air.compile_options", "llvm.ident",
                                              "llvm.module.flags"};

struct source {
   LLVMModuleRef module;
   LLVMValueRef function, outputs;
   LLVMValueRef inputs[AIR_MAX_METADATA_OPERANDS];
};

static bool
fail(struct stela_air_metadata *m, enum stela_air_error_kind kind, const char *detail)
{
   if (m->error->kind == STELA_AIR_OK) {
      m->error->kind = kind;
      snprintf(m->error->detail, sizeof(m->error->detail), "%s", detail);
   }
   return false;
}

/* Finds the function of `from` and what its air.visible entry says of it. */
static bool
load_source(struct stela_air_metadata *m, LLVMContextRef context,
            const struct stela_air_stitch_source *from, struct source *source)
{
   LLVMMemoryBufferRef buffer =
      LLVMCreateMemoryBufferWithMemoryRangeCopy(from->bitcode, from->size, "stitched function");
   bool parsed = buffer && !LLVMParseBitcodeInContext2(context, buffer, &source->module);
   if (buffer)
      LLVMDisposeMemoryBuffer(buffer);
   if (!parsed || m->error->kind != STELA_AIR_OK)
      return fail(m, STELA_AIR_BITCODE, "LLVM refused a stitched function's module");
   m->module = source->module;
   source->function = LLVMGetNamedFunction(source->module, from->name);
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_named_md(m, "air.visible", nodes, &count))
      return false;
   for (unsigned i = 0; source->function && i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned field_count, input_count;
      if (!stela_air_md_node(m, nodes[i], fields, &field_count))
         return false;
      if (field_count < 3 || fields[0] != source->function)
         continue;
      source->outputs = fields[1];
      if (!stela_air_md_node(m, fields[2], source->inputs, &input_count))
         return false;
      if (input_count != LLVMCountParams(source->function))
         return fail(m, STELA_AIR_METADATA, "a stitched function's inputs");
      return true;
   }
   return fail(m, STELA_AIR_INPUT, "a stitched function that is not visible");
}

/* The declaration whose call reads `builtin` as `type`, an integer scalar or
 * vector, which the parameters it feeds must share. */
static LLVMValueRef
builtin_function(struct stela_air_metadata *m, LLVMModuleRef out, uint32_t builtin, LLVMTypeRef type)
{
   const char *stem = builtin == STELA_AIR_STITCH_THREAD_POSITION_IN_GRID ?
                         STELA_AIR_STITCH_THREAD_POSITION_IN_GRID_NAME :
                      builtin == STELA_AIR_STITCH_THREAD_POSITION_IN_THREADGROUP ?
                         STELA_AIR_STITCH_THREAD_POSITION_IN_THREADGROUP_NAME : NULL;
   if (!stem) {
      fail(m, STELA_AIR_INPUT, "a stitched builtin this device does not know");
      return NULL;
   }
   bool vector = LLVMGetTypeKind(type) == LLVMVectorTypeKind;
   LLVMTypeRef element = vector ? LLVMGetElementType(type) : type;
   if (LLVMGetTypeKind(element) != LLVMIntegerTypeKind) {
      fail(m, STELA_AIR_INPUT, "a stitched thread position feeds a parameter that is not an integer");
      return NULL;
   }
   char name[64];
   unsigned bits = LLVMGetIntTypeWidth(element);
   if (vector)
      snprintf(name, sizeof(name), "%s.v%ui%u", stem, LLVMGetVectorSize(type), bits);
   else
      snprintf(name, sizeof(name), "%s.i%u", stem, bits);
   LLVMValueRef function = LLVMGetNamedFunction(out, name);
   return function ? function : LLVMAddFunction(out, name, LLVMFunctionType(type, NULL, 0, false));
}

/* A buffer address node's value as the `type` of the parameters it feeds:
 * a pointer `offset` bytes into the buffer, or the value of `type` there. */
static LLVMValueRef
buffer_address(struct stela_air_metadata *m, LLVMContextRef context, LLVMModuleRef out,
               LLVMBuilderRef builder, const struct stela_air_stitch_node *node, LLVMTypeRef type)
{
   bool pointer = LLVMGetTypeKind(type) == LLVMPointerTypeKind;
   unsigned space = node->dereference ? 2 : pointer ? LLVMGetPointerAddressSpace(type) : 0;
   if (space != 1 && space != 2) {
      fail(m, STELA_AIR_INPUT, "a stitched buffer address feeds a parameter that is no buffer pointer");
      return NULL;
   }
   char name[64];
   snprintf(name, sizeof(name), "%s.p%u", STELA_AIR_STITCH_BUFFER_ADDRESS_NAME, space);
   LLVMTypeRef address_type = LLVMPointerTypeInContext(context, space);
   LLVMTypeRef index_type = LLVMInt32TypeInContext(context);
   LLVMValueRef read = LLVMGetNamedFunction(out, name);
   if (!read)
      read = LLVMAddFunction(out, name, LLVMFunctionType(address_type, &index_type, 1, false));
   LLVMValueRef index = LLVMConstInt(index_type, node->input, false);
   LLVMValueRef offset = LLVMConstInt(LLVMInt64TypeInContext(context), node->offset, false);
   LLVMValueRef address =
      LLVMBuildCall2(builder, LLVMGlobalGetValueType(read), read, &index, 1, "");
   address = LLVMBuildGEP2(builder, LLVMInt8TypeInContext(context), address, &offset, 1, "");
   if (!node->dereference)
      return address;
   /* Metal binds a buffer aligned for what it holds. */
   LLVMTargetDataRef layout = LLVMCreateTargetData(LLVMGetDataLayoutStr(out));
   unsigned alignment = LLVMABIAlignmentOfType(layout, type);
   LLVMDisposeTargetData(layout);
   if (node->offset)
      alignment = MIN2(alignment, (unsigned)MIN2(node->offset & -node->offset, 1u << 16));
   LLVMValueRef value = LLVMBuildLoad2(builder, type, address, "");
   LLVMSetAlignment(value, alignment);
   return value;
}

/* The texture, sampler or threadgroup memory node's value, read from the
 * stitched kernel's binding at its index, as the `type` of the parameters it
 * feeds. */
static LLVMValueRef
bound_resource(struct stela_air_metadata *m, LLVMContextRef context, LLVMModuleRef out,
               LLVMBuilderRef builder, const struct stela_air_stitch_node *node, LLVMTypeRef type,
               const struct stela_air_texture *texture)
{
   static const struct {
      uint32_t function;
      unsigned space;
      const char *name, *refusal;
   } kinds[] = {
      {STELA_AIR_STITCH_TEXTURE, 1, STELA_AIR_STITCH_TEXTURE_NAME,
       "a stitched texture feeds a parameter that is no texture"},
      {STELA_AIR_STITCH_SAMPLER, 2, STELA_AIR_STITCH_SAMPLER_NAME,
       "a stitched sampler feeds a parameter that is no sampler"},
      {STELA_AIR_STITCH_THREADGROUP, 3, STELA_AIR_STITCH_THREADGROUP_NAME,
       "stitched threadgroup memory feeds a parameter that is no threadgroup pointer"},
   };
   unsigned kind = 0;
   while (kinds[kind].function != node->function)
      kind++;
   if (LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
       LLVMGetPointerAddressSpace(type) != kinds[kind].space) {
      fail(m, STELA_AIR_INPUT, kinds[kind].refusal);
      return NULL;
   }
   LLVMTypeRef index_type = LLVMInt32TypeInContext(context);
   LLVMValueRef read = LLVMGetNamedFunction(out, kinds[kind].name);
   if (!read)
      read = LLVMAddFunction(out, kinds[kind].name, LLVMFunctionType(type, &index_type, 1, false));
   LLVMValueRef index = LLVMConstInt(index_type, node->input, false);
   LLVMValueRef value = LLVMBuildCall2(builder, LLVMGlobalGetValueType(read), read, &index, 1, "");
   if (node->function == STELA_AIR_STITCH_TEXTURE && texture->type) {
      LLVMTypeRef word = LLVMInt32TypeInContext(context);
      LLVMValueRef fields[] = {
         LLVMConstInt(word, texture->type, false), LLVMConstInt(word, texture->access, false),
         LLVMConstInt(word, texture->primitive, false),
         LLVMConstInt(LLVMInt1TypeInContext(context), texture->depth, false),
      };
      const char *kind = STELA_AIR_STITCH_TEXTURE_METADATA;
      LLVMSetMetadata(value, LLVMGetMDKindIDInContext(context, kind, (unsigned)strlen(kind)),
                      LLVMMDNodeInContext(context, fields, ARRAY_SIZE(fields)));
   }
   return value;
}

/* Merges into *texture what the texture calls that take `parameter` say of
 * it; a parameter its function passes on says nothing here. */
static void
describe_texture(LLVMValueRef parameter, struct stela_air_texture *texture)
{
   for (LLVMUseRef use = LLVMGetFirstUse(parameter); use; use = LLVMGetNextUse(use)) {
      LLVMValueRef user = LLVMGetUser(use);
      struct stela_air_texture merged = *texture;
      if (LLVMIsACallInst(user) && LLVMGetOperand(user, 0) == parameter &&
          stela_air_texture_use(user, &merged))
         *texture = merged;
   }
}

/* Node `index` of graph if it is a call before node `before`. */
static const struct stela_air_stitch_node *
earlier_call(const struct stela_air_stitch_graph *graph, unsigned before, uint32_t index)
{
   const struct stela_air_stitch_node *node = index < before ? &graph->nodes[index] : NULL;
   return node && node->function < STELA_AIR_STITCH_CALLS ? node : NULL;
}

/* The type a call node's function returns. */
static LLVMTypeRef
returned(const struct source *sources, const struct stela_air_stitch_node *call)
{
   return LLVMGetReturnType(LLVMGlobalGetValueType(sources[call->function].function));
}

/* The input's metadata as the stitched function's argument `index`. */
static LLVMValueRef
argument_metadata(struct stela_air_metadata *m, LLVMContextRef context, LLVMValueRef input,
                  unsigned index)
{
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_md_node(m, input, fields, &count) || !count)
      return NULL;
   fields[0] = LLVMConstInt(LLVMInt32TypeInContext(context), index, false);
   return LLVMMDNodeInContext(context, fields, count);
}

static bool
stitch_graph(struct stela_air_metadata *m, LLVMContextRef context, LLVMModuleRef out,
             const struct source *sources, const struct stela_air_stitch_graph *graph)
{
   /* As Metal's, a kernel's graph takes no inputs and returns nothing, and
    * only it reads builtins and bindings. */
   for (unsigned i = 0; i < graph->node_count; i++) {
      uint32_t kind = graph->nodes[i].function;
      bool bound = kind == STELA_AIR_STITCH_BUILTIN || kind == STELA_AIR_STITCH_BUFFER_ADDRESS ||
                   kind == STELA_AIR_STITCH_TEXTURE || kind == STELA_AIR_STITCH_SAMPLER ||
                   kind == STELA_AIR_STITCH_THREADGROUP;
      if (graph->kernel && kind == STELA_AIR_STITCH_INPUT)
         return fail(m, STELA_AIR_INPUT, "a stitched kernel takes an input");
      if (!graph->kernel && bound)
         return fail(m, STELA_AIR_INPUT, "a stitched visible function reads a builtin or binding");
   }
   if (graph->kernel && graph->output != STELA_AIR_STITCH_NO_OUTPUT)
      return fail(m, STELA_AIR_INPUT, "a stitched kernel returns a value");
   LLVMTypeRef types[AIR_MAX_METADATA_OPERANDS] = {0};
   LLVMValueRef inputs[AIR_MAX_METADATA_OPERANDS] = {0};
   unsigned parameters = 0;
   /* Each builtin or buffer address node's type, the parameters' it feeds,
    * and each texture node's texture, as their texture calls take it: zero,
    * sampled and of no known type until one does. */
   LLVMTypeRef *builtins = calloc(graph->node_count, sizeof(*builtins));
   struct stela_air_texture *textures = calloc(graph->node_count, sizeof(*textures));
   if (!builtins || !textures) {
      free(builtins);
      free(textures);
      return fail(m, STELA_AIR_ALLOCATION, "stitched nodes");
   }
   for (unsigned i = 0; i < graph->node_count; i++) {
      const struct stela_air_stitch_node *node = &graph->nodes[i];
      if (node->function == STELA_AIR_STITCH_EARLY_RETURN) {
         const struct stela_air_stitch_node *condition = earlier_call(graph, i, node->input);
         const struct stela_air_stitch_node *value =
            node->argument_count == 1 ? earlier_call(graph, i, node->arguments[0]) : NULL;
         bool outputs = graph->output != STELA_AIR_STITCH_NO_OUTPUT;
         const struct stela_air_stitch_node *output = outputs ? &graph->nodes[graph->output] : NULL;
         const char *refusal =
            !condition ? "a stitched early return whose condition is no earlier call" :
            LLVMGetTypeKind(returned(sources, condition)) != LLVMIntegerTypeKind ?
               "a stitched early return whose condition is no integer" :
            node->argument_count != outputs ? "a stitched early return of other than the output's values" :
            outputs && (!value || output->function >= STELA_AIR_STITCH_CALLS ||
                        returned(sources, value) != returned(sources, output)) ?
               "a stitched early return of no earlier call of the output's type" : NULL;
         if (refusal) {
            free(builtins);
            free(textures);
            return fail(m, STELA_AIR_INPUT, refusal);
         }
         continue;
      }
      if (node->function >= STELA_AIR_STITCH_CALLS)
         continue;
      const struct source *source = &sources[node->function];
      if (node->argument_count != LLVMCountParams(source->function)) {
         free(builtins);
         free(textures);
         return fail(m, STELA_AIR_INPUT, "a stitched call has the wrong number of arguments");
      }
      for (unsigned j = 0; j < node->argument_count; j++) {
         const struct stela_air_stitch_node *argument = &graph->nodes[node->arguments[j]];
         LLVMTypeRef type = LLVMTypeOf(LLVMGetParam(source->function, j));
         if (argument->function == STELA_AIR_STITCH_EARLY_RETURN) {
            free(builtins);
            free(textures);
            return fail(m, STELA_AIR_INPUT, "a stitched early return is a call's argument");
         }
         if (argument->function == STELA_AIR_STITCH_BUILTIN ||
             argument->function == STELA_AIR_STITCH_BUFFER_ADDRESS ||
             argument->function == STELA_AIR_STITCH_TEXTURE ||
             argument->function == STELA_AIR_STITCH_SAMPLER ||
             argument->function == STELA_AIR_STITCH_THREADGROUP) {
            LLVMTypeRef *builtin = &builtins[node->arguments[j]];
            if (*builtin && *builtin != type) {
               free(builtins);
               free(textures);
               return fail(m, STELA_AIR_INPUT, "a stitched builtin or resource of two types");
            }
            *builtin = type;
            if (argument->function == STELA_AIR_STITCH_TEXTURE)
               describe_texture(LLVMGetParam(source->function, j), &textures[node->arguments[j]]);
            continue;
         }
         if (argument->function != STELA_AIR_STITCH_INPUT)
            continue;
         unsigned index = argument->input;
         if (index >= ARRAY_SIZE(types) || (types[index] && types[index] != type)) {
            free(builtins);
            free(textures);
            return fail(m, STELA_AIR_INPUT, index >= ARRAY_SIZE(types) ?
                                               "a stitched function's argument index" :
                                               "a stitched argument of two types");
         }
         types[index] = type;
         inputs[index] = source->inputs[j];
         parameters = MAX2(parameters, index + 1);
      }
   }
   LLVMValueRef arguments[AIR_MAX_METADATA_OPERANDS];
   const char *refusal = NULL;
   enum stela_air_error_kind refused = STELA_AIR_INPUT;
   for (unsigned i = 0; !refusal && i < parameters; i++) {
      arguments[i] = types[i] ? argument_metadata(m, context, inputs[i], i) : NULL;
      if (!types[i])
         refusal = "a stitched function skips an argument";
      else if (!arguments[i])
         refusal = "a stitched function's inputs", refused = STELA_AIR_METADATA;
   }

   const struct stela_air_stitch_node *output =
      graph->output == STELA_AIR_STITCH_NO_OUTPUT ? NULL : &graph->nodes[graph->output];
   if (!refusal && output && output->function == STELA_AIR_STITCH_INPUT)
      refusal = "a stitched function outputs an input";
   if (!refusal && output && output->function >= STELA_AIR_STITCH_CALLS)
      refusal = "a stitched function outputs what is no call";
   if (!refusal && LLVMGetNamedFunction(out, graph->name))
      refusal = "a stitched function has the name of another";
   LLVMValueRef *values = refusal ? NULL : calloc(graph->node_count, sizeof(*values));
   if (!refusal && !values)
      refusal = "stitched nodes", refused = STELA_AIR_ALLOCATION;
   if (refusal) {
      free(builtins);
      free(textures);
      return fail(m, refused, refusal);
   }
   LLVMTypeRef result = LLVMVoidTypeInContext(context);
   if (output)
      result = LLVMGetReturnType(LLVMGlobalGetValueType(sources[output->function].function));
   LLVMValueRef function =
      LLVMAddFunction(out, graph->name, LLVMFunctionType(result, types, parameters, false));

   LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
   LLVMPositionBuilderAtEnd(builder, LLVMAppendBasicBlockInContext(context, function, "entry"));
   bool stitched = true;
   for (unsigned i = 0; stitched && i < graph->node_count; i++) {
      const struct stela_air_stitch_node *node = &graph->nodes[i];
      if (node->function == STELA_AIR_STITCH_INPUT) {
         values[i] = LLVMGetParam(function, node->input);
         continue;
      }
      if (node->function == STELA_AIR_STITCH_BUILTIN) {
         /* A builtin that feeds nothing is never read. */
         if (!builtins[i])
            continue;
         LLVMValueRef read = builtin_function(m, out, node->input, builtins[i]);
         stitched = read != NULL;
         if (read)
            values[i] = LLVMBuildCall2(builder, LLVMGlobalGetValueType(read), read, NULL, 0, "");
         continue;
      }
      if (node->function == STELA_AIR_STITCH_EARLY_RETURN) {
         LLVMValueRef condition = values[node->input];
         LLVMValueRef taken = LLVMBuildICmp(builder, LLVMIntNE, condition,
                                            LLVMConstNull(LLVMTypeOf(condition)), "");
         LLVMBasicBlockRef returns = LLVMAppendBasicBlockInContext(context, function, "");
         LLVMBasicBlockRef rest = LLVMAppendBasicBlockInContext(context, function, "");
         LLVMBuildCondBr(builder, taken, returns, rest);
         LLVMPositionBuilderAtEnd(builder, returns);
         if (node->argument_count)
            LLVMBuildRet(builder, values[node->arguments[0]]);
         else
            LLVMBuildRetVoid(builder);
         LLVMPositionBuilderAtEnd(builder, rest);
         continue;
      }
      if (node->function == STELA_AIR_STITCH_TEXTURE || node->function == STELA_AIR_STITCH_SAMPLER ||
          node->function == STELA_AIR_STITCH_THREADGROUP) {
         if (!builtins[i])
            continue;
         values[i] = bound_resource(m, context, out, builder, node, builtins[i], &textures[i]);
         stitched = values[i] != NULL;
         continue;
      }
      if (node->function == STELA_AIR_STITCH_BUFFER_ADDRESS) {
         /* As a builtin, one that feeds nothing is never read. */
         if (!builtins[i])
            continue;
         values[i] = buffer_address(m, context, out, builder, node, builtins[i]);
         stitched = values[i] != NULL;
         continue;
      }
      const struct source *source = &sources[node->function];
      size_t name_bytes;
      const char *name = LLVMGetValueName2(source->function, &name_bytes);
      LLVMTypeRef type = LLVMGlobalGetValueType(source->function);
      LLVMValueRef callee = LLVMGetNamedFunction(out, name);
      if (!callee)
         callee = LLVMAddFunction(out, name, type);
      LLVMValueRef call_arguments[AIR_MAX_METADATA_OPERANDS];
      for (unsigned j = 0; stitched && j < node->argument_count; j++) {
         call_arguments[j] = values[node->arguments[j]];
         stitched = LLVMTypeOf(call_arguments[j]) == LLVMTypeOf(LLVMGetParam(source->function, j));
      }
      if (stitched) {
         values[i] = LLVMBuildCall2(builder, type, callee, call_arguments, node->argument_count, "");
         LLVMSetInstructionCallConv(values[i], LLVMGetFunctionCallConv(source->function));
      }
   }
   if (stitched) {
      if (output)
         LLVMBuildRet(builder, values[graph->output]);
      else
         LLVMBuildRetVoid(builder);
   } else {
      fail(m, STELA_AIR_INPUT, "a stitched call's argument has another type");
   }
   LLVMDisposeBuilder(builder);
   free(values);
   free(builtins);
   free(textures);
   if (!stitched)
      return false;

   LLVMValueRef empty = LLVMMDNodeInContext(context, NULL, 0);
   LLVMValueRef entry[] = {function, output ? sources[output->function].outputs : empty,
                           LLVMMDNodeInContext(context, arguments, parameters)};
   LLVMAddNamedMetadataOperand(out, graph->kernel ? "air.kernel" : "air.visible",
                               LLVMMDNodeInContext(context, entry, ARRAY_SIZE(entry)));
   return true;
}

static bool
stitch(struct stela_air_metadata *m, LLVMContextRef context, struct source *sources,
       const struct stela_air_stitch_source *from, unsigned source_count,
       const struct stela_air_stitch_graph *graphs, unsigned graph_count,
       stela_air_visit_bytes visit, void *data)
{
   for (unsigned i = 0; i < source_count; i++) {
      if (!load_source(m, context, &from[i], &sources[i]))
         return false;
   }
   LLVMModuleRef out = LLVMModuleCreateWithNameInContext("stitched", context);
   LLVMSetTarget(out, LLVMGetTarget(sources[0].module));
   LLVMSetDataLayout(out, LLVMGetDataLayoutStr(sources[0].module));
   m->module = sources[0].module;
   bool stitched = true;
   for (unsigned i = 0; stitched && i < ARRAY_SIZE(shared_metadata); i++) {
      LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      stitched = stela_air_named_md(m, shared_metadata[i], nodes, &count);
      for (unsigned j = 0; stitched && j < count; j++)
         LLVMAddNamedMetadataOperand(out, shared_metadata[i], nodes[j]);
   }
   for (unsigned i = 0; stitched && i < graph_count; i++)
      stitched = stitch_graph(m, context, out, sources, &graphs[i]);
   char *message = NULL;
   if (stitched && LLVMVerifyModule(out, LLVMReturnStatusAction, &message))
      stitched = fail(m, STELA_AIR_INPUT, "a stitched function LLVM refuses");
   LLVMDisposeMessage(message);
   LLVMMemoryBufferRef bitcode = stitched ? LLVMWriteBitcodeToMemoryBuffer(out) : NULL;
   if (stitched && !bitcode)
      stitched = fail(m, STELA_AIR_ALLOCATION, "stitched bitcode");
   if (stitched) {
      visit(data, LLVMGetBufferStart(bitcode), LLVMGetBufferSize(bitcode));
      LLVMDisposeMemoryBuffer(bitcode);
   }
   LLVMDisposeModule(out);
   return stitched;
}

bool
stela_air_stitch(const struct stela_air_stitch_source *from, unsigned source_count,
                 const struct stela_air_stitch_graph *graphs, unsigned graph_count,
                 stela_air_visit_bytes visit, void *data, struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   struct stela_air_metadata m = {.error = error ? error : &local};
   *m.error = (struct stela_air_error){0};
   if (!from || !source_count || !graphs || !graph_count || !visit)
      return fail(&m, STELA_AIR_INPUT, "invalid stitched functions");
   struct source *sources = calloc(source_count, sizeof(*sources));
   LLVMContextRef context = LLVMContextCreate();
   bool stitched = sources && context ?
      stitch(&m, context, sources, from, source_count, graphs, graph_count, visit, data) :
      fail(&m, STELA_AIR_ALLOCATION, "stitched functions");
   for (unsigned i = 0; sources && i < source_count; i++) {
      if (sources[i].module)
         LLVMDisposeModule(sources[i].module);
   }
   free(sources);
   if (context)
      LLVMContextDispose(context);
   return stitched;
}
