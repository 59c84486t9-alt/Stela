/* SPDX-License-Identifier: MIT */
/* Stitched functions: MTLFunctionStitchingGraph as a module of visible
 * functions, each of whose body calls its nodes' functions in order. The
 * functions it calls stay declarations, so a pipeline that links a stitched
 * function links their modules too, with their own function constant values.
 *
 * Nodes follow what they use, so calling each once in order keeps every
 * dependency, control or data. An input becomes an argument of the type and
 * metadata of the parameter it feeds, and a stitched function returns what its
 * output node's function returns. */
#define STELA_AIR_METADATA_INTERNAL
#include "air_metadata.h"
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
      if (field_count != 3 || fields[0] != source->function)
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
   LLVMTypeRef types[AIR_MAX_METADATA_OPERANDS] = {0};
   LLVMValueRef inputs[AIR_MAX_METADATA_OPERANDS] = {0};
   unsigned parameters = 0;
   for (unsigned i = 0; i < graph->node_count; i++) {
      const struct stela_air_stitch_node *node = &graph->nodes[i];
      if (node->function == STELA_AIR_STITCH_INPUT)
         continue;
      const struct source *source = &sources[node->function];
      if (node->argument_count != LLVMCountParams(source->function))
         return fail(m, STELA_AIR_INPUT, "a stitched call has the wrong number of arguments");
      for (unsigned j = 0; j < node->argument_count; j++) {
         const struct stela_air_stitch_node *argument = &graph->nodes[node->arguments[j]];
         if (argument->function != STELA_AIR_STITCH_INPUT)
            continue;
         unsigned index = argument->input;
         if (index >= ARRAY_SIZE(types))
            return fail(m, STELA_AIR_INPUT, "a stitched function's argument index");
         LLVMTypeRef type = LLVMTypeOf(LLVMGetParam(source->function, j));
         if (types[index] && types[index] != type)
            return fail(m, STELA_AIR_INPUT, "a stitched argument of two types");
         types[index] = type;
         inputs[index] = source->inputs[j];
         parameters = MAX2(parameters, index + 1);
      }
   }
   LLVMValueRef arguments[AIR_MAX_METADATA_OPERANDS];
   for (unsigned i = 0; i < parameters; i++) {
      if (!types[i])
         return fail(m, STELA_AIR_INPUT, "a stitched function skips an argument");
      arguments[i] = argument_metadata(m, context, inputs[i], i);
      if (!arguments[i])
         return fail(m, STELA_AIR_METADATA, "a stitched function's inputs");
   }

   const struct stela_air_stitch_node *output =
      graph->output == STELA_AIR_STITCH_NO_OUTPUT ? NULL : &graph->nodes[graph->output];
   if (output && output->function == STELA_AIR_STITCH_INPUT)
      return fail(m, STELA_AIR_INPUT, "a stitched function outputs an input");
   LLVMTypeRef result = LLVMVoidTypeInContext(context);
   if (output)
      result = LLVMGetReturnType(LLVMGlobalGetValueType(sources[output->function].function));
   if (LLVMGetNamedFunction(out, graph->name))
      return fail(m, STELA_AIR_INPUT, "a stitched function has the name of another");
   LLVMValueRef function =
      LLVMAddFunction(out, graph->name, LLVMFunctionType(result, types, parameters, false));

   LLVMValueRef *values = calloc(graph->node_count, sizeof(*values));
   if (!values)
      return fail(m, STELA_AIR_ALLOCATION, "stitched nodes");
   LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
   LLVMPositionBuilderAtEnd(builder, LLVMAppendBasicBlockInContext(context, function, "entry"));
   bool stitched = true;
   for (unsigned i = 0; stitched && i < graph->node_count; i++) {
      const struct stela_air_stitch_node *node = &graph->nodes[i];
      if (node->function == STELA_AIR_STITCH_INPUT) {
         values[i] = LLVMGetParam(function, node->input);
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
   if (!stitched)
      return false;

   LLVMValueRef empty = LLVMMDNodeInContext(context, NULL, 0);
   LLVMValueRef entry[] = {function, output ? sources[output->function].outputs : empty,
                           LLVMMDNodeInContext(context, arguments, parameters)};
   LLVMAddNamedMetadataOperand(out, "air.visible",
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
