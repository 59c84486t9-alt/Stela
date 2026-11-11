/* SPDX-License-Identifier: GPL-2.0-or-later */
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
 * output node's function returns.
 *
 * A graph's call passes one value for each of the function's stitching
 * arguments (air.stitching_info), which may differ from its parameters: a
 * struct argument passed coerced to its fields covers one parameter for each,
 * as Core Image's coreimage::Sampler does, and is passed a struct value whose
 * fields feed them. A struct argument passed indirectly, as a thread pointer
 * to a copy, is passed a pointer to a copy of the value, and a function that
 * returns a struct through its first parameter (sret) returns what the call
 * leaves there, as MPS's functions do. A stitched function whose output is
 * such a function's returns it the same way. Values cross modules by
 * layout: each module's named structs are distinct types of the same
 * fields.
 *
 * A function made with function constant values is called by its
 * specialized name (stela_air_specialized_name), which linking its module
 * with those values resolves, so two specializations of one function are
 * two functions, as Metal names them. */
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
   /* The struct it returns through its first parameter, or NULL. */
   LLVMTypeRef sret;
   /* The name its calls take. */
   char callee[512];
   /* Each stitching argument's first parameter, how many it covers and
    * whether it is a struct passed through a pointer to a copy. */
   unsigned arguments, first[AIR_MAX_METADATA_OPERANDS], covers[AIR_MAX_METADATA_OPERANDS];
   bool indirect[AIR_MAX_METADATA_OPERANDS];
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

/* Whether a parameter of `type` takes a struct through a pointer to a copy:
 * a thread pointer where the stitching argument is a struct. */
static bool
thread_pointer(LLVMTypeRef type)
{
   return LLVMGetTypeKind(type) == LLVMPointerTypeKind && !LLVMGetPointerAddressSpace(type);
}

/* The first `capacity` operands of metadata `node`, and how many it has.
 * `scratch`, of AIR_MAX_METADATA_OPERANDS, receives all of them: an
 * air.stitching_argument or air.stitching_type node carries its type's four
 * stitching_traits functions after the operands read here. */
static bool
md_operands(struct stela_air_metadata *m, LLVMValueRef node, LLVMValueRef *scratch,
            LLVMValueRef *operands, unsigned capacity, unsigned *count)
{
   if (!stela_air_md_node(m, node, scratch, count))
      return false;
   memcpy(operands, scratch, MIN2(*count, capacity) * sizeof(*operands));
   return true;
}

/* How many parameters each of `info`'s stitching arguments (an
 * air.stitching_info node: the return's air.stitching_type or null, then an
 * air.stitching_argument each) covers: one, or for a struct passed coerced,
 * one per field. A struct a thread pointer takes is passed indirectly, and
 * covers one. Info naming no argument leaves one per parameter. An sret
 * parameter is the return's, not an argument's. */
static bool
stitching_arguments(struct stela_air_metadata *m, LLVMValueRef info, struct source *source)
{
   unsigned offset = source->sret ? 1 : 0;
   unsigned total = LLVMCountParams(source->function);
   unsigned parameters = total - offset;
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_md_node(m, info, fields, &count) || !count ||
       !stela_air_md_string(fields[0], "air.stitching_info"))
      return fail(m, STELA_AIR_METADATA, "a stitched function's stitching info");
   unsigned arguments = 0;
   unsigned field_counts[AIR_MAX_METADATA_OPERANDS];
   LLVMValueRef scratch[AIR_MAX_METADATA_OPERANDS];
   /* Operand 1 is the return's type, null for a function returning void. */
   for (unsigned i = 2; i < count; i++) {
      LLVMValueRef entry[2], type[2], layout[6];
      unsigned entry_count, type_count, layout_count;
      if (!md_operands(m, fields[i], scratch, entry, ARRAY_SIZE(entry), &entry_count) ||
          !entry_count)
         return fail(m, STELA_AIR_METADATA, "a stitched function's stitching info");
      if (!stela_air_md_string(entry[0], "air.stitching_argument"))
         continue;
      if (entry_count < 2 || arguments == parameters)
         return fail(m, STELA_AIR_METADATA, "a stitched function's stitching arguments");
      if (!md_operands(m, entry[1], scratch, type, ARRAY_SIZE(type), &type_count) ||
          type_count < 2 ||
          !md_operands(m, type[1], scratch, layout, ARRAY_SIZE(layout), &layout_count) ||
          !layout_count)
         return fail(m, STELA_AIR_METADATA, "a stitched function's stitching type");
      field_counts[arguments] = 0;
      if (stela_air_md_string(layout[0], "air.struct_type") && layout_count >= 6) {
         unsigned member_count;
         if (!stela_air_md_node(m, layout[5], scratch, &member_count))
            return fail(m, STELA_AIR_METADATA, "a stitched struct argument's fields");
         field_counts[arguments] = member_count;
      }
      arguments++;
   }
   /* Every argument covers one parameter, or every struct argument not
    * passed indirectly is coerced to its fields: only these account for
    * every parameter. */
   bool coerced = arguments && arguments != parameters;
   source->arguments = arguments ? arguments : parameters;
   unsigned first = offset;
   for (unsigned i = 0; i < source->arguments; i++) {
      bool is_struct = arguments && field_counts[i];
      source->first[i] = first;
      source->indirect[i] =
         is_struct && first < total && thread_pointer(LLVMTypeOf(LLVMGetParam(source->function, first)));
      source->covers[i] = coerced && is_struct && !source->indirect[i] ? field_counts[i] : 1;
      first += source->covers[i];
   }
   if (first != total) {
      char detail[sizeof(m->error->detail)];
      snprintf(detail, sizeof(detail),
               "stitched function %s's %u arguments cover %u of its %u parameters",
               LLVMGetValueName(source->function), source->arguments, first, total);
      return fail(m, STELA_AIR_INPUT, detail);
   }
   return true;
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
   if (source->function && LLVMCountParams(source->function)) {
      unsigned kind = LLVMGetEnumAttributeKindForName("sret", 4);
      LLVMAttributeRef sret = LLVMGetEnumAttributeAtIndex(source->function, 1, kind);
      source->sret = sret ? LLVMGetTypeAttributeValue(sret) : NULL;
   }
   size_t name_bytes = strlen(from->name);
   bool named = from->constant_count ?
      stela_air_specialized_name(from->name, name_bytes, from->constants, from->constant_count,
                                 source->callee, sizeof(source->callee)) :
      name_bytes < sizeof(source->callee);
   if (!named)
      return fail(m, STELA_AIR_LIMIT, "a stitched function's name is too long");
   if (!from->constant_count)
      memcpy(source->callee, from->name, name_bytes + 1);
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
      if (field_count >= 4)
         return stitching_arguments(m, fields[3], source);
      unsigned offset = source->sret ? 1 : 0;
      source->arguments = input_count - offset;
      for (unsigned j = 0; j < source->arguments; j++) {
         source->first[j] = j + offset;
         source->covers[j] = 1;
      }
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

static LLVMTypeRef canonical(LLVMContextRef context, LLVMTypeRef type);

/* The type a call node's function returns, itself or through sret. */
static LLVMTypeRef
returned(const struct source *sources, const struct stela_air_stitch_node *call)
{
   const struct source *source = &sources[call->function];
   LLVMValueRef function = source->function;
   return canonical(LLVMGetTypeContext(LLVMTypeOf(function)),
                    source->sret ? source->sret :
                                   LLVMGetReturnType(LLVMGlobalGetValueType(function)));
}

/* Thread memory for a value of `type`, at the start of the stitched
 * function's `entry` block. */
static LLVMValueRef
slot(LLVMModuleRef out, LLVMBuilderRef allocas, LLVMBasicBlockRef entry, LLVMTypeRef type)
{
   LLVMValueRef first = LLVMGetFirstInstruction(entry);
   if (first)
      LLVMPositionBuilderBefore(allocas, first);
   else
      LLVMPositionBuilderAtEnd(allocas, entry);
   LLVMValueRef memory = LLVMBuildAlloca(allocas, type, "");
   LLVMTargetDataRef layout = LLVMCreateTargetData(LLVMGetDataLayoutStr(out));
   LLVMSetAlignment(memory, LLVMABIAlignmentOfType(layout, type));
   LLVMDisposeTargetData(layout);
   return memory;
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

/* Whether a and b hold the same values: equal, or structs and arrays whose
 * elements do. */
bool
stela_air_isomorphic(LLVMContextRef context, LLVMTypeRef a, LLVMTypeRef b)
{
   if (a == b)
      return true;
   LLVMTypeKind kind = LLVMGetTypeKind(a);
   if (kind != LLVMGetTypeKind(b))
      return false;
   if (kind == LLVMArrayTypeKind)
      return LLVMGetArrayLength2(a) == LLVMGetArrayLength2(b) &&
             stela_air_isomorphic(context, LLVMGetElementType(a), LLVMGetElementType(b));
   if (kind != LLVMStructTypeKind || LLVMIsPackedStruct(a) != LLVMIsPackedStruct(b) ||
       LLVMCountStructElementTypes(a) != LLVMCountStructElementTypes(b))
      return false;
   for (unsigned i = 0; i < LLVMCountStructElementTypes(a); i++) {
      if (!stela_air_isomorphic(context, LLVMStructGetTypeAtIndex(a, i),
                                LLVMStructGetTypeAtIndex(b, i)))
         return false;
   }
   return true;
}

/* A type with each named struct the first of its name it is isomorphic to.
 * Sources parse into one context, so a second source's copy of a struct type
 * they share is renamed (`T.0`); a callee declared with the copy keeps a call
 * type the definition linked with the original does not have, and is never
 * inlined (Core Image's _ci_sampler_builder and its filters both define
 * `struct.metal::texture2d`). */
static LLVMTypeRef
canonical(LLVMContextRef context, LLVMTypeRef type)
{
   switch (LLVMGetTypeKind(type)) {
   case LLVMStructTypeKind: {
      const char *name = LLVMGetStructName(type);
      if (!name || LLVMIsLiteralStruct(type))
         return type;
      char prefix[512];
      size_t length = strlen(name);
      if (length >= sizeof(prefix))
         return type;
      memcpy(prefix, name, length + 1);
      for (;;) {
         char *dot = strrchr(prefix, '.');
         if (!dot || !dot[1] || strspn(dot + 1, "0123456789") != strlen(dot + 1))
            return type;
         *dot = '\0';
         LLVMTypeRef original = LLVMGetTypeByName2(context, prefix);
         if (original && original != type && LLVMGetTypeKind(original) == LLVMStructTypeKind &&
             !LLVMIsOpaqueStruct(original) && !LLVMIsOpaqueStruct(type) &&
             stela_air_isomorphic(context, original, type))
            return original;
      }
   }
   case LLVMArrayTypeKind:
      return LLVMArrayType2(canonical(context, LLVMGetElementType(type)),
                            LLVMGetArrayLength2(type));
   case LLVMFunctionTypeKind: {
      unsigned count = LLVMCountParamTypes(type);
      LLVMTypeRef params[AIR_MAX_METADATA_OPERANDS];
      if (count > ARRAY_SIZE(params))
         return type;
      LLVMGetParamTypes(type, params);
      for (unsigned i = 0; i < count; i++)
         params[i] = canonical(context, params[i]);
      return LLVMFunctionType(canonical(context, LLVMGetReturnType(type)), params, count,
                              LLVMIsFunctionVarArg(type));
   }
   default:
      return type;
   }
}

/* `value` as `to`, a type of the same layout: itself, or for structs and
 * arrays of the same shape, its elements each converted; NULL otherwise. */
LLVMValueRef
stela_air_convert_layout(LLVMBuilderRef builder, LLVMValueRef value, LLVMTypeRef to)
{
   if (!value)
      return NULL;
   LLVMTypeRef from = LLVMTypeOf(value);
   if (from == to)
      return value;
   LLVMTypeKind kind = LLVMGetTypeKind(from);
   if (kind != LLVMGetTypeKind(to))
      return NULL;
   unsigned count;
   if (kind == LLVMStructTypeKind) {
      count = LLVMCountStructElementTypes(from);
      if (count != LLVMCountStructElementTypes(to) || LLVMIsPackedStruct(from) != LLVMIsPackedStruct(to))
         return NULL;
   } else if (kind == LLVMArrayTypeKind) {
      count = LLVMGetArrayLength2(from);
      if (count != LLVMGetArrayLength2(to))
         return NULL;
   } else {
      return NULL;
   }
   LLVMValueRef converted = LLVMGetPoison(to);
   for (unsigned i = 0; i < count; i++) {
      LLVMTypeRef element = kind == LLVMStructTypeKind ? LLVMStructGetTypeAtIndex(to, i) :
                                                         LLVMGetElementType(to);
      LLVMValueRef field =
         stela_air_convert_layout(builder, LLVMBuildExtractValue(builder, value, i, ""), element);
      if (!field)
         return NULL;
      converted = LLVMBuildInsertValue(builder, converted, field, i, "");
   }
   return converted;
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
      if (node->argument_count != source->arguments) {
         free(builtins);
         free(textures);
         return fail(m, STELA_AIR_INPUT, "a stitched call has the wrong number of arguments");
      }
      for (unsigned j = 0; j < node->argument_count; j++) {
         const struct stela_air_stitch_node *argument = &graph->nodes[node->arguments[j]];
         unsigned parameter = source->first[j];
         LLVMTypeRef type = LLVMTypeOf(LLVMGetParam(source->function, parameter));
         bool calls = argument->function < STELA_AIR_STITCH_CALLS;
         if (source->covers[j] != 1 && !calls) {
            free(builtins);
            free(textures);
            return fail(m, STELA_AIR_INPUT, "a stitched struct argument is no call's value");
         }
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
               describe_texture(LLVMGetParam(source->function, parameter),
                                &textures[node->arguments[j]]);
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
         inputs[index] = source->inputs[parameter];
         parameters = MAX2(parameters, index + 1);
      }
   }
   const struct stela_air_stitch_node *output =
      graph->output == STELA_AIR_STITCH_NO_OUTPUT ? NULL : &graph->nodes[graph->output];
   const char *refusal = NULL;
   enum stela_air_error_kind refused = STELA_AIR_INPUT;
   if (output && output->function == STELA_AIR_STITCH_INPUT)
      refusal = "a stitched function outputs an input";
   if (!refusal && output && output->function >= STELA_AIR_STITCH_CALLS)
      refusal = "a stitched function outputs what is no call";
   /* A function returning through sret is called the same way, and its
    * first parameter is its output's. */
   const struct source *output_source = output && !refusal ? &sources[output->function] : NULL;
   LLVMTypeRef output_sret =
      output_source && output_source->sret ? canonical(context, output_source->sret) : NULL;
   unsigned offset = output_sret ? 1 : 0;
   if (!refusal && parameters + offset > ARRAY_SIZE(types))
      refusal = "a stitched function's argument index";
   LLVMValueRef arguments[AIR_MAX_METADATA_OPERANDS];
   if (!refusal && output_sret) {
      arguments[0] = argument_metadata(m, context, output_source->inputs[0], 0);
      if (!arguments[0])
         refusal = "a stitched function's inputs", refused = STELA_AIR_METADATA;
   }
   for (unsigned i = 0; !refusal && i < parameters; i++) {
      arguments[i + offset] = types[i] ? argument_metadata(m, context, inputs[i], i + offset) : NULL;
      if (!types[i])
         refusal = "a stitched function skips an argument";
      else if (!arguments[i + offset])
         refusal = "a stitched function's inputs", refused = STELA_AIR_METADATA;
   }
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
   if (output && !output_sret)
      result = canonical(context, LLVMGetReturnType(LLVMGlobalGetValueType(output_source->function)));
   LLVMTypeRef parameter_list[AIR_MAX_METADATA_OPERANDS];
   if (output_sret)
      parameter_list[0] = LLVMPointerTypeInContext(context, 0);
   for (unsigned i = 0; i < parameters; i++)
      parameter_list[i + offset] = types[i];
   LLVMValueRef function = LLVMAddFunction(
      out, graph->name, LLVMFunctionType(result, parameter_list, parameters + offset, false));
   unsigned sret_kind = LLVMGetEnumAttributeKindForName("sret", 4);
   if (output_sret)
      LLVMAddAttributeAtIndex(function, 1, LLVMCreateTypeAttribute(context, sret_kind, output_sret));

   /* The entry block starts with the thread memory of calls. */
   LLVMBasicBlockRef entry = LLVMAppendBasicBlockInContext(context, function, "entry");
   LLVMBuilderRef allocas = LLVMCreateBuilderInContext(context);
   LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
   LLVMPositionBuilderAtEnd(builder, entry);
   bool stitched = true;
   for (unsigned i = 0; stitched && i < graph->node_count; i++) {
      const struct stela_air_stitch_node *node = &graph->nodes[i];
      if (node->function == STELA_AIR_STITCH_INPUT) {
         values[i] = LLVMGetParam(function, node->input + offset);
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
         if (node->argument_count && output_sret) {
            LLVMBuildStore(builder, values[node->arguments[0]], LLVMGetParam(function, 0));
            LLVMBuildRetVoid(builder);
         } else if (node->argument_count) {
            LLVMBuildRet(builder, values[node->arguments[0]]);
         } else {
            LLVMBuildRetVoid(builder);
         }
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
      LLVMTypeRef type = canonical(context, LLVMGlobalGetValueType(source->function));
      LLVMTypeRef sret = source->sret ? canonical(context, source->sret) : NULL;
      LLVMValueRef callee = LLVMGetNamedFunction(out, source->callee);
      if (!callee) {
         callee = LLVMAddFunction(out, source->callee, type);
         if (sret)
            LLVMAddAttributeAtIndex(callee, 1, LLVMCreateTypeAttribute(context, sret_kind, sret));
      }
      LLVMValueRef call_arguments[AIR_MAX_METADATA_OPERANDS];
      LLVMTypeRef parameter_types[AIR_MAX_METADATA_OPERANDS];
      unsigned parameters_passed = LLVMCountParams(source->function);
      if (parameters_passed > ARRAY_SIZE(parameter_types)) {
         fail(m, STELA_AIR_INPUT, "a stitched call has too many parameters");
         stitched = false;
         break;
      }
      LLVMGetParamTypes(type, parameter_types);
      LLVMValueRef returned_memory = sret ? slot(out, allocas, entry, sret) : NULL;
      if (sret)
         call_arguments[0] = returned_memory;
      for (unsigned j = 0; stitched && j < node->argument_count; j++) {
         LLVMValueRef value = values[node->arguments[j]];
         unsigned first = source->first[j], covers = source->covers[j];
         /* A struct value passed indirectly is copied to thread memory; a
          * pointer, as an input passes, is the copy's already. */
         if (source->indirect[j] && value &&
             LLVMGetTypeKind(LLVMTypeOf(value)) != LLVMPointerTypeKind) {
            LLVMValueRef copy = slot(out, allocas, entry, LLVMTypeOf(value));
            LLVMBuildStore(builder, value, copy);
            call_arguments[first] = copy;
            continue;
         }
         if (covers == 1) {
            call_arguments[first] =
               stela_air_convert_layout(builder, value, parameter_types[first]);
            stitched = call_arguments[first] != NULL;
            continue;
         }
         LLVMTypeRef from = value ? LLVMTypeOf(value) : NULL;
         stitched = from && LLVMGetTypeKind(from) == LLVMStructTypeKind &&
                    LLVMCountStructElementTypes(from) == covers;
         for (unsigned k = 0; stitched && k < covers; k++) {
            LLVMValueRef field = LLVMBuildExtractValue(builder, value, k, "");
            call_arguments[first + k] =
               stela_air_convert_layout(builder, field, parameter_types[first + k]);
            stitched = call_arguments[first + k] != NULL;
         }
      }
      if (stitched) {
         values[i] = LLVMBuildCall2(builder, type, callee, call_arguments, parameters_passed, "");
         LLVMSetInstructionCallConv(values[i], LLVMGetFunctionCallConv(source->function));
         if (sret) {
            LLVMAddCallSiteAttribute(values[i], 1, LLVMCreateTypeAttribute(context, sret_kind, sret));
            values[i] = LLVMBuildLoad2(builder, sret, returned_memory, "");
         }
      }
   }
   if (stitched && output_sret) {
      LLVMBuildStore(builder, values[graph->output], LLVMGetParam(function, 0));
      LLVMBuildRetVoid(builder);
   } else if (stitched && output) {
      LLVMBuildRet(builder, values[graph->output]);
   } else if (stitched) {
      LLVMBuildRetVoid(builder);
   } else {
      fail(m, STELA_AIR_INPUT, "a stitched call's argument has another type");
   }
   LLVMDisposeBuilder(builder);
   LLVMDisposeBuilder(allocas);
   free(values);
   free(builtins);
   free(textures);
   if (!stitched)
      return false;

   LLVMValueRef empty = LLVMMDNodeInContext(context, NULL, 0);
   LLVMValueRef listed[] = {function, output ? output_source->outputs : empty,
                            LLVMMDNodeInContext(context, arguments, parameters + offset)};
   LLVMAddNamedMetadataOperand(out, graph->kernel ? "air.kernel" : "air.visible",
                               LLVMMDNodeInContext(context, listed, ARRAY_SIZE(listed)));
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
