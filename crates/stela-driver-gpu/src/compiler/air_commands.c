/* SPDX-License-Identifier: MIT */
/* AIR's indirect command functions, as Apple's compiler emits them for
 * metal_command_buffer's render_command and compute_command methods. Each
 * takes the command_buffer an argument buffer holds and the command's
 * index, then the method's arguments. A buffer setter's name carries its
 * pointer's overload, ".p1i8" or ".p2i8", and an indexed draw's that of its
 * indices, ".p1i16" or ".p1i32". */
#define STELA_AIR_METADATA_INTERNAL
#include "air_commands.h"
#include <stdio.h>
#include <string.h>

/* One function. Its signature spells the operands after the buffer and the
 * index: C a command_buffer, S a pipeline state, P a buffer pointer, u a
 * uint, l a 64-bit stride (~0 for none) and v a uint3. */
struct form {
   const char *name; /* Between "air." and any overload. */
   enum stela_air_command_op op;
   bool render;
   enum stela_air_stage stage; /* A buffer setter's; zero for a kernel's. */
   const char *signature;
};

static const struct form forms[] = {
   {"reset_render_command", STELA_AIR_COMMAND_RESET, true, 0, ""},
   {"reset_compute_command", STELA_AIR_COMMAND_RESET, false, 0, ""},
   {"copy_render_command", STELA_AIR_COMMAND_COPY, true, 0, "Cu"},
   {"copy_compute_command", STELA_AIR_COMMAND_COPY, false, 0, "Cu"},
   {"set_barrier_render_command", STELA_AIR_COMMAND_SET_BARRIER, true, 0, ""},
   {"set_barrier_compute_command", STELA_AIR_COMMAND_SET_BARRIER, false, 0, ""},
   {"clear_barrier_render_command", STELA_AIR_COMMAND_CLEAR_BARRIER, true, 0, ""},
   {"clear_barrier_compute_command", STELA_AIR_COMMAND_CLEAR_BARRIER, false, 0, ""},
   {"set_pipeline_state_render_command", STELA_AIR_COMMAND_PIPELINE, true, 0, "S"},
   {"set_pipeline_state_compute_command", STELA_AIR_COMMAND_PIPELINE, false, 0, "S"},
   /* Metal 3.1 adds the vertex and kernel buffers' strides. */
   {"set_vertex_buffer_render_command", STELA_AIR_COMMAND_BUFFER, true, STELA_AIR_VERTEX, "Plu"},
   {"set_vertex_buffer_render_command", STELA_AIR_COMMAND_BUFFER, true, STELA_AIR_VERTEX, "Pu"},
   {"set_fragment_buffer_render_command", STELA_AIR_COMMAND_BUFFER, true, STELA_AIR_FRAGMENT, "Pu"},
   {"set_kernel_buffer_compute_command", STELA_AIR_COMMAND_BUFFER, false, 0, "Plu"},
   {"set_kernel_buffer_compute_command", STELA_AIR_COMMAND_BUFFER, false, 0, "Pu"},
   {"set_threadgroup_memory_length_compute_command", STELA_AIR_COMMAND_THREADGROUP_LENGTH, false,
    0, "uu"},
   {"set_stage_in_region_compute_command", STELA_AIR_COMMAND_STAGE_IN_REGION, false, 0, "vv"},
   {"draw_primitives_render_command", STELA_AIR_COMMAND_DRAW, true, 0, "uuuuu"},
   {"draw_indexed_primitives_render_command", STELA_AIR_COMMAND_DRAW_INDEXED, true, 0, "uuPuuu"},
   {"concurrent_dispatch_threadgroups_compute_command", STELA_AIR_COMMAND_DISPATCH_THREADGROUPS,
    false, 0, "vv"},
   {"concurrent_dispatch_threads_compute_command", STELA_AIR_COMMAND_DISPATCH_THREADS, false, 0,
    "vv"},
};

#define MAX_OPERANDS 8u

static bool
ends_with(const char *name, size_t bytes, const char *suffix)
{
   size_t length = strlen(suffix);
   return bytes >= length && !memcmp(name + bytes - length, suffix, length);
}

static bool
integer(LLVMTypeRef type, unsigned bits)
{
   return LLVMGetTypeKind(type) == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type) == bits;
}

/* Whether type is that of an operand of kind. */
static bool
operand_type(LLVMTypeRef type, char kind)
{
   bool pointer = LLVMGetTypeKind(type) == LLVMPointerTypeKind;
   switch (kind) {
   case 'C':
   case 'S':
      return pointer && LLVMGetPointerAddressSpace(type) == 1;
   case 'P':
      return pointer && (LLVMGetPointerAddressSpace(type) == 1 ||
                         LLVMGetPointerAddressSpace(type) == 2);
   case 'u':
      return integer(type, 32);
   case 'l':
      return integer(type, 64);
   default:
      return LLVMGetTypeKind(type) == LLVMVectorTypeKind && LLVMGetVectorSize(type) == 3 &&
             integer(LLVMGetElementType(type), 32);
   }
}

/* Checks the call against the signature kinds, of which the first two are
 * the buffer and the index. */
static bool
typed(const struct stela_air_command_context *c, LLVMValueRef call, LLVMValueRef callee,
      const char *kinds, LLVMTypeRef result)
{
   unsigned count = (unsigned)strlen(kinds);
   if (!stela_air_call_plain(&c->call, call, callee, count))
      return false;
   bool valid = LLVMTypeOf(call) == result;
   for (unsigned i = 0; valid && i < count; i++)
      valid = operand_type(LLVMTypeOf(LLVMGetOperand(call, i)), kinds[i]);
   return valid || stela_air_call_fail(&c->call, STELA_AIR_TYPE,
                                       "indirect command function with unexpected operands");
}

/* The name a form's call must have: its pointer operand's overload, and for
 * an indexed draw that of its index_bytes indices. */
static void
form_name(const struct form *form, LLVMValueRef call, unsigned index_bytes, char *name, size_t size)
{
   const char *pointer = strchr(form->signature, 'P');
   if (!pointer) {
      snprintf(name, size, "air.%s", form->name);
      return;
   }
   LLVMTypeRef type = LLVMTypeOf(LLVMGetOperand(call, 2 + (unsigned)(pointer - form->signature)));
   snprintf(name, size, "air.%s.p%ui%u", form->name, LLVMGetPointerAddressSpace(type),
            index_bytes ? 8 * index_bytes : 8);
}

/* An operand of kind as NIR, or NULL after reporting why. */
static nir_def *
operand(const struct stela_air_command_context *c, const struct form *form, LLVMValueRef value,
        char kind)
{
   switch (kind) {
   case 'C':
      return c->resource_id(c->call.translator, value, STELA_AIR_FIELD_COMMANDS);
   case 'S':
      return c->resource_id(c->call.translator, value, form->render ?
                            STELA_AIR_FIELD_RENDER_PIPELINE : STELA_AIR_FIELD_COMPUTE_PIPELINE);
   case 'P':
      return c->address(c->call.translator, value);
   default:
      return c->call.operand(c->call.translator, value);
   }
}

/* The command a form's call encodes, from its operands' values. */
static void
fill(nir_builder *b, const struct form *form, nir_def *const *values, unsigned index_bytes,
     struct stela_air_command *command)
{
   *command = (struct stela_air_command){.op = form->op, .render = form->render,
                                         .buffer = values[0], .index = values[1]};
   nir_def *const *v = values + 2;
   switch (form->op) {
   case STELA_AIR_COMMAND_COPY:
      command->source.buffer = v[0];
      command->source.index = v[1];
      break;
   case STELA_AIR_COMMAND_PIPELINE:
      command->pipeline = v[0];
      break;
   case STELA_AIR_COMMAND_BUFFER: {
      bool strided = form->signature[1] == 'l';
      command->binding.stage = form->stage;
      command->binding.address = v[0];
      command->binding.stride = strided ? v[1] : nir_imm_int64(b, -1);
      command->binding.slot = v[strided ? 2 : 1];
      break;
   }
   case STELA_AIR_COMMAND_THREADGROUP_LENGTH:
      command->threadgroup.length = v[0];
      command->threadgroup.slot = v[1];
      break;
   case STELA_AIR_COMMAND_STAGE_IN_REGION:
      command->region.origin = v[0];
      command->region.size = v[1];
      break;
   case STELA_AIR_COMMAND_DRAW:
      command->draw.primitive = v[0];
      command->draw.first_vertex = v[1];
      command->draw.count = v[2];
      command->draw.instances = v[3];
      command->draw.base_instance = v[4];
      break;
   case STELA_AIR_COMMAND_DRAW_INDEXED:
      command->draw.primitive = v[0];
      command->draw.count = v[1];
      command->draw.indices = v[2];
      command->draw.index_bytes = index_bytes;
      command->draw.instances = v[3];
      command->draw.base_vertex = v[4];
      command->draw.base_instance = v[5];
      break;
   case STELA_AIR_COMMAND_DISPATCH_THREADGROUPS:
   case STELA_AIR_COMMAND_DISPATCH_THREADS:
      command->dispatch.grid = v[0];
      command->dispatch.threads = v[1];
      break;
   case STELA_AIR_COMMAND_RESET:
   case STELA_AIR_COMMAND_SET_BARRIER:
   case STELA_AIR_COMMAND_CLEAR_BARRIER:
      break;
   }
}

enum stela_air_call_status
stela_air_command_call(const struct stela_air_command_context *c, LLVMValueRef call,
                       LLVMValueRef callee, const char *name, size_t bytes,
                       struct stela_air_command *command, bool *size)
{
   LLVMContextRef llvm = LLVMGetTypeContext(LLVMTypeOf(call));
   *size = stela_air_call_named(name, bytes, "air.get_size_command_buffer");
   if (*size) {
      if (!typed(c, call, callee, "C", LLVMInt32TypeInContext(llvm)))
         return STELA_AIR_CALL_FAILED;
      command->buffer = operand(c, NULL, LLVMGetOperand(call, 0), 'C');
      return command->buffer ? STELA_AIR_CALL_LOWERED : STELA_AIR_CALL_FAILED;
   }
   if (bytes < 4 || memcmp(name, "air.", 4))
      return STELA_AIR_CALL_OTHER;
   const char *stem = name + 4, *dot = memchr(stem, '.', bytes - 4);
   size_t stem_bytes = dot ? (size_t)(dot - stem) : bytes - 4;
   if (!ends_with(stem, stem_bytes, "_render_command") &&
       !ends_with(stem, stem_bytes, "_compute_command"))
      return STELA_AIR_CALL_OTHER;
   const struct form *form = NULL;
   unsigned operands = LLVMGetNumArgOperands(call);
   for (unsigned i = 0; i < ARRAY_SIZE(forms); i++) {
      if (stela_air_call_named(stem, stem_bytes, forms[i].name) &&
          (!form || operands == 2 + strlen(forms[i].signature)))
         form = &forms[i];
   }
   /* Patch and mesh draws, their buffers, rasterizer state and imageblocks. */
   if (!form) {
      stela_air_call_fail(&c->call, STELA_AIR_INSTRUCTION, "unsupported indirect command function %.*s",
                          (int)MIN2(bytes, 160), name);
      return STELA_AIR_CALL_FAILED;
   }

   char kinds[MAX_OPERANDS + 1];
   snprintf(kinds, sizeof(kinds), "Cu%s", form->signature);
   if (!typed(c, call, callee, kinds, LLVMVoidTypeInContext(llvm)))
      return STELA_AIR_CALL_FAILED;
   /* Indices are ushorts or uints. */
   unsigned index_bytes = form->op == STELA_AIR_COMMAND_DRAW_INDEXED ? 2 : 0;
   char expected[96];
   form_name(form, call, index_bytes, expected, sizeof(expected));
   if (index_bytes && !stela_air_call_named(name, bytes, expected)) {
      index_bytes = 4;
      form_name(form, call, index_bytes, expected, sizeof(expected));
   }
   if (!stela_air_call_named(name, bytes, expected)) {
      stela_air_call_fail(&c->call, STELA_AIR_INSTRUCTION, "noncanonical indirect command function %.*s",
                          (int)MIN2(bytes, 160), name);
      return STELA_AIR_CALL_FAILED;
   }

   nir_def *values[MAX_OPERANDS];
   for (unsigned i = 0; kinds[i]; i++) {
      values[i] = operand(c, form, LLVMGetOperand(call, i), kinds[i]);
      if (!values[i])
         return STELA_AIR_CALL_FAILED;
   }
   fill(c->call.b, form, values, index_bytes, command);
   return STELA_AIR_CALL_LOWERED;
}
