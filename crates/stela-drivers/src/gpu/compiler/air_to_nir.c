/* SPDX-License-Identifier: MIT */
#define STELA_AIR_METADATA_INTERNAL
#include "air_to_nir.h"
#include "air_calls.h"
#include "air_commands.h"
#include "air_constants.h"
#include "air_math.h"
#include "air_simd.h"
#include "air_texture.h"
#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/Core.h"
#include "llvm-c/Target.h"
#include "llvm-c/Error.h"
#include "llvm-c/Transforms/PassBuilder.h"
#include "util/hash_table.h"
#include "util/ralloc.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct air_block {
   LLVMBasicBlockRef llvm;
   nir_block *start;
   nir_block *end; /* Actual predecessor after any guarded-access splits. */
   bool reachable;
   LLVMValueRef incoming_phi, incoming_value; /* Deduplicate one PHI in linear time. */
};

struct value {
   nir_def *def;
   unsigned access; /* Buffer provenance; zero for integer values. */
   LLVMValueRef pointer_root; /* Proven resource identity, never a numeric address. */
   bool ssbo;
   unsigned ssbo_slot;
   /* Threadgroup or thread memory's variable, or, without one, constant data
    * at constant_base in the shader's data. Either is storage_size bytes. */
   nir_variable *storage;
   bool constant_data;
   unsigned storage_size, constant_base;
   /* A pointer into an argument buffer: the buffer's fields, the constant
    * part of the pointer's offset and the greatest common divisor of the
    * steps its dynamic indices add (zero without one). PHIs lose the
    * offset. */
   struct stela_air_fields fields;
   bool offset_known;
   uint64_t offset, steps;
   /* Partial values have no vector def until every lane is defined. Missing
    * lanes are tracked symbolically, never replaced with zero/undef. */
   nir_def *lanes[4];
   unsigned components, bits, aggregate_count;
   struct value **elements;
   /* Texture and sampler arguments, used only as texture call operands, and
    * the MTLResourceID of one an argument buffer or array holds. A texture or
    * sampler array argument, and each pointer into it, is instead an array:
    * def is the pointer's byte offset among the array's handles. */
   const struct stela_air_texture *texture;
   const struct stela_air_sampler *sampler;
   nir_def *id;
   bool array;
   /* The argument buffer field of an indirect command buffer or pipeline
    * state whose gpuResourceID is id, which only command calls use. */
   const struct stela_air_field *object;
   /* A two-member result: a texture call's {texel, residency} or cmpxchg's
    * {old value, exchanged}. A member is NULL when nothing reads it. */
   nir_def *members[2];
};

bool
stela_air_ssbo_view_valid(const struct stela_air_ssbo_view *view,
                          unsigned ssbo_count)
{
   return view && ssbo_count && ssbo_count <= UINT8_MAX &&
          view->slot < ssbo_count && view->size && view->size <= UINT32_MAX &&
          view->access >= STELA_AIR_READ && view->access <= STELA_AIR_READ_WRITE &&
          view->available_access >= STELA_AIR_READ && view->available_access <= STELA_AIR_READ_WRITE &&
          !(view->access & ~view->available_access) &&
          view->alignment && !(view->alignment & (view->alignment - 1)) &&
          !(view->offset & (view->alignment - 1)) &&
          view->offset <= view->buffer_size &&
          view->size <= view->buffer_size - view->offset;
}

struct pointer_node {
   LLVMValueRef llvm, root;
   unsigned index, low, next, component;
   bool active;
};

struct translator {
   LLVMContextRef context;
   LLVMModuleRef module;
   LLVMTargetDataRef layout; /* Borrowed from module. */
   struct stela_air_metadata metadata;
   nir_builder b;
   struct hash_table *values;
   const struct stela_air_options *options;
   const struct stela_air_stage_options *stage_options;
   struct stela_air_render render;
   const struct stela_air_field *fields; /* The entry's argument buffer fields. */
   nir_variable *outputs[AIR_MAX_ARGUMENTS];
   /* An object or mesh function's mesh grid properties or mesh, its payload,
    * a mesh's primitive indices, the grid or primitive count any thread may
    * set, and the block every thread leaves the function through. */
   LLVMValueRef mesh, mesh_grid;
   nir_variable *payload, *indices, *mesh_state;
   nir_block *exit;
   /* An amplified vertex function's layer and viewport outputs. */
   nir_variable *layer, *viewport;
   /* A post-tessellation vertex function's STELA_AIR_PATCH_IDS. */
   nir_def *patch_ids;
   struct stela_air_error *error;
   unsigned air_minor;
   unsigned language_major, language_minor;
   unsigned max_device_buffers;
   unsigned max_threadgroup_buffers;
   unsigned shared_resources;
   /* A dynamic kernel's threadgroup memory its dispatches place buffers in. */
   nir_variable *dynamic_threadgroup;
   unsigned shared_barriers;
   uint64_t shared_layout_bound;
   unsigned private_allocations;
   uint64_t private_layout_bound;
   bool denorms_disable;
   bool fast_math;
   bool fp_checked;
   LLVMValueRef entry;
   void *cfg_scratch;
   struct hash_table *block_map, *pointer_map;
   struct pointer_node *pointers;
   unsigned pointer_count;
   struct air_block *blocks;
   struct air_block **work;
   unsigned block_count, reachable_count;
};

static bool
fail(struct translator *t, enum stela_air_error_kind kind, const char *fmt, ...)
{
   if (t->error->kind == STELA_AIR_OK) {
      t->error->kind = kind;
      va_list args;
      va_start(args, fmt);
      vsnprintf(t->error->detail, sizeof(t->error->detail), fmt, args);
      va_end(args);
   }
   return false;
}

static void
diagnostic(LLVMDiagnosticInfoRef info, void *data)
{
   struct translator *t = data;
   if (LLVMGetDiagInfoSeverity(info) != LLVMDSError)
      return;
   char *message = LLVMGetDiagInfoDescription(info);
   fail(t, STELA_AIR_BITCODE, "%s", message ? message : "LLVM bitcode diagnostic");
   LLVMDisposeMessage(message);
}

#define md_string stela_air_md_string
#define md_uint stela_air_md_uint
static bool
md_node(struct translator *t, LLVMValueRef node, LLVMValueRef *operands, unsigned *count)
{
   return stela_air_md_node(&t->metadata, node, operands, count);
}
static bool
named_md(struct translator *t, const char *name, LLVMValueRef *operands, unsigned *count)
{
   return stela_air_named_md(&t->metadata, name, operands, count);
}

static bool
shape(LLVMTypeRef type, unsigned *components, unsigned *bits)
{
   *components = 1;
   if (LLVMGetTypeKind(type) == LLVMVectorTypeKind) {
      *components = LLVMGetVectorSize(type);
      if (*components < 2 || *components > 4)
         return false;
      type = LLVMGetElementType(type);
   }
   if (LLVMGetTypeKind(type) != LLVMIntegerTypeKind)
      return false;
   *bits = LLVMGetIntTypeWidth(type);
   return *bits == 1 || *bits == 8 || *bits == 16 || *bits == 32 || *bits == 64;
}

static bool
float_shape(LLVMTypeRef type, unsigned *components, unsigned *bits)
{
   *components = 1;
   if (LLVMGetTypeKind(type) == LLVMVectorTypeKind) {
      *components = LLVMGetVectorSize(type);
      if (*components < 2 || *components > 4)
         return false;
      type = LLVMGetElementType(type);
   }
   *bits = LLVMGetTypeKind(type) == LLVMHalfTypeKind ? 16 : 32;
   return LLVMGetTypeKind(type) == LLVMFloatTypeKind || LLVMGetTypeKind(type) == LLVMHalfTypeKind;
}

static bool
value_shape(LLVMTypeRef type, unsigned *components, unsigned *bits)
{
   return shape(type, components, bits) || float_shape(type, components, bits);
}

/* A render aggregate leaf: an integer, float or half scalar or vector. */
static bool
leaf_shape(LLVMTypeRef type)
{
   unsigned components, bits;
   return value_shape(type, &components, &bits);
}

static bool
fp_environment(struct translator *t)
{
   if (t->fp_checked)
      return true;
   if (t->denorms_disable && t->options->fp_profile != STELA_AIR_FP_METAL)
      return fail(t, STELA_AIR_METADATA, "AIR denorms_disable arithmetic requires the Metal FP profile");
   bool ftz = t->denorms_disable;
   const char *special[] = {"strictfp", "denormal_fpenv"};
   for (unsigned i = 0; i < ARRAY_SIZE(special); i++) {
      unsigned kind = LLVMGetEnumAttributeKindForName(special[i], strlen(special[i]));
      if (kind && LLVMGetEnumAttributeAtIndex(t->entry, LLVMAttributeFunctionIndex, kind))
         return fail(t, STELA_AIR_TYPE, "unsupported FP environment attribute: %s", special[i]);
   }
   const char *strings[] = {"denormal-fp-math", "denormal-fp-math-f32", "rounding-math"};
   for (unsigned i = 0; i < ARRAY_SIZE(strings); i++) {
      if (LLVMGetStringAttributeAtIndex(t->entry, LLVMAttributeFunctionIndex,
                                       strings[i], strlen(strings[i])))
         return fail(t, STELA_AIR_TYPE, "unsupported FP environment attribute: %s", strings[i]);
   }
   t->b.shader->info.float_controls_execution_mode =
      (ftz ? FLOAT_CONTROLS_DENORM_FLUSH_TO_ZERO_FP32 : FLOAT_CONTROLS_DENORM_PRESERVE_FP32) |
      FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP32;
   t->fp_checked = true;
   return true;
}

/* Whether any ALU operation reads or writes a half. */
static bool
half_arithmetic(nir_shader *shader)
{
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_alu)
               continue;
            nir_alu_instr *alu = nir_instr_as_alu(instr);
            const nir_op_info *info = &nir_op_infos[alu->op];
            if (nir_alu_type_get_base_type(info->output_type) == nir_type_float &&
                alu->def.bit_size == 16)
               return true;
            for (unsigned i = 0; i < info->num_inputs; i++) {
               if (nir_alu_type_get_base_type(info->input_types[i]) == nir_type_float &&
                   nir_src_bit_size(alu->src[i].src) == 16)
                  return true;
            }
         }
      }
   }
   return false;
}

static unsigned
fp_math_control(LLVMValueRef inst)
{
   unsigned control = nir_fp_no_fast_math;
   LLVMFastMathFlags flags = LLVMCanValueUseFastMathFlags(inst) ? LLVMGetFastMathFlags(inst) : 0;
   if (flags & LLVMFastMathNoNaNs)
      control &= ~nir_fp_preserve_nan;
   if (flags & LLVMFastMathNoInfs)
      control &= ~nir_fp_preserve_inf;
   /* LLVM 23 nsz permits changing zero input signs; NIR's corresponding bit
    * also relaxes output signs. Keeping it set is a conservative refinement. */
   if (flags & LLVMFastMathAllowContract)
      control &= ~nir_fp_no_contract;
   if (flags & LLVMFastMathAllowReassoc)
      control &= ~nir_fp_no_reassoc;
   /* Keep NIR's broader real-number transform restriction. LLVM arcp/afn are
    * permissions, not required approximations; division/functions are refused. */
   return control;
}

static bool
put_value(struct translator *t, LLVMValueRef llvm, nir_def *def, unsigned access)
{
   if (!def)
      return fail(t, STELA_AIR_ALLOCATION, "AIR value definition unavailable");
   struct value *value = ralloc(t->values, struct value);
   if (!value)
      return fail(t, STELA_AIR_ALLOCATION, "AIR value allocation failed");
   *value = (struct value){.def = def, .access = access,
      .components = def->num_components, .bits = def->bit_size};
   if (!_mesa_hash_table_insert(t->values, llvm, value))
      return fail(t, STELA_AIR_ALLOCATION, "AIR value map allocation failed");
   return true;
}

static bool
put_pair(struct translator *t, LLVMValueRef llvm, nir_def *first, nir_def *second)
{
   struct value *value = rzalloc(t->values, struct value);
   if (!value || !_mesa_hash_table_insert(t->values, llvm, value))
      return fail(t, STELA_AIR_ALLOCATION, "AIR pair allocation failed");
   value->members[0] = first;
   value->members[1] = second;
   return true;
}

static struct value *
find_value(struct translator *t, LLVMValueRef llvm)
{
   struct hash_entry *entry = _mesa_hash_table_search(t->values, llvm);
   return entry ? entry->data : NULL;
}

static nir_def *module_global(struct translator *t, LLVMValueRef global);
static nir_variable *shared_resource(struct translator *t, uint64_t size, unsigned alignment);
static nir_variable *dynamic_threadgroup(struct translator *t, const struct stela_air_buffer *buffer);
static nir_def *stage_narrow(nir_builder *b, nir_def *def, enum stela_air_primitive p);

/* Static pointer authority is separate from the offset/VA in def. */
static void
pointer_authority(struct value *target, const struct value *root)
{
   target->pointer_root = root->pointer_root;
   target->access = root->access;
   target->ssbo = root->ssbo;
   target->ssbo_slot = root->ssbo_slot;
   target->storage = root->storage;
   target->constant_data = root->constant_data;
   target->storage_size = root->storage_size;
   target->constant_base = root->constant_base;
   target->fields = root->fields;
   target->array = root->array;
   target->texture = root->texture;
   target->sampler = root->sampler;
}

static uint64_t
gcd(uint64_t a, uint64_t b)
{
   while (b) {
      uint64_t rest = a % b;
      a = b;
      b = rest;
   }
   return a;
}

/* A derived pointer's offset within its argument buffer: origin's, plus
 * offset and dynamic indices of steps. */
static void
pointer_offset(struct value *target, const struct value *origin, uint64_t offset, uint64_t steps)
{
   target->offset_known = origin->offset_known;
   target->offset = origin->offset + offset;
   target->steps = gcd(origin->steps, steps);
}

/* Thread, device, constant, threadgroup or object data memory; roots
 * validate the rest. */
static bool
pointer_space(LLVMTypeRef type)
{
   return LLVMGetTypeKind(type) == LLVMPointerTypeKind &&
          (LLVMGetPointerAddressSpace(type) <= 3 || LLVMGetPointerAddressSpace(type) == 6);
}

/* A kernel, object or mesh function. */
static bool
compute_like(const struct translator *t)
{
   return !t->stage_options || t->stage_options->stage == STELA_AIR_OBJECT ||
          t->stage_options->stage == STELA_AIR_MESH;
}

static nir_def *
get_value(struct translator *t, LLVMValueRef llvm)
{
   struct value *value = find_value(t, llvm);
   if (value) {
      if (!value->def) fail(t, STELA_AIR_INSTRUCTION, "undefined/poison/aggregate reaches scalar-vector use");
      return value->def;
   }
   if (LLVMIsAGlobalVariable(llvm))
      return module_global(t, llvm);
   unsigned components, bits;
   if (!value_shape(LLVMTypeOf(llvm), &components, &bits)) {
      fail(t, STELA_AIR_TYPE, "unsupported AIR operand type");
      return NULL;
   }
   if (LLVMIsAConstantAggregateZero(llvm))
      return nir_imm_zero(&t->b, components, bits);
   if (components == 1 && LLVMIsAConstantInt(llvm))
      return nir_imm_intN_t(&t->b, LLVMConstIntGetZExtValue(llvm), bits);
   if (components == 1 && LLVMIsAConstantFP(llvm)) {
      /* Let LLVM serialize its APFloat bits; a host float/double conversion
       * could change a NaN's payload or signed zero before NIR sees it. */
      LLVMValueRef encoded = LLVMConstBitCast(llvm, LLVMIntTypeInContext(t->context, bits));
      if (LLVMIsAConstantInt(encoded))
         return nir_imm_intN_t(&t->b, LLVMConstIntGetZExtValue(encoded), bits);
   }
   if (components > 1 && (LLVMIsAConstantVector(llvm) ||
                         LLVMIsAConstantDataVector(llvm) ||
                         (t->stage_options && (LLVMIsAConstantFP(llvm) || LLVMIsAConstantInt(llvm))))) {
      nir_def *elements[4];
      for (unsigned i = 0; i < components; i++) {
         LLVMValueRef element = LLVMGetAggregateElement(llvm, i);
         elements[i] = get_value(t, element);
         if (!elements[i])
            return NULL;
      }
      return nir_vec(&t->b, elements, components);
   }
   fail(t, STELA_AIR_INSTRUCTION, "undefined/poison/forward/constant-expression operand");
   return NULL;
}

/* A pointer operand's value, materializing a module global on first use. */
static struct value *
pointer_value(struct translator *t, LLVMValueRef pointer)
{
   if (LLVMIsAGlobalVariable(pointer) && !get_value(t, pointer))
      return NULL;
   return find_value(t, pointer);
}

/* A texture or sampler argument's value, which only texture calls use, or an
 * array argument's, which only its element loads do. */
static bool
put_resource(struct translator *t, LLVMValueRef param, const struct stela_air_texture *texture,
             const struct stela_air_sampler *sampler)
{
   unsigned length = texture ? texture->length : sampler->length;
   bool bound = texture ? t->options->bind_texture_id != NULL : t->options->bind_sampler_id != NULL;
   if (length && (!t->options->resource_id || !bound))
      return fail(t, STELA_AIR_ARGUMENT, "unbound texture or sampler array %u",
                  texture ? texture->argument : sampler->argument);
   struct value *value = rzalloc(t->values, struct value);
   if (!value)
      return fail(t, STELA_AIR_ALLOCATION, "AIR resource value allocation failed");
   if (length) {
      *value = (struct value){.def = nir_imm_int64(&t->b, 0), .access = STELA_AIR_READ,
         .pointer_root = param, .offset_known = true, .array = true, .components = 1, .bits = 64};
   }
   if (texture) {
      struct stela_air_texture *copy = ralloc(t->values, struct stela_air_texture);
      if (!copy)
         return fail(t, STELA_AIR_ALLOCATION, "AIR texture allocation failed");
      *copy = *texture;
      value->texture = copy;
   } else {
      struct stela_air_sampler *copy = ralloc(t->values, struct stela_air_sampler);
      if (!copy)
         return fail(t, STELA_AIR_ALLOCATION, "AIR sampler allocation failed");
      *copy = *sampler;
      value->sampler = copy;
   }
   if (!_mesa_hash_table_insert(t->values, param, value))
      return fail(t, STELA_AIR_ALLOCATION, "AIR value map allocation failed");
   return true;
}

static bool
binding_prelude(struct translator *t)
{
   if (exec_list_length(&t->b.impl->body) != 1 ||
       nir_block_ends_in_jump(nir_start_block(t->b.impl)))
      return fail(t, STELA_AIR_CONTROL_FLOW, "resource callback must emit a straight-line prelude");
   return true;
}

static nir_def *
device_value(struct translator *t, enum stela_air_device_value value)
{
   if (!t->options->load_device_value) {
      fail(t, STELA_AIR_ARGUMENT, "builtin needs a device value the target does not supply");
      return NULL;
   }
   nir_def *def = t->options->load_device_value(&t->b, value, t->options->binding_data);
   unsigned components = value == STELA_AIR_DISPATCH_GRID || value == STELA_AIR_PATCH_IDS ||
                         value == STELA_AIR_THREADGROUP_SHAPE ? 3 : 1;
   if (!def || def->num_components != components || def->bit_size != 32 || !binding_prelude(t)) {
      fail(t, STELA_AIR_ARGUMENT, "invalid device value");
      return NULL;
   }
   return def;
}

static nir_def *
workgroup_size(struct translator *t)
{
   const unsigned *size = t->options->workgroup_size;
   return nir_imm_ivec3(&t->b, (int)size[0], (int)size[1], (int)size[2]);
}

/* The threadgroup's shape: the workgroup's, or a dynamic kernel's
 * dispatch's. */
static nir_def *
threadgroup_shape(struct translator *t)
{
   return t->options->dynamic_shape ? device_value(t, STELA_AIR_THREADGROUP_SHAPE) :
                                      workgroup_size(t);
}

/* The thread's position in its threadgroup; in a dynamic kernel, its
 * linear index's in the shape. */
static nir_def *
local_position(struct translator *t)
{
   nir_builder *b = &t->b;
   if (!t->options->dynamic_shape)
      return nir_load_local_invocation_id(b);
   nir_def *shape = threadgroup_shape(t);
   if (!shape)
      return NULL;
   /* Threads of an empty shape skip the function; avoid dividing by zero. */
   nir_def *width = nir_umax_imm(b, nir_channel(b, shape, 0), 1);
   nir_def *height = nir_umax_imm(b, nir_channel(b, shape, 1), 1);
   nir_def *index = nir_load_local_invocation_index(b);
   nir_def *row = nir_udiv(b, index, width);
   return nir_vec3(b, nir_umod(b, index, width), nir_umod(b, row, height), nir_udiv(b, row, height));
}

/* Metal's grid starts at zero, with no dispatch-base parameter. Form its ID
 * directly from NIR's workgroup/local builtins; a generic global-ID lowering
 * may add a Vulkan base input. */
static nir_def *
grid_position(struct translator *t)
{
   nir_def *shape = threadgroup_shape(t), *local = local_position(t);
   if (!shape || !local)
      return NULL;
   return nir_iadd(&t->b, nir_imul(&t->b, nir_load_workgroup_id(&t->b), shape), local);
}

/* The threads of this threadgroup that a dispatchThreads grid holds. */
static nir_def *
dispatch_size(struct translator *t)
{
   nir_def *grid = device_value(t, STELA_AIR_DISPATCH_GRID);
   nir_def *size = threadgroup_shape(t);
   if (!grid || !size)
      return NULL;
   nir_def *first = nir_imul(&t->b, nir_load_workgroup_id(&t->b), size);
   nir_def *edge = nir_umin(&t->b, size, nir_isub(&t->b, grid, first));
   return nir_bcsel(&t->b, nir_ieq_imm(&t->b, nir_channel(&t->b, grid, 0), 0), size, edge);
}

static nir_def *
volume(nir_builder *b, nir_def *size)
{
   return nir_imul(b, nir_imul(b, nir_channel(b, size, 0), nir_channel(b, size, 1)),
                   nir_channel(b, size, 2));
}

/* A fragment input the rasterizer supplies as a flat uint varying. */
static nir_def *
flat_input(struct translator *t, gl_varying_slot slot, const char *name)
{
   nir_variable *var = nir_variable_create(t->b.shader, nir_var_shader_in, glsl_uint_type(), name);
   if (!var) {
      fail(t, STELA_AIR_ALLOCATION, "builtin variable allocation failed");
      return NULL;
   }
   var->data.location = slot;
   var->data.interpolation = INTERP_MODE_FLAT;
   return nir_load_var(&t->b, var);
}

/* A builtin input's 32-bit value; positions and sizes are uvec3. */
static nir_def *
builtin_value(struct translator *t, enum stela_air_builtin builtin)
{
   nir_builder *b = &t->b;
   const unsigned *size = t->options->workgroup_size;
   nir_def *value;
   switch (builtin) {
   case STELA_AIR_THREAD_POSITION_IN_GRID:
      return grid_position(t);
   case STELA_AIR_THREAD_POSITION_IN_THREADGROUP:
      return local_position(t);
   case STELA_AIR_THREADGROUP_POSITION_IN_GRID:
      return nir_load_workgroup_id(b);
   case STELA_AIR_THREADS_PER_THREADGROUP:
      return threadgroup_shape(t);
   case STELA_AIR_DISPATCH_THREADS_PER_THREADGROUP:
      return dispatch_size(t);
   case STELA_AIR_THREADGROUPS_PER_GRID:
      return nir_load_num_workgroups(b);
   case STELA_AIR_THREADS_PER_GRID: {
      nir_def *grid = device_value(t, STELA_AIR_DISPATCH_GRID);
      nir_def *shape = threadgroup_shape(t);
      if (!grid || !shape)
         return NULL;
      nir_def *uniform = nir_imul(b, nir_load_num_workgroups(b), shape);
      return nir_bcsel(b, nir_ieq_imm(b, nir_channel(b, grid, 0), 0), uniform, grid);
   }
   case STELA_AIR_THREAD_INDEX_IN_THREADGROUP:
      return nir_load_local_invocation_index(b);
   case STELA_AIR_SIMDGROUP_INDEX_IN_THREADGROUP:
      return nir_load_subgroup_id(b);
   case STELA_AIR_SIMDGROUPS_PER_THREADGROUP:
      if (!t->options->dynamic_shape)
         return nir_load_num_subgroups(b);
      value = threadgroup_shape(t);
      if (!value)
         return NULL;
      return nir_udiv(b, nir_iadd(b, volume(b, value), nir_iadd_imm(b, nir_load_subgroup_size(b), -1)),
                      nir_load_subgroup_size(b));
   case STELA_AIR_DISPATCH_SIMDGROUPS_PER_THREADGROUP:
      value = dispatch_size(t);
      if (!value)
         return NULL;
      return nir_udiv(b, nir_iadd(b, volume(b, value), nir_iadd_imm(b, nir_load_subgroup_size(b), -1)),
                      nir_load_subgroup_size(b));
   case STELA_AIR_QUADGROUP_INDEX_IN_THREADGROUP:
      return nir_ushr_imm(b, nir_load_local_invocation_index(b), 2);
   case STELA_AIR_QUADGROUPS_PER_THREADGROUP:
      if (!t->options->dynamic_shape)
         return nir_imm_int(b, (int)DIV_ROUND_UP(size[0] * size[1] * size[2], 4));
      value = threadgroup_shape(t);
      if (!value)
         return NULL;
      return nir_ushr_imm(b, nir_iadd_imm(b, volume(b, value), 3), 2);
   case STELA_AIR_DISPATCH_QUADGROUPS_PER_THREADGROUP:
      value = dispatch_size(t);
      if (!value)
         return NULL;
      return nir_ushr_imm(b, nir_iadd_imm(b, volume(b, value), 3), 2);
   case STELA_AIR_THREAD_INDEX_IN_SIMDGROUP:
      return nir_load_subgroup_invocation(b);
   case STELA_AIR_THREADS_PER_SIMDGROUP:
   case STELA_AIR_THREAD_EXECUTION_WIDTH:
      return nir_load_subgroup_size(b);
   case STELA_AIR_THREAD_INDEX_IN_QUADGROUP:
      return nir_iand_imm(b, nir_load_subgroup_invocation(b), 3);
   case STELA_AIR_VERTEX_ID:
      /* Metal's vertex_id includes the base vertex, as NIR's vertex_id
       * does, unlike vertex_id_zero_base. */
      return nir_load_vertex_id(b);
   case STELA_AIR_INSTANCE_ID:
      /* Metal's instance_id includes the base instance; NIR's does not. A
       * post-tessellation function's comes with its patch. */
      if (t->patch_ids)
         return nir_channel(b, t->patch_ids, 1);
      return nir_iadd(b, nir_load_instance_id(b), nir_load_base_instance(b));
   case STELA_AIR_BASE_VERTEX:
      return nir_load_base_vertex(b);
   case STELA_AIR_BASE_INSTANCE:
      return t->patch_ids ? nir_channel(b, t->patch_ids, 2) : nir_load_base_instance(b);
   case STELA_AIR_PATCH_ID:
      return nir_channel(b, t->patch_ids, 0);
   case STELA_AIR_AMPLIFICATION_ID:
      return device_value(t, STELA_AIR_AMPLIFICATION);
   case STELA_AIR_FRONT_FACING:
      return nir_load_front_face(b, 1);
   case STELA_AIR_SAMPLE_ID:
      return nir_load_sample_id(b);
   case STELA_AIR_SAMPLE_MASK_IN:
      return nir_load_sample_mask_in(b);
   case STELA_AIR_PRIMITIVE_ID:
      return flat_input(t, VARYING_SLOT_PRIMITIVE_ID, "air.primitive_id");
   case STELA_AIR_RENDER_TARGET_ARRAY_INDEX_IN:
      return flat_input(t, VARYING_SLOT_LAYER, "air.render_target_array_index");
   case STELA_AIR_VIEWPORT_ARRAY_INDEX_IN:
      return flat_input(t, VARYING_SLOT_VIEWPORT, "air.viewport_array_index");
   case STELA_AIR_POINT_COORD:
      /* Both Metal's and Vulkan's have an upper-left origin. */
      return nir_load_point_coord(b);
   case STELA_AIR_BUILTIN_NONE:
   case STELA_AIR_BUILTIN_COUNT:
      break;
   }
   UNREACHABLE("builtins are validated with their stage");
}

/* A builtin input in its argument's type: the leading lanes, narrowed to
 * 16-bit lanes for ushort forms. */
static nir_def *
builtin_argument(struct translator *t, enum stela_air_builtin builtin, LLVMValueRef param)
{
   nir_def *value = builtin_value(t, builtin);
   if (!value)
      return NULL;
   LLVMTypeRef type = LLVMTypeOf(param);
   unsigned components = 1;
   if (LLVMGetTypeKind(type) == LLVMVectorTypeKind) {
      components = LLVMGetVectorSize(type);
      type = LLVMGetElementType(type);
   }
   value = nir_trim_vector(&t->b, value, components);
   return LLVMGetTypeKind(type) == LLVMIntegerTypeKind && LLVMGetIntTypeWidth(type) == 16 ?
      nir_u2u16(&t->b, value) : value;
}

/* A stage-in attribute at location in its type, as fetch_attribute reads
 * it at `at`. */
static nir_def *
stage_in_attribute(struct translator *t, unsigned location, nir_def *at, nir_def *point,
                   enum stela_air_primitive p, unsigned components)
{
   bool integer = p != STELA_AIR_FLOAT && p != STELA_AIR_HALF;
   const struct stela_air_options *options = t->options;
   nir_def *lanes = options->fetch_attribute ?
      options->fetch_attribute(&t->b, location, at, point, integer, options->binding_data) : NULL;
   if (!lanes || lanes->num_components != 4 || lanes->bit_size != 32) {
      fail(t, STELA_AIR_ARGUMENT, "stage-in attribute %u is not provided", location);
      return NULL;
   }
   return stage_narrow(&t->b, nir_trim_vector(&t->b, lanes, components), p);
}

/* A buffer argument's value as the root of its pointers. Argument buffers
 * hold device addresses, which SSBO bindings have no counterpart of. */
static bool
argument_root(struct translator *t, struct value *value, LLVMValueRef param,
              const struct stela_air_argument *argument)
{
   value->pointer_root = param;
   if (!argument->is_argument_buffer)
      return true;
   if (t->options->bind_ssbo)
      return fail(t, STELA_AIR_ARGUMENT, "argument buffer %u requires device addresses",
                  argument->buffer.argument);
   value->fields = argument->fields;
   value->offset_known = true;
   return true;
}

/* The object payload: task payload memory, which both stages address from
 * zero. */
static bool
payload_argument(struct translator *t, LLVMValueRef param, const struct stela_air_buffer *desc)
{
   if (desc->type_size > t->stage_options->max_payload_bytes)
      return fail(t, STELA_AIR_LIMIT, "object payload exceeds the target limit");
   nir_variable *var = nir_variable_create(t->b.shader, nir_var_mem_task_payload,
      glsl_array_type(glsl_uint8_t_type(), desc->type_size, 1), "air.payload");
   if (!var || !put_value(t, param, nir_imm_int64(&t->b, 0), desc->access))
      return fail(t, STELA_AIR_ALLOCATION, "object payload allocation failed");
   var->data.alignment = desc->type_alignment;
   struct value *value = find_value(t, param);
   value->pointer_root = param;
   value->storage = var;
   value->storage_size = desc->type_size;
   t->payload = var;
   return true;
}

/* The arguments of a kernel, object or mesh function. */
static bool
compute_arguments(struct translator *t, const struct stela_air_kernel *kernel)
{
   t->fields = kernel->fields;
   bool ssbo_slots[UINT8_MAX + 1] = {false};
   for (unsigned a = 0; a < kernel->count; a++) {
      const struct stela_air_argument *argument = &kernel->arguments[a];
      LLVMValueRef param = argument->value;
      if (argument->is_mesh || argument->is_mesh_grid) {
         /* Only the mesh setters take these. */
         *(argument->is_mesh ? &t->mesh : &t->mesh_grid) = param;
         continue;
      }
      if (argument->is_payload) {
         if (!payload_argument(t, param, &argument->buffer))
            return false;
         continue;
      }
      if (argument->is_texture || argument->is_sampler) {
         if (!put_resource(t, param, argument->is_texture ? &argument->texture : NULL,
                           &argument->sampler))
            return false;
         continue;
      }
      if (argument->is_stage_in) {
         /* Attributes the kernel never reads need no layout. */
         if (!LLVMGetFirstUse(param))
            continue;
         nir_def *def = stage_in_attribute(t, argument->location, grid_position(t), NULL,
                                           argument->primitive, argument->type_components);
         if (!def || !put_value(t, param, def, 0))
            return false;
         continue;
      }
      struct stela_air_buffer desc = argument->buffer;
      unsigned index = desc.argument;
      bool buffer = argument->is_buffer;
      nir_def *def;
      unsigned ssbo_slot = 0;
      nir_variable *shared = NULL;
      unsigned shared_size = 0;
      if (buffer) {
         bool threadgroup = desc.address_space == 3;
         if (threadgroup && t->options->dynamic_threadgroup_bytes) {
            shared = dynamic_threadgroup(t, &desc);
            def = shared ? t->options->threadgroup_offset(&t->b, &desc, t->options->binding_data) :
                           NULL;
            if (!binding_prelude(t))
               return false;
            if (!def || def->num_components != 1 || def->bit_size != 32)
               return fail(t, STELA_AIR_ARGUMENT, "threadgroup offset callback refused buffer %u", index);
            def = nir_u2u64(&t->b, def);
            shared_size = t->options->dynamic_threadgroup_bytes;
         } else if (threadgroup) {
            struct stela_air_threadgroup_view view = {0};
            if (!t->options->bind_threadgroup ||
                !t->options->bind_threadgroup(&desc, &view, t->options->binding_data) ||
                view.size < desc.type_size || view.alignment < desc.type_alignment ||
                view.available_access < STELA_AIR_READ || view.available_access > STELA_AIR_READ_WRITE ||
                (desc.access & ~view.available_access))
               return fail(t, STELA_AIR_ARGUMENT, "invalid/unbound threadgroup buffer %u", index);
            shared = shared_resource(t, view.size, view.alignment);
            if (!shared)
               return false;
            shared_size = (unsigned)view.size;
            def = nir_imm_int64(&t->b, 0);
         } else if (t->options->bind_ssbo) {
            if (!t->options->bind_ssbo(&desc, &ssbo_slot, t->options->binding_data) ||
                ssbo_slot >= t->options->ssbo_count || ssbo_slots[ssbo_slot])
               return fail(t, STELA_AIR_ARGUMENT, "SSBO callback refused/invalid slot for buffer %u", index);
            ssbo_slots[ssbo_slot] = true;
            /* The exact Metal view is the surface, not an inferred raw VA. */
            def = nir_imm_int64(&t->b, 0);
         } else {
            if (!t->options->bind_buffer)
               return fail(t, STELA_AIR_ARGUMENT, "unbound device buffer %u", index);
            def = t->options->bind_buffer(&t->b, &desc, t->options->binding_data);
            if (!binding_prelude(t))
               return false;
            if (!def || def->num_components != 1 || def->bit_size != 64)
               return fail(t, STELA_AIR_ARGUMENT, "binding callback refused/invalid buffer %u", index);
         }
      } else {
         def = builtin_argument(t, argument->builtin, param);
         if (!def)
            return false;
      }
      if (!put_value(t, param, def, desc.access))
         return false;
      if (buffer && !argument_root(t, find_value(t, param), param, argument))
         return false;
      if (shared) {
         struct value *value = find_value(t, param);
         value->storage = shared;
         value->storage_size = shared_size;
      } else if (buffer && t->options->bind_ssbo) {
         struct value *value = find_value(t, param);
         value->ssbo = true;
         value->ssbo_slot = ssbo_slot;
      }
   }
   return true;
}

/* Whether the workgroup is within a function's air.max_work_group_size. */
static bool
workgroup_within(struct translator *t, unsigned max_threads)
{
   const unsigned *size = t->options->workgroup_size;
   return !max_threads || (uint64_t)size[0] * size[1] * size[2] <= max_threads ||
      fail(t, STELA_AIR_LIMIT, "workgroup exceeds the function's maximum threads");
}

static bool
kernel_arguments(struct translator *t, LLVMValueRef fn)
{
   /* The fields outlive this function in the translation's values. */
   struct stela_air_kernel *kernel = ralloc(t->values, struct stela_air_kernel);
   if (!kernel)
      return fail(t, STELA_AIR_ALLOCATION, "AIR kernel reflection allocation failed");
   return stela_air_metadata_kernel(&t->metadata, fn, kernel) &&
          workgroup_within(t, kernel->max_threads) && compute_arguments(t, kernel);
}

static bool
fixed_storage_type(struct translator *t, LLVMTypeRef type, unsigned depth,
                   unsigned *budget)
{
   if (depth >= 64 || !*budget)
      return fail(t, STELA_AIR_LIMIT, "GEP type-layout budget exceeded");
   (*budget)--;
   switch (LLVMGetTypeKind(type)) {
   case LLVMArrayTypeKind:
   case LLVMVectorTypeKind:
      return fixed_storage_type(t, LLVMGetElementType(type), depth + 1, budget);
   case LLVMStructTypeKind:
      if (LLVMIsOpaqueStruct(type))
         return fail(t, STELA_AIR_TYPE, "opaque GEP storage type");
      for (unsigned i = 0; i < LLVMCountStructElementTypes(type); i++) {
         if (!fixed_storage_type(t, LLVMStructGetTypeAtIndex(type, i), depth + 1, budget))
            return false;
      }
      return true;
   case LLVMIntegerTypeKind:
   case LLVMPointerTypeKind:
   case LLVMHalfTypeKind:
   case LLVMFloatTypeKind:
   case LLVMDoubleTypeKind:
   case LLVMX86_FP80TypeKind:
   case LLVMFP128TypeKind:
   case LLVMPPC_FP128TypeKind:
   case LLVMBFloatTypeKind:
      return LLVMTypeIsSized(type) || fail(t, STELA_AIR_TYPE, "unsized GEP storage type");
   default:
      /* In particular, LLVM's fixed-size C DataLayout queries must not be
       * called on scalable vectors or aggregates containing them. */
      return fail(t, STELA_AIR_TYPE, "unsupported/scalable GEP storage type");
   }
}

static bool
shared_profile(struct translator *t)
{
   return stela_air_metadata_shared_profile(&t->metadata);
}

static nir_variable *
shared_resource(struct translator *t, uint64_t size, unsigned alignment)
{
   if (!size || size > t->options->max_threadgroup_bytes ||
       !alignment || (alignment & (alignment - 1)) ||
       t->shared_resources == AIR_MAX_ARGUMENTS ||
       t->shared_layout_bound + size + alignment - 1 > UINT32_MAX) {
      fail(t, STELA_AIR_LIMIT, "shared-memory size/alignment/layout budget exceeded");
      return NULL;
   }
   if (!shared_profile(t))
      return NULL;
   /* Original NIR owns byte-storage placement, alignment and final lowering.
    * The conservative bound above only prevents its unsigned layout overflow. */
   nir_variable *var = nir_variable_create(t->b.shader, nir_var_mem_shared,
      glsl_array_type(glsl_uint8_t_type(), (unsigned)size, 1), "air.shared");
   if (!var) {
      fail(t, STELA_AIR_ALLOCATION, "shared-memory variable allocation failed");
      return NULL;
   }
   var->data.alignment = alignment;
   t->shared_resources++;
   t->shared_layout_bound += size + alignment - 1;
   return var;
}

/* A dynamic kernel's threadgroup memory, in which its dispatches place
 * threadgroup buffers at offsets aligned to 16 bytes. */
static nir_variable *
dynamic_threadgroup(struct translator *t, const struct stela_air_buffer *buffer)
{
   if (buffer->type_alignment > 16) {
      fail(t, STELA_AIR_ARGUMENT, "threadgroup buffer %u is aligned past its placement",
           buffer->argument);
      return NULL;
   }
   if (!t->dynamic_threadgroup)
      t->dynamic_threadgroup = shared_resource(t, t->options->dynamic_threadgroup_bytes, 16);
   return t->dynamic_threadgroup;
}

/* A storage root at offset zero, defined at entry: it dominates every use, even
 * when first referenced in conditional or loop code. Memory effects keep their
 * source cursor. */
static struct value *
storage_root(struct translator *t, LLVMValueRef llvm, unsigned access)
{
   nir_builder entry = nir_builder_at(nir_before_impl(t->b.impl));
   if (!put_value(t, llvm, nir_imm_int64(&entry, 0), access))
      return NULL;
   struct value *value = find_value(t, llvm);
   value->pointer_root = llvm;
   return value;
}

/* The bytes of a constant initializer of `type`, which the data starts
 * zeroed: undefined bytes may hold any value. */
static bool
constant_bytes(struct translator *t, LLVMValueRef value, LLVMTypeRef type, uint8_t *bytes,
               unsigned depth)
{
   if (depth == 32)
      return fail(t, STELA_AIR_LIMIT, "constant data nesting exceeded");
   if (LLVMIsAConstantAggregateZero(value) || LLVMIsUndef(value) ||
       !LLVMABISizeOfType(t->layout, type))
      return true;
   LLVMTypeKind kind = LLVMGetTypeKind(type);
   if (kind == LLVMIntegerTypeKind || kind == LLVMHalfTypeKind || kind == LLVMFloatTypeKind) {
      unsigned bits = kind == LLVMIntegerTypeKind ? LLVMGetIntTypeWidth(type) :
                      kind == LLVMHalfTypeKind ? 16 : 32;
      /* LLVM serializes its APFloat bits, as for immediate operands. */
      LLVMValueRef encoded = kind == LLVMIntegerTypeKind ? value :
         LLVMConstBitCast(value, LLVMIntTypeInContext(t->context, bits));
      if (!LLVMIsAConstantInt(encoded))
         return fail(t, STELA_AIR_TYPE, "unsupported constant data initializer");
      uint64_t encoding = LLVMConstIntGetZExtValue(encoded);
      for (unsigned i = 0; i < bits / 8; i++)
         bytes[i] = encoding >> (8 * i);
      return true;
   }
   uint64_t count = kind == LLVMStructTypeKind ? LLVMCountStructElementTypes(type) :
                    kind == LLVMArrayTypeKind ? LLVMGetArrayLength2(type) : LLVMGetVectorSize(type);
   for (uint64_t i = 0; i < count; i++) {
      LLVMValueRef element = LLVMGetAggregateElement(value, (unsigned)i);
      if (!element)
         return fail(t, STELA_AIR_TYPE, "unsupported constant data initializer");
      LLVMTypeRef element_type = kind == LLVMStructTypeKind ?
         LLVMStructGetTypeAtIndex(type, (unsigned)i) : LLVMGetElementType(type);
      /* Vectors bit-pack their lanes; arrays step by allocation size. */
      uint64_t offset = kind == LLVMStructTypeKind ? LLVMOffsetOfElement(t->layout, type, (unsigned)i) :
         i * (kind == LLVMVectorTypeKind ? LLVMStoreSizeOfType(t->layout, element_type) :
                                           LLVMABISizeOfType(t->layout, element_type));
      if (!constant_bytes(t, element, element_type, bytes + offset, depth + 1))
         return false;
   }
   return true;
}

/* Lays a constant global out in the shader's constant data at `base`. */
static bool
constant_data(struct translator *t, LLVMValueRef global, const struct stela_air_global *info,
              unsigned *base)
{
   nir_shader *shader = t->b.shader;
   uint64_t start = ALIGN_POT((uint64_t)shader->constant_data_size, info->alignment);
   if (start + info->size > t->options->max_constant_bytes)
      return fail(t, STELA_AIR_LIMIT, "constant data exceeds the target limit");
   if (LLVMByteOrder(t->layout) != LLVMLittleEndian)
      return fail(t, STELA_AIR_TARGET, "constant data requires a little-endian layout");
   uint8_t *data = rerzalloc_size(shader, shader->constant_data, shader->constant_data_size,
                                  start + info->size);
   if (!data)
      return fail(t, STELA_AIR_ALLOCATION, "constant data allocation failed");
   shader->constant_data = data;
   shader->constant_data_size = start + info->size;
   *base = start;
   return constant_bytes(t, LLVMGetInitializer(global), LLVMGlobalGetValueType(global),
                         data + start, 0);
}

static nir_def *
module_global(struct translator *t, LLVMValueRef global)
{
   struct stela_air_global info;
   if (!stela_air_metadata_global(&t->metadata, global, &info))
      return NULL;
   nir_variable *var = NULL;
   unsigned base = 0;
   if (info.constant ? !constant_data(t, global, &info, &base) :
                       !(var = shared_resource(t, info.size, info.alignment)))
      return NULL;
   struct value *value = storage_root(t, global, info.constant ? STELA_AIR_READ : STELA_AIR_READ_WRITE);
   if (!value)
      return NULL;
   value->storage = var;
   value->constant_data = info.constant;
   value->storage_size = (unsigned)info.size;
   value->constant_base = base;
   return value->def;
}

/* An entry-block alloca of a fixed size: thread memory. */
static struct value *
private_allocation(struct translator *t, LLVMValueRef alloca)
{
   struct value *value = find_value(t, alloca);
   if (value)
      return value;
   LLVMTypeRef type = LLVMGetAllocatedType(alloca);
   LLVMValueRef count = LLVMGetOperand(alloca, 0);
   if (LLVMGetInstructionParent(alloca) != LLVMGetEntryBasicBlock(t->entry) ||
       !LLVMIsAConstantInt(count) || LLVMGetPointerAddressSpace(LLVMTypeOf(alloca)) != 0) {
      fail(t, STELA_AIR_MEMORY, "thread memory requires a fixed entry-block allocation");
      return NULL;
   }
   if (LLVMPointerSizeForAS(t->layout, 0) != 8) {
      fail(t, STELA_AIR_TARGET, "thread memory pointers require 64-bit layout");
      return NULL;
   }
   unsigned budget = 4096;
   if (!fixed_storage_type(t, type, 0, &budget))
      return NULL;
   uint64_t element = LLVMABISizeOfType(t->layout, type), length = LLVMConstIntGetZExtValue(count);
   uint64_t limit = t->options->max_private_bytes;
   unsigned alignment = LLVMGetAlignment(alloca);
   if (!element || !length || length > limit / element ||
       !alignment || (alignment & (alignment - 1)) ||
       t->private_layout_bound + element * length + alignment - 1 > limit) {
      fail(t, STELA_AIR_LIMIT, "thread memory size/alignment exceeds the target limit");
      return NULL;
   }
   uint64_t size = element * length;
   nir_variable *var = nir_local_variable_create(t->b.impl,
      glsl_array_type(glsl_uint8_t_type(), (unsigned)size, 1), "air.private");
   if (!var) {
      fail(t, STELA_AIR_ALLOCATION, "thread memory variable allocation failed");
      return NULL;
   }
   var->data.alignment = alignment;
   t->private_allocations++;
   t->private_layout_bound += size + alignment - 1;
   value = storage_root(t, alloca, STELA_AIR_READ_WRITE);
   if (value) {
      value->storage = var;
      value->storage_size = (unsigned)size;
   }
   return value;
}

static bool
thread_memory(const struct value *value)
{
   return value->storage && value->storage->data.mode == nir_var_function_temp;
}

/* A GEP's address, with the constant part of its offset and the greatest
 * common divisor of its dynamic indices' steps. */
static nir_def *
gep(struct translator *t, LLVMValueRef inst, const struct value **origin, uint64_t *constant,
    uint64_t *steps)
{
   struct value *base = pointer_value(t, LLVMGetOperand(inst, 0));
   LLVMTypeRef result_type = LLVMTypeOf(inst);
   if (!base || !base->access || LLVMGetTypeKind(result_type) != LLVMPointerTypeKind) {
      fail(t, STELA_AIR_MEMORY, "GEP requires a validated buffer/shared pointer");
      return NULL;
   }
   LLVMTypeRef type = LLVMGetGEPSourceElementType(inst);
   unsigned type_budget = 4096;
   if (!fixed_storage_type(t, type, 0, &type_budget))
      return NULL;
   nir_def *address = base->def;
   *constant = *steps = 0;
   unsigned operands = LLVMGetNumOperands(inst);
   for (unsigned i = 1; i < operands; i++) {
      LLVMValueRef index = LLVMGetOperand(inst, i);
      LLVMTypeRef index_type = LLVMTypeOf(index);
      if (LLVMGetTypeKind(index_type) != LLVMIntegerTypeKind ||
          LLVMGetIntTypeWidth(index_type) > 64) {
         fail(t, STELA_AIR_TYPE, "unsupported GEP index type");
         return NULL;
      }
      if (i > 1 && LLVMGetTypeKind(type) == LLVMStructTypeKind) {
         if (!LLVMIsAConstantInt(index) || LLVMIsOpaqueStruct(type)) {
            fail(t, STELA_AIR_TYPE, "GEP requires a constant sized-struct index");
            return NULL;
         }
         uint64_t field = LLVMConstIntGetZExtValue(index);
         if (field >= LLVMCountStructElementTypes(type)) {
            fail(t, STELA_AIR_TYPE, "GEP struct index out of range");
            return NULL;
         }
         uint64_t offset = LLVMOffsetOfElement(t->layout, type, field);
         address = nir_iadd_imm(&t->b, address, offset);
         *constant += offset;
         type = LLVMStructGetTypeAtIndex(type, field);
      } else {
         bool vector_element = false;
         if (i > 1) {
            LLVMTypeKind kind = LLVMGetTypeKind(type);
            if (kind != LLVMArrayTypeKind && kind != LLVMVectorTypeKind) {
               fail(t, STELA_AIR_TYPE, "unsupported GEP aggregate");
               return NULL;
            }
            vector_element = kind == LLVMVectorTypeKind;
            type = LLVMGetElementType(type);
         }
         if (!LLVMTypeIsSized(type)) {
            fail(t, STELA_AIR_TYPE, "unsized GEP element");
            return NULL;
         }
         nir_def *offset = get_value(t, index);
         if (!offset)
            return NULL;
         offset = offset->bit_size == 1 ?
            nir_ineg(&t->b, nir_b2i64(&t->b, offset)) : nir_i2i64(&t->b, offset);
         uint64_t stride;
         if (vector_element) {
            /* LLVM's getSequentialElementStride bit-packs vectors, even when
             * the scalar element has a larger ABI allocation alignment.
             * Arrays and the root pointer step retain allocation-size stride. */
            stride = LLVMStoreSizeOfType(t->layout, type);
            if (LLVMSizeOfTypeInBits(t->layout, type) != stride * 8) {
               fail(t, STELA_AIR_TYPE, "non-byte-addressable GEP vector element");
               return NULL;
            }
         } else {
            stride = LLVMABISizeOfType(t->layout, type);
         }
         if (LLVMIsAConstantInt(index))
            *constant += (uint64_t)LLVMConstIntGetSExtValue(index) * stride;
         else
            *steps = gcd(*steps, stride);
         offset = nir_imul_imm(&t->b, offset, stride);
         address = nir_iadd(&t->b, address, offset);
      }
   }
   *origin = base;
   return address;
}

/* All frontend branches, including memory guards introduced within an LLVM
 * block, use the same flat CFG. Mesa alone performs structurization. */
static nir_block *
new_block(struct translator *t)
{
   nir_block *block = nir_block_create(t->b.impl);
   if (!block) {
      fail(t, STELA_AIR_ALLOCATION, "AIR NIR block allocation failed");
      return NULL;
   }
   exec_list_push_tail(&t->b.impl->body, &block->cf_node.node);
   block->cf_node.parent = &t->b.impl->cf_node;
   return block;
}

struct memory_guard {
   nir_block *then_block, *else_block, *merge;
};

static bool
memory_guard_begin(struct translator *t, nir_def *condition, struct memory_guard *guard)
{
   *guard = (struct memory_guard){new_block(t), new_block(t), new_block(t)};
   if (!guard->then_block || !guard->else_block || !guard->merge)
      return false;
   nir_goto_if(&t->b, guard->then_block, condition, guard->else_block);
   t->b.cursor = nir_after_block(guard->then_block);
   return true;
}

static nir_def *
memory_guard_end(struct translator *t, const struct memory_guard *guard, nir_def *loaded)
{
   nir_block *then_end = nir_cursor_current_block(t->b.cursor);
   nir_goto(&t->b, guard->merge);
   t->b.cursor = nir_after_block(guard->else_block);
   nir_def *zero = loaded ? nir_imm_zero(&t->b, loaded->num_components, loaded->bit_size) : NULL;
   nir_goto(&t->b, guard->merge);
   t->b.cursor = nir_after_block(guard->merge);
   if (!loaded)
      return NULL;
   nir_phi_instr *phi = nir_phi_instr_create(t->b.shader);
   if (!phi) {
      fail(t, STELA_AIR_ALLOCATION, "AIR memory-guard PHI allocation failed");
      return NULL;
   }
   nir_def_init(&phi->instr, &phi->def, loaded->num_components, loaded->bit_size);
   nir_phi_instr_add_src(phi, then_end, loaded);
   nir_phi_instr_add_src(phi, guard->else_block, zero);
   nir_builder_instr_insert(&t->b, &phi->instr);
   return &phi->def;
}

/* A relaxed atomic read-modify-write of `data`, compared with `compare` for a
 * compare-exchange. */
struct atomic {
   nir_atomic_op op;
   nir_def *data, *compare;
};

static nir_def *
ssbo_access(struct translator *t, const struct value *address, nir_def *stored,
            const struct atomic *atomic, enum gl_access_qualifier access,
            unsigned components, unsigned bits, unsigned alignment)
{
   nir_builder *b = &t->b;
   nir_def *slot = nir_imm_int(b, address->ssbo_slot);
   nir_def *size = nir_u2u64(b, nir_get_ssbo_size(b, 32, slot));
   unsigned bytes = components * (bits / 8);
   /* Compare at LLVM pointer width before narrowing to the native SSBO offset.
    * Subtract the small access size only with a separate size>=bytes guard;
    * offset+bytes could overflow, and offset truncation would alias low bytes.
    * The surface byte length ABI is validated at command binding, not guessed
    * from the argument's scalar type size or a synthetic backing allocation. */
   nir_def *valid = nir_iand(b, nir_uge_imm(b, size, bytes),
      nir_uge(b, nir_iadd_imm(b, size, -(int64_t)bytes), address->def));
   nir_def *loaded = NULL;
   struct memory_guard guard;
   if (!memory_guard_begin(t, valid, &guard))
      return NULL;
   nir_def *offset = nir_u2u32(b, address->def);
   if (atomic && atomic->compare)
      loaded = nir_ssbo_atomic_swap(b, bits, slot, offset, atomic->compare, atomic->data,
                                    .atomic_op = atomic->op);
   else if (atomic)
      loaded = nir_ssbo_atomic(b, bits, slot, offset, atomic->data, .atomic_op = atomic->op);
   else if (stored)
      nir_store_ssbo(b, stored, slot, offset, .align_mul = alignment, .access = access);
   else
      loaded = nir_load_ssbo(b, components, bits, slot, offset, .align_mul = alignment, .access = access);
   return memory_guard_end(t, &guard, loaded);
}

/* Begins a guard for an access of `bytes` within a storage_size view. LLVM64
 * offsets are compared before narrowing, so an out-of-view access never
 * truncates into another allocation or a valid low offset. */
static bool
storage_guard_begin(struct translator *t, const struct value *address, unsigned bytes,
                    struct memory_guard *guard)
{
   nir_builder *b = &t->b;
   nir_def *valid = address->storage_size >= bytes ?
      nir_uge(b, nir_imm_int64(b, address->storage_size - bytes), address->def) : nir_imm_false(b);
   return memory_guard_begin(t, valid, guard);
}

/* An access to threadgroup or thread memory, through its byte variable. */
static nir_def *
variable_access(struct translator *t, const struct value *address, nir_def *stored,
                const struct atomic *atomic, enum gl_access_qualifier access,
                unsigned components, unsigned bits, unsigned alignment)
{
   nir_builder *b = &t->b;
   unsigned bytes = components * (bits / 8);
   struct memory_guard guard;
   if (!storage_guard_begin(t, address, bytes, &guard))
      return NULL;
   nir_deref_instr *byte = nir_build_deref_array(b, nir_build_deref_var(b, address->storage),
                                                nir_u2u32(b, address->def));
   const struct glsl_type *type = glsl_vector_type(glsl_get_base_type(glsl_uintN_t_type(bits)), components);
   nir_deref_instr *typed = nir_build_deref_cast_with_alignment(b, &byte->def,
      address->storage->data.mode, type, bytes, alignment, 0);
   nir_def *loaded = NULL;
   if (atomic && atomic->compare)
      loaded = nir_deref_atomic_swap(b, bits, &typed->def, atomic->compare, atomic->data,
                                     .atomic_op = atomic->op);
   else if (atomic)
      loaded = nir_deref_atomic(b, bits, &typed->def, atomic->data, .atomic_op = atomic->op);
   else if (stored)
      nir_store_deref_with_access(b, typed, stored, BITFIELD_MASK(components), access);
   else
      loaded = nir_load_deref_with_access(b, typed, access);
   return memory_guard_end(t, &guard, loaded);
}

/* A load of constant data. */
static nir_def *
constant_access(struct translator *t, const struct value *address, unsigned components,
                unsigned bits, unsigned alignment)
{
   struct memory_guard guard;
   if (!storage_guard_begin(t, address, components * (bits / 8), &guard))
      return NULL;
   nir_def *loaded = nir_load_constant(&t->b, components, bits, nir_u2u32(&t->b, address->def),
                                       .base = address->constant_base,
                                       .range = address->storage_size, .align_mul = alignment);
   return memory_guard_end(t, &guard, loaded);
}

static nir_def *
global_access(struct translator *t, const struct value *address, nir_def *stored,
              const struct atomic *atomic, enum gl_access_qualifier access,
              unsigned components, unsigned bits, unsigned alignment)
{
   nir_builder *b = &t->b;
   if (atomic && atomic->compare)
      return nir_global_atomic_swap(b, bits, address->def, atomic->compare, atomic->data,
                                    .atomic_op = atomic->op);
   if (atomic)
      return nir_global_atomic(b, bits, address->def, atomic->data, .atomic_op = atomic->op);
   if (stored) {
      nir_store_global(b, stored, address->def, .align_mul = alignment, .access = access);
      return NULL;
   }
   return nir_load_global(b, components, bits, address->def, .align_mul = alignment, .access = access);
}

/* One access at `address`: a load, a store of `stored` or an atomic, which
 * return the loaded or old value. */
static nir_def *
memory_access(struct translator *t, const struct value *address, nir_def *stored,
              const struct atomic *atomic, enum gl_access_qualifier access,
              unsigned components, unsigned bits, unsigned alignment)
{
   if (address->array) {
      fail(t, STELA_AIR_MEMORY, "texture and sampler arrays are only read by element");
      return NULL;
   }
   if (address->storage)
      return variable_access(t, address, stored, atomic, access, components, bits, alignment);
   if (address->constant_data)
      return constant_access(t, address, components, bits, alignment);
   if (address->ssbo)
      return ssbo_access(t, address, stored, atomic, access, components, bits, alignment);
   return global_access(t, address, stored, atomic, access, components, bits, alignment);
}

/* The value an atomic `op` of `data` at `pointer` replaces, negated first
 * when `negate`; `expected` makes it a compare-exchange. Atomics act on 32-
 * and 64-bit integers, and exchange and add also on floats. NIR's atomics are
 * device-scope, which refines every Metal scope. */
static nir_def *
atomic_old(struct translator *t, LLVMValueRef pointer, nir_atomic_op op, bool negate,
           LLVMTypeRef type, nir_def *data, nir_def *expected, unsigned alignment)
{
   unsigned components, bits;
   bool floating = LLVMGetTypeKind(type) == LLVMFloatTypeKind;
   if (!value_shape(type, &components, &bits) || components != 1 ||
       (floating ? expected || (op != nir_atomic_op_xchg && op != nir_atomic_op_fadd) :
                   (bits != 32 && bits != 64) || op == nir_atomic_op_fadd)) {
      fail(t, STELA_AIR_TYPE, "unsupported atomic operand type");
      return NULL;
   }
   if (alignment < bits / 8) {
      fail(t, STELA_AIR_MEMORY, "atomic access is not naturally aligned");
      return NULL;
   }
   const struct value *address = pointer_value(t, pointer);
   if (!address || (address->access & STELA_AIR_READ_WRITE) != STELA_AIR_READ_WRITE ||
       thread_memory(address)) {
      fail(t, STELA_AIR_MEMORY, "atomic access lacks a device or threadgroup read-write pointer");
      return NULL;
   }
   if (negate)
      data = floating ? nir_ixor(&t->b, data, nir_imm_int(&t->b, INT32_MIN)) : nir_ineg(&t->b, data);
   const struct atomic atomic = {op, data, expected};
   return memory_access(t, address, NULL, &atomic, 0, 1, bits, alignment);
}

/* An atomic `op` of `operand` at `pointer`, as atomic_old; `compare` makes
 * it a compare-exchange whose result is {old value, exchanged}. */
static bool
atomic_access(struct translator *t, LLVMValueRef inst, LLVMValueRef pointer, nir_atomic_op op,
              bool negate, LLVMValueRef operand, LLVMValueRef compare, unsigned alignment)
{
   nir_def *data = get_value(t, operand);
   nir_def *expected = compare ? get_value(t, compare) : NULL;
   if (!data || (compare && !expected))
      return false;
   nir_def *old = atomic_old(t, pointer, op, negate, LLVMTypeOf(operand), data, expected, alignment);
   if (!old)
      return false;
   return compare ? put_pair(t, inst, old, nir_ieq(&t->b, old, expected)) : put_value(t, inst, old, 0);
}

/* LLVM's atomicrmw and cmpxchg. Metal's atomics are relaxed, so stronger
 * orderings are refused rather than approximated. */
static bool
atomic_instruction(struct translator *t, LLVMValueRef inst, LLVMOpcode op)
{
   bool exchange = op == LLVMAtomicCmpXchg;
   bool relaxed = exchange ?
      LLVMGetCmpXchgSuccessOrdering(inst) == LLVMAtomicOrderingMonotonic &&
      LLVMGetCmpXchgFailureOrdering(inst) == LLVMAtomicOrderingMonotonic :
      LLVMGetOrdering(inst) == LLVMAtomicOrderingMonotonic;
   if (!relaxed)
      return fail(t, STELA_AIR_MEMORY, "only relaxed (monotonic) atomics are supported");
   nir_atomic_op atomic = nir_atomic_op_cmpxchg;
   bool negate = false;
   if (!exchange) {
      switch (LLVMGetAtomicRMWBinOp(inst)) {
      case LLVMAtomicRMWBinOpXchg: atomic = nir_atomic_op_xchg; break;
      case LLVMAtomicRMWBinOpSub: negate = true; FALLTHROUGH;
      case LLVMAtomicRMWBinOpAdd: atomic = nir_atomic_op_iadd; break;
      case LLVMAtomicRMWBinOpAnd: atomic = nir_atomic_op_iand; break;
      case LLVMAtomicRMWBinOpOr: atomic = nir_atomic_op_ior; break;
      case LLVMAtomicRMWBinOpXor: atomic = nir_atomic_op_ixor; break;
      case LLVMAtomicRMWBinOpMax: atomic = nir_atomic_op_imax; break;
      case LLVMAtomicRMWBinOpMin: atomic = nir_atomic_op_imin; break;
      case LLVMAtomicRMWBinOpUMax: atomic = nir_atomic_op_umax; break;
      case LLVMAtomicRMWBinOpUMin: atomic = nir_atomic_op_umin; break;
      case LLVMAtomicRMWBinOpFSub: negate = true; FALLTHROUGH;
      case LLVMAtomicRMWBinOpFAdd: atomic = nir_atomic_op_fadd; break;
      default: return fail(t, STELA_AIR_INSTRUCTION, "unsupported atomicrmw operation");
      }
   }
   return atomic_access(t, inst, LLVMGetOperand(inst, 0), atomic, negate,
                        LLVMGetOperand(inst, exchange ? 2 : 1),
                        exchange ? LLVMGetOperand(inst, 1) : NULL, LLVMGetAlignment(inst));
}

static nir_def *
compare(struct translator *t, LLVMValueRef inst, nir_def *a, nir_def *b)
{
   switch (LLVMGetICmpPredicate(inst)) {
   case LLVMIntEQ: return nir_ieq(&t->b, a, b);
   case LLVMIntNE: return nir_ine(&t->b, a, b);
   case LLVMIntUGT: return nir_ult(&t->b, b, a);
   case LLVMIntUGE: return nir_uge(&t->b, a, b);
   case LLVMIntULT: return nir_ult(&t->b, a, b);
   case LLVMIntULE: return nir_uge(&t->b, b, a);
   case LLVMIntSGT: return nir_ilt(&t->b, b, a);
   case LLVMIntSGE: return nir_ige(&t->b, a, b);
   case LLVMIntSLT: return nir_ilt(&t->b, a, b);
   case LLVMIntSLE: return nir_ige(&t->b, b, a);
   default: fail(t, STELA_AIR_INSTRUCTION, "unsupported integer predicate"); return NULL;
   }
}

static nir_def *
value_lane(struct translator *t, struct value *v, unsigned lane)
{
   if (!v || lane >= v->components) return NULL;
   return v->def ? nir_channel(&t->b, v->def, lane) : v->lanes[lane];
}

static struct value *
partial_value(struct translator *t, LLVMValueRef llvm)
{
   struct value *v = find_value(t, llvm);
   if (v) return v;
   unsigned n, bits;
   if (!value_shape(LLVMTypeOf(llvm), &n, &bits)) {
      fail(t, STELA_AIR_TYPE, "unsupported partial value type"); return NULL;
   }
   if (LLVMIsUndef(llvm) || LLVMIsPoison(llvm)) {
      v = rzalloc(t->values, struct value);
      if (!v) {
         fail(t, STELA_AIR_ALLOCATION, "partial value allocation failed"); return NULL;
      }
      v->components = n; v->bits = bits;
      return v;
   }
   if (n > 1 && (LLVMIsAConstantVector(llvm) || LLVMIsAConstantDataVector(llvm) ||
                 LLVMIsAConstantFP(llvm) || LLVMIsAConstantInt(llvm))) {
      v = rzalloc(t->values, struct value);
      if (!v) { fail(t, STELA_AIR_ALLOCATION, "partial vector allocation failed"); return NULL; }
      v->components = n; v->bits = bits;
      bool complete = true;
      for (unsigned i = 0; i < n; i++) {
         LLVMValueRef element = LLVMGetAggregateElement(llvm, i);
         if (LLVMIsUndef(element) || LLVMIsPoison(element)) complete = false;
         else if (!(v->lanes[i] = get_value(t, element))) return NULL;
      }
      if (complete) v->def = nir_vec(&t->b, v->lanes, n);
      /* Constants are rematerialized at the actual use. Caching a vector's
       * branch-local channels under the LLVM constant would violate dominance
       * at a later use in another region. Instruction defs remain in the map. */
      return v;
   }
   nir_def *def = get_value(t, llvm);
   if (!def) return NULL;
   v = rzalloc(t->values, struct value);
   if (!v) { fail(t, STELA_AIR_ALLOCATION, "constant value wrapper allocation failed"); return NULL; }
   v->def = def; v->components = n; v->bits = bits;
   return v;
}

static bool
put_lanes(struct translator *t, LLVMValueRef llvm, nir_def **lanes, unsigned n, unsigned bits)
{
   struct value *v = rzalloc(t->values, struct value);
   if (!v) return fail(t, STELA_AIR_ALLOCATION, "vector lane allocation failed");
   v->components = n; v->bits = bits;
   bool complete = true;
   for (unsigned i = 0; i < n; i++) { v->lanes[i] = lanes[i]; complete &= lanes[i] != NULL; }
   if (complete) v->def = nir_vec(&t->b, lanes, n);
   return _mesa_hash_table_insert(t->values, llvm, v) != NULL ||
      fail(t, STELA_AIR_ALLOCATION, "vector lane map allocation failed");
}

/* A clip-distance array, the one aggregate a render aggregate holds. */
static bool
clip_array(LLVMTypeRef type)
{
   return LLVMGetTypeKind(type) == LLVMArrayTypeKind && LLVMGetArrayLength2(type) &&
          LLVMGetArrayLength2(type) <= AIR_MAX_CLIP_DISTANCES &&
          LLVMGetTypeKind(LLVMGetElementType(type)) == LLVMFloatTypeKind;
}

/* A render aggregate's element count: a packed struct of scalar, vector and
 * clip-array leaves, or a clip array. Zero for any other type. */
static unsigned
aggregate_count(LLVMTypeRef type)
{
   if (clip_array(type))
      return (unsigned)LLVMGetArrayLength2(type);
   if (LLVMGetTypeKind(type) != LLVMStructTypeKind || LLVMIsOpaqueStruct(type) ||
       !LLVMIsPackedStruct(type) || !LLVMCountStructElementTypes(type) ||
       LLVMCountStructElementTypes(type) > AIR_MAX_ARGUMENTS)
      return 0;
   for (unsigned i = 0; i < LLVMCountStructElementTypes(type); i++) {
      LLVMTypeRef element = LLVMStructGetTypeAtIndex(type, i);
      if (!leaf_shape(element) && !clip_array(element))
         return 0;
   }
   return LLVMCountStructElementTypes(type);
}

static LLVMTypeRef
aggregate_element_type(LLVMTypeRef type, unsigned index)
{
   return LLVMGetTypeKind(type) == LLVMStructTypeKind ? LLVMStructGetTypeAtIndex(type, index) :
                                                        LLVMGetElementType(type);
}

/* An aggregate of `count` elements, copied from `from` or undefined. */
static struct value *
new_aggregate(struct translator *t, unsigned count, const struct value *from)
{
   struct value *v = rzalloc(t->values, struct value);
   if (!v || !(v->elements = rzalloc_array(t->values, struct value *, count))) {
      fail(t, STELA_AIR_ALLOCATION, "aggregate value allocation failed");
      return NULL;
   }
   v->aggregate_count = count;
   if (from)
      memcpy(v->elements, from->elements, count * sizeof(*v->elements));
   return v;
}

static struct value *
aggregate_value(struct translator *t, LLVMValueRef llvm)
{
   struct value *v = find_value(t, llvm);
   if (v) {
      if (v->aggregate_count) return v;
      fail(t, STELA_AIR_TYPE, "nonaggregate render value"); return NULL;
   }
   unsigned count = aggregate_count(LLVMTypeOf(llvm));
   if (!count || (!LLVMIsUndef(llvm) && !LLVMIsPoison(llvm))) {
      fail(t, STELA_AIR_TYPE, "unsupported/forward render aggregate"); return NULL;
   }
   v = new_aggregate(t, count, NULL);
   if (v && !_mesa_hash_table_insert(t->values, llvm, v)) {
      fail(t, STELA_AIR_ALLOCATION, "aggregate value allocation failed"); return NULL;
   }
   return v;
}

/* `a`, of LLVM type `type`, with `leaf` at the index path, copying each
 * aggregate on the path. */
static struct value *
aggregate_insert(struct translator *t, const struct value *a, LLVMTypeRef type,
                 const unsigned *indices, unsigned depth, struct value *leaf)
{
   if (indices[0] >= a->aggregate_count) {
      fail(t, STELA_AIR_INSTRUCTION, "invalid aggregate leaf index");
      return NULL;
   }
   struct value *v = new_aggregate(t, a->aggregate_count, a);
   if (!v)
      return NULL;
   if (depth == 1) {
      v->elements[indices[0]] = leaf;
      return v;
   }
   LLVMTypeRef inner_type = aggregate_element_type(type, indices[0]);
   const struct value *inner = a->elements[indices[0]];
   if (!inner && !(inner = new_aggregate(t, aggregate_count(inner_type), NULL)))
      return NULL;
   if (!inner->aggregate_count) {
      fail(t, STELA_AIR_INSTRUCTION, "aggregate index path enters a leaf");
      return NULL;
   }
   v->elements[indices[0]] = aggregate_insert(t, inner, inner_type, indices + 1, depth - 1, leaf);
   return v->elements[indices[0]] ? v : NULL;
}

/* A render aggregate's insertvalue or extractvalue. Paths are a struct
 * leaf, an array element or a struct's array element. */
static bool
aggregate_instruction(struct translator *t, LLVMValueRef inst, LLVMOpcode op)
{
   unsigned depth = LLVMGetNumIndices(inst);
   const unsigned *indices = LLVMGetIndices(inst);
   struct value *a = aggregate_value(t, LLVMGetOperand(inst, 0));
   if (!a || !depth || depth > 2)
      return fail(t, STELA_AIR_INSTRUCTION, "invalid aggregate index path");
   if (op == LLVMExtractValue) {
      struct value *leaf = a;
      for (unsigned i = 0; leaf && i < depth; i++)
         leaf = indices[i] < leaf->aggregate_count ? leaf->elements[indices[i]] : NULL;
      if (leaf && leaf->aggregate_count)
         return _mesa_hash_table_insert(t->values, inst, leaf) != NULL ||
            fail(t, STELA_AIR_ALLOCATION, "aggregate extraction map failed");
      return (leaf && leaf->def && put_value(t, inst, leaf->def, 0)) ||
         fail(t, STELA_AIR_INSTRUCTION, "undefined/poison aggregate leaf escapes");
   }
   LLVMValueRef inserted = LLVMGetOperand(inst, 1);
   struct value *leaf = aggregate_count(LLVMTypeOf(inserted)) ? aggregate_value(t, inserted) :
                                                                partial_value(t, inserted);
   struct value *v = leaf ? aggregate_insert(t, a, LLVMTypeOf(LLVMGetOperand(inst, 0)), indices,
                                             depth, leaf) : NULL;
   return v && (_mesa_hash_table_insert(t->values, inst, v) != NULL ||
                fail(t, STELA_AIR_ALLOCATION, "aggregate insertion map failed"));
}

/* An extractelement, insertelement or shufflevector, whose operands and
 * result may be partially defined vectors. */
static bool
vector_instruction(struct translator *t, LLVMValueRef inst, LLVMOpcode op)
{
   struct value *a = partial_value(t, LLVMGetOperand(inst, 0));
   if (!a) return false;
   if (op == LLVMExtractElement || op == LLVMInsertElement) {
      LLVMValueRef index = LLVMGetOperand(inst, op == LLVMInsertElement ? 2 : 1);
      if (!LLVMIsAConstantInt(index) || LLVMConstIntGetZExtValue(index) >= a->components)
         return fail(t, STELA_AIR_INSTRUCTION, "invalid/dynamic vector index");
      unsigned channel = LLVMConstIntGetZExtValue(index);
      if (op == LLVMExtractElement) {
         nir_def *lane = value_lane(t, a, channel);
         return (lane && put_value(t, inst, lane, 0)) ||
            fail(t, STELA_AIR_INSTRUCTION, "undefined/poison extracted lane escapes");
      }
      nir_def *lane = get_value(t, LLVMGetOperand(inst, 1));
      if (!lane) return false;
      nir_def *lanes[4];
      for (unsigned i = 0; i < a->components; i++)
         lanes[i] = i == channel ? lane : value_lane(t, a, i);
      return put_lanes(t, inst, lanes, a->components, a->bits);
   }
   struct value *b = partial_value(t, LLVMGetOperand(inst, 1));
   unsigned n = LLVMGetNumMaskElements(inst);
   if (!b || a->components != b->components || a->bits != b->bits || !n || n > 4)
      return fail(t, STELA_AIR_TYPE, "unsupported shuffle shape");
   nir_def *lanes[4] = {0};
   for (unsigned i = 0; i < n; i++) {
      int mask = LLVMGetMaskValue(inst, i);
      if (mask < 0) continue; /* Undefined result lane stays symbolic. */
      unsigned channel = (unsigned)mask;
      if (channel >= a->components + b->components)
         return fail(t, STELA_AIR_INSTRUCTION, "invalid shuffle selector");
      lanes[i] = channel < a->components ? value_lane(t, a, channel) : value_lane(t, b, channel - a->components);
   }
   return put_lanes(t, inst, lanes, n, a->bits);
}

/* The varying map's row for a varying. */
static const struct stela_air_varying_slot *
varying_slot(struct translator *t, const struct stela_air_stage_io *io)
{
   for (unsigned i = 0; i < t->stage_options->varying_count; i++) {
      const struct stela_air_varying_slot *v = &t->stage_options->varyings[i];
      if (v->identifier_bytes == io->identifier_bytes && !memcmp(v->identifier, io->identifier, io->identifier_bytes))
         return v;
   }
   UNREACHABLE("stage map validated before emission");
}

static unsigned
stage_location(struct translator *t, const struct stela_air_stage_io *io)
{
   switch (io->semantic) {
   case STELA_AIR_POSITION: return VARYING_SLOT_POS;
   case STELA_AIR_RENDER_TARGET: return FRAG_RESULT_DATA0 + io->location;
   case STELA_AIR_VERTEX_INPUT: return VERT_ATTRIB_GENERIC0 + io->location;
   case STELA_AIR_POINT_SIZE: return VARYING_SLOT_PSIZ;
   case STELA_AIR_LAYER: return VARYING_SLOT_LAYER;
   case STELA_AIR_VIEWPORT: return VARYING_SLOT_VIEWPORT;
   case STELA_AIR_CLIP_DISTANCE: return VARYING_SLOT_CLIP_DIST0;
   case STELA_AIR_DEPTH: return FRAG_RESULT_DEPTH;
   case STELA_AIR_SAMPLE_MASK: return FRAG_RESULT_SAMPLE_MASK;
   case STELA_AIR_STENCIL: return FRAG_RESULT_STENCIL;
   case STELA_AIR_MESH_PRIMITIVE_ID: return VARYING_SLOT_PRIMITIVE_ID;
   default: break;
   }
   return VARYING_SLOT_VAR0 + varying_slot(t, io)->location;
}

/* Stage IO crosses the stage boundary in 32-bit lanes: floats for float and
 * half, signed or unsigned integers for the integer types. */
static bool
stage_signed(enum stela_air_primitive p)
{
   return p == STELA_AIR_CHAR || p == STELA_AIR_SHORT || p == STELA_AIR_INT;
}

static unsigned
stage_bits(enum stela_air_primitive p)
{
   return p == STELA_AIR_CHAR || p == STELA_AIR_UCHAR ? 8 :
          p == STELA_AIR_SHORT || p == STELA_AIR_USHORT || p == STELA_AIR_HALF ? 16 : 32;
}

static nir_def *
stage_narrow(nir_builder *b, nir_def *def, enum stela_air_primitive p)
{
   unsigned bits = stage_bits(p);
   if (bits == 32)
      return def;
   if (p == STELA_AIR_HALF)
      return nir_f2f16(b, def);
   return stage_signed(p) ? nir_i2iN(b, def, bits) : nir_u2uN(b, def, bits);
}

static nir_def *
stage_widen(nir_builder *b, nir_def *def, enum stela_air_primitive p)
{
   if (def->bit_size == 32)
      return def;
   if (p == STELA_AIR_HALF)
      return nir_f2f32(b, def);
   return stage_signed(p) ? nir_i2i32(b, def) : nir_u2u32(b, def);
}

static nir_variable *
stage_variable(struct translator *t, const struct stela_air_stage_io *io, bool output)
{
   char name[4097];
   const char *source = io->name ? io->name : "air.output";
   size_t n = io->name ? io->name_bytes : strlen(source);
   memcpy(name, source, n); name[n] = 0;
   enum glsl_base_type base = io->primitive == STELA_AIR_FLOAT || io->primitive == STELA_AIR_HALF ?
      GLSL_TYPE_FLOAT : stage_signed(io->primitive) ? GLSL_TYPE_INT : GLSL_TYPE_UINT;
   /* The indices and masks are ints, as SPIR-V's builtins are. */
   if (io->semantic == STELA_AIR_LAYER || io->semantic == STELA_AIR_VIEWPORT ||
       io->semantic == STELA_AIR_SAMPLE_MASK || io->semantic == STELA_AIR_STENCIL ||
       io->semantic == STELA_AIR_MESH_PRIMITIVE_ID)
      base = GLSL_TYPE_INT;
   /* Clip distances are a compact float array, as SPIR-V's ClipDistance is. */
   bool clip = io->semantic == STELA_AIR_CLIP_DISTANCE;
   const struct glsl_type *type = clip ? glsl_array_type(glsl_float_type(), io->clip_distances, 0) :
                                         glsl_vector_type(base, io->components);
   /* A mesh output has one element per vertex or primitive. */
   const struct stela_air_stage_entry *entry = &t->render.entry;
   bool mesh = t->stage_options->stage == STELA_AIR_MESH;
   if (mesh)
      type = glsl_array_type(type, io->per_primitive ? entry->max_primitives : entry->max_vertices, 0);
   nir_variable *var = nir_variable_create(t->b.shader, output ? nir_var_shader_out : nir_var_shader_in,
                                           type, name);
   if (!var) { fail(t, STELA_AIR_ALLOCATION, "render IO variable allocation failed"); return NULL; }
   var->data.location = stage_location(t, io);
   var->data.compact = clip;
   var->data.per_primitive = mesh && io->per_primitive;
   if (clip)
      t->b.shader->info.clip_distance_array_size = io->clip_distances;
   var->data.index = io->semantic == STELA_AIR_RENDER_TARGET ? io->index : 0;
   var->data.invariant = io->invariant;
   if (io->semantic == STELA_AIR_DEPTH) {
      static const enum gl_frag_depth_layout layouts[] = {
         [STELA_AIR_DEPTH_ANY] = FRAG_DEPTH_LAYOUT_ANY,
         [STELA_AIR_DEPTH_GREATER] = FRAG_DEPTH_LAYOUT_GREATER,
         [STELA_AIR_DEPTH_LESS] = FRAG_DEPTH_LAYOUT_LESS,
      };
      t->b.shader->info.fs.depth_layout = layouts[io->depth];
   }
   if (!output && io->semantic != STELA_AIR_VERTEX_INPUT) {
      var->data.interpolation = io->interpolation == STELA_AIR_PERSPECTIVE ? INTERP_MODE_SMOOTH :
                                io->interpolation == STELA_AIR_FLAT ? INTERP_MODE_FLAT :
                                INTERP_MODE_NOPERSPECTIVE;
      var->data.centroid = io->sampling == STELA_AIR_CENTROID;
      var->data.sample = io->sampling == STELA_AIR_SAMPLE;
      /* Mesh primitive data is constant over its primitive. */
      if (io->semantic == STELA_AIR_VARYING && varying_slot(t, io)->per_primitive) {
         var->data.per_primitive = true;
         var->data.interpolation = INTERP_MODE_FLAT;
         var->data.centroid = var->data.sample = false;
      }
   }
   return var;
}

/* A mesh function's shader info and outputs: its data and primitive
 * indices. */
static bool
mesh_outputs(struct translator *t)
{
   const struct stela_air_stage_entry *entry = &t->render.entry;
   if (entry->max_vertices > t->stage_options->max_mesh_vertices ||
       entry->max_primitives > t->stage_options->max_mesh_primitives)
      return fail(t, STELA_AIR_LIMIT, "mesh capacities exceed the target limits");
   shader_info *info = &t->b.shader->info;
   info->mesh.max_vertices_out = entry->max_vertices;
   info->mesh.max_primitives_out = entry->max_primitives;
   info->mesh.primitive_type = entry->topology == STELA_AIR_POINTS ? MESA_PRIM_POINTS :
                               entry->topology == STELA_AIR_LINES ? MESA_PRIM_LINES :
                               MESA_PRIM_TRIANGLES;
   for (unsigned i = 0; i < entry->output_count; i++) {
      if (!(t->outputs[i] = stage_variable(t, &t->render.outputs[i], true)))
         return false;
   }
   unsigned corners = mesa_vertices_per_prim(info->mesh.primitive_type);
   t->indices = nir_variable_create(t->b.shader, nir_var_shader_out,
      glsl_array_type(glsl_vector_type(GLSL_TYPE_UINT, corners), entry->max_primitives, 0),
      "air.primitive_indices");
   if (!t->indices)
      return fail(t, STELA_AIR_ALLOCATION, "mesh index variable allocation failed");
   t->indices->data.location = VARYING_SLOT_PRIMITIVE_INDICES;
   t->indices->data.per_primitive = true;
   return true;
}

/* The arguments of an object or mesh function, and a mesh function's
 * outputs. The grid or primitive count lives in threadgroup memory: Metal
 * lets any thread set it, while Vulkan takes it uniformly at the end. */
static bool
mesh_stage_arguments(struct translator *t)
{
   if (!compute_arguments(t, &t->render.arguments))
      return false;
   bool object = t->stage_options->stage == STELA_AIR_OBJECT;
   t->mesh_state = nir_variable_create(t->b.shader, nir_var_mem_shared,
      glsl_array_type(glsl_uint_type(), object ? 3 : 1, 0), "air.mesh_state");
   if (!t->mesh_state)
      return fail(t, STELA_AIR_ALLOCATION, "mesh state allocation failed");
   return object || mesh_outputs(t);
}

/* A flat int output an amplified vertex function writes for its view. */
static nir_variable *
view_output(struct translator *t, gl_varying_slot slot, const char *name)
{
   nir_variable *var = nir_variable_create(t->b.shader, nir_var_shader_out, glsl_int_type(), name);
   if (!var)
      fail(t, STELA_AIR_ALLOCATION, "render IO variable allocation failed");
   else
      var->data.location = slot;
   return var;
}

/* A call of a post-tessellation vertex function's control point function:
 * the attributes of the control point its first operand indexes. Members
 * the function never reads stay undefined. */
static bool
control_point_call(struct translator *t, LLVMValueRef inst, LLVMValueRef callee, bool *lowered)
{
   *lowered = callee && callee == t->render.control_point_function;
   if (!*lowered)
      return true;
   const struct stela_air_stage_io *io = t->render.inputs;
   while (io->semantic != STELA_AIR_CONTROL_POINTS)
      io++;
   if (LLVMGetNumArgOperands(inst) != 2 || LLVMGetInstructionCallConv(inst) != LLVMCCallConv ||
       LLVMGetOperand(inst, 1) != LLVMGetParam(t->entry, io->argument))
      return fail(t, STELA_AIR_INSTRUCTION, "control points are read through their argument");
   nir_def *point = get_value(t, LLVMGetOperand(inst, 0));
   struct value *v = point ? new_aggregate(t, io->member_count, NULL) : NULL;
   if (!v)
      return false;
   for (unsigned i = 0; i < io->member_count; i++) {
      const struct stela_air_struct_member *member = &io->members[i];
      if (member->unused)
         continue;
      nir_def *def = stage_in_attribute(t, member->location, t->patch_ids, point, member->primitive,
                                        member->components);
      if (!def)
         return false;
      struct value *leaf = rzalloc(t->values, struct value);
      if (!leaf)
         return fail(t, STELA_AIR_ALLOCATION, "control point allocation failed");
      *leaf = (struct value){.def = def, .components = def->num_components, .bits = def->bit_size};
      v->elements[i] = leaf;
   }
   return _mesa_hash_table_insert(t->values, inst, v) != NULL ||
      fail(t, STELA_AIR_ALLOCATION, "control point map allocation failed");
}

/* An air.interpolate_<place>_<perspective>.<type> call: the interpolant
 * argument its first operand names, sampled at the pixel center, the
 * centroid, a sample or an offset. Metal measures offsets from the pixel's
 * upper-left corner and NIR from its center, as SPIRV-Cross's MSL backend
 * accounts for. */
static bool
interpolant_call(struct translator *t, LLVMValueRef inst, const char *name, size_t name_length,
                 bool *lowered)
{
   static const char prefix[] = "air.interpolate_";
   *lowered = name_length > strlen(prefix) && !memcmp(name, prefix, strlen(prefix));
   if (!*lowered)
      return true;
   enum { CENTER, CENTROID, SAMPLE, OFFSET };
   static const char *const places[] = {
      [CENTER] = "center_", [CENTROID] = "centroid_", [SAMPLE] = "sample_", [OFFSET] = "offset_",
   };
   const char *rest = name + strlen(prefix);
   size_t left = name_length - strlen(prefix);
   unsigned place = 0;
   while (place < ARRAY_SIZE(places) &&
          (left < strlen(places[place]) || memcmp(rest, places[place], strlen(places[place]))))
      place++;
   if (place == ARRAY_SIZE(places))
      return fail(t, STELA_AIR_INSTRUCTION, "unsupported interpolation %.*s", (int)name_length, name);
   rest += strlen(places[place]);
   left -= strlen(places[place]);
   static const char perspective[] = "perspective.", linear[] = "no_perspective.";
   enum stela_air_interpolation interpolation =
      left > strlen(perspective) && !memcmp(rest, perspective, strlen(perspective)) ?
         STELA_AIR_PERSPECTIVE :
      left > strlen(linear) && !memcmp(rest, linear, strlen(linear)) ? STELA_AIR_NO_PERSPECTIVE :
                                                                        STELA_AIR_INTERPOLATION_NONE;
   const struct stela_air_stage_io *io = NULL;
   unsigned operands = place == SAMPLE || place == OFFSET ? 2 : 1;
   for (unsigned i = 0; LLVMGetNumArgOperands(inst) == operands && i < t->render.entry.input_count;
        i++) {
      if (t->render.inputs[i].interpolant &&
          LLVMGetOperand(inst, 0) == LLVMGetParam(t->entry, t->render.inputs[i].argument))
         io = &t->render.inputs[i];
   }
   if (!io)
      return fail(t, STELA_AIR_INSTRUCTION, "interpolants are read through their argument");
   LLVMTypeRef type = LLVMTypeOf(inst);
   bool vector = LLVMGetTypeKind(type) == LLVMVectorTypeKind;
   LLVMTypeKind scalar = LLVMGetTypeKind(vector ? LLVMGetElementType(type) : type);
   if (interpolation != io->interpolation || (vector ? LLVMGetVectorSize(type) : 1) != io->components ||
       scalar != (io->primitive == STELA_AIR_HALF ? LLVMHalfTypeKind : LLVMFloatTypeKind))
      return fail(t, STELA_AIR_TYPE, "interpolation of another interpolant");
   nir_variable *var =
      nir_find_variable_with_location(t->b.shader, nir_var_shader_in, stage_location(t, io));
   nir_def *deref = &nir_build_deref_var(&t->b, var)->def, *def;
   if (place == CENTROID) {
      def = nir_interp_deref_at_centroid(&t->b, io->components, 32, deref);
   } else if (place == SAMPLE) {
      nir_def *sample = get_value(t, LLVMGetOperand(inst, 1));
      if (!sample || sample->num_components != 1 || sample->bit_size != 32)
         return fail(t, STELA_AIR_TYPE, "interpolation sample is one uint");
      def = nir_interp_deref_at_sample(&t->b, io->components, 32, deref, sample);
   } else {
      nir_def *offset = place == CENTER ? nir_imm_vec2(&t->b, 0.0f, 0.0f) :
                                          get_value(t, LLVMGetOperand(inst, 1));
      if (!offset || offset->num_components != 2 || offset->bit_size != 32)
         return fail(t, STELA_AIR_TYPE, "interpolation offset is one float2");
      if (place == OFFSET)
         offset = nir_fadd_imm(&t->b, offset, -0.5);
      def = nir_interp_deref_at_offset(&t->b, io->components, 32, deref, offset);
   }
   return put_value(t, inst, stage_narrow(&t->b, def, io->primitive), 0);
}

static bool
stage_arguments(struct translator *t, LLVMValueRef fn)
{
   bool slots[UINT8_MAX + 1] = {0};
   t->fields = t->render.arguments.fields;
   /* Its builtins and stage-in read the patch's IDs. */
   if (t->render.entry.patch && !(t->patch_ids = device_value(t, STELA_AIR_PATCH_IDS)))
      return false;
   for (unsigned i = 0; i < t->render.entry.input_count; i++) {
      const struct stela_air_stage_io *io = &t->render.inputs[i];
      const struct stela_air_argument *argument = &t->render.arguments.arguments[i];
      LLVMValueRef param = LLVMGetParam(fn, io->argument);
      nir_def *def;
      unsigned slot = 0;
      if (io->semantic == STELA_AIR_STAGE_TEXTURE || io->semantic == STELA_AIR_STAGE_SAMPLER) {
         bool texture = io->semantic == STELA_AIR_STAGE_TEXTURE;
         if (!put_resource(t, param, texture ? &io->texture : NULL, &io->sampler))
            return false;
         continue;
      }
      if (io->semantic == STELA_AIR_STAGE_BUFFER) {
         /* Full stage metadata/layout validation has already completed. An
          * actually unused declaration needs no resource binding or SSA value;
          * a dead instruction using the parameter still counts as a real use. */
         if (!io->used && !LLVMGetFirstUse(param)) continue;
         if (t->options->bind_ssbo) {
            if (!t->options->bind_ssbo(&io->buffer, &slot, t->options->binding_data) ||
                slot >= t->options->ssbo_count || slots[slot])
               return fail(t, STELA_AIR_ARGUMENT, "invalid render buffer SSBO binding");
            slots[slot] = true; def = nir_imm_int64(&t->b, 0);
         } else {
            if (!t->options->bind_buffer)
               return fail(t, STELA_AIR_ARGUMENT, "unbound render buffer");
            def = t->options->bind_buffer(&t->b, &io->buffer, t->options->binding_data);
            if (!binding_prelude(t))
               return false;
            if (!def || def->num_components != 1 || def->bit_size != 64)
               return fail(t, STELA_AIR_ARGUMENT, "invalid/unbound render buffer");
         }
      } else if (io->semantic == STELA_AIR_STAGE_BUILTIN) {
         def = builtin_argument(t, io->builtin, param);
         if (!def)
            return false;
      } else if (io->semantic == STELA_AIR_POSITION) {
         t->b.shader->info.fs.origin_upper_left = true;
         t->b.shader->info.fs.pixel_center_integer = false;
         if (!io->used) continue;
         def = nir_load_frag_coord(&t->b);
      } else if (io->semantic == STELA_AIR_CONTROL_POINTS) {
         continue; /* Calls of its function read it. */
      } else if (io->semantic == STELA_AIR_BARYCENTRIC) {
         if (!io->used) continue;
         enum glsl_interp_mode mode = io->interpolation == STELA_AIR_PERSPECTIVE ?
            INTERP_MODE_SMOOTH : INTERP_MODE_NOPERSPECTIVE;
         def = io->sampling == STELA_AIR_SAMPLE ?
                  nir_load_barycentric_coord_sample(&t->b, 32, .interp_mode = mode) :
               io->sampling == STELA_AIR_CENTROID ?
                  nir_load_barycentric_coord_centroid(&t->b, 32, .interp_mode = mode) :
                  nir_load_barycentric_coord_pixel(&t->b, 32, .interp_mode = mode);
         def = nir_trim_vector(&t->b, def, io->components);
      } else if (io->semantic == STELA_AIR_POSITION_IN_PATCH) {
         /* Metal's patch coordinates are Vulkan's with the upper-left domain
          * origin. */
         def = nir_trim_vector(&t->b, nir_load_tess_coord(&t->b), io->components);
      } else if (t->render.entry.patch) {
         if (!io->used) continue;
         if (!(def = stage_in_attribute(t, io->location, t->patch_ids, NULL, io->primitive,
                                        io->components)))
            return false;
      } else {
         nir_variable *var = stage_variable(t, io, false);
         if (!var) return false;
         if (io->interpolant) continue; /* Calls interpolate it. */
         def = stage_narrow(&t->b, nir_load_var(&t->b, var), io->primitive);
      }
      if (!put_value(t, param, def, io->buffer.access)) return false;
      if (io->semantic == STELA_AIR_STAGE_BUFFER) {
         struct value *v = find_value(t, param);
         if (!argument_root(t, v, param, argument))
            return false;
         v->ssbo = t->options->bind_ssbo != NULL; v->ssbo_slot = slot;
      }
   }
   for (unsigned i = 0; i < t->render.entry.output_count; i++) {
      const struct stela_air_stage_io *io = &t->render.outputs[i];
      if (!(t->outputs[i] = stage_variable(t, io, true))) return false;
      if (io->semantic == STELA_AIR_LAYER) t->layer = t->outputs[i];
      if (io->semantic == STELA_AIR_VIEWPORT) t->viewport = t->outputs[i];
   }
   if (t->stage_options->amplified) {
      if (!t->layer && !(t->layer = view_output(t, VARYING_SLOT_LAYER, "air.view_layer")))
         return false;
      if (!t->viewport && !(t->viewport = view_output(t, VARYING_SLOT_VIEWPORT, "air.view_viewport")))
         return false;
   }
   return true;
}

static bool
stage_return(struct translator *t, LLVMValueRef inst)
{
   if (!t->render.entry.output_count && !LLVMGetNumOperands(inst))
      return true;
   if (LLVMGetNumOperands(inst) != 1) return fail(t, STELA_AIR_TYPE, "render entry requires its real return value");
   LLVMValueRef returned = LLVMGetOperand(inst, 0);
   struct value *aggregate = NULL;
   if (LLVMGetTypeKind(LLVMTypeOf(returned)) == LLVMStructTypeKind) {
      aggregate = aggregate_value(t, returned);
      if (!aggregate || aggregate->aggregate_count != t->render.entry.output_count)
         return fail(t, STELA_AIR_TYPE, "render output aggregate mismatch");
   }
   nir_def *values[AIR_MAX_ARGUMENTS];
   nir_def *clip[AIR_MAX_CLIP_DISTANCES];
   for (unsigned i = 0; i < t->render.entry.output_count; i++) {
      const struct stela_air_stage_io *io = &t->render.outputs[i];
      const struct value *leaf = aggregate ? aggregate->elements[i] : NULL;
      if (io->semantic == STELA_AIR_CLIP_DISTANCE) {
         /* The one clip-distance output: every distance is defined. */
         for (unsigned j = 0; leaf && j < io->clip_distances; j++) {
            clip[j] = leaf->elements[j] ? leaf->elements[j]->def : NULL;
            if (!clip[j]) leaf = NULL;
         }
         values[i] = leaf ? clip[0] : NULL;
      } else {
         values[i] = aggregate ? (leaf ? leaf->def : NULL) : get_value(t, returned);
      }
      if (!values[i]) return fail(t, STELA_AIR_INSTRUCTION, "undefined/poison render output leaf/lane");
   }
   /* Validate ALL leaves before emitting any output effect. */
   nir_def *layer = NULL, *viewport = NULL;
   for (unsigned i = 0; i < t->render.entry.output_count; i++) {
      const struct stela_air_stage_io *io = &t->render.outputs[i];
      if (io->semantic == STELA_AIR_CLIP_DISTANCE) {
         nir_deref_instr *array = nir_build_deref_var(&t->b, t->outputs[i]);
         for (unsigned j = 0; j < io->clip_distances; j++)
            nir_store_deref(&t->b, nir_build_deref_array_imm(&t->b, array, j), clip[j], 1);
         continue;
      }
      nir_def *value = stage_widen(&t->b, values[i], io->primitive);
      if (t->stage_options->amplified && t->outputs[i] == t->layer)
         layer = value;
      else if (t->stage_options->amplified && t->outputs[i] == t->viewport)
         viewport = value;
      else
         nir_store_var(&t->b, t->outputs[i], value, BITFIELD_MASK(value->num_components));
   }
   if (t->stage_options->amplified) {
      nir_def *mapping = device_value(t, STELA_AIR_VIEW_MAPPING);
      if (!mapping)
         return false;
      nir_def *zero = nir_imm_int(&t->b, 0);
      nir_store_var(&t->b, t->layer, nir_iadd(&t->b, layer ? layer : zero, nir_ushr_imm(&t->b, mapping, 16)), 1);
      nir_store_var(&t->b, t->viewport,
                    nir_iadd(&t->b, viewport ? viewport : zero, nir_iand_imm(&t->b, mapping, 0xffff)), 1);
   }
   return true;
}

enum integer_count_operation {
   INTEGER_COUNT_POPULATION,
   INTEGER_COUNT_LEADING_ZEROS,
   INTEGER_COUNT_TRAILING_ZEROS,
};

/* Admit canonical LLVM overloads, never names that merely share a prefix. */
static bool
integer_count(struct translator *t, LLVMValueRef inst, LLVMValueRef callee,
              unsigned intrinsic, enum integer_count_operation operation)
{
   unsigned components, bits;
   LLVMTypeRef type = LLVMTypeOf(inst);
   if (!shape(type, &components, &bits) || bits == 1)
      return fail(t, STELA_AIR_TYPE, "unsupported LLVM integer-count result shape");
   LLVMTypeRef expected = LLVMIntrinsicGetType(t->context, intrinsic, &type, 1);
   unsigned arity = operation == INTEGER_COUNT_POPULATION ? 1 : 2;
   if (!LLVMIsDeclaration(callee) || LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
       LLVMGetInstructionCallConv(inst) != LLVMCCallConv ||
       LLVMGlobalGetValueType(callee) != expected || LLVMGetCalledFunctionType(inst) != expected ||
       LLVMGetNumArgOperands(inst) != arity || LLVMCountParams(callee) != arity ||
       LLVMIsFunctionVarArg(expected) || LLVMGetNumOperandBundles(inst) ||
       LLVMTypeOf(LLVMGetOperand(inst, 0)) != type)
      return fail(t, STELA_AIR_TYPE, "unsupported LLVM integer-count call signature");
   size_t canonical_length = 0, name_length = 0;
   char *canonical = LLVMIntrinsicCopyOverloadedName2(t->module, intrinsic, &type, 1,
                                                     &canonical_length);
   if (!canonical)
      return fail(t, STELA_AIR_ALLOCATION, "LLVM integer-count overload name unavailable");
   const char *name = LLVMGetValueName2(callee, &name_length);
   bool canonical_name = name_length == canonical_length && !memcmp(name, canonical, name_length);
   LLVMDisposeMessage(canonical); /* The pinned C API uses strdup/free. */
   if (!canonical_name)
      return fail(t, STELA_AIR_INSTRUCTION, "noncanonical LLVM integer-count overload name");
   if (operation != INTEGER_COUNT_POPULATION) {
      LLVMValueRef flag = LLVMGetOperand(inst, 1);
      if (LLVMTypeOf(flag) != LLVMInt1TypeInContext(t->context) || !LLVMIsAConstantInt(flag))
         return fail(t, STELA_AIR_INSTRUCTION, "LLVM zero-count poison flag requires constant scalar i1");
      /* true with a zero input is LLVM poison. Defined inputs have the same
       * mapping for either flag; no zero-result/trap claim is made for true. */
   }
   nir_def *input = get_value(t, LLVMGetOperand(inst, 0));
   if (!input)
      return false;
   if (input->num_components != components || input->bit_size != bits)
      return fail(t, STELA_AIR_TYPE, "LLVM integer-count operand shape mismatch");
   /* NIR ufind_msb is only valid for 32/64-bit sources. Widen without sign
    * extension so the original width still determines leading-zero counts. */
   if (bits < 32)
      input = nir_u2u32(&t->b, input);
   nir_def *count;
   if (operation == INTEGER_COUNT_POPULATION) {
      count = nir_bit_count(&t->b, input);
   } else if (operation == INTEGER_COUNT_LEADING_ZEROS) {
      count = nir_isub(&t->b, nir_imm_int(&t->b, bits - 1), nir_ufind_msb(&t->b, input));
   } else {
      nir_def *lsb = nir_find_lsb(&t->b, input);
      count = nir_bcsel(&t->b, nir_ieq_imm(&t->b, lsb, -1), nir_imm_int(&t->b, bits), lsb);
   }
   return put_value(t, inst, nir_u2uN(&t->b, count, bits), 0);
}

enum integer_permutation_operation {
   INTEGER_REVERSE_BITS,
   INTEGER_SWAP_BYTES,
};

enum { AIR_BYTE_BITS = 8, AIR_HALFWORD_BITS = 16, AIR_WORD_BITS = 32 };

static nir_def *
byte_swap32(nir_builder *b, nir_def *value)
{
   const uint32_t low_bytes_of_halfwords = UINT32_C(0x00ff00ff);
   nir_def *adjacent = nir_ior(b,
      nir_ishl_imm(b, nir_iand_imm(b, value, low_bytes_of_halfwords), AIR_BYTE_BITS),
      nir_iand_imm(b, nir_ushr_imm(b, value, AIR_BYTE_BITS), low_bytes_of_halfwords));
   return nir_ior(b, nir_ishl_imm(b, adjacent, AIR_HALFWORD_BITS),
                     nir_ushr_imm(b, adjacent, AIR_HALFWORD_BITS));
}

static bool
integer_permutation(struct translator *t, LLVMValueRef inst, LLVMValueRef callee,
                    unsigned intrinsic, enum integer_permutation_operation operation)
{
   unsigned components, bits;
   LLVMTypeRef type = LLVMTypeOf(inst);
   if (!shape(type, &components, &bits) || bits == 1 ||
       (operation == INTEGER_SWAP_BYTES && bits % AIR_HALFWORD_BITS))
      return fail(t, STELA_AIR_TYPE, "unsupported LLVM integer-permutation result shape");
   LLVMTypeRef expected = LLVMIntrinsicGetType(t->context, intrinsic, &type, 1);
   if (!LLVMIsDeclaration(callee) || LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
       LLVMGetInstructionCallConv(inst) != LLVMCCallConv ||
       LLVMGlobalGetValueType(callee) != expected || LLVMGetCalledFunctionType(inst) != expected ||
       LLVMGetNumArgOperands(inst) != 1 || LLVMCountParams(callee) != 1 ||
       LLVMIsFunctionVarArg(expected) || LLVMGetNumOperandBundles(inst) ||
       LLVMTypeOf(LLVMGetOperand(inst, 0)) != type)
      return fail(t, STELA_AIR_TYPE, "unsupported LLVM integer-permutation call signature");
   size_t canonical_length = 0, name_length = 0;
   char *canonical = LLVMIntrinsicCopyOverloadedName2(t->module, intrinsic, &type, 1,
                                                     &canonical_length);
   if (!canonical)
      return fail(t, STELA_AIR_ALLOCATION, "LLVM integer-permutation overload name unavailable");
   const char *name = LLVMGetValueName2(callee, &name_length);
   bool canonical_name = name_length == canonical_length && !memcmp(name, canonical, name_length);
   LLVMDisposeMessage(canonical);
   if (!canonical_name)
      return fail(t, STELA_AIR_INSTRUCTION, "noncanonical LLVM integer-permutation overload name");
   nir_def *input = get_value(t, LLVMGetOperand(inst, 0));
   if (!input)
      return false;
   if (input->num_components != components || input->bit_size != bits)
      return fail(t, STELA_AIR_TYPE, "LLVM integer-permutation operand shape mismatch");
   if (bits < AIR_WORD_BITS)
      input = nir_u2u32(&t->b, input);
   nir_def *result;
   if (operation == INTEGER_REVERSE_BITS) {
      /* Keep native64 available to ACO's uniform scalar selector. Each actual
       * compiler owns its existing lowering; ELK intake adds its missing bit. */
      result = nir_bitfield_reverse(&t->b, input);
      if (bits < AIR_WORD_BITS)
         result = nir_ushr_imm(&t->b, result, AIR_WORD_BITS - bits);
   } else if (bits == AIR_HALFWORD_BITS) {
      result = nir_ior(&t->b, nir_ishl_imm(&t->b, input, AIR_BYTE_BITS),
                             nir_ushr_imm(&t->b, input, AIR_BYTE_BITS));
   } else if (bits == AIR_WORD_BITS) {
      result = byte_swap32(&t->b, input);
   } else {
      nir_def *low = byte_swap32(&t->b, nir_unpack_64_2x32_split_x(&t->b, input));
      nir_def *high = byte_swap32(&t->b, nir_unpack_64_2x32_split_y(&t->b, input));
      result = nir_pack_64_2x32_split(&t->b, high, low);
   }
   return put_value(t, inst, nir_u2uN(&t->b, result, bits), 0);
}

enum integer_minmax_operation {
   INTEGER_SIGNED_MINIMUM,
   INTEGER_SIGNED_MAXIMUM,
   INTEGER_UNSIGNED_MINIMUM,
   INTEGER_UNSIGNED_MAXIMUM,
};

static bool
integer_minmax(struct translator *t, LLVMValueRef inst, LLVMValueRef callee,
               unsigned intrinsic, enum integer_minmax_operation operation)
{
   unsigned components, bits;
   LLVMTypeRef type = LLVMTypeOf(inst);
   if (!shape(type, &components, &bits) || bits == 1)
      return fail(t, STELA_AIR_TYPE, "unsupported LLVM integer-minmax result shape");
   LLVMTypeRef expected = LLVMIntrinsicGetType(t->context, intrinsic, &type, 1);
   if (!LLVMIsDeclaration(callee) || LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
       LLVMGetInstructionCallConv(inst) != LLVMCCallConv ||
       LLVMGlobalGetValueType(callee) != expected || LLVMGetCalledFunctionType(inst) != expected ||
       LLVMGetNumArgOperands(inst) != 2 || LLVMCountParams(callee) != 2 ||
       LLVMIsFunctionVarArg(expected) || LLVMGetNumOperandBundles(inst) ||
       LLVMTypeOf(LLVMGetOperand(inst, 0)) != type || LLVMTypeOf(LLVMGetOperand(inst, 1)) != type)
      return fail(t, STELA_AIR_TYPE, "unsupported LLVM integer-minmax call signature");
   size_t canonical_length = 0, name_length = 0;
   char *canonical = LLVMIntrinsicCopyOverloadedName2(t->module, intrinsic, &type, 1,
                                                     &canonical_length);
   if (!canonical)
      return fail(t, STELA_AIR_ALLOCATION, "LLVM integer-minmax overload name unavailable");
   const char *name = LLVMGetValueName2(callee, &name_length);
   bool canonical_name = name_length == canonical_length && !memcmp(name, canonical, name_length);
   LLVMDisposeMessage(canonical);
   if (!canonical_name)
      return fail(t, STELA_AIR_INSTRUCTION, "noncanonical LLVM integer-minmax overload name");
   nir_def *a = get_value(t, LLVMGetOperand(inst, 0));
   nir_def *b = get_value(t, LLVMGetOperand(inst, 1));
   if (!a || !b)
      return false;
   if (a->num_components != components || b->num_components != components ||
       a->bit_size != bits || b->bit_size != bits)
      return fail(t, STELA_AIR_TYPE, "LLVM integer-minmax operand shape mismatch");
   nir_def *result;
   switch (operation) {
   case INTEGER_SIGNED_MINIMUM: result = nir_imin(&t->b, a, b); break;
   case INTEGER_SIGNED_MAXIMUM: result = nir_imax(&t->b, a, b); break;
   case INTEGER_UNSIGNED_MINIMUM: result = nir_umin(&t->b, a, b); break;
   case INTEGER_UNSIGNED_MAXIMUM: result = nir_umax(&t->b, a, b); break;
   default: return fail(t, STELA_AIR_INSTRUCTION, "unknown LLVM integer-minmax operation");
   }
   return put_value(t, inst, result, 0);
}

enum integer_funnel_operation {
   INTEGER_FUNNEL_LEFT,
   INTEGER_FUNNEL_RIGHT,
};

static bool
integer_funnel(struct translator *t, LLVMValueRef inst, LLVMValueRef callee,
               unsigned intrinsic, enum integer_funnel_operation operation)
{
   unsigned components, bits;
   LLVMTypeRef type = LLVMTypeOf(inst);
   LLVMTypeRef element = LLVMGetTypeKind(type) == LLVMVectorTypeKind ? LLVMGetElementType(type) : type;
   if (LLVMGetTypeKind(element) != LLVMIntegerTypeKind ||
       !shape(type, &components, &bits) || bits == 1)
      return fail(t, STELA_AIR_TYPE, "unsupported LLVM integer-funnel result shape");
   LLVMTypeRef expected = LLVMIntrinsicGetType(t->context, intrinsic, &type, 1);
   if (!LLVMIsDeclaration(callee) || LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
       LLVMGetInstructionCallConv(inst) != LLVMCCallConv ||
       LLVMGlobalGetValueType(callee) != expected || LLVMGetCalledFunctionType(inst) != expected ||
       LLVMGetNumArgOperands(inst) != 3 || LLVMCountParams(callee) != 3 ||
       LLVMIsFunctionVarArg(expected) || LLVMGetNumOperandBundles(inst) ||
       LLVMTypeOf(LLVMGetOperand(inst, 0)) != type ||
       LLVMTypeOf(LLVMGetOperand(inst, 1)) != type ||
       LLVMTypeOf(LLVMGetOperand(inst, 2)) != type)
      return fail(t, STELA_AIR_TYPE, "unsupported LLVM integer-funnel call signature");
   size_t canonical_length = 0, name_length = 0;
   char *canonical = LLVMIntrinsicCopyOverloadedName2(t->module, intrinsic, &type, 1,
                                                     &canonical_length);
   if (!canonical)
      return fail(t, STELA_AIR_ALLOCATION, "LLVM integer-funnel overload name unavailable");
   const char *name = LLVMGetValueName2(callee, &name_length);
   bool canonical_name = name_length == canonical_length && !memcmp(name, canonical, name_length);
   LLVMDisposeMessage(canonical);
   if (!canonical_name)
      return fail(t, STELA_AIR_INSTRUCTION, "noncanonical LLVM integer-funnel overload name");
   nir_def *a = get_value(t, LLVMGetOperand(inst, 0));
   nir_def *b = get_value(t, LLVMGetOperand(inst, 1));
   nir_def *amount = get_value(t, LLVMGetOperand(inst, 2));
   if (!a || !b || !amount)
      return false;
   if (a->num_components != components || b->num_components != components ||
       amount->num_components != components || a->bit_size != bits ||
       b->bit_size != bits || amount->bit_size != bits)
      return fail(t, STELA_AIR_TYPE, "LLVM integer-funnel operand shape mismatch");
   /* NIR shift amounts are uint32 and masked by the data width. Truncating
    * i64 first preserves every bit relevant to modulo 64. Keep data native. */
   nir_def *k = nir_iand_imm(&t->b, nir_u2u32(&t->b, amount), bits - 1);
   bool left = operation == INTEGER_FUNNEL_LEFT;
   bool same_input = LLVMGetOperand(inst, 0) == LLVMGetOperand(inst, 1);
   const nir_shader_compiler_options *options = t->b.shader->options;
   bool rotate = (bits == 8 && options->has_rotate8) ||
                 (bits == 16 && options->has_rotate16) ||
                 (bits == 32 && options->has_rotate32);
   nir_def *result;
   if (same_input && rotate) {
      result = left ? nir_urol(&t->b, a, k) : nir_uror(&t->b, a, k);
   } else if (bits == 32 && options->has_shfr32) {
      result = nir_shfr(&t->b, a, b, left ? nir_ineg(&t->b, k) : k);
      if (left && !same_input)
         result = nir_bcsel(&t->b, nir_ieq_imm(&t->b, k, 0), a, result);
   } else {
      nir_def *negative = nir_ineg(&t->b, k);
      nir_def *shifted = left ? nir_ior(&t->b, nir_ishl(&t->b, a, k), nir_ushr(&t->b, b, negative)) :
                                nir_ior(&t->b, nir_ishl(&t->b, a, negative), nir_ushr(&t->b, b, k));
      /* At zero, the masked complementary shift is also zero. OR would be
       * wrong for unequal a/b; LLVM selects a for left and b for right. */
      result = nir_bcsel(&t->b, nir_ieq_imm(&t->b, k, 0), left ? a : b, shifted);
   }
   return put_value(t, inst, result, 0);
}

static bool same_pointer_resource(const struct value *a, const struct value *b);

static nir_def *
texture_operand(void *translator, LLVMValueRef value)
{
   return get_value(translator, value);
}

static const struct stela_air_texture *
texture_argument(void *translator, LLVMValueRef value, nir_def **id)
{
   const struct value *v = find_value(translator, value);
   *id = v ? v->id : NULL;
   return v && !v->array ? v->texture : NULL;
}

static bool
math_environment(void *translator)
{
   return fp_environment(translator);
}

static bool
math_store(void *translator, LLVMValueRef pointer, nir_def *value)
{
   struct translator *t = translator;
   const struct value *address = pointer_value(t, pointer);
   if (!address || !(address->access & STELA_AIR_WRITE))
      return fail(t, STELA_AIR_MEMORY, "math function result pointer is not writable");
   memory_access(t, address, value, NULL, 0, value->num_components, value->bit_size,
                 value->bit_size / 8);
   return t->error->kind == STELA_AIR_OK;
}

/* LLVM's conversions to, from and between half and float. */
static bool
fp_conversion(struct translator *t, LLVMValueRef inst, LLVMOpcode op)
{
   unsigned components, bits, source_components, source_bits;
   LLVMTypeRef result = LLVMTypeOf(inst), source = LLVMTypeOf(LLVMGetOperand(inst, 0));
   bool to_float = op != LLVMFPToSI && op != LLVMFPToUI;
   bool from_float = op != LLVMSIToFP && op != LLVMUIToFP;
   if (!(to_float ? float_shape(result, &components, &bits) : shape(result, &components, &bits)) ||
       !(from_float ? float_shape(source, &source_components, &source_bits) :
                      shape(source, &source_components, &source_bits)) ||
       components != source_components || (!to_float && bits == 1))
      return fail(t, STELA_AIR_TYPE, "unsupported floating-point conversion types");
   if (!fp_environment(t))
      return false;
   nir_def *a = get_value(t, LLVMGetOperand(inst, 0));
   if (!a)
      return false;
   nir_def *value;
   switch (op) {
   case LLVMFPExt:
   case LLVMFPTrunc:
      value = bits == 16 ? nir_f2f16_rtne(&t->b, a) : nir_f2fN(&t->b, a, bits);
      break;
   case LLVMFPToSI: value = nir_f2iN(&t->b, a, bits); break;
   case LLVMFPToUI: value = nir_f2uN(&t->b, a, bits); break;
   case LLVMSIToFP:
      value = source_bits == 1 ? nir_bcsel(&t->b, a, nir_imm_floatN_t(&t->b, -1.0, bits),
                                           nir_imm_floatN_t(&t->b, 0.0, bits)) :
                                 nir_i2fN(&t->b, a, bits);
      break;
   default:
      value = source_bits == 1 ? nir_b2fN(&t->b, a, bits) : nir_u2fN(&t->b, a, bits);
      break;
   }
   return put_value(t, inst, value, 0);
}

static const struct stela_air_sampler *
sampler_argument(void *translator, LLVMValueRef value, nir_def **id)
{
   const struct value *v = find_value(translator, value);
   *id = v ? v->id : NULL;
   return v && !v->array ? v->sampler : NULL;
}

/* A call of one of AIR's texture functions; false with no error when the
 * call is something else. */
/* The read-write word at a texture call's pointer operand. */
static const struct value *
texture_word(struct translator *t, LLVMValueRef pointer)
{
   const struct value *address = pointer_value(t, pointer);
   if (!address || (address->access & STELA_AIR_READ_WRITE) != STELA_AIR_READ_WRITE) {
      fail(t, STELA_AIR_MEMORY, "texture call lacks a bound read-write pointer");
      return NULL;
   }
   return address;
}

static nir_def *
texture_load_word(void *translator, LLVMValueRef pointer)
{
   struct translator *t = translator;
   const struct value *address = texture_word(t, pointer);
   return address ? memory_access(t, address, NULL, NULL, 0, 1, 32, 4) : NULL;
}

static bool
texture_store_word(void *translator, LLVMValueRef pointer, nir_def *value)
{
   struct translator *t = translator;
   const struct value *address = texture_word(t, pointer);
   if (address)
      memory_access(t, address, value, NULL, 0, 1, 32, 4);
   return t->error->kind == STELA_AIR_OK;
}

static bool
texture_call(struct translator *t, LLVMValueRef inst, const char *name, size_t name_length,
             bool *lowered)
{
   const struct stela_air_texture_context context = {
      .b = &t->b, .options = t->options, .error = t->error, .translator = t,
      .operand = texture_operand, .texture = texture_argument, .sampler = sampler_argument,
      .load_word = texture_load_word, .store_word = texture_store_word,
   };
   nir_def *result, *residency;
   bool pair;
   switch (stela_air_texture_call(&context, inst, name, name_length, &result, &pair, &residency)) {
   case STELA_AIR_TEXTURE_OTHER:
      *lowered = false;
      return true;
   case STELA_AIR_TEXTURE_FAILED:
      return false;
   case STELA_AIR_TEXTURE_LOWERED:
      break;
   }
   *lowered = true;
   if (!result)
      return true;
   if (!pair)
      return put_value(t, inst, result, 0);
   return put_pair(t, inst, result, residency);
}

static nir_def *
command_resource(void *translator, LLVMValueRef value, enum stela_air_field_kind kind)
{
   struct translator *t = translator;
   const struct value *v = find_value(t, value);
   if (!v || !v->object || v->object->kind != kind) {
      fail(t, STELA_AIR_ARGUMENT, "command call operand is not its argument buffer field");
      return NULL;
   }
   return v->id;
}

/* A buffer a command binds: a device or constant buffer's address, or none. */
static nir_def *
command_address(void *translator, LLVMValueRef value)
{
   struct translator *t = translator;
   if (LLVMIsAConstantPointerNull(value))
      return nir_imm_int64(&t->b, 0);
   const struct value *v = pointer_value(t, value);
   if (!v || !v->pointer_root || v->storage || v->constant_data || v->ssbo || v->array ||
       v->object || !v->def || v->def->bit_size != 64) {
      fail(t, STELA_AIR_MEMORY, "indirect commands bind device or constant buffer addresses");
      return NULL;
   }
   return v->def;
}

/* Copies bytes to encoding's destination, 16 at a time: a loop of the flat
 * CFG. */
static bool
command_copy(struct translator *t, const struct stela_air_command_encoding *encoding)
{
   nir_builder *b = &t->b;
   nir_block *entry = nir_cursor_current_block(b->cursor);
   nir_block *header = new_block(t), *body = new_block(t), *exit = new_block(t);
   nir_phi_instr *phi = nir_phi_instr_create(b->shader);
   if (!header || !body || !exit || !phi)
      return fail(t, STELA_AIR_ALLOCATION, "AIR command copy allocation failed");
   nir_def *zero = nir_imm_int(b, 0);
   nir_goto(b, header);
   /* The offset PHI heads the header once both its sources exist. */
   nir_def_init(&phi->instr, &phi->def, 1, 32);
   b->cursor = nir_after_block(header);
   nir_goto_if(b, body, nir_ult(b, &phi->def, encoding->bytes), exit);
   b->cursor = nir_after_block(body);
   nir_def *offset = nir_u2u64(b, &phi->def);
   nir_def *chunk = encoding->source ?
      nir_load_global(b, 4, 32, nir_iadd(b, encoding->source, offset), .align_mul = 16) :
      nir_imm_zero(b, 4, 32);
   nir_store_global(b, chunk, nir_iadd(b, encoding->destination, offset), .align_mul = 16);
   nir_def *next = nir_iadd_imm(b, &phi->def, 16);
   nir_goto(b, header);
   nir_phi_instr_add_src(phi, entry, zero);
   nir_phi_instr_add_src(phi, body, next);
   nir_instr_insert(nir_before_block(header), &phi->instr);
   b->cursor = nir_after_block(exit);
   return true;
}

/* An indirect command's encoding: its stores, under guards that consecutive
 * stores with one condition share, then its copy under its own. */
static bool
command_writes(struct translator *t, const struct stela_air_command_encoding *encoding)
{
   if (encoding->store_count > STELA_AIR_COMMAND_STORES)
      return fail(t, STELA_AIR_ARGUMENT, "command callback exceeded its stores");
   for (unsigned i = 0; i < encoding->store_count;) {
      nir_def *valid = encoding->stores[i].valid;
      struct memory_guard guard;
      if (!memory_guard_begin(t, valid, &guard))
         return false;
      for (; i < encoding->store_count && encoding->stores[i].valid == valid; i++) {
         const struct stela_air_command_store *store = &encoding->stores[i];
         nir_store_global(&t->b, store->value, store->address,
                          .align_mul = store->value->bit_size / 8);
      }
      memory_guard_end(t, &guard, NULL);
   }
   if (!encoding->bytes)
      return true;
   struct memory_guard guard;
   if (!memory_guard_begin(t, encoding->copy_valid, &guard) || !command_copy(t, encoding))
      return false;
   memory_guard_end(t, &guard, NULL);
   return true;
}

/* A call of one of AIR's indirect command functions; false with no error
 * when the call is something else. */
static bool
command_call(struct translator *t, LLVMValueRef inst, LLVMValueRef callee, const char *name,
             size_t name_length, bool *lowered)
{
   const struct stela_air_command_context context = {
      .call = {.b = &t->b, .error = t->error, .translator = t, .operand = texture_operand},
      .resource_id = command_resource, .address = command_address,
   };
   struct stela_air_command command;
   bool size;
   switch (stela_air_command_call(&context, inst, callee, name, name_length, &command, &size)) {
   case STELA_AIR_CALL_OTHER:
      *lowered = false;
      return true;
   case STELA_AIR_CALL_FAILED:
      return false;
   case STELA_AIR_CALL_LOWERED:
      break;
   }
   *lowered = true;
   const struct stela_air_options *o = t->options;
   if (!o->command_count || !o->encode_command)
      return fail(t, STELA_AIR_INSTRUCTION, "indirect command functions are unbound");
   if (size) {
      nir_def *count = o->command_count(&t->b, command.buffer, o->binding_data);
      if (!count || count->num_components != 1 || count->bit_size != 32)
         return fail(t, STELA_AIR_ARGUMENT, "command count callback refused a buffer");
      return put_value(t, inst, count, 0);
   }
   struct stela_air_command_encoding encoding = {0};
   if (!o->encode_command(&t->b, &command, &encoding, o->binding_data))
      return fail(t, STELA_AIR_ARGUMENT, "command callback refused an indirect command");
   return command_writes(t, &encoding);
}

/* extractvalue of a two-member result. */
static bool
pair_member(struct translator *t, LLVMValueRef inst, const struct value *pair)
{
   if (LLVMGetNumIndices(inst) != 1)
      return fail(t, STELA_AIR_INSTRUCTION, "nested pair indexing");
   unsigned index = LLVMGetIndices(inst)[0];
   if (index > 1 || !pair->members[index])
      return fail(t, STELA_AIR_INSTRUCTION, "pair member %u is not lowered", index);
   return put_value(t, inst, pair->members[index], 0);
}

/* AIR's relaxed atomics, as Apple's compiler names them:
 *
 *   air.atomic.<global|local>.load.<type>(pointer, order, scope, volatile)
 *   air.atomic.<global|local>.<store|xchg>.<type>(pointer, value, order, scope,
 *                                                 volatile)
 *   air.atomic.<global|local>.cmpxchg.weak.<type>(pointer, expected, desired,
 *                                                 success, failure, scope,
 *                                                 volatile)
 *   air.atomic.<global|local>.<add|sub|and|or|xor|min|max>.<sign><type>(
 *       pointer, value, order, scope, volatile)
 *
 * A floating-point type is bare ("f32"); an integer one carries its sign
 * ("s.i32") for arithmetic, which selects min and max. Orders are relaxed;
 * scopes need no lowering, as NIR's atomics are device-scope. A
 * compare-exchange returns the old value and writes it through expected, a
 * thread pointer. The 64-bit min and max return nothing. */
static bool
air_atomic_call(struct translator *t, LLVMValueRef inst, LLVMValueRef callee, const char *name,
                size_t length, bool *lowered)
{
   static const char *const spaces[] = {"air.atomic.global.", "air.atomic.local."};
   unsigned space = 0;
   while (space < ARRAY_SIZE(spaces) &&
          (length <= strlen(spaces[space]) || memcmp(name, spaces[space], strlen(spaces[space]))))
      space++;
   *lowered = space < ARRAY_SIZE(spaces);
   if (!*lowered)
      return true;
   enum form { LOAD, STORE, EXCHANGE, COMPARE, ARITHMETIC };
   /* Each form's name and value operands. */
   static const struct {
      const char *name;
      unsigned operands;
   } forms[] = {
      [LOAD] = {"load.", 1}, [STORE] = {"store.", 2}, [EXCHANGE] = {"xchg.", 2},
      [COMPARE] = {"cmpxchg.weak.", 3}, [ARITHMETIC] = {"", 2},
   };
   const char *operation = name + strlen(spaces[space]);
   size_t operation_length = length - strlen(spaces[space]);
   enum form form = ARITHMETIC;
   for (unsigned i = 0; i < ARITHMETIC; i++) {
      if (operation_length > strlen(forms[i].name) &&
          !memcmp(operation, forms[i].name, strlen(forms[i].name)))
         form = i;
   }
   /* Then the orders, a compare-exchange's success and failure, the scope
    * and the volatility. */
   unsigned operands = forms[form].operands, count = operands + (form == COMPARE ? 4 : 3);
   if (!LLVMIsAFunction(callee) || !LLVMIsDeclaration(callee) ||
       LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
       LLVMGetInstructionCallConv(inst) != LLVMCCallConv || LLVMGetNumArgOperands(inst) != count ||
       LLVMCountParams(callee) != count || LLVMIsFunctionVarArg(LLVMGlobalGetValueType(callee)) ||
       LLVMGetCalledFunctionType(inst) != LLVMGlobalGetValueType(callee) ||
       LLVMGetNumOperandBundles(inst))
      return fail(t, STELA_AIR_INSTRUCTION, "unsupported AIR atomic call signature");
   LLVMValueRef pointer = LLVMGetOperand(inst, 0);
   LLVMValueRef operand = form == LOAD ? NULL : LLVMGetOperand(inst, operands - 1);
   LLVMTypeRef type = operand ? LLVMTypeOf(operand) : LLVMTypeOf(inst);
   bool returns = LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMVoidTypeKind;
   bool typed = form == STORE ? !returns :
                form == ARITHMETIC ? !returns || LLVMTypeOf(inst) == type : LLVMTypeOf(inst) == type;
   if (LLVMGetTypeKind(LLVMTypeOf(pointer)) != LLVMPointerTypeKind ||
       LLVMGetPointerAddressSpace(LLVMTypeOf(pointer)) != (space ? 3u : 1u) || !typed)
      return fail(t, STELA_AIR_INSTRUCTION, "AIR atomic types disagree with its name");
   for (unsigned i = operands; i < count; i++) {
      LLVMValueRef value = LLVMGetOperand(inst, i);
      if (!LLVMIsAConstantInt(value) ||
          LLVMGetIntTypeWidth(LLVMTypeOf(value)) != (i == count - 1 ? 1u : 32u))
         return fail(t, STELA_AIR_INSTRUCTION, "AIR atomic order, scope and volatility must be constants");
      if (i < count - 2 && LLVMConstIntGetZExtValue(value))
         return fail(t, STELA_AIR_MEMORY, "only relaxed AIR atomics are supported");
   }
   char overload[16], expected[64];
   stela_air_call_overload(type, overload, sizeof(overload));
   bool floating = LLVMGetTypeKind(type) == LLVMFloatTypeKind;
   unsigned alignment = LLVMABIAlignmentOfType(t->layout, type);
   unsigned components, bits;
   if (form != ARITHMETIC) {
      snprintf(expected, sizeof(expected), "%s%s%s", spaces[space], forms[form].name, overload);
      if (!stela_air_call_named(name, length, expected))
         return fail(t, STELA_AIR_INSTRUCTION, "unsupported AIR atomic function");
      if (!value_shape(type, &components, &bits) || components != 1 ||
          (!floating && bits != 32 && bits != 64))
         return fail(t, STELA_AIR_TYPE, "unsupported atomic operand type");
   }
   switch (form) {
   case LOAD:
   case STORE: {
      const struct value *address = pointer_value(t, pointer);
      if (!address || !(address->access & (form == LOAD ? STELA_AIR_READ : STELA_AIR_WRITE)) ||
          thread_memory(address))
         return fail(t, STELA_AIR_MEMORY, "atomic access lacks a device or threadgroup pointer");
      nir_def *stored = operand ? get_value(t, operand) : NULL;
      if (operand && !stored)
         return false;
      /* Relaxed atomic loads and stores are single, coherent accesses. */
      nir_def *loaded = memory_access(t, address, stored, NULL, ACCESS_ATOMIC | ACCESS_COHERENT,
                                      1, bits, alignment);
      return form == STORE ? t->error->kind == STELA_AIR_OK : put_value(t, inst, loaded, 0);
   }
   case EXCHANGE:
      return atomic_access(t, inst, pointer, nir_atomic_op_xchg, false, operand, NULL, alignment);
   case COMPARE: {
      /* expected holds the value compared, and receives the old one. */
      const struct value *slot = pointer_value(t, LLVMGetOperand(inst, 1));
      if (!slot || !thread_memory(slot) ||
          (slot->access & STELA_AIR_READ_WRITE) != STELA_AIR_READ_WRITE)
         return fail(t, STELA_AIR_MEMORY, "compare-exchange expects a thread pointer");
      nir_def *compared = memory_access(t, slot, NULL, NULL, 0, 1, bits, alignment);
      nir_def *desired = compared ? get_value(t, operand) : NULL;
      if (!desired)
         return false;
      nir_def *old = atomic_old(t, pointer, nir_atomic_op_cmpxchg, false, type, desired, compared,
                                alignment);
      if (!old)
         return false;
      memory_access(t, slot, old, NULL, 0, 1, bits, alignment);
      return t->error->kind == STELA_AIR_OK && put_value(t, inst, old, 0);
   }
   case ARITHMETIC:
      break;
   }
   /* Float atomics add and subtract; the integer forms are unsigned, signed. */
   static const struct {
      const char *name;
      nir_atomic_op integer[2];
      bool floating, negate;
   } arithmetic[] = {
      {"add", {nir_atomic_op_iadd, nir_atomic_op_iadd}, true, false},
      {"sub", {nir_atomic_op_iadd, nir_atomic_op_iadd}, true, true},
      {"and", {nir_atomic_op_iand, nir_atomic_op_iand}, false, false},
      {"or", {nir_atomic_op_ior, nir_atomic_op_ior}, false, false},
      {"xor", {nir_atomic_op_ixor, nir_atomic_op_ixor}, false, false},
      {"min", {nir_atomic_op_umin, nir_atomic_op_imin}, false, false},
      {"max", {nir_atomic_op_umax, nir_atomic_op_imax}, false, false},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(arithmetic); i++) {
      if (floating && !arithmetic[i].floating)
         continue;
      for (unsigned sign = 0; sign < (floating ? 1u : 2u); sign++) {
         snprintf(expected, sizeof(expected), "%s%s.%s%s", spaces[space], arithmetic[i].name,
                  floating ? "" : sign ? "s." : "u.", overload);
         if (!stela_air_call_named(name, length, expected))
            continue;
         nir_atomic_op op = floating ? nir_atomic_op_fadd : arithmetic[i].integer[sign];
         if (returns)
            return atomic_access(t, inst, pointer, op, arithmetic[i].negate, operand, NULL, alignment);
         nir_def *data = get_value(t, operand);
         return data && atomic_old(t, pointer, op, arithmetic[i].negate, type, data, NULL, alignment);
      }
   }
   return fail(t, STELA_AIR_INSTRUCTION, "unsupported AIR atomic function");
}

/* AIR's barriers and fences, with memory flags 1 device, 2 threadgroup and 4
 * texture memory. A barrier is (flags, scope), as Apple's compiler emits, or
 * (flags, order, scope); a fence is (flags, order, scope). Orders are C++'s,
 * 0 relaxed and 5 sequentially consistent, which NIR's acquire-release
 * barrier implements as SPIR-V's does. Scopes are 1 threadgroup, 2 device and
 * 4 SIMD-group; a barrier takes its own: threadgroup_barrier the threadgroup,
 * simdgroup_barrier the SIMD-group. */
static bool
synchronization_call(struct translator *t, LLVMValueRef inst, LLVMValueRef callee,
                     const char *name, size_t length, bool *lowered)
{
   enum { THREADGROUP_BARRIER, SIMDGROUP_BARRIER, FENCE } kind;
   if (stela_air_call_named(name, length, "air.wg.barrier"))
      kind = THREADGROUP_BARRIER;
   else if (stela_air_call_named(name, length, "air.simdgroup.barrier"))
      kind = SIMDGROUP_BARRIER;
   else if (stela_air_call_named(name, length, "air.atomic.fence"))
      kind = FENCE;
   else
      return *lowered = false, true;
   *lowered = true;
   if (kind == THREADGROUP_BARRIER) {
      if (!compute_like(t))
         return fail(t, STELA_AIR_INSTRUCTION, "threadgroup barriers exist only in compute-like functions");
      if (!shared_profile(t))
         return false;
   }
   unsigned count = LLVMGetNumArgOperands(inst);
   unsigned convergent = LLVMGetEnumAttributeKindForName("convergent", strlen("convergent"));
   if ((kind == THREADGROUP_BARRIER && !t->options->max_threadgroup_bytes) ||
       !LLVMIsAFunction(callee) || !LLVMIsDeclaration(callee) ||
       LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
       LLVMGetInstructionCallConv(inst) != LLVMCCallConv ||
       (count != 3 && (kind == FENCE || count != 2)) || LLVMCountParams(callee) != count ||
       LLVMIsFunctionVarArg(LLVMGlobalGetValueType(callee)) ||
       LLVMGetCalledFunctionType(inst) != LLVMGlobalGetValueType(callee) ||
       LLVMGetNumOperandBundles(inst) || LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMVoidTypeKind ||
       (kind != FENCE && (!LLVMGetEnumAttributeAtIndex(callee, LLVMAttributeFunctionIndex, convergent) ||
                          !LLVMGetCallSiteEnumAttribute(inst, LLVMAttributeFunctionIndex, convergent))))
      return fail(t, STELA_AIR_INSTRUCTION, "unsupported/unconfigured barrier or fence signature");
   unsigned values[3];
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef operand = LLVMGetOperand(inst, i);
      if (!LLVMIsAConstantInt(operand) || LLVMGetIntTypeWidth(LLVMTypeOf(operand)) != 32)
         return fail(t, STELA_AIR_INSTRUCTION, "unsupported barrier or fence memory flags/order/scope");
      values[i] = LLVMConstIntGetZExtValue(operand);
   }
   unsigned flags = values[0], order = count == 3 ? values[1] : 5, scope = values[count - 1];
   if (flags & ~7u || (kind == FENCE ? order != 0 && order != 5 : order != 5) ||
       (kind == FENCE ? scope != 1 && scope != 2 && scope != 4 :
                        scope != (kind == THREADGROUP_BARRIER ? 1u : 4u)))
      return fail(t, STELA_AIR_INSTRUCTION, "unsupported barrier or fence memory flags/order/scope");
   nir_variable_mode modes = (flags & 1 ? nir_var_mem_ssbo | nir_var_mem_global : 0) |
                             (flags & 2 ? nir_var_mem_shared : 0) | (flags & 4 ? nir_var_image : 0);
   bool ordered = modes && order;
   mesa_scope execution = kind == THREADGROUP_BARRIER ? SCOPE_WORKGROUP :
                          kind == SIMDGROUP_BARRIER ? SCOPE_SUBGROUP : SCOPE_NONE;
   /* A relaxed fence orders nothing. */
   if (!ordered && execution == SCOPE_NONE)
      return true;
   nir_barrier(&t->b, .execution_scope = execution,
               .memory_scope = !ordered ? SCOPE_NONE : scope == 2 ? SCOPE_DEVICE :
                               scope == 4 ? SCOPE_SUBGROUP : SCOPE_WORKGROUP,
               .memory_semantics = ordered ? NIR_MEMORY_ACQ_REL : 0, .memory_modes = ordered ? modes : 0);
   t->shared_barriers++;
   return true;
}

enum { MEMORY_INTRINSIC_ACCESSES = 256 };

/* A call's alignment attribute on pointer argument `argument`, or 1. */
static unsigned
argument_alignment(LLVMValueRef call, unsigned argument)
{
   unsigned kind = LLVMGetEnumAttributeKindForName("align", strlen("align"));
   /* Attribute index 0 is the return value; arguments follow it. */
   LLVMAttributeRef attribute = LLVMGetCallSiteEnumAttribute(call, 1 + argument, kind);
   return attribute ? (unsigned)LLVMGetEnumAttributeValue(attribute) : 1;
}

/* LLVM's lifetime markers, and memset, memcpy and memmove of a constant
 * length, in chunks of the largest size the alignment allows, up to 16 bytes.
 * A copy loads every chunk before storing any, so overlap is handled too. */
static bool
memory_intrinsic(struct translator *t, LLVMValueRef inst, unsigned intrinsic, bool *lowered)
{
   enum { LIFETIME_START, LIFETIME_END, SET, COPY, MOVE };
   static const char *const names[] = {
      [LIFETIME_START] = "llvm.lifetime.start", [LIFETIME_END] = "llvm.lifetime.end",
      [SET] = "llvm.memset", [COPY] = "llvm.memcpy", [MOVE] = "llvm.memmove",
   };
   unsigned operation = ARRAY_SIZE(names);
   for (unsigned i = 0; intrinsic && i < ARRAY_SIZE(names); i++) {
      if (intrinsic == LLVMLookupIntrinsicID(names[i], strlen(names[i])))
         operation = i;
   }
   *lowered = operation < ARRAY_SIZE(names);
   /* Contents are undefined outside a lifetime, so the stored ones refine them. */
   if (!*lowered || operation <= LIFETIME_END)
      return true;
   LLVMValueRef length = LLVMGetOperand(inst, 2), is_volatile = LLVMGetOperand(inst, 3);
   if (!LLVMIsAConstantInt(length) || !LLVMIsAConstantInt(is_volatile) ||
       LLVMConstIntGetZExtValue(is_volatile) || LLVMGetNumOperandBundles(inst))
      return fail(t, STELA_AIR_MEMORY, "memory intrinsics take a constant length and no volatile");
   const struct value *destination = pointer_value(t, LLVMGetOperand(inst, 0));
   const struct value *source = operation == SET ? NULL : pointer_value(t, LLVMGetOperand(inst, 1));
   nir_def *fill = operation == SET ? get_value(t, LLVMGetOperand(inst, 1)) : NULL;
   if (t->error->kind != STELA_AIR_OK)
      return false;
   if (!destination || !(destination->access & STELA_AIR_WRITE) ||
       (operation != SET && (!source || !(source->access & STELA_AIR_READ))))
      return fail(t, STELA_AIR_MEMORY, "memory intrinsic lacks a bound writable/readable pointer");
   unsigned alignment = argument_alignment(inst, 0);
   if (source)
      alignment = MIN2(alignment, argument_alignment(inst, 1));
   uint64_t bytes = LLVMConstIntGetZExtValue(length);
   unsigned chunks[MEMORY_INTRINSIC_ACCESSES], count = 0;
   for (uint64_t offset = 0, size = MIN2(alignment, 16); offset < bytes; offset += size) {
      while (size > bytes - offset)
         size /= 2;
      if (count == ARRAY_SIZE(chunks))
         return fail(t, STELA_AIR_LIMIT, "memory intrinsic exceeds the access budget");
      chunks[count++] = size;
   }
   nir_def *values[MEMORY_INTRINSIC_ACCESSES];
   for (unsigned pass = 0; pass < 2; pass++) {
      uint64_t offset = 0;
      for (unsigned i = 0; i < count; offset += chunks[i++]) {
         unsigned components = chunks[i] >= 4 ? chunks[i] / 4 : 1;
         unsigned bits = chunks[i] >= 4 ? 32 : chunks[i] * 8;
         if (!pass && !source) {
            nir_def *pattern = nir_imul_imm(&t->b, nir_u2uN(&t->b, fill, bits),
                                            0x01010101u & BITFIELD_MASK(bits));
            values[i] = nir_replicate(&t->b, pattern, components);
            continue;
         }
         struct value at = pass ? *destination : *source;
         at.def = nir_iadd_imm(&t->b, at.def, offset);
         nir_def *loaded = memory_access(t, &at, pass ? values[i] : NULL, NULL, 0,
                                         components, bits, chunks[i]);
         if (t->error->kind != STELA_AIR_OK)
            return false;
         if (!pass)
            values[i] = loaded;
      }
   }
   return true;
}

/* The field of an argument buffer an element access at address reads: the
 * field whose elements the constant offset names, which dynamic indices
 * step through by whole elements. */
static const struct stela_air_field *
argument_field(struct translator *t, const struct value *address)
{
   if (!address->offset_known) {
      fail(t, STELA_AIR_MEMORY, "argument buffer field access through a pointer PHI");
      return NULL;
   }
   for (unsigned i = 0; i < address->fields.count; i++) {
      const struct stela_air_field *field = &t->fields[address->fields.first + i];
      if (address->offset < field->offset || address->offset - field->offset >= field->size)
         continue;
      unsigned element = field->size / field->count;
      if ((address->offset - field->offset) % element || address->steps % element ||
          (address->steps && field->count == 1))
         break;
      return field;
   }
   fail(t, STELA_AIR_MEMORY, "pointer load names no argument buffer element");
   return NULL;
}

/* A resource ID's value, which names its texture or sampler for texture
 * calls. */
static bool
put_id(struct translator *t, LLVMValueRef inst, const struct stela_air_texture *texture,
       const struct stela_air_sampler *sampler, nir_def *id)
{
   struct value *value = rzalloc(t->values, struct value);
   if (!value || !_mesa_hash_table_insert(t->values, inst, value))
      return fail(t, STELA_AIR_ALLOCATION, "AIR resource value allocation failed");
   value->texture = texture;
   value->sampler = sampler;
   value->id = id;
   return true;
}

/* A load of a texture or sampler array's handle: the resource ID of the
 * element its offset selects. */
static bool
array_load(struct translator *t, LLVMValueRef inst, const struct value *address)
{
   unsigned space = address->texture ? 1 : 2;
   LLVMTypeRef type = LLVMTypeOf(inst);
   if (LLVMGetPointerAddressSpace(type) != space || LLVMPointerSizeForAS(t->layout, space) != 8 ||
       LLVMGetVolatile(inst) || LLVMGetOrdering(inst) != LLVMAtomicOrderingNotAtomic)
      return fail(t, STELA_AIR_TYPE, "load differs from its texture or sampler array's handles");
   if (!address->offset_known || address->offset % 8 || address->steps % 8)
      return fail(t, STELA_AIR_MEMORY, "texture or sampler array load names no handle");
   nir_def *element = nir_ushr_imm(&t->b, address->def, 3);
   nir_def *id = t->options->resource_id(&t->b, address->texture, address->sampler, element,
                                         t->options->binding_data);
   if (!id || id->num_components != 1 || id->bit_size != 64)
      return fail(t, STELA_AIR_ARGUMENT, "resource ID callback refused a texture or sampler array");
   return put_id(t, inst, address->texture, address->sampler, id);
}

/* The address space of the pointer a load of field yields, zero for inline
 * data. */
static unsigned
field_space(const struct stela_air_field *field)
{
   switch (field->kind) {
   case STELA_AIR_FIELD_DATA:
      return 0;
   case STELA_AIR_FIELD_BUFFER:
   case STELA_AIR_FIELD_ARGUMENTS:
      return field->buffer.address_space;
   case STELA_AIR_FIELD_SAMPLER:
      return 2;
   case STELA_AIR_FIELD_TEXTURE:
   case STELA_AIR_FIELD_COMMANDS:
   case STELA_AIR_FIELD_RENDER_PIPELINE:
   case STELA_AIR_FIELD_COMPUTE_PIPELINE:
      return 1;
   }
   return 0;
}

/* A load of an address or resource ID from an argument buffer, or of a
 * texture or sampler array's handle. An address roots the pointers derived
 * from it, with its field's access; an ID names its texture or sampler for
 * texture calls, or its command buffer or pipeline state for command calls. */
static bool
argument_load(struct translator *t, LLVMValueRef inst)
{
   const struct value *address = pointer_value(t, LLVMGetOperand(inst, 0));
   if (address && address->array)
      return array_load(t, inst, address);
   if (!address || !address->fields.count || !(address->access & STELA_AIR_READ) ||
       LLVMGetVolatile(inst) || LLVMGetOrdering(inst) != LLVMAtomicOrderingNotAtomic ||
       !LLVMGetAlignment(inst))
      return fail(t, STELA_AIR_MEMORY, "pointer loads read argument buffers");
   const struct stela_air_field *field = argument_field(t, address);
   if (!field)
      return false;
   LLVMTypeRef type = LLVMTypeOf(inst);
   unsigned space = LLVMGetPointerAddressSpace(type);
   unsigned expected = field_space(field);
   if (!expected || space != expected || LLVMPointerSizeForAS(t->layout, space) != 8)
      return fail(t, STELA_AIR_TYPE, "pointer load differs from its argument buffer field");
   nir_def *loaded = memory_access(t, address, NULL, NULL, 0, 1, 64, LLVMGetAlignment(inst));
   if (!loaded)
      return false;
   switch (field->kind) {
   case STELA_AIR_FIELD_TEXTURE:
      return put_id(t, inst, &field->texture, NULL, loaded);
   case STELA_AIR_FIELD_SAMPLER:
      return put_id(t, inst, NULL, &field->sampler, loaded);
   case STELA_AIR_FIELD_COMMANDS:
   case STELA_AIR_FIELD_RENDER_PIPELINE:
   case STELA_AIR_FIELD_COMPUTE_PIPELINE:
      if (!put_id(t, inst, NULL, NULL, loaded))
         return false;
      find_value(t, inst)->object = field;
      return true;
   default:
      break;
   }
   if (!put_value(t, inst, loaded, field->buffer.access))
      return false;
   struct value *value = find_value(t, inst);
   value->pointer_root = inst;
   value->fields = field->arguments;
   value->offset_known = true;
   return true;
}

/* Object and mesh functions' setters of their mesh grid properties and
 * mesh, in DXMT's AIR forms: the handle, then indices, then the value. */
enum mesh_setter {
   MESH_POSITION, MESH_POINT_SIZE, MESH_CLIP_DISTANCE, MESH_VERTEX_DATA, MESH_PRIMITIVE_DATA,
   MESH_LAYER, MESH_VIEWPORT, MESH_PRIMITIVE_ID, MESH_INDEX, MESH_PRIMITIVE_COUNT, MESH_GRID,
};

static const struct {
   const char *stem;
   unsigned operands; /* Including the handle. */
   bool overload; /* The name ends with the value's overload. */
   enum stela_air_stage_semantic semantic; /* The output it sets, if any. */
} mesh_setters[] = {
   [MESH_POSITION] = {"air.set_position_mesh", 3, false, STELA_AIR_POSITION},
   [MESH_POINT_SIZE] = {"air.set_point_size_mesh", 3, false, STELA_AIR_POINT_SIZE},
   [MESH_CLIP_DISTANCE] = {"air.set_clip_distance_mesh", 4, false, STELA_AIR_CLIP_DISTANCE},
   [MESH_VERTEX_DATA] = {"air.set_vertex_data_mesh", 4, true, STELA_AIR_VARYING},
   [MESH_PRIMITIVE_DATA] = {"air.set_primitive_data_mesh", 4, true, STELA_AIR_VARYING},
   [MESH_LAYER] = {"air.set_render_target_array_index_mesh", 3, true, STELA_AIR_LAYER},
   [MESH_VIEWPORT] = {"air.set_viewport_array_index_mesh", 3, true, STELA_AIR_VIEWPORT},
   [MESH_PRIMITIVE_ID] = {"air.set_primitive_id_mesh", 3, false, STELA_AIR_MESH_PRIMITIVE_ID},
   [MESH_INDEX] = {"air.set_index_mesh", 3},
   [MESH_PRIMITIVE_COUNT] = {"air.set_primitive_count_mesh", 2},
   [MESH_GRID] = {"air.set_threadgroups_per_grid_mesh_properties", 2},
};

/* The setter a call names, or UINT_MAX. */
static unsigned
mesh_setter(LLVMValueRef inst, const char *name, size_t length)
{
   unsigned operands = LLVMGetNumArgOperands(inst);
   for (unsigned s = 0; s < ARRAY_SIZE(mesh_setters); s++) {
      char expected[96];
      size_t stem = strlen(mesh_setters[s].stem);
      memcpy(expected, mesh_setters[s].stem, stem + 1);
      if (mesh_setters[s].overload && operands) {
         expected[stem] = '.';
         stela_air_call_overload(LLVMTypeOf(LLVMGetOperand(inst, operands - 1)), expected + stem + 1,
                                 sizeof(expected) - stem - 1);
      }
      if (stela_air_call_named(name, length, expected))
         return s;
   }
   return UINT_MAX;
}

/* The output a setter sets; mesh data by its constant data index. */
static unsigned
mesh_output(struct translator *t, enum mesh_setter setter, LLVMValueRef data)
{
   const struct stela_air_stage_entry *entry = &t->render.entry;
   for (unsigned i = 0; i < entry->output_count; i++) {
      const struct stela_air_stage_io *io = &t->render.outputs[i];
      if (io->semantic != mesh_setters[setter].semantic)
         continue;
      if (io->semantic != STELA_AIR_VARYING ||
          (io->per_primitive == (setter == MESH_PRIMITIVE_DATA) && LLVMIsAConstantInt(data) &&
           LLVMConstIntGetZExtValue(data) == io->index))
         return i;
   }
   return UINT_MAX;
}

/* Stores value to element (below count), and below `inner` its index, of
 * an arrayed output, or the components `mask` names of the element; out of
 * range, the store is discarded. */
static bool
mesh_store(struct translator *t, nir_variable *var, nir_def *element, unsigned count,
           nir_def *index, unsigned inner, nir_def *value, unsigned mask)
{
   nir_builder *b = &t->b;
   nir_def *inside = nir_ult_imm(b, element, count);
   if (index)
      inside = nir_iand(b, inside, nir_ult_imm(b, index, inner));
   struct memory_guard guard;
   if (!memory_guard_begin(t, inside, &guard))
      return false;
   nir_deref_instr *deref = nir_build_deref_array(b, nir_build_deref_var(b, var), element);
   if (index)
      deref = nir_build_deref_array(b, deref, index);
   nir_store_deref(b, deref, value, mask);
   memory_guard_end(t, &guard, NULL);
   return true;
}

/* Metal's flat index list: index i is corner i % n of primitive i / n. */
static bool
mesh_index(struct translator *t, nir_def *index, nir_def *vertex)
{
   nir_builder *b = &t->b;
   unsigned corners = mesa_vertices_per_prim(t->b.shader->info.mesh.primitive_type);
   nir_def *primitive = nir_udiv_imm(b, index, corners);
   nir_def *corner = nir_umod_imm(b, index, corners);
   nir_def *value = nir_replicate(b, nir_u2u32(b, vertex), corners);
   for (unsigned c = 0; c < corners; c++) {
      /* Only the matching corner's guard passes. */
      nir_def *element = nir_bcsel(b, nir_ieq_imm(b, corner, c), primitive,
                                   nir_imm_int(b, t->render.entry.max_primitives));
      if (!mesh_store(t, t->indices, element, t->render.entry.max_primitives, NULL, 0, value,
                      1u << c))
         return false;
   }
   return true;
}

/* A call of an object or mesh setter; false with no error when the call is
 * something else. */
static bool
mesh_call(struct translator *t, LLVMValueRef inst, LLVMValueRef callee, const char *name,
          size_t length, bool *lowered)
{
   unsigned setter = mesh_setter(inst, name, length);
   *lowered = setter != UINT_MAX;
   if (!*lowered)
      return true;
   LLVMValueRef handle = setter == MESH_GRID ? t->mesh_grid : t->mesh;
   unsigned operands = mesh_setters[setter].operands;
   if (!handle || !LLVMIsAFunction(callee) || !LLVMIsDeclaration(callee) ||
       LLVMGetNumArgOperands(inst) != operands || LLVMGetOperand(inst, 0) != handle ||
       LLVMGetCalledFunctionType(inst) != LLVMGlobalGetValueType(callee) ||
       LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMVoidTypeKind)
      return fail(t, STELA_AIR_INSTRUCTION, "mesh setter without its function's mesh or grid");
   nir_def *values[4] = {NULL};
   for (unsigned i = 1; i < operands; i++) {
      if (!(values[i] = get_value(t, LLVMGetOperand(inst, i))))
         return false;
   }
   nir_builder *b = &t->b;
   nir_def *value = values[operands - 1];
   for (unsigned i = 1; i + 1 < operands; i++) {
      if (values[i]->num_components != 1 || values[i]->bit_size != 32)
         return fail(t, STELA_AIR_TYPE, "mesh setter indices are 32-bit integers");
   }
   switch (setter) {
   case MESH_GRID: {
      if (value->num_components != 3 || value->bit_size != 32)
         return fail(t, STELA_AIR_TYPE, "a mesh grid is three 32-bit integers");
      nir_deref_instr *state = nir_build_deref_var(b, t->mesh_state);
      for (unsigned i = 0; i < 3; i++)
         nir_store_deref(b, nir_build_deref_array_imm(b, state, i), nir_channel(b, value, i), 1);
      return true;
   }
   case MESH_PRIMITIVE_COUNT:
      if (value->num_components != 1 || value->bit_size != 32)
         return fail(t, STELA_AIR_TYPE, "a primitive count is a 32-bit integer");
      nir_store_deref(b, nir_build_deref_array_imm(b, nir_build_deref_var(b, t->mesh_state), 0),
                      value, 1);
      return true;
   case MESH_INDEX:
      if (value->num_components != 1 || value->bit_size != 8)
         return fail(t, STELA_AIR_TYPE, "a mesh index is an 8-bit vertex");
      return mesh_index(t, values[1], value);
   default:
      break;
   }
   bool data = setter == MESH_VERTEX_DATA || setter == MESH_PRIMITIVE_DATA;
   unsigned output = mesh_output(t, setter, data ? LLVMGetOperand(inst, 1) : NULL);
   if (output == UINT_MAX)
      return fail(t, STELA_AIR_INSTRUCTION, "mesh setter of an output the mesh lacks");
   const struct stela_air_stage_io *io = &t->render.outputs[output];
   if (!stela_air_metadata_output_type(io, LLVMTypeOf(LLVMGetOperand(inst, operands - 1))))
      return fail(t, STELA_AIR_TYPE, "mesh setter value differs from its output");
   const struct stela_air_stage_entry *entry = &t->render.entry;
   unsigned count = io->per_primitive ? entry->max_primitives : entry->max_vertices;
   bool clip = setter == MESH_CLIP_DISTANCE;
   nir_def *element = values[clip || data ? 2 : 1];
   value = stage_widen(b, value, io->primitive);
   return mesh_store(t, t->outputs[output], element, count, clip ? values[1] : NULL,
                     io->clip_distances, value, BITFIELD_MASK(value->num_components));
}

static bool
instruction(struct translator *t, LLVMValueRef inst)
{
   LLVMOpcode op = LLVMGetInstructionOpcode(inst);
   t->b.fp_math_ctrl = fp_math_control(inst);
   unsigned components = 0, bits = 0;
   if (op == LLVMRet)
      return !compute_like(t) ? stage_return(t, inst) : LLVMGetNumOperands(inst) == 0 || fail(t, STELA_AIR_TYPE, "compute kernel return value");
   if (op == LLVMExtractValue) {
      const struct value *pair = find_value(t, LLVMGetOperand(inst, 0));
      if (pair && pair->members[0])
         return pair_member(t, inst, pair);
   }
   if (op == LLVMAtomicRMW || op == LLVMAtomicCmpXchg)
      return atomic_instruction(t, inst, op);
   if (op == LLVMAlloca)
      return private_allocation(t, inst) != NULL;
   if (op == LLVMLoad && LLVMGetTypeKind(LLVMTypeOf(inst)) == LLVMPointerTypeKind)
      return argument_load(t, inst);
   if (t->stage_options && (op == LLVMInsertValue || op == LLVMExtractValue))
      return aggregate_instruction(t, inst, op);
   if (op == LLVMShuffleVector || op == LLVMExtractElement || op == LLVMInsertElement)
      return vector_instruction(t, inst, op);
   if (op != LLVMStore && op != LLVMGetElementPtr && op != LLVMBitCast && op != LLVMCall &&
       !value_shape(LLVMTypeOf(inst), &components, &bits))
      return fail(t, STELA_AIR_TYPE, "unsupported AIR instruction result type (opcode %u)", op);
   if (op == LLVMGetElementPtr) {
      const struct value *origin;
      uint64_t constant, steps;
      nir_def *def = gep(t, inst, &origin, &constant, &steps);
      if (!def || !put_value(t, inst, def, origin->access))
         return false;
      pointer_authority(find_value(t, inst), origin);
      pointer_offset(find_value(t, inst), origin, constant, steps);
      return true;
   }
   if (op == LLVMBitCast) {
      unsigned src_components, src_bits;
      LLVMTypeRef source = LLVMTypeOf(LLVMGetOperand(inst, 0));
      if (pointer_space(source) && LLVMTypeOf(inst) == source) {
         const struct value *origin = pointer_value(t, LLVMGetOperand(inst, 0));
         if (!origin || !origin->access || !put_value(t, inst, origin->def, origin->access))
            return fail(t, STELA_AIR_MEMORY, "pointer identity cast lacks buffer provenance");
         pointer_authority(find_value(t, inst), origin);
         pointer_offset(find_value(t, inst), origin, 0, 0);
         return true;
      }
      if (!value_shape(source, &src_components, &src_bits) ||
          !value_shape(LLVMTypeOf(inst), &components, &bits) || src_bits == 1 || bits == 1 ||
          src_components * src_bits != components * bits)
         return fail(t, STELA_AIR_TYPE, "bitcast between unsupported or differently sized types");
      nir_def *value = get_value(t, LLVMGetOperand(inst, 0));
      return value && put_value(t, inst, nir_bitcast_vector(&t->b, value, bits), 0);
   }
   if (op == LLVMCall) {
      LLVMValueRef callee = LLVMGetCalledValue(inst);
      /* Inlining leaves no call of a defined function, and dispatch only
       * calls through other pointers than a table's. */
      if (stela_air_defined_function(callee))
         return fail(t, STELA_AIR_INSTRUCTION, "a function call was not inlined");
      if (!LLVMIsAFunction(callee))
         return fail(t, STELA_AIR_INSTRUCTION, "function pointers come only from visible function tables");
      if (LLVMIsAFunction(callee)) {
         bool lowered;
         if (!memory_intrinsic(t, inst, LLVMGetIntrinsicID(callee), &lowered))
            return false;
         if (lowered)
            return true;
      }
      if (LLVMIsAFunction(callee)) {
         unsigned intrinsic = LLVMGetIntrinsicID(callee);
         static const char *const counts[] = {
            [INTEGER_COUNT_POPULATION] = "llvm.ctpop",
            [INTEGER_COUNT_LEADING_ZEROS] = "llvm.ctlz",
            [INTEGER_COUNT_TRAILING_ZEROS] = "llvm.cttz",
         };
         for (unsigned operation = 0; intrinsic && operation < ARRAY_SIZE(counts); operation++) {
            unsigned expected = LLVMLookupIntrinsicID(counts[operation], strlen(counts[operation]));
            if (expected && intrinsic == expected)
               return integer_count(t, inst, callee, intrinsic, (enum integer_count_operation)operation);
         }
      }
      if (LLVMIsAFunction(callee)) {
         unsigned intrinsic = LLVMGetIntrinsicID(callee);
         static const char *const permutations[] = {
            [INTEGER_REVERSE_BITS] = "llvm.bitreverse",
            [INTEGER_SWAP_BYTES] = "llvm.bswap",
         };
         for (unsigned operation = 0; intrinsic && operation < ARRAY_SIZE(permutations); operation++) {
            unsigned expected = LLVMLookupIntrinsicID(permutations[operation], strlen(permutations[operation]));
            if (expected && intrinsic == expected)
               return integer_permutation(t, inst, callee, intrinsic, (enum integer_permutation_operation)operation);
         }
      }
      if (LLVMIsAFunction(callee)) {
         unsigned intrinsic = LLVMGetIntrinsicID(callee);
         static const char *const minmax[] = {
            [INTEGER_SIGNED_MINIMUM] = "llvm.smin",
            [INTEGER_SIGNED_MAXIMUM] = "llvm.smax",
            [INTEGER_UNSIGNED_MINIMUM] = "llvm.umin",
            [INTEGER_UNSIGNED_MAXIMUM] = "llvm.umax",
         };
         for (unsigned operation = 0; intrinsic && operation < ARRAY_SIZE(minmax); operation++) {
            unsigned expected = LLVMLookupIntrinsicID(minmax[operation], strlen(minmax[operation]));
            if (expected && intrinsic == expected)
               return integer_minmax(t, inst, callee, intrinsic, (enum integer_minmax_operation)operation);
         }
      }
      if (LLVMIsAFunction(callee)) {
         unsigned intrinsic = LLVMGetIntrinsicID(callee);
         static const char *const funnels[] = {
            [INTEGER_FUNNEL_LEFT] = "llvm.fshl",
            [INTEGER_FUNNEL_RIGHT] = "llvm.fshr",
         };
         for (unsigned operation = 0; intrinsic && operation < ARRAY_SIZE(funnels); operation++) {
            unsigned expected = LLVMLookupIntrinsicID(funnels[operation], strlen(funnels[operation]));
            if (expected && intrinsic == expected)
               return integer_funnel(t, inst, callee, intrinsic, (enum integer_funnel_operation)operation);
         }
      }
      size_t name_length = 0;
      const char *name = LLVMGetValueName2(callee, &name_length);
      bool lowered;
      if (!control_point_call(t, inst, callee, &lowered))
         return false;
      if (lowered)
         return true;
      if (!interpolant_call(t, inst, name, name_length, &lowered))
         return false;
      if (lowered)
         return true;
      if (!texture_call(t, inst, name, name_length, &lowered))
         return false;
      if (lowered)
         return true;
      if (!mesh_call(t, inst, callee, name, name_length, &lowered))
         return false;
      if (lowered)
         return true;
      if (!synchronization_call(t, inst, callee, name, name_length, &lowered))
         return false;
      if (lowered)
         return true;
      if (!air_atomic_call(t, inst, callee, name, name_length, &lowered))
         return false;
      if (lowered)
         return true;
      if (!command_call(t, inst, callee, name, name_length, &lowered))
         return false;
      if (lowered)
         return true;
      nir_def *math;
      const struct stela_air_call_context math_context = {
         .b = &t->b, .error = t->error, .translator = t,
         .fragment = t->stage_options && t->stage_options->stage == STELA_AIR_FRAGMENT,
         .operand = texture_operand, .fp_environment = math_environment, .store = math_store,
      };
      switch (stela_air_simd_call(&math_context, inst, callee, name, name_length, &math)) {
      case STELA_AIR_CALL_OTHER:
         break;
      case STELA_AIR_CALL_FAILED:
         return false;
      case STELA_AIR_CALL_LOWERED:
         return put_value(t, inst, math, 0);
      }
      switch (stela_air_math_call(&math_context, inst, callee, name, name_length, &math)) {
      case STELA_AIR_CALL_OTHER:
         if (!LLVMGetIntrinsicID(callee) && (name_length < 4 || memcmp(name, "air.", 4)))
            return fail(t, STELA_AIR_INSTRUCTION, "unresolved external function %.*s",
                        (int)MIN2(name_length, 160), name);
         return fail(t, STELA_AIR_INSTRUCTION, "unsupported AIR call %.*s",
                     (int)MIN2(name_length, 160), name);
      case STELA_AIR_CALL_FAILED:
         return false;
      case STELA_AIR_CALL_LOWERED:
         break;
      }
      return !math || put_value(t, inst, math, 0);
   }
   if (op == LLVMFNeg) {
      nir_def *value = get_value(t, LLVMGetOperand(inst, 0));
      /* LLVM fneg changes only the sign bit, even for NaNs/subnormals. Do not
       * route this through a target arithmetic negate that can canonicalize. */
      return value && put_value(t, inst, nir_ixor(&t->b, value,
         nir_imm_intN_t(&t->b, 1ull << (value->bit_size - 1), value->bit_size)), 0);
   }
   if (op == LLVMFPExt || op == LLVMFPTrunc || op == LLVMFPToSI || op == LLVMFPToUI ||
       op == LLVMSIToFP || op == LLVMUIToFP)
      return fp_conversion(t, inst, op);
   /* NIR divides at Vulkan's 2.5 ULP, which only fast math permits. */
   if ((op == LLVMFDiv || op == LLVMFRem) && LLVMGetFastMathFlags(inst) != LLVMFastMathAll)
      return fail(t, STELA_AIR_INSTRUCTION, "precise/partially relaxed FP division is unqualified");
   if (op == LLVMFAdd || op == LLVMFSub || op == LLVMFMul || op == LLVMFDiv || op == LLVMFRem ||
       op == LLVMFCmp) {
      if (!fp_environment(t))
         return false;
      nir_def *a = get_value(t, LLVMGetOperand(inst, 0));
      if (!a)
         return false;
      nir_def *b = get_value(t, LLVMGetOperand(inst, 1));
      if (!b || !float_shape(LLVMTypeOf(LLVMGetOperand(inst, 0)), &components, &bits))
         return fail(t, STELA_AIR_TYPE, "only half and float arithmetic/comparison supported");
      nir_def *value = NULL;
      if (op == LLVMFAdd)
         value = nir_fadd(&t->b, a, b);
      else if (op == LLVMFSub)
         value = nir_fsub(&t->b, a, b);
      else if (op == LLVMFMul)
         value = nir_fmul(&t->b, a, b);
      else if (op == LLVMFDiv)
         value = nir_fdiv(&t->b, a, b);
      /* LLVM's frem is C's fmod. */
      else if (op == LLVMFRem)
         value = nir_frem(&t->b, a, b);
      else {
         const nir_shader_compiler_options *options = t->b.shader->options;
         /* Match the original frontend/NIR option contract. Some backends
          * lower only canonical comparisons before converting bool widths.
          * These NaN-correct recipes come from the original SPIR-V frontend
          * and NIR algebraic rules; NIR can fuse them when permitted. */
         switch (LLVMGetFCmpPredicate(inst)) {
         case LLVMRealPredicateFalse: value = nir_imm_zero(&t->b, components, 1); break;
         case LLVMRealPredicateTrue: value = nir_inot(&t->b, nir_imm_zero(&t->b, components, 1)); break;
         case LLVMRealOEQ: value = nir_feq(&t->b, a, b); break;
         case LLVMRealOGT: value = nir_flt(&t->b, b, a); break;
         case LLVMRealOGE: value = nir_fge(&t->b, a, b); break;
         case LLVMRealOLT: value = nir_flt(&t->b, a, b); break;
         case LLVMRealOLE: value = nir_fge(&t->b, b, a); break;
         case LLVMRealONE:
            value = options->has_fneo_fcmpu ? nir_fneo(&t->b, a, b) :
               nir_ior(&t->b, nir_flt(&t->b, a, b), nir_flt(&t->b, b, a));
            break;
         case LLVMRealORD:
            value = options->has_ford_funord ? nir_ford(&t->b, a, b) :
               nir_iand(&t->b, nir_feq(&t->b, a, a), nir_feq(&t->b, b, b));
            break;
         case LLVMRealUNO:
            value = options->has_ford_funord ? nir_funord(&t->b, a, b) :
               nir_ior(&t->b, nir_fneu(&t->b, a, a), nir_fneu(&t->b, b, b));
            break;
         case LLVMRealUEQ:
            value = options->has_fneo_fcmpu ? nir_fequ(&t->b, a, b) :
               nir_ior(&t->b, nir_feq(&t->b, a, b),
                       nir_ior(&t->b, nir_fneu(&t->b, a, a), nir_fneu(&t->b, b, b)));
            break;
         case LLVMRealUGT:
            value = options->has_fneo_fcmpu ? nir_fltu(&t->b, b, a) : nir_inot(&t->b, nir_fge(&t->b, b, a));
            break;
         case LLVMRealUGE:
            value = options->has_fneo_fcmpu ? nir_fgeu(&t->b, a, b) : nir_inot(&t->b, nir_flt(&t->b, a, b));
            break;
         case LLVMRealULT:
            value = options->has_fneo_fcmpu ? nir_fltu(&t->b, a, b) : nir_inot(&t->b, nir_fge(&t->b, a, b));
            break;
         case LLVMRealULE:
            value = options->has_fneo_fcmpu ? nir_fgeu(&t->b, b, a) : nir_inot(&t->b, nir_flt(&t->b, b, a));
            break;
         case LLVMRealUNE: value = nir_fneu(&t->b, a, b); break;
         default: return fail(t, STELA_AIR_INSTRUCTION, "unknown floating comparison");
         }
      }
      return put_value(t, inst, value, 0);
   }
   if (bits == 1 && (op == LLVMAdd || op == LLVMSub || op == LLVMMul ||
                    op == LLVMUDiv || op == LLVMSDiv || op == LLVMURem || op == LLVMSRem ||
                    op == LLVMShl || op == LLVMLShr || op == LLVMAShr))
      return fail(t, STELA_AIR_TYPE, "one-bit arithmetic/division/remainder/shift unsupported");
   if (op == LLVMICmp && LLVMGetTypeKind(LLVMTypeOf(LLVMGetOperand(inst, 0))) == LLVMPointerTypeKind) {
      LLVMIntPredicate predicate = LLVMGetICmpPredicate(inst);
      if (predicate != LLVMIntEQ && predicate != LLVMIntNE)
         return fail(t, STELA_AIR_TYPE, "pointer relational comparison unsupported");
      const struct value *a = pointer_value(t, LLVMGetOperand(inst, 0));
      const struct value *b = a ? pointer_value(t, LLVMGetOperand(inst, 1)) : NULL;
      if (t->error->kind != STELA_AIR_OK)
         return false;
      if (!same_pointer_resource(a, b) || !a->def || !b->def ||
          a->def->num_components != 1 || b->def->num_components != 1 ||
          a->def->bit_size != 64 || b->def->bit_size != 64)
         return fail(t, STELA_AIR_MEMORY, "pointer equality requires one validated resource origin");
      /* Equality is invariant under the same unknown base modulo 2^64. */
      return put_value(t, inst, predicate == LLVMIntEQ ?
         nir_ieq(&t->b, a->def, b->def) : nir_ine(&t->b, a->def, b->def), 0);
   }
   if (op == LLVMLoad || op == LLVMStore) {
      struct value *address = pointer_value(t, LLVMGetOperand(inst, op == LLVMStore ? 1 : 0));
      unsigned required = op == LLVMStore ? STELA_AIR_WRITE : STELA_AIR_READ;
      LLVMAtomicOrdering ordering = LLVMGetOrdering(inst);
      bool atomic = ordering != LLVMAtomicOrderingNotAtomic;
      if (!address || !(address->access & required) || LLVMGetVolatile(inst) ||
          (atomic && ordering != LLVMAtomicOrderingUnordered && ordering != LLVMAtomicOrderingMonotonic))
         return fail(t, STELA_AIR_MEMORY, "unsupported volatile/ordered/unbound/disallowed memory access");
      if (atomic && (thread_memory(address) || address->constant_data))
         return fail(t, STELA_AIR_MEMORY, "atomic access to thread memory or constant data");
      if (op == LLVMStore && !value_shape(LLVMTypeOf(LLVMGetOperand(inst, 0)), &components, &bits))
         return fail(t, STELA_AIR_TYPE, "unsupported store type");
      if (bits == 1)
         return fail(t, STELA_AIR_MEMORY, "sub-byte memory access unsupported");
      if (atomic && (components != 1 || (bits != 32 && bits != 64) || LLVMGetAlignment(inst) < bits / 8))
         return fail(t, STELA_AIR_MEMORY, "relaxed atomic loads and stores take aligned 32- or 64-bit scalars");
      /* Relaxed atomic loads and stores are single, coherent accesses. */
      enum gl_access_qualifier access = atomic ? ACCESS_ATOMIC | ACCESS_COHERENT : 0;
      unsigned alignment = LLVMGetAlignment(inst);
      if (!alignment)
         return fail(t, STELA_AIR_MEMORY, "memory access lacks explicit alignment");
      if (op == LLVMStore) {
         nir_def *value = get_value(t, LLVMGetOperand(inst, 0));
         if (!value)
            return false;
         memory_access(t, address, value, NULL, access, components, bits, alignment);
         return t->error->kind == STELA_AIR_OK;
      }
      return put_value(t, inst, memory_access(t, address, NULL, NULL, access, components, bits,
                                              alignment), 0);
   }
   /* The remaining arithmetic is integer-only. Flags restricting defined
    * LLVM inputs (nuw/nsw/exact) need no extra NIR operation on those inputs;
    * direct poison/undef, freeze and all remaining opcodes are refused. LLVM
    * divisor-zero and signed MIN/-1 (including srem) inputs are undefined;
    * no result or trap contract is invented for those cases. */
   nir_def *a = NULL, *b = NULL, *def = NULL;
   switch (op) {
   case LLVMAdd: case LLVMSub: case LLVMMul:
   case LLVMUDiv: case LLVMSDiv: case LLVMURem: case LLVMSRem:
   case LLVMAnd: case LLVMOr: case LLVMXor:
   case LLVMShl: case LLVMLShr: case LLVMAShr: case LLVMICmp:
   case LLVMTrunc: case LLVMZExt: case LLVMSExt:
   case LLVMSelect:
      a = get_value(t, LLVMGetOperand(inst, 0));
      if (!a)
         return false;
      break;
   default:
      return fail(t, STELA_AIR_INSTRUCTION, "unsupported AIR opcode %u", op);
   }
   if (op == LLVMTrunc && bits == 1)
      def = nir_ine_imm(&t->b, nir_iand_imm(&t->b, a, 1), 0);
   else if (op == LLVMZExt && a->bit_size == 1)
      def = nir_b2iN(&t->b, a, bits);
   else if (op == LLVMSExt && a->bit_size == 1)
      def = nir_ineg(&t->b, nir_b2iN(&t->b, a, bits));
   else if (op == LLVMTrunc || op == LLVMZExt)
      def = nir_u2uN(&t->b, a, bits);
   else if (op == LLVMSExt)
      def = nir_i2iN(&t->b, a, bits);
   else {
      b = get_value(t, LLVMGetOperand(inst, 1));
      if (!b)
         return false;
      switch (op) {
      case LLVMAdd: def = nir_iadd(&t->b, a, b); break;
      case LLVMSub: def = nir_isub(&t->b, a, b); break;
      case LLVMMul: def = nir_imul(&t->b, a, b); break;
      case LLVMUDiv: def = nir_udiv(&t->b, a, b); break;
      case LLVMSDiv: def = nir_idiv(&t->b, a, b); break;
      case LLVMURem: def = nir_umod(&t->b, a, b); break;
      case LLVMSRem: def = nir_irem(&t->b, a, b); break;
      case LLVMAnd: def = nir_iand(&t->b, a, b); break;
      case LLVMOr: def = nir_ior(&t->b, a, b); break;
      case LLVMXor: def = nir_ixor(&t->b, a, b); break;
      case LLVMShl: def = nir_ishl(&t->b, a, nir_u2u32(&t->b, b)); break;
      case LLVMLShr: def = nir_ushr(&t->b, a, nir_u2u32(&t->b, b)); break;
      case LLVMAShr: def = nir_ishr(&t->b, a, nir_u2u32(&t->b, b)); break;
      case LLVMICmp: def = compare(t, inst, a, b); break;
      case LLVMSelect: {
         nir_def *c = get_value(t, LLVMGetOperand(inst, 2));
         if (c)
            def = nir_bcsel(&t->b, a, b, c);
         break;
      }
      default: return fail(t, STELA_AIR_INSTRUCTION, "unsupported integer opcode %u", op);
      }
   }
   return def && put_value(t, inst, def, 0);
}

/* Count before and after LLVM legalization. Even unreachable input consumes
 * the caller's compilation budget; it cannot hide an unbounded dead CFG. */
static bool
instruction_budget(struct translator *t, LLVMValueRef fn)
{
   unsigned count = 0;
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block)) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block); inst;
           inst = LLVMGetNextInstruction(inst)) {
         if (count == t->options->max_instructions) {
            t->error->instruction = count;
            return fail(t, STELA_AIR_LIMIT, "AIR instruction budget exceeded");
         }
         count++;
      }
   }
   return true;
}

static bool
legalize_switches(struct translator *t, LLVMValueRef fn)
{
   if (!instruction_budget(t, fn))
      return false;
   bool has_switch = false;
   unsigned cases = 0;
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block)) {
      LLVMValueRef term = LLVMGetBasicBlockTerminator(block);
      if (LLVMGetInstructionOpcode(term) == LLVMSwitch) {
         unsigned count = LLVMGetNumSuccessors(term) - 1; /* Exclude default. */
         if (count > t->options->max_instructions - cases)
            return fail(t, STELA_AIR_LIMIT, "AIR switch-case budget exceeded");
         cases += count;
         has_switch = true;
      }
   }
   if (!has_switch)
      return true;

   LLVMPassBuilderOptionsRef options = LLVMCreatePassBuilderOptions();
   if (!options)
      return fail(t, STELA_AIR_ALLOCATION, "LLVM pass options allocation failed");
   /* Only the selected entry is legalized. This is the pinned LLVM pass, not
    * target-specific switch recipes or an optimization of unrelated entries. */
   LLVMErrorRef error = LLVMRunPassesOnFunction(fn, "lower-switch", NULL, options);
   LLVMDisposePassBuilderOptions(options);
   if (error) {
      char *message = LLVMGetErrorMessage(error); /* Consumes error. */
      fail(t, STELA_AIR_CONTROL_FLOW, "LLVM switch legalization failed: %s",
           message ? message : "no diagnostic");
      LLVMDisposeErrorMessage(message);
      return false;
   }
   char *verification = NULL;
   bool invalid = LLVMVerifyModule(t->module, LLVMReturnStatusAction, &verification);
   if (invalid)
      fail(t, STELA_AIR_VERIFY, "%s", verification ? verification : "invalid legalized AIR");
   LLVMDisposeMessage(verification);
   return !invalid && t->error->kind == STELA_AIR_OK && instruction_budget(t, fn);
}

static struct air_block *
cfg_block(struct translator *t, LLVMBasicBlockRef llvm)
{
   struct hash_entry *entry = _mesa_hash_table_search(t->block_map, llvm);
   return entry ? entry->data : NULL;
}

static bool
cfg_prepare(struct translator *t, LLVMValueRef fn)
{
   if (!legalize_switches(t, fn))
      return false;
   t->block_count = LLVMCountBasicBlocks(fn);
   if (!t->block_count || t->block_count > t->options->max_instructions)
      return fail(t, STELA_AIR_LIMIT, "AIR basic-block budget exceeded");
   t->cfg_scratch = ralloc_context(NULL);
   if (!t->cfg_scratch)
      return fail(t, STELA_AIR_ALLOCATION, "AIR CFG scratch allocation failed");
   t->blocks = rzalloc_array(t->cfg_scratch, struct air_block, t->block_count);
   t->work = ralloc_array(t->cfg_scratch, struct air_block *, t->block_count);
   t->block_map = _mesa_pointer_hash_table_create(t->cfg_scratch);
   if (!t->blocks || !t->work || !t->block_map)
      return fail(t, STELA_AIR_ALLOCATION, "AIR CFG allocation failed");
   unsigned i = 0;
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block)) {
      t->blocks[i].llvm = block;
      if (!_mesa_hash_table_insert(t->block_map, block, &t->blocks[i++]))
         return fail(t, STELA_AIR_ALLOCATION, "AIR block map allocation failed");
   }

   /* Iterative discovery does not impose a recursion/nesting limit. A block
    * enters the queue once; all dominators precede its emission regardless of
    * the input's textual block order. PHI backedge defs are declared separately. */
   t->blocks[0].reachable = true;
   t->work[t->reachable_count++] = &t->blocks[0];
   for (unsigned current = 0; current < t->reachable_count; current++) {
      LLVMValueRef term = LLVMGetBasicBlockTerminator(t->work[current]->llvm);
      LLVMOpcode op = LLVMGetInstructionOpcode(term);
      if (op != LLVMRet && op != LLVMUncondBr && op != LLVMCondBr)
         return fail(t, STELA_AIR_CONTROL_FLOW, "unsupported AIR terminator %u", op);
      for (unsigned s = 0; s < LLVMGetNumSuccessors(term); s++) {
         struct air_block *next = cfg_block(t, LLVMGetSuccessor(term, s));
         if (!next)
            return fail(t, STELA_AIR_CONTROL_FLOW, "branch leaves AIR entry");
         if (!next->reachable) {
            next->reachable = true;
            t->work[t->reachable_count++] = next;
         }
      }
   }
   return true;
}

static bool
same_pointer_resource(const struct value *a, const struct value *b)
{
   return a && b && a->pointer_root && a->pointer_root == b->pointer_root &&
      a->access == b->access && a->ssbo == b->ssbo && a->ssbo_slot == b->ssbo_slot &&
      a->fields.first == b->fields.first && a->fields.count == b->fields.count &&
      a->storage == b->storage && a->constant_data == b->constant_data &&
      a->storage_size == b->storage_size && a->constant_base == b->constant_base;
}

static struct pointer_node *
pointer_node(struct translator *t, LLVMValueRef llvm)
{
   struct hash_entry *entry = _mesa_hash_table_search(t->pointer_map, llvm);
   return entry ? entry->data : NULL;
}

/* Validates a provenance root. An address loaded from an argument buffer is
 * a root its load validates when translated. */
static bool
pointer_anchor(struct translator *t, LLVMValueRef llvm)
{
   if (LLVMIsALoadInst(llvm))
      return true;
   struct value *value = find_value(t, llvm);
   if (!value && LLVMIsAAllocaInst(llvm))
      value = private_allocation(t, llvm);
   else if (!value && LLVMIsAGlobalVariable(llvm))
      value = pointer_value(t, llvm);
   return (value && value->access && value->pointer_root == llvm &&
           pointer_space(LLVMTypeOf(llvm)) && value->def &&
           value->def->num_components == 1 && value->def->bit_size == 64) ||
      fail(t, STELA_AIR_MEMORY, "pointer PHI dependency lacks validated resource origin");
}

static unsigned
pointer_dependencies(const struct pointer_node *node)
{
   return LLVMGetInstructionOpcode(node->llvm) == LLVMPHI ? LLVMCountIncoming(node->llvm) : 1;
}

static LLVMValueRef
pointer_dependency(struct translator *t, const struct pointer_node *node, unsigned index)
{
   if (LLVMGetInstructionOpcode(node->llvm) != LLVMPHI)
      return LLVMGetOperand(node->llvm, 0);
   struct air_block *pred = cfg_block(t, LLVMGetIncomingBlock(node->llvm, index));
   /* LLVM verification has already established entry-local predecessor edges. */
   return pred && pred->reachable ? LLVMGetIncomingValue(node->llvm, index) : NULL;
}

/* Resolve one SCC only from already-proven outgoing dependencies. In
 * particular, a rooted user cannot lend authority backward to a rootless cycle. */
static bool
pointer_component(struct translator *t, struct pointer_node **stack,
                  unsigned begin, unsigned end, unsigned component)
{
   LLVMValueRef root = NULL;
   for (unsigned i = begin; i < end; i++)
      stack[i]->component = component;
   for (unsigned i = begin; i < end; i++) {
      struct pointer_node *node = stack[i];
      unsigned count = pointer_dependencies(node);
      for (unsigned j = 0; j < count; j++) {
         LLVMValueRef dependency = pointer_dependency(t, node, j);
         if (!dependency)
            continue;
         struct pointer_node *dep = pointer_node(t, dependency);
         LLVMValueRef candidate;
         if (dep) {
            if (dep->component == component)
               continue;
            if (dep->component == UINT_MAX)
               return fail(t, STELA_AIR_MEMORY, "unresolved pointer provenance component");
            candidate = dep->root;
         } else {
            if (!pointer_anchor(t, dependency))
               return false;
            candidate = dependency;
         }
         if (root && root != candidate)
            return fail(t, STELA_AIR_MEMORY, "pointer PHI joins distinct resource origins");
         root = candidate;
      }
   }
   if (!root)
      return fail(t, STELA_AIR_MEMORY, "pointer PHI has a rootless dependency cycle");
   for (unsigned i = begin; i < end; i++)
      stack[i]->root = root;
   return true;
}

static bool
pointer_solve(struct translator *t, struct pointer_node **dfs, struct pointer_node **stack)
{
   unsigned serial = 0, component = 0, depth = 0, active = 0;
   for (unsigned i = 0; i < t->pointer_count; i++) {
      struct pointer_node *node = &t->pointers[i];
      node->index = node->component = UINT_MAX;
      node->next = 0;
      node->active = false;
   }
   for (unsigned i = 0; i < t->pointer_count; i++) {
      if (t->pointers[i].index != UINT_MAX)
         continue;
      dfs[depth++] = &t->pointers[i];
      while (depth) {
         struct pointer_node *node = dfs[depth - 1];
         if (node->index == UINT_MAX) {
            node->index = node->low = serial++;
            node->active = true;
            stack[active++] = node;
         }
         unsigned count = pointer_dependencies(node);
         if (node->next < count) {
            LLVMValueRef llvm = pointer_dependency(t, node, node->next++);
            struct pointer_node *dep = llvm ? pointer_node(t, llvm) : NULL;
            if (!dep)
               continue; /* Roots are checked when the SCC is resolved. */
            if (dep->index == UINT_MAX) {
               dfs[depth++] = dep;
            } else if (dep->active) {
               node->low = MIN2(node->low, dep->index);
            }
            continue;
         }
         if (node->low == node->index) {
            unsigned end = active;
            do {
               stack[--active]->active = false;
            } while (stack[active] != node);
            if (!pointer_component(t, stack, active, end, component++))
               return false;
         }
         depth--;
         if (depth)
            dfs[depth - 1]->low = MIN2(dfs[depth - 1]->low, node->low);
      }
   }
   return true;
}

static bool
pointer_provenance(struct translator *t)
{
   for (unsigned i = 0; i < t->reachable_count; i++) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(t->work[i]->llvm); inst;
           inst = LLVMGetNextInstruction(inst)) {
         if (LLVMGetTypeKind(LLVMTypeOf(inst)) == LLVMPointerTypeKind)
            t->pointer_count++;
      }
   }
   t->pointer_map = _mesa_pointer_hash_table_create(t->cfg_scratch);
   if (!t->pointer_map)
      return fail(t, STELA_AIR_ALLOCATION, "pointer provenance map allocation failed");
   if (!t->pointer_count)
      return true;
   t->pointers = rzalloc_array(t->cfg_scratch, struct pointer_node, t->pointer_count);
   struct pointer_node **dfs = ralloc_array(t->cfg_scratch, struct pointer_node *, t->pointer_count);
   struct pointer_node **stack = ralloc_array(t->cfg_scratch, struct pointer_node *, t->pointer_count);
   if (!t->pointers || !dfs || !stack)
      return fail(t, STELA_AIR_ALLOCATION, "pointer provenance scratch allocation failed");
   unsigned next = 0;
   for (unsigned i = 0; i < t->reachable_count; i++) {
      for (LLVMValueRef inst = LLVMGetFirstInstruction(t->work[i]->llvm); inst;
           inst = LLVMGetNextInstruction(inst)) {
         if (LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMPointerTypeKind)
            continue;
         LLVMOpcode op = LLVMGetInstructionOpcode(inst);
         if (op == LLVMAlloca || op == LLVMLoad)
            continue; /* Roots, like arguments and globals. */
         if (op != LLVMPHI && op != LLVMGetElementPtr && op != LLVMBitCast)
            return fail(t, STELA_AIR_TYPE, "unsupported pointer provenance producer");
         if (!pointer_space(LLVMTypeOf(inst)) ||
             (op != LLVMPHI && LLVMTypeOf(LLVMGetOperand(inst, 0)) != LLVMTypeOf(inst)))
            return fail(t, STELA_AIR_MEMORY, "unsupported pointer provenance address space");
         struct pointer_node *node = &t->pointers[next++];
         node->llvm = inst;
         if (!_mesa_hash_table_insert(t->pointer_map, inst, node))
            return fail(t, STELA_AIR_ALLOCATION, "pointer provenance insertion failed");
      }
   }
   t->pointer_count = next; /* Allocations are roots, not nodes. */
   return pointer_solve(t, dfs, stack);
}

static bool
cfg_phi_shape(struct translator *t, LLVMTypeRef type, unsigned *leaves)
{
   unsigned components, bits;
   *leaves = 0;
   if (value_shape(type, &components, &bits) || pointer_space(type))
      return true;
   if (!t->stage_options || LLVMGetTypeKind(type) != LLVMStructTypeKind ||
       LLVMIsOpaqueStruct(type) || !LLVMIsPackedStruct(type) ||
       !LLVMCountStructElementTypes(type) || LLVMCountStructElementTypes(type) > AIR_MAX_ARGUMENTS)
      return fail(t, STELA_AIR_TYPE, "PHI requires numeric/proven pointer value or packed flat FP32 render aggregate");
   *leaves = LLVMCountStructElementTypes(type);
   for (unsigned i = 0; i < *leaves; i++) {
      if (!leaf_shape(LLVMStructGetTypeAtIndex(type, i)))
         return fail(t, STELA_AIR_TYPE, "aggregate PHI requires flat scalar/vector leaves");
   }
   return true;
}

static struct value *
cfg_phi_leaf(struct translator *t, LLVMTypeRef type)
{
   unsigned components, bits;
   if (pointer_space(type)) {
      components = 1;
      bits = 64;
   } else if (!value_shape(type, &components, &bits)) {
      fail(t, STELA_AIR_TYPE, "unsupported PHI leaf type");
      return NULL;
   }
   struct value *value = rzalloc(t->values, struct value);
   nir_phi_instr *phi = nir_phi_instr_create(t->b.shader);
   if (!value || !phi) {
      fail(t, STELA_AIR_ALLOCATION, "AIR PHI leaf allocation failed");
      return NULL;
   }
   nir_def_init(&phi->instr, &phi->def, components, bits);
   nir_builder_instr_insert(&t->b, &phi->instr);
   value->def = &phi->def;
   value->components = components;
   value->bits = bits;
   return value;
}

static bool
cfg_declare_phi(struct translator *t, LLVMValueRef inst)
{
   LLVMTypeRef type = LLVMTypeOf(inst);
   unsigned leaves;
   if (!cfg_phi_shape(t, type, &leaves))
      return false;
   struct value *value;
   if (leaves) {
      value = rzalloc(t->values, struct value);
      if (!value || !(value->elements = rzalloc_array(t->values, struct value *, leaves)))
         return fail(t, STELA_AIR_ALLOCATION, "aggregate PHI wrapper allocation failed");
      value->aggregate_count = leaves;
      for (unsigned i = 0; i < leaves; i++) {
         value->elements[i] = cfg_phi_leaf(t, LLVMStructGetTypeAtIndex(type, i));
         if (!value->elements[i])
            return false;
      }
   } else {
      value = cfg_phi_leaf(t, type);
      if (!value)
         return false;
   }
   if (pointer_space(type)) {
      struct pointer_node *node = pointer_node(t, inst);
      if (node && LLVMIsALoadInst(node->root))
         return fail(t, STELA_AIR_MEMORY, "pointer PHI of an address loaded from an argument buffer");
      struct value *root = node ? find_value(t, node->root) : NULL;
      if (!root)
         return fail(t, STELA_AIR_MEMORY, "pointer PHI lacks completed provenance proof");
      pointer_authority(value, root);
   }
   return _mesa_hash_table_insert(t->values, inst, value) != NULL ||
      fail(t, STELA_AIR_ALLOCATION, "AIR PHI value map allocation failed");
}

/* A workgroup execution barrier ordering threadgroup memory. */
static void
workgroup_barrier(struct translator *t)
{
   nir_barrier(&t->b, .execution_scope = SCOPE_WORKGROUP, .memory_scope = SCOPE_WORKGROUP,
               .memory_semantics = NIR_MEMORY_ACQ_REL, .memory_modes = nir_var_mem_shared);
}

/* Where every thread of an object or mesh function leaves it: an object
 * function launches the grid its threads set, carrying its payload; a mesh
 * function outputs the primitives its threads set, up to its capacity. */
static void
mesh_epilogue(struct translator *t)
{
   nir_builder *b = &t->b;
   b->cursor = nir_after_block(t->exit);
   workgroup_barrier(t);
   nir_deref_instr *state = nir_build_deref_var(b, t->mesh_state);
   if (t->stage_options->stage == STELA_AIR_OBJECT) {
      nir_def *grid[3];
      for (unsigned i = 0; i < 3; i++)
         grid[i] = nir_load_deref(b, nir_build_deref_array_imm(b, state, i));
      unsigned payload = t->payload ? glsl_get_length(t->payload->type) : 0;
      nir_launch_mesh_workgroups(b, nir_vec(b, grid, 3), .base = 0, .range = payload);
   } else {
      const struct stela_air_stage_entry *entry = &t->render.entry;
      nir_def *count = nir_umin(b, nir_load_deref(b, nir_build_deref_array_imm(b, state, 0)),
                                nir_imm_int(b, entry->max_primitives));
      nir_set_vertex_and_primitive_count(b, nir_imm_int(b, entry->max_vertices), count,
                                         nir_undef(b, 1, 32));
   }
   nir_goto(b, b->impl->end_block);
}

static bool
cfg_declare(struct translator *t)
{
   nir_block *entry = nir_start_block(t->b.impl);
   if (!binding_prelude(t))
      return false;
   t->b.impl->structured = false;
   t->b.cursor = nir_after_block(entry);
   t->exit = t->b.impl->end_block;
   /* The device value belongs to the straight-line prelude. */
   bool grid_bounded = !t->stage_options ? t->options->load_device_value != NULL :
                       compute_like(t) && t->stage_options->launched_by_grid;
   nir_def *grid = grid_bounded ? device_value(t, STELA_AIR_DISPATCH_GRID) : NULL;
   if (grid_bounded && !grid)
      return false;
   if (t->mesh_state) {
      /* Every thread clears the state before any sets it. */
      nir_deref_instr *state = nir_build_deref_var(&t->b, t->mesh_state);
      for (unsigned i = 0; i < glsl_get_length(t->mesh_state->type); i++)
         nir_store_deref(&t->b, nir_build_deref_array_imm(&t->b, state, i), nir_imm_int(&t->b, 0), 1);
      workgroup_barrier(t);
      if (!(t->exit = new_block(t)))
         return false;
   }
   /* Threads outside a dispatchThreads grid or a dynamic kernel's shape
    * skip the function. */
   nir_def *runs = NULL;
   if (grid) {
      nir_def *position = grid_position(t);
      if (!position)
         return false;
      runs = nir_ior(&t->b, nir_ball(&t->b, nir_ult(&t->b, position, grid)),
                     nir_ieq_imm(&t->b, nir_channel(&t->b, grid, 0), 0));
   }
   if (t->options->dynamic_shape) {
      nir_def *shape = threadgroup_shape(t);
      if (!shape)
         return false;
      nir_def *inside = nir_ult(&t->b, nir_load_local_invocation_index(&t->b), volume(&t->b, shape));
      runs = runs ? nir_iand(&t->b, runs, inside) : inside;
   }
   if (runs) {
      nir_block *body = new_block(t);
      if (!body)
         return false;
      nir_goto_if(&t->b, body, runs, t->exit);
      entry = body;
   }
   t->work[0]->start = entry;
   for (unsigned i = 1; i < t->reachable_count; i++) {
      t->work[i]->start = new_block(t);
      if (!t->work[i]->start)
         return false;
   }
   for (unsigned i = 0; i < t->reachable_count; i++) {
      struct air_block *block = t->work[i];
      t->b.cursor = nir_before_block(block->start);
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block->llvm);
           inst && LLVMGetInstructionOpcode(inst) == LLVMPHI; inst = LLVMGetNextInstruction(inst)) {
         if (!cfg_declare_phi(t, inst))
            return false;
      }
   }
   return true;
}

static bool
cfg_emit(struct translator *t)
{
   if (!pointer_provenance(t) || !cfg_declare(t))
      return false;
   for (unsigned i = 0; i < t->reachable_count; i++) {
      struct air_block *block = t->work[i];
      t->b.cursor = nir_after_block(block->start);
      LLVMValueRef term = LLVMGetBasicBlockTerminator(block->llvm);
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block->llvm); inst != term;
           inst = LLVMGetNextInstruction(inst)) {
         if (LLVMGetInstructionOpcode(inst) != LLVMPHI && !instruction(t, inst))
            return false;
         t->error->instruction++;
      }
      LLVMOpcode op = LLVMGetInstructionOpcode(term);
      if (op == LLVMRet) {
         if (!instruction(t, term))
            return false;
         nir_goto(&t->b, t->exit);
      } else {
         struct air_block *yes = cfg_block(t, LLVMGetSuccessor(term, 0));
         if (op == LLVMUncondBr) {
            nir_goto(&t->b, yes->start);
         } else {
            nir_def *condition = get_value(t, LLVMGetCondition(term));
            if (!condition || condition->num_components != 1 || condition->bit_size != 1)
               return fail(t, STELA_AIR_TYPE, "branch requires scalar i1");
            struct air_block *no = cfg_block(t, LLVMGetSuccessor(term, 1));
            if (yes == no)
               nir_goto(&t->b, yes->start);
            else
               nir_goto_if(&t->b, yes->start, condition, no->start);
         }
      }
      /* SSBO/shared bounds checks may have split the LLVM block. Its actual
       * final jump, not its original NIR entry, supplies every outgoing PHI. */
      block->end = nir_cursor_current_block(t->b.cursor);
      t->error->instruction++;
   }

   for (unsigned i = 0; i < t->reachable_count; i++) {
      struct air_block *block = t->work[i];
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block->llvm);
           inst && LLVMGetInstructionOpcode(inst) == LLVMPHI; inst = LLVMGetNextInstruction(inst)) {
         struct value *target = find_value(t, inst);
         unsigned sources = 0;
         for (unsigned s = 0; s < LLVMCountIncoming(inst); s++) {
            struct air_block *pred = cfg_block(t, LLVMGetIncomingBlock(inst, s));
            if (!pred)
               return fail(t, STELA_AIR_CONTROL_FLOW, "PHI predecessor leaves AIR entry");
            if (!pred->reachable)
               continue; /* No NIR edge exists for an unreachable LLVM block. */
            LLVMValueRef incoming = LLVMGetIncomingValue(inst, s);
            if (pred->incoming_phi == inst) {
               if (pred->incoming_value != incoming)
                  return fail(t, STELA_AIR_VERIFY, "different PHI values on duplicate predecessor edges");
               continue;
            }
            pred->incoming_phi = inst;
            pred->incoming_value = incoming;
            /* Constants are materialized before the predecessor's jump. Uses
             * of loop-carried PHIs retain their original simultaneous defs. */
            t->b.cursor = nir_before_instr(nir_block_last_instr(pred->end));
            if (target->pointer_root && !same_pointer_resource(target, find_value(t, incoming)))
               return fail(t, STELA_AIR_MEMORY, "pointer PHI incoming authority differs from proof");
            struct value *aggregate = target->aggregate_count ? aggregate_value(t, incoming) : NULL;
            if (target->aggregate_count &&
                (!aggregate || aggregate->aggregate_count != target->aggregate_count))
               return fail(t, STELA_AIR_TYPE, "aggregate PHI incoming shape mismatch");
            unsigned leaves = target->aggregate_count ? target->aggregate_count : 1;
            for (unsigned leaf = 0; leaf < leaves; leaf++) {
               nir_def *value = aggregate ?
                  (aggregate->elements[leaf] ? aggregate->elements[leaf]->def : NULL) : get_value(t, incoming);
               if (!value)
                  return fail(t, STELA_AIR_INSTRUCTION, "undefined/poison aggregate PHI leaf/lane");
               nir_def *def = target->aggregate_count ? target->elements[leaf]->def : target->def;
               if (value->num_components != def->num_components || value->bit_size != def->bit_size)
                  return fail(t, STELA_AIR_TYPE, "PHI incoming leaf shape mismatch");
               nir_phi_instr *phi = nir_instr_as_phi(nir_def_instr(def));
               /* Leaves are already inserted; attach each late use as well. */
               nir_phi_src *source = nir_phi_instr_add_src(phi, pred->end, value);
               list_addtail(&source->src.use_link, &value->uses);
            }
            sources++;
         }
         if (sources != nir_block_num_preds(block->start))
            return fail(t, STELA_AIR_CONTROL_FLOW, "PHI sources differ from emitted predecessor edges");
      }
   }
   if (t->mesh_state)
      mesh_epilogue(t);
   nir_sort_unstructured_blocks(t->b.impl);
   nir_validate_shader(t->b.shader, "AIR flat CFG before Mesa structurization");
   nir_lower_goto_ifs(t->b.shader);
   nir_lower_vars_to_ssa(t->b.shader);
   nir_validate_shader(t->b.shader, "AIR structured CFG after Mesa lowering");
   return true;
}

static nir_shader *
translate(const void *bitcode, size_t size, const char *entry,
                 const nir_shader_compiler_options *nir_options,
                 const struct stela_air_options *options,
                 struct stela_air_error *error, const struct stela_air_stage_options *stage)
{
   struct stela_air_error local_error = {0};
   if (!error)
      error = &local_error;
   *error = (struct stela_air_error){0};
   struct translator t = {.options = options, .error = error, .stage_options = stage};
   bool compute = compute_like(&t);
   if (!bitcode || size < 4 || size > AIR_MAX_BITCODE_BYTES ||
       memcmp(bitcode, "BC\xc0\xde", 4) || !entry || !*entry || !nir_options ||
       !options || !options->max_instructions || (options->constant_count && !options->constants) ||
       (compute && (!options->workgroup_size[0] ||
       !options->workgroup_size[1] || !options->workgroup_size[2]))) {
      fail(&t, STELA_AIR_INPUT, "invalid AIR bitcode/options");
      return NULL;
   }
   if (stage && (stage->stage < STELA_AIR_VERTEX || stage->stage > STELA_AIR_MESH ||
       (!compute && (options->workgroup_size[0] || options->workgroup_size[1] ||
                     options->workgroup_size[2] || options->max_threadgroup_bytes ||
                     options->bind_threadgroup || stage->launched_by_grid)) ||
       (stage->amplified && stage->stage != STELA_AIR_VERTEX) ||
       stage->max_varying_slots > VARYING_SLOT_MAX - VARYING_SLOT_VAR0)) {
      fail(&t, STELA_AIR_INPUT, "stage options must suit the function's stage");
      return NULL;
   }
   for (unsigned i = 0; i < 3; i++) {
      if (options->workgroup_size[i] > UINT16_MAX) {
         fail(&t, STELA_AIR_INPUT, "workgroup dimension exceeds NIR representation");
         return NULL;
      }
   }
   if ((options->bind_buffer && options->bind_ssbo) ||
       (options->bind_ssbo && (!options->ssbo_count || options->ssbo_count > UINT8_MAX)) ||
       (!options->bind_ssbo && options->ssbo_count)) {
      fail(&t, STELA_AIR_INPUT, "invalid/mixed global and SSBO binding ABI");
      return NULL;
   }
   if (options->bind_threadgroup && !options->max_threadgroup_bytes) {
      fail(&t, STELA_AIR_INPUT, "threadgroup callback requires an explicit shared-byte limit");
      return NULL;
   }
   if ((options->dynamic_shape && (stage || options->workgroup_size[1] != 1 ||
                                   options->workgroup_size[2] != 1 || !options->load_device_value)) ||
       (options->dynamic_threadgroup_bytes &&
        (!options->dynamic_shape || !options->threadgroup_offset ||
         options->dynamic_threadgroup_bytes % 16))) {
      fail(&t, STELA_AIR_INPUT, "dynamic threadgroups are a linear kernel's, with their callbacks");
      return NULL;
   }
   if (options->fp_profile != STELA_AIR_FP_IEEE_DEFAULT &&
       options->fp_profile != STELA_AIR_FP_METAL) {
      fail(&t, STELA_AIR_INPUT, "unknown AIR floating-point profile");
      return NULL;
   }
   unsigned major, minor, patch;
   LLVMGetVersion(&major, &minor, &patch);
   if (major != 23) {
      fail(&t, STELA_AIR_LLVM_VERSION, "requires LLVM 23 C ABI, found %u.%u.%u", major, minor, patch);
      return NULL;
   }
   t.context = LLVMContextCreate();
   LLVMContextSetDiagnosticHandler(t.context, diagnostic, &t);
   LLVMMemoryBufferRef buffer = LLVMCreateMemoryBufferWithMemoryRangeCopy(bitcode, size, entry);
   LLVMBool parse_failed = LLVMParseBitcodeInContext2(t.context, buffer, &t.module);
   LLVMDisposeMemoryBuffer(buffer);
   nir_shader *result = NULL;
   if (parse_failed || error->kind != STELA_AIR_OK) {
      fail(&t, STELA_AIR_BITCODE, "LLVM refused AIR bitcode");
      goto done;
   }
   char *verification = NULL;
   if (LLVMVerifyModule(t.module, LLVMReturnStatusAction, &verification)) {
      fail(&t, STELA_AIR_VERIFY, "%s", verification ? verification : "invalid LLVM module");
      LLVMDisposeMessage(verification);
      goto done;
   }
   LLVMDisposeMessage(verification);
   const char *target = LLVMGetTarget(t.module);
   size_t asm_size;
   LLVMGetModuleInlineAsm(t.module, &asm_size);
   if (strncmp(target, "air64_v", 7) || asm_size ||
       LLVMGetFirstGlobalAlias(t.module) ||
       LLVMGetFirstGlobalIFunc(t.module)) {
      fail(&t, STELA_AIR_TARGET, "unsupported target/globals/inline assembly");
      goto done;
   }
   t.metadata = (struct stela_air_metadata){.module = t.module, .error = error, .render = stage != NULL};
   if (!stela_air_metadata_layout(&t.metadata) || !stela_air_metadata_validate(&t.metadata) ||
       !stela_air_specialize_constants(&t.metadata, options->constants, options->constant_count) ||
       !stela_air_construct_constants(&t.metadata) ||
       !stela_air_link_modules(&t.metadata, options->modules, options->module_count) ||
       !stela_air_dispatch_tables(&t.metadata, options->linked_functions,
                                  options->linked_function_count) ||
       !stela_air_inline_calls(&t.metadata, LLVMGetNamedFunction(t.module, entry),
                               options->max_call_stack_depth, options->max_instructions))
      goto done;
   t.layout = t.metadata.layout;
   t.air_minor = t.metadata.air_minor;
   t.language_major = t.metadata.language_major;
   t.language_minor = t.metadata.language_minor;
   t.max_device_buffers = t.metadata.max_device_buffers;
   t.max_threadgroup_buffers = t.metadata.max_threadgroup_buffers;
   t.denorms_disable = t.metadata.denorms_disable;
   t.fast_math = t.metadata.fast_math;
   bool threadgroup_globals;
   if (!stela_air_metadata_globals(&t.metadata, &threadgroup_globals))
      goto done;
   /* Linking sets the triple again. */
   target = LLVMGetTarget(t.module);
   char target_prefix[40];
   snprintf(target_prefix, sizeof(target_prefix), "air64_v2%u-apple-macosx", t.air_minor);
   if (strncmp(target, target_prefix, strlen(target_prefix))) {
      fail(&t, STELA_AIR_TARGET, "AIR version and target triple disagree");
      goto done;
   }
   LLVMValueRef fn = LLVMGetNamedFunction(t.module, entry);
   if (!fn || LLVMIsDeclaration(fn) || LLVMGetFunctionCallConv(fn) != LLVMCCallConv ||
       (!stage && LLVMGetTypeKind(LLVMGetReturnType(LLVMGlobalGetValueType(fn))) != LLVMVoidTypeKind) ||
       LLVMIsFunctionVarArg(LLVMGlobalGetValueType(fn))) {
      fail(&t, STELA_AIR_ARGUMENT, "entry must be a defined nonvariadic void C-convention kernel");
      goto done;
   }
   if (stage && (!stela_air_metadata_stage(&t.metadata, fn, stage->stage, &t.render) ||
                 !stela_air_metadata_stage_map(&t.metadata, &t.render, stage->varyings,
                                               stage->varying_count, stage->max_varying_slots)))
      goto done;
   if (!cfg_prepare(&t, fn))
      goto done;
   t.entry = fn;
   if (!workgroup_within(&t, t.render.entry.max_threads))
      goto done;
   static const mesa_shader_stage stages[] = {
      [STELA_AIR_VERTEX] = MESA_SHADER_VERTEX, [STELA_AIR_FRAGMENT] = MESA_SHADER_FRAGMENT,
      [STELA_AIR_OBJECT] = MESA_SHADER_TASK, [STELA_AIR_MESH] = MESA_SHADER_MESH,
   };
   /* Post-tessellation vertex functions are evaluation shaders. */
   enum stela_air_patch domain = t.render.entry.patch;
   t.b = nir_builder_init_simple_shader(!stage ? MESA_SHADER_COMPUTE : domain ? MESA_SHADER_TESS_EVAL :
                                        stages[stage->stage], nir_options, "%s", entry);
   if (domain)
      t.b.shader->info.tess._primitive_mode = domain == STELA_AIR_PATCH_QUAD ? TESS_PRIMITIVE_QUADS :
                                                                              TESS_PRIMITIVE_TRIANGLES;
   if (stage && stage->stage == STELA_AIR_FRAGMENT)
      t.b.shader->info.fs.early_fragment_tests = t.render.entry.early_fragment_tests;
   t.b.fp_math_ctrl = nir_fp_no_fast_math;
   if (options->fp_profile != STELA_AIR_FP_IEEE_DEFAULT && !fp_environment(&t))
      goto done;
   for (unsigned i = 0; i < 3; i++)
      t.b.shader->info.workgroup_size[i] = options->workgroup_size[i];
   t.b.shader->info.num_ssbos = options->ssbo_count;
   t.values = _mesa_pointer_hash_table_create(t.cfg_scratch);
   if (!t.values || !(!stage ? kernel_arguments(&t, fn) :
                      compute ? mesh_stage_arguments(&t) : stage_arguments(&t, fn))) {
      fail(&t, STELA_AIR_ALLOCATION, "AIR shader/value map allocation failed");
      goto done;
   }
   if (!cfg_emit(&t))
      goto done;
   /* Metal keeps half denormals in every mode. Only half users declare it, so
    * backends without FP16 controls still take FP32-only shaders. */
   if (t.fp_checked && half_arithmetic(t.b.shader))
      t.b.shader->info.float_controls_execution_mode |=
         FLOAT_CONTROLS_DENORM_PRESERVE_FP16 | FLOAT_CONTROLS_ROUNDING_MODE_RTE_FP16;
   if (t.payload) {
      /* Both stages lay the payload out alike: one variable at offset zero. */
      nir_lower_vars_to_explicit_types(t.b.shader, nir_var_mem_task_payload,
                                       glsl_get_natural_size_align_bytes);
      nir_lower_explicit_io(t.b.shader, nir_var_mem_task_payload, nir_address_format_32bit_offset);
   }
   if (t.shared_resources || t.mesh_state) {
      nir_lower_vars_to_explicit_types(t.b.shader, nir_var_mem_shared, glsl_get_natural_size_align_bytes);
      if (t.b.shader->info.shared_size > options->max_threadgroup_bytes) {
         fail(&t, STELA_AIR_LIMIT, "aligned shared layout exceeds target/backend byte limit");
         goto done;
      }
      nir_lower_explicit_io(t.b.shader, nir_var_mem_shared, nir_address_format_32bit_offset);
   }
   if (t.private_allocations) {
      nir_lower_vars_to_explicit_types(t.b.shader, nir_var_function_temp, glsl_get_natural_size_align_bytes);
      if (t.b.shader->scratch_size > options->max_private_bytes) {
         fail(&t, STELA_AIR_LIMIT, "aligned thread memory layout exceeds the target limit");
         goto done;
      }
      nir_lower_explicit_io(t.b.shader, nir_var_function_temp, nir_address_format_32bit_offset);
      nir_remove_dead_variables(t.b.shader, nir_var_function_temp, NULL);
   }
   if (stage || t.shared_resources || t.shared_barriers)
      nir_shader_gather_info(t.b.shader, nir_shader_get_entrypoint(t.b.shader));
   nir_validate_shader(t.b.shader, stage ? "AIR bounded render translation" : "AIR bounded compute translation");
   /* The lowering map is compiler scratch, not shader state. Drop LLVM keys
    * and render descriptor/lane wrappers before their input/stack owners end. */
   ralloc_free(t.values);
   t.values = NULL;
   result = t.b.shader;
   t.b.shader = NULL;
   error->instruction = 0;

done:
   ralloc_free(t.cfg_scratch);
   ralloc_free(t.b.shader);
   if (t.module)
      LLVMDisposeModule(t.module);
   LLVMContextDispose(t.context);
   return result;
}

nir_shader *
stela_air_to_nir(const void *bitcode, size_t size, const char *entry,
                  const nir_shader_compiler_options *nir_options,
                  const struct stela_air_options *options, struct stela_air_error *error)
{
   return translate(bitcode, size, entry, nir_options, options, error, NULL);
}

nir_shader *
stela_air_stage_to_nir(const void *bitcode, size_t size, const char *entry,
                        const nir_shader_compiler_options *nir_options,
                        const struct stela_air_stage_options *options, struct stela_air_error *error)
{
   if (!options) {
      if (error) *error = (struct stela_air_error){.kind = STELA_AIR_INPUT};
      return NULL;
   }
   return translate(bitcode, size, entry, nir_options, &options->resources, error, options);
}
