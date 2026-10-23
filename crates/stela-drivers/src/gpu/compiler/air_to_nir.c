/* SPDX-License-Identifier: MIT */
#define STELA_AIR_METADATA_INTERNAL
#include "air_to_nir.h"
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
   nir_variable *shared;
   unsigned shared_size;
   const struct stela_air_stage_io *constant_view; /* Borrowed only during translation. */
   bool view_root;
   /* Partial render values have no vector def until every lane is defined.
    * Missing lanes are tracked symbolically, never replaced with zero/undef. */
   nir_def *lanes[4];
   unsigned components, bits, aggregate_count;
   struct value **elements;
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
   bool active, view_root;
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
   nir_variable *outputs[AIR_MAX_ARGUMENTS];
   struct stela_air_error *error;
   unsigned air_minor;
   unsigned language_major, language_minor;
   unsigned max_device_buffers;
   unsigned max_threadgroup_buffers;
   unsigned shared_resources;
   unsigned shared_barriers;
   uint64_t shared_layout_bound;
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
   *bits = 32;
   return LLVMGetTypeKind(type) == LLVMFloatTypeKind;
}

static bool
value_shape(LLVMTypeRef type, unsigned *components, unsigned *bits)
{
   return shape(type, components, bits) || float_shape(type, components, bits);
}

static bool
fp_environment(struct translator *t)
{
   if (t->fp_checked)
      return true;
   bool ftz = t->options->fp_profile == STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41;
   if (ftz) {
      LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS], fields[AIR_MAX_METADATA_OPERANDS];
      unsigned count, fields_count;
      if (t->air_minor != 9 || t->language_major != 4 || t->language_minor != 1 ||
          strcmp(LLVMGetTarget(t->module), "air64_v29-apple-macosx27.2.0") ||
          !t->denorms_disable || !t->fast_math ||
          !named_md(t, "llvm.ident", nodes, &count) || count != 1 ||
          !md_node(t, nodes[0], fields, &fields_count) || fields_count != 1 ||
          !md_string(fields[0], "Apple metal version 32023.922 (metalfe-32023.922.4)"))
         return fail(t, STELA_AIR_METADATA, "AIR/compiler metadata differs from selected FP32 profile");
   } else if (t->denorms_disable) {
      return fail(t, STELA_AIR_METADATA, "AIR denorms_disable arithmetic requires qualified FP profile");
   }
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

static struct value *
find_value(struct translator *t, LLVMValueRef llvm)
{
   struct hash_entry *entry = _mesa_hash_table_search(t->values, llvm);
   return entry ? entry->data : NULL;
}

static nir_def *shared_global(struct translator *t, LLVMValueRef global);
static nir_variable *shared_resource(struct translator *t, uint64_t size, unsigned alignment);

static nir_def *
get_value(struct translator *t, LLVMValueRef llvm)
{
   struct value *value = find_value(t, llvm);
   if (value) {
      if (!value->def) fail(t, STELA_AIR_INSTRUCTION, "undefined/poison/aggregate reaches scalar-vector use");
      return value->def;
   }
   if (LLVMIsAGlobalVariable(llvm))
      return shared_global(t, llvm);
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
      LLVMValueRef encoded = LLVMConstBitCast(llvm, LLVMInt32TypeInContext(t->context));
      if (LLVMIsAConstantInt(encoded))
         return nir_imm_intN_t(&t->b, LLVMConstIntGetZExtValue(encoded), 32);
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

static bool
binding_prelude(struct translator *t)
{
   if (exec_list_length(&t->b.impl->body) != 1 ||
       nir_block_ends_in_jump(nir_start_block(t->b.impl)))
      return fail(t, STELA_AIR_CONTROL_FLOW, "resource callback must emit a straight-line prelude");
   return true;
}

static bool
kernel_arguments(struct translator *t, LLVMValueRef fn)
{
   struct stela_air_kernel kernel;
   if (!stela_air_metadata_kernel(&t->metadata, fn, &kernel))
      return false;
   bool ssbo_slots[UINT8_MAX + 1] = {false};
   for (unsigned a = 0; a < kernel.count; a++) {
      const struct stela_air_argument *argument = &kernel.arguments[a];
      LLVMValueRef param = argument->value;
      struct stela_air_buffer desc = argument->buffer;
      unsigned index = desc.argument, components = argument->components;
      bool buffer = argument->is_buffer;
      nir_def *def;
      unsigned ssbo_slot = 0;
      nir_variable *shared = NULL;
      unsigned shared_size = 0;
      if (buffer) {
         bool threadgroup = desc.address_space == 3;
         if (threadgroup) {
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
         /* Metal's grid starts at zero, with no dispatch-base parameter.
          * Form its ID directly from existing NIR workgroup/local builtins;
          * a generic global-ID lowering may add an OpenCL/Vulkan base input. */
         nir_def *size = nir_imm_ivec3(&t->b,
            t->options->workgroup_size[0], t->options->workgroup_size[1],
            t->options->workgroup_size[2]);
         def = nir_iadd(&t->b, nir_imul(&t->b, nir_load_workgroup_id(&t->b), size),
                        nir_load_local_invocation_id(&t->b));
         if (components == 1)
            def = nir_channel(&t->b, def, 0);
      }
      if (!put_value(t, param, def, desc.access))
         return false;
      if (buffer)
         find_value(t, param)->pointer_root = param;
      if (shared) {
         struct value *value = find_value(t, param);
         value->shared = shared;
         value->shared_size = shared_size;
      } else if (buffer && t->options->bind_ssbo) {
         struct value *value = find_value(t, param);
         value->ssbo = true;
         value->ssbo_slot = ssbo_slot;
      }
   }
   return true;
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

static bool
shared_global_info(struct translator *t, LLVMValueRef global,
                   uint64_t *size, unsigned *alignment)
{
   return stela_air_metadata_shared_global(&t->metadata, global, size, alignment);
}

static bool
shared_globals(struct translator *t)
{
   return stela_air_metadata_shared_globals(&t->metadata);
}

static nir_def *
shared_global(struct translator *t, LLVMValueRef global)
{
   uint64_t size;
   unsigned alignment;
   if (!shared_global_info(t, global, &size, &alignment))
      return NULL;
   nir_variable *var = shared_resource(t, size, alignment);
   if (!var)
      return NULL;
   /* A global's logical base dominates every use, even if its first reference
    * occurs inside conditional/loop code. Only this pure offset is inserted at
    * entry; storage is still undef and memory effects keep their source cursor. */
   nir_builder entry = nir_builder_at(nir_before_impl(t->b.impl));
   if (!put_value(t, global, nir_imm_int64(&entry, 0), STELA_AIR_READ_WRITE))
      return NULL;
   struct value *value = find_value(t, global);
   value->shared = var;
   value->shared_size = (unsigned)size;
   value->pointer_root = global;
   return value->def;
}

static nir_def *
gep(struct translator *t, LLVMValueRef inst, const struct value **origin)
{
   if (LLVMIsAGlobalVariable(LLVMGetOperand(inst, 0)) && !get_value(t, LLVMGetOperand(inst, 0)))
      return NULL;
   struct value *base = find_value(t, LLVMGetOperand(inst, 0));
   LLVMTypeRef result_type = LLVMTypeOf(inst);
   if (!base || !base->access || LLVMGetTypeKind(result_type) != LLVMPointerTypeKind ||
       LLVMGetPointerAddressSpace(result_type) != (base->shared ? 3 : base->constant_view ? 2 : 1)) {
      fail(t, STELA_AIR_MEMORY, "GEP requires a validated buffer/shared pointer");
      return NULL;
   }
   LLVMTypeRef type = LLVMGetGEPSourceElementType(inst);
   if (base->view_root && !stela_air_metadata_stage_buffer_type(&t->metadata, base->constant_view, type))
      return NULL;
   unsigned type_budget = 4096;
   if (!fixed_storage_type(t, type, 0, &type_budget))
      return NULL;
   nir_def *address = base->def;
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
         address = nir_iadd_imm(&t->b, address, LLVMOffsetOfElement(t->layout, type, field));
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

static nir_def *
ssbo_access(struct translator *t, const struct value *address, nir_def *stored,
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
   if (stored)
      nir_store_ssbo(b, stored, slot, offset, .align_mul = alignment);
   else
      loaded = nir_load_ssbo(b, components, bits, slot, offset, .align_mul = alignment);
   return memory_guard_end(t, &guard, loaded);
}

static nir_def *
shared_access(struct translator *t, const struct value *address, nir_def *stored,
               unsigned components, unsigned bits, unsigned alignment)
{
   nir_builder *b = &t->b;
   unsigned bytes = components * (bits / 8);
   /* Preserve LLVM64 offsets and resource provenance. An out-of-view access
    * never truncates into another shared allocation or a valid low offset. */
   nir_def *valid = address->shared_size >= bytes ?
      nir_uge(b, nir_imm_int64(b, address->shared_size - bytes), address->def) : nir_imm_false(b);
   struct memory_guard guard;
   if (!memory_guard_begin(t, valid, &guard))
      return NULL;
   nir_deref_instr *byte = nir_build_deref_array(b, nir_build_deref_var(b, address->shared),
                                                nir_u2u32(b, address->def));
   const struct glsl_type *type = glsl_vector_type(glsl_get_base_type(glsl_uintN_t_type(bits)), components);
   nir_deref_instr *typed = nir_build_deref_cast_with_alignment(b, &byte->def,
      nir_var_mem_shared, type, bytes, alignment, 0);
   nir_def *loaded = NULL;
   if (stored)
      nir_store_deref(b, typed, stored, BITFIELD_MASK(components));
   else
      loaded = nir_load_deref(b, typed);
   return memory_guard_end(t, &guard, loaded);
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
      fail(t, STELA_AIR_TYPE, "unsupported partial render value type"); return NULL;
   }
   if (LLVMIsUndef(llvm) || LLVMIsPoison(llvm)) {
      v = rzalloc(t->values, struct value);
      if (!v) {
         fail(t, STELA_AIR_ALLOCATION, "partial render value allocation failed"); return NULL;
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
   if (!v) return fail(t, STELA_AIR_ALLOCATION, "render lane allocation failed");
   v->components = n; v->bits = bits;
   bool complete = true;
   for (unsigned i = 0; i < n; i++) { v->lanes[i] = lanes[i]; complete &= lanes[i] != NULL; }
   if (complete) v->def = nir_vec(&t->b, lanes, n);
   return _mesa_hash_table_insert(t->values, llvm, v) != NULL ||
      fail(t, STELA_AIR_ALLOCATION, "render lane map allocation failed");
}

static struct value *
aggregate_value(struct translator *t, LLVMValueRef llvm)
{
   struct value *v = find_value(t, llvm);
   if (v) {
      if (v->aggregate_count) return v;
      fail(t, STELA_AIR_TYPE, "nonaggregate render value"); return NULL;
   }
   LLVMTypeRef type = LLVMTypeOf(llvm);
   if (LLVMGetTypeKind(type) != LLVMStructTypeKind || LLVMIsOpaqueStruct(type) ||
       !LLVMIsPackedStruct(type) || !LLVMCountStructElementTypes(type) ||
       LLVMCountStructElementTypes(type) > AIR_MAX_ARGUMENTS ||
       (!LLVMIsUndef(llvm) && !LLVMIsPoison(llvm))) {
      fail(t, STELA_AIR_TYPE, "unsupported/forward render aggregate"); return NULL;
   }
   unsigned count = LLVMCountStructElementTypes(type);
   for (unsigned i = 0; i < count; i++) {
      unsigned n, bits;
      if (!float_shape(LLVMStructGetTypeAtIndex(type, i), &n, &bits)) {
         fail(t, STELA_AIR_TYPE, "aggregate requires flat FP32 scalar/vector leaves"); return NULL;
      }
   }
   v = rzalloc(t->values, struct value);
   if (!v || !(v->elements = rzalloc_array(t->values, struct value *, count)) ||
       !_mesa_hash_table_insert(t->values, llvm, v)) {
      fail(t, STELA_AIR_ALLOCATION, "aggregate value allocation failed"); return NULL;
   }
   v->aggregate_count = count;
   return v;
}

static bool
stage_value_instruction(struct translator *t, LLVMValueRef inst, LLVMOpcode op)
{
   if (op == LLVMInsertValue || op == LLVMExtractValue) {
      if (LLVMGetNumIndices(inst) != 1)
         return fail(t, STELA_AIR_INSTRUCTION, "nested aggregate indexing unsupported");
      struct value *a = aggregate_value(t, LLVMGetOperand(inst, 0));
      unsigned index = LLVMGetIndices(inst)[0];
      if (!a || index >= a->aggregate_count)
         return fail(t, STELA_AIR_INSTRUCTION, "invalid aggregate leaf index");
      if (op == LLVMExtractValue) {
         struct value *leaf = a->elements[index];
         return (leaf && leaf->def && put_value(t, inst, leaf->def, 0)) ||
            fail(t, STELA_AIR_INSTRUCTION, "undefined/poison aggregate leaf escapes");
      }
      struct value *leaf = partial_value(t, LLVMGetOperand(inst, 1));
      if (!leaf) return false;
      struct value *v = rzalloc(t->values, struct value);
      if (!v || !(v->elements = ralloc_array(t->values, struct value *, a->aggregate_count)))
         return fail(t, STELA_AIR_ALLOCATION, "aggregate insertion allocation failed");
      v->aggregate_count = a->aggregate_count;
      memcpy(v->elements, a->elements, a->aggregate_count * sizeof(*v->elements));
      v->elements[index] = leaf;
      return _mesa_hash_table_insert(t->values, inst, v) != NULL ||
         fail(t, STELA_AIR_ALLOCATION, "aggregate insertion map failed");
   }
   struct value *a = partial_value(t, LLVMGetOperand(inst, 0));
   if (!a) return false;
   if (op == LLVMExtractElement || op == LLVMInsertElement) {
      LLVMValueRef index = LLVMGetOperand(inst, op == LLVMInsertElement ? 2 : 1);
      if (!LLVMIsAConstantInt(index) || LLVMConstIntGetZExtValue(index) >= a->components)
         return fail(t, STELA_AIR_INSTRUCTION, "invalid/dynamic render vector index");
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
      return fail(t, STELA_AIR_TYPE, "unsupported render shuffle shape");
   nir_def *lanes[4] = {0};
   for (unsigned i = 0; i < n; i++) {
      int mask = LLVMGetMaskValue(inst, i);
      if (mask < 0) continue; /* Undefined result lane stays symbolic. */
      unsigned channel = (unsigned)mask;
      if (channel >= a->components + b->components)
         return fail(t, STELA_AIR_INSTRUCTION, "invalid render shuffle selector");
      lanes[i] = channel < a->components ? value_lane(t, a, channel) : value_lane(t, b, channel - a->components);
   }
   return put_lanes(t, inst, lanes, n, a->bits);
}

static unsigned
stage_location(struct translator *t, const struct stela_air_stage_io *io)
{
   if (io->semantic == STELA_AIR_POSITION) return VARYING_SLOT_POS;
   if (io->semantic == STELA_AIR_RENDER_TARGET) return FRAG_RESULT_DATA0;
   for (unsigned i = 0; i < t->stage_options->varying_count; i++) {
      const struct stela_air_varying_slot *v = &t->stage_options->varyings[i];
      if (v->identifier_bytes == io->identifier_bytes && !memcmp(v->identifier, io->identifier, io->identifier_bytes))
         return VARYING_SLOT_VAR0 + v->location;
   }
   UNREACHABLE("stage map validated before emission");
}

static nir_variable *
stage_variable(struct translator *t, const struct stela_air_stage_io *io, bool output)
{
   char name[4097];
   const char *source = io->name ? io->name : "air.output";
   size_t n = io->name ? io->name_bytes : strlen(source);
   memcpy(name, source, n); name[n] = 0;
   nir_variable *var = nir_variable_create(t->b.shader, output ? nir_var_shader_out : nir_var_shader_in,
      glsl_vector_type(GLSL_TYPE_FLOAT, io->components), name);
   if (!var) { fail(t, STELA_AIR_ALLOCATION, "render IO variable allocation failed"); return NULL; }
   var->data.location = stage_location(t, io);
   if (!output) var->data.interpolation = io->interpolation == STELA_AIR_PERSPECTIVE ?
      INTERP_MODE_SMOOTH : INTERP_MODE_NOPERSPECTIVE;
   return var;
}

static bool
stage_arguments(struct translator *t, LLVMValueRef fn)
{
   bool slots[UINT8_MAX + 1] = {0};
   for (unsigned i = 0; i < t->render.entry.input_count; i++) {
      const struct stela_air_stage_io *io = &t->render.inputs[i];
      LLVMValueRef param = LLVMGetParam(fn, io->argument);
      nir_def *def;
      unsigned slot = 0;
      if (io->semantic == STELA_AIR_STAGE_BUFFER) {
         /* Full stage metadata/layout validation has already completed. An
          * actually unused declaration needs no resource binding or SSA value;
          * a dead instruction using the parameter still counts as a real use. */
         if (!io->used && !LLVMGetFirstUse(param)) continue;
         if (t->options->bind_ssbo) {
            if (!t->options->bind_ssbo(&io->buffer, &slot, t->options->binding_data) ||
                slot >= t->options->ssbo_count || slots[slot])
               return fail(t, STELA_AIR_ARGUMENT, "invalid constant-buffer SSBO binding");
            slots[slot] = true; def = nir_imm_int64(&t->b, 0);
         } else {
            if (!t->options->bind_buffer)
               return fail(t, STELA_AIR_ARGUMENT, "unbound readonly constant view");
            def = t->options->bind_buffer(&t->b, &io->buffer, t->options->binding_data);
            if (!binding_prelude(t))
               return false;
            if (!def || def->num_components != 1 || def->bit_size != 64)
               return fail(t, STELA_AIR_ARGUMENT, "invalid/unbound readonly constant view");
         }
      } else if (io->semantic == STELA_AIR_VERTEX_ID) {
         /* Metal vertex_id includes the base vertex; this is NIR's vertex_id,
          * not vertex_id_zero_base. Actual draw arguments belong to runtime. */
         def = nir_load_vertex_id(&t->b);
      } else if (io->semantic == STELA_AIR_POSITION) {
         t->b.shader->info.fs.origin_upper_left = true;
         t->b.shader->info.fs.pixel_center_integer = false;
         if (!io->used) continue;
         def = nir_load_frag_coord(&t->b);
      } else {
         nir_variable *var = stage_variable(t, io, false);
         if (!var) return false;
         def = nir_load_var(&t->b, var);
      }
      if (!put_value(t, param, def, io->buffer.access)) return false;
      if (io->semantic == STELA_AIR_STAGE_BUFFER) {
         struct value *v = find_value(t, param);
         v->constant_view = io; v->view_root = true; v->pointer_root = param;
         v->ssbo = t->options->bind_ssbo != NULL; v->ssbo_slot = slot;
      }
   }
   for (unsigned i = 0; i < t->render.entry.output_count; i++) {
      if (!(t->outputs[i] = stage_variable(t, &t->render.outputs[i], true))) return false;
   }
   return true;
}

static bool
stage_return(struct translator *t, LLVMValueRef inst)
{
   if (LLVMGetNumOperands(inst) != 1) return fail(t, STELA_AIR_TYPE, "render entry requires its real return value");
   LLVMValueRef returned = LLVMGetOperand(inst, 0);
   struct value *aggregate = NULL;
   if (LLVMGetTypeKind(LLVMTypeOf(returned)) == LLVMStructTypeKind) {
      aggregate = aggregate_value(t, returned);
      if (!aggregate || aggregate->aggregate_count != t->render.entry.output_count)
         return fail(t, STELA_AIR_TYPE, "render output aggregate mismatch");
   }
   nir_def *values[AIR_MAX_ARGUMENTS];
   for (unsigned i = 0; i < t->render.entry.output_count; i++) {
      values[i] = aggregate ? (aggregate->elements[i] ? aggregate->elements[i]->def : NULL) : get_value(t, returned);
      if (!values[i]) return fail(t, STELA_AIR_INSTRUCTION, "undefined/poison render output leaf/lane");
   }
   /* Validate ALL leaves before emitting any output effect. */
   for (unsigned i = 0; i < t->render.entry.output_count; i++)
      nir_store_var(&t->b, t->outputs[i], values[i], BITFIELD_MASK(values[i]->num_components));
   return true;
}

static bool same_pointer_resource(const struct value *a, const struct value *b);

static bool
instruction(struct translator *t, LLVMValueRef inst)
{
   LLVMOpcode op = LLVMGetInstructionOpcode(inst);
   t->b.fp_math_ctrl = fp_math_control(inst);
   unsigned components = 0, bits = 0;
   if (op == LLVMRet)
      return t->stage_options ? stage_return(t, inst) : LLVMGetNumOperands(inst) == 0 || fail(t, STELA_AIR_TYPE, "compute kernel return value");
   if (t->stage_options && (op == LLVMInsertValue || op == LLVMExtractValue || op == LLVMShuffleVector ||
                            op == LLVMExtractElement || op == LLVMInsertElement))
      return stage_value_instruction(t, inst, op);
   if (op != LLVMStore && op != LLVMGetElementPtr && op != LLVMBitCast && op != LLVMCall &&
       !value_shape(LLVMTypeOf(inst), &components, &bits))
      return fail(t, STELA_AIR_TYPE, "unsupported AIR instruction result type (opcode %u)", op);
   if (op == LLVMGetElementPtr) {
      const struct value *origin;
      nir_def *def = gep(t, inst, &origin);
      if (!def || !put_value(t, inst, def, origin->access))
         return false;
      struct value *value = find_value(t, inst);
      value->pointer_root = origin->pointer_root;
      value->ssbo = origin->ssbo;
      value->ssbo_slot = origin->ssbo_slot;
      value->shared = origin->shared;
      value->shared_size = origin->shared_size;
      value->constant_view = origin->constant_view;
      return true;
   }
   if (op == LLVMBitCast) {
      unsigned src_components, src_bits;
      LLVMTypeRef source = LLVMTypeOf(LLVMGetOperand(inst, 0));
      if (LLVMGetTypeKind(source) == LLVMPointerTypeKind &&
          LLVMGetTypeKind(LLVMTypeOf(inst)) == LLVMPointerTypeKind &&
          (LLVMGetPointerAddressSpace(source) == 1 || LLVMGetPointerAddressSpace(source) == 3 ||
           (t->stage_options && LLVMGetPointerAddressSpace(source) == 2)) &&
          LLVMGetPointerAddressSpace(LLVMTypeOf(inst)) == LLVMGetPointerAddressSpace(source)) {
         const struct value *origin = find_value(t, LLVMGetOperand(inst, 0));
         if (!origin || !origin->access || !put_value(t, inst, origin->def, origin->access))
            return fail(t, STELA_AIR_MEMORY, "pointer identity cast lacks buffer provenance");
         struct value *value = find_value(t, inst);
         value->pointer_root = origin->pointer_root;
         value->ssbo = origin->ssbo;
         value->ssbo_slot = origin->ssbo_slot;
         value->shared = origin->shared;
         value->shared_size = origin->shared_size;
         value->constant_view = origin->constant_view;
         value->view_root = origin->view_root;
         return true;
      }
      bool fp_pair = (float_shape(source, &src_components, &src_bits) &&
                      shape(LLVMTypeOf(inst), &components, &bits)) ||
                     (shape(source, &src_components, &src_bits) &&
                      float_shape(LLVMTypeOf(inst), &components, &bits));
      if (!fp_pair || src_components != components || src_bits != 32 || bits != 32)
         return fail(t, STELA_AIR_TYPE, "only component-preserving FP32/i32 bitcast supported");
      nir_def *value = get_value(t, LLVMGetOperand(inst, 0));
      return value && put_value(t, inst, value, 0);
   }
   if (op == LLVMCall) {
      LLVMValueRef callee = LLVMGetCalledValue(inst);
      size_t name_length = 0;
      const char *name = LLVMGetValueName2(callee, &name_length);
      if (name_length == strlen("air.wg.barrier") && !memcmp(name, "air.wg.barrier", name_length)) {
         if (!shared_profile(t))
            return false;
         unsigned convergent = LLVMGetEnumAttributeKindForName("convergent", strlen("convergent"));
         if (!t->options->max_threadgroup_bytes || !LLVMIsAFunction(callee) || !LLVMIsDeclaration(callee) ||
             LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
             LLVMGetInstructionCallConv(inst) != LLVMCCallConv || LLVMGetNumArgOperands(inst) != 3 ||
             LLVMCountParams(callee) != 3 || LLVMIsFunctionVarArg(LLVMGlobalGetValueType(callee)) ||
             LLVMGetCalledFunctionType(inst) != LLVMGlobalGetValueType(callee) ||
             LLVMGetNumOperandBundles(inst) ||
             LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMVoidTypeKind ||
             !LLVMGetEnumAttributeAtIndex(callee, LLVMAttributeFunctionIndex, convergent) ||
             !LLVMGetCallSiteEnumAttribute(inst, LLVMAttributeFunctionIndex, convergent))
            return fail(t, STELA_AIR_INSTRUCTION, "unsupported/unconfigured workgroup barrier signature");
         const unsigned expected[] = {2, 5, 1};
         for (unsigned i = 0; i < ARRAY_SIZE(expected); i++) {
            LLVMValueRef operand = LLVMGetOperand(inst, i);
            if (!LLVMIsAConstantInt(operand) || LLVMGetIntTypeWidth(LLVMTypeOf(operand)) != 32 ||
                LLVMConstIntGetZExtValue(operand) != expected[i])
               return fail(t, STELA_AIR_INSTRUCTION, "unsupported workgroup barrier memory flags/order/scope");
         }
         /* Qualified MSL collective: all WG threads rendezvous, publishing
          * ordinary shared-memory reads/writes. No atomic SC order, device or
          * image memory scope is implemented by this observed form. */
         nir_barrier(&t->b, .execution_scope = SCOPE_WORKGROUP, .memory_scope = SCOPE_WORKGROUP,
            .memory_semantics = NIR_MEMORY_ACQ_REL, .memory_modes = nir_var_mem_shared);
         t->shared_barriers++;
         return true;
      }
      const char *signed_name = "air.convert.f.f32.s.i32";
      const char *unsigned_name = "air.convert.f.f32.u.i32";
      bool signed_conversion = name_length == strlen(signed_name) && !memcmp(name, signed_name, name_length);
      bool unsigned_conversion = name_length == strlen(unsigned_name) && !memcmp(name, unsigned_name, name_length);
      unsigned conversion_components = 1;
      if (t->stage_options && !signed_conversion && !unsigned_conversion) {
         for (unsigned n = 2; n <= 4; n++) {
            char expected[64];
            snprintf(expected, sizeof(expected), "air.convert.f.v%uf32.u.v%ui32", n, n);
            if (name_length == strlen(expected) && !memcmp(name, expected, name_length)) {
               unsigned_conversion = true; conversion_components = n; break;
            }
         }
      }
      if (!signed_conversion && !unsigned_conversion)
         return fail(t, STELA_AIR_INSTRUCTION, "unsupported AIR function/intrinsic call");
      if (!LLVMIsAFunction(callee) || !LLVMIsDeclaration(callee) ||
          LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
          LLVMGetInstructionCallConv(inst) != LLVMCCallConv || LLVMGetNumArgOperands(inst) != 1 ||
          LLVMCountParams(callee) != 1 || LLVMIsFunctionVarArg(LLVMGlobalGetValueType(callee)) ||
          (t->stage_options && (LLVMGetNumOperandBundles(inst) ||
           LLVMGetCalledFunctionType(inst) != LLVMGlobalGetValueType(callee))) ||
          (conversion_components == 1 ?
             (LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMFloatTypeKind ||
              LLVMGetTypeKind(LLVMTypeOf(LLVMGetOperand(inst, 0))) != LLVMIntegerTypeKind ||
              LLVMGetIntTypeWidth(LLVMTypeOf(LLVMGetOperand(inst, 0))) != 32) :
             (LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMVectorTypeKind ||
              LLVMGetVectorSize(LLVMTypeOf(inst)) != conversion_components ||
              LLVMGetTypeKind(LLVMGetElementType(LLVMTypeOf(inst))) != LLVMFloatTypeKind ||
              LLVMGetTypeKind(LLVMTypeOf(LLVMGetOperand(inst, 0))) != LLVMVectorTypeKind ||
              LLVMGetVectorSize(LLVMTypeOf(LLVMGetOperand(inst, 0))) != conversion_components ||
              LLVMGetTypeKind(LLVMGetElementType(LLVMTypeOf(LLVMGetOperand(inst, 0)))) != LLVMIntegerTypeKind ||
              LLVMGetIntTypeWidth(LLVMGetElementType(LLVMTypeOf(LLVMGetOperand(inst, 0)))) != 32)))
         return fail(t, STELA_AIR_TYPE, "unsupported AIR integer-to-FP conversion signature");
      if (t->stage_options) {
         unsigned strict = LLVMGetEnumAttributeKindForName("strictfp", strlen("strictfp"));
         if (strict && (LLVMGetEnumAttributeAtIndex(callee, LLVMAttributeFunctionIndex, strict) ||
                        LLVMGetCallSiteEnumAttribute(inst, LLVMAttributeFunctionIndex, strict)))
            return fail(t, STELA_AIR_TYPE, "strict conversion environment is unsupported");
         const char *environment[] = {"denormal-fp-math", "denormal-fp-math-f32", "rounding-math"};
         for (unsigned i = 0; i < ARRAY_SIZE(environment); i++) {
            if (LLVMGetStringAttributeAtIndex(callee, LLVMAttributeFunctionIndex,
                                              environment[i], strlen(environment[i])) ||
                LLVMGetCallSiteStringAttribute(inst, LLVMAttributeFunctionIndex,
                                               environment[i], strlen(environment[i])))
               return fail(t, STELA_AIR_TYPE, "conversion environment override is unsupported");
         }
      }
      if (t->options->fp_profile != STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41)
         return fail(t, STELA_AIR_METADATA, "AIR conversion intrinsic requires qualified compiler profile");
      if (!fp_environment(t))
         return false;
      nir_def *a = get_value(t, LLVMGetOperand(inst, 0));
      return a && put_value(t, inst, signed_conversion ? nir_i2f32(&t->b, a) : nir_u2f32(&t->b, a), 0);
   }
   if (op == LLVMFNeg) {
      nir_def *value = get_value(t, LLVMGetOperand(inst, 0));
      /* LLVM fneg changes only the sign bit, even for NaNs/subnormals. Do not
       * route this through a target arithmetic negate that can canonicalize. */
      return value && put_value(t, inst, nir_ixor(&t->b, value, nir_imm_int(&t->b, INT32_MIN)), 0);
   }
   if (t->stage_options && op == LLVMFDiv && LLVMGetFastMathFlags(inst) != LLVMFastMathAll)
      return fail(t, STELA_AIR_INSTRUCTION, "precise/partially relaxed render FP division is unqualified");
   if (op == LLVMFAdd || op == LLVMFSub || op == LLVMFMul || (t->stage_options && op == LLVMFDiv) || op == LLVMFCmp ||
       op == LLVMSIToFP || op == LLVMUIToFP) {
      if (!fp_environment(t))
         return false;
      nir_def *a = get_value(t, LLVMGetOperand(inst, 0));
      if (!a)
         return false;
      if (op == LLVMSIToFP || op == LLVMUIToFP) {
         unsigned src_components, src_bits;
         if (!shape(LLVMTypeOf(LLVMGetOperand(inst, 0)), &src_components, &src_bits) || src_bits != 32)
            return fail(t, STELA_AIR_TYPE, "only i32/u32 to FP32 conversion supported");
         return put_value(t, inst, op == LLVMSIToFP ? nir_i2f32(&t->b, a) : nir_u2f32(&t->b, a), 0);
      }
      nir_def *b = get_value(t, LLVMGetOperand(inst, 1));
      if (!b || !float_shape(LLVMTypeOf(LLVMGetOperand(inst, 0)), &components, &bits))
         return fail(t, STELA_AIR_TYPE, "only FP32 arithmetic/comparison supported");
      nir_def *value = NULL;
      if (op == LLVMFAdd)
         value = nir_fadd(&t->b, a, b);
      else if (op == LLVMFSub)
         value = nir_fsub(&t->b, a, b);
      else if (op == LLVMFMul)
         value = nir_fmul(&t->b, a, b);
      else if (op == LLVMFDiv)
         value = nir_fdiv(&t->b, a, b);
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
      LLVMValueRef left = LLVMGetOperand(inst, 0), right = LLVMGetOperand(inst, 1);
      if ((LLVMIsAGlobalVariable(left) && !get_value(t, left)) ||
          (LLVMIsAGlobalVariable(right) && !get_value(t, right)))
         return false;
      const struct value *a = find_value(t, left), *b = find_value(t, right);
      if (!same_pointer_resource(a, b) || !a->def || !b->def ||
          a->def->num_components != 1 || b->def->num_components != 1 ||
          a->def->bit_size != 64 || b->def->bit_size != 64)
         return fail(t, STELA_AIR_MEMORY, "pointer equality requires one validated resource origin");
      /* Equality is invariant under the same unknown base modulo 2^64.
       * AS2 root reflection affects typing, not the pointer's address. */
      return put_value(t, inst, predicate == LLVMIntEQ ?
         nir_ieq(&t->b, a->def, b->def) : nir_ine(&t->b, a->def, b->def), 0);
   }
   if (op == LLVMLoad || op == LLVMStore) {
      LLVMValueRef pointer = LLVMGetOperand(inst, op == LLVMStore ? 1 : 0);
      if (LLVMIsAGlobalVariable(pointer) && !get_value(t, pointer))
         return false;
      struct value *address = find_value(t, pointer);
      unsigned required = op == LLVMStore ? STELA_AIR_WRITE : STELA_AIR_READ;
      if (!address || !(address->access & required) || LLVMGetVolatile(inst) ||
          LLVMGetOrdering(inst) != LLVMAtomicOrderingNotAtomic)
         return fail(t, STELA_AIR_MEMORY, "unsupported volatile/atomic/unbound/disallowed memory access");
      if (op == LLVMStore && !value_shape(LLVMTypeOf(LLVMGetOperand(inst, 0)), &components, &bits))
         return fail(t, STELA_AIR_TYPE, "unsupported store type");
      if (bits == 1)
         return fail(t, STELA_AIR_MEMORY, "sub-byte memory access unsupported");
      if (address->view_root && op == LLVMLoad &&
          !stela_air_metadata_stage_buffer_type(&t->metadata, address->constant_view, LLVMTypeOf(inst)))
         return false;
      unsigned alignment = LLVMGetAlignment(inst);
      if (!alignment)
         return fail(t, STELA_AIR_MEMORY, "memory access lacks explicit alignment");
      if (op == LLVMStore) {
         nir_def *value = get_value(t, LLVMGetOperand(inst, 0));
         if (!value)
            return false;
         if (address->shared)
            shared_access(t, address, value, components, bits, alignment);
         else if (address->ssbo)
            ssbo_access(t, address, value, components, bits, alignment);
         else
            nir_store_global(&t->b, value, address->def, .align_mul = alignment);
         return t->error->kind == STELA_AIR_OK;
      }
      if (address->shared)
         return put_value(t, inst, shared_access(t, address, NULL, components, bits, alignment), 0);
      if (address->ssbo)
         return put_value(t, inst, ssbo_access(t, address, NULL, components, bits, alignment), 0);
      return put_value(t, inst, nir_load_global(&t->b, components, bits,
                       address->def, .align_mul = alignment), 0);
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
   case LLVMSelect: case LLVMExtractElement: case LLVMInsertElement:
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
   else if (op == LLVMExtractElement || op == LLVMInsertElement) {
      LLVMValueRef index = LLVMGetOperand(inst, op == LLVMInsertElement ? 2 : 1);
      if (!LLVMIsAConstantInt(index) || LLVMConstIntGetZExtValue(index) >= a->num_components)
         return fail(t, STELA_AIR_INSTRUCTION, "dynamic/out-of-range vector index unsupported");
      unsigned channel = LLVMConstIntGetZExtValue(index);
      if (op == LLVMExtractElement)
         def = nir_channel(&t->b, a, channel);
      else {
         b = get_value(t, LLVMGetOperand(inst, 1));
         if (!b)
            return false;
         def = nir_vector_insert_imm(&t->b, a, b, channel);
      }
   } else {
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

/* Static pointer authority is separate from the offset/VA in def. */
static void
pointer_authority(struct value *target, const struct value *root, bool view_root)
{
   target->pointer_root = root->pointer_root;
   target->access = root->access;
   target->ssbo = root->ssbo;
   target->ssbo_slot = root->ssbo_slot;
   target->shared = root->shared;
   target->shared_size = root->shared_size;
   target->constant_view = root->constant_view;
   target->view_root = view_root;
}

static bool
same_pointer_resource(const struct value *a, const struct value *b)
{
   return a && b && a->pointer_root && a->pointer_root == b->pointer_root &&
      a->access == b->access && a->ssbo == b->ssbo && a->ssbo_slot == b->ssbo_slot &&
      a->shared == b->shared && a->shared_size == b->shared_size &&
      a->constant_view == b->constant_view;
}

static bool
same_pointer_authority(const struct value *a, const struct value *b)
{
   return same_pointer_resource(a, b) && a->view_root == b->view_root;
}

static struct pointer_node *
pointer_node(struct translator *t, LLVMValueRef llvm)
{
   struct hash_entry *entry = _mesa_hash_table_search(t->pointer_map, llvm);
   return entry ? entry->data : NULL;
}

static bool
pointer_space(struct translator *t, LLVMTypeRef type)
{
   if (LLVMGetTypeKind(type) != LLVMPointerTypeKind)
      return false;
   unsigned space = LLVMGetPointerAddressSpace(type);
   return space == 1 || space == 3 || (t->stage_options && space == 2);
}

static struct value *
pointer_anchor(struct translator *t, LLVMValueRef llvm)
{
   struct value *value = find_value(t, llvm);
   if (!value && LLVMIsAGlobalVariable(llvm)) {
      if (!shared_global(t, llvm))
         return NULL;
      value = find_value(t, llvm);
   }
   if (!value || !value->access || value->pointer_root != llvm ||
       !pointer_space(t, LLVMTypeOf(llvm)) || !value->def ||
       value->def->num_components != 1 || value->def->bit_size != 64 ||
       LLVMGetPointerAddressSpace(LLVMTypeOf(llvm)) !=
          (value->shared ? 3 : value->constant_view ? 2 : 1)) {
      fail(t, STELA_AIR_MEMORY, "pointer PHI dependency lacks validated resource origin");
      return NULL;
   }
   return value;
}

static unsigned
pointer_dependencies(const struct pointer_node *node, bool reflection)
{
   LLVMOpcode op = LLVMGetInstructionOpcode(node->llvm);
   if (reflection && op == LLVMGetElementPtr)
      return 0; /* A GEP is a non-root reflection anchor, even in a cycle. */
   return op == LLVMPHI ? LLVMCountIncoming(node->llvm) : 1;
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
 * particular, a rooted user cannot lend authority backward to a rootless cycle.
 * Reflection uses the same solver with GEP as a terminal false anchor. */
static bool
pointer_component(struct translator *t, struct pointer_node **stack,
                  unsigned begin, unsigned end, unsigned component, bool reflection)
{
   LLVMValueRef root = NULL;
   bool state = false, anchored = false;
   for (unsigned i = begin; i < end; i++)
      stack[i]->component = component;
   for (unsigned i = begin; i < end; i++) {
      struct pointer_node *node = stack[i];
      if (reflection && LLVMGetInstructionOpcode(node->llvm) == LLVMGetElementPtr) {
         if (anchored && state)
            return fail(t, STELA_AIR_MEMORY, "pointer PHI mixes AS2 root reflection states");
         anchored = true;
         state = false;
      }
      unsigned count = pointer_dependencies(node, reflection);
      for (unsigned j = 0; j < count; j++) {
         LLVMValueRef dependency = pointer_dependency(t, node, j);
         if (!dependency)
            continue;
         struct pointer_node *dep = pointer_node(t, dependency);
         LLVMValueRef candidate;
         bool candidate_state;
         if (dep) {
            if (dep->component == component)
               continue;
            if (dep->component == UINT_MAX)
               return fail(t, STELA_AIR_MEMORY, "unresolved pointer provenance component");
            candidate = dep->root;
            candidate_state = dep->view_root;
         } else {
            struct value *value = pointer_anchor(t, dependency);
            if (!value)
               return false;
            candidate = dependency;
            candidate_state = value->view_root;
         }
         if (anchored && (reflection ? state != candidate_state : root != candidate))
            return fail(t, STELA_AIR_MEMORY, reflection ?
               "pointer PHI mixes AS2 root reflection states" :
               "pointer PHI joins distinct resource origins");
         anchored = true;
         root = candidate;
         state = candidate_state;
      }
   }
   if (!anchored)
      return fail(t, STELA_AIR_MEMORY, "pointer PHI has a rootless dependency cycle");
   for (unsigned i = begin; i < end; i++) {
      if (reflection)
         stack[i]->view_root = state;
      else
         stack[i]->root = root;
   }
   return true;
}

static bool
pointer_solve(struct translator *t, struct pointer_node **dfs,
              struct pointer_node **stack, bool reflection)
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
         unsigned count = pointer_dependencies(node, reflection);
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
            if (!pointer_component(t, stack, active, end, component++, reflection))
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
         if (op != LLVMPHI && op != LLVMGetElementPtr && op != LLVMBitCast)
            return fail(t, STELA_AIR_TYPE, "unsupported pointer provenance producer");
         if (!pointer_space(t, LLVMTypeOf(inst)) ||
             (op != LLVMPHI && LLVMTypeOf(LLVMGetOperand(inst, 0)) != LLVMTypeOf(inst)))
            return fail(t, STELA_AIR_MEMORY, "unsupported pointer provenance address space");
         struct pointer_node *node = &t->pointers[next++];
         node->llvm = inst;
         if (!_mesa_hash_table_insert(t->pointer_map, inst, node))
            return fail(t, STELA_AIR_ALLOCATION, "pointer provenance insertion failed");
      }
   }
   return pointer_solve(t, dfs, stack, false) && pointer_solve(t, dfs, stack, true);
}

static bool
cfg_phi_shape(struct translator *t, LLVMTypeRef type, unsigned *leaves)
{
   unsigned components, bits;
   *leaves = 0;
   if (value_shape(type, &components, &bits) || pointer_space(t, type))
      return true;
   if (!t->stage_options || LLVMGetTypeKind(type) != LLVMStructTypeKind ||
       LLVMIsOpaqueStruct(type) || !LLVMIsPackedStruct(type) ||
       !LLVMCountStructElementTypes(type) || LLVMCountStructElementTypes(type) > AIR_MAX_ARGUMENTS)
      return fail(t, STELA_AIR_TYPE, "PHI requires numeric/proven pointer value or packed flat FP32 render aggregate");
   *leaves = LLVMCountStructElementTypes(type);
   for (unsigned i = 0; i < *leaves; i++) {
      if (!float_shape(LLVMStructGetTypeAtIndex(type, i), &components, &bits))
         return fail(t, STELA_AIR_TYPE, "aggregate PHI requires flat FP32 scalar/vector leaves");
   }
   return true;
}

static struct value *
cfg_phi_leaf(struct translator *t, LLVMTypeRef type)
{
   unsigned components, bits;
   if (pointer_space(t, type)) {
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
   if (pointer_space(t, type)) {
      struct pointer_node *node = pointer_node(t, inst);
      struct value *root = node ? find_value(t, node->root) : NULL;
      if (!root)
         return fail(t, STELA_AIR_MEMORY, "pointer PHI lacks completed provenance proof");
      pointer_authority(value, root, node->view_root);
   }
   return _mesa_hash_table_insert(t->values, inst, value) != NULL ||
      fail(t, STELA_AIR_ALLOCATION, "AIR PHI value map allocation failed");
}

static bool
cfg_declare(struct translator *t)
{
   nir_block *entry = nir_start_block(t->b.impl);
   if (!binding_prelude(t))
      return false;
   t->b.impl->structured = false;
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
         nir_goto(&t->b, t->b.impl->end_block);
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
            if (target->pointer_root && !same_pointer_authority(target, find_value(t, incoming)))
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
   if (!bitcode || size < 4 || size > AIR_MAX_BITCODE_BYTES ||
       memcmp(bitcode, "BC\xc0\xde", 4) || !entry || !*entry || !nir_options ||
       !options || !options->max_instructions || (!stage && (!options->workgroup_size[0] ||
       !options->workgroup_size[1] || !options->workgroup_size[2]))) {
      fail(&t, STELA_AIR_INPUT, "invalid AIR bitcode/options");
      return NULL;
   }
   if (stage && ((stage->stage != STELA_AIR_VERTEX && stage->stage != STELA_AIR_FRAGMENT) ||
       options->workgroup_size[0] || options->workgroup_size[1] || options->workgroup_size[2] ||
       options->max_threadgroup_bytes || options->bind_threadgroup ||
       stage->max_varying_slots > VARYING_SLOT_MAX - VARYING_SLOT_VAR0)) {
      fail(&t, STELA_AIR_INPUT, "render options must not supply compute/shared specializations");
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
   if (options->fp_profile != STELA_AIR_FP_IEEE_DEFAULT &&
       options->fp_profile != STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41) {
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
   if (!stela_air_metadata_layout(&t.metadata) || !stela_air_metadata_validate(&t.metadata))
      goto done;
   t.layout = t.metadata.layout;
   t.air_minor = t.metadata.air_minor;
   t.language_major = t.metadata.language_major;
   t.language_minor = t.metadata.language_minor;
   t.max_device_buffers = t.metadata.max_device_buffers;
   t.max_threadgroup_buffers = t.metadata.max_threadgroup_buffers;
   t.denorms_disable = t.metadata.denorms_disable;
   t.fast_math = t.metadata.fast_math;
   if (!shared_globals(&t))
      goto done;
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
   t.b = nir_builder_init_simple_shader(stage ? (stage->stage == STELA_AIR_VERTEX ?
      MESA_SHADER_VERTEX : MESA_SHADER_FRAGMENT) : MESA_SHADER_COMPUTE, nir_options, "%s", entry);
   t.b.fp_math_ctrl = nir_fp_no_fast_math;
   if (options->fp_profile != STELA_AIR_FP_IEEE_DEFAULT && !fp_environment(&t))
      goto done;
   for (unsigned i = 0; i < 3; i++)
      t.b.shader->info.workgroup_size[i] = options->workgroup_size[i];
   t.b.shader->info.num_ssbos = options->ssbo_count;
   t.values = _mesa_pointer_hash_table_create(t.cfg_scratch);
   if (!t.values || !(stage ? stage_arguments(&t, fn) : kernel_arguments(&t, fn))) {
      fail(&t, STELA_AIR_ALLOCATION, "AIR shader/value map allocation failed");
      goto done;
   }
   if (!cfg_emit(&t))
      goto done;
   if (t.shared_resources) {
      nir_lower_vars_to_explicit_types(t.b.shader, nir_var_mem_shared, glsl_get_natural_size_align_bytes);
      if (t.b.shader->info.shared_size > options->max_threadgroup_bytes) {
         fail(&t, STELA_AIR_LIMIT, "aligned shared layout exceeds target/backend byte limit");
         goto done;
      }
      nir_lower_explicit_io(t.b.shader, nir_var_mem_shared, nir_address_format_32bit_offset);
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
