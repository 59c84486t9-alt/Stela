/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/Core.h"
#include "llvm-c/Target.h"
#include "util/hash_table.h"
#include "util/ralloc.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define AIR_MAX_ARGUMENTS 128
#define AIR_MAX_METADATA_OPERANDS 256
#define AIR_MAX_BITCODE_BYTES (64u * 1024u * 1024u)
#define AIR_MAX_BLOCKS 128
#define AIR_MAX_CONTROL_DEPTH 32
#define AIR_MAX_MERGE_PHIS 128

struct air_block {
   LLVMBasicBlockRef llvm;
   unsigned predecessors;
   unsigned visit; /* LLVM CFG validation: 0=new, 1=active, 2=complete. */
   bool emitted;
   struct air_block *latch; /* Non-NULL only on a recognized natural header. */
   struct air_block *loop_header;
   struct air_block *preheader;
   struct air_block *loop_body;
   struct air_block *loop_exit;
   bool loop_active;
};

struct value {
   nir_def *def;
   unsigned access; /* Buffer provenance; zero for integer values. */
   bool ssbo;
   unsigned ssbo_slot;
   nir_variable *shared;
   unsigned shared_size;
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

struct translator {
   LLVMContextRef context;
   LLVMModuleRef module;
   LLVMTargetDataRef layout; /* Borrowed from module. */
   nir_builder b;
   struct hash_table *values;
   const struct stela_air_options *options;
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
   struct air_block blocks[AIR_MAX_BLOCKS];
   unsigned block_count;
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

static bool
md_string(LLVMValueRef value, const char *expected)
{
   if (!value || !LLVMIsAMDString(value))
      return false;
   unsigned length;
   const char *string = LLVMGetMDString(value, &length);
   return length == strlen(expected) && !memcmp(string, expected, length);
}

static bool
md_uint(LLVMValueRef value, unsigned *number)
{
   if (!value || !LLVMIsAConstantInt(value) ||
       LLVMGetIntTypeWidth(LLVMTypeOf(value)) > 32)
      return false;
   *number = LLVMConstIntGetZExtValue(value);
   return true;
}

static bool
md_node(struct translator *t, LLVMValueRef node, LLVMValueRef *operands,
        unsigned *count)
{
   if (!node || !LLVMIsAMDNode(node))
      return fail(t, STELA_AIR_METADATA, "expected AIR metadata node");
   *count = LLVMGetMDNodeNumOperands(node);
   if (*count > AIR_MAX_METADATA_OPERANDS)
      return fail(t, STELA_AIR_LIMIT, "AIR metadata operand budget exceeded");
   LLVMGetMDNodeOperands(node, operands);
   return true;
}

static bool
named_md(struct translator *t, const char *name, LLVMValueRef *operands,
         unsigned *count)
{
   *count = LLVMGetNamedMetadataNumOperands(t->module, name);
   if (*count > AIR_MAX_METADATA_OPERANDS)
      return fail(t, STELA_AIR_LIMIT, "%s metadata budget exceeded", name);
   LLVMGetNamedMetadataOperands(t->module, name, operands);
   return true;
}

static bool
version_metadata(struct translator *t, const char *name, bool language)
{
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned count, fields_count, major, minor, patch;
   if (!named_md(t, name, nodes, &count) || count != 1 ||
       !md_node(t, nodes[0], fields, &fields_count))
      return fail(t, STELA_AIR_METADATA, "missing or invalid %s", name);
   unsigned base = language ? 1 : 0;
   if (fields_count != base + 3 || (language && !md_string(fields[0], "Metal")) ||
       !md_uint(fields[base], &major) || !md_uint(fields[base + 1], &minor) ||
       !md_uint(fields[base + 2], &patch) || patch != 0)
      return fail(t, STELA_AIR_METADATA, "invalid %s", name);
   bool supported = language ?
      ((major == 1 && minor >= 1 && minor <= 2) ||
       (major == 2 && minor <= 4) || (major == 3 && minor <= 2) ||
       (major == 4 && minor <= 1)) : (major == 2 && (minor == 8 || minor == 9));
   /* AIR 2.8 has only been observed with Metal 4.0 here. The AIR 2.9
    * combinations below come from actual independent compiler requests. */
   if (language && t->air_minor == 8)
      supported &= major == 4 && minor == 0;
   if (!supported)
      return fail(t, STELA_AIR_METADATA, "unsupported %s %u.%u.%u", name, major, minor, patch);
   if (!language)
      t->air_minor = minor;
   else {
      t->language_major = major;
      t->language_minor = minor;
   }
   return true;
}

static bool
module_flags(struct translator *t)
{
   /* These are the LLVM IR serialized behavior values, not the smaller C API
    * LLVMModuleFlagBehavior enum (which does not expose Max in LLVM 23). */
   enum { IR_FLAG_ERROR = 1, IR_FLAG_MAX = 7 };
   const char *keys[] = {"wchar_size", "frame-pointer", "air.max_device_buffers",
      "air.max_constant_buffers", "air.max_threadgroup_buffers", "air.max_textures",
      "air.max_read_write_textures", "air.max_samplers"};
   LLVMValueRef flags[AIR_MAX_METADATA_OPERANDS];
   unsigned count, seen = 0;
   if (!named_md(t, "llvm.module.flags", flags, &count))
      return false;
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned field_count, behavior, value, key;
      if (!md_node(t, flags[i], fields, &field_count) || field_count != 3 ||
          !md_uint(fields[0], &behavior) || !md_uint(fields[2], &value))
         return fail(t, STELA_AIR_METADATA, "unsupported module flag shape");
      for (key = 0; key < ARRAY_SIZE(keys); key++) {
         if (md_string(fields[1], keys[key]))
            break;
      }
      if (key == ARRAY_SIZE(keys) || (seen & (1u << key)))
         return fail(t, STELA_AIR_METADATA, "unsupported/duplicate module flag");
      seen |= 1u << key;
      if (behavior != (key == 0 ? IR_FLAG_ERROR : IR_FLAG_MAX) ||
          (key == 0 && value != 4) || (key == 1 && value > 2) ||
          (key >= 2 && !value))
         return fail(t, STELA_AIR_METADATA, "unsupported module flag value: %s", keys[key]);
      if (key == 2)
         t->max_device_buffers = value;
      if (key == 4)
         t->max_threadgroup_buffers = value;
   }
   /* No linking, CPU frame operations or source wchar operations occur in the
    * implemented compute subset. Other resource kinds remain refused.
    * Device/threadgroup location bounds are enforced below, never advertised as the
    * hardware's actual Metal capability or silently removed from the input. */
   return true;
}

static bool
module_metadata(struct translator *t)
{
   for (LLVMNamedMDNodeRef node = LLVMGetFirstNamedMetadata(t->module); node;
        node = LLVMGetNextNamedMetadata(node)) {
      size_t size;
      const char *name = LLVMGetNamedMetadataName(node, &size);
      const char *allowed[] = {"air.version", "air.language_version",
                              "air.compile_options", "air.kernel", "llvm.ident",
                              "llvm.module.flags"};
      bool found = false;
      for (unsigned i = 0; i < ARRAY_SIZE(allowed); i++)
         found |= size == strlen(allowed[i]) && !memcmp(name, allowed[i], size);
      if (!found)
         return fail(t, STELA_AIR_METADATA, "unsupported module metadata: %.*s",
                     (int)MIN2(size, 160), name);
   }
   if (!version_metadata(t, "air.version", false) ||
       !version_metadata(t, "air.language_version", true) || !module_flags(t))
      return false;
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!named_md(t, "air.compile_options", nodes, &count))
      return false;
   unsigned seen = 0;
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned fields_count;
      if (!md_node(t, nodes[i], fields, &fields_count) || fields_count != 1 ||
          !(md_string(fields[0], "air.compile.denorms_disable") ||
            md_string(fields[0], "air.compile.fast_math_enable") ||
            md_string(fields[0], "air.compile.framebuffer_fetch_enable") ||
            md_string(fields[0], "air.compile.framebuffer_fetch_disable")))
         return fail(t, STELA_AIR_METADATA, "unsupported AIR compile option");
      unsigned bit = md_string(fields[0], "air.compile.denorms_disable") ? 1 :
                     md_string(fields[0], "air.compile.fast_math_enable") ? 2 : 4;
      if (seen & bit)
         return fail(t, STELA_AIR_METADATA, "duplicate/conflicting AIR compile option");
      seen |= bit;
   }
   t->denorms_disable = seen & 1;
   t->fast_math = seen & 2;
   /* Arithmetic requires an explicit qualified FP policy for this private AIR
    * option. Exact storage/shared access and integer operations do not depend
    * on FP denorm mode. */
   return true;
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
   struct value *value = ralloc(t->b.shader, struct value);
   if (!value)
      return fail(t, STELA_AIR_ALLOCATION, "AIR value allocation failed");
   *value = (struct value){.def = def, .access = access};
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
   if (value)
      return value->def;
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
                         LLVMIsAConstantDataVector(llvm))) {
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
kernel_arguments(struct translator *t, LLVMValueRef fn)
{
   LLVMValueRef kernels[AIR_MAX_METADATA_OPERANDS], args_node = NULL;
   unsigned kernel_count;
   if (!named_md(t, "air.kernel", kernels, &kernel_count))
      return false;
   for (unsigned i = 0; i < kernel_count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      if (!md_node(t, kernels[i], fields, &count) || count != 3)
         return fail(t, STELA_AIR_METADATA, "invalid air.kernel descriptor");
      if (fields[0] == fn) {
         LLVMValueRef outputs[AIR_MAX_METADATA_OPERANDS];
         unsigned output_count;
         if (args_node || !md_node(t, fields[1], outputs, &output_count) || output_count)
            return fail(t, STELA_AIR_METADATA, "duplicate kernel or nonempty compute outputs");
         args_node = fields[2];
      }
   }
   if (!args_node)
      return fail(t, STELA_AIR_METADATA, "entry is not an AIR compute kernel");
   unsigned argc = LLVMCountParams(fn);
   if (argc > AIR_MAX_ARGUMENTS)
      return fail(t, STELA_AIR_LIMIT, "AIR argument budget exceeded");
   LLVMValueRef args[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!md_node(t, args_node, args, &count) || count != argc)
      return fail(t, STELA_AIR_METADATA, "AIR argument descriptors do not match parameters");
   bool used[AIR_MAX_ARGUMENTS] = {false};
   bool buffer_indices[AIR_MAX_ARGUMENTS] = {false};
   bool shared_indices[AIR_MAX_ARGUMENTS] = {false};
   bool ssbo_slots[UINT8_MAX + 1] = {false};
   for (unsigned a = 0; a < argc; a++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned fields_count, index;
      if (!md_node(t, args[a], fields, &fields_count) || fields_count < 2 ||
          !md_uint(fields[0], &index) || index >= argc || used[index])
         return fail(t, STELA_AIR_METADATA, "invalid/duplicate argument index");
      used[index] = true;
      LLVMValueRef param = LLVMGetParam(fn, index);
      unsigned attributes_count = LLVMGetAttributeCountAtIndex(fn, index + 1);
      if (attributes_count > AIR_MAX_METADATA_OPERANDS)
         return fail(t, STELA_AIR_LIMIT, "argument attribute budget exceeded");
      LLVMAttributeRef attributes[AIR_MAX_METADATA_OPERANDS];
      LLVMGetAttributesAtIndex(fn, index + 1, attributes);
      const char *abi_attributes[] = {"sret", "byval", "byref", "inalloca",
         "preallocated", "nest", "swiftself", "swifterror", "elementtype"};
      for (unsigned attribute = 0; attribute < attributes_count; attribute++) {
         if (LLVMIsTypeAttribute(attributes[attribute]))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported typed parameter attribute");
         if (!LLVMIsEnumAttribute(attributes[attribute]))
            continue;
         unsigned kind = LLVMGetEnumAttributeKind(attributes[attribute]);
         for (unsigned k = 0; k < ARRAY_SIZE(abi_attributes); k++) {
            if (kind == LLVMGetEnumAttributeKindForName(abi_attributes[k], strlen(abi_attributes[k])))
               return fail(t, STELA_AIR_ARGUMENT, "unsupported parameter ABI attribute: %s", abi_attributes[k]);
         }
      }
      bool buffer = md_string(fields[1], "air.buffer");
      bool thread_id = md_string(fields[1], "air.thread_position_in_grid");
      if (!buffer && !thread_id)
         return fail(t, STELA_AIR_ARGUMENT, "unsupported AIR argument kind at %u", index);
      struct stela_air_buffer desc = {.argument = index};
      bool has_location = false, has_as = false, has_size = false, has_align = false;
      bool has_name = false, has_type_name = false;
      for (unsigned f = 2; f < fields_count;) {
         LLVMValueRef key = fields[f++];
         if (md_string(key, "air.read") || md_string(key, "air.write") ||
             md_string(key, "air.read_write")) {
            if (!buffer || desc.access)
               return fail(t, STELA_AIR_METADATA, "duplicate/inapplicable buffer access");
            desc.access = md_string(key, "air.read") ? STELA_AIR_READ :
                          md_string(key, "air.write") ? STELA_AIR_WRITE : STELA_AIR_READ_WRITE;
         } else if (md_string(key, "air.location_index")) {
            unsigned locations;
            if (!buffer || has_location || f + 2 > fields_count ||
                !md_uint(fields[f], &desc.index) || !md_uint(fields[f + 1], &locations) ||
                locations != 1 || desc.index >= AIR_MAX_ARGUMENTS)
               return fail(t, STELA_AIR_METADATA, "unsupported/duplicate buffer location");
            has_location = true;
            f += 2;
         } else if (md_string(key, "air.address_space")) {
            if (!buffer || has_as || f == fields_count || !md_uint(fields[f++], &desc.address_space))
               return fail(t, STELA_AIR_METADATA, "invalid buffer address space");
            has_as = true;
         } else if (md_string(key, "air.arg_type_size") || md_string(key, "air.arg_type_align_size")) {
            bool alignment = md_string(key, "air.arg_type_align_size");
            bool *present = alignment ? &has_align : &has_size;
            unsigned *number = alignment ? &desc.type_alignment : &desc.type_size;
            if (!buffer || *present || f == fields_count || !md_uint(fields[f++], number) ||
                (alignment && (!*number || (*number & (*number - 1)))))
               return fail(t, STELA_AIR_METADATA, "invalid argument size/alignment");
            *present = true;
         } else if (md_string(key, "air.arg_name") || md_string(key, "air.arg_type_name")) {
            bool *present = md_string(key, "air.arg_name") ? &has_name : &has_type_name;
            if (*present || f == fields_count || !fields[f] || !LLVMIsAMDString(fields[f++]))
               return fail(t, STELA_AIR_METADATA, "invalid argument reflection string");
            *present = true;
         } else {
            return fail(t, STELA_AIR_METADATA, "unsupported argument metadata at %u", index);
         }
      }
      nir_def *def;
      unsigned ssbo_slot = 0;
      nir_variable *shared = NULL;
      unsigned shared_size = 0;
      if (buffer) {
         LLVMTypeRef type = LLVMTypeOf(param);
         if (!has_location || !has_as || !desc.access ||
             (desc.address_space != 1 && desc.address_space != 3) ||
             LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
             LLVMGetPointerAddressSpace(type) != desc.address_space)
            return fail(t, STELA_AIR_ARGUMENT, "unsupported buffer %u", index);
         bool threadgroup = desc.address_space == 3;
         bool *indices = threadgroup ? shared_indices : buffer_indices;
         unsigned limit = threadgroup ? t->max_threadgroup_buffers : t->max_device_buffers;
         if (indices[desc.index] || (limit && desc.index >= limit))
            return fail(t, STELA_AIR_METADATA, "duplicate buffer or location exceeds AIR module limit");
         indices[desc.index] = true;
         if (threadgroup) {
            struct stela_air_threadgroup_view view = {0};
            if (!has_size || !has_align || !desc.type_size || !desc.type_alignment ||
                !t->options->bind_threadgroup ||
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
            if (!def || def->num_components != 1 || def->bit_size != 64)
               return fail(t, STELA_AIR_ARGUMENT, "binding callback refused/invalid buffer %u", index);
         }
      } else {
         unsigned components, bits;
         if (!shape(LLVMTypeOf(param), &components, &bits) || bits != 32 ||
             (components != 1 && components != 3))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported thread-position type");
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
address_layout(struct translator *t)
{
   t->layout = LLVMGetModuleDataLayout(t->module);
   const char *layout = LLVMGetDataLayoutStr(t->module);
   if (!layout || !*layout || LLVMByteOrder(t->layout) != LLVMLittleEndian ||
       LLVMPointerSizeForAS(t->layout, 0) != 8 || LLVMPointerSizeForAS(t->layout, 1) != 8)
      return fail(t, STELA_AIR_TARGET, "requires explicit little-endian 64-bit AIR layout");
   /* LLVM's C DataLayout API does not expose pointer-index width. Validate only
    * that property here; actual allocation sizes/field offsets come from LLVM.
    * Nonintegral/external-state pointers need a different NIR representation. */
   for (const char *part = layout; *part;) {
      const char *end = strchr(part, '-');
      size_t length = end ? (size_t)(end - part) : strlen(part);
      if ((length > 3 && !memcmp(part, "ni:", 3)) || (length && *part == 'P'))
         return fail(t, STELA_AIR_TARGET, "unsupported nonintegral/program address-space layout");
      if (length && *part == 'p') {
         unsigned colons = 0;
         const char *last = NULL;
         for (size_t i = 0; i < length; i++) {
            if (part[i] == ':') {
               colons++;
               last = part + i + 1;
            }
         }
         if (colons > 4 || (colons == 4 &&
             ((size_t)(part + length - last) != 2 || memcmp(last, "64", 2))))
            return fail(t, STELA_AIR_TARGET, "unsupported pointer-index width");
      }
      part += length;
      if (*part)
         part++;
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
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS], fields[AIR_MAX_METADATA_OPERANDS];
   unsigned count, fields_count;
   if (t->air_minor != 9 || t->language_major != 4 || t->language_minor != 1 ||
       strcmp(LLVMGetTarget(t->module), "air64_v29-apple-macosx27.2.0") ||
       !named_md(t, "llvm.ident", nodes, &count) || count != 1 ||
       !md_node(t, nodes[0], fields, &fields_count) || fields_count != 1 ||
       !md_string(fields[0], "Apple metal version 32023.922 (metalfe-32023.922.4)"))
      return fail(t, STELA_AIR_METADATA, "shared-memory AIR/compiler profile is unqualified");
   if (LLVMPointerSizeForAS(t->layout, 3) != 8)
      return fail(t, STELA_AIR_TARGET, "shared-memory AIR pointers require 64-bit layout");
   return true;
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
shared_storage_size(struct translator *t, LLVMTypeRef type, unsigned depth,
                     uint64_t *size)
{
   if (depth == 32)
      return fail(t, STELA_AIR_LIMIT, "shared storage type nesting exceeded");
   if (LLVMGetTypeKind(type) == LLVMArrayTypeKind) {
      uint64_t element;
      if (!shared_storage_size(t, LLVMGetElementType(type), depth + 1, &element))
         return false;
      uint64_t length = LLVMGetArrayLength2(type);
      if (!length || length > UINT32_MAX / element)
         return fail(t, STELA_AIR_LIMIT, "shared storage array extent exceeded");
   } else {
      unsigned components, bits;
      if (!value_shape(type, &components, &bits) || bits < 8)
         return fail(t, STELA_AIR_TYPE, "shared globals require fixed integer/FP32 scalar/vector arrays");
   }
   /* Aggregate extents were bounded before invoking fixed-size LLVM queries. */
   *size = LLVMABISizeOfType(t->layout, type);
   return (*size && *size <= UINT32_MAX) ||
      fail(t, STELA_AIR_LIMIT, "shared storage allocation size exceeded");
}

static bool
shared_global_info(struct translator *t, LLVMValueRef global,
                    uint64_t *size, unsigned *alignment)
{
   const char *section = LLVMGetSection(global);
   LLVMValueRef initializer = LLVMGetInitializer(global);
   if (LLVMGetPointerAddressSpace(LLVMTypeOf(global)) != 3 ||
       LLVMGetLinkage(global) != LLVMInternalLinkage || LLVMIsThreadLocal(global) ||
       LLVMIsGlobalConstant(global) || LLVMIsExternallyInitialized(global) ||
       (section && *section) || !initializer || !LLVMIsUndef(initializer) || LLVMIsPoison(initializer))
      return fail(t, STELA_AIR_TARGET, "unsupported global/shared initializer or storage ABI");
   LLVMTypeRef type = LLVMGlobalGetValueType(global);
   if (!shared_storage_size(t, type, 0, size))
      return false;
   *alignment = LLVMGetAlignment(global);
   if (!*alignment)
      *alignment = LLVMABIAlignmentOfType(t->layout, type);
   return (*alignment && !(*alignment & (*alignment - 1))) ||
      fail(t, STELA_AIR_TYPE, "unsupported shared global alignment");
}

static bool
shared_globals(struct translator *t)
{
   unsigned count = 0;
   for (LLVMValueRef global = LLVMGetFirstGlobal(t->module); global;
        global = LLVMGetNextGlobal(global)) {
      uint64_t size;
      unsigned alignment;
      if (++count > AIR_MAX_ARGUMENTS)
         return fail(t, STELA_AIR_LIMIT, "shared global count exceeded");
      if (!shared_global_info(t, global, &size, &alignment))
         return false;
   }
   return true;
}

static nir_def *
shared_global(struct translator *t, LLVMValueRef global)
{
   uint64_t size;
   unsigned alignment;
   if (!shared_global_info(t, global, &size, &alignment))
      return NULL;
   nir_variable *var = shared_resource(t, size, alignment);
   if (!var || !put_value(t, global, nir_imm_int64(&t->b, 0), STELA_AIR_READ_WRITE))
      return NULL;
   struct value *value = find_value(t, global);
   value->shared = var;
   value->shared_size = (unsigned)size;
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
       LLVMGetPointerAddressSpace(result_type) != (base->shared ? 3 : 1)) {
      fail(t, STELA_AIR_MEMORY, "GEP requires a validated buffer/shared pointer");
      return NULL;
   }
   LLVMTypeRef type = LLVMGetGEPSourceElementType(inst);
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
   nir_push_if(b, valid);
   nir_def *offset = nir_u2u32(b, address->def);
   if (stored)
      nir_store_ssbo(b, stored, slot, offset, .align_mul = alignment);
   else
      loaded = nir_load_ssbo(b, components, bits, slot, offset, .align_mul = alignment);
   nir_push_else(b, NULL);
   nir_def *zero = stored ? NULL : nir_imm_zero(b, components, bits);
   nir_pop_if(b, NULL);
   return stored ? NULL : nir_if_phi(b, loaded, zero);
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
   nir_push_if(b, valid);
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
   nir_push_else(b, NULL);
   nir_def *zero = stored ? NULL : nir_imm_zero(b, components, bits);
   nir_pop_if(b, NULL);
   return stored ? NULL : nir_if_phi(b, loaded, zero);
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

static bool
instruction(struct translator *t, LLVMValueRef inst)
{
   LLVMOpcode op = LLVMGetInstructionOpcode(inst);
   t->b.fp_math_ctrl = fp_math_control(inst);
   unsigned components = 0, bits = 0;
   if (op == LLVMRet)
      return LLVMGetNumOperands(inst) == 0 || fail(t, STELA_AIR_TYPE, "compute kernel return value");
   if (op != LLVMStore && op != LLVMGetElementPtr && op != LLVMBitCast && op != LLVMCall &&
       !value_shape(LLVMTypeOf(inst), &components, &bits))
      return fail(t, STELA_AIR_TYPE, "unsupported AIR instruction result type (opcode %u)", op);
   if (op == LLVMGetElementPtr) {
      const struct value *origin;
      nir_def *def = gep(t, inst, &origin);
      if (!def || !put_value(t, inst, def, origin->access))
         return false;
      struct value *value = find_value(t, inst);
      value->ssbo = origin->ssbo;
      value->ssbo_slot = origin->ssbo_slot;
      value->shared = origin->shared;
      value->shared_size = origin->shared_size;
      return true;
   }
   if (op == LLVMBitCast) {
      unsigned src_components, src_bits;
      LLVMTypeRef source = LLVMTypeOf(LLVMGetOperand(inst, 0));
      if (LLVMGetTypeKind(source) == LLVMPointerTypeKind &&
          LLVMGetTypeKind(LLVMTypeOf(inst)) == LLVMPointerTypeKind &&
          (LLVMGetPointerAddressSpace(source) == 1 || LLVMGetPointerAddressSpace(source) == 3) &&
          LLVMGetPointerAddressSpace(LLVMTypeOf(inst)) == LLVMGetPointerAddressSpace(source)) {
         const struct value *origin = find_value(t, LLVMGetOperand(inst, 0));
         if (!origin || !origin->access || !put_value(t, inst, origin->def, origin->access))
            return fail(t, STELA_AIR_MEMORY, "pointer identity cast lacks buffer provenance");
         struct value *value = find_value(t, inst);
         value->ssbo = origin->ssbo;
         value->ssbo_slot = origin->ssbo_slot;
         value->shared = origin->shared;
         value->shared_size = origin->shared_size;
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
      if (!signed_conversion && !unsigned_conversion)
         return fail(t, STELA_AIR_INSTRUCTION, "unsupported AIR function/intrinsic call");
      if (!LLVMIsAFunction(callee) || !LLVMIsDeclaration(callee) ||
          LLVMGetFunctionCallConv(callee) != LLVMCCallConv ||
          LLVMGetInstructionCallConv(inst) != LLVMCCallConv || LLVMGetNumArgOperands(inst) != 1 ||
          LLVMCountParams(callee) != 1 || LLVMIsFunctionVarArg(LLVMGlobalGetValueType(callee)) ||
          LLVMGetTypeKind(LLVMTypeOf(inst)) != LLVMFloatTypeKind ||
          LLVMGetTypeKind(LLVMTypeOf(LLVMGetOperand(inst, 0))) != LLVMIntegerTypeKind ||
          LLVMGetIntTypeWidth(LLVMTypeOf(LLVMGetOperand(inst, 0))) != 32)
         return fail(t, STELA_AIR_TYPE, "unsupported AIR integer-to-FP conversion signature");
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
   if (op == LLVMFAdd || op == LLVMFSub || op == LLVMFMul || op == LLVMFCmp ||
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
                    op == LLVMShl || op == LLVMLShr || op == LLVMAShr))
      return fail(t, STELA_AIR_TYPE, "one-bit arithmetic/shift unsupported");
   if (op == LLVMICmp && LLVMGetTypeKind(LLVMTypeOf(LLVMGetOperand(inst, 0))) == LLVMPointerTypeKind)
      return fail(t, STELA_AIR_TYPE, "pointer comparison unsupported");
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
         return true;
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
    * poison, freeze, FP, division and all helper calls are explicitly refused. */
   nir_def *a = NULL, *b = NULL, *def = NULL;
   switch (op) {
   case LLVMAdd: case LLVMSub: case LLVMMul:
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

static struct air_block *
cfg_block(struct translator *t, LLVMBasicBlockRef llvm)
{
   for (unsigned i = 0; i < t->block_count; i++) {
      if (t->blocks[i].llvm == llvm)
         return &t->blocks[i];
   }
   return NULL;
}

static bool
cfg_visit(struct translator *t, struct air_block *block)
{
   if (block->visit == 1)
      return fail(t, STELA_AIR_CONTROL_FLOW, "cyclic AIR control flow unsupported");
   if (block->visit == 2)
      return true;
   block->visit = 1;
   LLVMValueRef terminator = LLVMGetBasicBlockTerminator(block->llvm);
   for (unsigned i = 0; i < LLVMGetNumSuccessors(terminator); i++) {
      struct air_block *next = cfg_block(t, LLVMGetSuccessor(terminator, i));
      if (!next)
         return false;
      if (next->visit == 1) {
         if (next->latch)
            return fail(t, STELA_AIR_CONTROL_FLOW, "multiple AIR loop backedges unsupported");
         next->latch = block;
      } else if (!cfg_visit(t, next)) {
         return false;
      }
   }
   block->visit = 2;
   return true;
}

static bool
cfg_loops(struct translator *t)
{
   for (unsigned h = 0; h < t->block_count; h++) {
      struct air_block *header = &t->blocks[h];
      if (!header->latch)
         continue;
      LLVMValueRef term = LLVMGetBasicBlockTerminator(header->llvm);
      LLVMValueRef latch_term = LLVMGetBasicBlockTerminator(header->latch->llvm);
      if (header == header->latch || header->predecessors != 2 ||
          LLVMGetInstructionOpcode(term) != LLVMCondBr ||
          LLVMGetInstructionOpcode(latch_term) != LLVMUncondBr ||
          LLVMGetSuccessor(latch_term, 0) != header->llvm)
         return fail(t, STELA_AIR_CONTROL_FLOW, "requires pre-tested AIR loop with distinct unconditional latch");

      /* Original natural-loop construction: walk predecessors of the latch,
       * stopping at the header. Fixed CFG/instruction budgets were checked
       * before this bounded walk. Validate every boundary edge afterwards;
       * an irreducible side entry cannot be mistaken for a loop preheader. */
      bool member[AIR_MAX_BLOCKS] = {0};
      struct air_block *stack[AIR_MAX_BLOCKS];
      unsigned count = 0;
      member[h] = true;
      member[header->latch - t->blocks] = true;
      stack[count++] = header->latch;
      while (count) {
         struct air_block *block = stack[--count];
         if (block == &t->blocks[0])
            return fail(t, STELA_AIR_CONTROL_FLOW, "AIR loop has no single entry header");
         for (unsigned p = 0; p < t->block_count; p++) {
            LLVMValueRef pred_term = LLVMGetBasicBlockTerminator(t->blocks[p].llvm);
            for (unsigned s = 0; s < LLVMGetNumSuccessors(pred_term); s++) {
               if (LLVMGetSuccessor(pred_term, s) == block->llvm && !member[p]) {
                  member[p] = true;
                  stack[count++] = &t->blocks[p];
               }
            }
         }
      }
      for (unsigned p = 0; p < t->block_count; p++) {
         LLVMValueRef pred_term = LLVMGetBasicBlockTerminator(t->blocks[p].llvm);
         if (member[p] && t->blocks[p].loop_header)
            return fail(t, STELA_AIR_CONTROL_FLOW, "nested/overlapping AIR loops unsupported");
         for (unsigned s = 0; s < LLVMGetNumSuccessors(pred_term); s++) {
            struct air_block *next = cfg_block(t, LLVMGetSuccessor(pred_term, s));
            bool inside = member[next - t->blocks];
            if (!member[p] && inside) {
               if (next != header || header->preheader ||
                   LLVMGetInstructionOpcode(pred_term) != LLVMUncondBr)
                  return fail(t, STELA_AIR_CONTROL_FLOW, "requires one unconditional AIR loop preheader");
               header->preheader = &t->blocks[p];
            } else if (member[p] && !inside) {
               if (&t->blocks[p] != header || header->loop_exit)
                  return fail(t, STELA_AIR_CONTROL_FLOW, "AIR loop body exit unsupported");
               header->loop_exit = next;
            }
         }
      }
      if (!header->preheader || !header->loop_exit)
         return fail(t, STELA_AIR_CONTROL_FLOW, "AIR loop requires one entry and one header exit");
      header->loop_body = cfg_block(t, LLVMGetSuccessor(term,
         LLVMGetSuccessor(term, 0) == header->loop_exit->llvm ? 1 : 0));
      if (!member[header->loop_body - t->blocks])
         return fail(t, STELA_AIR_CONTROL_FLOW, "AIR loop has no body successor");
      for (LLVMValueRef phi = LLVMGetFirstInstruction(header->llvm);
           phi && LLVMGetInstructionOpcode(phi) == LLVMPHI; phi = LLVMGetNextInstruction(phi)) {
         unsigned components, bits;
         if (!value_shape(LLVMTypeOf(phi), &components, &bits))
            return fail(t, STELA_AIR_TYPE, "only integer/FP32 scalar/vector loop PHIs supported");
         if (LLVMCountIncoming(phi) != 2 ||
             !((LLVMGetIncomingBlock(phi, 0) == header->preheader->llvm &&
                LLVMGetIncomingBlock(phi, 1) == header->latch->llvm) ||
               (LLVMGetIncomingBlock(phi, 1) == header->preheader->llvm &&
                LLVMGetIncomingBlock(phi, 0) == header->latch->llvm)))
            return fail(t, STELA_AIR_CONTROL_FLOW, "AIR loop PHIs require preheader and latch sources");
      }
      for (unsigned p = 0; p < t->block_count; p++) {
         if (member[p])
            t->blocks[p].loop_header = header;
      }
   }
   return true;
}

static bool
cfg_prepare(struct translator *t, LLVMValueRef fn)
{
   t->block_count = LLVMCountBasicBlocks(fn);
   if (!t->block_count || t->block_count > AIR_MAX_BLOCKS)
      return fail(t, STELA_AIR_LIMIT, "AIR basic-block budget exceeded");
   unsigned i = 0;
   for (LLVMBasicBlockRef block = LLVMGetFirstBasicBlock(fn); block;
        block = LLVMGetNextBasicBlock(block))
      t->blocks[i++].llvm = block;
   unsigned instructions = 0, returns = 0;
   for (i = 0; i < t->block_count; i++) {
      struct air_block *block = &t->blocks[i];
      LLVMValueRef term = LLVMGetBasicBlockTerminator(block->llvm);
      LLVMOpcode opcode = LLVMGetInstructionOpcode(term);
      if (opcode == LLVMRet) {
         returns++;
      } else if (opcode != LLVMUncondBr && opcode != LLVMCondBr) {
         return fail(t, STELA_AIR_CONTROL_FLOW, "unsupported AIR terminator %u", opcode);
      }
      if (opcode == LLVMCondBr &&
          LLVMGetSuccessor(term, 0) == LLVMGetSuccessor(term, 1))
         return fail(t, STELA_AIR_CONTROL_FLOW, "duplicate conditional edges unsupported");
      for (unsigned s = 0; s < LLVMGetNumSuccessors(term); s++) {
         struct air_block *next = cfg_block(t, LLVMGetSuccessor(term, s));
         if (!next)
            return fail(t, STELA_AIR_CONTROL_FLOW, "branch leaves AIR kernel");
         next->predecessors++;
      }
      unsigned phis = 0;
      for (LLVMValueRef inst = LLVMGetFirstInstruction(block->llvm); inst;
           inst = LLVMGetNextInstruction(inst)) {
         if (instructions == t->options->max_instructions) {
            t->error->instruction = instructions;
            return fail(t, STELA_AIR_LIMIT, "AIR instruction budget exceeded");
         }
         instructions++;
         if (LLVMGetInstructionOpcode(inst) == LLVMPHI && ++phis > AIR_MAX_MERGE_PHIS)
            return fail(t, STELA_AIR_LIMIT, "AIR merge PHI budget exceeded");
      }
   }
   if (returns != 1 || !cfg_visit(t, &t->blocks[0]))
      return fail(t, STELA_AIR_CONTROL_FLOW, "requires one compute return");
   for (i = 0; i < t->block_count; i++) {
      if (t->blocks[i].visit != 2)
         return fail(t, STELA_AIR_CONTROL_FLOW, "unreachable AIR blocks unsupported");
   }
   return cfg_loops(t);
}

struct arm_exit {
   struct air_block *merge;
   LLVMBasicBlockRef predecessor;
};

struct merge_phi {
   LLVMValueRef llvm;
   nir_def *then_value;
   nir_def *else_value;
};

static bool
phi_edge_value(struct translator *t, LLVMValueRef phi, LLVMBasicBlockRef predecessor,
               unsigned incoming_count, nir_def **value)
{
   unsigned components, bits;
   if (!value_shape(LLVMTypeOf(phi), &components, &bits))
      return fail(t, STELA_AIR_TYPE, "only integer/FP32 scalar/vector PHI values supported");
   if (LLVMCountIncoming(phi) != incoming_count)
      return fail(t, STELA_AIR_CONTROL_FLOW, "PHI predecessor count differs from structured merge");
   LLVMValueRef incoming = NULL;
   for (unsigned i = 0; i < incoming_count; i++) {
      if (LLVMGetIncomingBlock(phi, i) == predecessor) {
         if (incoming)
            return fail(t, STELA_AIR_CONTROL_FLOW, "duplicate PHI predecessor");
         incoming = LLVMGetIncomingValue(phi, i);
      }
   }
   if (!incoming)
      return fail(t, STELA_AIR_CONTROL_FLOW, "missing PHI predecessor edge");
   *value = get_value(t, incoming);
   return *value != NULL;
}

static bool
emit_block(struct translator *t, struct air_block *block, LLVMBasicBlockRef predecessor)
{
   if (block->emitted)
      return fail(t, STELA_AIR_CONTROL_FLOW, "overlapping/unstructured AIR regions");
   block->emitted = true;
   LLVMValueRef term = LLVMGetBasicBlockTerminator(block->llvm);
   for (LLVMValueRef inst = LLVMGetFirstInstruction(block->llvm); inst != term;
        inst = LLVMGetNextInstruction(inst)) {
      if (LLVMGetInstructionOpcode(inst) == LLVMPHI) {
         if (!find_value(t, inst)) {
            nir_def *value = NULL;
            if (block->predecessors != 1 ||
                !phi_edge_value(t, inst, predecessor, 1, &value) ||
                !put_value(t, inst, value, 0))
               return fail(t, STELA_AIR_CONTROL_FLOW, "unsupported standalone PHI");
            t->error->instruction++;
         }
      } else {
         if (!instruction(t, inst))
            return false;
         t->error->instruction++;
      }
   }
   t->error->instruction++;
   return true;
}

static bool emit_region(struct translator *t, struct air_block *block,
                        LLVMBasicBlockRef predecessor, unsigned depth, struct arm_exit *exit);

static bool
emit_loop(struct translator *t, struct air_block *header, unsigned depth)
{
   if (depth == AIR_MAX_CONTROL_DEPTH)
      return fail(t, STELA_AIR_LIMIT, "AIR control-flow nesting budget exceeded");
   struct {
      LLVMValueRef llvm;
      nir_def *initial;
      nir_phi_instr *nir;
   } phis[AIR_MAX_MERGE_PHIS];
   unsigned phi_count = 0;
   for (LLVMValueRef phi = LLVMGetFirstInstruction(header->llvm);
        phi && LLVMGetInstructionOpcode(phi) == LLVMPHI; phi = LLVMGetNextInstruction(phi)) {
      if (phi_count == AIR_MAX_MERGE_PHIS)
         return fail(t, STELA_AIR_LIMIT, "AIR loop PHI budget exceeded");
      phis[phi_count].llvm = phi;
      if (!phi_edge_value(t, phi, header->preheader->llvm, 2, &phis[phi_count].initial))
         return false;
      phi_count++;
   }
   nir_block *preheader = nir_cursor_current_block(t->b.cursor);
   nir_loop *loop = nir_push_loop(&t->b);
   /* Use original NIR's loop SSA construction. All header definitions exist
    * simultaneously, before translating any header/body use. Backedge sources
    * are attached to the real emitted latch, never sequentially substituted. */
   for (unsigned i = 0; i < phi_count; i++) {
      nir_phi_instr *phi = nir_phi_instr_create(t->b.shader);
      if (!phi)
         return fail(t, STELA_AIR_ALLOCATION, "AIR loop PHI allocation failed");
      nir_def_init(&phi->instr, &phi->def,
                   phis[i].initial->num_components, phis[i].initial->bit_size);
      nir_phi_instr_add_src(phi, preheader, phis[i].initial);
      phis[i].nir = phi;
      if (!put_value(t, phis[i].llvm, &phi->def, 0))
         return false;
      t->error->instruction++;
   }
   header->loop_active = true;
   if (!emit_block(t, header, NULL))
      return false;
   LLVMValueRef term = LLVMGetBasicBlockTerminator(header->llvm);
   nir_def *condition = get_value(t, LLVMGetCondition(term));
   if (!condition || condition->num_components != 1 || condition->bit_size != 1)
      return fail(t, STELA_AIR_TYPE, "loop branch requires scalar i1");
   nir_break_if(&t->b, LLVMGetSuccessor(term, 0) == header->loop_exit->llvm ?
                       condition : nir_inot(&t->b, condition));
   struct arm_exit backedge = {0};
   if (!emit_region(t, header->loop_body, header->llvm, depth + 1, &backedge))
      return false;
   if (backedge.merge != header || backedge.predecessor != header->latch->llvm)
      return fail(t, STELA_AIR_CONTROL_FLOW, "AIR loop body does not end at its latch");
   nir_block *latch = nir_cursor_current_block(t->b.cursor);
   for (unsigned i = 0; i < phi_count; i++) {
      nir_def *value = NULL;
      if (!phi_edge_value(t, phis[i].llvm, header->latch->llvm, 2, &value))
         return false;
      nir_phi_instr_add_src(phis[i].nir, latch, value);
   }
   nir_pop_loop(&t->b, loop);
   /* As required by nir_phi_instr_add_src, attach both sources before
    * inserting the instruction, so original NIR links every SSA use. */
   nir_cursor after_loop = t->b.cursor;
   t->b.cursor = nir_before_block(nir_loop_first_block(loop));
   for (unsigned i = 0; i < phi_count; i++)
      nir_builder_instr_insert(&t->b, &phis[i].nir->instr);
   t->b.cursor = after_loop;
   header->loop_active = false;
   return true;
}

static bool
loop_entry(struct air_block *block, LLVMBasicBlockRef predecessor)
{
   return block->latch && !block->loop_active && block->preheader->llvm == predecessor;
}

static bool
emit_region(struct translator *t, struct air_block *block, LLVMBasicBlockRef predecessor,
            unsigned depth, struct arm_exit *exit)
{
   if (depth > AIR_MAX_CONTROL_DEPTH)
      return fail(t, STELA_AIR_LIMIT, "AIR control-flow nesting budget exceeded");
   /* Bounded structured regions: unique-predecessor arms meet at a common
    * two-predecessor merge, or enter a previously validated natural loop. */
   if (predecessor && block->predecessors > 1 && !loop_entry(block, predecessor)) {
      *exit = (struct arm_exit){block, predecessor};
      return true;
   }
   while (block) {
      if (loop_entry(block, predecessor)) {
         if (!emit_loop(t, block, depth))
            return false;
         predecessor = block->llvm;
         block = block->loop_exit;
         if (block->predecessors > 1) {
            *exit = (struct arm_exit){block, predecessor};
            return true;
         }
         continue;
      }
      if (!emit_block(t, block, predecessor))
         return false;
      LLVMValueRef term = LLVMGetBasicBlockTerminator(block->llvm);
      if (LLVMGetInstructionOpcode(term) == LLVMRet) {
         if (depth || !instruction(t, term))
            return fail(t, STELA_AIR_CONTROL_FLOW, "return inside conditional arm unsupported");
         *exit = (struct arm_exit){0};
         return true;
      }
      if (LLVMGetInstructionOpcode(term) == LLVMUncondBr) {
         predecessor = block->llvm;
         block = cfg_block(t, LLVMGetSuccessor(term, 0));
         if (block->predecessors > 1 && !loop_entry(block, predecessor)) {
            *exit = (struct arm_exit){block, predecessor};
            return true;
         }
         continue;
      }
      if (depth == AIR_MAX_CONTROL_DEPTH)
         return fail(t, STELA_AIR_LIMIT, "AIR control-flow nesting budget exceeded");
      nir_def *condition = get_value(t, LLVMGetCondition(term));
      if (!condition || condition->num_components != 1 || condition->bit_size != 1)
         return fail(t, STELA_AIR_TYPE, "conditional branch requires scalar i1");
      struct arm_exit then_exit = {0}, else_exit = {0};
      struct merge_phi phis[AIR_MAX_MERGE_PHIS];
      unsigned phi_count = 0;
      nir_if *nif = nir_push_if(&t->b, condition);
      if (!emit_region(t, cfg_block(t, LLVMGetSuccessor(term, 0)), block->llvm,
                       depth + 1, &then_exit))
         return false;
      if (!then_exit.merge || then_exit.merge->predecessors != 2)
         return fail(t, STELA_AIR_CONTROL_FLOW, "requires two-predecessor structured merge");
      for (LLVMValueRef phi = LLVMGetFirstInstruction(then_exit.merge->llvm);
           phi && LLVMGetInstructionOpcode(phi) == LLVMPHI; phi = LLVMGetNextInstruction(phi)) {
         if (phi_count == AIR_MAX_MERGE_PHIS)
            return fail(t, STELA_AIR_LIMIT, "AIR merge PHI budget exceeded");
         phis[phi_count] = (struct merge_phi){.llvm = phi};
         if (!phi_edge_value(t, phi, then_exit.predecessor, 2, &phis[phi_count].then_value))
            return false;
         phi_count++;
      }
      nir_push_else(&t->b, nif);
      if (!emit_region(t, cfg_block(t, LLVMGetSuccessor(term, 1)), block->llvm,
                       depth + 1, &else_exit))
         return false;
      if (then_exit.merge != else_exit.merge ||
          then_exit.predecessor == else_exit.predecessor)
         return fail(t, STELA_AIR_CONTROL_FLOW, "conditional arms do not form a structured merge");
      for (unsigned i = 0; i < phi_count; i++) {
         if (!phi_edge_value(t, phis[i].llvm, else_exit.predecessor, 2, &phis[i].else_value))
            return false;
      }
      nir_pop_if(&t->b, nif);
      for (unsigned i = 0; i < phi_count; i++) {
         if (!put_value(t, phis[i].llvm,
                        nir_if_phi(&t->b, phis[i].then_value, phis[i].else_value), 0))
            return false;
         t->error->instruction++;
      }
      block = then_exit.merge;
      predecessor = NULL; /* Merge PHIs were handled simultaneously above. */
   }
   return fail(t, STELA_AIR_CONTROL_FLOW, "missing AIR region exit");
}

nir_shader *
stela_air_to_nir(const void *bitcode, size_t size, const char *entry,
                 const nir_shader_compiler_options *nir_options,
                 const struct stela_air_options *options,
                 struct stela_air_error *error)
{
   struct stela_air_error local_error = {0};
   if (!error)
      error = &local_error;
   *error = (struct stela_air_error){0};
   struct translator t = {.options = options, .error = error};
   if (!bitcode || size < 4 || size > AIR_MAX_BITCODE_BYTES ||
       memcmp(bitcode, "BC\xc0\xde", 4) || !entry || !*entry || !nir_options ||
       !options || !options->max_instructions || !options->workgroup_size[0] ||
       !options->workgroup_size[1] || !options->workgroup_size[2]) {
      fail(&t, STELA_AIR_INPUT, "invalid AIR bitcode/options");
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
   if (!address_layout(&t) || !module_metadata(&t) || !shared_globals(&t))
      goto done;
   char target_prefix[40];
   snprintf(target_prefix, sizeof(target_prefix), "air64_v2%u-apple-macosx", t.air_minor);
   if (strncmp(target, target_prefix, strlen(target_prefix))) {
      fail(&t, STELA_AIR_TARGET, "AIR version and target triple disagree");
      goto done;
   }
   LLVMValueRef fn = LLVMGetNamedFunction(t.module, entry);
   if (!fn || LLVMIsDeclaration(fn) || LLVMGetFunctionCallConv(fn) != LLVMCCallConv ||
       LLVMGetTypeKind(LLVMGetReturnType(LLVMGlobalGetValueType(fn))) != LLVMVoidTypeKind ||
       LLVMIsFunctionVarArg(LLVMGlobalGetValueType(fn))) {
      fail(&t, STELA_AIR_ARGUMENT, "entry must be a defined nonvariadic void C-convention kernel");
      goto done;
   }
   if (!cfg_prepare(&t, fn))
      goto done;
   t.entry = fn;
   t.b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, nir_options, "%s", entry);
   t.b.fp_math_ctrl = nir_fp_no_fast_math;
   if (options->fp_profile != STELA_AIR_FP_IEEE_DEFAULT && !fp_environment(&t))
      goto done;
   for (unsigned i = 0; i < 3; i++)
      t.b.shader->info.workgroup_size[i] = options->workgroup_size[i];
   t.b.shader->info.num_ssbos = options->ssbo_count;
   t.values = _mesa_pointer_hash_table_create(t.b.shader);
   if (!t.values || !kernel_arguments(&t, fn)) {
      fail(&t, STELA_AIR_ALLOCATION, "AIR shader/value map allocation failed");
      goto done;
   }
   struct arm_exit exit = {0};
   if (!emit_region(&t, &t.blocks[0], NULL, 0, &exit))
      goto done;
   if (exit.merge) {
      fail(&t, STELA_AIR_CONTROL_FLOW, "unpaired AIR merge region");
      goto done;
   }
   for (unsigned i = 0; i < t.block_count; i++) {
      if (!t.blocks[i].emitted) {
         fail(&t, STELA_AIR_CONTROL_FLOW, "unconsumed AIR control-flow region");
         goto done;
      }
   }
   if (t.shared_resources) {
      nir_lower_vars_to_explicit_types(t.b.shader, nir_var_mem_shared, glsl_get_natural_size_align_bytes);
      if (t.b.shader->info.shared_size > options->max_threadgroup_bytes) {
         fail(&t, STELA_AIR_LIMIT, "aligned shared layout exceeds target/backend byte limit");
         goto done;
      }
      nir_lower_explicit_io(t.b.shader, nir_var_mem_shared, nir_address_format_32bit_offset);
   }
   if (t.shared_resources || t.shared_barriers)
      nir_shader_gather_info(t.b.shader, nir_shader_get_entrypoint(t.b.shader));
   nir_validate_shader(t.b.shader, "AIR bounded compute translation");
   result = t.b.shader;
   t.b.shader = NULL;
   error->instruction = 0;

done:
   ralloc_free(t.b.shader);
   if (t.module)
      LLVMDisposeModule(t.module);
   LLVMContextDispose(t.context);
   return result;
}
