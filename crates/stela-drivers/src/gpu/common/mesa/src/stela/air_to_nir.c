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

struct value {
   nir_def *def;
   unsigned access; /* Buffer provenance; zero for integer values. */
   bool ssbo;
   unsigned ssbo_slot;
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
       !md_uint(fields[base + 2], &patch) ||
       major != (language ? 4 : 2) || minor != (language ? 0 : 8) || patch != 0)
      return fail(t, STELA_AIR_METADATA, "unsupported %s (qualified AIR 2.8 / Metal 4.0)", name);
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
                              "air.compile_options", "air.kernel", "llvm.ident"};
      bool found = false;
      for (unsigned i = 0; i < ARRAY_SIZE(allowed); i++)
         found |= size == strlen(allowed[i]) && !memcmp(name, allowed[i], size);
      if (!found)
         return fail(t, STELA_AIR_METADATA, "unsupported module metadata: %.*s",
                     (int)MIN2(size, 160), name);
   }
   if (!version_metadata(t, "air.version", false) ||
       !version_metadata(t, "air.language_version", true))
      return false;
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!named_md(t, "air.compile_options", nodes, &count))
      return false;
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned fields_count;
      if (!md_node(t, nodes[i], fields, &fields_count) || fields_count != 1 ||
          !(md_string(fields[0], "air.compile.denorms_disable") ||
            md_string(fields[0], "air.compile.fast_math_enable") ||
            md_string(fields[0], "air.compile.framebuffer_fetch_enable")))
         return fail(t, STELA_AIR_METADATA, "unsupported AIR compile option");
   }
   /* These options do not change the integer/buffer-only subset implemented
    * below. Floating point, images and framebuffer access remain refused. */
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

static nir_def *
get_value(struct translator *t, LLVMValueRef llvm)
{
   struct value *value = find_value(t, llvm);
   if (value)
      return value->def;
   unsigned components, bits;
   if (!shape(LLVMTypeOf(llvm), &components, &bits)) {
      fail(t, STELA_AIR_TYPE, "unsupported AIR operand type");
      return NULL;
   }
   if (LLVMIsAConstantAggregateZero(llvm))
      return nir_imm_zero(&t->b, components, bits);
   if (components == 1 && LLVMIsAConstantInt(llvm))
      return nir_imm_intN_t(&t->b, LLVMConstIntGetZExtValue(llvm), bits);
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
                locations != 1 || desc.index >= AIR_MAX_ARGUMENTS || buffer_indices[desc.index])
               return fail(t, STELA_AIR_METADATA, "unsupported/duplicate buffer location");
            buffer_indices[desc.index] = true;
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
      if (buffer) {
         LLVMTypeRef type = LLVMTypeOf(param);
         if (!has_location || !has_as || !desc.access || desc.address_space != 1 ||
             LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
             LLVMGetPointerAddressSpace(type) != desc.address_space ||
             (!t->options->bind_buffer && !t->options->bind_ssbo))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported/unbound device buffer %u", index);
         if (t->options->bind_ssbo) {
            if (!t->options->bind_ssbo(&desc, &ssbo_slot, t->options->binding_data) ||
                ssbo_slot >= t->options->ssbo_count || ssbo_slots[ssbo_slot])
               return fail(t, STELA_AIR_ARGUMENT, "SSBO callback refused/invalid slot for buffer %u", index);
            ssbo_slots[ssbo_slot] = true;
            /* The exact Metal view is the surface, not an inferred raw VA. */
            def = nir_imm_int64(&t->b, 0);
         } else {
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
      if (buffer && t->options->bind_ssbo) {
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

static nir_def *
gep(struct translator *t, LLVMValueRef inst, const struct value **origin)
{
   struct value *base = find_value(t, LLVMGetOperand(inst, 0));
   LLVMTypeRef result_type = LLVMTypeOf(inst);
   if (!base || !base->access || LLVMGetTypeKind(result_type) != LLVMPointerTypeKind ||
       LLVMGetPointerAddressSpace(result_type) != 1) {
      fail(t, STELA_AIR_MEMORY, "GEP requires a validated device-buffer pointer");
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
   unsigned components = 0, bits = 0;
   if (op == LLVMRet)
      return LLVMGetNumOperands(inst) == 0 || fail(t, STELA_AIR_TYPE, "compute kernel return value");
   if (op != LLVMStore && op != LLVMGetElementPtr &&
       !shape(LLVMTypeOf(inst), &components, &bits))
      return fail(t, STELA_AIR_TYPE, "unsupported AIR instruction result type (opcode %u)", op);
   if (op == LLVMGetElementPtr) {
      const struct value *origin;
      nir_def *def = gep(t, inst, &origin);
      if (!def || !put_value(t, inst, def, origin->access))
         return false;
      struct value *value = find_value(t, inst);
      value->ssbo = origin->ssbo;
      value->ssbo_slot = origin->ssbo_slot;
      return true;
   }
   if (bits == 1 && (op == LLVMAdd || op == LLVMSub || op == LLVMMul ||
                    op == LLVMShl || op == LLVMLShr || op == LLVMAShr))
      return fail(t, STELA_AIR_TYPE, "one-bit arithmetic/shift unsupported");
   if (op == LLVMICmp && LLVMGetTypeKind(LLVMTypeOf(LLVMGetOperand(inst, 0))) == LLVMPointerTypeKind)
      return fail(t, STELA_AIR_TYPE, "pointer comparison unsupported");
   if (op == LLVMLoad || op == LLVMStore) {
      LLVMValueRef pointer = LLVMGetOperand(inst, op == LLVMStore ? 1 : 0);
      struct value *address = find_value(t, pointer);
      unsigned required = op == LLVMStore ? STELA_AIR_WRITE : STELA_AIR_READ;
      if (!address || !(address->access & required) || LLVMGetVolatile(inst) ||
          LLVMGetOrdering(inst) != LLVMAtomicOrderingNotAtomic)
         return fail(t, STELA_AIR_MEMORY, "unsupported volatile/atomic/unbound/disallowed memory access");
      if (op == LLVMStore && !shape(LLVMTypeOf(LLVMGetOperand(inst, 0)), &components, &bits))
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
         if (address->ssbo)
            ssbo_access(t, address, value, components, bits, alignment);
         else
            nir_store_global(&t->b, value, address->def, .align_mul = alignment);
         return true;
      }
      if (address->ssbo)
         return put_value(t, inst, ssbo_access(t, address, NULL, components, bits, alignment), 0);
      return put_value(t, inst, nir_load_global(&t->b, components, bits,
                       address->def, .align_mul = alignment), 0);
   }
   /* The implemented arithmetic is integer-only. Flags restricting defined
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
   const char *prefix = "air64_v28-apple-macosx";
   size_t asm_size;
   LLVMGetModuleInlineAsm(t.module, &asm_size);
   if (strncmp(target, prefix, strlen(prefix)) || asm_size ||
       LLVMGetFirstGlobal(t.module) || LLVMGetFirstGlobalAlias(t.module) ||
       LLVMGetFirstGlobalIFunc(t.module)) {
      fail(&t, STELA_AIR_TARGET, "unsupported target/globals/inline assembly");
      goto done;
   }
   if (!address_layout(&t) || !module_metadata(&t))
      goto done;
   LLVMValueRef fn = LLVMGetNamedFunction(t.module, entry);
   if (!fn || LLVMIsDeclaration(fn) || LLVMGetFunctionCallConv(fn) != LLVMCCallConv ||
       LLVMGetTypeKind(LLVMGetReturnType(LLVMGlobalGetValueType(fn))) != LLVMVoidTypeKind ||
       LLVMIsFunctionVarArg(LLVMGlobalGetValueType(fn))) {
      fail(&t, STELA_AIR_ARGUMENT, "entry must be a defined nonvariadic void C-convention kernel");
      goto done;
   }
   if (LLVMCountBasicBlocks(fn) != 1) {
      fail(&t, STELA_AIR_CONTROL_FLOW, "only straight-line compute kernels supported");
      goto done;
   }
   t.b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, nir_options, "%s", entry);
   for (unsigned i = 0; i < 3; i++)
      t.b.shader->info.workgroup_size[i] = options->workgroup_size[i];
   t.b.shader->info.num_ssbos = options->ssbo_count;
   t.values = _mesa_pointer_hash_table_create(t.b.shader);
   if (!t.values || !kernel_arguments(&t, fn)) {
      fail(&t, STELA_AIR_ALLOCATION, "AIR shader/value map allocation failed");
      goto done;
   }
   for (LLVMValueRef inst = LLVMGetFirstInstruction(LLVMGetFirstBasicBlock(fn));
        inst; inst = LLVMGetNextInstruction(inst)) {
      if (error->instruction >= options->max_instructions) {
         fail(&t, STELA_AIR_LIMIT, "AIR instruction budget exceeded");
         goto done;
      }
      if (!instruction(&t, inst))
         goto done;
      error->instruction++;
   }
   nir_validate_shader(t.b.shader, "AIR integer compute translation");
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
