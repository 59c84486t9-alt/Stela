/* SPDX-License-Identifier: MIT */
#define STELA_AIR_METADATA_INTERNAL
#include "air_metadata.h"
#include "llvm-c/Analysis.h"
#include "llvm-c/BitReader.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MIN2(a,b) ((a) < (b) ? (a) : (b))
static bool
fail(struct stela_air_metadata *t, enum stela_air_error_kind kind, const char *fmt, ...)
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

bool
stela_air_md_string(LLVMValueRef value, const char *expected)
{
   if (!value || !LLVMIsAMDString(value))
      return false;
   unsigned length;
   const char *string = LLVMGetMDString(value, &length);
   return length == strlen(expected) && !memcmp(string, expected, length);
}

bool
stela_air_md_uint(LLVMValueRef value, unsigned *number)
{
   if (!value || !LLVMIsAConstantInt(value) ||
       LLVMGetIntTypeWidth(LLVMTypeOf(value)) > 32)
      return false;
   *number = LLVMConstIntGetZExtValue(value);
   return true;
}

bool
stela_air_md_node(struct stela_air_metadata *t, LLVMValueRef node, LLVMValueRef *operands,
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

bool
stela_air_named_md(struct stela_air_metadata *t, const char *name, LLVMValueRef *operands,
         unsigned *count)
{
   *count = LLVMGetNamedMetadataNumOperands(t->module, name);
   if (*count > AIR_MAX_METADATA_OPERANDS)
      return fail(t, STELA_AIR_LIMIT, "%s metadata budget exceeded", name);
   LLVMGetNamedMetadataOperands(t->module, name, operands);
   return true;
}

bool
stela_air_metadata_shared_profile(struct stela_air_metadata *t)
{
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS], fields[AIR_MAX_METADATA_OPERANDS];
   unsigned count, fields_count;
   if (t->air_minor != 9 || t->language_major != 4 || t->language_minor != 1 ||
       strcmp(LLVMGetTarget(t->module), "air64_v29-apple-macosx27.2.0") ||
       !stela_air_named_md(t, "llvm.ident", nodes, &count) || count != 1 ||
       !stela_air_md_node(t, nodes[0], fields, &fields_count) || fields_count != 1 ||
       !stela_air_md_string(fields[0], "Apple metal version 32023.922 (metalfe-32023.922.4)"))
      return fail(t, STELA_AIR_METADATA, "shared-memory AIR/compiler profile is unqualified");
   if (LLVMPointerSizeForAS(t->layout, 3) != 8)
      return fail(t, STELA_AIR_TARGET, "shared-memory AIR pointers require 64-bit layout");
   return true;
}

/* Fixed storage of integer and floating scalars, 2-4 lane vectors, arrays and
 * structs, at most UINT32_MAX bytes. */
static bool
storage_size(struct stela_air_metadata *t, LLVMTypeRef type, unsigned depth, unsigned *budget,
             uint64_t *size)
{
   if (depth == 32 || !*budget)
      return fail(t, STELA_AIR_LIMIT, "global storage type budget exceeded");
   (*budget)--;
   bool valid;
   switch (LLVMGetTypeKind(type)) {
   case LLVMArrayTypeKind: {
      uint64_t element;
      if (!storage_size(t, LLVMGetElementType(type), depth + 1, budget, &element))
         return false;
      if (element && LLVMGetArrayLength2(type) > UINT32_MAX / element)
         return fail(t, STELA_AIR_LIMIT, "global storage size exceeded");
      valid = true;
      break;
   }
   case LLVMStructTypeKind:
      if (LLVMIsOpaqueStruct(type))
         return fail(t, STELA_AIR_TYPE, "globals require fixed integer or floating storage");
      for (unsigned i = 0; i < LLVMCountStructElementTypes(type); i++) {
         uint64_t field;
         if (!storage_size(t, LLVMStructGetTypeAtIndex(type, i), depth + 1, budget, &field))
            return false;
      }
      valid = true;
      break;
   case LLVMVectorTypeKind: {
      LLVMTypeKind element = LLVMGetTypeKind(LLVMGetElementType(type));
      unsigned components = LLVMGetVectorSize(type);
      uint64_t bytes;
      valid = components >= 2 && components <= 4 && element != LLVMArrayTypeKind &&
              element != LLVMStructTypeKind && element != LLVMVectorTypeKind;
      if (valid && !storage_size(t, LLVMGetElementType(type), depth + 1, budget, &bytes))
         return false;
      break;
   }
   case LLVMIntegerTypeKind: {
      unsigned bits = LLVMGetIntTypeWidth(type);
      valid = bits == 8 || bits == 16 || bits == 32 || bits == 64;
      break;
   }
   case LLVMHalfTypeKind:
   case LLVMFloatTypeKind:
      valid = true;
      break;
   default:
      valid = false;
      break;
   }
   if (!valid)
      return fail(t, STELA_AIR_TYPE, "globals require fixed integer or floating storage");
   /* Extents were bounded before invoking fixed-size LLVM queries. */
   *size = LLVMABISizeOfType(t->layout, type);
   return *size <= UINT32_MAX || fail(t, STELA_AIR_LIMIT, "global storage size exceeded");
}

/* Threadgroup memory is an undefined internal AS3 global; constant data is an
 * initialized internal or private AS2 constant. */
bool
stela_air_metadata_global(struct stela_air_metadata *t, LLVMValueRef global,
                          struct stela_air_global *info)
{
   const char *section = LLVMGetSection(global);
   LLVMValueRef initializer = LLVMGetInitializer(global);
   unsigned space = LLVMGetPointerAddressSpace(LLVMTypeOf(global));
   LLVMLinkage linkage = LLVMGetLinkage(global);
   bool constant = LLVMIsGlobalConstant(global);
   bool threadgroup = space == 3 && !constant && linkage == LLVMInternalLinkage && initializer &&
                      LLVMIsUndef(initializer) && !LLVMIsPoison(initializer);
   bool data = space == 2 && constant && initializer &&
               (linkage == LLVMInternalLinkage || linkage == LLVMPrivateLinkage);
   if ((!threadgroup && !data) || LLVMIsThreadLocal(global) || LLVMIsExternallyInitialized(global) ||
       (section && *section))
      return fail(t, STELA_AIR_TARGET, "unsupported global storage or initializer ABI");
   size_t metadata_count;
   LLVMValueMetadataEntry *metadata = LLVMGlobalCopyAllMetadata(global, &metadata_count);
   LLVMDisposeValueMetadataEntries(metadata);
   if (metadata_count)
      return fail(t, STELA_AIR_TARGET, "unsupported global metadata");
   if (LLVMPointerSizeForAS(t->layout, space) != 8)
      return fail(t, STELA_AIR_TARGET, "global pointers require 64-bit layout");
   LLVMTypeRef type = LLVMGlobalGetValueType(global);
   unsigned budget = 4096;
   *info = (struct stela_air_global){.constant = constant};
   if (!storage_size(t, type, 0, &budget, &info->size))
      return false;
   if (!info->size)
      return fail(t, STELA_AIR_TYPE, "globals require nonempty storage");
   info->alignment = LLVMGetAlignment(global);
   if (!info->alignment)
      info->alignment = LLVMABIAlignmentOfType(t->layout, type);
   return (info->alignment && !(info->alignment & (info->alignment - 1))) ||
      fail(t, STELA_AIR_TYPE, "unsupported global alignment");
}

bool
stela_air_metadata_globals(struct stela_air_metadata *t, bool *threadgroup)
{
   unsigned count = 0;
   *threadgroup = false;
   for (LLVMValueRef global = LLVMGetFirstGlobal(t->module); global;
        global = LLVMGetNextGlobal(global)) {
      struct stela_air_global info;
      if (++count > AIR_MAX_ARGUMENTS)
         return fail(t, STELA_AIR_LIMIT, "global count exceeded");
      if (!stela_air_metadata_global(t, global, &info))
         return false;
      *threadgroup |= !info.constant;
   }
   return true;
}

static bool
version_metadata(struct stela_air_metadata *t, const char *name, bool language)
{
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned count, fields_count, major, minor, patch;
   if (!stela_air_named_md(t, name, nodes, &count) || count != 1 ||
       !stela_air_md_node(t, nodes[0], fields, &fields_count))
      return fail(t, STELA_AIR_METADATA, "missing or invalid %s", name);
   unsigned base = language ? 1 : 0;
   if (fields_count != base + 3 || (language && !stela_air_md_string(fields[0], "Metal")) ||
       !stela_air_md_uint(fields[base], &major) || !stela_air_md_uint(fields[base + 1], &minor) ||
       !stela_air_md_uint(fields[base + 2], &patch) || patch != 0)
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
module_flags(struct stela_air_metadata *t)
{
   /* These are the LLVM IR serialized behavior values, not the smaller C API
    * LLVMModuleFlagBehavior enum (which does not expose Max in LLVM 23). */
   enum { IR_FLAG_ERROR = 1, IR_FLAG_MAX = 7 };
   const char *keys[] = {"wchar_size", "frame-pointer", "air.max_device_buffers",
      "air.max_constant_buffers", "air.max_threadgroup_buffers", "air.max_textures",
      "air.max_read_write_textures", "air.max_samplers"};
   LLVMValueRef flags[AIR_MAX_METADATA_OPERANDS];
   unsigned count, seen = 0;
   if (!stela_air_named_md(t, "llvm.module.flags", flags, &count))
      return false;
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned field_count, behavior, value, key;
      if (!stela_air_md_node(t, flags[i], fields, &field_count) || field_count != 3 ||
          !stela_air_md_uint(fields[0], &behavior) || !stela_air_md_uint(fields[2], &value))
         return fail(t, STELA_AIR_METADATA, "unsupported module flag shape");
      for (key = 0; key < ARRAY_SIZE(keys); key++) {
         if (stela_air_md_string(fields[1], keys[key]))
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
      if (key == 3)
         t->max_constant_buffers = value;
   }
   /* No linking, CPU frame operations or source wchar operations occur in the
    * implemented compute subset. Other resource kinds remain refused.
    * Device/threadgroup location bounds are enforced below, never advertised as the
    * hardware's actual Metal capability or silently removed from the input. */
   return true;
}

bool
stela_air_metadata_validate(struct stela_air_metadata *t)
{
   for (LLVMNamedMDNodeRef node = LLVMGetFirstNamedMetadata(t->module); node;
        node = LLVMGetNextNamedMetadata(node)) {
      size_t size;
      const char *name = LLVMGetNamedMetadataName(node, &size);
      const char *allowed[] = {"air.version", "air.language_version",
                              "air.compile_options", "air.kernel", "llvm.ident",
                              "llvm.module.flags"};
      bool found = t->render &&
         ((size == 10 && !memcmp(name, "air.vertex", size)) ||
          (size == 12 && !memcmp(name, "air.fragment", size)));
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
   if (!stela_air_named_md(t, "air.compile_options", nodes, &count))
      return false;
   unsigned seen = 0;
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned fields_count;
      if (!stela_air_md_node(t, nodes[i], fields, &fields_count) || fields_count != 1 ||
          !(stela_air_md_string(fields[0], "air.compile.denorms_disable") ||
            stela_air_md_string(fields[0], "air.compile.fast_math_enable") ||
            stela_air_md_string(fields[0], "air.compile.framebuffer_fetch_enable") ||
            stela_air_md_string(fields[0], "air.compile.framebuffer_fetch_disable")))
         return fail(t, STELA_AIR_METADATA, "unsupported AIR compile option");
      unsigned bit = stela_air_md_string(fields[0], "air.compile.denorms_disable") ? 1 :
                     stela_air_md_string(fields[0], "air.compile.fast_math_enable") ? 2 : 4;
      if (seen & bit)
         return fail(t, STELA_AIR_METADATA, "duplicate/conflicting AIR compile option");
      seen |= bit;
      if (bit == 4) {
         t->framebuffer_fetch_present = true;
         t->framebuffer_fetch_enabled = stela_air_md_string(fields[0], "air.compile.framebuffer_fetch_enable");
      }
   }
   t->denorms_disable = seen & 1;
   t->fast_math = seen & 2;
   /* Arithmetic requires an explicit qualified FP policy for this private AIR
    * option. Exact storage/shared access and integer operations do not depend
    * on FP denorm mode. */
   return true;
}

bool
stela_air_metadata_layout(struct stela_air_metadata *t)
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

/* This is only a conservative public-reflection classification. Unknown/struct
 * types are NOT inferred to lack argument buffers. It changes no NIR admission.
 * MSL argument buffers require structures; builtin scalar/vector buffer elements
 * cannot describe such a structure. Exact IR/layout validation remains separate. */
static enum stela_air_primitive
primitive_type(LLVMValueRef name, unsigned *components)
{
   const char *scalar[] = {"char", "uchar", "short", "ushort", "int", "uint", "long", "ulong", "float",
                           "half"};
   for (unsigned i = 0; i < ARRAY_SIZE(scalar); i++) {
      for (unsigned n = 1; n <= 4; n++) {
         char type[16];
         if (n == 1)
            snprintf(type, sizeof(type), "%s", scalar[i]);
         else
            snprintf(type, sizeof(type), "%s%u", scalar[i], n);
         if (stela_air_md_string(name, type)) {
            *components = n;
            return STELA_AIR_CHAR + i;
         }
      }
   }
   *components = 0;
   return STELA_AIR_PRIMITIVE_UNKNOWN;
}

/* A texture's reflected type name, "<type><<component>, <access>>" with
 * optional spaces: the MTLTextureType and component type. The access comes
 * from the argument's own access key. */
static bool
texture_type(const char *name, unsigned bytes, struct stela_air_texture *texture)
{
   static const struct {
      const char *name;
      enum stela_air_texture_type type;
      bool depth;
   } types[] = {
      {"texture1d", STELA_AIR_TEXTURE_1D}, {"texture1d_array", STELA_AIR_TEXTURE_1D_ARRAY},
      {"texture2d", STELA_AIR_TEXTURE_2D}, {"texture2d_array", STELA_AIR_TEXTURE_2D_ARRAY},
      {"texture2d_ms", STELA_AIR_TEXTURE_2D_MS},
      {"texture2d_ms_array", STELA_AIR_TEXTURE_2D_MS_ARRAY},
      {"texture3d", STELA_AIR_TEXTURE_3D}, {"texturecube", STELA_AIR_TEXTURE_CUBE},
      {"texturecube_array", STELA_AIR_TEXTURE_CUBE_ARRAY},
      {"texture_buffer", STELA_AIR_TEXTURE_BUFFER},
      {"depth2d", STELA_AIR_TEXTURE_2D, true}, {"depth2d_array", STELA_AIR_TEXTURE_2D_ARRAY, true},
      {"depth2d_ms", STELA_AIR_TEXTURE_2D_MS, true},
      {"depth2d_ms_array", STELA_AIR_TEXTURE_2D_MS_ARRAY, true},
      {"depthcube", STELA_AIR_TEXTURE_CUBE, true},
      {"depthcube_array", STELA_AIR_TEXTURE_CUBE_ARRAY, true},
   };
   static const struct {
      const char *name;
      enum stela_air_primitive primitive;
   } components[] = {
      {"float", STELA_AIR_FLOAT}, {"half", STELA_AIR_HALF}, {"int", STELA_AIR_INT},
      {"uint", STELA_AIR_UINT}, {"short", STELA_AIR_SHORT}, {"ushort", STELA_AIR_USHORT},
   };
   const char *open = memchr(name, '<', bytes);
   const char *end = name + bytes;
   if (!open || end[-1] != '>')
      return false;
   size_t type_bytes = (size_t)(open - name);
   const char *component = open + 1;
   while (component < end && *component == ' ')
      component++;
   const char *comma = memchr(component, ',', (size_t)(end - component));
   if (!comma)
      return false;
   size_t component_bytes = (size_t)(comma - component);
   while (component_bytes && component[component_bytes - 1] == ' ')
      component_bytes--;
   texture->type = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(types); i++) {
      if (strlen(types[i].name) == type_bytes && !memcmp(types[i].name, name, type_bytes)) {
         texture->type = types[i].type;
         texture->depth = types[i].depth;
      }
   }
   texture->primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
   for (unsigned i = 0; i < ARRAY_SIZE(components); i++) {
      if (strlen(components[i].name) == component_bytes &&
          !memcmp(components[i].name, component, component_bytes))
         texture->primitive = components[i].primitive;
   }
   return texture->type && texture->primitive &&
          (!texture->depth || texture->primitive == STELA_AIR_FLOAT);
}

/* This is reflection admission, not a change to executable/NIR admission.
 * Reject unknown function metadata/string attributes and unqualified globals
 * instead of claiming absent annotations/constants/static-resource reflection.
 * Threadgroup memory and constant data globals add no function argument;
 * actual selected-entry allocation remains the original NIR compiler's work. The
 * accepted strings are standard LLVM code-generation/FP attributes observed in
 * the retained original AIR, not arbitrary app or compiler-name exceptions. */
static bool
complete_reflection(struct stela_air_metadata *m, LLVMValueRef fn,
                    const struct stela_air_kernel *kernel)
{
   if (LLVMGetFirstGlobal(m->module)) {
      /* Reflection incompleteness is observational, not an inspection failure.
       * Keep executable/profile diagnostics local to this conservative query. */
      struct stela_air_error observed_error = {0};
      struct stela_air_metadata observed = *m;
      observed.error = &observed_error;
      bool threadgroup;
      if (!stela_air_metadata_globals(&observed, &threadgroup) ||
          (threadgroup && !stela_air_metadata_shared_profile(&observed)))
         return false;
   }
   size_t metadata_count;
   LLVMValueMetadataEntry *metadata = LLVMGlobalCopyAllMetadata(fn, &metadata_count);
   LLVMDisposeValueMetadataEntries(metadata);
   if (metadata_count)
      return false;
   unsigned count = LLVMGetAttributeCountAtIndex(fn, LLVMAttributeFunctionIndex);
   if (count > AIR_MAX_METADATA_OPERANDS)
      return false;
   LLVMAttributeRef attributes[AIR_MAX_METADATA_OPERANDS];
   LLVMGetAttributesAtIndex(fn, LLVMAttributeFunctionIndex, attributes);
   const char *allowed[] = {"approx-func-fp-math", "frame-pointer", "min-legal-vector-width",
      "no-builtins", "no-infs-fp-math", "no-nans-fp-math", "no-signed-zeros-fp-math",
      "no-trapping-math", "stack-protector-buffer-size", "unsafe-fp-math"};
   for (unsigned a = 0; a < count; a++) {
      if (!LLVMIsStringAttribute(attributes[a]))
         continue;
      unsigned bytes;
      const char *key = LLVMGetStringAttributeKind(attributes[a], &bytes);
      bool found = false;
      for (unsigned i = 0; i < ARRAY_SIZE(allowed); i++)
         found |= bytes == strlen(allowed[i]) && !memcmp(key, allowed[i], bytes);
      if (!found)
         return false;
   }
   for (unsigned a = 0; a < kernel->count; a++) {
      const struct stela_air_argument *arg = &kernel->arguments[a];
      if (!arg->is_buffer)
         continue;
      if (!arg->plain_buffer_type || !arg->name_bytes || arg->name_bytes > 4096 ||
          memchr(arg->name, 0, arg->name_bytes))
         return false;
      unsigned scalar = arg->primitive <= STELA_AIR_UCHAR ? 1 :
                        arg->primitive <= STELA_AIR_USHORT ? 2 :
                        arg->primitive == STELA_AIR_LONG || arg->primitive == STELA_AIR_ULONG ? 8 : 4;
      unsigned extent = scalar * (arg->type_components == 3 ? 4 : arg->type_components);
      if (arg->buffer.type_size != extent || arg->buffer.type_alignment != extent)
         return false;
      /* Unknown parameter string attributes could carry unimplemented source
       * reflection; only the observed AIR alias contract is recognized here. */
      count = LLVMGetAttributeCountAtIndex(fn, arg->buffer.argument + 1);
      if (count > AIR_MAX_METADATA_OPERANDS)
         return false;
      LLVMGetAttributesAtIndex(fn, arg->buffer.argument + 1, attributes);
      for (unsigned i = 0; i < count; i++) {
         if (!LLVMIsStringAttribute(attributes[i]))
            continue;
         unsigned bytes;
         const char *key = LLVMGetStringAttributeKind(attributes[i], &bytes);
         if (bytes != strlen("air-buffer-no-alias") || memcmp(key, "air-buffer-no-alias", bytes))
            return false;
      }
   }
   return true;
}

/* UTF-8 scalar validation is bounded by the explicit metadata string length.
 * No locale-dependent normalization: opaque linkage bytes compare exactly. */
static bool
stage_text(const char *s, size_t n)
{
   if (!s || !n || n > 4096) return false;
   for (size_t i = 0; i < n;) {
      unsigned a = (unsigned char)s[i++], value, count, minimum;
      if (!a) return false;
      if (a < 0x80) continue;
      if (a >= 0xc2 && a <= 0xdf) { value = a & 31; count = 1; minimum = 0x80; }
      else if (a >= 0xe0 && a <= 0xef) { value = a & 15; count = 2; minimum = 0x800; }
      else if (a >= 0xf0 && a <= 0xf4) { value = a & 7; count = 3; minimum = 0x10000; }
      else return false;
      if (count > n - i) return false;
      while (count--) {
         unsigned b = (unsigned char)s[i++];
         if ((b & 0xc0) != 0x80) return false;
         value = (value << 6) | (b & 63);
      }
      if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
   }
   return true;
}

static bool
metadata_text(struct stela_air_metadata *m, LLVMValueRef v, const char **s, size_t *n)
{
   if (!v || !LLVMIsAMDString(v)) return fail(m, STELA_AIR_METADATA, "expected stage metadata string");
   unsigned bytes;
   *s = LLVMGetMDString(v, &bytes); *n = bytes;
   return stage_text(*s, *n) || fail(m, STELA_AIR_METADATA, "invalid stage metadata text");
}

static unsigned
primitive_bytes(enum stela_air_primitive p)
{
   return p == STELA_AIR_CHAR || p == STELA_AIR_UCHAR ? 1 :
          p == STELA_AIR_SHORT || p == STELA_AIR_USHORT || p == STELA_AIR_HALF ? 2 :
          p == STELA_AIR_INT || p == STELA_AIR_UINT || p == STELA_AIR_FLOAT ? 4 :
          p == STELA_AIR_LONG || p == STELA_AIR_ULONG ? 8 : 0;
}

static bool
stage_type_matches(LLVMTypeRef type, enum stela_air_primitive p, unsigned n)
{
   if (!n || n > 4) return false;
   if (n > 1) {
      if (LLVMGetTypeKind(type) != LLVMVectorTypeKind || LLVMGetVectorSize(type) != n) return false;
      type = LLVMGetElementType(type);
   }
   return p == STELA_AIR_FLOAT ? LLVMGetTypeKind(type) == LLVMFloatTypeKind :
      p == STELA_AIR_HALF ? LLVMGetTypeKind(type) == LLVMHalfTypeKind :
      primitive_bytes(p) && LLVMGetTypeKind(type) == LLVMIntegerTypeKind &&
      LLVMGetIntTypeWidth(type) == primitive_bytes(p) * 8;
}

/* These types are fixed, sized builtin leaves selected from validated metadata.
 * Never ask DataLayout to size an unvalidated source/scalable/opaque type. */
static bool
stage_primitive_layout(struct stela_air_metadata *m, enum stela_air_primitive p,
                       unsigned components, unsigned size, unsigned alignment)
{
   unsigned bytes = primitive_bytes(p);
   if (!bytes || !components || components > 4)
      return fail(m, STELA_AIR_TYPE, "unsupported reflected primitive storage");
   LLVMContextRef context = LLVMGetModuleContext(m->module);
   LLVMTypeRef type = p == STELA_AIR_FLOAT ? LLVMFloatTypeInContext(context) :
      p == STELA_AIR_HALF ? LLVMHalfTypeInContext(context) : LLVMIntTypeInContext(context, bytes * 8);
   if (components > 1) type = LLVMVectorType(type, components);
   return (LLVMABISizeOfType(m->layout, type) == size &&
           LLVMABIAlignmentOfType(m->layout, type) == alignment) ||
      fail(m, STELA_AIR_TYPE, "reflected primitive storage differs from IR DataLayout");
}

static bool
stage_struct(struct stela_air_metadata *m, struct stela_air_render *r,
              struct stela_air_stage_io *io, LLVMValueRef node)
{
   if (!node) {
      unsigned bytes = primitive_bytes(io->primitive) * (io->components == 3 ? 4 : io->components);
      if (!bytes || bytes != io->buffer.type_size || bytes != io->buffer.type_alignment)
         return fail(m, STELA_AIR_ARGUMENT, "constant buffer reflection requires exact primitive or understood structure");
      return stage_primitive_layout(m, io->primitive, io->components,
                                    io->buffer.type_size, io->buffer.type_alignment);
   }
   if (io->primitive != STELA_AIR_PRIMITIVE_UNKNOWN)
      return fail(m, STELA_AIR_METADATA, "primitive buffer has structure metadata");
   LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_md_node(m, node, fields, &count) || !count || count % 5 ||
       count / 5 > AIR_MAX_ARGUMENTS - r->member_count)
      return fail(m, STELA_AIR_LIMIT, "structure reflection member budget/shape exceeded");
   io->members = &r->members[r->member_count];
   unsigned end = 0, align = 1;
   for (unsigned i = 0; i < count; i += 5) {
      struct stela_air_struct_member *member = &r->members[r->member_count++];
      unsigned flags;
      if (!stela_air_md_uint(fields[i], &member->offset) ||
          !stela_air_md_uint(fields[i + 1], &member->size) ||
          !stela_air_md_uint(fields[i + 2], &flags) || flags ||
          !metadata_text(m, fields[i + 3], &member->type_name, &member->type_name_bytes) ||
          !metadata_text(m, fields[i + 4], &member->name, &member->name_bytes))
         return fail(m, STELA_AIR_METADATA, "unsupported structure reflection member");
      member->primitive = primitive_type(fields[i + 3], &member->components);
      unsigned bytes = primitive_bytes(member->primitive) * (member->components == 3 ? 4 : member->components);
      if (!bytes || member->size != bytes || member->offset < end || member->offset % bytes ||
          member->offset > io->buffer.type_size || bytes > io->buffer.type_size - member->offset)
         return fail(m, STELA_AIR_TYPE, "structure reflection layout is inconsistent");
      if (!stage_primitive_layout(m, member->primitive, member->components, bytes, bytes))
         return false;
      unsigned expected = (end + bytes - 1) & ~(bytes - 1);
      if (expected != member->offset)
         return fail(m, STELA_AIR_TYPE, "unsupported explicit structure padding");
      end = member->offset + bytes;
      if (bytes > align) align = bytes;
      io->member_count++;
   }
   return (io->buffer.type_alignment == align &&
           ((end + align - 1) & ~(align - 1)) == io->buffer.type_size) ||
      fail(m, STELA_AIR_TYPE, "structure reflection extent/alignment mismatch");
}

bool
stela_air_metadata_stage_buffer_type(struct stela_air_metadata *m,
                                     const struct stela_air_stage_io *io, LLVMTypeRef type)
{
   if (!io->member_count) {
      if (!stage_type_matches(type, io->primitive, io->components))
         return fail(m, STELA_AIR_TYPE, "constant view source type differs from reflection");
      return (LLVMABISizeOfType(m->layout, type) == io->buffer.type_size &&
              LLVMABIAlignmentOfType(m->layout, type) == io->buffer.type_alignment) ||
         fail(m, STELA_AIR_TYPE, "constant-view IR allocation differs from reflection");
   }
   /* Every leaf is checked before ANY fixed-size DataLayout query; opaque,
    * scalable, target-extension, nested and unsized storage are refused. */
   if (LLVMGetTypeKind(type) != LLVMStructTypeKind || LLVMIsOpaqueStruct(type) ||
       LLVMIsPackedStruct(type) || LLVMCountStructElementTypes(type) != io->member_count)
      return fail(m, STELA_AIR_TYPE, "unsupported constant-view structure type");
   for (unsigned i = 0; i < io->member_count; i++) {
      const struct stela_air_struct_member *a = &io->members[i];
      if (!stage_type_matches(LLVMStructGetTypeAtIndex(type, i), a->primitive, a->components))
         return fail(m, STELA_AIR_TYPE, "constant-view member type differs from reflection");
   }
   if (LLVMABISizeOfType(m->layout, type) != io->buffer.type_size ||
       LLVMABIAlignmentOfType(m->layout, type) != io->buffer.type_alignment)
      return fail(m, STELA_AIR_TYPE, "constant-view IR allocation differs from reflection");
   for (unsigned i = 0; i < io->member_count; i++) {
      if (LLVMOffsetOfElement(m->layout, type, i) != io->members[i].offset)
         return fail(m, STELA_AIR_TYPE, "constant-view IR member offset differs from reflection");
   }
   return true;
}

/* The builtin input an argument descriptor's kind names, when the stage has
 * it. Positions and sizes have up to three lanes; the rest are scalars. */
static enum stela_air_builtin
builtin_input(LLVMValueRef kind, const struct stela_air_render *render, unsigned *lanes)
{
   enum { KERNEL = 1, VERTEX = 2, FRAGMENT = 4, RENDER = VERTEX | FRAGMENT, ALL = 7 };
   static const struct {
      const char *name;
      enum stela_air_builtin builtin;
      unsigned stages, lanes;
   } builtins[] = {
      {"air.thread_position_in_grid", STELA_AIR_THREAD_POSITION_IN_GRID, KERNEL, 3},
      {"air.thread_position_in_threadgroup", STELA_AIR_THREAD_POSITION_IN_THREADGROUP, KERNEL, 3},
      {"air.threadgroup_position_in_grid", STELA_AIR_THREADGROUP_POSITION_IN_GRID, KERNEL, 3},
      {"air.threads_per_threadgroup", STELA_AIR_THREADS_PER_THREADGROUP, KERNEL, 3},
      {"air.dispatch_threads_per_threadgroup", STELA_AIR_DISPATCH_THREADS_PER_THREADGROUP, KERNEL, 3},
      {"air.threadgroups_per_grid", STELA_AIR_THREADGROUPS_PER_GRID, KERNEL, 3},
      {"air.threads_per_grid", STELA_AIR_THREADS_PER_GRID, KERNEL, 3},
      {"air.thread_index_in_threadgroup", STELA_AIR_THREAD_INDEX_IN_THREADGROUP, KERNEL, 1},
      {"air.simdgroup_index_in_threadgroup", STELA_AIR_SIMDGROUP_INDEX_IN_THREADGROUP, KERNEL, 1},
      {"air.simdgroups_per_threadgroup", STELA_AIR_SIMDGROUPS_PER_THREADGROUP, KERNEL, 1},
      {"air.dispatch_simdgroups_per_threadgroup", STELA_AIR_DISPATCH_SIMDGROUPS_PER_THREADGROUP,
       KERNEL, 1},
      {"air.quadgroup_index_in_threadgroup", STELA_AIR_QUADGROUP_INDEX_IN_THREADGROUP, KERNEL, 1},
      {"air.quadgroups_per_threadgroup", STELA_AIR_QUADGROUPS_PER_THREADGROUP, KERNEL, 1},
      {"air.dispatch_quadgroups_per_threadgroup", STELA_AIR_DISPATCH_QUADGROUPS_PER_THREADGROUP,
       KERNEL, 1},
      {"air.thread_index_in_simdgroup", STELA_AIR_THREAD_INDEX_IN_SIMDGROUP, ALL, 1},
      {"air.threads_per_simdgroup", STELA_AIR_THREADS_PER_SIMDGROUP, ALL, 1},
      {"air.thread_execution_width", STELA_AIR_THREAD_EXECUTION_WIDTH, ALL, 1},
      {"air.thread_index_in_quadgroup", STELA_AIR_THREAD_INDEX_IN_QUADGROUP, ALL, 1},
      {"air.vertex_id", STELA_AIR_VERTEX_ID, VERTEX, 1},
      {"air.instance_id", STELA_AIR_INSTANCE_ID, VERTEX, 1},
      {"air.base_vertex", STELA_AIR_BASE_VERTEX, VERTEX, 1},
      {"air.base_instance", STELA_AIR_BASE_INSTANCE, VERTEX, 1},
      {"air.amplification_id", STELA_AIR_AMPLIFICATION_ID, RENDER, 1},
      {"air.front_facing", STELA_AIR_FRONT_FACING, FRAGMENT, 1},
      {"air.sample_id", STELA_AIR_SAMPLE_ID, FRAGMENT, 1},
      {"air.sample_mask_in", STELA_AIR_SAMPLE_MASK_IN, FRAGMENT, 1},
      {"air.primitive_id", STELA_AIR_PRIMITIVE_ID, FRAGMENT, 1},
      {"air.render_target_array_index", STELA_AIR_RENDER_TARGET_ARRAY_INDEX_IN, FRAGMENT, 1},
      {"air.viewport_array_index", STELA_AIR_VIEWPORT_ARRAY_INDEX_IN, FRAGMENT, 1},
   };
   unsigned stage = !render ? KERNEL : render->entry.stage == STELA_AIR_VERTEX ? VERTEX : FRAGMENT;
   for (unsigned i = 0; i < ARRAY_SIZE(builtins); i++) {
      if (stela_air_md_string(kind, builtins[i].name)) {
         *lanes = builtins[i].lanes;
         return builtins[i].stages & stage ? builtins[i].builtin : STELA_AIR_BUILTIN_NONE;
      }
   }
   return STELA_AIR_BUILTIN_NONE;
}

/* Stage IO carries 8-, 16- and 32-bit integers and 16- and 32-bit floats. */
static bool
stage_varying(enum stela_air_primitive p)
{
   return p != STELA_AIR_PRIMITIVE_UNKNOWN && p != STELA_AIR_LONG && p != STELA_AIR_ULONG;
}

static bool argument_fields(struct stela_air_metadata *m, struct stela_air_kernel *kernel,
                            LLVMValueRef node, unsigned extent, unsigned argument,
                            unsigned depth, struct stela_air_fields *fields);

/* Whether key is an access key, whose texture or buffer access *access
 * receives. */
static bool
field_access(LLVMValueRef key, bool texture, unsigned *access)
{
   if (texture && stela_air_md_string(key, "air.sample"))
      *access = STELA_AIR_TEXTURE_SAMPLE;
   else if (stela_air_md_string(key, "air.read"))
      *access = texture ? STELA_AIR_TEXTURE_READ : STELA_AIR_READ;
   else if (stela_air_md_string(key, "air.write"))
      *access = texture ? STELA_AIR_TEXTURE_WRITE : STELA_AIR_WRITE;
   else if (stela_air_md_string(key, "air.read_write"))
      *access = texture ? STELA_AIR_TEXTURE_READ_WRITE : STELA_AIR_READ_WRITE;
   else
      return false;
   return true;
}

/* One field's argument tuple: its position, its kind and its keyed
 * reflection, as a top-level argument of that kind spells it. */
static bool
argument_field(struct stela_air_metadata *m, struct stela_air_kernel *kernel, LLVMValueRef node,
               unsigned argument, unsigned depth, struct stela_air_field *field)
{
   static const struct {
      const char *name;
      enum stela_air_field_kind kind;
   } kinds[] = {
      {"air.indirect_constant", STELA_AIR_FIELD_DATA},
      {"air.buffer", STELA_AIR_FIELD_BUFFER},
      {"air.indirect_buffer", STELA_AIR_FIELD_ARGUMENTS},
      {"air.texture", STELA_AIR_FIELD_TEXTURE},
      {"air.sampler", STELA_AIR_FIELD_SAMPLER},
   };
   LLVMValueRef operands[AIR_MAX_METADATA_OPERANDS];
   unsigned count, position, k = 0;
   if (!stela_air_md_node(m, node, operands, &count) || count < 2 ||
       !stela_air_md_uint(operands[0], &position))
      return fail(m, STELA_AIR_METADATA, "invalid argument buffer field");
   while (k < ARRAY_SIZE(kinds) && !stela_air_md_string(operands[1], kinds[k].name))
      k++;
   if (k == ARRAY_SIZE(kinds))
      return fail(m, STELA_AIR_ARGUMENT, "unsupported argument buffer field kind");
   field->kind = kinds[k].kind;
   bool texture = field->kind == STELA_AIR_FIELD_TEXTURE;
   bool buffer = field->kind == STELA_AIR_FIELD_BUFFER || field->kind == STELA_AIR_FIELD_ARGUMENTS;
   bool has_location = false, has_access = false, has_space = false, has_size = false;
   unsigned index = 0, access = 0, keyed, buffer_size = 0;
   const char *type_name = NULL;
   unsigned type_name_bytes = 0;
   LLVMValueRef info = NULL;
   for (unsigned f = 2; f < count;) {
      LLVMValueRef key = operands[f++];
      unsigned *number = stela_air_md_string(key, "air.address_space") ? &field->buffer.address_space :
                         stela_air_md_string(key, "air.buffer_size") ? &buffer_size :
                         stela_air_md_string(key, "air.arg_type_size") ? &field->buffer.type_size :
                         stela_air_md_string(key, "air.arg_type_align_size") ?
                            &field->buffer.type_alignment : NULL;
      if (stela_air_md_string(key, "air.location_index")) {
         if (has_location || f + 2 > count || !stela_air_md_uint(operands[f], &index) ||
             !stela_air_md_uint(operands[f + 1], &field->count) || !field->count)
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer field location");
         has_location = true;
         f += 2;
      } else if (field_access(key, texture, &keyed)) {
         if (has_access || (!buffer && !texture))
            return fail(m, STELA_AIR_METADATA, "duplicate/inapplicable argument buffer field access");
         access = keyed;
         has_access = true;
      } else if (number) {
         if (!buffer || f == count || !stela_air_md_uint(operands[f++], number))
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer field size or space");
         has_space |= number == &field->buffer.address_space;
         has_size |= number == &buffer_size;
      } else if (stela_air_md_string(key, "air.struct_type_info")) {
         if (field->kind != STELA_AIR_FIELD_ARGUMENTS || info || f == count)
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer field structure");
         info = operands[f++];
      } else if (stela_air_md_string(key, "air.arg_type_name") ||
                 stela_air_md_string(key, "air.arg_name")) {
         if (f == count || !operands[f] || !LLVMIsAMDString(operands[f]))
            return fail(m, STELA_AIR_METADATA, "invalid argument buffer field name");
         if (stela_air_md_string(key, "air.arg_type_name"))
            type_name = LLVMGetMDString(operands[f], &type_name_bytes);
         f++;
      } else {
         return fail(m, STELA_AIR_METADATA, "unsupported argument buffer field metadata");
      }
   }
   if (!has_location)
      return fail(m, STELA_AIR_METADATA, "argument buffer field lacks a location");
   switch (field->kind) {
   case STELA_AIR_FIELD_DATA:
      return true;
   case STELA_AIR_FIELD_TEXTURE:
      field->texture = (struct stela_air_texture){.argument = argument, .index = index,
                                                  .access = access};
      return (has_access && type_name && texture_type(type_name, type_name_bytes, &field->texture)) ||
         fail(m, STELA_AIR_ARGUMENT, "unsupported argument buffer texture");
   case STELA_AIR_FIELD_SAMPLER:
      field->sampler = (struct stela_air_sampler){.argument = argument, .index = index};
      return (type_name && type_name_bytes == strlen("sampler") &&
              !memcmp(type_name, "sampler", type_name_bytes)) ||
         fail(m, STELA_AIR_ARGUMENT, "unsupported argument buffer sampler");
   case STELA_AIR_FIELD_BUFFER:
   case STELA_AIR_FIELD_ARGUMENTS:
      break;
   }
   struct stela_air_buffer *desc = &field->buffer;
   desc->argument = argument;
   desc->index = index;
   desc->access = access;
   if (!has_access || !has_space || desc->address_space < 1 || desc->address_space > 2 ||
       (desc->address_space == 2 && access != STELA_AIR_READ) ||
       (desc->type_alignment & (desc->type_alignment - 1)))
      return fail(m, STELA_AIR_ARGUMENT, "unsupported buffer in an argument buffer");
   if (field->kind == STELA_AIR_FIELD_BUFFER)
      return true;
   if (!info || !desc->type_size || (has_size && buffer_size != desc->type_size))
      return fail(m, STELA_AIR_ARGUMENT, "unsupported nested argument buffer");
   return argument_fields(m, kernel, info, desc->type_size, argument, depth + 1, &field->arguments);
}

/* An argument buffer's air.struct_type_info: per field its offset, byte size,
 * element count (zero for one), type name, name, "air.indirect_argument" and
 * argument tuple, in increasing offsets within extent bytes. */
static bool
argument_fields(struct stela_air_metadata *m, struct stela_air_kernel *kernel, LLVMValueRef node,
                unsigned extent, unsigned argument, unsigned depth, struct stela_air_fields *fields)
{
   enum { MEMBER = 7 };
   LLVMValueRef operands[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (depth >= AIR_MAX_ARGUMENT_BUFFER_DEPTH)
      return fail(m, STELA_AIR_LIMIT, "argument buffer nesting exceeded");
   if (!stela_air_md_node(m, node, operands, &count) || !count || count % MEMBER)
      return fail(m, STELA_AIR_METADATA, "invalid argument buffer structure");
   if (count / MEMBER > AIR_MAX_FIELDS - kernel->field_count)
      return fail(m, STELA_AIR_LIMIT, "argument buffer field budget exceeded");
   /* Reserve this level's range before nested levels take theirs. */
   *fields = (struct stela_air_fields){kernel->field_count, count / MEMBER};
   kernel->field_count += fields->count;
   unsigned end = 0;
   for (unsigned i = 0; i < fields->count; i++) {
      const LLVMValueRef *member = &operands[i * MEMBER];
      struct stela_air_field *field = &kernel->fields[fields->first + i];
      *field = (struct stela_air_field){0};
      unsigned offset, size, elements;
      if (!stela_air_md_uint(member[0], &offset) || !stela_air_md_uint(member[1], &size) ||
          !stela_air_md_uint(member[2], &elements) || !member[3] || !LLVMIsAMDString(member[3]) ||
          !member[4] || !LLVMIsAMDString(member[4]) ||
          !stela_air_md_string(member[5], "air.indirect_argument"))
         return fail(m, STELA_AIR_METADATA, "invalid argument buffer member");
      if (!argument_field(m, kernel, member[6], argument, depth, field))
         return false;
      field->offset = offset;
      field->size = size;
      if (elements && elements != field->count)
         return fail(m, STELA_AIR_METADATA, "argument buffer member and location counts differ");
      if (!size || size % field->count || offset < end || offset > extent || size > extent - offset)
         return fail(m, STELA_AIR_TYPE, "argument buffer members overlap or exceed the buffer");
      if (field->kind != STELA_AIR_FIELD_DATA && (offset % 8 || size / field->count != 8))
         return fail(m, STELA_AIR_TYPE, "argument buffer addresses and IDs are aligned 8-byte values");
      end = offset + size;
   }
   return true;
}

static bool
metadata_arguments(struct stela_air_metadata *t, LLVMValueRef fn, LLVMValueRef args_node,
                   struct stela_air_kernel *kernel, struct stela_air_render *render)
{
   unsigned argc = LLVMCountParams(fn);
   if (argc > AIR_MAX_ARGUMENTS)
      return fail(t, STELA_AIR_LIMIT, "AIR argument budget exceeded");
   LLVMValueRef args[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_md_node(t, args_node, args, &count) || count != argc)
      return fail(t, STELA_AIR_METADATA, "AIR argument descriptors do not match parameters");
   bool used[AIR_MAX_ARGUMENTS] = {false};
   bool buffer_indices[AIR_MAX_ARGUMENTS] = {false};
   bool shared_indices[AIR_MAX_ARGUMENTS] = {false};
   bool texture_indices[AIR_MAX_TEXTURES] = {false};
   bool sampler_indices[AIR_MAX_SAMPLERS] = {false};
   bool builtins[STELA_AIR_BUILTIN_COUNT] = {false};
   bool attribute_locations[AIR_MAX_VERTEX_ATTRIBUTES] = {false};
   kernel->field_count = 0;
   for (unsigned a = 0; a < argc; a++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned fields_count, index;
      if (!stela_air_md_node(t, args[a], fields, &fields_count) || fields_count < 2 ||
          !stela_air_md_uint(fields[0], &index) || index >= argc || used[index])
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
      bool indirect = stela_air_md_string(fields[1], "air.indirect_buffer");
      bool buffer = indirect || stela_air_md_string(fields[1], "air.buffer");
      unsigned lanes = 0;
      enum stela_air_builtin builtin = builtin_input(fields[1], render, &lanes);
      bool position = render && render->entry.stage == STELA_AIR_FRAGMENT &&
                      stela_air_md_string(fields[1], "air.position");
      bool varying = render && render->entry.stage == STELA_AIR_FRAGMENT &&
                     stela_air_md_string(fields[1], "air.fragment_input");
      bool vertex_input = render && render->entry.stage == STELA_AIR_VERTEX &&
                          stela_air_md_string(fields[1], "air.vertex_input");
      bool texture = stela_air_md_string(fields[1], "air.texture");
      bool sampler = stela_air_md_string(fields[1], "air.sampler");
      if (!buffer && !builtin && !position && !varying && !vertex_input && !texture && !sampler)
         return fail(t, STELA_AIR_ARGUMENT, "unsupported AIR argument kind at %u", index);
      if (builtin && builtins[builtin])
         return fail(t, STELA_AIR_METADATA, "duplicate builtin argument");
      builtins[builtin] = true;
      struct stela_air_buffer desc = {.argument = index};
      struct stela_air_texture texture_desc = {.argument = index};
      struct stela_air_sampler sampler_desc = {.argument = index};
      bool has_access = false;
      struct stela_air_stage_io *io = render ? &render->inputs[a] : NULL;
      if (io) {
         *io = (struct stela_air_stage_io){.argument = index,
            .semantic = buffer ? STELA_AIR_STAGE_BUFFER : builtin ? STELA_AIR_STAGE_BUILTIN :
                        position ? STELA_AIR_POSITION : texture ? STELA_AIR_STAGE_TEXTURE :
                        vertex_input ? STELA_AIR_VERTEX_INPUT :
                        sampler ? STELA_AIR_STAGE_SAMPLER : STELA_AIR_VARYING};
      }
      unsigned first_field = 2;
      if (varying) {
         if (fields_count < 3 || !metadata_text(t, fields[2], &io->identifier, &io->identifier_bytes))
            return fail(t, STELA_AIR_METADATA, "missing fragment linkage identifier");
         first_field++;
      }
      bool unused = false;
      LLVMValueRef struct_info = NULL;
      bool has_location = false, has_as = false, has_size = false, has_align = false;
      bool has_name = false, has_type_name = false, has_buffer_size = false;
      unsigned buffer_size = 0;
      struct stela_air_fields argument_buffer = {0};
      enum stela_air_primitive primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
      unsigned type_components = 0;
      const char *name = NULL, *type_name = NULL;
      unsigned name_bytes = 0, type_name_bytes = 0;
      for (unsigned f = first_field; f < fields_count;) {
         LLVMValueRef key = fields[f++];
         if (texture && (stela_air_md_string(key, "air.sample") || stela_air_md_string(key, "air.read") ||
                         stela_air_md_string(key, "air.write") || stela_air_md_string(key, "air.read_write"))) {
            if (has_access)
               return fail(t, STELA_AIR_METADATA, "duplicate texture access");
            texture_desc.access = stela_air_md_string(key, "air.sample") ? STELA_AIR_TEXTURE_SAMPLE :
                                  stela_air_md_string(key, "air.read") ? STELA_AIR_TEXTURE_READ :
                                  stela_air_md_string(key, "air.write") ? STELA_AIR_TEXTURE_WRITE :
                                  STELA_AIR_TEXTURE_READ_WRITE;
            has_access = true;
         } else if ((texture || sampler || vertex_input) && stela_air_md_string(key, "air.location_index")) {
            unsigned *slot = texture ? &texture_desc.index : sampler ? &sampler_desc.index : &io->location;
            unsigned locations;
            if (has_location || f + 2 > fields_count || !stela_air_md_uint(fields[f], slot) ||
                !stela_air_md_uint(fields[f + 1], &locations))
               return fail(t, STELA_AIR_METADATA, "invalid/duplicate resource or attribute location");
            if (locations != 1)
               return fail(t, STELA_AIR_ARGUMENT, "texture, sampler and attribute arrays are unsupported");
            has_location = true;
            f += 2;
         } else if (stela_air_md_string(key, "air.read") || stela_air_md_string(key, "air.write") ||
             stela_air_md_string(key, "air.read_write")) {
            if (!buffer || desc.access)
               return fail(t, STELA_AIR_METADATA, "duplicate/inapplicable buffer access");
            desc.access = stela_air_md_string(key, "air.read") ? STELA_AIR_READ :
                          stela_air_md_string(key, "air.write") ? STELA_AIR_WRITE : STELA_AIR_READ_WRITE;
         } else if (stela_air_md_string(key, "air.location_index")) {
            unsigned locations;
            if (!buffer || has_location || f + 2 > fields_count ||
                !stela_air_md_uint(fields[f], &desc.index) || !stela_air_md_uint(fields[f + 1], &locations) ||
                locations != 1 || desc.index >= AIR_MAX_ARGUMENTS)
               return fail(t, STELA_AIR_METADATA, "unsupported/duplicate buffer location");
            has_location = true;
            f += 2;
         } else if (stela_air_md_string(key, "air.address_space")) {
            if (!buffer || has_as || f == fields_count || !stela_air_md_uint(fields[f++], &desc.address_space))
               return fail(t, STELA_AIR_METADATA, "invalid buffer address space");
            has_as = true;
         } else if (stela_air_md_string(key, "air.arg_type_size") || stela_air_md_string(key, "air.arg_type_align_size")) {
            bool alignment = stela_air_md_string(key, "air.arg_type_align_size");
            bool *present = alignment ? &has_align : &has_size;
            unsigned *number = alignment ? &desc.type_alignment : &desc.type_size;
            if (!buffer || *present || f == fields_count || !stela_air_md_uint(fields[f++], number) ||
                (alignment && (!*number || (*number & (*number - 1)))))
               return fail(t, STELA_AIR_METADATA, "invalid argument size/alignment");
            *present = true;
         } else if (stela_air_md_string(key, "air.arg_name") || stela_air_md_string(key, "air.arg_type_name")) {
            bool *present = stela_air_md_string(key, "air.arg_name") ? &has_name : &has_type_name;
            if (*present || f == fields_count || !fields[f] || !LLVMIsAMDString(fields[f]))
               return fail(t, STELA_AIR_METADATA, "invalid argument reflection string");
            if (present == &has_type_name) {
               primitive = primitive_type(fields[f], &type_components);
               type_name = LLVMGetMDString(fields[f], &type_name_bytes);
            } else {
               name = LLVMGetMDString(fields[f], &name_bytes);
            }
            f++;
            *present = true;
         } else if (indirect && stela_air_md_string(key, "air.buffer_size")) {
            if (has_buffer_size || f == fields_count || !stela_air_md_uint(fields[f++], &buffer_size))
               return fail(t, STELA_AIR_METADATA, "invalid argument buffer size");
            has_buffer_size = true;
         } else if ((io || indirect) && stela_air_md_string(key, "air.struct_type_info")) {
            if (!buffer || struct_info || f == fields_count)
               return fail(t, STELA_AIR_METADATA, "invalid structure reflection");
            struct_info = fields[f++];
         } else if (io && (position || varying) &&
                    (stela_air_md_string(key, "air.center") || stela_air_md_string(key, "air.centroid") ||
                     stela_air_md_string(key, "air.sample"))) {
            if (io->sampling) return fail(t, STELA_AIR_METADATA, "duplicate sampling qualifier");
            io->sampling = stela_air_md_string(key, "air.center") ? STELA_AIR_CENTER :
                           stela_air_md_string(key, "air.centroid") ? STELA_AIR_CENTROID : STELA_AIR_SAMPLE;
         } else if (io && (position || varying) &&
                    (stela_air_md_string(key, "air.perspective") || stela_air_md_string(key, "air.no_perspective") ||
                     stela_air_md_string(key, "air.flat"))) {
            if (io->interpolation) return fail(t, STELA_AIR_METADATA, "duplicate interpolation qualifier");
            io->interpolation = stela_air_md_string(key, "air.perspective") ? STELA_AIR_PERSPECTIVE :
                                stela_air_md_string(key, "air.no_perspective") ? STELA_AIR_NO_PERSPECTIVE :
                                STELA_AIR_FLAT;
         } else if (io && (position || varying) && stela_air_md_string(key, "air.arg_unused")) {
            if (unused) return fail(t, STELA_AIR_METADATA, "duplicate unused qualifier");
            unused = true;
         } else {
            return fail(t, STELA_AIR_METADATA, "unsupported argument metadata at %u", index);
         }
      }
      unsigned components = 0;
      if (texture || sampler) {
         LLVMTypeRef type = LLVMTypeOf(param);
         unsigned space = texture ? 1 : 2;
         if (!has_location || !has_type_name || LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
             LLVMGetPointerAddressSpace(type) != space)
            return fail(t, STELA_AIR_ARGUMENT, "unsupported texture or sampler %u", index);
         if (texture && (!has_access || !texture_type(type_name, type_name_bytes, &texture_desc)))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported texture type at %u", index);
         if (sampler && (type_name_bytes != strlen("sampler") || memcmp(type_name, "sampler", type_name_bytes)))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported sampler type at %u", index);
         unsigned slot = texture ? texture_desc.index : sampler_desc.index;
         bool *indices = texture ? texture_indices : sampler_indices;
         if (slot >= (texture ? AIR_MAX_TEXTURES : AIR_MAX_SAMPLERS) || indices[slot])
            return fail(t, STELA_AIR_METADATA, "duplicate or out-of-range texture or sampler location");
         indices[slot] = true;
         primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
         type_components = 0;
      } else if (buffer) {
         LLVMTypeRef type = LLVMTypeOf(param);
         /* Device and constant buffers share the buffer indices; render
          * functions have no threadgroup memory, and constant is read-only. */
         if (!has_location || !has_as || !desc.access || desc.address_space < 1 ||
             desc.address_space > (render ? 2 : 3) ||
             (desc.address_space == 2 && desc.access != STELA_AIR_READ) ||
             LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
             LLVMGetPointerAddressSpace(type) != desc.address_space)
            return fail(t, STELA_AIR_ARGUMENT, "unsupported buffer %u", index);
         bool shared = desc.address_space == 3;
         bool *indices = shared ? shared_indices : buffer_indices;
         unsigned limit = shared ? t->max_threadgroup_buffers :
                          desc.address_space == 2 ? t->max_constant_buffers : t->max_device_buffers;
         if (indices[desc.index] || (limit && desc.index >= limit))
            return fail(t, STELA_AIR_METADATA, "duplicate buffer or location exceeds AIR module limit");
         indices[desc.index] = true;
         if (indirect && (shared || !struct_info || !desc.type_size ||
                          (has_buffer_size && buffer_size != desc.type_size)))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported argument buffer %u", index);
         if (indirect && !argument_fields(t, kernel, struct_info, desc.type_size, index, 0,
                                          &argument_buffer))
            return false;
         if (render && !indirect && desc.address_space == 2 &&
             (!has_size || !has_align || !desc.type_size || !desc.type_alignment))
            return fail(t, STELA_AIR_ARGUMENT, "render constant view must be reflected and readonly");
         if (shared && (!has_size || !has_align || !desc.type_size || !desc.type_alignment))
            return fail(t, STELA_AIR_ARGUMENT, "invalid/unbound threadgroup buffer %u", index);
      } else if (position || varying) {
         bool flat = io->interpolation == STELA_AIR_FLAT;
         bool real = primitive == STELA_AIR_FLOAT || primitive == STELA_AIR_HALF;
         if (!io->interpolation || flat == (io->sampling != STELA_AIR_SAMPLING_NONE) ||
             !stage_varying(primitive) || (!real && !flat) ||
             !stage_type_matches(LLVMTypeOf(param), primitive, type_components) ||
             (position && (primitive != STELA_AIR_FLOAT || type_components != 4 ||
                           io->sampling != STELA_AIR_CENTER ||
                           io->interpolation != STELA_AIR_NO_PERSPECTIVE)))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported fragment input type/interpolation");
         components = type_components;
      } else if (vertex_input) {
         if (!has_location || io->location >= AIR_MAX_VERTEX_ATTRIBUTES || attribute_locations[io->location] ||
             !stage_varying(primitive) ||
             !stage_type_matches(LLVMTypeOf(param), primitive, type_components))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported/duplicate stage-in attribute at %u", index);
         attribute_locations[io->location] = true;
         components = type_components;
      } else {
         LLVMTypeRef type = LLVMTypeOf(param);
         components = 1;
         if (LLVMGetTypeKind(type) == LLVMVectorTypeKind) {
            components = LLVMGetVectorSize(type);
            type = LLVMGetElementType(type);
         }
         unsigned width = LLVMGetTypeKind(type) == LLVMIntegerTypeKind ? LLVMGetIntTypeWidth(type) : 0;
         if (components > lanes ||
             (builtin == STELA_AIR_FRONT_FACING ? width != 1 : width != 16 && width != 32))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported builtin type at %u", index);
      }
      if (io) {
         io->buffer = desc; io->primitive = primitive;
         io->components = builtin ? components : type_components;
         io->texture = texture_desc; io->sampler = sampler_desc; io->builtin = builtin;
         io->name = name; io->name_bytes = name_bytes;
         io->type_name = type_name; io->type_name_bytes = type_name_bytes;
         io->used = LLVMGetFirstUse(param) != NULL;
         if (unused && io->used)
            return fail(t, STELA_AIR_METADATA, "used fragment input marked unused");
         if (buffer && !indirect && desc.address_space == 2 && !stage_struct(t, render, io, struct_info))
            return false;
      }
      kernel->arguments[a] = (struct stela_air_argument) {
         .value = param, .buffer = desc, .is_buffer = buffer, .components = components,
         .is_argument_buffer = indirect, .fields = argument_buffer,
         .texture = texture_desc, .sampler = sampler_desc, .is_texture = texture, .is_sampler = sampler,
         .builtin = builtin,
         .plain_buffer_type = primitive != STELA_AIR_PRIMITIVE_UNKNOWN,
         .name = name, .name_bytes = name_bytes, .type_name = type_name, .type_name_bytes = type_name_bytes,
         .primitive = primitive, .type_components = type_components, .used = LLVMGetFirstUse(param) != NULL,
      };
   }
   kernel->count = argc;
   return true;
}

bool
stela_air_metadata_kernel(struct stela_air_metadata *t, LLVMValueRef fn,
                           struct stela_air_kernel *kernel)
{
   if (!fn || LLVMIsDeclaration(fn) || LLVMGetFunctionCallConv(fn) != LLVMCCallConv ||
       LLVMGetTypeKind(LLVMGetReturnType(LLVMGlobalGetValueType(fn))) != LLVMVoidTypeKind ||
       LLVMIsFunctionVarArg(LLVMGlobalGetValueType(fn)))
      return fail(t, STELA_AIR_ARGUMENT, "entry must be a defined nonvariadic void C-convention kernel");
   LLVMValueRef kernels[AIR_MAX_METADATA_OPERANDS], args_node = NULL;
   unsigned kernel_count;
   if (!stela_air_named_md(t, "air.kernel", kernels, &kernel_count))
      return false;
   for (unsigned i = 0; i < kernel_count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      if (!stela_air_md_node(t, kernels[i], fields, &count) || count != 3)
         return fail(t, STELA_AIR_METADATA, "invalid air.kernel descriptor");
      if (fields[0] == fn) {
         LLVMValueRef outputs[AIR_MAX_METADATA_OPERANDS];
         unsigned output_count;
         if (args_node || !stela_air_md_node(t, fields[1], outputs, &output_count) || output_count)
            return fail(t, STELA_AIR_METADATA, "duplicate kernel or nonempty compute outputs");
         args_node = fields[2];
      }
   }
   if (!args_node)
      return fail(t, STELA_AIR_METADATA, "entry is not an AIR compute kernel");
   return metadata_arguments(t, fn, args_node, kernel, NULL);
}

bool
stela_air_metadata_stage(struct stela_air_metadata *m, LLVMValueRef fn,
                         enum stela_air_stage stage, struct stela_air_render *r)
{
   if (!m->render || (stage != STELA_AIR_VERTEX && stage != STELA_AIR_FRAGMENT) ||
       !fn || !LLVMIsAFunction(fn) || LLVMIsDeclaration(fn) ||
       LLVMGetFunctionCallConv(fn) != LLVMCCallConv || LLVMIsFunctionVarArg(LLVMGlobalGetValueType(fn)))
      return fail(m, STELA_AIR_ARGUMENT, "invalid render entry/stage ABI");
   if (!stela_air_metadata_shared_profile(m)) return false;
   if (LLVMPointerSizeForAS(m->layout, 2) != 8)
      return fail(m, STELA_AIR_TARGET, "render constant pointers require 64-bit layout");
   bool threadgroup;
   if (!stela_air_metadata_globals(m, &threadgroup))
      return false;
   if (threadgroup)
      return fail(m, STELA_AIR_TARGET, "render functions have no threadgroup memory");
   *r = (struct stela_air_render){0};
   r->entry.stage = stage;
   r->entry.framebuffer_fetch_present = m->framebuffer_fetch_present;
   r->entry.framebuffer_fetch_enabled = m->framebuffer_fetch_enabled;
   r->entry.name = LLVMGetValueName2(fn, &r->entry.name_bytes);
   if (!stage_text(r->entry.name, r->entry.name_bytes))
      return fail(m, STELA_AIR_METADATA, "invalid render entry name");
   LLVMValueRef args = NULL, outputs = NULL;
   const char *lists[] = {"air.vertex", "air.fragment", "air.kernel"};
   for (unsigned list = 0; list < ARRAY_SIZE(lists); list++) {
      LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
      unsigned count;
      if (!stela_air_named_md(m, lists[list], nodes, &count)) return false;
      for (unsigned i = 0; i < count; i++) {
         LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
         unsigned fields_count;
         if (!stela_air_md_node(m, nodes[i], fields, &fields_count) || fields_count != 3 ||
             !fields[0] || !LLVMIsAFunction(fields[0]))
            return fail(m, STELA_AIR_METADATA, "invalid stage manifest descriptor");
         if (fields[0] != fn) continue;
         if (args || list + 1 != (unsigned)stage)
            return fail(m, STELA_AIR_METADATA, "duplicate or mismatched selected render stage");
         outputs = fields[1]; args = fields[2];
      }
   }
   if (!args || !metadata_arguments(m, fn, args, &r->arguments, r))
      return fail(m, STELA_AIR_METADATA, "selected entry is not a supported render stage");
   r->entry.input_count = r->arguments.count;
   r->entry.inputs = r->inputs; r->entry.outputs = r->outputs;
   bool position = false;
   for (unsigned i = 0; i < r->entry.input_count; i++) {
      struct stela_air_stage_io *io = &r->inputs[i];
      if (!stage_text(io->name, io->name_bytes) || !stage_text(io->type_name, io->type_name_bytes))
         return fail(m, STELA_AIR_METADATA, "missing/invalid stage argument name/type");
      if (io->semantic == STELA_AIR_POSITION) {
         if (position) return fail(m, STELA_AIR_METADATA, "duplicate render builtin argument");
         position = true;
      }
      if (io->semantic == STELA_AIR_VARYING) {
         for (unsigned j = 0; j < i; j++) {
            if (r->inputs[j].semantic == STELA_AIR_VARYING &&
                io->identifier_bytes == r->inputs[j].identifier_bytes &&
                !memcmp(io->identifier, r->inputs[j].identifier, io->identifier_bytes))
               return fail(m, STELA_AIR_METADATA, "duplicate fragment linkage identifier");
         }
      }
   }
   LLVMValueRef nodes[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_md_node(m, outputs, nodes, &count) || !count || count > AIR_MAX_ARGUMENTS)
      return fail(m, STELA_AIR_LIMIT, "render output budget/shape exceeded");
   LLVMTypeRef result = LLVMGetReturnType(LLVMGlobalGetValueType(fn));
   bool aggregate = LLVMGetTypeKind(result) == LLVMStructTypeKind;
   if (aggregate && (LLVMIsOpaqueStruct(result) || !LLVMIsPackedStruct(result) ||
                     LLVMCountStructElementTypes(result) != count))
      return fail(m, STELA_AIR_TYPE, "render return must match ordered packed output leaves");
   if (!aggregate && count != 1)
      return fail(m, STELA_AIR_TYPE, "render return/output count mismatch");
   unsigned positions = 0;
   for (unsigned i = 0; i < count; i++) {
      struct stela_air_stage_io *io = &r->outputs[i];
      io->argument = i;
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned n;
      if (!stela_air_md_node(m, nodes[i], fields, &n) || n < 3)
         return fail(m, STELA_AIR_METADATA, "invalid stage output descriptor");
      unsigned f = 1;
      bool vertex = stage == STELA_AIR_VERTEX, fragment = stage == STELA_AIR_FRAGMENT;
      if (vertex && stela_air_md_string(fields[0], "air.position")) {
         io->semantic = STELA_AIR_POSITION; positions++;
      } else if (vertex && stela_air_md_string(fields[0], "air.vertex_output")) {
         io->semantic = STELA_AIR_VARYING;
         if (!metadata_text(m, fields[f++], &io->identifier, &io->identifier_bytes)) return false;
      } else if (vertex && stela_air_md_string(fields[0], "air.point_size")) {
         io->semantic = STELA_AIR_POINT_SIZE;
      } else if (vertex && stela_air_md_string(fields[0], "air.render_target_array_index")) {
         io->semantic = STELA_AIR_LAYER;
      } else if (vertex && stela_air_md_string(fields[0], "air.viewport_array_index")) {
         io->semantic = STELA_AIR_VIEWPORT;
      } else if (vertex && stela_air_md_string(fields[0], "air.clip_distance")) {
         io->semantic = STELA_AIR_CLIP_DISTANCE;
         if (!stela_air_md_string(fields[f++], "air.clip_distance_array_size") ||
             !stela_air_md_uint(fields[f++], &io->clip_distances) || !io->clip_distances ||
             io->clip_distances > AIR_MAX_CLIP_DISTANCES)
            return fail(m, STELA_AIR_ARGUMENT, "clip distances need an array size of 1 to %u",
                        AIR_MAX_CLIP_DISTANCES);
      } else if (fragment && stela_air_md_string(fields[0], "air.render_target")) {
         io->semantic = STELA_AIR_RENDER_TARGET;
         /* Dual-source blending writes index 1 of attachment 0. */
         if (n < 5 || !stela_air_md_uint(fields[f++], &io->location) ||
             io->location >= AIR_MAX_RENDER_TARGETS || !stela_air_md_uint(fields[f++], &io->index) ||
             io->index > 1 || (io->index && io->location))
            return fail(m, STELA_AIR_ARGUMENT, "unsupported attachment/dual-source output");
      } else if (fragment && stela_air_md_string(fields[0], "air.depth")) {
         io->semantic = STELA_AIR_DEPTH;
      } else if (fragment && stela_air_md_string(fields[0], "air.sample_mask")) {
         io->semantic = STELA_AIR_SAMPLE_MASK;
      } else if (fragment && stela_air_md_string(fields[0], "air.stencil")) {
         io->semantic = STELA_AIR_STENCIL;
      } else return fail(m, STELA_AIR_METADATA, "unsupported stage output semantic");
      bool qualified = false;
      for (; f < n;) {
         LLVMValueRef key = fields[f++];
         if (stela_air_md_string(key, "air.arg_type_name")) {
            if (io->type_name || f == n ||
                !metadata_text(m, fields[f], &io->type_name, &io->type_name_bytes))
               return fail(m, STELA_AIR_METADATA, "invalid output type name");
            io->primitive = primitive_type(fields[f++], &io->components);
         } else if (stela_air_md_string(key, "air.arg_name")) {
            if (io->name || f == n || !metadata_text(m, fields[f++], &io->name, &io->name_bytes))
               return fail(m, STELA_AIR_METADATA, "invalid output name");
         } else if (io->semantic == STELA_AIR_POSITION && stela_air_md_string(key, "air.invariant")) {
            if (io->invariant) return fail(m, STELA_AIR_METADATA, "duplicate invariant qualifier");
            io->invariant = true;
         } else if (io->semantic == STELA_AIR_DEPTH && stela_air_md_string(key, "air.depth_qualifier")) {
            if (qualified || f == n) return fail(m, STELA_AIR_METADATA, "invalid depth qualifier");
            LLVMValueRef value = fields[f++];
            if (stela_air_md_string(value, "air.any")) io->depth = STELA_AIR_DEPTH_ANY;
            else if (stela_air_md_string(value, "air.greater")) io->depth = STELA_AIR_DEPTH_GREATER;
            else if (stela_air_md_string(value, "air.less")) io->depth = STELA_AIR_DEPTH_LESS;
            else return fail(m, STELA_AIR_METADATA, "invalid depth qualifier");
            qualified = true;
         } else return fail(m, STELA_AIR_METADATA, "unsupported output metadata");
      }
      LLVMTypeRef leaf = aggregate ? LLVMStructGetTypeAtIndex(result, i) : result;
      bool scalar = io->components == 1;
      bool integer = io->primitive == STELA_AIR_INT || io->primitive == STELA_AIR_UINT;
      bool type;
      switch (io->semantic) {
      case STELA_AIR_POSITION: type = io->primitive == STELA_AIR_FLOAT && io->components == 4; break;
      case STELA_AIR_VARYING: case STELA_AIR_RENDER_TARGET: type = stage_varying(io->primitive); break;
      case STELA_AIR_POINT_SIZE: case STELA_AIR_DEPTH: type = io->primitive == STELA_AIR_FLOAT && scalar; break;
      case STELA_AIR_CLIP_DISTANCE:
         type = io->primitive == STELA_AIR_FLOAT && scalar && LLVMGetTypeKind(leaf) == LLVMArrayTypeKind &&
                LLVMGetArrayLength2(leaf) == io->clip_distances;
         leaf = type ? LLVMGetElementType(leaf) : leaf;
         break;
      default: type = integer && scalar; break; /* Layer, viewport, sample mask and stencil. */
      }
      if (!type || !stage_type_matches(leaf, io->primitive, io->components))
         return fail(m, STELA_AIR_TYPE, "unsupported render output type");
      for (unsigned j = 0; j < i; j++) {
         const struct stela_air_stage_io *other = &r->outputs[j];
         bool same = io->semantic == other->semantic &&
            (io->semantic == STELA_AIR_VARYING ?
                io->identifier_bytes == other->identifier_bytes &&
                !memcmp(io->identifier, other->identifier, io->identifier_bytes) :
             io->semantic == STELA_AIR_RENDER_TARGET ?
                io->location == other->location && io->index == other->index : true);
         if (same)
            return fail(m, STELA_AIR_METADATA, "duplicate render output");
      }
   }
   if (stage == STELA_AIR_VERTEX && positions != 1)
      return fail(m, STELA_AIR_METADATA, "vertex entry requires exactly one position output");
   r->entry.output_count = count;
   return true;
}

bool
stela_air_metadata_stage_map(struct stela_air_metadata *m, const struct stela_air_render *r,
                             const struct stela_air_varying_slot *rows, unsigned count, unsigned max_slots)
{
   if (!max_slots || max_slots > 32 || count > max_slots || (count && !rows))
      return fail(m, STELA_AIR_INPUT, "invalid explicit render varying map/budget");
   for (unsigned i = 0; i < count; i++) {
      const struct stela_air_varying_slot *v = &rows[i];
      if (!stage_text(v->identifier, v->identifier_bytes) || v->location >= max_slots ||
          !stage_varying(v->primitive) || !v->components || v->components > 4)
         return fail(m, STELA_AIR_ARGUMENT, "invalid explicit varying map identifier/type/location");
      for (unsigned j = 0; j < i; j++) {
         if (v->location == rows[j].location || (v->identifier_bytes == rows[j].identifier_bytes &&
             !memcmp(v->identifier, rows[j].identifier, v->identifier_bytes)))
            return fail(m, STELA_AIR_ARGUMENT, "duplicate varying map identifier/location");
      }
   }
   for (unsigned direction = 0; direction < 2; direction++) {
      const struct stela_air_stage_io *io = direction ? r->entry.outputs : r->entry.inputs;
      unsigned n = direction ? r->entry.output_count : r->entry.input_count;
      for (unsigned i = 0; i < n; i++) {
         if (io[i].semantic != STELA_AIR_VARYING) continue;
         unsigned j;
         for (j = 0; j < count; j++) {
            if (rows[j].identifier_bytes == io[i].identifier_bytes &&
                !memcmp(rows[j].identifier, io[i].identifier, io[i].identifier_bytes)) break;
         }
         if (j == count || rows[j].primitive != io[i].primitive || rows[j].components != io[i].components)
            return fail(m, STELA_AIR_ARGUMENT, "selected stage linkage missing/type mismatch");
      }
   }
   return true;
}

bool
stela_air_link_stage_io(const struct stela_air_stage_entry *vs,
                        const struct stela_air_stage_entry *fs, unsigned max_slots,
                        struct stela_air_varying_slot *rows, unsigned capacity,
                        unsigned *count, struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   if (!error) error = &local;
   *error = (struct stela_air_error){0};
   struct stela_air_metadata m = {.error = error};
   if (!vs || !fs || vs->stage != STELA_AIR_VERTEX || fs->stage != STELA_AIR_FRAGMENT ||
       !max_slots || max_slots > 32 || capacity > AIR_MAX_ARGUMENTS || !count ||
       !rows || vs->output_count > AIR_MAX_ARGUMENTS || fs->input_count > AIR_MAX_ARGUMENTS ||
       (vs->output_count && !vs->outputs) || (fs->input_count && !fs->inputs))
      return fail(&m, STELA_AIR_INPUT, "invalid bounded stage linkage input");
   struct stela_air_varying_slot result[AIR_MAX_ARGUMENTS];
   unsigned n = 0;
   for (unsigned i = 0; i < vs->output_count; i++) {
      const struct stela_air_stage_io *v = &vs->outputs[i];
      if (v->semantic != STELA_AIR_VARYING) continue;
      if (!stage_text(v->identifier, v->identifier_bytes) || !stage_varying(v->primitive) ||
          !v->components || v->components > 4 || n == max_slots || n == capacity)
         return fail(&m, STELA_AIR_LIMIT, "vertex varying type/identifier/slot limit");
      for (unsigned j = 0; j < n; j++) {
         if (v->identifier_bytes == result[j].identifier_bytes &&
             !memcmp(v->identifier, result[j].identifier, v->identifier_bytes))
            return fail(&m, STELA_AIR_METADATA, "duplicate vertex varying map identifier");
      }
      result[n] = (struct stela_air_varying_slot){v->identifier,v->identifier_bytes,v->primitive,v->components,n};
      n++;
   }
   for (unsigned i = 0; i < fs->input_count; i++) {
      const struct stela_air_stage_io *f = &fs->inputs[i];
      if (f->semantic != STELA_AIR_VARYING) continue;
      unsigned j;
      for (j = 0; j < n; j++) {
         if (f->identifier_bytes == result[j].identifier_bytes &&
             stage_text(f->identifier, f->identifier_bytes) &&
             !memcmp(f->identifier, result[j].identifier, f->identifier_bytes)) break;
      }
      if (j == n || f->primitive != result[j].primitive || f->components != result[j].components ||
          !f->interpolation)
         return fail(&m, STELA_AIR_METADATA, "fragment varying missing/mismatched in vertex map");
      for (unsigned k = 0; k < i; k++) {
         const struct stela_air_stage_io *previous = &fs->inputs[k];
         if (previous->semantic == STELA_AIR_VARYING && previous->identifier_bytes == f->identifier_bytes &&
             !memcmp(previous->identifier, f->identifier, f->identifier_bytes))
            return fail(&m, STELA_AIR_METADATA, "duplicate fragment varying map identifier");
      }
   }
   memcpy(rows, result, n * sizeof(*rows)); *count = n;
   return true;
}

static void
inspection_diagnostic(LLVMDiagnosticInfoRef info, void *data)
{
   struct stela_air_metadata *m = data;
   if (LLVMGetDiagInfoSeverity(info) != LLVMDSError)
      return;
   char *message = LLVMGetDiagInfoDescription(info);
   fail(m, STELA_AIR_BITCODE, "%s", message ? message : "LLVM bitcode diagnostic");
   LLVMDisposeMessage(message);
}

static bool
inspect(const void *bitcode, size_t size, unsigned max_entries,
         stela_air_visit_entry visit, void *data, struct stela_air_error *error,
         const char *render_name, enum stela_air_stage stage, stela_air_visit_stage render_visit)
{
   struct stela_air_error local = {0};
   if (!error)
      error = &local;
   *error = (struct stela_air_error){0};
   struct stela_air_metadata m = {.error = error, .render = render_name != NULL};
   if (!bitcode || size < 4 || size > AIR_MAX_BITCODE_BYTES ||
       memcmp(bitcode, "BC\xc0\xde", 4) || !max_entries ||
       max_entries > AIR_MAX_METADATA_OPERANDS || (!render_name && !visit) ||
       (render_name && (!render_visit || !stage_text(render_name, strlen(render_name)))))
      return fail(&m, STELA_AIR_INPUT, "invalid AIR inspection input/budget");
   unsigned major, minor, patch;
   LLVMGetVersion(&major, &minor, &patch);
   if (major != 23)
      return fail(&m, STELA_AIR_LLVM_VERSION, "requires LLVM 23 C ABI, found %u.%u.%u", major, minor, patch);
   LLVMContextRef context = LLVMContextCreate();
   if (!context)
      return fail(&m, STELA_AIR_ALLOCATION, "LLVM context unavailable");
   LLVMContextSetDiagnosticHandler(context, inspection_diagnostic, &m);
   LLVMMemoryBufferRef buffer = LLVMCreateMemoryBufferWithMemoryRangeCopy(bitcode, size, "Metal input");
   if (!buffer) {
      LLVMContextDispose(context);
      return fail(&m, STELA_AIR_ALLOCATION, "LLVM buffer unavailable");
   }
   bool parsed = !LLVMParseBitcodeInContext2(context, buffer, &m.module);
   LLVMDisposeMemoryBuffer(buffer);
   bool success = false;
   struct decoded_entry {
      LLVMValueRef fn;
      const char *name;
      size_t name_bytes;
      struct stela_air_kernel kernel;
   } *entries = NULL;
   if (!parsed || error->kind != STELA_AIR_OK) {
      fail(&m, STELA_AIR_BITCODE, "LLVM refused AIR bitcode");
      goto done;
   }
   char *verification = NULL;
   if (LLVMVerifyModule(m.module, LLVMReturnStatusAction, &verification)) {
      fail(&m, STELA_AIR_VERIFY, "%s", verification ? verification : "invalid LLVM module");
      LLVMDisposeMessage(verification);
      goto done;
   }
   LLVMDisposeMessage(verification);
   const char *target = LLVMGetTarget(m.module);
   size_t assembly;
   LLVMGetModuleInlineAsm(m.module, &assembly);
   if (strncmp(target, "air64_v", 7) || assembly || LLVMGetFirstGlobalAlias(m.module) ||
       LLVMGetFirstGlobalIFunc(m.module)) {
      fail(&m, STELA_AIR_TARGET, "unsupported target/globals/inline assembly");
      goto done;
   }
   if (!stela_air_metadata_layout(&m) || !stela_air_metadata_validate(&m))
      goto done;
   char prefix[40];
   snprintf(prefix, sizeof(prefix), "air64_v2%u-apple-macosx", m.air_minor);
   if (strncmp(target, prefix, strlen(prefix))) {
      fail(&m, STELA_AIR_TARGET, "AIR version and target triple disagree");
      goto done;
   }
   if (render_name) {
      struct stela_air_render render;
      if (!stela_air_metadata_stage(&m, LLVMGetNamedFunction(m.module, render_name), stage, &render)) goto done;
      struct stela_air_inspection info = {.target = target, .target_bytes = strlen(target),
         .air_minor = m.air_minor, .language_major = m.language_major, .language_minor = m.language_minor,
         .denorms_disable = m.denorms_disable, .fast_math = m.fast_math};
      success = render_visit(&info, &render.entry, data);
      if (!success) fail(&m, STELA_AIR_LIMIT, "AIR stage receiver refused entry");
      goto done;
   }
   LLVMValueRef kernels[AIR_MAX_METADATA_OPERANDS];
   unsigned count;
   if (!stela_air_named_md(&m, "air.kernel", kernels, &count))
      goto done;
   if (!count || count > max_entries) {
      fail(&m, STELA_AIR_LIMIT, "no executable compute entries or entry budget exceeded");
      goto done;
   }
   entries = calloc(count, sizeof(*entries));
   if (!entries) {
      fail(&m, STELA_AIR_ALLOCATION, "entry manifest allocation failed");
      goto done;
   }
   /* Validate the complete manifest BEFORE the first callback. A later invalid
    * entry cannot publish a partially accepted library through this interface. */
   for (unsigned i = 0; i < count; i++) {
      LLVMValueRef fields[AIR_MAX_METADATA_OPERANDS];
      unsigned fields_count;
      if (!stela_air_md_node(&m, kernels[i], fields, &fields_count) || fields_count != 3 ||
          !fields[0] || !LLVMIsAFunction(fields[0])) {
         fail(&m, STELA_AIR_METADATA, "invalid AIR kernel manifest entry");
         goto done;
      }
      entries[i].fn = fields[0];
      entries[i].name = LLVMGetValueName2(fields[0], &entries[i].name_bytes);
      if (!entries[i].name_bytes || entries[i].name_bytes > 4096 ||
          memchr(entries[i].name, 0, entries[i].name_bytes)) {
         fail(&m, STELA_AIR_METADATA, "invalid/oversized AIR entry name");
         goto done;
      }
      for (unsigned j = 0; j < i; j++) {
         if (entries[j].fn == entries[i].fn) {
            fail(&m, STELA_AIR_METADATA, "duplicate AIR kernel manifest entry");
            goto done;
         }
      }
      if (!stela_air_metadata_kernel(&m, entries[i].fn, &entries[i].kernel))
         goto done;
   }
   struct stela_air_inspection info = {
      .target = target, .target_bytes = strlen(target), .air_minor = m.air_minor,
      .language_major = m.language_major, .language_minor = m.language_minor,
      .denorms_disable = m.denorms_disable, .fast_math = m.fast_math,
   };
   for (unsigned i = 0; i < count; i++) {
      struct stela_air_argument_info args[AIR_MAX_ARGUMENTS];
      for (unsigned a = 0; a < entries[i].kernel.count; a++) {
         const struct stela_air_argument *arg = &entries[i].kernel.arguments[a];
         args[a] = (struct stela_air_argument_info) {
            .buffer = arg->buffer, .kind = arg->is_buffer ? 1 : arg->is_texture ? 3 : arg->is_sampler ? 4 : 2,
            .texture = arg->texture, .sampler = arg->sampler, .builtin = arg->builtin,
            .components = arg->components,
            .plain_buffer_type = arg->plain_buffer_type,
            .name = arg->name, .name_bytes = arg->name_bytes,
            .type_name = arg->type_name, .type_name_bytes = arg->type_name_bytes,
            .primitive = arg->primitive, .type_components = arg->type_components, .used = arg->used,
         };
      }
      struct stela_air_entry entry = {
         .name = entries[i].name, .name_bytes = entries[i].name_bytes,
         .argument_count = entries[i].kernel.count, .arguments = args,
         .reflection_complete = complete_reflection(&m, entries[i].fn, &entries[i].kernel),
      };
      if (!visit(&info, &entry, data)) {
         fail(&m, STELA_AIR_LIMIT, "AIR manifest receiver refused entry");
         goto done;
      }
   }
   success = true;
done:
   free(entries);
   if (m.module)
      LLVMDisposeModule(m.module);
   LLVMContextDispose(context);
   return success;
}

bool
stela_air_inspect(const void *bitcode, size_t size, unsigned max_entries,
                   stela_air_visit_entry visit, void *data, struct stela_air_error *error)
{
   return inspect(bitcode, size, max_entries, visit, data, error, NULL, 0, NULL);
}

bool
stela_air_inspect_stage(const void *bitcode, size_t size, const char *entry,
                         enum stela_air_stage stage, stela_air_visit_stage visit,
                         void *data, struct stela_air_error *error)
{
   if (!entry || (stage != STELA_AIR_VERTEX && stage != STELA_AIR_FRAGMENT)) {
      if (error) *error = (struct stela_air_error){.kind = STELA_AIR_INPUT};
      return false;
   }
   return inspect(bitcode, size, AIR_MAX_METADATA_OPERANDS, NULL, data, error, entry, stage, visit);
}
