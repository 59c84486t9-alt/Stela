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

static bool
shared_storage_size(struct stela_air_metadata *t, LLVMTypeRef type, unsigned depth,
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
      LLVMTypeRef scalar = type;
      if (LLVMGetTypeKind(type) == LLVMVectorTypeKind) {
         unsigned components = LLVMGetVectorSize(type);
         if (components < 2 || components > 4)
            return fail(t, STELA_AIR_TYPE, "shared globals require fixed integer/FP32 scalar/vector arrays");
         scalar = LLVMGetElementType(type);
      }
      bool valid = LLVMGetTypeKind(scalar) == LLVMFloatTypeKind;
      if (LLVMGetTypeKind(scalar) == LLVMIntegerTypeKind) {
         unsigned bits = LLVMGetIntTypeWidth(scalar);
         valid = bits == 8 || bits == 16 || bits == 32 || bits == 64;
      }
      if (!valid)
         return fail(t, STELA_AIR_TYPE, "shared globals require fixed integer/FP32 scalar/vector arrays");
   }
   /* Aggregate extents were bounded before invoking fixed-size LLVM queries. */
   *size = LLVMABISizeOfType(t->layout, type);
   return (*size && *size <= UINT32_MAX) ||
      fail(t, STELA_AIR_LIMIT, "shared storage allocation size exceeded");
}

bool
stela_air_metadata_shared_global(struct stela_air_metadata *t, LLVMValueRef global,
                    uint64_t *size, unsigned *alignment)
{
   const char *section = LLVMGetSection(global);
   LLVMValueRef initializer = LLVMGetInitializer(global);
   if (LLVMGetPointerAddressSpace(LLVMTypeOf(global)) != 3 ||
       LLVMGetLinkage(global) != LLVMInternalLinkage || LLVMIsThreadLocal(global) ||
       LLVMIsGlobalConstant(global) || LLVMIsExternallyInitialized(global) ||
       (section && *section) || !initializer || !LLVMIsUndef(initializer) || LLVMIsPoison(initializer))
      return fail(t, STELA_AIR_TARGET, "unsupported global/shared initializer or storage ABI");
   size_t metadata_count;
   LLVMValueMetadataEntry *metadata = LLVMGlobalCopyAllMetadata(global, &metadata_count);
   LLVMDisposeValueMetadataEntries(metadata);
   if (metadata_count)
      return fail(t, STELA_AIR_TARGET, "unsupported shared global metadata");
   LLVMTypeRef type = LLVMGlobalGetValueType(global);
   if (!shared_storage_size(t, type, 0, size))
      return false;
   *alignment = LLVMGetAlignment(global);
   if (!*alignment)
      *alignment = LLVMABIAlignmentOfType(t->layout, type);
   return (*alignment && !(*alignment & (*alignment - 1))) ||
      fail(t, STELA_AIR_TYPE, "unsupported shared global alignment");
}

bool
stela_air_metadata_shared_globals(struct stela_air_metadata *t)
{
   unsigned count = 0;
   for (LLVMValueRef global = LLVMGetFirstGlobal(t->module); global;
        global = LLVMGetNextGlobal(global)) {
      uint64_t size;
      unsigned alignment;
      if (++count > AIR_MAX_ARGUMENTS)
         return fail(t, STELA_AIR_LIMIT, "shared global count exceeded");
      if (!stela_air_metadata_shared_global(t, global, &size, &alignment))
         return false;
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
   const char *scalar[] = {"char", "uchar", "short", "ushort", "int", "uint", "long", "ulong", "float"};
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

/* This is reflection admission, not a change to executable/NIR admission.
 * Reject unknown function metadata/string attributes and unqualified globals
 * instead of claiming absent annotations/constants/static-resource reflection.
 * The known internal undef AS3 storage ABI does not add a function argument;
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
      if (!stela_air_metadata_shared_profile(&observed) ||
          !stela_air_metadata_shared_globals(&observed))
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
      bool buffer = stela_air_md_string(fields[1], "air.buffer");
      bool thread_id = stela_air_md_string(fields[1], "air.thread_position_in_grid");
      if (!buffer && !thread_id)
         return fail(t, STELA_AIR_ARGUMENT, "unsupported AIR argument kind at %u", index);
      struct stela_air_buffer desc = {.argument = index};
      bool has_location = false, has_as = false, has_size = false, has_align = false;
      bool has_name = false, has_type_name = false;
      enum stela_air_primitive primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
      unsigned type_components = 0;
      const char *name = NULL, *type_name = NULL;
      unsigned name_bytes = 0, type_name_bytes = 0;
      for (unsigned f = 2; f < fields_count;) {
         LLVMValueRef key = fields[f++];
         if (stela_air_md_string(key, "air.read") || stela_air_md_string(key, "air.write") ||
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
         } else {
            return fail(t, STELA_AIR_METADATA, "unsupported argument metadata at %u", index);
         }
      }
      unsigned components = 0;
      if (buffer) {
         LLVMTypeRef type = LLVMTypeOf(param);
         if (!has_location || !has_as || !desc.access ||
             (desc.address_space != 1 && desc.address_space != 3) ||
             LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
             LLVMGetPointerAddressSpace(type) != desc.address_space)
            return fail(t, STELA_AIR_ARGUMENT, "unsupported buffer %u", index);
         bool shared = desc.address_space == 3;
         bool *indices = shared ? shared_indices : buffer_indices;
         unsigned limit = shared ? t->max_threadgroup_buffers : t->max_device_buffers;
         if (indices[desc.index] || (limit && desc.index >= limit))
            return fail(t, STELA_AIR_METADATA, "duplicate buffer or location exceeds AIR module limit");
         indices[desc.index] = true;
         if (shared && (!has_size || !has_align || !desc.type_size || !desc.type_alignment))
            return fail(t, STELA_AIR_ARGUMENT, "invalid/unbound threadgroup buffer %u", index);
      } else {
         LLVMTypeRef type = LLVMTypeOf(param);
         components = 1;
         if (LLVMGetTypeKind(type) == LLVMVectorTypeKind) {
            components = LLVMGetVectorSize(type);
            if (components != 3)
               return fail(t, STELA_AIR_ARGUMENT, "unsupported thread-position vector width");
            type = LLVMGetElementType(type);
         }
         if (LLVMGetTypeKind(type) != LLVMIntegerTypeKind || LLVMGetIntTypeWidth(type) != 32 ||
             (components != 1 && components != 3))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported thread-position type");
      }
      kernel->arguments[a] = (struct stela_air_argument) {
         .value = param, .buffer = desc, .is_buffer = buffer, .components = components,
         .plain_buffer_type = primitive != STELA_AIR_PRIMITIVE_UNKNOWN,
         .name = name, .name_bytes = name_bytes, .type_name = type_name, .type_name_bytes = type_name_bytes,
         .primitive = primitive, .type_components = type_components, .used = LLVMGetFirstUse(param) != NULL,
      };
   }
   kernel->count = argc;
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

bool
stela_air_inspect(const void *bitcode, size_t size, unsigned max_entries,
                   stela_air_visit_entry visit, void *data,
                   struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   if (!error)
      error = &local;
   *error = (struct stela_air_error){0};
   struct stela_air_metadata m = {.error = error};
   if (!bitcode || size < 4 || size > AIR_MAX_BITCODE_BYTES ||
       memcmp(bitcode, "BC\xc0\xde", 4) || !max_entries ||
       max_entries > AIR_MAX_METADATA_OPERANDS || !visit)
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
            .buffer = arg->buffer, .kind = arg->is_buffer ? 1 : 2, .components = arg->components,
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
