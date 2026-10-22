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
          p == STELA_AIR_SHORT || p == STELA_AIR_USHORT ? 2 :
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
      LLVMIntTypeInContext(context, bytes * 8);
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
      bool vertex_id = render && render->entry.stage == STELA_AIR_VERTEX &&
                       stela_air_md_string(fields[1], "air.vertex_id");
      bool position = render && render->entry.stage == STELA_AIR_FRAGMENT &&
                      stela_air_md_string(fields[1], "air.position");
      bool varying = render && render->entry.stage == STELA_AIR_FRAGMENT &&
                     stela_air_md_string(fields[1], "air.fragment_input");
      if ((render && thread_id) || (!buffer && !thread_id && !vertex_id && !position && !varying))
         return fail(t, STELA_AIR_ARGUMENT, "unsupported AIR argument kind at %u", index);
      struct stela_air_buffer desc = {.argument = index};
      struct stela_air_stage_io *io = render ? &render->inputs[a] : NULL;
      if (io) {
         *io = (struct stela_air_stage_io){.argument = index,
            .semantic = buffer ? STELA_AIR_STAGE_BUFFER : vertex_id ? STELA_AIR_VERTEX_ID :
                        position ? STELA_AIR_POSITION : STELA_AIR_VARYING};
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
      bool has_name = false, has_type_name = false;
      enum stela_air_primitive primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
      unsigned type_components = 0;
      const char *name = NULL, *type_name = NULL;
      unsigned name_bytes = 0, type_name_bytes = 0;
      for (unsigned f = first_field; f < fields_count;) {
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
         } else if (io && stela_air_md_string(key, "air.struct_type_info")) {
            if (!buffer || struct_info || f == fields_count)
               return fail(t, STELA_AIR_METADATA, "invalid structure reflection");
            struct_info = fields[f++];
         } else if (io && (position || varying) && stela_air_md_string(key, "air.center")) {
            if (io->center) return fail(t, STELA_AIR_METADATA, "duplicate sampling qualifier");
            io->center = true;
         } else if (io && (position || varying) &&
                    (stela_air_md_string(key, "air.perspective") || stela_air_md_string(key, "air.no_perspective"))) {
            if (io->interpolation) return fail(t, STELA_AIR_METADATA, "duplicate interpolation qualifier");
            io->interpolation = stela_air_md_string(key, "air.perspective") ?
               STELA_AIR_PERSPECTIVE : STELA_AIR_NO_PERSPECTIVE;
         } else if (io && (position || varying) && stela_air_md_string(key, "air.arg_unused")) {
            if (unused) return fail(t, STELA_AIR_METADATA, "duplicate unused qualifier");
            unused = true;
         } else {
            return fail(t, STELA_AIR_METADATA, "unsupported argument metadata at %u", index);
         }
      }
      unsigned components = 0;
      if (buffer) {
         LLVMTypeRef type = LLVMTypeOf(param);
         if (!has_location || !has_as || !desc.access ||
             (render ? desc.address_space != 2 : (desc.address_space != 1 && desc.address_space != 3)) ||
             LLVMGetTypeKind(type) != LLVMPointerTypeKind ||
             LLVMGetPointerAddressSpace(type) != desc.address_space)
            return fail(t, STELA_AIR_ARGUMENT, "unsupported buffer %u", index);
         bool shared = desc.address_space == 3;
         bool *indices = shared ? shared_indices : buffer_indices;
         unsigned limit = shared ? t->max_threadgroup_buffers : render ? t->max_constant_buffers : t->max_device_buffers;
         if (indices[desc.index] || (limit && desc.index >= limit))
            return fail(t, STELA_AIR_METADATA, "duplicate buffer or location exceeds AIR module limit");
         indices[desc.index] = true;
         if (render && (desc.access != STELA_AIR_READ || !has_size || !has_align ||
                        !desc.type_size || !desc.type_alignment))
            return fail(t, STELA_AIR_ARGUMENT, "render constant view must be reflected and readonly");
         if (shared && (!has_size || !has_align || !desc.type_size || !desc.type_alignment))
            return fail(t, STELA_AIR_ARGUMENT, "invalid/unbound threadgroup buffer %u", index);
      } else if (position || varying) {
         if (!io->center || !io->interpolation || primitive != STELA_AIR_FLOAT ||
             !stage_type_matches(LLVMTypeOf(param), primitive, type_components) ||
             (position && (type_components != 4 || io->interpolation != STELA_AIR_NO_PERSPECTIVE)))
            return fail(t, STELA_AIR_ARGUMENT, "unsupported fragment input type/interpolation");
         components = type_components;
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
      if (io) {
         io->buffer = desc; io->primitive = primitive; io->components = type_components;
         io->name = name; io->name_bytes = name_bytes;
         io->type_name = type_name; io->type_name_bytes = type_name_bytes;
         io->used = LLVMGetFirstUse(param) != NULL;
         if (unused && io->used)
            return fail(t, STELA_AIR_METADATA, "used fragment input marked unused");
         if (vertex_id && (primitive != STELA_AIR_UINT || type_components != 1 || components != 1))
            return fail(t, STELA_AIR_ARGUMENT, "vertex ID must be uint");
         if (buffer && !stage_struct(t, render, io, struct_info))
            return false;
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
   if (LLVMGetFirstGlobal(m->module))
      return fail(m, STELA_AIR_TARGET, "render globals/sampler storage are unsupported");
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
   unsigned builtin_mask = 0;
   for (unsigned i = 0; i < r->entry.input_count; i++) {
      struct stela_air_stage_io *io = &r->inputs[i];
      if (!stage_text(io->name, io->name_bytes) || !stage_text(io->type_name, io->type_name_bytes))
         return fail(m, STELA_AIR_METADATA, "missing/invalid stage argument name/type");
      if (io->semantic == STELA_AIR_VERTEX_ID || io->semantic == STELA_AIR_POSITION) {
         unsigned bit = 1u << io->semantic;
         if (builtin_mask & bit) return fail(m, STELA_AIR_METADATA, "duplicate render builtin argument");
         builtin_mask |= bit;
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
      if (stage == STELA_AIR_VERTEX && stela_air_md_string(fields[0], "air.position")) {
         io->semantic = STELA_AIR_POSITION; positions++;
      } else if (stage == STELA_AIR_VERTEX && stela_air_md_string(fields[0], "air.vertex_output")) {
         io->semantic = STELA_AIR_VARYING;
         if (!metadata_text(m, fields[f++], &io->identifier, &io->identifier_bytes)) return false;
      } else if (stage == STELA_AIR_FRAGMENT && stela_air_md_string(fields[0], "air.render_target")) {
         io->semantic = STELA_AIR_RENDER_TARGET;
         if (count != 1 || n < 5 || !stela_air_md_uint(fields[f++], &io->location) || io->location ||
             !stela_air_md_uint(fields[f++], &io->index) || io->index)
            return fail(m, STELA_AIR_ARGUMENT, "unsupported attachment/dual-source output");
      } else return fail(m, STELA_AIR_METADATA, "unsupported stage output semantic");
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
         } else return fail(m, STELA_AIR_METADATA, "unsupported output metadata");
      }
      LLVMTypeRef leaf = aggregate ? LLVMStructGetTypeAtIndex(result, i) : result;
      if (io->primitive != STELA_AIR_FLOAT || !stage_type_matches(leaf, io->primitive, io->components) ||
          (io->semantic == STELA_AIR_POSITION && io->components != 4))
         return fail(m, STELA_AIR_TYPE, "unsupported render output type");
      for (unsigned j = 0; j < i; j++) {
         if (io->semantic == STELA_AIR_VARYING && r->outputs[j].semantic == STELA_AIR_VARYING &&
             io->identifier_bytes == r->outputs[j].identifier_bytes &&
             !memcmp(io->identifier, r->outputs[j].identifier, io->identifier_bytes))
            return fail(m, STELA_AIR_METADATA, "duplicate vertex linkage identifier");
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
          v->primitive != STELA_AIR_FLOAT || !v->components || v->components > 4)
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
      if (!stage_text(v->identifier, v->identifier_bytes) || v->primitive != STELA_AIR_FLOAT ||
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
          !f->center || !f->interpolation)
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
