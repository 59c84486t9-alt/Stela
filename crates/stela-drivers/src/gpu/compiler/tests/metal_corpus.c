/* SPDX-License-Identifier: MIT */
/* Compiles every entry point of AIR modules the way the Metal device does,
 * with NAK's NIR options, and reports each one's outcome: the shader
 * coverage sweep of metal-device.md's bring-up plan. Each argument is an
 * .air module from Apple's `metal -c`; the inputs are never committed.
 *
 *   stela_metal_corpus [--sm SM] MODULE.air...
 *
 * A kernel takes a 64-thread threadgroup and every threadgroup buffer its
 * declared bytes; a render function is linked with the varyings it writes
 * or reads;
 * a post-tessellation vertex function takes its patch's default
 * tessellation, and each of its attributes a buffer of its own; required
 * function constants take zero. Exits nonzero when
 * any entry point is refused. */
#include "compiler/glsl_types.h"
#include "compiler/metal_compiler.h"
#include "llvm-c/BitReader.h"
#include "llvm-c/Core.h"
#include "nouveau/compiler/nak.h"
#include "nouveau/headers/nv_device_info.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WRAPPER_MAGIC 0x0b17c0deu

static struct stela_metal_reflection reflection;

/* The module's bitcode, unwrapped from an LLVM bitcode wrapper. */
static const uint8_t *
bitcode(const uint8_t *bytes, size_t *size)
{
   uint32_t words[5];
   if (*size < sizeof(words))
      return bytes;
   memcpy(words, bytes, sizeof(words));
   if (words[0] != WRAPPER_MAGIC || words[2] > *size || words[3] > *size - words[2])
      return bytes;
   *size = words[3];
   return bytes + words[2];
}

/* Bytes of a function constant of an MSL type: its scalar's, times its
 * lanes. */
static size_t
constant_bytes(const char *type, size_t length)
{
   static const struct { const char *name; size_t bytes; } scalars[] = {
      {"bool", 1}, {"char", 1}, {"uchar", 1}, {"short", 2}, {"ushort", 2}, {"half", 2},
      {"bfloat", 2}, {"int", 4}, {"uint", 4}, {"float", 4}, {"long", 8}, {"ulong", 8},
   };
   for (unsigned i = 0; i < sizeof(scalars) / sizeof(scalars[0]); i++) {
      size_t name = strlen(scalars[i].name);
      if (length < name || memcmp(type, scalars[i].name, name))
         continue;
      if (length == name)
         return scalars[i].bytes;
      unsigned lanes = (unsigned)(type[name] - '0');
      if (length == name + 1 && lanes >= 2 && lanes <= 4)
         return scalars[i].bytes * (lanes == 3 ? 4 : lanes);
   }
   return 16;
}

/* The MTLVertexFormat of 32-bit lanes that carries an attribute. */
static uint32_t
attribute_format(const struct stela_metal_attribute_use *attribute)
{
   uint32_t lanes = attribute->components;
   switch (attribute->primitive) {
   case STELA_AIR_FLOAT: case STELA_AIR_HALF: return 27 + lanes; /* Float */
   case STELA_AIR_UINT: case STELA_AIR_USHORT: case STELA_AIR_UCHAR: return 35 + lanes; /* UInt */
   default: return 31 + lanes; /* Int */
   }
}

/* Compiles entry, which reflected into reflection: NULL after reporting
 * why in error. */
static nir_shader *
compile(const uint8_t *air, size_t size, const char *entry,
        const struct stela_metal_target *target, struct stela_air_error *error)
{
   struct stela_metal_specialization specialization = {.max_call_stack_depth = 1};
   uint32_t stage = reflection.stage;
   if (stage == STELA_METAL_KERNEL || stage == STELA_METAL_OBJECT || stage == STELA_METAL_MESH) {
      unsigned threads = reflection.max_total_threads && reflection.max_total_threads < 64 ?
                            reflection.max_total_threads : 64;
      specialization.workgroup_size[0] = threads;
      specialization.workgroup_size[1] = specialization.workgroup_size[2] = 1;
   }
   static struct stela_metal_threadgroup_length lengths[STELA_METAL_BUFFERS];
   for (unsigned i = 0; i < reflection.threadgroup_count; i++) {
      uint32_t bytes = reflection.threadgroup[i].bytes ? reflection.threadgroup[i].bytes : 16;
      lengths[i] = (struct stela_metal_threadgroup_length){reflection.threadgroup[i].index,
                                                           (bytes + 15) & ~15u};
   }
   specialization.threadgroup_lengths = lengths;
   specialization.threadgroup_length_count = reflection.threadgroup_count;
   static struct stela_metal_linked_varying varyings[STELA_METAL_VARYINGS];
   for (unsigned i = 0; i < reflection.varying_count; i++) {
      const struct stela_metal_varying *varying = &reflection.varyings[i];
      varyings[i] = (struct stela_metal_linked_varying){
         reflection.names + varying->identifier, varying->identifier_bytes, varying->per_primitive};
   }
   specialization.varyings = varyings;
   specialization.varying_count = reflection.varying_count;
   static struct stela_air_constant_value constants[STELA_METAL_FUNCTION_CONSTANTS];
   static const uint8_t zeros[16];
   unsigned constant_count = 0;
   for (unsigned i = 0; i < reflection.function_constant_count; i++) {
      const struct stela_metal_function_constant *constant = &reflection.function_constants[i];
      if (constant->required)
         constants[constant_count++] = (struct stela_air_constant_value){
            constant->index, zeros, constant_bytes(reflection.names + constant->type,
                                                   constant->type_bytes)};
   }
   specialization.constants = constants;
   specialization.constant_count = constant_count;
   const struct stela_metal_tessellation tessellation = {
      .quad = reflection.patch == STELA_AIR_PATCH_QUAD, .max_factor = 16,
      .partition = STELA_METAL_PARTITION_POW2, .step = STELA_METAL_FACTOR_STEP_PER_PATCH,
   };
   static struct stela_metal_stage_in stage_in;
   memset(&stage_in, 0, sizeof(stage_in));
   for (unsigned i = 0; i < reflection.attribute_count; i++) {
      const struct stela_metal_attribute_use *attribute = &reflection.attributes[i];
      stage_in.attributes[attribute->index] = (struct stela_metal_stage_in_attribute){
         attribute_format(attribute), 0, attribute->index};
      stage_in.layouts[attribute->index] = (struct stela_metal_stage_in_layout){
         16, attribute->patch_control_point ? STELA_METAL_STEP_PER_PATCH_CONTROL_POINT :
             reflection.patch ? STELA_METAL_STEP_PER_PATCH : STELA_METAL_STEP_THREAD_POSITION_IN_GRID_X,
         1};
   }
   /* Vertex functions fetch through the pipeline's vertex input instead. */
   if (reflection.attribute_count && (stage == STELA_METAL_KERNEL || reflection.patch))
      specialization.stage_in = &stage_in;
   if (reflection.patch)
      specialization.tessellation = &tessellation;
   /* Each constexpr sampler state a sampler of its own, as the device
    * creates them. */
   static uint64_t states[STELA_METAL_SAMPLER_STATES];
   static struct stela_air_constexpr_sampler samplers[STELA_METAL_SAMPLER_STATES];
   if (!stela_metal_sampler_states(air, size, states, &specialization.sampler_count, error))
      return NULL;
   for (unsigned i = 0; i < specialization.sampler_count; i++)
      samplers[i] = (struct stela_air_constexpr_sampler){states[i], (uint64_t)i << 32 | i};
   specialization.samplers = samplers;
   return stela_metal_compile(air, size, entry, target, &specialization, error);
}

static unsigned
sweep(const char *path, const struct stela_metal_target *target)
{
   FILE *file = fopen(path, "rb");
   if (!file) {
      printf("%s: unreadable\n", path);
      return 1;
   }
   fseek(file, 0, SEEK_END);
   size_t size = (size_t)ftell(file);
   fseek(file, 0, SEEK_SET);
   uint8_t *bytes = malloc(size ? size : 1);
   size_t read = bytes ? fread(bytes, 1, size, file) : 0;
   fclose(file);
   if (read != size) {
      free(bytes);
      printf("%s: unreadable\n", path);
      return 1;
   }
   const uint8_t *air = bitcode(bytes, &size);
   LLVMContextRef context = LLVMContextCreate();
   LLVMMemoryBufferRef buffer = LLVMCreateMemoryBufferWithMemoryRange((const char *)air, size,
                                                                     path, false);
   LLVMModuleRef module = NULL;
   unsigned refused = 0;
   if (LLVMParseBitcodeInContext2(context, buffer, &module)) {
      printf("%s: not bitcode\n", path);
      refused++;
   }
   for (LLVMValueRef fn = module ? LLVMGetFirstFunction(module) : NULL; fn;
        fn = LLVMGetNextFunction(fn)) {
      size_t name_bytes;
      const char *name = LLVMGetValueName2(fn, &name_bytes);
      if (LLVMIsDeclaration(fn) || !name_bytes)
         continue;
      char *entry = strndup(name, name_bytes);
      struct stela_air_error error;
      if (!stela_metal_reflect(air, size, entry, NULL, 0, &reflection, &error)) {
         /* Helpers and other functions no entry metadata lists. */
         if (!strstr(error.detail, "not a listed AIR function"))
            printf("%s %s: reflection refused (%u): %s\n", path, entry, error.kind, error.detail),
               refused++;
      } else if (reflection.stage != STELA_METAL_VISIBLE) {
         nir_shader *shader = compile(air, size, entry, target, &error);
         if (shader) {
            printf("%s %s: ok\n", path, entry);
            stela_metal_release(shader);
         } else {
            printf("%s %s: refused (%u): %s\n", path, entry, error.kind, error.detail);
            refused++;
         }
      }
      free(entry);
   }
   if (module)
      LLVMDisposeModule(module);
   else
      LLVMDisposeMemoryBuffer(buffer);
   LLVMContextDispose(context);
   free(bytes);
   return refused;
}

int
main(int argc, char **argv)
{
   unsigned sm = 120;
   int first = 1;
   if (argc > 2 && !strcmp(argv[1], "--sm")) {
      sm = (unsigned)atoi(argv[2]);
      first = 3;
   }
   if (first >= argc) {
      fprintf(stderr, "usage: %s [--sm SM] MODULE.air...\n", argv[0]);
      return 2;
   }
   glsl_type_singleton_init_or_ref();
   const struct nv_device_info device = {.sm = (uint8_t)sm, .max_warps_per_mp = 48};
   struct nak_compiler *nak = nak_compiler_create(&device);
   if (!nak) {
      fprintf(stderr, "NAK refused SM %u\n", sm);
      return 2;
   }
   const struct stela_metal_target target = {
      .nir = nak_nir_options(nak), .max_instructions = 1u << 20, .max_threadgroup_bytes = 49152,
      .max_private_bytes = 1u << 16, .max_constant_bytes = 65536, .max_varying_slots = 31,
      .max_payload_bytes = 16384, .max_mesh_vertices = 256, .max_mesh_primitives = 512,
   };
   unsigned refused = 0;
   for (int i = first; i < argc; i++)
      refused += sweep(argv[i], &target);
   nak_compiler_destroy(nak);
   glsl_type_singleton_decref();
   printf("%u refused\n", refused);
   return refused != 0;
}
