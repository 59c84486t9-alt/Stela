/* SPDX-License-Identifier: MIT */
#ifndef STELA_METAL_COMPILER_H
#define STELA_METAL_COMPILER_H
/* The Metal device's compiler service: shader::Compiler's reflection and
 * compilation of one AIR function, over the binding ABI of metal_abi.h. The
 * platform links it with LLVM and Mesa and hands the device a table of these
 * functions; metal/compiler.rs mirrors every layout here, and the
 * STELA_METAL_*_BYTES sizes are checked on both sides. */
#include "metal_abi.h"

/* MTLFunctionType values of the stages. */
enum stela_metal_function_stage {
   STELA_METAL_VERTEX = 1,
   STELA_METAL_FRAGMENT = 2,
   STELA_METAL_KERNEL = 3,
   STELA_METAL_MESH = 7,
   STELA_METAL_OBJECT = 8,
};

#define STELA_METAL_ATTRIBUTES 31u
#define STELA_METAL_VARYINGS 32u
/* Eight render targets and the second source of dual-source blending. */
#define STELA_METAL_COLOR_OUTPUTS 9u
#define STELA_METAL_FUNCTION_CONSTANTS 256u
#define STELA_METAL_NAME_BYTES 8192u

/* Access flags, as shader.rs Access. */
#define STELA_METAL_ACCESS_READ 1u
#define STELA_METAL_ACCESS_WRITE 2u
#define STELA_METAL_ACCESS_SAMPLE 4u

/* A buffer slot; argument_buffer marks an argument buffer. */
struct stela_metal_buffer_use {
   uint32_t index, access, argument_buffer;
};
/* A texture slot: type is an enum stela_air_texture_type and primitive the
 * enum stela_air_primitive of its components. */
struct stela_metal_texture_use {
   uint32_t index, access, type, primitive;
};
/* A threadgroup buffer slot and the bytes its type declares. */
struct stela_metal_threadgroup_use {
   uint32_t index, bytes;
};
/* A stage-in attribute. */
struct stela_metal_attribute_use {
   uint32_t index, primitive, components;
};
/* A varying: its identifier is names[identifier, identifier + bytes). */
struct stela_metal_varying {
   uint32_t identifier, identifier_bytes, primitive, components, per_primitive;
};
/* A render target output; dual_source marks [[index(1)]]. */
struct stela_metal_color_output {
   uint32_t index, primitive, dual_source;
};

/* A function constant: its name and MSL type spelling are in names. */
struct stela_metal_function_constant {
   uint32_t index, name, name_bytes, type, type_bytes, required;
};

/* One function's reflection. names holds the varying identifiers, the
 * function constants' names and types and the module's llvm.ident, whose
 * bytes are zero when it records none. */
struct stela_metal_reflection {
   uint32_t stage, max_total_threads;
   uint64_t threadgroup_bytes;
   uint32_t buffer_count, texture_count, sampler_count, threadgroup_count;
   uint32_t attribute_count, varying_count, color_output_count;
   uint32_t writes_depth, writes_stencil, writes_sample_mask, discards, amplification;
   uint32_t ident, ident_bytes, names_bytes, function_constant_count;
   /* A post-tessellation vertex function's enum stela_air_patch and the
    * control points it declares, zero when it declares none. */
   uint32_t patch, patch_control_points;
   struct stela_metal_buffer_use buffers[STELA_METAL_BUFFERS];
   struct stela_metal_texture_use textures[STELA_METAL_TEXTURES];
   uint32_t samplers[STELA_METAL_SAMPLERS];
   struct stela_metal_threadgroup_use threadgroup[STELA_METAL_BUFFERS];
   struct stela_metal_attribute_use attributes[STELA_METAL_ATTRIBUTES];
   struct stela_metal_varying varyings[STELA_METAL_VARYINGS];
   struct stela_metal_color_output color_outputs[STELA_METAL_COLOR_OUTPUTS];
   struct stela_metal_function_constant function_constants[STELA_METAL_FUNCTION_CONSTANTS];
   char names[STELA_METAL_NAME_BYTES];
};
#define STELA_METAL_REFLECTION_BYTES 18280u

/* The target's facts, fixed for a device. nir is the Vulkan driver's
 * compiler options, which must outlive every shader compiled with them. */
struct stela_metal_target {
   const nir_shader_compiler_options *nir;
   uint32_t max_instructions, max_threadgroup_bytes, max_private_bytes, max_constant_bytes;
   uint32_t max_varying_slots, max_payload_bytes, max_mesh_vertices, max_mesh_primitives;
};
#define STELA_METAL_TARGET_BYTES 40u

/* A threadgroup buffer's setThreadgroupMemoryLength:atIndex:. */
struct stela_metal_threadgroup_length {
   uint32_t index, bytes;
};
/* A linked varying, at the location of its position. */
struct stela_metal_linked_varying {
   const char *identifier;
   size_t identifier_bytes;
   uint32_t per_primitive;
};
#define STELA_METAL_LINKED_VARYING_BYTES 24u

#define STELA_METAL_CONSTANT_VALUE_BYTES 24u

/* shader.rs Specialization, with a post-tessellation vertex function's
 * pipeline tessellation, and the stage-in layout a kernel or
 * post-tessellation vertex function fetches by; either may be NULL, and
 * every other function has neither. */
struct stela_metal_specialization {
   uint32_t workgroup_size[3];
   uint32_t threadgroup_length_count;
   const struct stela_metal_threadgroup_length *threadgroup_lengths;
   const struct stela_metal_linked_varying *varyings;
   uint32_t varying_count, amplified, launched_by_grid, constant_count;
   const struct stela_air_constant_value *constants;
   const struct stela_metal_tessellation *tessellation;
   const struct stela_metal_stage_in *stage_in;
};
#define STELA_METAL_SPECIALIZATION_BYTES 72u
/* The metal_abi.h layouts it points to. */
#define STELA_METAL_PIPELINE_TESSELLATION_BYTES 24u
#define STELA_METAL_STAGE_IN_BYTES 752u

/* Reflects entry of the AIR module. False after reporting why in error. */
bool stela_metal_reflect(const void *air, size_t size, const char *entry,
                         struct stela_metal_reflection *reflection,
                         struct stela_air_error *error);

/* Compiles entry against the specialization: NIR whose entry point is
 * main, which stela_metal_release frees, or NULL after reporting why. */
nir_shader *stela_metal_compile(const void *air, size_t size, const char *entry,
                                const struct stela_metal_target *target,
                                const struct stela_metal_specialization *specialization,
                                struct stela_air_error *error);

/* The vertex and control stages a tessellated pipeline runs ahead of its
 * post-tessellation vertex function (metal_abi.h), each with entry point
 * main, which stela_metal_release frees. */
void stela_metal_tessellation_stages(const struct stela_metal_target *target,
                                     const struct stela_metal_tessellation *tessellation,
                                     nir_shader *stages[2]);

void stela_metal_release(nir_shader *shader);
#endif
