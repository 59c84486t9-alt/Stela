/* SPDX-License-Identifier: MIT */
#ifndef STELA_METAL_ABI_H
#define STELA_METAL_ABI_H

#include "compiler/nir/nir_builder.h"
#include "air_to_nir.h"

/* The Metal device's binding ABI as compiled shaders read it; the device
 * side is metal/binding.rs, whose tests check these values against its own.
 * Every pipeline's push constants hold the GPU address of each stage's
 * argument table, which holds Metal's buffer, texture and sampler slots.
 * Shaders read the push constants with load_push_constant, which the Vulkan
 * driver lowers through its pipeline layout, and everything else from global
 * memory. */
#define STELA_METAL_PUSH_BYTES 52u
#define STELA_METAL_PUSH_TABLES 0u
#define STELA_METAL_PUSH_ARGUMENTS 24u
#define STELA_METAL_PUSH_GRID 32u
#define STELA_METAL_PUSH_AMPLIFICATION 44u
#define STELA_METAL_PUSH_VIEW_MAPPING 48u

#define STELA_METAL_BUFFERS 31u
#define STELA_METAL_TEXTURES 128u
#define STELA_METAL_SAMPLERS 16u
#define STELA_METAL_TABLE_BUFFER_ADDRESSES 0u
#define STELA_METAL_TABLE_BUFFER_LENGTHS 248u
#define STELA_METAL_TABLE_TEXTURES 496u
#define STELA_METAL_TABLE_SAMPLERS 1520u
#define STELA_METAL_TABLE_BYTES 1648u

/* AccumulateArguments and SelectArguments, which the internal kernels read
 * at the push constants' arguments address. */
#define STELA_METAL_ACCUMULATE_RESULTS 0u
#define STELA_METAL_ACCUMULATE_COUNT 8u
#define STELA_METAL_ACCUMULATE_STRIDE 12u
#define STELA_METAL_ACCUMULATE_RUNS 16u
#define STELA_METAL_ACCUMULATE_RUN_BYTES 16u
#define STELA_METAL_SELECT_RANGE 0u
#define STELA_METAL_SELECT_FLAGS 8u
#define STELA_METAL_SELECT_COUNT 16u
#define STELA_METAL_KERNEL_WORKGROUP 64u

/* TessellationArguments, which the tessellation control stage reads at the
 * push constants' arguments address. Bindings are (address, length). */
#define STELA_METAL_TESSELLATION_FACTORS 0u
#define STELA_METAL_TESSELLATION_PATCH_INDICES 16u
#define STELA_METAL_TESSELLATION_CONTROL_POINT_INDICES 32u
#define STELA_METAL_TESSELLATION_INSTANCE_STRIDE 48u
#define STELA_METAL_TESSELLATION_FACTOR_SCALE 52u

/* Descriptor set 0 is the device's bindless heap: one array per
 * binding.rs HeapArray, indexed by the halves of a texture's or sampler's
 * MTLResourceID. A texture's low half names its sampled image or uniform
 * texel buffer, its high half its storage texel buffer or storage images, one
 * per level from the index below STELA_METAL_LEVEL_SHIFT, whose bits from
 * there count them less one; a sampler's low half names its float-border
 * sampler, its high half its integer-border twin. */
#define STELA_METAL_HEAP_SET 0u
#define STELA_METAL_LEVEL_SHIFT 27u
enum stela_metal_heap_array {
   STELA_METAL_HEAP_SAMPLED_IMAGES,
   STELA_METAL_HEAP_STORAGE_IMAGES,
   STELA_METAL_HEAP_SAMPLERS,
   STELA_METAL_HEAP_UNIFORM_TEXEL_BUFFERS,
   STELA_METAL_HEAP_STORAGE_TEXEL_BUFFERS,
};

/* binding.rs TableSlot: the push-constant table a stage reads. */
enum stela_metal_table {
   STELA_METAL_TABLE_PRIMARY, /* Vertex, kernel and object functions. */
   STELA_METAL_TABLE_FRAGMENT,
   STELA_METAL_TABLE_MESH,
};

/* The binding_data of the stela_metal_bind_* callbacks. */
struct stela_metal_stage {
   enum stela_metal_table table;
};

/* The 64-bit address of the stage's argument table. */
nir_def *stela_metal_load_table(nir_builder *b, enum stela_metal_table table);

/* stela_air_load_device_value over the push constants. */
nir_def *stela_metal_load_device_value(nir_builder *b, enum stela_air_device_value value,
                                       void *stage);

/* stela_air_bind_buffer over the argument table: the bound address of the
 * buffer at Metal index buffer->index. Refuses indices past the table. */
nir_def *stela_metal_bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer,
                                 void *stage);

/* stela_air_bind_texture over the argument table and the heap: the heap
 * element the texture's MTLResourceID names, of the level for a storage
 * image, or the null descriptor for a level past the texture's. Refuses
 * indices past the table. */
nir_deref_instr *stela_metal_bind_texture(nir_builder *b, const struct stela_air_texture *texture,
                                          const struct glsl_type *type, nir_def *level,
                                          void *stage);

/* stela_air_texture_levels: the count the texture's MTLResourceID carries. */
nir_def *stela_metal_texture_levels(nir_builder *b, const struct stela_air_texture *texture,
                                    nir_def *id, void *stage);

/* stela_air_bind_sampler likewise, of the sampler's float- or integer-border
 * descriptor. */
nir_deref_instr *stela_metal_bind_sampler(nir_builder *b, const struct stela_air_sampler *sampler,
                                          bool integer, void *stage);

/* stela_air_bind_texture_id and stela_air_bind_sampler_id: the heap element
 * a loaded MTLResourceID names, as for an argument table's. */
nir_deref_instr *stela_metal_bind_texture_id(nir_builder *b, nir_def *id,
                                             const struct glsl_type *type, nir_def *level,
                                             void *stage);
nir_deref_instr *stela_metal_bind_sampler_id(nir_builder *b, nir_def *id, bool integer,
                                             void *stage);

/* The device's internal kernels, entry point "main", in workgroups of
 * STELA_METAL_KERNEL_WORKGROUP threads. Options may be NULL: the Vulkan
 * driver supplies its own when it compiles them. The caller frees the shader
 * with ralloc_free once its pipeline exists. */

/* Thread n sums run n of the AccumulateArguments: the count 64-bit results
 * at results[first + j * stride], stored to the run's destination. */
nir_shader *stela_metal_accumulate_kernel(const nir_shader_compiler_options *options);

/* Thread n below count writes the 32-bit flags[n]: 1 when the execution range
 * (uint location, length) at range holds command n, else 0. */
nir_shader *stela_metal_select_kernel(const nir_shader_compiler_options *options);

/* MTLTessellationPartitionMode, MTLTessellationFactorStepFunction and
 * MTLWinding, in their raw values. */
enum stela_metal_partition {
   STELA_METAL_PARTITION_POW2,
   STELA_METAL_PARTITION_INTEGER,
   STELA_METAL_PARTITION_FRACTIONAL_ODD,
   STELA_METAL_PARTITION_FRACTIONAL_EVEN,
};
enum stela_metal_factor_step {
   STELA_METAL_FACTOR_STEP_CONSTANT,
   STELA_METAL_FACTOR_STEP_PER_PATCH,
   STELA_METAL_FACTOR_STEP_PER_INSTANCE,
   STELA_METAL_FACTOR_STEP_PER_PATCH_AND_PER_INSTANCE,
};
enum stela_metal_winding {
   STELA_METAL_WINDING_CLOCKWISE,
   STELA_METAL_WINDING_COUNTER_CLOCKWISE,
};

/* A tessellated pipeline's fixed tessellation properties. */
struct stela_metal_tessellation {
   bool quad; /* Quad patches; triangle patches otherwise. */
   enum stela_metal_partition partition;
   unsigned max_factor; /* maxTessellationFactor, even. */
   enum stela_metal_factor_step step;
   enum stela_metal_winding winding;
};

/* The stages a tessellated pipeline runs ahead of its post-tessellation
 * vertex function, which becomes the evaluation stage. Each patch is one
 * single-point patch-list vertex numbered by the draw's patch number. The
 * vertex stage passes (vertex index, instance index, base instance) on in
 * VAR0; the instance index includes the base instance, as Metal's
 * instance_id does. The control stage maps the patch number through the
 * patch index buffer to the patch ID, reads the patch's
 * MTL{Triangle,Quad}TessellationFactorsHalf by the step function, takes each
 * through stela_metal_tessellation_factor and emits them with (patch ID,
 * instance index, base instance) in PATCH0, which the evaluation stage reads
 * as its STELA_AIR_PATCH_IDS. A patch whose
 * patch index or factors lie outside their buffers is culled with zero
 * factors, as are patches Metal culls: those with a zero, negative or NaN
 * edge factor. Entry points "main"; options may be NULL. */
nir_shader *stela_metal_tessellation_vertex(const nir_shader_compiler_options *options);
nir_shader *stela_metal_tessellation_control(const nir_shader_compiler_options *options,
                                             const struct stela_metal_tessellation *tessellation);

/* Stage-in attributes that shaders fetch from buffers themselves: a post-
 * tessellation vertex function's control points and per-patch data, and a
 * kernel's stage-in. format is an MTLVertexFormat's raw value. An attribute
 * reads as Metal's shaders see it: four 32-bit lanes, floats for normalized,
 * half and float formats and integers for the others, with the lanes the
 * format lacks filled from (0, 0, 0, 1). */

/* The attribute's bytes, or zero for a value that names no format. */
unsigned stela_metal_vertex_format_bytes(unsigned format);
/* Whether the attribute reads as integers. */
bool stela_metal_vertex_format_integer(unsigned format);
/* The attribute in words: the 32-bit words holding its bytes, the first in
 * the low bits of the first word. */
nir_def *stela_metal_decode_attribute(nir_builder *b, nir_def *words, unsigned format);
/* The attribute at a 4-byte aligned address, read in whole words. */
nir_def *stela_metal_fetch_attribute(nir_builder *b, nir_def *address, unsigned format);

/* One 32-bit Metal factor as Vulkan's tessellator takes it: scaled, clamped
 * to the maximum factor (less one for fractional-odd partitions) and, for
 * pow2 partitions, rounded up to a power of two. Zero, negative and NaN
 * factors pass through unchanged. */
nir_def *stela_metal_tessellation_factor(nir_builder *b, nir_def *factor, nir_def *scale,
                                         const struct stela_metal_tessellation *tessellation);

#endif
