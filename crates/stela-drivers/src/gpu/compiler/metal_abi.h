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

/* MTLStageInRegionIndirectArguments, which a kernel with stage-in reads at
 * the push constants' arguments address: uint origin[3], then size[3]. */
#define STELA_METAL_STAGE_IN_ORIGIN 0u
#define STELA_METAL_STAGE_IN_SIZE 12u

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

/* TessellationArguments, which a patch draw's stages read at the push
 * constants' arguments address. Bindings are (address, length); the draw's
 * control points per patch follow the factor scale, then a uint stride per
 * vertex buffer, bound with setVertexBuffer:offset:attributeStride:. */
#define STELA_METAL_TESSELLATION_FACTORS 0u
#define STELA_METAL_TESSELLATION_PATCH_INDICES 16u
#define STELA_METAL_TESSELLATION_CONTROL_POINT_INDICES 32u
#define STELA_METAL_TESSELLATION_INSTANCE_STRIDE 48u
#define STELA_METAL_TESSELLATION_FACTOR_SCALE 52u
#define STELA_METAL_TESSELLATION_CONTROL_POINTS 56u
#define STELA_METAL_TESSELLATION_STRIDES 60u
#define STELA_METAL_TESSELLATION_BYTES 184u

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

/* stela_air_resource_id over the argument table: the MTLResourceID in an
 * array argument's slot for element, or ID zero, the null descriptors, for an
 * element past the array. Refuses arrays past the table. */
nir_def *stela_metal_resource_id(nir_builder *b, const struct stela_air_texture *texture,
                                 const struct stela_air_sampler *sampler, nir_def *element,
                                 void *stage);

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
   /* Bytes of each control point index of indexed patch draws, 2 or 4;
    * zero for patch draws without control point indices. */
   unsigned control_point_index_bytes;
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
/* The attribute at the 32-bit byte offset from base, a 4-byte aligned
 * address, read in whole words. Reads with words past the 32-bit bound
 * read zero words. */
nir_def *stela_metal_fetch_attribute(nir_builder *b, nir_def *base, nir_def *offset, nir_def *bound,
                                     unsigned format);

/* MTLStepFunction. */
enum stela_metal_step {
   STELA_METAL_STEP_CONSTANT,
   STELA_METAL_STEP_PER_VERTEX,
   STELA_METAL_STEP_PER_INSTANCE,
   STELA_METAL_STEP_PER_PATCH,
   STELA_METAL_STEP_PER_PATCH_CONTROL_POINT,
   STELA_METAL_STEP_THREAD_POSITION_IN_GRID_X,
   STELA_METAL_STEP_THREAD_POSITION_IN_GRID_Y,
   STELA_METAL_STEP_THREAD_POSITION_IN_GRID_X_INDEXED,
   STELA_METAL_STEP_THREAD_POSITION_IN_GRID_Y_INDEXED,
};
/* A stage-in attribute: its MTLVertexFormat, zero for an attribute the
 * layout lacks, its byte offset in each element and its buffer's index. */
struct stela_metal_stage_in_attribute {
   uint32_t format, offset, buffer;
};
/* A buffer's elements: their stride, or STELA_METAL_STRIDE_DYNAMIC, and
 * the step function and rate that select one. */
struct stela_metal_stage_in_layout {
   uint32_t stride, step, rate;
};
#define STELA_METAL_STRIDE_DYNAMIC UINT32_MAX
/* A stage-in layout by attribute and buffer index: an MTLVertexDescriptor
 * or MTLStageInputOutputDescriptor, whose indexed steps read the index
 * buffer at index_buffer of index_bytes, 2 or 4, indices. Offsets and
 * strides are multiples of four. */
struct stela_metal_stage_in {
   struct stela_metal_stage_in_attribute attributes[AIR_MAX_VERTEX_ATTRIBUTES];
   struct stela_metal_stage_in_layout layouts[STELA_METAL_BUFFERS];
   uint32_t index_bytes, index_buffer;
};

/* A post-tessellation vertex function's attribute at location, as
 * stela_air_fetch_attribute reads it, from the vertex buffer of its layout
 * in the primary argument table. The step function selects the element:
 * the patch ID or instance index over the rate, the first element, or the
 * control point `point` of the patch, through the draw's control point
 * indices when it has them; a patch with no point reads only the others.
 * Elements past the bound buffer read zero, as do control point indices
 * past theirs. NULL when the layout does not provide the attribute so. */
nir_def *stela_metal_fetch_patch_attribute(nir_builder *b, const struct stela_metal_stage_in *stage_in,
                                           const struct stela_metal_tessellation *tessellation,
                                           unsigned location, nir_def *ids, nir_def *point,
                                           bool integer);

/* A kernel's attribute at location, as stela_air_fetch_attribute reads it
 * at the thread's position in the grid, from the buffer of its layout in
 * the primary argument table. The step function selects the element: the
 * stage-in region's origin plus the position over the rate on the step's
 * axis, through the index buffer for indexed steps, or the first. Threads
 * outside the region read zero, as do elements past the bound buffer and
 * indices past theirs. NULL when the layout does not provide the attribute
 * so. */
nir_def *stela_metal_fetch_stage_in(nir_builder *b, const struct stela_metal_stage_in *stage_in,
                                    unsigned location, nir_def *position, bool integer);

/* One 32-bit Metal factor as Vulkan's tessellator takes it: scaled, clamped
 * to the maximum factor (less one for fractional-odd partitions) and, for
 * pow2 partitions, rounded up to a power of two. Zero, negative and NaN
 * factors pass through unchanged. */
nir_def *stela_metal_tessellation_factor(nir_builder *b, nir_def *factor, nir_def *scale,
                                         const struct stela_metal_tessellation *tessellation);

#endif
