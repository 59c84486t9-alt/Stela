/* SPDX-License-Identifier: MIT */
#ifndef STELA_METAL_ABI_H
#define STELA_METAL_ABI_H

#include "compiler/nir/nir_builder.h"
#include "air_metadata.h"

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

/* binding.rs TableSlot: the push-constant table a stage reads. */
enum stela_metal_table {
   STELA_METAL_TABLE_PRIMARY, /* Vertex, kernel and object functions. */
   STELA_METAL_TABLE_FRAGMENT,
   STELA_METAL_TABLE_MESH,
};

/* The binding_data of stela_metal_bind_buffer. */
struct stela_metal_stage {
   enum stela_metal_table table;
};

/* The 64-bit address of the stage's argument table. */
nir_def *stela_metal_load_table(nir_builder *b, enum stela_metal_table table);

/* stela_air_bind_buffer over the argument table: the bound address of the
 * buffer at Metal index buffer->index. Refuses indices past the table. */
nir_def *stela_metal_bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer,
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

#endif
