/* SPDX-License-Identifier: MIT */
/* Indirect command encoding from kernels: AIR's command functions in the
 * forms Apple's compiler emits for render_command and compute_command,
 * written to GPU-resident records over the Metal ABI, and run over test
 * memory. Original LLVM IR fixtures; no Apple output. */
#include "../metal_abi.h"
#include "compiler/air_to_nir.h"
#include "air_effect_oracle.h"
#include "air_test_fixture.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef NDEBUG
#error "These tests require active assertions"
#endif

static const nir_shader_compiler_options nir_options = {.max_unroll_iterations = 32};

static const char *module =
   "target datalayout = \"e-p:64:64-i32:32-i64:64-f32:32-v128:128-n8:16:32\"\n"
   "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
   "%struct.Commands = type { ptr addrspace(1), ptr addrspace(1), ptr addrspace(1) }\n"
   "declare i32 @air.get_size_command_buffer(ptr addrspace(1))\n"
   "declare void @air.set_pipeline_state_render_command(ptr addrspace(1), i32, ptr addrspace(1))\n"
   "declare void @air.set_vertex_buffer_render_command.p1i8(ptr addrspace(1), i32, ptr addrspace(1),"
   " i64, i32)\n"
   "declare void @air.set_fragment_buffer_render_command.p2i8(ptr addrspace(1), i32,"
   " ptr addrspace(2), i32)\n"
   "declare void @air.set_barrier_render_command(ptr addrspace(1), i32)\n"
   "declare void @air.draw_primitives_render_command(ptr addrspace(1), i32, i32, i32, i32, i32, i32)\n"
   "declare void @air.draw_indexed_primitives_render_command.p1i16(ptr addrspace(1), i32, i32, i32,"
   " ptr addrspace(1), i32, i32, i32)\n"
   "declare void @air.copy_render_command(ptr addrspace(1), i32, ptr addrspace(1), i32)\n"
   "declare void @air.reset_render_command(ptr addrspace(1), i32)\n"
   "declare void @air.set_pipeline_state_compute_command(ptr addrspace(1), i32, ptr addrspace(1))\n"
   "declare void @air.set_kernel_buffer_compute_command.p1i8(ptr addrspace(1), i32, ptr addrspace(1),"
   " i64, i32)\n"
   "declare void @air.set_threadgroup_memory_length_compute_command(ptr addrspace(1), i32, i32, i32)\n"
   "declare void @air.set_stage_in_region_compute_command(ptr addrspace(1), i32, <3 x i32>,"
   " <3 x i32>)\n"
   "declare void @air.clear_barrier_compute_command(ptr addrspace(1), i32)\n"
   "declare void @air.concurrent_dispatch_threads_compute_command(ptr addrspace(1), i32, <3 x i32>,"
   " <3 x i32>)\n"
   "declare void @air.draw_patches_render_command.p1i32.p1i8(ptr addrspace(1), i32, i32, i32, i32,"
   " ptr addrspace(1), i32, i32, ptr addrspace(1), i32, float)\n";

#define KERNEL(body) \
   "define void @kernel(ptr addrspace(1) %icb, ptr addrspace(1) %vertices," \
   " ptr addrspace(2) %constants, ptr addrspace(1) %indices, ptr addrspace(1) %out) {\n" \
   "%cp = getelementptr inbounds %struct.Commands, ptr addrspace(1) %icb, i64 0, i32 0\n" \
   "%cb = load ptr addrspace(1), ptr addrspace(1) %cp, align 8\n" \
   "%pp = getelementptr inbounds %struct.Commands, ptr addrspace(1) %icb, i64 0, i32 1\n" \
   "%ps = load ptr addrspace(1), ptr addrspace(1) %pp, align 8\n" \
   "%op = getelementptr inbounds %struct.Commands, ptr addrspace(1) %icb, i64 0, i32 2\n" \
   "%other = load ptr addrspace(1), ptr addrspace(1) %op, align 8\n" body "ret void\n}\n"

static const char *render_body = KERNEL(
   "%size = call i32 @air.get_size_command_buffer(ptr addrspace(1) %cb)\n"
   "store i32 %size, ptr addrspace(1) %out, align 4\n"
   "call void @air.set_pipeline_state_render_command(ptr addrspace(1) %cb, i32 1,"
   " ptr addrspace(1) %ps)\n"
   "call void @air.set_vertex_buffer_render_command.p1i8(ptr addrspace(1) %cb, i32 1,"
   " ptr addrspace(1) %vertices, i64 32, i32 1)\n"
   "call void @air.set_vertex_buffer_render_command.p1i8(ptr addrspace(1) %cb, i32 1,"
   " ptr addrspace(1) %vertices, i64 -1, i32 2)\n"
   "call void @air.set_fragment_buffer_render_command.p2i8(ptr addrspace(1) %cb, i32 1,"
   " ptr addrspace(2) %constants, i32 3)\n"
   "call void @air.set_barrier_render_command(ptr addrspace(1) %cb, i32 1)\n"
   "call void @air.draw_indexed_primitives_render_command.p1i16(ptr addrspace(1) %cb, i32 1,"
   " i32 3, i32 6, ptr addrspace(1) %indices, i32 2, i32 -2, i32 7)\n"
   /* A command past the buffer and a slot past its table. */
   "call void @air.draw_primitives_render_command(ptr addrspace(1) %cb, i32 3, i32 2, i32 0,"
   " i32 4, i32 1, i32 0)\n"
   "call void @air.set_vertex_buffer_render_command.p1i8(ptr addrspace(1) %cb, i32 0,"
   " ptr addrspace(1) %vertices, i64 -1, i32 4)\n"
   "call void @air.copy_render_command(ptr addrspace(1) %cb, i32 2, ptr addrspace(1) %other,"
   " i32 1)\n"
   "call void @air.reset_render_command(ptr addrspace(1) %other, i32 0)\n");

static const char *compute_body = KERNEL(
   "call void @air.set_pipeline_state_compute_command(ptr addrspace(1) %cb, i32 0,"
   " ptr addrspace(1) %ps)\n"
   "call void @air.set_kernel_buffer_compute_command.p1i8(ptr addrspace(1) %cb, i32 0,"
   " ptr addrspace(1) %vertices, i64 -1, i32 2)\n"
   "call void @air.set_threadgroup_memory_length_compute_command(ptr addrspace(1) %cb, i32 0,"
   " i32 1024, i32 1)\n"
   "call void @air.set_stage_in_region_compute_command(ptr addrspace(1) %cb, i32 0,"
   " <3 x i32> <i32 1, i32 2, i32 3>, <3 x i32> <i32 4, i32 5, i32 6>)\n"
   "call void @air.clear_barrier_compute_command(ptr addrspace(1) %cb, i32 0)\n"
   "call void @air.concurrent_dispatch_threads_compute_command(ptr addrspace(1) %cb, i32 0,"
   " <3 x i32> <i32 100, i32 2, i32 1>, <3 x i32> <i32 32, i32 2, i32 1>)\n");

static const char *metadata(bool compute)
{
   static char text[4096];
   snprintf(text, sizeof(text),
      "!air.kernel = !{!2}\n"
      "!air.version = !{!20}\n!air.language_version = !{!21}\n"
      "!2 = !{ptr @kernel, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7, !8, !9}\n"
      "!5 = !{i32 0, !\"air.indirect_buffer\", !\"air.buffer_size\", i32 24, !\"air.location_index\","
      " i32 0, i32 1, !\"air.read_write\", !\"air.address_space\", i32 1, !\"air.struct_type_info\", !30,"
      " !\"air.arg_type_size\", i32 24, !\"air.arg_type_align_size\", i32 8, !\"air.arg_type_name\","
      " !\"Commands\", !\"air.arg_name\", !\"icb\"}\n"
      "!6 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 1, i32 1, !\"air.read\","
      " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\","
      " i32 16, !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"vertices\"}\n"
      "!7 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 2, i32 1, !\"air.read\","
      " !\"air.address_space\", i32 2, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
      " i32 4, !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"constants\"}\n"
      "!8 = !{i32 3, !\"air.buffer\", !\"air.location_index\", i32 3, i32 1, !\"air.read\","
      " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 2, !\"air.arg_type_align_size\","
      " i32 2, !\"air.arg_type_name\", !\"ushort\", !\"air.arg_name\", !\"indices\"}\n"
      "!9 = !{i32 4, !\"air.buffer\", !\"air.location_index\", i32 4, i32 1, !\"air.read_write\","
      " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
      " i32 4, !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"out\"}\n"
      "!30 = !{i32 0, i32 8, i32 0, !\"command_buffer\", !\"commands\", !\"air.indirect_argument\", !31,"
      " i32 8, i32 8, i32 0, !\"%s_pipeline_state\", !\"pipeline\", !\"air.indirect_argument\", !32,"
      " i32 16, i32 8, i32 0, !\"command_buffer\", !\"other\", !\"air.indirect_argument\", !33}\n"
      "!31 = !{i32 0, !\"air.command_buffer\", !\"air.location_index\", i32 0, i32 1,"
      " !\"air.arg_type_name\", !\"command_buffer\", !\"air.arg_name\", !\"commands\"}\n"
      "!32 = !{i32 1, !\"air.%s_pipeline_state\", !\"air.location_index\", i32 1, i32 1,"
      " !\"air.arg_type_name\", !\"%s_pipeline_state\", !\"air.arg_name\", !\"pipeline\"}\n"
      "!33 = !{i32 2, !\"air.command_buffer\", !\"air.location_index\", i32 2, i32 1,"
      " !\"air.arg_type_name\", !\"command_buffer\", !\"air.arg_name\", !\"other\"}\n"
      "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n",
      compute ? "compute" : "render", compute ? "compute" : "render", compute ? "compute" : "render");
   return text;
}

static struct stela_metal_stage primary = {.table = STELA_METAL_TABLE_PRIMARY};

static nir_shader *
kernel(const char *body, const char *metadata, struct stela_air_error *error)
{
   const struct stela_air_options o = {
      .workgroup_size = {1, 1, 1}, .max_instructions = 10000,
      .bind_buffer = stela_metal_bind_buffer, .binding_data = &primary,
      .command_count = stela_metal_command_count, .encode_command = stela_metal_encode_command,
   };
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, body, metadata, "");
   *error = (struct stela_air_error){0};
   nir_shader *shader = stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                         "kernel", &nir_options, &o, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

static nir_shader *
translated(const char *body, const char *metadata)
{
   struct stela_air_error error;
   nir_shader *shader = kernel(body, metadata, &error);
   if (!shader)
      fprintf(stderr, "kernel: %u %s\n", error.kind, error.detail);
   assert(shader && error.kind == STELA_AIR_OK);
   return shader;
}

/* Test memory: the argument table, the argument buffer, the size result
 * and two indirect command buffers' records. */
#define BASE 0x10000ull
#define TABLE 0x0u
#define ARGUMENTS 0x700u
#define OUT 0x780u
#define COMMANDS 0x800u
#define OTHER 0x1000u
#define MEMORY 0x1800u
#define SENTINEL 0xcd
#define VERTICES 0xabc000ull
#define CONSTANTS 0xdef000ull
#define INDICES 0x123400ull
#define PIPELINE 0x0000000300000002ull

/* Records of four buffer slots per table and four words: a render
 * buffer's vertex and fragment tables, or a compute buffer's kernel table. */
struct layout {
   uint32_t stride, count, tables[2], table_slots[2], words, word_count;
};
static const struct layout render_layout = {224, 3, {80, 144}, {4, 4}, 208, 4};
static const struct layout compute_layout = {160, 2, {80, 0}, {4, 0}, 144, 4};

static uint8_t memory[MEMORY];
static uint8_t push[STELA_METAL_PUSH_BYTES];

static void put32(uint8_t *at, uint32_t value)
{
   for (unsigned i = 0; i < 4; i++)
      at[i] = (uint8_t)(value >> (8 * i));
}
static void put64(uint8_t *at, uint64_t value)
{
   put32(at, (uint32_t)value);
   put32(at + 4, (uint32_t)(value >> 32));
}
static uint32_t get32(const uint8_t *at)
{
   return at[0] | (uint32_t)at[1] << 8 | (uint32_t)at[2] << 16 | (uint32_t)at[3] << 24;
}
static uint64_t get64(const uint8_t *at)
{
   return get32(at) | (uint64_t)get32(at + 4) << 32;
}

static void header(unsigned at, const struct layout *layout)
{
   uint8_t *h = memory + at;
   memset(h, 0, STELA_METAL_INDIRECT_HEADER_BYTES);
   put32(h + STELA_METAL_INDIRECT_STRIDE, layout->stride);
   put32(h + STELA_METAL_INDIRECT_COUNT, layout->count);
   for (unsigned t = 0; t < 2; t++) {
      put32(h + STELA_METAL_INDIRECT_TABLES + 4 * t, layout->tables[t]);
      put32(h + STELA_METAL_INDIRECT_TABLE_SLOTS + 4 * t, layout->table_slots[t]);
   }
   put32(h + STELA_METAL_INDIRECT_WORDS, layout->words);
   put32(h + STELA_METAL_INDIRECT_WORD_COUNT, layout->word_count);
}

/* Fills memory with sentinels, the headers and the table, and runs. */
static void run(nir_shader *shader, const struct layout *layout)
{
   memset(memory, SENTINEL, sizeof(memory));
   memset(push, 0, sizeof(push));
   put64(push + STELA_METAL_PUSH_TABLES, BASE + TABLE);
   const uint64_t slots[] = {BASE + ARGUMENTS, VERTICES, CONSTANTS, INDICES, BASE + OUT};
   for (unsigned i = 0; i < ARRAY_SIZE(slots); i++)
      put64(memory + TABLE + STELA_METAL_TABLE_BUFFER_ADDRESSES + 8 * i, slots[i]);
   put64(memory + ARGUMENTS, BASE + COMMANDS);
   put64(memory + ARGUMENTS + 8, PIPELINE);
   put64(memory + ARGUMENTS + 16, BASE + OTHER);
   header(COMMANDS, layout);
   header(OTHER, layout);
   /* The other buffer's command 1 is a pattern a copy carries. */
   uint8_t *source = memory + OTHER + STELA_METAL_INDIRECT_HEADER_BYTES + layout->stride;
   for (unsigned i = 0; i < layout->stride; i++)
      source[i] = (uint8_t)i;

   /* Structurization's path variables. */
   nir_lower_vars_to_ssa(shader);
   nir_opt_dce(shader);
   const struct air_effect_environment test = {.base = BASE, .bytes = memory,
                                               .size = sizeof(memory), .push = push,
                                               .push_size = sizeof(push)};
   struct air_effect_store trace[64];
   struct air_effect_run result = air_effect_execute_in(shader, 100000, trace, ARRAY_SIZE(trace),
                                                        &test);
   if (result.status != AIR_EFFECT_COMPLETE) {
      fprintf(stderr, "run: %u %s\n", result.status, result.detail);
      nir_print_shader(shader, stderr);
   }
   assert(result.status == AIR_EFFECT_COMPLETE);
}

static uint8_t *record(unsigned buffer, const struct layout *layout, unsigned index)
{
   return memory + buffer + STELA_METAL_INDIRECT_HEADER_BYTES + index * layout->stride;
}

static bool untouched(const uint8_t *bytes, unsigned count)
{
   for (unsigned i = 0; i < count; i++) {
      if (bytes[i] != SENTINEL)
         return false;
   }
   return true;
}

static void
kernels_encode_render_commands(void)
{
   nir_shader *shader = translated(render_body, metadata(false));
   const struct layout *l = &render_layout;
   run(shader, l);
   assert(get32(memory + OUT) == 3);

   const uint8_t *r = record(COMMANDS, l, 1);
   assert(get64(r + STELA_METAL_RECORD_PIPELINE) == PIPELINE);
   assert(get32(r + STELA_METAL_RECORD_BARRIER) == 1);
   /* Vertex buffers 1 and 2, with a stride and the pipeline's, and
    * fragment buffer 3, each unbounded. */
   const uint8_t *vertex = r + l->tables[0], *fragment = r + l->tables[1];
   for (unsigned slot = 1; slot <= 2; slot++) {
      assert(get64(vertex + 8 * slot) == VERTICES);
      assert(get64(vertex + 8 * (4 + slot)) == STELA_METAL_RECORD_UNBOUNDED);
   }
   assert(get32(r + l->words + 4) == 32 && get32(r + l->words + 8) == 0);
   assert(untouched(vertex, 8) && untouched(vertex + 24, 16));
   assert(get64(fragment + 8 * 3) == CONSTANTS);
   assert(get64(fragment + 8 * (4 + 3)) == STELA_METAL_RECORD_UNBOUNDED);
   /* The indexed draw. */
   assert(get32(r + STELA_METAL_RECORD_ACTION) == STELA_METAL_RECORD_DRAW_INDEXED);
   assert(get32(r + STELA_METAL_RECORD_VERTICES) == 6);
   assert(get32(r + STELA_METAL_RECORD_INSTANCES) == 2);
   assert(get32(r + STELA_METAL_RECORD_FIRST_VERTEX) == 0);
   assert(get32(r + STELA_METAL_RECORD_BASE_VERTEX) == (uint32_t)-2);
   assert(get32(r + STELA_METAL_RECORD_BASE_INSTANCE) == 7);
   assert(get32(r + STELA_METAL_RECORD_PRIMITIVE) == 3);
   assert(get64(r + STELA_METAL_RECORD_INDEX_ADDRESS) == INDICES);
   assert(get32(r + STELA_METAL_RECORD_INDEX_LENGTH) == 12);
   assert(get32(r + STELA_METAL_RECORD_INDEX_TYPE) == 0);

   /* Nothing past the buffer, nor past record 0's vertex table. */
   assert(untouched(record(COMMANDS, l, 3), l->stride));
   assert(untouched(record(COMMANDS, l, 0), l->stride));
   /* Command 2 is the other buffer's command 1, whose command 0 is reset. */
   assert(!memcmp(record(COMMANDS, l, 2), record(OTHER, l, 1), l->stride));
   for (unsigned i = 0; i < l->stride; i++)
      assert(record(OTHER, l, 0)[i] == 0);
   ralloc_free(shader);
}

static void
kernels_encode_compute_commands(void)
{
   nir_shader *shader = translated(compute_body, metadata(true));
   const struct layout *l = &compute_layout;
   run(shader, l);
   const uint8_t *r = record(COMMANDS, l, 0);
   assert(get64(r + STELA_METAL_RECORD_PIPELINE) == PIPELINE);
   assert(get32(r + STELA_METAL_RECORD_BARRIER) == 0);
   assert(get64(r + l->tables[0] + 8 * 2) == VERTICES);
   assert(get32(r + l->words + 4) == 1024);
   for (unsigned i = 0; i < 3; i++) {
      assert(get32(r + STELA_METAL_RECORD_STAGE_IN_ORIGIN + 4 * i) == 1 + i);
      assert(get32(r + STELA_METAL_RECORD_STAGE_IN_SIZE + 4 * i) == 4 + i);
   }
   assert(get32(r + STELA_METAL_RECORD_STAGE_IN) == 1);
   assert(get32(r + STELA_METAL_RECORD_ACTION) == STELA_METAL_RECORD_DISPATCH_THREADS);
   const uint32_t grid[] = {100, 2, 1, 32, 2, 1};
   for (unsigned i = 0; i < 6; i++)
      assert(get32(r + STELA_METAL_RECORD_GRID + 4 * i) == grid[i]);
   assert(untouched(record(COMMANDS, l, 1), l->stride));
   ralloc_free(shader);
}

static void
refused(const char *body, const char *metadata, enum stela_air_error_kind kind)
{
   struct stela_air_error error;
   nir_shader *shader = kernel(body, metadata, &error);
   if (shader || error.kind != kind)
      fprintf(stderr, "expected refusal %u, got %u %s\n", kind, error.kind, error.detail);
   assert(!shader && error.kind == kind);
}

static void
unsupported_commands_are_refused(void)
{
   /* Patch draws are not lowered. */
   refused(KERNEL("call void @air.draw_patches_render_command.p1i32.p1i8(ptr addrspace(1) %cb,"
                  " i32 0, i32 3, i32 0, i32 1, ptr addrspace(1) %indices, i32 1, i32 0,"
                  " ptr addrspace(1) %vertices, i32 0, float 1.0)\n"),
           metadata(false), STELA_AIR_INSTRUCTION);
   /* A pipeline state of the other kind, and a buffer as a command buffer. */
   refused(KERNEL("call void @air.set_pipeline_state_compute_command(ptr addrspace(1) %cb, i32 0,"
                  " ptr addrspace(1) %ps)\n"),
           metadata(false), STELA_AIR_ARGUMENT);
   refused(KERNEL("call void @air.reset_render_command(ptr addrspace(1) %vertices, i32 0)\n"),
           metadata(false), STELA_AIR_ARGUMENT);
   /* Without the callbacks. */
   const struct stela_air_options o = {
      .workgroup_size = {1, 1, 1}, .max_instructions = 10000,
      .bind_buffer = stela_metal_bind_buffer, .binding_data = &primary,
   };
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, render_body, metadata(false), "");
   struct stela_air_error error = {0};
   assert(!stela_air_to_nir(LLVMGetBufferStart(input), LLVMGetBufferSize(input), "kernel",
                            &nir_options, &o, &error) &&
          error.kind == STELA_AIR_INSTRUCTION);
   LLVMDisposeMemoryBuffer(input);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   kernels_encode_render_commands();
   kernels_encode_compute_commands();
   unsupported_commands_are_refused();
   glsl_type_singleton_decref();
   puts("air commands: ok");
   return 0;
}
