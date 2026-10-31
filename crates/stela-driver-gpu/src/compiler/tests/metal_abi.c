/* SPDX-License-Identifier: MIT */
/* The Metal ABI's NIR shapes; the GPU behavior needs a device. */
#include "../metal_abi.h"
#include "air_effect_oracle.h"
#include "util/ralloc.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#ifdef NDEBUG
#error "These tests require active assertions"
#endif

static nir_intrinsic_instr *intrinsic(nir_def *def, nir_intrinsic_op op)
{
   assert(nir_def_is_intrinsic(def));
   nir_intrinsic_instr *instr = nir_def_as_intrinsic(def);
   assert(instr->intrinsic == op);
   return instr;
}

/* The intrinsic at address + offset. */
static nir_intrinsic_instr *offset_from(nir_def *address, unsigned offset, nir_intrinsic_op op)
{
   nir_alu_instr *add = nir_def_as_alu(address);
   assert(add->op == nir_op_iadd);
   assert(nir_src_as_uint(add->src[1].src) == offset);
   return intrinsic(add->src[0].src.ssa, op);
}

static void buffers_load_their_table_slot(void)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_FRAGMENT, NULL, "bind");
   const struct stela_metal_stage stage = {.table = STELA_METAL_TABLE_FRAGMENT};
   const struct stela_air_buffer buffer = {.index = 5, .access = STELA_AIR_READ_WRITE};
   nir_def *address = stela_metal_bind_buffer(&b, &buffer, (void *)&stage);
   nir_intrinsic_instr *load = intrinsic(address, nir_intrinsic_load_global);
   assert(load->def.bit_size == 64 && nir_intrinsic_access(load) & ACCESS_NON_WRITEABLE);
   nir_intrinsic_instr *table = offset_from(load->src[0].ssa,
                                            STELA_METAL_TABLE_BUFFER_ADDRESSES + 5 * 8,
                                            nir_intrinsic_load_push_constant);
   assert(nir_intrinsic_base(table) == STELA_METAL_PUSH_TABLES + 8);
   assert(nir_intrinsic_range(table) == 8 && table->def.bit_size == 64);

   const struct stela_air_buffer past = {.index = STELA_METAL_BUFFERS};
   assert(!stela_metal_bind_buffer(&b, &past, (void *)&stage));
   ralloc_free(b.shader);
}

/* The table load and ID half a heap element's index takes. */
static void check_heap_index(nir_deref_instr *deref, unsigned table_offset, bool high)
{
   nir_def *index = deref->arr.index.ssa;
   nir_alu_instr *half = nir_def_as_alu(index);
   /* A storage image's first level is the half below the level count. */
   if (half->op == nir_op_iand)
      half = nir_def_as_alu(half->src[0].src.ssa);
   if (half->op == nir_op_i2i32 || half->op == nir_op_u2u32 || half->op == nir_op_i2i64 ||
       half->op == nir_op_u2u64)
      half = nir_def_as_alu(half->src[0].src.ssa);
   assert(half->op == (high ? nir_op_unpack_64_2x32_split_y : nir_op_unpack_64_2x32_split_x));
   nir_intrinsic_instr *id = intrinsic(half->src[0].src.ssa, nir_intrinsic_load_global);
   assert(id->def.bit_size == 64 && nir_intrinsic_access(id) & ACCESS_CAN_REORDER);
   offset_from(id->src[0].ssa, table_offset, nir_intrinsic_load_push_constant);
}

static nir_variable *check_heap(nir_deref_instr *deref, enum stela_metal_heap_array array,
                                nir_variable_mode mode, const struct glsl_type *type)
{
   assert(deref->deref_type == nir_deref_type_array && deref->type == type);
   nir_variable *var = nir_deref_instr_get_variable(deref);
   assert(var->data.mode == mode && var->data.descriptor_set == STELA_METAL_HEAP_SET);
   assert(var->data.binding == array && glsl_get_length(var->type) == 0);
   return var;
}

static void textures_and_samplers_index_the_heap(void)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_FRAGMENT, NULL, "heap");
   const struct stela_metal_stage stage = {.table = STELA_METAL_TABLE_FRAGMENT};
   const struct glsl_type *sampled = glsl_texture_type(GLSL_SAMPLER_DIM_2D, false, GLSL_TYPE_FLOAT);
   const struct glsl_type *storage = glsl_image_type(GLSL_SAMPLER_DIM_2D, true, GLSL_TYPE_UINT);
   const struct glsl_type *texels = glsl_texture_type(GLSL_SAMPLER_DIM_BUF, false, GLSL_TYPE_INT);
   const struct glsl_type *buffer = glsl_image_type(GLSL_SAMPLER_DIM_BUF, false, GLSL_TYPE_FLOAT);
   const struct stela_air_texture texture = {.index = 3};

   nir_deref_instr *deref =
      stela_metal_bind_texture(&b, &texture, sampled, false, NULL, (void *)&stage);
   nir_variable *images = check_heap(deref, STELA_METAL_HEAP_SAMPLED_IMAGES, nir_var_uniform,
                                     sampled);
   check_heap_index(deref, STELA_METAL_TABLE_TEXTURES + 3 * 8, false);
   /* One variable per element type. */
   deref = stela_metal_bind_texture(&b, &texture, sampled, false, NULL, (void *)&stage);
   assert(nir_deref_instr_get_variable(deref) == images);

   deref = stela_metal_bind_texture(&b, &texture, storage, false, NULL, (void *)&stage);
   nir_variable *image = check_heap(deref, STELA_METAL_HEAP_STORAGE_IMAGES, nir_var_image,
                                    storage);
   assert(image->data.image.format == PIPE_FORMAT_NONE);
   check_heap_index(deref, STELA_METAL_TABLE_TEXTURES + 3 * 8, true);

   deref = stela_metal_bind_texture(&b, &texture, texels, false, NULL, (void *)&stage);
   check_heap(deref, STELA_METAL_HEAP_UNIFORM_TEXEL_BUFFERS, nir_var_uniform, texels);
   deref = stela_metal_bind_texture(&b, &texture, buffer, false, NULL, (void *)&stage);
   check_heap(deref, STELA_METAL_HEAP_STORAGE_TEXEL_BUFFERS, nir_var_image, buffer);

   const struct stela_air_sampler sampler = {.index = 15};
   deref = stela_metal_bind_sampler(&b, &sampler, false, (void *)&stage);
   check_heap(deref, STELA_METAL_HEAP_SAMPLERS, nir_var_uniform, glsl_bare_sampler_type());
   check_heap_index(deref, STELA_METAL_TABLE_SAMPLERS + 15 * 8, false);
   deref = stela_metal_bind_sampler(&b, &sampler, true, (void *)&stage);
   check_heap_index(deref, STELA_METAL_TABLE_SAMPLERS + 15 * 8, true);

   const struct stela_air_texture past_textures = {.index = STELA_METAL_TEXTURES};
   const struct stela_air_sampler past_samplers = {.index = STELA_METAL_SAMPLERS};
   assert(!stela_metal_bind_texture(&b, &past_textures, sampled, false, NULL, (void *)&stage));
   assert(!stela_metal_bind_sampler(&b, &past_samplers, false, (void *)&stage));
   ralloc_free(b.shader);
}

/* A storage image's level indexes its texture's run of descriptors, and a
 * level past the run indexes the null descriptor. */
static void storage_levels_index_their_run(void)
{
   const struct glsl_type *storage = glsl_image_type(GLSL_SAMPLER_DIM_2D, false, GLSL_TYPE_FLOAT);
   /* Three levels from descriptor 9. */
   const uint64_t id = (uint64_t)(9u | 2u << STELA_METAL_LEVEL_SHIFT) << 32 | 4u;
   const unsigned expected[] = {9, 10, 11, 0};
   for (unsigned level = 0; level < ARRAY_SIZE(expected); level++) {
      nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "level");
      nir_deref_instr *deref = stela_metal_bind_texture_id(&b, nir_imm_int64(&b, id), storage,
                                                           false, nir_imm_int(&b, level), NULL);
      nir_opt_constant_folding(b.shader);
      assert(nir_src_is_const(deref->arr.index) &&
             nir_src_as_uint(deref->arr.index) == expected[level]);
      ralloc_free(b.shader);
   }
}

/* A cube's faces are the sampled image after its own; the null texture's
 * are null. */
static void cube_faces_follow_their_cube(void)
{
   const struct glsl_type *faces = glsl_texture_type(GLSL_SAMPLER_DIM_2D, true, GLSL_TYPE_FLOAT);
   const struct glsl_type *storage = glsl_image_type(GLSL_SAMPLER_DIM_CUBE, false, GLSL_TYPE_FLOAT);
   const uint64_t ids[][2] = {{0x0000000900000004ull, 5}, {0, 0}};
   for (unsigned i = 0; i < ARRAY_SIZE(ids); i++) {
      nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "faces");
      nir_deref_instr *deref =
         stela_metal_bind_texture_id(&b, nir_imm_int64(&b, ids[i][0]), faces, true, NULL, NULL);
      check_heap(deref, STELA_METAL_HEAP_SAMPLED_IMAGES, nir_var_uniform, faces);
      nir_opt_constant_folding(b.shader);
      assert(nir_src_is_const(deref->arr.index) && nir_src_as_uint(deref->arr.index) == ids[i][1]);
      assert(!stela_metal_bind_texture_id(&b, nir_imm_int64(&b, ids[i][0]), storage, true, NULL,
                                          NULL));
      ralloc_free(b.shader);
   }
}

/* An argument buffer's IDs take the same halves of the same arrays. */
static void loaded_ids_index_the_heap(void)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "heap ids");
   const struct glsl_type *sampled = glsl_texture_type(GLSL_SAMPLER_DIM_2D, false, GLSL_TYPE_FLOAT);
   const struct glsl_type *storage = glsl_image_type(GLSL_SAMPLER_DIM_3D, false, GLSL_TYPE_INT);
   nir_def *id = nir_imm_int64(&b, 0x0000000700000005ull);

   nir_deref_instr *deref = stela_metal_bind_texture_id(&b, id, sampled, false, NULL, NULL);
   check_heap(deref, STELA_METAL_HEAP_SAMPLED_IMAGES, nir_var_uniform, sampled);
   assert(nir_def_as_alu(deref->arr.index.ssa)->op == nir_op_unpack_64_2x32_split_x);
   deref = stela_metal_bind_texture_id(&b, id, storage, false, NULL, NULL);
   check_heap(deref, STELA_METAL_HEAP_STORAGE_IMAGES, nir_var_image, storage);
   nir_alu_instr *first = nir_def_as_alu(deref->arr.index.ssa);
   assert(first->op == nir_op_iand);
   assert(nir_def_as_alu(first->src[0].src.ssa)->op == nir_op_unpack_64_2x32_split_y);

   deref = stela_metal_bind_sampler_id(&b, id, true, NULL);
   check_heap(deref, STELA_METAL_HEAP_SAMPLERS, nir_var_uniform, glsl_bare_sampler_type());
   assert(nir_def_as_alu(deref->arr.index.ssa)->op == nir_op_unpack_64_2x32_split_y);
   assert(nir_def_as_alu(deref->arr.index.ssa)->src[0].src.ssa == id);
   ralloc_free(b.shader);
}

/* An array element's ID loads from the array's slots, its element clamped
 * to them, and is the null descriptors' past them. */
static void array_elements_load_within_their_slots(void)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "array ids");
   const struct stela_metal_stage stage = {.table = STELA_METAL_TABLE_PRIMARY};
   nir_def *element = nir_u2u64(&b, nir_channel(&b, nir_load_global_invocation_id(&b, 32), 0));
   const struct stela_air_texture textures = {.index = 4, .length = 3};
   const struct stela_air_sampler samplers = {.index = 1, .length = 2};
   const unsigned firsts[] = {STELA_METAL_TABLE_TEXTURES + 4 * 8, STELA_METAL_TABLE_SAMPLERS + 1 * 8};
   const unsigned lengths[] = {3, 2};
   for (unsigned i = 0; i < 2; i++) {
      nir_def *id = stela_metal_resource_id(&b, i ? NULL : &textures, i ? &samplers : NULL, element,
                                            (void *)&stage);
      nir_alu_instr *select = nir_def_as_alu(id);
      assert(select->op == nir_op_bcsel && nir_src_as_uint(select->src[2].src) == 0);
      nir_alu_instr *inside = nir_def_as_alu(select->src[0].src.ssa);
      assert(inside->op == nir_op_ult && inside->src[0].src.ssa == element);
      assert(nir_src_as_uint(inside->src[1].src) == lengths[i]);
      nir_intrinsic_instr *load = intrinsic(select->src[1].src.ssa, nir_intrinsic_load_global);
      assert(load->def.bit_size == 64 && nir_intrinsic_access(load) & ACCESS_NON_WRITEABLE);
      nir_alu_instr *first = nir_def_as_alu(load->src[0].ssa);
      assert(first->op == nir_op_iadd && nir_src_as_uint(first->src[1].src) == firsts[i]);
      nir_alu_instr *slot = nir_def_as_alu(first->src[0].src.ssa);
      assert(slot->op == nir_op_iadd);
      intrinsic(slot->src[0].src.ssa, nir_intrinsic_load_push_constant);
      nir_alu_instr *scaled = nir_def_as_alu(slot->src[1].src.ssa);
      nir_alu_instr *clamped = nir_def_as_alu(scaled->src[0].src.ssa);
      assert(clamped->op == nir_op_umin && clamped->src[0].src.ssa == element);
      assert(nir_src_as_uint(clamped->src[1].src) == lengths[i] - 1);
   }

   const struct stela_air_texture one = {.index = 4};
   const struct stela_air_sampler past = {.index = STELA_METAL_SAMPLERS - 1, .length = 2};
   assert(!stela_metal_resource_id(&b, &one, NULL, element, (void *)&stage));
   assert(!stela_metal_resource_id(&b, NULL, &past, element, (void *)&stage));
   ralloc_free(b.shader);
}

struct census {
   unsigned push_constants, loads, stores, loops;
   unsigned push_base;
};

static struct census count(nir_shader *shader)
{
   struct census census = {0};
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_cf_node *parent = block->cf_node.parent;
         if (parent->type == nir_cf_node_loop && block == nir_loop_first_block(nir_cf_node_as_loop(parent)))
            census.loops++;
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *intrinsic = nir_instr_as_intrinsic(instr);
            switch (intrinsic->intrinsic) {
            case nir_intrinsic_load_push_constant:
               census.push_constants++;
               census.push_base = (unsigned)nir_intrinsic_base(intrinsic);
               break;
            case nir_intrinsic_load_global:
               census.loads++;
               break;
            case nir_intrinsic_store_global:
               census.stores++;
               break;
            default:
               break;
            }
         }
      }
   }
   return census;
}

static void check_kernel(nir_shader *shader)
{
   assert(shader->info.stage == MESA_SHADER_COMPUTE);
   assert(shader->info.workgroup_size[0] == STELA_METAL_KERNEL_WORKGROUP);
   assert(shader->info.workgroup_size[1] == 1 && shader->info.workgroup_size[2] == 1);
   assert(!strcmp(nir_shader_get_entrypoint(shader)->function->name, "main"));
   assert(nir_shader_get_entrypoint(shader)->function->is_entrypoint);
   /* Lowered to SSA: no variable remains for the driver to lower. */
   assert(exec_list_is_empty(&nir_shader_get_entrypoint(shader)->locals));
}

static void accumulate_sums_each_run_in_a_loop(void)
{
   nir_shader *shader = stela_metal_accumulate_kernel(NULL);
   check_kernel(shader);
   struct census census = count(shader);
   assert(census.push_constants == 1 && census.push_base == STELA_METAL_PUSH_ARGUMENTS);
   /* Count, results, stride, the run's three fields and each result. */
   assert(census.loads == 7);
   assert(census.stores == 1 && census.loops == 1);
   ralloc_free(shader);
}

static void select_flags_each_command(void)
{
   nir_shader *shader = stela_metal_select_kernel(NULL);
   check_kernel(shader);
   struct census census = count(shader);
   assert(census.push_constants == 1 && census.push_base == STELA_METAL_PUSH_ARGUMENTS);
   /* Count, range, location, length and flags. */
   assert(census.loads == 5);
   assert(census.stores == 1 && census.loops == 0);
   ralloc_free(shader);
}

static void resolve_writes_each_command_sequence(void)
{
   nir_shader *shader = stela_metal_resolve_draws_kernel(NULL);
   check_kernel(shader);
   struct census census = count(shader);
   assert(census.push_constants == 1 && census.push_base == STELA_METAL_PUSH_ARGUMENTS);
   /* Each stage's table copy and buffer slots, the vertex buffers and the
    * slots. */
   assert(census.loops == 6);
   /* The execution set index, 13 push constant words, per stage a table
    * word, its two slot fields and its address, the index buffer's three
    * fields, a vertex buffer's three, the draws' one and five, and a
    * count. */
   assert(census.stores == 1 + 13 + 2 * 4 + 3 + 3 + 1 + 5 + 1);
   ralloc_free(shader);
}

static void put32(uint8_t *bytes, uint32_t value)
{
   memcpy(bytes, &value, sizeof(value));
}

static void put64(uint8_t *bytes, uint64_t value)
{
   memcpy(bytes, &value, sizeof(value));
}

static uint32_t get32(const uint8_t *bytes)
{
   uint32_t value;
   memcpy(&value, bytes, sizeof(value));
   return value;
}

static uint64_t get64(const uint8_t *bytes)
{
   uint64_t value;
   memcpy(&value, bytes, sizeof(value));
   return value;
}

static void expect_words(const uint8_t *bytes, const uint32_t *words, unsigned count)
{
   for (unsigned i = 0; i < count; i++)
      assert(get32(bytes + 4 * i) == words[i]);
}

/* The dispatch resolve's memory: a compute indirect command buffer of two
 * commands, each with a kernel table of two slots and three threadgroup
 * memory lengths, the encoder's kernel table, the execution range, the
 * arguments, and the sequences and tables the kernel writes. */
#define BASE 0x100000ull
#define HEADER 0x0u
#define RECORD_BYTES 128u
#define WORDS 112u
#define ENCODER 0x200u
#define RANGE 0x900u
#define ARGUMENTS 0xa00u
#define SEQUENCES 0x1000u
#define TABLES 0x1800u
#define MEMORY (TABLES + 4 * STELA_METAL_TABLE_BYTES)

static uint8_t memory[MEMORY];

static void resolve_dispatch(nir_shader *shader, uint32_t thread, uint32_t flags)
{
   put32(memory + ARGUMENTS + STELA_METAL_RESOLVE_FLAGS, flags);
   uint8_t push[STELA_METAL_PUSH_BYTES] = {0};
   put64(push + STELA_METAL_PUSH_ARGUMENTS, BASE + ARGUMENTS);
   const struct air_effect_environment environment = {
      .base = BASE, .bytes = memory, .size = sizeof(memory), .push = push,
      .push_size = sizeof(push), .local_index = thread,
   };
   static struct air_effect_store trace[1024];
   struct air_effect_run run = air_effect_execute_in(shader, 1000000, trace, ARRAY_SIZE(trace),
                                                     &environment);
   if (run.status != AIR_EFFECT_COMPLETE)
      fprintf(stderr, "resolve dispatches: %s\n", run.detail);
   assert(run.status == AIR_EFFECT_COMPLETE);
}

static void resolve_dispatches_writes_each_command_sequence(void)
{
   nir_shader *shader = stela_metal_resolve_dispatches_kernel(NULL);
   check_kernel(shader);

   uint8_t *header = memory + HEADER;
   const uint32_t words[] = {RECORD_BYTES, 2, STELA_METAL_RECORD_STAGE_IN + 16, 0, 2, 0, WORDS, 3};
   for (unsigned i = 0; i < 8; i++)
      put32(header + 4 * i, words[i]);
   /* dispatchThreads of 100x3x1 in 32x2x1 threadgroups, stage-in region
    * (1, 2, 3) of (4, 5, 6), with compute pipeline 5. */
   uint8_t *record = header + STELA_METAL_INDIRECT_HEADER_BYTES;
   put32(record + STELA_METAL_RECORD_ACTION, STELA_METAL_RECORD_DISPATCH_THREADS);
   put64(record + STELA_METAL_RECORD_PIPELINE,
         (uint64_t)STELA_METAL_RECORD_COMPUTE_PIPELINES << 32 | 5);
   const uint32_t arguments[] = {100, 3, 1, 32, 2, 1, 1, 2, 3, 4, 5, 6, 1};
   for (unsigned i = 0; i < 13; i++)
      put32(record + STELA_METAL_RECORD_GRID + 4 * i, arguments[i]);
   uint8_t *table = record + STELA_METAL_RECORD_STAGE_IN + 16;
   put64(table, 0xa000);
   put64(table + 8, 0xb000);
   put64(table + 16, 64);
   put64(table + 24, 128);
   const uint32_t lengths[] = {20, 0, 48};
   for (unsigned i = 0; i < 3; i++)
      put32(record + WORDS + 4 * i, lengths[i]);
   /* Six threadgroups of a render pipeline's handle. */
   record += RECORD_BYTES;
   put32(record + STELA_METAL_RECORD_ACTION, STELA_METAL_RECORD_DISPATCH);
   put64(record + STELA_METAL_RECORD_PIPELINE, 1ull << 32 | 5);
   put32(record + STELA_METAL_RECORD_GRID, 6);
   put32(record + STELA_METAL_RECORD_GRID + 4, 1);
   put32(record + STELA_METAL_RECORD_GRID + 8, 1);
   put32(record + STELA_METAL_RECORD_THREADS, 64);

   for (unsigned word = 0; word < STELA_METAL_TABLE_BYTES / 4; word++)
      put32(memory + ENCODER + 4 * word, 0xe0000000u + word);
   put32(memory + RANGE + 4, 2);
   uint8_t *at = memory + ARGUMENTS;
   put64(at + STELA_METAL_RESOLVE_HEADER, BASE + HEADER);
   put64(at + STELA_METAL_RESOLVE_RANGE, BASE + RANGE);
   put64(at + STELA_METAL_RESOLVE_SEQUENCES, BASE + SEQUENCES);
   put64(at + STELA_METAL_RESOLVE_TABLES, BASE + TABLES);
   put32(at + STELA_METAL_RESOLVE_COUNT, 2);
   put64(at + STELA_METAL_RESOLVE_PUSH + STELA_METAL_PUSH_TABLES, BASE + ENCODER);
   put32(at + STELA_METAL_RESOLVE_PUSH + STELA_METAL_PUSH_VIEW_MAPPING, 7);

   resolve_dispatch(shader, 0, 0);
   const uint8_t *sequence = memory + SEQUENCES;
   const uint8_t *push = sequence + STELA_METAL_SEQUENCE_PUSH;
   const uint8_t *dispatch = sequence + STELA_METAL_SEQUENCE_DISPATCH_ARGUMENTS;
   assert(get32(sequence + STELA_METAL_SEQUENCE_PIPELINE) == 5);
   assert(get64(push + STELA_METAL_PUSH_TABLES) == BASE + TABLES);
   assert(get64(push + STELA_METAL_PUSH_ARGUMENTS) ==
          BASE + SEQUENCES + STELA_METAL_SEQUENCE_DISPATCH_ARGUMENTS);
   expect_words(push + STELA_METAL_PUSH_GRID, (const uint32_t[]){100, 3, 1}, 3);
   assert(get32(push + STELA_METAL_PUSH_VIEW_MAPPING) == 7);
   expect_words(sequence + STELA_METAL_SEQUENCE_DISPATCH, (const uint32_t[]){4, 2, 1}, 3);
   expect_words(dispatch + STELA_METAL_DISPATCH_REGION, (const uint32_t[]){1, 2, 3, 4, 5, 6}, 6);
   expect_words(dispatch + STELA_METAL_DISPATCH_SHAPE, (const uint32_t[]){32, 2, 1}, 3);
   expect_words(dispatch + STELA_METAL_DISPATCH_OFFSETS, (const uint32_t[]){0, 32, 32, 80, 80}, 5);
   assert(get32(dispatch + STELA_METAL_DISPATCH_OFFSETS + 4 * (STELA_METAL_BUFFERS - 1)) == 80);
   /* The encoder's table, with the record's slots. */
   const uint8_t *written = memory + TABLES;
   assert(get64(written + STELA_METAL_TABLE_BUFFER_ADDRESSES) == 0xa000);
   assert(get64(written + STELA_METAL_TABLE_BUFFER_ADDRESSES + 8) == 0xb000);
   assert(get64(written + STELA_METAL_TABLE_BUFFER_LENGTHS + 8) == 128);
   assert(get32(written + STELA_METAL_TABLE_BUFFER_ADDRESSES + 16) == 0xe0000004u);
   assert(get32(written + STELA_METAL_TABLE_SAMPLERS) == 0xe0000000u + STELA_METAL_TABLE_SAMPLERS / 4);

   /* A render pipeline's handle dispatches nothing. */
   resolve_dispatch(shader, 1, 0);
   sequence += STELA_METAL_SEQUENCE_BYTES;
   push = sequence + STELA_METAL_SEQUENCE_PUSH;
   assert(get32(sequence + STELA_METAL_SEQUENCE_PIPELINE) == 0);
   assert(get64(push + STELA_METAL_PUSH_TABLES) == BASE + TABLES + 2 * STELA_METAL_TABLE_BYTES);
   expect_words(sequence + STELA_METAL_SEQUENCE_DISPATCH, (const uint32_t[]){0, 0, 0}, 3);
   /* Inheriting the pipeline and buffers, it dispatches its threadgroups
    * with the encoder's table. */
   resolve_dispatch(shader, 1, STELA_METAL_RESOLVE_INHERIT_PIPELINE |
                               STELA_METAL_RESOLVE_INHERIT_BUFFERS);
   assert(get64(push + STELA_METAL_PUSH_TABLES) == BASE + ENCODER);
   expect_words(push + STELA_METAL_PUSH_GRID, (const uint32_t[]){0, 0, 0}, 3);
   expect_words(sequence + STELA_METAL_SEQUENCE_DISPATCH, (const uint32_t[]){6, 1, 1}, 3);
   /* Outside the execution range, nothing. */
   put32(memory + RANGE, 0);
   put32(memory + RANGE + 4, 1);
   resolve_dispatch(shader, 1, STELA_METAL_RESOLVE_INHERIT_PIPELINE);
   expect_words(sequence + STELA_METAL_SEQUENCE_DISPATCH, (const uint32_t[]){0, 0, 0}, 3);
   ralloc_free(shader);
}

/* The folded factor of factor * scale. */
static float fold_factor(enum stela_metal_partition partition, unsigned max, float factor,
                         float scale)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_TESS_CTRL, NULL, "factor");
   const struct stela_metal_tessellation tessellation = {.partition = partition,
                                                         .max_factor = max};
   nir_def *value = stela_metal_tessellation_factor(&b, nir_imm_float(&b, factor),
                                                    nir_imm_float(&b, scale), &tessellation);
   nir_store_global(&b, value, nir_imm_int64(&b, 0), .align_mul = 4);
   nir_opt_constant_folding(b.shader);
   nir_intrinsic_instr *store = NULL;
   nir_foreach_block(block, b.impl) {
      nir_foreach_instr(instr, block) {
         if (instr->type == nir_instr_type_intrinsic &&
             nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_store_global)
            store = nir_instr_as_intrinsic(instr);
      }
   }
   assert(store && nir_src_is_const(store->src[0]));
   float folded = (float)nir_src_as_float(store->src[0]);
   ralloc_free(b.shader);
   return folded;
}

static void tessellation_factors_follow_metal_rules(void)
{
   assert(fold_factor(STELA_METAL_PARTITION_INTEGER, 16, 5, 2) == 10);
   assert(fold_factor(STELA_METAL_PARTITION_INTEGER, 16, 20, 1) == 16);
   assert(fold_factor(STELA_METAL_PARTITION_FRACTIONAL_EVEN, 16, 20, 1) == 16);
   assert(fold_factor(STELA_METAL_PARTITION_FRACTIONAL_ODD, 16, 20, 1) == 15);
   assert(fold_factor(STELA_METAL_PARTITION_FRACTIONAL_ODD, 16, 2.5f, 1) == 2.5f);
   /* pow2 rounds up, within the maximum. */
   assert(fold_factor(STELA_METAL_PARTITION_POW2, 64, 5, 1) == 8);
   assert(fold_factor(STELA_METAL_PARTITION_POW2, 64, 8, 1) == 8);
   assert(fold_factor(STELA_METAL_PARTITION_POW2, 64, 1, 1) == 1);
   assert(fold_factor(STELA_METAL_PARTITION_POW2, 64, 0.25f, 1) == 1);
   assert(fold_factor(STELA_METAL_PARTITION_POW2, 64, 33, 1) == 64);
   assert(fold_factor(STELA_METAL_PARTITION_POW2, 48, 40, 1) == 48);
   /* Culling factors pass through. */
   assert(fold_factor(STELA_METAL_PARTITION_POW2, 64, 0, 1) == 0);
   assert(fold_factor(STELA_METAL_PARTITION_INTEGER, 64, 4, -1) == -4);
   assert(isnan(fold_factor(STELA_METAL_PARTITION_POW2, 64, NAN, 1)));
}

static nir_variable *variable(nir_shader *shader, nir_variable_mode mode, unsigned location)
{
   nir_foreach_variable_with_modes(var, shader, mode) {
      if (var->data.location == (int)location)
         return var;
   }
   assert(!"missing variable");
   return NULL;
}

static void evaluation_stages_read_their_patch_ids(void)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_TESS_EVAL, NULL, "patch");
   nir_def *ids = stela_metal_load_device_value(&b, STELA_AIR_PATCH_IDS, NULL);
   assert(ids->num_components == 3 && ids->bit_size == 32);
   nir_variable *input = variable(b.shader, nir_var_shader_in, VARYING_SLOT_PATCH0);
   assert(input->data.patch && input->type == glsl_uvec_type(3));
   ralloc_free(b.shader);
}

static void tessellation_vertex_passes_the_draw_indices(void)
{
   nir_shader *shader = stela_metal_tessellation_vertex(NULL);
   assert(shader->info.stage == MESA_SHADER_VERTEX);
   assert(!strcmp(nir_shader_get_entrypoint(shader)->function->name, "main"));
   nir_variable *patch = variable(shader, nir_var_shader_out, VARYING_SLOT_VAR0);
   assert(patch->type == glsl_uvec_type(3));
   nir_shader_gather_info(shader, nir_shader_get_entrypoint(shader));
   assert(BITSET_TEST(shader->info.system_values_read, SYSTEM_VALUE_VERTEX_ID));
   assert(BITSET_TEST(shader->info.system_values_read, SYSTEM_VALUE_BASE_INSTANCE));
   ralloc_free(shader);
}

static void tessellation_control_reads_factors_by_step(void)
{
   const struct {
      struct stela_metal_tessellation tessellation;
      enum tess_primitive_mode mode;
      enum gl_tess_spacing spacing;
      bool ccw;
      /* Of the TessellationArguments and the factor record. */
      unsigned loads;
   } cases[] = {
      {{false, STELA_METAL_PARTITION_POW2, 64, STELA_METAL_FACTOR_STEP_CONSTANT,
        STELA_METAL_WINDING_CLOCKWISE},
       TESS_PRIMITIVE_TRIANGLES, TESS_SPACING_EQUAL, true, 2 + 1 + 3 + 4},
      {{true, STELA_METAL_PARTITION_FRACTIONAL_ODD, 16, STELA_METAL_FACTOR_STEP_PER_PATCH,
        STELA_METAL_WINDING_COUNTER_CLOCKWISE},
       TESS_PRIMITIVE_QUADS, TESS_SPACING_FRACTIONAL_ODD, false, 2 + 1 + 3 + 6},
      {{true, STELA_METAL_PARTITION_FRACTIONAL_EVEN, 16,
        STELA_METAL_FACTOR_STEP_PER_PATCH_AND_PER_INSTANCE, STELA_METAL_WINDING_CLOCKWISE},
       TESS_PRIMITIVE_QUADS, TESS_SPACING_FRACTIONAL_EVEN, true, 2 + 1 + 4 + 6},
      {{false, STELA_METAL_PARTITION_INTEGER, 16, STELA_METAL_FACTOR_STEP_PER_INSTANCE,
        STELA_METAL_WINDING_COUNTER_CLOCKWISE},
       TESS_PRIMITIVE_TRIANGLES, TESS_SPACING_EQUAL, false, 2 + 1 + 4 + 4},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(cases); i++) {
      nir_shader *shader = stela_metal_tessellation_control(NULL, &cases[i].tessellation);
      assert(shader->info.stage == MESA_SHADER_TESS_CTRL);
      assert(!strcmp(nir_shader_get_entrypoint(shader)->function->name, "main"));
      assert(shader->info.tess.tcs_vertices_out == 1);
      assert(shader->info.tess._primitive_mode == cases[i].mode);
      assert(shader->info.tess.spacing == cases[i].spacing);
      assert(shader->info.tess.ccw == cases[i].ccw);
      assert(exec_list_is_empty(&nir_shader_get_entrypoint(shader)->locals));

      nir_variable *outer = variable(shader, nir_var_shader_out, VARYING_SLOT_TESS_LEVEL_OUTER);
      nir_variable *inner = variable(shader, nir_var_shader_out, VARYING_SLOT_TESS_LEVEL_INNER);
      nir_variable *patch = variable(shader, nir_var_shader_out, VARYING_SLOT_PATCH0);
      assert(outer->data.patch && outer->data.compact && glsl_get_length(outer->type) == 4);
      assert(inner->data.patch && inner->data.compact && glsl_get_length(inner->type) == 2);
      assert(patch->data.patch && !patch->data.compact && patch->type == glsl_uvec_type(3));
      assert(glsl_type_is_array(variable(shader, nir_var_shader_in, VARYING_SLOT_VAR0)->type));

      struct census census = count(shader);
      assert(census.push_constants == 1 && census.push_base == STELA_METAL_PUSH_ARGUMENTS);
      /* The patch index binding and entry, the factor binding, the scale,
       * the stride by step, and each half factor. */
      assert(census.loads == cases[i].loads);
      assert(census.stores == 0 && census.loops == 0);
      ralloc_free(shader);
   }
}

/* The last op intrinsic of the shader b builds, once its constants fold. */
static nir_intrinsic_instr *last(nir_builder *b, nir_intrinsic_op op)
{
   while (nir_opt_constant_folding(b->shader) | nir_opt_copy_prop(b->shader))
      ;
   nir_intrinsic_instr *found = NULL;
   nir_foreach_block(block, nir_shader_get_entrypoint(b->shader)) {
      nir_foreach_instr(instr, block) {
         if (instr->type == nir_instr_type_intrinsic &&
             nir_instr_as_intrinsic(instr)->intrinsic == op)
            found = nir_instr_as_intrinsic(instr);
      }
   }
   assert(found);
   return found;
}

/* Decodes words holding one attribute and folds it to constants. */
static void decoded(const uint32_t *words, unsigned count, unsigned format, uint32_t expected[4])
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "decode");
   nir_def *packed = nir_build_imm(&b, count, 32,
                                   (nir_const_value[4]){{.u32 = words[0]},
                                                        {.u32 = count > 1 ? words[1] : 0},
                                                        {.u32 = count > 2 ? words[2] : 0},
                                                        {.u32 = count > 3 ? words[3] : 0}});
   nir_def *value = stela_metal_decode_attribute(&b, packed, format);
   nir_variable *out = nir_variable_create(b.shader, nir_var_shader_out, glsl_uvec4_type(), "v");
   nir_store_var(&b, out, value, 0xf);
   while (nir_opt_constant_folding(b.shader) |
          nir_opt_copy_prop(b.shader) | nir_opt_dce(b.shader))
      ;
   nir_intrinsic_instr *store = NULL;
   nir_foreach_block(block, nir_shader_get_entrypoint(b.shader)) {
      nir_foreach_instr(instr, block) {
         if (instr->type == nir_instr_type_intrinsic &&
             nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_store_deref)
            store = nir_instr_as_intrinsic(instr);
      }
   }
   assert(store && nir_src_is_const(store->src[1]));
   for (unsigned i = 0; i < 4; i++)
      expected[i] = nir_src_comp_as_uint(store->src[1], i);
   ralloc_free(b.shader);
}

static uint32_t bits_of(float value)
{
   uint32_t bits;
   memcpy(&bits, &value, 4);
   return bits;
}

/* Vertex formats decode to Metal's lanes with (0, 0, 0, 1) filling the rest. */
static void attributes_decode_metal_vertex_formats(void)
{
   uint32_t lanes[4];
   /* UChar4Normalized_BGRA: bytes B, G, R, A. */
   decoded((uint32_t[]){0xff000033}, 1, 42, lanes);
   assert(lanes[0] == bits_of(0.0f) && lanes[1] == bits_of(0.0f) &&
          lanes[2] == bits_of(0.2f) && lanes[3] == bits_of(1.0f));
   /* Char3: sign-extended, integer fill. */
   decoded((uint32_t[]){0x007f80ff}, 1, 5, lanes);
   assert((int32_t)lanes[0] == -1 && (int32_t)lanes[1] == -128 && lanes[2] == 127 &&
          lanes[3] == 1);
   /* Short2Normalized: -32768 clamps to -1. */
   decoded((uint32_t[]){0x80007fff}, 1, 22, lanes);
   assert(lanes[0] == bits_of(1.0f) && lanes[1] == bits_of(-1.0f) && lanes[2] == bits_of(0.0f) &&
          lanes[3] == bits_of(1.0f));
   /* Half3 spans two words. */
   decoded((uint32_t[]){0xc0003c00, 0x00003800}, 2, 26, lanes);
   assert(lanes[0] == bits_of(1.0f) && lanes[1] == bits_of(-2.0f) && lanes[2] == bits_of(0.5f) &&
          lanes[3] == bits_of(1.0f));
   /* Float2 passes through. */
   decoded((uint32_t[]){bits_of(3.0f), bits_of(-4.0f)}, 2, 29, lanes);
   assert(lanes[0] == bits_of(3.0f) && lanes[1] == bits_of(-4.0f) && lanes[2] == bits_of(0.0f));
   /* UInt1010102Normalized: x in the low bits. */
   decoded((uint32_t[]){0xc00003ff}, 1, 41, lanes);
   assert(lanes[0] == bits_of(1.0f) && lanes[1] == bits_of(0.0f) && lanes[3] == bits_of(1.0f));
   assert(stela_metal_vertex_format_bytes(14) == 6 && stela_metal_vertex_format_bytes(54) == 4);
   assert(!stela_metal_vertex_format_bytes(43) && !stela_metal_vertex_format_bytes(56));
   assert(stela_metal_vertex_format_integer(39) && !stela_metal_vertex_format_integer(9));

   /* Fetches read the attribute's whole words, within their bound. */
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "fetch");
   nir_def *base = nir_imm_int64(&b, 0x1000), *offset = nir_imm_int(&b, 8);
   nir_def *value = stela_metal_fetch_attribute(&b, base, offset, nir_imm_int(&b, 64), 14);
   assert(value->num_components == 4);
   assert(!stela_metal_fetch_attribute(&b, base, offset, nir_imm_int(&b, 64), 0));
   nir_intrinsic_instr *load = last(&b, nir_intrinsic_load_global_constant_bounded);
   assert(load->def.num_components == 2 && nir_intrinsic_align_mul(load) == 4);
   ralloc_free(b.shader);
}

static const struct stela_metal_tessellation quads = {.quad = true, .max_factor = 64};

/* The constant offset the fetch of location 0 reads at, for patch 5 of
 * instance 9 from base instance 2. */
static uint32_t patch_fetch_offset(const struct stela_metal_stage_in *stage_in)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_TESS_EVAL, NULL, "patch");
   nir_def *ids = nir_imm_ivec3(&b, 5, 9, 2);
   nir_def *value = stela_metal_fetch_patch_attribute(&b, stage_in, &quads, 0, ids, NULL, false);
   assert(value && value->num_components == 4);
   nir_intrinsic_instr *load = last(&b, nir_intrinsic_load_global_constant_bounded);
   assert(nir_src_is_const(load->src[1]));
   uint32_t offset = nir_src_as_uint(load->src[1]);
   ralloc_free(b.shader);
   return offset;
}

/* Each step function selects its element of the attribute's buffer. */
static void patch_attributes_fetch_their_step_functions_element(void)
{
   struct stela_metal_stage_in stage_in = {0};
   /* Float4 at 4 in 16-byte elements of buffer 3. */
   stage_in.attributes[0] = (struct stela_metal_stage_in_attribute){31, 4, 3};
   stage_in.layouts[3] = (struct stela_metal_stage_in_layout){16, STELA_METAL_STEP_PER_PATCH, 2};
   assert(patch_fetch_offset(&stage_in) == 2 * 16 + 4);
   stage_in.layouts[3] = (struct stela_metal_stage_in_layout){16, STELA_METAL_STEP_PER_INSTANCE, 3};
   assert(patch_fetch_offset(&stage_in) == (2 + 7 / 3) * 16 + 4);
   stage_in.layouts[3] = (struct stela_metal_stage_in_layout){16, STELA_METAL_STEP_CONSTANT, 0};
   assert(patch_fetch_offset(&stage_in) == 4);

   const struct stela_metal_tessellation indexed = {
      .quad = true, .max_factor = 64, .control_point_index_bytes = 2};
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_TESS_EVAL, NULL, "patch");
   nir_def *ids = nir_imm_ivec3(&b, 5, 9, 2), *point = nir_imm_int(&b, 1);
   stage_in.layouts[3] = (struct stela_metal_stage_in_layout){
      STELA_METAL_STRIDE_DYNAMIC, STELA_METAL_STEP_PER_PATCH_CONTROL_POINT, 1};
   /* Control points need a point, the attribute's type and the format. */
   assert(!stela_metal_fetch_patch_attribute(&b, &stage_in, &indexed, 0, ids, NULL, false));
   assert(!stela_metal_fetch_patch_attribute(&b, &stage_in, &indexed, 0, ids, point, true));
   assert(!stela_metal_fetch_patch_attribute(&b, &stage_in, &indexed, 1, ids, point, false));
   /* They read through the 16-bit indices, at the bound stride. */
   assert(stela_metal_fetch_patch_attribute(&b, &stage_in, &indexed, 0, ids, point, false));
   bool indices = false, stride = false;
   nir_foreach_block(block, nir_shader_get_entrypoint(b.shader)) {
      nir_foreach_instr(instr, block) {
         if (instr->type != nir_instr_type_intrinsic)
            continue;
         nir_intrinsic_instr *load = nir_instr_as_intrinsic(instr);
         if (load->intrinsic == nir_intrinsic_load_global_constant_bounded)
            indices |= load->def.bit_size == 16;
         /* The arguments' stride of buffer 3: a word at their address
          * plus its offset. */
         nir_alu_instr *address = load->intrinsic == nir_intrinsic_load_global &&
                                  nir_def_is_alu(load->src[0].ssa) ?
                                  nir_def_as_alu(load->src[0].ssa) : NULL;
         stride |= address && address->op == nir_op_iadd && load->def.bit_size == 32 &&
                   nir_src_is_const(address->src[1].src) &&
                   nir_src_as_uint(address->src[1].src) == STELA_METAL_TESSELLATION_STRIDES + 12;
      }
   }
   assert(indices && stride);
   /* Instance and patch rates are nonzero. */
   stage_in.layouts[3] = (struct stela_metal_stage_in_layout){16, STELA_METAL_STEP_PER_INSTANCE, 0};
   assert(!stela_metal_fetch_patch_attribute(&b, &stage_in, &indexed, 0, ids, NULL, false));
   ralloc_free(b.shader);
}

/* Kernels read their region's elements through the index buffer for
 * indexed steps; threads outside the region read nothing. */
static void kernel_stage_in_reads_within_its_region(void)
{
   struct stela_metal_stage_in stage_in = {.index_bytes = 4, .index_buffer = 7};
   /* UInt2 at 8 in 16-byte elements of buffer 3. */
   stage_in.attributes[1] = (struct stela_metal_stage_in_attribute){37, 8, 3};
   stage_in.layouts[3] = (struct stela_metal_stage_in_layout){
      16, STELA_METAL_STEP_THREAD_POSITION_IN_GRID_Y_INDEXED, 1};
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "kernel");
   nir_def *position = nir_load_global_invocation_id(&b, 32);
   assert(stela_metal_fetch_stage_in(&b, &stage_in, 1, position, true));
   nir_intrinsic_instr *fetch = last(&b, nir_intrinsic_load_global_constant_bounded);
   assert(fetch->def.num_components == 2 && fetch->def.bit_size == 32);
   /* The bound is zero outside the region. */
   assert(nir_def_is_alu(fetch->src[2].ssa) && nir_def_as_alu(fetch->src[2].ssa)->op == nir_op_bcsel);
   bool indices = false;
   nir_foreach_block(block, nir_shader_get_entrypoint(b.shader)) {
      nir_foreach_instr(instr, block) {
         indices |= instr->type == nir_instr_type_intrinsic &&
                    nir_instr_as_intrinsic(instr)->intrinsic ==
                       nir_intrinsic_load_global_constant_bounded &&
                    nir_instr_as_intrinsic(instr)->def.num_components == 1;
      }
   }
   assert(indices);
   /* Rates are nonzero, indexed steps need indices, and the attribute's
    * type and format agree. */
   assert(!stela_metal_fetch_stage_in(&b, &stage_in, 1, position, false));
   stage_in.index_bytes = 0;
   assert(!stela_metal_fetch_stage_in(&b, &stage_in, 1, position, true));
   stage_in.layouts[3] = (struct stela_metal_stage_in_layout){
      16, STELA_METAL_STEP_THREAD_POSITION_IN_GRID_X, 0};
   assert(!stela_metal_fetch_stage_in(&b, &stage_in, 1, position, true));
   stage_in.layouts[3].step = STELA_METAL_STEP_PER_PATCH;
   stage_in.layouts[3].rate = 1;
   assert(!stela_metal_fetch_stage_in(&b, &stage_in, 1, position, true));
   ralloc_free(b.shader);
}

int main(void)
{
   glsl_type_singleton_init_or_ref();
   buffers_load_their_table_slot();
   textures_and_samplers_index_the_heap();
   loaded_ids_index_the_heap();
   array_elements_load_within_their_slots();
   storage_levels_index_their_run();
   cube_faces_follow_their_cube();
   accumulate_sums_each_run_in_a_loop();
   select_flags_each_command();
   resolve_writes_each_command_sequence();
   resolve_dispatches_writes_each_command_sequence();
   tessellation_factors_follow_metal_rules();
   tessellation_vertex_passes_the_draw_indices();
   evaluation_stages_read_their_patch_ids();
   patch_attributes_fetch_their_step_functions_element();
   kernel_stage_in_reads_within_its_region();
   tessellation_control_reads_factors_by_step();
   attributes_decode_metal_vertex_formats();
   glsl_type_singleton_decref();
   puts("metal abi: ok");
   return 0;
}
