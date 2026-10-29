/* SPDX-License-Identifier: MIT */
/* The Metal ABI's NIR shapes; the GPU behavior needs a device. */
#include "../metal_abi.h"
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

   nir_deref_instr *deref = stela_metal_bind_texture(&b, &texture, sampled, NULL, (void *)&stage);
   nir_variable *images = check_heap(deref, STELA_METAL_HEAP_SAMPLED_IMAGES, nir_var_uniform,
                                     sampled);
   check_heap_index(deref, STELA_METAL_TABLE_TEXTURES + 3 * 8, false);
   /* One variable per element type. */
   deref = stela_metal_bind_texture(&b, &texture, sampled, NULL, (void *)&stage);
   assert(nir_deref_instr_get_variable(deref) == images);

   deref = stela_metal_bind_texture(&b, &texture, storage, NULL, (void *)&stage);
   nir_variable *image = check_heap(deref, STELA_METAL_HEAP_STORAGE_IMAGES, nir_var_image,
                                    storage);
   assert(image->data.image.format == PIPE_FORMAT_NONE);
   check_heap_index(deref, STELA_METAL_TABLE_TEXTURES + 3 * 8, true);

   deref = stela_metal_bind_texture(&b, &texture, texels, NULL, (void *)&stage);
   check_heap(deref, STELA_METAL_HEAP_UNIFORM_TEXEL_BUFFERS, nir_var_uniform, texels);
   deref = stela_metal_bind_texture(&b, &texture, buffer, NULL, (void *)&stage);
   check_heap(deref, STELA_METAL_HEAP_STORAGE_TEXEL_BUFFERS, nir_var_image, buffer);

   const struct stela_air_sampler sampler = {.index = 15};
   deref = stela_metal_bind_sampler(&b, &sampler, false, (void *)&stage);
   check_heap(deref, STELA_METAL_HEAP_SAMPLERS, nir_var_uniform, glsl_bare_sampler_type());
   check_heap_index(deref, STELA_METAL_TABLE_SAMPLERS + 15 * 8, false);
   deref = stela_metal_bind_sampler(&b, &sampler, true, (void *)&stage);
   check_heap_index(deref, STELA_METAL_TABLE_SAMPLERS + 15 * 8, true);

   const struct stela_air_texture past_textures = {.index = STELA_METAL_TEXTURES};
   const struct stela_air_sampler past_samplers = {.index = STELA_METAL_SAMPLERS};
   assert(!stela_metal_bind_texture(&b, &past_textures, sampled, NULL, (void *)&stage));
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
                                                           nir_imm_int(&b, level), NULL);
      nir_opt_constant_folding(b.shader);
      assert(nir_src_is_const(deref->arr.index) &&
             nir_src_as_uint(deref->arr.index) == expected[level]);
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

   nir_deref_instr *deref = stela_metal_bind_texture_id(&b, id, sampled, NULL, NULL);
   check_heap(deref, STELA_METAL_HEAP_SAMPLED_IMAGES, nir_var_uniform, sampled);
   assert(nir_def_as_alu(deref->arr.index.ssa)->op == nir_op_unpack_64_2x32_split_x);
   deref = stela_metal_bind_texture_id(&b, id, storage, NULL, NULL);
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

static void tessellation_vertex_passes_the_draw_indices(void)
{
   nir_shader *shader = stela_metal_tessellation_vertex(NULL);
   assert(shader->info.stage == MESA_SHADER_VERTEX);
   assert(!strcmp(nir_shader_get_entrypoint(shader)->function->name, "main"));
   nir_variable *patch = variable(shader, nir_var_shader_out, VARYING_SLOT_VAR0);
   assert(patch->type == glsl_uvec_type(2));
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
      assert(patch->data.patch && !patch->data.compact && patch->type == glsl_uvec_type(2));
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

   /* Fetches read the attribute's whole words. */
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, NULL, "fetch");
   nir_def *value = stela_metal_fetch_attribute(&b, nir_imm_int64(&b, 0x1000), 14);
   assert(value->num_components == 4);
   assert(!stela_metal_fetch_attribute(&b, nir_imm_int64(&b, 0x1000), 0));
   bool loaded = false;
   nir_foreach_block(block, nir_shader_get_entrypoint(b.shader)) {
      nir_foreach_instr(instr, block) {
         if (instr->type == nir_instr_type_intrinsic &&
             nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_load_global) {
            nir_intrinsic_instr *load = nir_instr_as_intrinsic(instr);
            loaded = load->def.num_components == 2 && nir_intrinsic_align_mul(load) == 4;
         }
      }
   }
   assert(loaded);
   ralloc_free(b.shader);
}

int main(void)
{
   glsl_type_singleton_init_or_ref();
   buffers_load_their_table_slot();
   textures_and_samplers_index_the_heap();
   loaded_ids_index_the_heap();
   storage_levels_index_their_run();
   accumulate_sums_each_run_in_a_loop();
   select_flags_each_command();
   tessellation_factors_follow_metal_rules();
   tessellation_vertex_passes_the_draw_indices();
   tessellation_control_reads_factors_by_step();
   attributes_decode_metal_vertex_formats();
   glsl_type_singleton_decref();
   puts("metal abi: ok");
   return 0;
}
