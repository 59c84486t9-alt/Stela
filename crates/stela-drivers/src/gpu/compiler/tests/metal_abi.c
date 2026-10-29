/* SPDX-License-Identifier: MIT */
/* The Metal ABI's NIR shapes; the GPU behavior needs a device. */
#include "../metal_abi.h"
#include "util/ralloc.h"
#include <assert.h>
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

   nir_deref_instr *deref = stela_metal_bind_texture(&b, &texture, sampled, (void *)&stage);
   nir_variable *images = check_heap(deref, STELA_METAL_HEAP_SAMPLED_IMAGES, nir_var_uniform,
                                     sampled);
   check_heap_index(deref, STELA_METAL_TABLE_TEXTURES + 3 * 8, false);
   /* One variable per element type. */
   deref = stela_metal_bind_texture(&b, &texture, sampled, (void *)&stage);
   assert(nir_deref_instr_get_variable(deref) == images);

   deref = stela_metal_bind_texture(&b, &texture, storage, (void *)&stage);
   nir_variable *image = check_heap(deref, STELA_METAL_HEAP_STORAGE_IMAGES, nir_var_image,
                                    storage);
   assert(image->data.image.format == PIPE_FORMAT_NONE);
   check_heap_index(deref, STELA_METAL_TABLE_TEXTURES + 3 * 8, true);

   deref = stela_metal_bind_texture(&b, &texture, texels, (void *)&stage);
   check_heap(deref, STELA_METAL_HEAP_UNIFORM_TEXEL_BUFFERS, nir_var_uniform, texels);
   deref = stela_metal_bind_texture(&b, &texture, buffer, (void *)&stage);
   check_heap(deref, STELA_METAL_HEAP_STORAGE_TEXEL_BUFFERS, nir_var_image, buffer);

   const struct stela_air_sampler sampler = {.index = 15};
   deref = stela_metal_bind_sampler(&b, &sampler, false, (void *)&stage);
   check_heap(deref, STELA_METAL_HEAP_SAMPLERS, nir_var_uniform, glsl_bare_sampler_type());
   check_heap_index(deref, STELA_METAL_TABLE_SAMPLERS + 15 * 8, false);
   deref = stela_metal_bind_sampler(&b, &sampler, true, (void *)&stage);
   check_heap_index(deref, STELA_METAL_TABLE_SAMPLERS + 15 * 8, true);

   const struct stela_air_texture past_textures = {.index = STELA_METAL_TEXTURES};
   const struct stela_air_sampler past_samplers = {.index = STELA_METAL_SAMPLERS};
   assert(!stela_metal_bind_texture(&b, &past_textures, sampled, (void *)&stage));
   assert(!stela_metal_bind_sampler(&b, &past_samplers, false, (void *)&stage));
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

int main(void)
{
   glsl_type_singleton_init_or_ref();
   buffers_load_their_table_slot();
   textures_and_samplers_index_the_heap();
   accumulate_sums_each_run_in_a_loop();
   select_flags_each_command();
   glsl_type_singleton_decref();
   puts("metal abi: ok");
   return 0;
}
