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
   accumulate_sums_each_run_in_a_loop();
   select_flags_each_command();
   glsl_type_singleton_decref();
   puts("metal abi: ok");
   return 0;
}
