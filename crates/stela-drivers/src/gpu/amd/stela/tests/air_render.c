/*
 * Copyright © 2019, 2022 Valve Corporation.
 * Copyright © 2016 Red Hat.
 * Copyright © 2016 Bas Nieuwenhuizen
 * Based in part on anv: Copyright © 2015 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */
/* Offline original AIR -> original AMD legacy VS / NGG / PS compilation.
 * Explicit modeled compiler/raster ABI fixtures, never initialized devices.
 * Mesa policy provenance:31e9a6b2e95e30d84bf3177d1f497d063e59b6b2.
 */
#include "ac_nir.h"
#include "air_probe_input.h"
#include "air_to_nir.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_shader_args.h"
#include "amd/common/ac_shader_util.h"
#include "amd/compiler/aco_interface.h"
#include "amdgfxregs.h"
#include "vulkan/radv_constants.h"
#include "stela/tests/targets/amd.h"
#include "util/ralloc.h"
#if AMD_LLVM_AVAILABLE
#include "amd/llvm/ac_llvm_util.h"
#endif

#define CHECK(c)                                                                                             \
   do {                                                                                                      \
      if (!(c)) {                                                                                            \
         fprintf(stderr, "%s:%u: %s\n", __func__, __LINE__, #c);                                             \
         exit(1);                                                                                            \
      }                                                                                                      \
   } while (0)
#define PARAM_LIMIT 32
#define BUFFER_LIMIT 2

struct resource {
   struct stela_air_buffer metadata;
   struct ac_arg descriptor;
};
struct abi {
   struct ac_shader_args args;
   struct resource resources[BUFFER_LIMIT];
   unsigned resource_count, callbacks, bindings, attribute_loads;
   unsigned param_exports;
   enum amd_gfx_level gfx;
};
/* The modeled raster ABI of one compiled stage. */
struct abi_facts {
   unsigned hw_stage, lds_bytes, spi_ps_input, resource_count, attribute_ring_loads;
   unsigned wgp_mode, nir_float_controls, cb_shader_mask;
};
struct captured {
   struct ac_shader_config config;
   struct abi_facts abi;
   uint32_t *code;
   unsigned code_dw, executable_bytes;
   char *assembly;
};
struct input {
   const void *bytes;
   size_t size;
   const char *vs_name, *fs_name;
   const struct stela_air_stage_entry *vertex;
   char hash[BLAKE3_HEX_LEN];
};
/* A compile target: "<family>.wave<N>-<stage>", also its artifact's stem. */
static void
target_name(char name[48], enum radeon_family family, unsigned wave, unsigned stage)
{
   stela_amd_target_name(name, family, wave);
   strcat(name, stage == STELA_AIR_VERTEX ? "-vertex" : "-fragment");
}
static void
add(struct abi *a, enum ac_arg_regfile file, unsigned size, struct ac_arg *arg)
{
   ac_add_arg(&a->args, file, size, AC_ARG_VALUE, arg);
}

/* The attribute ring's descriptor, from the 16-byte ring table the
 * ring_offsets SGPR pair addresses. The hardware counts at least one
 * per-vertex parameter in the ring's stride; this probe exports no
 * per-primitive parameters. */
static nir_def *
attribute_ring(nir_builder *b, const struct abi *a)
{
   nir_def *table = nir_pack_64_2x32(b, ac_nir_load_arg(b, &a->args, a->args.ring_offsets));
   nir_def *desc = ac_nir_load_smem(b, 4, table, nir_imm_int(b, RING_PS_ATTR * 16u), 4,
                                    ACCESS_CAN_SPECULATE);
   const unsigned stride = 16 * MAX2(1, a->param_exports);
   nir_def *dword1 = nir_ior_imm(b, nir_channel(b, desc, 1), S_008F04_STRIDE(stride));
   return nir_vector_insert_imm(b, desc, dword1, 1);
}

/* Architectural VGPR recipes retain original RADV ordering. User resource
 * DWORDs are this explicit fixture's frontend ABI, not Vulkan descriptor sets. */
static void
vertex_args(struct abi *a, const struct stela_air_stage_entry *entry, bool ngg)
{
   ac_add_arg(&a->args, AC_ARG_SGPR, 2, AC_ARG_CONST_ADDR, &a->args.ring_offsets);
   if (ngg) {
      add(a, AC_ARG_SGPR, 1, &a->args.gs_tg_info);
      add(a, AC_ARG_SGPR, 1, &a->args.merged_wave_info);
      add(a, AC_ARG_SGPR, 1, &a->args.tess_offchip_offset);
      add(a, AC_ARG_SGPR, 1, a->gfx >= GFX11 ? &a->args.gs_attr_offset : &a->args.scratch_offset);
      add(a, AC_ARG_SGPR, 1, NULL);
      add(a, AC_ARG_SGPR, 1, NULL);
      CHECK(a->args.num_sgprs_used == 8);
   }
   add(a, AC_ARG_SGPR, 1, &a->args.base_vertex);
   for (unsigned i = 0; i < entry->input_count; i++) {
      const struct stela_air_stage_io *io = &entry->inputs[i];
      if (io->semantic != STELA_AIR_STAGE_BUFFER)
         continue;
      CHECK(a->resource_count < BUFFER_LIMIT && io->buffer.address_space == 2 &&
            io->buffer.access == STELA_AIR_READ);
      struct resource *r = &a->resources[a->resource_count++];
      r->metadata = io->buffer;
      add(a, AC_ARG_SGPR, 4, &r->descriptor);
   }
   CHECK(a->resource_count == 2);
   if (!ngg)
      add(a, AC_ARG_SGPR, 1, &a->args.scratch_offset);
   if (ngg) {
      add(a, AC_ARG_VGPR, 1, &a->args.gs_vtx_offset[0]);
      if (a->gfx >= GFX12) {
         add(a, AC_ARG_VGPR, 1, &a->args.gs_prim_id);
         add(a, AC_ARG_VGPR, 1, &a->args.gs_vtx_offset[1]);
      } else {
         add(a, AC_ARG_VGPR, 1, &a->args.gs_vtx_offset[1]);
         add(a, AC_ARG_VGPR, 1, &a->args.gs_prim_id);
         add(a, AC_ARG_VGPR, 1, &a->args.gs_invocation_id);
         add(a, AC_ARG_VGPR, 1, &a->args.gs_vtx_offset[2]);
      }
   }
   add(a, AC_ARG_VGPR, 1, &a->args.vertex_id);
   if (a->gfx >= GFX12) {
      add(a, AC_ARG_VGPR, 1, &a->args.instance_id);
   } else if (ngg) {
      add(a, AC_ARG_VGPR, 1, NULL);
      add(a, AC_ARG_VGPR, 1, NULL);
      add(a, AC_ARG_VGPR, 1, &a->args.instance_id);
   } else {
      CHECK(a->gfx < GFX10);
      add(a, AC_ARG_VGPR, 1, &a->args.instance_id);
      add(a, AC_ARG_VGPR, 1, &a->args.vs_prim_id);
      add(a, AC_ARG_VGPR, 1, NULL);
   }
}
static void
pixel_args(struct abi *a, unsigned mask)
{
   ac_add_arg(&a->args, AC_ARG_SGPR, 2, AC_ARG_CONST_ADDR, &a->args.ring_offsets);
   add(a, AC_ARG_SGPR, 1, &a->args.prim_mask);
   if (a->gfx < GFX11)
      add(a, AC_ARG_SGPR, 1, &a->args.scratch_offset);
   add(a, AC_ARG_VGPR, 2, &a->args.persp_sample);
   add(a, AC_ARG_VGPR, 2, &a->args.persp_center);
   add(a, AC_ARG_VGPR, 2, &a->args.persp_centroid);
   add(a, AC_ARG_VGPR, 3, &a->args.pull_model);
   add(a, AC_ARG_VGPR, 2, &a->args.linear_sample);
   add(a, AC_ARG_VGPR, 2, &a->args.linear_center);
   add(a, AC_ARG_VGPR, 2, &a->args.linear_centroid);
   add(a, AC_ARG_VGPR, 1, &a->args.line_stipple_tex_ena);
   for (unsigned i = 0; i < 4; i++)
      add(a, AC_ARG_VGPR, 1, &a->args.frag_pos[i]);
   add(a, AC_ARG_VGPR, 1, &a->args.front_face);
   add(a, AC_ARG_VGPR, 1, &a->args.ancillary);
   add(a, AC_ARG_VGPR, 1, &a->args.sample_coverage);
   add(a, AC_ARG_VGPR, 1, &a->args.pos_fixed_pt);
   ac_compact_ps_vgpr_args(&a->args, mask);
}
static bool
bind_ssbo(const struct stela_air_buffer *buffer, unsigned *slot, void *context)
{
   struct abi *a = context;
   for (unsigned i = 0; i < a->resource_count; i++) {
      const struct stela_air_buffer *b = &a->resources[i].metadata;
      if (b->argument == buffer->argument && b->index == buffer->index &&
          b->address_space == buffer->address_space && b->access == buffer->access &&
          b->type_size == buffer->type_size && b->type_alignment == buffer->type_alignment) {
         a->callbacks++;
         *slot = i;
         return true;
      }
   }
   return false;
}
static bool
lower_abi(nir_builder *b, nir_intrinsic_instr *i, void *data)
{
   struct abi *a = data;
   b->cursor = nir_before_instr(&i->instr);
   if (i->intrinsic == nir_intrinsic_ssbo_descriptor_amd || i->intrinsic == nir_intrinsic_load_ssbo) {
      if (i->intrinsic == nir_intrinsic_load_ssbo && i->src[0].ssa->num_components == 4)
         return false;
      CHECK(nir_src_is_const(i->src[0]));
      unsigned slot = nir_src_as_uint(i->src[0]);
      CHECK(slot < a->resource_count);
      nir_def *desc = ac_nir_load_arg(b, &a->args, a->resources[slot].descriptor);
      CHECK(desc->num_components == 4 && desc->bit_size == 32);
      a->bindings++;
      if (i->intrinsic == nir_intrinsic_load_ssbo)
         nir_src_rewrite(&i->src[0], desc);
      else {
         nir_def_replace(&i->def, desc);
      }
      return true;
   }
   if (i->intrinsic == nir_intrinsic_load_ring_attr_amd) {
      nir_def_replace(&i->def, attribute_ring(b, a));
      a->attribute_loads++;
      return true;
   }
   return false;
}
static unsigned
type_size_vec4(const struct glsl_type *type, bool bindless)
{
   (void)bindless;
   return glsl_count_attribute_slots(type, false);
}
static void
optimize(nir_shader *s)
{
   bool progress;
   do {
      progress = nir_opt_copy_prop(s); /* original generic propagation */
      progress |= nir_opt_constant_folding(s);
      progress |= nir_opt_algebraic(s);
      progress |= nir_opt_dce(s);
      progress |= nir_opt_dead_cf(s);
   } while (progress);
}
static void
lower_io(nir_shader *s)
{
   nir_lower_io_vars_to_temporaries(s, nir_shader_get_entrypoint(s), nir_var_shader_out);
   nir_lower_global_vars_to_local(s);
   nir_lower_var_copies(s);
   nir_lower_vars_to_ssa(s);
   nir_lower_array_deref_of_vec(
       s, nir_var_shader_in | nir_var_shader_out, NULL,
       nir_lower_direct_array_deref_of_vec_load | nir_lower_indirect_array_deref_of_vec_load |
           nir_lower_direct_array_deref_of_vec_store | nir_lower_indirect_array_deref_of_vec_store);
   nir_assign_io_var_locations(s, nir_var_shader_in);
   nir_assign_io_var_locations(s, nir_var_shader_out);
   nir_lower_io(s, nir_var_shader_in | nir_var_shader_out, type_size_vec4,
                nir_lower_io_lower_64bit_to_32 | nir_lower_io_use_interpolated_input_intrinsics);
   nir_lower_system_values(s);
   optimize(s);
   nir_shader_gather_info(s, nir_shader_get_entrypoint(s));
   nir_remove_dead_variables(s, nir_var_shader_in | nir_var_shader_out, NULL);
}
static void
capture(void **private, const struct ac_shader_config *config, const char *ir, unsigned ir_bytes,
        const char *assembly, unsigned assembly_bytes, struct amd_stats *stats, uint32_t executable,
        const uint32_t *code, uint32_t code_dw, const struct aco_symbol *symbols, unsigned symbol_count,
        const struct ac_shader_debug_info *debug, unsigned debug_count)
{
   (void)ir;
   (void)ir_bytes;
   (void)stats;
   (void)symbols;
   (void)debug;
   (void)debug_count;
   struct captured *c = *private;
   CHECK(!c->code && config && code_dw && executable && executable <= code_dw * 4 && !symbol_count);
   c->config = *config;
   c->code_dw = code_dw;
   c->executable_bytes = executable;
   c->code = malloc((size_t)code_dw * 4);
   CHECK(c->code);
   memcpy(c->code, code, (size_t)code_dw * 4);
   if (assembly && assembly_bytes) {
      c->assembly = malloc((size_t)assembly_bytes + 1);
      CHECK(c->assembly);
      memcpy(c->assembly, assembly, assembly_bytes);
      c->assembly[assembly_bytes] = 0;
   }
}
static nir_shader *
translate(const struct input *input, const char *entry, enum stela_air_stage stage,
          const struct stela_air_varying_slot *map, unsigned count,
          const nir_shader_compiler_options *options, struct abi *abi)
{
   struct stela_air_stage_options o = {
       .stage = stage,
       .resources = {.max_instructions = 10000, .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41},
       .varyings = map,
       .varying_count = count,
       .max_varying_slots = PARAM_LIMIT};
   if (stage == STELA_AIR_VERTEX) {
      o.resources.bind_ssbo = bind_ssbo;
      o.resources.ssbo_count = abi->resource_count;
      o.resources.binding_data = abi;
   }
   struct stela_air_error error;
   nir_shader *s = stela_air_stage_to_nir(input->bytes, input->size, entry, options, &o, &error);
   if (!s)
      fprintf(stderr, "AIRstage%u refused%u: %s\n", stage, error.kind, error.detail);
   CHECK(s);
   return s;
}
static bool
reject_resource(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
   (void)buffer;
   (void)slot;
   (void)data;
   return false;
}
static bool
invalid_resource(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
   (void)buffer;
   (void)data;
   *slot = BUFFER_LIMIT;
   return true;
}
static bool
duplicate_resource(const struct stela_air_buffer *buffer, unsigned *slot, void *data)
{
   (void)buffer;
   (void)data;
   *slot = 0;
   return true;
}
static void
resource_negatives(const struct input *input, const struct stela_air_varying_slot *map, unsigned count)
{
   struct radeon_info profile = {.family = CHIP_NAVI31, .gfx_level = GFX11, .has_graphics = true};
   ac_fill_compiler_info(&profile, NULL, false);
   nir_shader_compiler_options options;
   ac_nir_set_options(&profile.compiler_info, false, &options);
   struct abi abi = {.gfx = GFX11};
   vertex_args(&abi, input->vertex, true);
   unsigned cases = 0;
   for (unsigned resource = 0; resource < abi.resource_count; resource++) {
      for (unsigned field = 0; field < 6; field++) {
         struct stela_air_buffer wrong = abi.resources[resource].metadata;
         switch (field) {
         case 0:
            wrong.argument ^= 1;
            break;
         case 1:
            wrong.index ^= 1;
            break;
         case 2:
            wrong.address_space = 1;
            break;
         case 3:
            wrong.access = STELA_AIR_READ_WRITE;
            break;
         case 4:
            wrong.type_size ^= 1;
            break;
         case 5:
            wrong.type_alignment ^= 1;
            break;
         }
         unsigned untouched = UINT_MAX;
         CHECK(!bind_ssbo(&wrong, &untouched, &abi) && untouched == UINT_MAX);
         cases++;
      }
   }
   for (unsigned kind = 0; kind < 7; kind++) {
      struct stela_air_stage_options o = {
          .stage = STELA_AIR_VERTEX,
          .resources = {.max_instructions = 10000,
                        .fp_profile = STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41,
                        .bind_ssbo = bind_ssbo,
                        .ssbo_count = abi.resource_count,
                        .binding_data = &abi},
          .varyings = map,
          .varying_count = count,
          .max_varying_slots = PARAM_LIMIT,
      };
      switch (kind) {
      case 0:
         o.resources.bind_ssbo = reject_resource;
         break;
      case 1:
         o.resources.bind_ssbo = invalid_resource;
         break;
      case 2:
         o.resources.bind_ssbo = duplicate_resource;
         break;
      case 3:
         o.resources.ssbo_count = 1;
         break;
      case 4:
         o.varyings = NULL;
         o.varying_count = 0;
         break;
      case 5:
         o.max_varying_slots = 0;
         break;
      case 6:
         o.resources.max_instructions = 1;
         break;
      }
      struct stela_air_error error;
      nir_shader *s = stela_air_stage_to_nir(input->bytes, input->size, input->vs_name, &options, &o, &error);
      CHECK(!s && error.kind != STELA_AIR_OK);
      cases++;
   }
   record_begin("evidence");
   record_str("topic", "render-resource-refusals");
   record_object("facts");
   record_uint("cases", cases);
   record_str("scope", "metadata-slot-budget-map");
   record_end();
}
static void
readonly_bounds(nir_shader *s, unsigned resources)
{
   unsigned loads = 0, sizes = 0;
   nir_foreach_function_impl(impl, s) nir_foreach_block(block, impl) nir_foreach_instr(instr, block)
   {
      if (instr->type != nir_instr_type_intrinsic)
         continue;
      nir_intrinsic_instr *i = nir_instr_as_intrinsic(instr);
      CHECK(i->intrinsic != nir_intrinsic_load_global && i->intrinsic != nir_intrinsic_store_global &&
            i->intrinsic != nir_intrinsic_store_ssbo);
      if (i->intrinsic == nir_intrinsic_load_ssbo) {
         CHECK(nir_src_is_const(i->src[0]) && nir_src_as_uint(i->src[0]) < resources);
         /* Original bridge emits a guarded then-block, with the full-width
          * range condition before any narrowing of the byte offset. */
         CHECK(block->cf_node.parent && block->cf_node.parent->type == nir_cf_node_if);
         loads++;
      }
      if (i->intrinsic == nir_intrinsic_get_ssbo_size)
         sizes++;
   }
   CHECK(loads && sizes >= resources);
   printf("read-only bounds: %u guarded loads, %u dynamic descriptor sizes\n", loads, sizes);
}
static unsigned
pixel_input_mask(nir_shader *s)
{
   /* Bounded fixture: exactly the observed linked center-perspective color,
    * no live position/sample/other PS system input is silently discarded. */
   bool center = false;
   nir_foreach_function_impl(impl, s) nir_foreach_block(block, impl) nir_foreach_instr(instr, block)
   {
      if (instr->type != nir_instr_type_intrinsic)
         continue;
      nir_intrinsic_instr *i = nir_instr_as_intrinsic(instr);
      if (i->intrinsic == nir_intrinsic_load_barycentric_pixel) {
         CHECK(nir_intrinsic_interp_mode(i) == INTERP_MODE_SMOOTH);
         center = true;
      }
      CHECK(i->intrinsic != nir_intrinsic_load_frag_coord && i->intrinsic != nir_intrinsic_load_sample_id &&
            i->intrinsic != nir_intrinsic_load_front_face);
   }
   CHECK(center);
   return S_0286CC_PERSP_CENTER_ENA(1);
}
static struct captured
compile_one(struct input *input, const struct stela_air_stage_entry *entry,
            const struct stela_air_varying_slot *map, unsigned map_count, enum radeon_family family,
            unsigned wave, enum stela_air_stage stage)
{
   /* MODELED original compiler profile only: no initialized device/resource
    * APIs consume this object. The real native driver must supply real facts. */
   struct radeon_info profile = {
       .family = family, .gfx_level = ac_get_gfx_level(family), .has_graphics = true};
   ac_fill_compiler_info(&profile, NULL, false);
   CHECK(aco_is_gpu_supported(&profile));
   nir_shader_compiler_options options;
   ac_nir_set_options(&profile.compiler_info, false, &options);
   bool ngg = stage == STELA_AIR_VERTEX && profile.gfx_level >= GFX10;
   struct abi abi = {.gfx = profile.gfx_level, .param_exports = map_count};
   if (stage == STELA_AIR_VERTEX)
      vertex_args(&abi, entry, ngg);
   nir_shader *s = translate(input, stage == STELA_AIR_VERTEX ? input->vs_name : input->fs_name, stage, map,
                             map_count, &options, &abi);
   CHECK(stage != STELA_AIR_VERTEX || abi.callbacks == abi.resource_count);
   if (stage == STELA_AIR_VERTEX)
      readonly_bounds(s, abi.resource_count);
   s->info.min_subgroup_size = s->info.max_subgroup_size = wave;
   lower_io(s);
   unsigned mask = 0;
   struct ac_spi_color_formats formats;
   ac_choose_spi_color_formats(V_028C70_COLOR_32_32_32_32, V_028C70_SWAP_STD, V_028C70_NUMBER_FLOAT, false,
                               false, &formats);
   CHECK(formats.normal == V_028714_SPI_SHADER_32_ABGR);
   if (stage == STELA_AIR_FRAGMENT) {
      mask = pixel_input_mask(s);
      pixel_args(&abi, mask);
      ac_nir_lower_ps_early_options early = {.msaa_disabled = true,
                                             .alpha_func = COMPARE_FUNC_ALWAYS,
                                             .spi_shader_col_format_hint = formats.normal};
      ac_nir_lower_ps_early(s, &early);
      optimize(s);
   }
   ac_nir_lower_resinfo(s, profile.gfx_level);
   nir_shader_intrinsics_pass(s, lower_abi, nir_metadata_none, &abi);
   nir_lower_alu_width(s, ac_nir_opt_vectorize_cb, &profile.gfx_level);
   optimize(s);
   uint8_t offsets[VARYING_SLOT_MAX];
   memset(offsets, AC_EXP_PARAM_UNDEFINED, sizeof(offsets));
   for (unsigned i = 0; i < map_count; i++) {
      CHECK(map[i].location < PARAM_LIMIT);
      offsets[VARYING_SLOT_VAR0 + map[i].location] = map[i].location;
   }
   if (stage == STELA_AIR_VERTEX) {
      if (ngg) {
         ac_nir_lower_ngg_options o = {.compiler_info = &profile.compiler_info,
                                       .max_workgroup_size = 256,
                                       .wave_size = wave,
                                       .vs_output_param_offset = offsets,
                                       .has_param_exports = map_count != 0,
                                       .num_vertices_per_primitive = 3,
                                       .passthrough = true,
                                       .disable_streamout = true};
         uint32_t vertex_size = 0;
         uint8_t scratch_size = 0;
         ac_nir_lower_ngg_nogs(s, &o, &vertex_size, &scratch_size);
         /* This exact no-cull/no-streamout/no-primitive-ID passthrough key
          * must require no additional original NGG LDS allocation policy. */
         CHECK(!vertex_size && !scratch_size && !s->info.shared_size);
      } else
         ac_nir_lower_legacy_vs(s, profile.gfx_level, 0, false, offsets, map_count != 0, false, true, false);
   } else {
      ac_nir_lower_ps_late_options late = {
          .gfx_level = profile.gfx_level, .use_aco = true, .spi_shader_col_format = formats.normal};
      ac_nir_lower_ps_late(s, &late);
   }
   enum ac_hw_stage hw = stage == STELA_AIR_FRAGMENT ? AC_HW_PIXEL_SHADER
                         : ngg                       ? AC_HW_NEXT_GEN_GEOMETRY_SHADER
                                                     : AC_HW_VERTEX_SHADER;
   ac_nir_lower_intrinsics_to_args_options arg_options = {
       .gfx_level = profile.gfx_level, .hw_stage = hw, .wave_size = wave, .workgroup_size = ngg ? 256 : wave};
   ac_nir_lower_intrinsics_to_args(s, &abi.args, &arg_options);
   nir_shader_intrinsics_pass(s, lower_abi, nir_metadata_none, &abi);
   ac_nir_lower_global_access(s, profile.gfx_level);
   nir_lower_int64(s);
   optimize(s);
   nir_lower_load_const_to_scalar(s);
   nir_opt_copy_prop(s);
   nir_opt_dce(s);
   /* Original post-link graphics lowerings replace IO with exports; gathering
    * shader_info again here would erase the pre-export IO facts. */
   nir_validate_shader(s, "AIR AMD render final");
   const struct aco_compiler_options co = {.compiler_info = &profile.compiler_info,
                                           .family = family,
                                           .gfx_level = profile.gfx_level,
                                           .record_asm = true,
                                           .record_ir = true,
                                           /* Original radv_should_use_wgp_mode: this zero-LDS NGG key enables
                                            * WGP only on GFX10; newer NGG and every PS use CU mode. */
                                           .wgp_mode = ngg && profile.gfx_level == GFX10};
   const struct aco_shader_info info = {.hw_stage = hw,
                                        .wave_size = wave,
                                        .workgroup_size = ngg ? 256 : wave,
                                        .lds_size = s->info.shared_size,
                                        .ps = {.num_inputs = stage == STELA_AIR_FRAGMENT ? map_count : 0,
                                               .spi_ps_input_ena = mask,
                                               .spi_ps_input_addr = mask}};
   struct captured result = {0};
   void *private = &result;
   if (getenv("STELA_RENDER_DUMP_NIR")) {
      fprintf(stderr, "AMD render final NIR target=%s stage=%u wave=%u\n", ac_get_family_name(family), stage,
              wave);
      nir_print_shader(s, stderr);
   }
   aco_compile_shader(&co, &info, 1, &s, &abi.args, capture, &private);
   CHECK(result.code && result.config.num_vgprs && !result.config.scratch_bytes_per_wave);
   if (stage == STELA_AIR_VERTEX)
      CHECK(abi.bindings && (profile.gfx_level < GFX11 || abi.attribute_loads));
   if (stage == STELA_AIR_FRAGMENT)
      CHECK(result.config.spi_ps_input_ena == mask && result.config.spi_ps_input_addr == mask);
   result.abi = (struct abi_facts){
      .hw_stage = hw, .lds_bytes = s->info.shared_size, .spi_ps_input = mask,
      .resource_count = abi.resource_count, .attribute_ring_loads = abi.attribute_loads,
      .wgp_mode = co.wgp_mode, .nir_float_controls = s->info.float_controls_execution_mode,
      .cb_shader_mask = stage == STELA_AIR_FRAGMENT ? ac_get_cb_shader_mask(formats.normal) : 0};
   ralloc_free(s);
   return result;
}
static void
config_words(const struct ac_shader_config *c, uint32_t words[14])
{
   const uint32_t values[14] = {c->num_sgprs,
                                c->num_vgprs,
                                c->num_shared_vgprs,
                                c->spilled_sgprs,
                                c->spilled_vgprs,
                                c->lds_size,
                                c->spi_ps_input_ena,
                                c->spi_ps_input_addr,
                                c->float_mode,
                                c->scratch_bytes_per_wave,
                                c->wgp_mode,
                                c->rsrc1,
                                c->rsrc2,
                                c->rsrc3};
   memcpy(words, values, sizeof(values));
}
static void
write_binary(const struct captured *binary, const char *target)
{
   const char *directory = getenv("STELA_RENDER_BINARY_DIR");
   if (!directory)
      return;
   char name[64], path[4096];
   int n = snprintf(name, sizeof(name), "%s.bin", target);
   CHECK(n > 0 && (unsigned)n < sizeof(name));
   n = snprintf(path, sizeof(path), "%s/%s", directory, name);
   CHECK(n > 0 && (unsigned)n < sizeof(path));
   FILE *file = fopen(path, "wb");
   CHECK(file);
   CHECK(fwrite(binary->code, 4, binary->code_dw, file) == binary->code_dw);
   CHECK(fclose(file) == 0);
   record_artifact(name);
}
static void
dispose(struct captured *c)
{
   free(c->code);
   free(c->assembly);
   memset(c, 0, sizeof(*c));
}
/* The manifest's render targets: every stage of every family and wave. */
static void
expect_targets(void)
{
   for (unsigned i = 0; i < ARRAY_SIZE(stela_amd_targets); i++) {
      const enum radeon_family family = stela_amd_targets[i];
      for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2) {
         for (unsigned stage = STELA_AIR_VERTEX; stage <= STELA_AIR_FRAGMENT; stage++) {
            char target[48];
            target_name(target, family, wave, stage);
            record_expect(target, stela_amd_aco_hold(family));
         }
      }
   }
}
/* Original ACO refuses the held families before any stage compiles. */
static void
held(enum radeon_family family)
{
   const struct radeon_info profile = {.family = family, .gfx_level = ac_get_gfx_level(family),
                                       .has_graphics = stela_amd_has_graphics(family)};
   CHECK(!aco_is_gpu_supported(&profile));
   for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2) {
      for (unsigned stage = STELA_AIR_VERTEX; stage <= STELA_AIR_FRAGMENT; stage++) {
         char target[48];
         target_name(target, family, wave, stage);
         record_held(target, stela_amd_aco_hold(family));
      }
   }
}
static bool
fragment(const struct stela_air_inspection *inspection, const struct stela_air_stage_entry *fs, void *data)
{
   (void)inspection;
   struct input *input = data;
   struct stela_air_varying_slot map[PARAM_LIMIT];
   unsigned count = 0;
   struct stela_air_error error;
   CHECK(stela_air_link_stage_io(input->vertex, fs, PARAM_LIMIT, map, PARAM_LIMIT, &count, &error));
   CHECK(count == 1);
   resource_negatives(input, map, count);
   for (unsigned i = 0; i < ARRAY_SIZE(stela_amd_targets); i++) {
      const enum radeon_family family = stela_amd_targets[i];
      if (stela_amd_aco_hold(family)) {
         held(family);
         continue;
      }
      for (unsigned wave = 64; wave >= stela_amd_min_wave(family); wave /= 2) {
         for (unsigned stage = STELA_AIR_VERTEX; stage <= STELA_AIR_FRAGMENT; stage++) {
            const struct stela_air_stage_entry *entry = stage == STELA_AIR_VERTEX ? input->vertex : fs;
            struct captured a = compile_one(input, entry, map, count, family, wave, stage);
            struct captured b = compile_one(input, entry, map, count, family, wave, stage);
            CHECK(a.code_dw == b.code_dw && a.executable_bytes == b.executable_bytes &&
                  !memcmp(a.code, b.code, (size_t)a.code_dw * 4));
            uint32_t ca[14], cb[14];
            config_words(&a.config, ca);
            config_words(&b.config, cb);
            CHECK(!memcmp(ca, cb, sizeof(ca)) && !memcmp(&a.abi, &b.abi, sizeof(a.abi)));
            CHECK(a.assembly && b.assembly && !strcmp(a.assembly, b.assembly));
            char target[48];
            target_name(target, family, wave, stage);
            write_binary(&a, target);
            record_compiled(target, a.code_dw * 4);
            record_object("facts");
            record_str("profile", "modeled-original-Mesa-family");
            record_str("input_blake3", input->hash);
            record_uint("executable_bytes", a.executable_bytes);
            record_blake3("code_blake3", a.code, (size_t)a.code_dw * 4);
            record_uints("config_words", ca, ARRAY_SIZE(ca));
            record_blake3("config_blake3", ca, sizeof(ca));
            record_uint("hw_stage", a.abi.hw_stage);
            record_uint("lds_bytes", a.abi.lds_bytes);
            record_uint("spi_ps_input", a.abi.spi_ps_input);
            record_uint("resource_count", a.abi.resource_count);
            record_uint("attribute_ring_loads", a.abi.attribute_ring_loads);
            record_uint("wgp_mode", a.abi.wgp_mode);
            record_uint("nir_float_controls", a.abi.nir_float_controls);
            record_uint("cb_shader_mask", a.abi.cb_shader_mask);
            record_end();
            printf("%s\n", a.assembly);
            dispose(&a);
            dispose(&b);
         }
      }
   }
   return true;
}
static bool
vertex(const struct stela_air_inspection *inspection, const struct stela_air_stage_entry *vs, void *data)
{
   (void)inspection;
   struct input *input = data;
   input->vertex = vs;
   struct stela_air_error error;
   CHECK(stela_air_inspect_stage(input->bytes, input->size, input->fs_name, STELA_AIR_FRAGMENT, fragment,
                                 input, &error));
   input->vertex = NULL;
   return true;
}
int
main(int argc, char **argv)
{
   fprintf(stderr, "AMD render start\n");
   if (argc != 7 || strcmp(argv[1], "--input") || strcmp(argv[3], "--vs") || strcmp(argv[5], "--fs")) {
      fprintf(stderr, "usage: %s --input original.bc --vs vertex_entry --fs fragment_entry\n", argv[0]);
      return 2;
   }
#if AMD_LLVM_AVAILABLE
   ac_init_llvm_once();
#endif
   glsl_type_singleton_init_or_ref();
   LLVMMemoryBufferRef buffer = read_raw_input(argv[2]);
   CHECK(buffer);
   struct input input = {.bytes = LLVMGetBufferStart(buffer),
                         .size = LLVMGetBufferSize(buffer),
                         .vs_name = argv[4],
                         .fs_name = argv[6]};
   const unsigned no_workgroup[3] = {0};
   CHECK(input_receipt_options(buffer, input.vs_name, true, input.hash, no_workgroup, 10000));
   CHECK(input_receipt_options(buffer, input.fs_name, true, input.hash, no_workgroup, 10000));
   record_begin("evidence");
   record_str("topic", "render-pipeline");
   record_object("facts");
   record_str("primitive", "triangle");
   record_uint("samples", 1);
   record_str("color0", "RGBA32_FLOAT");
   record_bool("depth", false);
   record_bool("blend", false);
   record_bool("streamout", false);
   record_bool("culling", false);
   record_bool("queries", false);
   record_str("resource_abi", "dynamic-RAW-descriptor-SGPR-quartets");
   record_str("fp_profile", "apple-32023.922-air2.9-msl4.1");
   record_end();
   expect_targets();
   struct stela_air_error error;
   CHECK(stela_air_inspect_stage(input.bytes, input.size, input.vs_name, STELA_AIR_VERTEX, vertex, &input,
                                 &error));
   LLVMDisposeMemoryBuffer(buffer);
   glsl_type_singleton_decref();
   return 0;
}
