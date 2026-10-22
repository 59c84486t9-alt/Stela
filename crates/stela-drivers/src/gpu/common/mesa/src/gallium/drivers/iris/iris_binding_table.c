/*
 * Copyright © 2017 Intel Corporation
 * SPDX-License-Identifier: MIT
 *
 * @file iris_program.c
 *
 * This file contains the driver interface for compiling shaders.
 *
 * See iris_program_cache.c for the in-memory program cache where the
 * compiled shaders are stored.
 */

#include "iris_binding_table.h"
#include "compiler/nir/nir_builder.h"
#include "intel/dev/intel_device_info.h"
#include "intel/dev/intel_debug.h"
#include "util/u_debug.h"
#include "util/u_math.h"
#include <stdio.h>
#include <string.h>

static const char *surface_group_names[] = {
   [IRIS_SURFACE_GROUP_RENDER_TARGET]      = "render target",
   [IRIS_SURFACE_GROUP_RENDER_TARGET_READ] = "non-coherent render target read",
   [IRIS_SURFACE_GROUP_CS_WORK_GROUPS]     = "CS work groups",
   [IRIS_SURFACE_GROUP_TEXTURE_LOW64]      = "texture",
   [IRIS_SURFACE_GROUP_TEXTURE_HIGH64]     = "texture",
   [IRIS_SURFACE_GROUP_UBO]                = "ubo",
   [IRIS_SURFACE_GROUP_SSBO]               = "ssbo",
   [IRIS_SURFACE_GROUP_IMAGE]              = "image",
};

static void
iris_print_binding_table(FILE *fp, const char *name,
                         const struct iris_binding_table *bt)
{
   STATIC_ASSERT(ARRAY_SIZE(surface_group_names) == IRIS_SURFACE_GROUP_COUNT);

   uint32_t total = 0;
   uint32_t compacted = 0;

   for (int i = 0; i < IRIS_SURFACE_GROUP_COUNT; i++) {
      uint32_t surf_count = bt->surf_count[i];
      total += surf_count;
      if (surf_count)
         compacted += util_bitcount64(bt->used_mask[i]);
   }

   if (total == 0) {
      fprintf(fp, "Binding table for %s is empty\n\n", name);
      return;
   }

   if (total != compacted) {
      fprintf(fp, "Binding table for %s "
              "(compacted to %u entries from %u entries)\n",
              name, compacted, total);
   } else {
      fprintf(fp, "Binding table for %s (%u entries)\n", name, total);
   }

   uint32_t entry = 0;
   for (int i = 0; i < IRIS_SURFACE_GROUP_COUNT; i++) {
      uint64_t mask = bt->used_mask[i];
      while (mask) {
         int index = u_bit_scan64(&mask);
         fprintf(fp, "  [%u] %s #%d\n", entry++, surface_group_names[i], index);
      }
   }
   fprintf(fp, "\n");
}

enum {
   /* Max elements in a surface group. */
   SURFACE_GROUP_MAX_ELEMENTS = 64,
};

/**
 * Map a <group, index> pair to a binding table index.
 *
 * For example: <UBO, 5> => binding table index 12
 */
uint32_t
iris_group_index_to_bti(const struct iris_binding_table *bt,
                        enum iris_surface_group group, uint32_t index)
{
   assert(index < bt->surf_count[group]);
   uint64_t mask = bt->used_mask[group];
   uint64_t bit = 1ull << index;
   if (bit & mask) {
      return bt->offsets[group] + util_bitcount64((bit - 1) & mask);
   } else {
      return IRIS_SURFACE_NOT_USED;
   }
}

/**
 * Map a binding table index back to a <group, index> pair.
 *
 * For example: binding table index 12 => <UBO, 5>
 */
uint32_t
iris_bti_to_group_index(const struct iris_binding_table *bt,
                        enum iris_surface_group group, uint32_t bti)
{
   uint64_t used_mask = bt->used_mask[group];
   assert(bti >= bt->offsets[group]);

   uint32_t c = bti - bt->offsets[group];
   while (used_mask) {
      int i = u_bit_scan64(&used_mask);
      if (c == 0)
         return i;
      c--;
   }

   return IRIS_SURFACE_NOT_USED;
}

static void
rewrite_src_with_bti(nir_builder *b, struct iris_binding_table *bt,
                     nir_instr *instr, nir_src *src,
                     enum iris_surface_group group)
{
   assert(bt->surf_count[group] > 0);

   b->cursor = nir_before_instr(instr);
   nir_def *bti;
   if (nir_src_is_const(*src)) {
      uint32_t index = nir_src_as_uint(*src);
      bti = nir_imm_intN_t(b, iris_group_index_to_bti(bt, group, index),
                           src->ssa->bit_size);
   } else {
      /* Indirect usage makes all the surfaces of the group to be available,
       * so we can just add the base.
       */
      assert(bt->used_mask[group] == BITFIELD64_MASK(bt->surf_count[group]));
      bti = nir_iadd_imm(b, src->ssa, bt->offsets[group]);
   }
   nir_src_rewrite(src, bti);
}

static void
mark_used_with_src(struct iris_binding_table *bt, nir_src *src,
                   enum iris_surface_group group)
{
   assert(bt->surf_count[group] > 0);

   if (nir_src_is_const(*src)) {
      uint64_t index = nir_src_as_uint(*src);
      assert(index < bt->surf_count[group]);
      bt->used_mask[group] |= 1ull << index;
   } else {
      /* There's an indirect usage, we need all the surfaces. */
      bt->used_mask[group] = BITFIELD64_MASK(bt->surf_count[group]);
   }
}

static bool
skip_compacting_binding_tables(void)
{
   static int skip = -1;
   if (skip < 0)
      skip = debug_get_bool_option("INTEL_DISABLE_COMPACT_BINDING_TABLE", false);
   return skip;
}

/**
 * Set up the binding table indices and apply to the shader.
 */
void
iris_setup_binding_table(const struct intel_device_info *devinfo,
                         struct nir_shader *nir,
                         struct iris_binding_table *bt,
                         unsigned num_render_targets,
                         unsigned num_system_values,
                         unsigned num_cbufs,
                         bool use_null_rt)
{
   const struct shader_info *info = &nir->info;

   memset(bt, 0, sizeof(*bt));

   /* Set the sizes for each surface group.  For some groups, we already know
    * upfront how many will be used, so mark them.
    */
   if (info->stage == MESA_SHADER_FRAGMENT) {
      bt->surf_count[IRIS_SURFACE_GROUP_RENDER_TARGET] = num_render_targets;
      /* All render targets used. */
      bt->used_mask[IRIS_SURFACE_GROUP_RENDER_TARGET] =
         BITFIELD64_MASK(num_render_targets);

      /* Setup render target read surface group in order to support non-coherent
       * framebuffer fetch on Gfx8
       */
      if (devinfo->ver == 8 && info->outputs_read) {
         bt->surf_count[IRIS_SURFACE_GROUP_RENDER_TARGET_READ] = num_render_targets;
         bt->used_mask[IRIS_SURFACE_GROUP_RENDER_TARGET_READ] =
            BITFIELD64_MASK(num_render_targets);
      }

      bt->use_null_rt = use_null_rt;
   } else if (info->stage == MESA_SHADER_COMPUTE) {
      bt->surf_count[IRIS_SURFACE_GROUP_CS_WORK_GROUPS] = 1;
   }

   assert(ARRAY_SIZE(info->textures_used) >= 4);
   int max_tex = BITSET_LAST_BIT(info->textures_used);
   assert(max_tex <= 128);
   bt->surf_count[IRIS_SURFACE_GROUP_TEXTURE_LOW64] = MIN2(64, max_tex);
   bt->surf_count[IRIS_SURFACE_GROUP_TEXTURE_HIGH64] = MAX2(0, max_tex - 64);
   bt->used_mask[IRIS_SURFACE_GROUP_TEXTURE_LOW64] =
      info->textures_used[0] | ((uint64_t)info->textures_used[1]) << 32;
   bt->used_mask[IRIS_SURFACE_GROUP_TEXTURE_HIGH64] =
      info->textures_used[2] | ((uint64_t)info->textures_used[3]) << 32;
   bt->samplers_used_mask = info->samplers_used[0];

   bt->surf_count[IRIS_SURFACE_GROUP_IMAGE] = BITSET_LAST_BIT(info->images_used);

   /* Allocate an extra slot in the UBO section for NIR constants.
    * Binding table compaction will remove it if unnecessary.
    *
    * We don't include them in iris_compiled_shader::num_cbufs because
    * they are uploaded separately from shs->constbuf[], but from a shader
    * point of view, they're another UBO (at the end of the section).
    */
   bt->surf_count[IRIS_SURFACE_GROUP_UBO] = num_cbufs + 1;

   bt->surf_count[IRIS_SURFACE_GROUP_SSBO] = info->num_ssbos;

   for (int i = 0; i < IRIS_SURFACE_GROUP_COUNT; i++)
      assert(bt->surf_count[i] <= SURFACE_GROUP_MAX_ELEMENTS);

   /* Mark surfaces used for the cases we don't have the information available
    * upfront.
    */
   nir_function_impl *impl = nir_shader_get_entrypoint(nir);
   nir_foreach_block (block, impl) {
      nir_foreach_instr (instr, block) {
         if (instr->type != nir_instr_type_intrinsic)
            continue;

         nir_intrinsic_instr *intrin = nir_instr_as_intrinsic(instr);
         switch (intrin->intrinsic) {
         case nir_intrinsic_load_num_workgroups:
            bt->used_mask[IRIS_SURFACE_GROUP_CS_WORK_GROUPS] = 1;
            break;

         case nir_intrinsic_load_output:
            if (devinfo->ver == 8) {
               mark_used_with_src(bt, &intrin->src[0],
                                  IRIS_SURFACE_GROUP_RENDER_TARGET_READ);
            }
            break;

         case nir_intrinsic_image_size:
         case nir_intrinsic_image_load:
         case nir_intrinsic_image_store:
         case nir_intrinsic_image_atomic:
         case nir_intrinsic_image_atomic_swap:
         case nir_intrinsic_image_load_raw_intel:
         case nir_intrinsic_image_store_raw_intel:
            mark_used_with_src(bt, &intrin->src[0], IRIS_SURFACE_GROUP_IMAGE);
            break;

         case nir_intrinsic_load_ubo:
            mark_used_with_src(bt, &intrin->src[0], IRIS_SURFACE_GROUP_UBO);
            break;

         case nir_intrinsic_store_ssbo:
            mark_used_with_src(bt, &intrin->src[1], IRIS_SURFACE_GROUP_SSBO);
            break;

         case nir_intrinsic_get_ssbo_size:
         case nir_intrinsic_ssbo_atomic:
         case nir_intrinsic_ssbo_atomic_swap:
         case nir_intrinsic_load_ssbo:
            mark_used_with_src(bt, &intrin->src[0], IRIS_SURFACE_GROUP_SSBO);
            break;

         default:
            break;
         }
      }
   }

   /* When disable we just mark everything as used. */
   if (unlikely(skip_compacting_binding_tables())) {
      for (int i = 0; i < IRIS_SURFACE_GROUP_COUNT; i++)
         bt->used_mask[i] = BITFIELD64_MASK(bt->surf_count[i]);
   }

   /* Calculate the offsets and the binding table size based on the used
    * surfaces.  After this point, the functions to go between "group indices"
    * and binding table indices can be used.
    */
   uint32_t next = 0;
   for (int i = 0; i < IRIS_SURFACE_GROUP_COUNT; i++) {
      if (bt->used_mask[i] != 0) {
         bt->offsets[i] = next;
         next += util_bitcount64(bt->used_mask[i]);
      }
   }
   bt->size_bytes = next * 4;

   if (INTEL_DEBUG(DEBUG_BT)) {
      iris_print_binding_table(stderr, mesa_shader_stage_name(info->stage), bt);
   }

   /* Apply the binding table indices.  The backend compiler is not expected
    * to change those, as we haven't set any of the *_start entries in brw
    * binding_table.
    */
   nir_builder b = nir_builder_create(impl);

   nir_foreach_block (block, impl) {
      nir_foreach_instr_safe (instr, block) {
         if (instr->type == nir_instr_type_tex) {
            nir_tex_instr *tex = nir_instr_as_tex(instr);
            if (tex->texture_index < 64) {
               tex->texture_index =
                  iris_group_index_to_bti(bt, IRIS_SURFACE_GROUP_TEXTURE_LOW64,
                                          tex->texture_index);
            } else {
               tex->texture_index =
                  iris_group_index_to_bti(bt, IRIS_SURFACE_GROUP_TEXTURE_HIGH64,
                                          tex->texture_index - 64);
            }
            continue;
         }

         if (instr->type != nir_instr_type_intrinsic)
            continue;

         nir_intrinsic_instr *intrin = nir_instr_as_intrinsic(instr);
         switch (intrin->intrinsic) {
         case nir_intrinsic_image_size:
         case nir_intrinsic_image_load:
         case nir_intrinsic_image_store:
         case nir_intrinsic_image_atomic:
         case nir_intrinsic_image_atomic_swap:
         case nir_intrinsic_image_load_raw_intel:
         case nir_intrinsic_image_store_raw_intel:
            rewrite_src_with_bti(&b, bt, instr, &intrin->src[0],
                                 IRIS_SURFACE_GROUP_IMAGE);
            break;

         case nir_intrinsic_load_ubo:
            rewrite_src_with_bti(&b, bt, instr, &intrin->src[0],
                                 IRIS_SURFACE_GROUP_UBO);
            break;

         case nir_intrinsic_store_ssbo:
            rewrite_src_with_bti(&b, bt, instr, &intrin->src[1],
                                 IRIS_SURFACE_GROUP_SSBO);
            break;

         case nir_intrinsic_load_output:
            if (devinfo->ver == 8) {
               /* We're using a BTI as the load_output offset here which
                * breaks newer NIR assumptions.
                */
               nir_io_semantics io_sem = nir_intrinsic_io_semantics(intrin);
               io_sem.no_validate = true;
               nir_intrinsic_set_io_semantics(intrin, io_sem);

               rewrite_src_with_bti(&b, bt, instr, &intrin->src[0],
                                    IRIS_SURFACE_GROUP_RENDER_TARGET_READ);
            }
            break;

         case nir_intrinsic_get_ssbo_size:
         case nir_intrinsic_ssbo_atomic:
         case nir_intrinsic_ssbo_atomic_swap:
         case nir_intrinsic_load_ssbo:
            rewrite_src_with_bti(&b, bt, instr, &intrin->src[0],
                                 IRIS_SURFACE_GROUP_SSBO);
            break;

         case nir_intrinsic_load_num_workgroups:
            b.cursor = nir_before_instr(instr);
            nir_def_replace(
               &intrin->def,
               nir_load_ubo(&b,
                            intrin->def.num_components,
                            intrin->def.bit_size,
                            nir_imm_int(&b, bt->offsets[
                                           IRIS_SURFACE_GROUP_CS_WORK_GROUPS]),
                            nir_imm_int(&b, 0),
                            .range_base = 0,
                            .range = intrin->def.num_components *
                                     intrin->def.bit_size / 8));
            break;

         default:
            break;
         }
      }
   }

   nir_validate_shader(nir, "after iris_setup_binding_table");
}

