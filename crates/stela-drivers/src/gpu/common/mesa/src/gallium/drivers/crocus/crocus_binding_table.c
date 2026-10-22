/*
 * Copyright © 2017 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "crocus_binding_table.h"
#include "compiler/nir/nir_builder.h"
#include "intel/dev/intel_device_info.h"
#include "intel/dev/intel_debug.h"
#include "util/u_debug.h"
#include "util/u_math.h"
#include <stdio.h>
#include <string.h>
#include "intel/compiler/elk/elk_compiler.h"

static const char *surface_group_names[] = {
   [CROCUS_SURFACE_GROUP_RENDER_TARGET]      = "render target",
   [CROCUS_SURFACE_GROUP_RENDER_TARGET_READ] = "non-coherent render target read",
   [CROCUS_SURFACE_GROUP_SOL]                = "streamout",
   [CROCUS_SURFACE_GROUP_CS_WORK_GROUPS]     = "CS work groups",
   [CROCUS_SURFACE_GROUP_TEXTURE]            = "texture",
   [CROCUS_SURFACE_GROUP_TEXTURE_GATHER]     = "texture gather",
   [CROCUS_SURFACE_GROUP_UBO]                = "ubo",
   [CROCUS_SURFACE_GROUP_SSBO]               = "ssbo",
   [CROCUS_SURFACE_GROUP_IMAGE]              = "image",
};

static void
crocus_print_binding_table(FILE *fp, const char *name,
                           const struct crocus_binding_table *bt)
{
   STATIC_ASSERT(ARRAY_SIZE(surface_group_names) == CROCUS_SURFACE_GROUP_COUNT);

   uint32_t total = 0;
   uint32_t compacted = 0;

   for (int i = 0; i < CROCUS_SURFACE_GROUP_COUNT; i++) {
      uint32_t size = bt->sizes[i];
      total += size;
      if (size)
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
   for (int i = 0; i < CROCUS_SURFACE_GROUP_COUNT; i++) {
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

static void
rewrite_src_with_bti(nir_builder *b, struct crocus_binding_table *bt,
                     nir_instr *instr, nir_src *src,
                     enum crocus_surface_group group)
{
   assert(bt->sizes[group] > 0);

   b->cursor = nir_before_instr(instr);
   nir_def *bti;
   if (nir_src_is_const(*src)) {
      uint32_t index = nir_src_as_uint(*src);
      bti = nir_imm_intN_t(b, crocus_group_index_to_bti(bt, group, index),
                           src->ssa->bit_size);
   } else {
      /* Indirect usage makes all the surfaces of the group to be available,
       * so we can just add the base.
       */
      assert(bt->used_mask[group] == BITFIELD64_MASK(bt->sizes[group]));
      bti = nir_iadd_imm(b, src->ssa, bt->offsets[group]);
   }
   nir_src_rewrite(src, bti);
}

static void
mark_used_with_src(struct crocus_binding_table *bt, nir_src *src,
                   enum crocus_surface_group group)
{
   assert(bt->sizes[group] > 0);

   if (nir_src_is_const(*src)) {
      uint64_t index = nir_src_as_uint(*src);
      assert(index < bt->sizes[group]);
      bt->used_mask[group] |= 1ull << index;
   } else {
      /* There's an indirect usage, we need all the surfaces. */
      bt->used_mask[group] = BITFIELD64_MASK(bt->sizes[group]);
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
crocus_setup_binding_table(const struct intel_device_info *devinfo,
                           struct nir_shader *nir,
                           struct crocus_binding_table *bt,
                           unsigned num_render_targets,
                           unsigned num_system_values,
                           unsigned num_cbufs,
                           const struct elk_sampler_prog_key_data *key)
{
   const struct shader_info *info = &nir->info;

   memset(bt, 0, sizeof(*bt));

   /* Set the sizes for each surface group.  For some groups, we already know
    * upfront how many will be used, so mark them.
    */
   if (info->stage == MESA_SHADER_FRAGMENT) {
      bt->sizes[CROCUS_SURFACE_GROUP_RENDER_TARGET] = num_render_targets;
      /* All render targets used. */
      bt->used_mask[CROCUS_SURFACE_GROUP_RENDER_TARGET] =
         BITFIELD64_MASK(num_render_targets);

      /* Setup render target read surface group in order to support non-coherent
       * framebuffer fetch on Gfx7
       */
      if (devinfo->ver >= 6 && info->outputs_read) {
         bt->sizes[CROCUS_SURFACE_GROUP_RENDER_TARGET_READ] = num_render_targets;
         bt->used_mask[CROCUS_SURFACE_GROUP_RENDER_TARGET_READ] =
            BITFIELD64_MASK(num_render_targets);
      }
   } else if (info->stage == MESA_SHADER_COMPUTE) {
      bt->sizes[CROCUS_SURFACE_GROUP_CS_WORK_GROUPS] = 1;
   } else if (info->stage == MESA_SHADER_GEOMETRY) {
      /* In gfx6 we reserve the first ELK_MAX_SOL_BINDINGS entries for transform
       * feedback surfaces.
       */
      if (devinfo->ver == 6) {
         bt->sizes[CROCUS_SURFACE_GROUP_SOL] = ELK_MAX_SOL_BINDINGS;
         bt->used_mask[CROCUS_SURFACE_GROUP_SOL] = (uint64_t)-1;
      }
   }

   bt->sizes[CROCUS_SURFACE_GROUP_TEXTURE] = BITSET_LAST_BIT(info->textures_used);
   bt->used_mask[CROCUS_SURFACE_GROUP_TEXTURE] = info->textures_used[0];

   if (info->uses_texture_gather && devinfo->ver < 8) {
      bt->sizes[CROCUS_SURFACE_GROUP_TEXTURE_GATHER] = BITSET_LAST_BIT(info->textures_used);
      bt->used_mask[CROCUS_SURFACE_GROUP_TEXTURE_GATHER] = info->textures_used[0];
   }

   bt->sizes[CROCUS_SURFACE_GROUP_IMAGE] = info->num_images;

   /* Allocate an extra slot in the UBO section for NIR constants.
    * Binding table compaction will remove it if unnecessary.
    *
    * We don't include them in crocus_compiled_shader::num_cbufs because
    * they are uploaded separately from shs->constbufs[], but from a shader
    * point of view, they're another UBO (at the end of the section).
    */
   bt->sizes[CROCUS_SURFACE_GROUP_UBO] = num_cbufs + 1;

   bt->sizes[CROCUS_SURFACE_GROUP_SSBO] = info->num_ssbos;

   for (int i = 0; i < CROCUS_SURFACE_GROUP_COUNT; i++)
      assert(bt->sizes[i] <= SURFACE_GROUP_MAX_ELEMENTS);

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
            bt->used_mask[CROCUS_SURFACE_GROUP_CS_WORK_GROUPS] = 1;
            break;

         case nir_intrinsic_load_output:
            if (devinfo->ver >= 6) {
               mark_used_with_src(bt, &intrin->src[0],
                                  CROCUS_SURFACE_GROUP_RENDER_TARGET_READ);
            }
            break;

         case nir_intrinsic_image_size:
         case nir_intrinsic_image_load:
         case nir_intrinsic_image_store:
         case nir_intrinsic_image_atomic:
         case nir_intrinsic_image_atomic_swap:
         case nir_intrinsic_image_load_raw_intel:
         case nir_intrinsic_image_store_raw_intel:
            mark_used_with_src(bt, &intrin->src[0], CROCUS_SURFACE_GROUP_IMAGE);
            break;

         case nir_intrinsic_load_ubo:
            mark_used_with_src(bt, &intrin->src[0], CROCUS_SURFACE_GROUP_UBO);
            break;

         case nir_intrinsic_store_ssbo:
            mark_used_with_src(bt, &intrin->src[1], CROCUS_SURFACE_GROUP_SSBO);
            break;

         case nir_intrinsic_get_ssbo_size:
         case nir_intrinsic_ssbo_atomic:
         case nir_intrinsic_ssbo_atomic_swap:
         case nir_intrinsic_load_ssbo:
            mark_used_with_src(bt, &intrin->src[0], CROCUS_SURFACE_GROUP_SSBO);
            break;

         default:
            break;
         }
      }
   }

   /* When disable we just mark everything as used. */
   if (unlikely(skip_compacting_binding_tables())) {
      for (int i = 0; i < CROCUS_SURFACE_GROUP_COUNT; i++)
         bt->used_mask[i] = BITFIELD64_MASK(bt->sizes[i]);
   }

   /* Calculate the offsets and the binding table size based on the used
    * surfaces.  After this point, the functions to go between "group indices"
    * and binding table indices can be used.
    */
   uint32_t next = 0;
   for (int i = 0; i < CROCUS_SURFACE_GROUP_COUNT; i++) {
      if (bt->used_mask[i] != 0) {
         bt->offsets[i] = next;
         next += util_bitcount64(bt->used_mask[i]);
      }
   }
   bt->size_bytes = next * 4;

   if (INTEL_DEBUG(DEBUG_BT)) {
      crocus_print_binding_table(stderr, mesa_shader_stage_name(info->stage), bt);
   }

   /* Apply the binding table indices.  The backend compiler is not expected
    * to change those, as we haven't set any of the *_start entries in elk
    * binding_table.
    */
   nir_builder b = nir_builder_create(impl);

   nir_foreach_block (block, impl) {
      nir_foreach_instr (instr, block) {
         if (instr->type == nir_instr_type_tex) {
            nir_tex_instr *tex = nir_instr_as_tex(instr);
            bool is_gather = devinfo->ver < 8 && tex->op == nir_texop_tg4;

            /* rewrite the tg4 component from green to blue before replacing the
               texture index */
            if (devinfo->verx10 == 70) {
               if (tex->component == 1)
                  if (key->gather_channel_quirk_mask & (1 << tex->texture_index))
                     tex->component = 2;
            }

            if (is_gather && devinfo->ver == 6 && key->gfx6_gather_wa[tex->texture_index]) {
               b.cursor = nir_after_instr(instr);
               enum elk_gfx6_gather_sampler_wa wa = key->gfx6_gather_wa[tex->texture_index];
               int width = (wa & ELK_WA_8BIT) ? 8 : 16;

               nir_def *val = nir_fmul_imm(&b, &tex->def, (1 << width) - 1);
               val = nir_f2u32(&b, val);
               if (wa & ELK_WA_SIGN) {
                  val = nir_ishl_imm(&b, val, 32 - width);
                  val = nir_ishr_imm(&b, val, 32 - width);
               }
               nir_def_rewrite_uses_after(&tex->def, val);
            }

            tex->texture_index =
               crocus_group_index_to_bti(bt, is_gather ? CROCUS_SURFACE_GROUP_TEXTURE_GATHER : CROCUS_SURFACE_GROUP_TEXTURE,
                                         tex->texture_index);
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
                                 CROCUS_SURFACE_GROUP_IMAGE);
            break;

         case nir_intrinsic_load_ubo:
            rewrite_src_with_bti(&b, bt, instr, &intrin->src[0],
                                 CROCUS_SURFACE_GROUP_UBO);
            break;

         case nir_intrinsic_store_ssbo:
            rewrite_src_with_bti(&b, bt, instr, &intrin->src[1],
                                 CROCUS_SURFACE_GROUP_SSBO);
            break;

         case nir_intrinsic_load_output:
            if (devinfo->ver >= 6) {
               /* We're using a BTI as the load_output offset here which
                * breaks newer NIR assumptions.
                */
               nir_io_semantics io_sem = nir_intrinsic_io_semantics(intrin);
               io_sem.no_validate = true;
               nir_intrinsic_set_io_semantics(intrin, io_sem);

               rewrite_src_with_bti(&b, bt, instr, &intrin->src[0],
                                    CROCUS_SURFACE_GROUP_RENDER_TARGET_READ);
            }
            break;

         case nir_intrinsic_get_ssbo_size:
         case nir_intrinsic_ssbo_atomic:
         case nir_intrinsic_ssbo_atomic_swap:
         case nir_intrinsic_load_ssbo:
            rewrite_src_with_bti(&b, bt, instr, &intrin->src[0],
                                 CROCUS_SURFACE_GROUP_SSBO);
            break;

         default:
            break;
         }
      }
   }

   nir_validate_shader(nir, "after crocus_setup_binding_table");
}

