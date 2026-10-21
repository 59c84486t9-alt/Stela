/*
 * Copyright © 2011 Red Hat All Rights Reserved.
 * Copyright © 2017 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: MIT
 */

/* Surface diagnostics are separate from Addrlib layout and metadata services. */
#include "ac_surface.h"
#include "ac_gpu_info.h"
#include "ac_drm_fourcc.h"
#include <inttypes.h>
#include <stdlib.h>

#ifdef _WIN32
static char *
drmGetFormatModifierName(uint64_t modifier)
{
   return NULL;
}
#else
#include <xf86drm.h>
#endif

void ac_surface_print_info(FILE *out, const struct radeon_info *info,
                           const struct radeon_surf *surf)
{
   if (info->gfx_level >= GFX9) {
      fprintf(out,
              "    Surf: size=%" PRIu64 ", slice_size=%" PRIu64 ", "
              "alignment=%u, swmode=%u, tile_swizzle=%u, epitch=%u, pitch=%u, blk_w=%u, "
              "blk_h=%u, bpe=%u, flags=0x%"PRIx64"\n",
              surf->surf_size, surf->u.gfx9.surf_slice_size,
              1 << surf->surf_alignment_log2, surf->u.gfx9.swizzle_mode, surf->tile_swizzle,
              surf->u.gfx9.epitch, surf->u.gfx9.surf_pitch,
              surf->blk_w, surf->blk_h, surf->bpe, surf->flags);

      if (surf->modifier != DRM_FORMAT_MOD_INVALID) {
         char *name = drmGetFormatModifierName(surf->modifier);
         fprintf(out, "    Modifier: %s\n", name);
         free(name);
      }

      if (surf->fmask_offset)
         fprintf(out,
                 "    FMask: offset=%" PRIu64 ", size=%" PRIu64 ", "
                 "alignment=%u, swmode=%u, epitch=%u\n",
                 surf->fmask_offset, surf->fmask_size,
                 1 << surf->fmask_alignment_log2, surf->u.gfx9.color.fmask_swizzle_mode,
                 surf->u.gfx9.color.fmask_epitch);

      if (surf->cmask_offset)
         fprintf(out,
                 "    CMask: offset=%" PRIu64 ", size=%u, "
                 "alignment=%u\n",
                 surf->cmask_offset, surf->cmask_size,
                 1 << surf->cmask_alignment_log2);

      if (surf->flags & RADEON_SURF_Z_OR_SBUFFER && surf->meta_offset)
         fprintf(out,
                 "    HTile: offset=%" PRIu64 ", size=%u, alignment=%u\n",
                 surf->meta_offset, surf->meta_size,
                 1 << surf->meta_alignment_log2);

      if (!(surf->flags & RADEON_SURF_Z_OR_SBUFFER) && surf->meta_offset)
         fprintf(out,
                 "    DCC: offset=%" PRIu64 ", size=%u, "
                 "alignment=%u, pitch_max=%u, num_dcc_levels=%u\n",
                 surf->meta_offset, surf->meta_size, 1 << surf->meta_alignment_log2,
                 surf->u.gfx9.color.display_dcc_pitch_max, surf->num_meta_levels);

      if (surf->has_stencil)
         fprintf(out,
                 "    Stencil: offset=%" PRIu64 ", swmode=%u, epitch=%u\n",
                 surf->u.gfx9.zs.stencil_offset,
                 surf->u.gfx9.zs.stencil_swizzle_mode,
                 surf->u.gfx9.zs.stencil_epitch);

      if (info->gfx_level == GFX12) {
         if (surf->u.gfx9.zs.hiz.size) {
            fprintf(out,
                    "    HiZ: offset=%" PRIu64 ", size=%u, swmode=%u, width_in_tiles=%u, height_in_tiles=%u\n",
                    surf->u.gfx9.zs.hiz.offset, surf->u.gfx9.zs.hiz.size, surf->u.gfx9.zs.hiz.swizzle_mode,
                    surf->u.gfx9.zs.hiz.width_in_tiles, surf->u.gfx9.zs.hiz.height_in_tiles);
         }
      }
   } else {
      fprintf(out,
              "    Surf: size=%" PRIu64 ", alignment=%u, blk_w=%u, blk_h=%u, "
              "bpe=%u, flags=0x%"PRIx64"\n",
              surf->surf_size, 1 << surf->surf_alignment_log2, surf->blk_w,
              surf->blk_h, surf->bpe, surf->flags);

      fprintf(out,
              "    Layout: size=%" PRIu64 ", alignment=%u, bankw=%u, bankh=%u, "
              "nbanks=%u, mtilea=%u, tilesplit=%u, pipeconfig=%u, scanout=%u\n",
              surf->surf_size, 1 << surf->surf_alignment_log2,
              surf->u.legacy.bankw, surf->u.legacy.bankh,
              surf->u.legacy.num_banks, surf->u.legacy.mtilea,
              surf->u.legacy.tile_split, surf->u.legacy.pipe_config,
              (surf->flags & RADEON_SURF_SCANOUT) != 0);

      if (surf->fmask_offset)
         fprintf(out,
                 "    FMask: offset=%" PRIu64 ", size=%" PRIu64 ", "
                 "alignment=%u, pitch_in_pixels=%u, bankh=%u, "
                 "slice_tile_max=%u, tile_mode_index=%u\n",
                 surf->fmask_offset, surf->fmask_size,
                 1 << surf->fmask_alignment_log2, surf->u.legacy.color.fmask.pitch_in_pixels,
                 surf->u.legacy.color.fmask.bankh,
                 surf->u.legacy.color.fmask.slice_tile_max,
                 surf->u.legacy.color.fmask.tiling_index);

      if (surf->cmask_offset)
         fprintf(out,
                 "    CMask: offset=%" PRIu64 ", size=%u, alignment=%u, "
                 "slice_tile_max=%u\n",
                 surf->cmask_offset, surf->cmask_size,
                 1 << surf->cmask_alignment_log2, surf->u.legacy.color.cmask_slice_tile_max);

      if (surf->flags & RADEON_SURF_Z_OR_SBUFFER && surf->meta_offset)
         fprintf(out, "    HTile: offset=%" PRIu64 ", size=%u, alignment=%u\n",
                 surf->meta_offset, surf->meta_size,
                 1 << surf->meta_alignment_log2);

      if (!(surf->flags & RADEON_SURF_Z_OR_SBUFFER) && surf->meta_offset)
         fprintf(out, "    DCC: offset=%" PRIu64 ", size=%u, alignment=%u\n",
                 surf->meta_offset, surf->meta_size, 1 << surf->meta_alignment_log2);

      if (surf->has_stencil)
         fprintf(out, "    StencilLayout: tilesplit=%u\n",
                 surf->u.legacy.stencil_tile_split);
   }
}
