/*
 * Copyright © 2017 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: MIT
 */

/* Shared pure compute limits; kept separate from OS/device query services. */
#include "ac_gpu_info.h"
#include "util/u_math.h"
#include "sid.h"

unsigned
ac_get_compute_resource_limits(const struct radeon_info *info, unsigned waves_per_threadgroup,
                               unsigned max_waves_per_sh, unsigned threadgroups_per_cu)
{
   unsigned compute_resource_limits = S_00B854_SIMD_DEST_CNTL(waves_per_threadgroup % 4 == 0);

   if (info->gfx_level >= GFX7) {
      unsigned num_cu_per_se = info->num_cu / info->num_se;

      /* Gfx9 should set the limit to max instead of 0 to fix high priority compute. */
      if (info->gfx_level == GFX9 && !max_waves_per_sh) {
         max_waves_per_sh = info->max_good_cu_per_sa *
                            info->compiler_info.num_simd_per_compute_unit *
                            info->compiler_info.max_waves_per_simd;
      }

      /* On GFX12+, WAVES_PER_SH means waves per SE. */
      if (info->gfx_level >= GFX12)
         max_waves_per_sh *= info->max_sa_per_se;

      /* Force even distribution on all SIMDs in CU if the workgroup
       * size is 64. This has shown some good improvements if # of CUs
       * per SE is not a multiple of 4.
       */
      if (num_cu_per_se % 4 && waves_per_threadgroup == 1)
         compute_resource_limits |= S_00B854_FORCE_SIMD_DIST(1);

      assert(threadgroups_per_cu >= 1 && threadgroups_per_cu <= 8);
      compute_resource_limits |=
         S_00B854_WAVES_PER_SH(max_waves_per_sh) | S_00B854_CU_GROUP_COUNT(threadgroups_per_cu - 1);
   } else {
      /* GFX6 */
      if (max_waves_per_sh) {
         unsigned limit_div16 = DIV_ROUND_UP(max_waves_per_sh, 16);
         compute_resource_limits |= S_00B854_WAVES_PER_SH_GFX6(limit_div16);
      }
   }
   return compute_resource_limits;
}
