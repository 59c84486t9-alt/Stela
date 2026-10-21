/* SPDX-License-Identifier: MIT */
/* Command-encoding fixture only: this is not initialized physical hardware. */
#include "amd/common/ac_gpu_info.h"

const void *stela_amd_test_info(void);

const void *
stela_amd_test_info(void)
{
   static const struct radeon_info info = {
      .gfx_level = GFX11,
      .family = CHIP_NAVI31,
      .has_graphics = true,
      .spi_cu_en = 0x00f3,
      .max_se = 8,
      .address32_hi = 0x1234,
      .has_set_sh_pairs_packed = true,
   };
   return &info;
}
