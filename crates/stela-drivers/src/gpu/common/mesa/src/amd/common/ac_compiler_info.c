/*
 * Copyright © 2017 Advanced Micro Devices, Inc.
 *
 * SPDX-License-Identifier: MIT
 */

/* Pure capability derivation shared by hardware queries and native shader
 * compilation. No libdrm functions or device I/O belong in this file.
 */
#include "ac_gpu_info.h"
#include "drm-uapi/amdgpu_drm.h"
#include "util/macros.h"

void
ac_fill_compiler_info(struct radeon_info *info, const struct drm_amdgpu_info_device *device_info,
                      bool compat_mode)
{
   /* We use ac_compiler_info for shader cache keys, so make sure there is no padding. */
   STATIC_ASSERT(sizeof(enum amd_gfx_level) == 4);
   STATIC_ASSERT(sizeof(struct ac_compiler_info) == 60);

   struct ac_compiler_info *out = &info->compiler_info;

   out->gfx_level = info->gfx_level;

   if (info->gfx_level >= GFX10_3)
      out->max_waves_per_simd = 16;
   else if (info->gfx_level == GFX10)
      out->max_waves_per_simd = 20;
   else if (info->family >= CHIP_POLARIS10 && info->family <= CHIP_VEGAM)
      out->max_waves_per_simd = 8;
   else
      out->max_waves_per_simd = 10;

   if (info->gfx_level >= GFX10) {
      out->num_physical_sgprs_per_simd = 108 * out->max_waves_per_simd;
      out->min_sgpr_alloc = 108;
      out->max_sgpr_alloc = 108; /* includes VCC, which can be treated as s[106-107] on GFX10+ */
      out->sgpr_alloc_granularity = 108;
   } else if (info->family == CHIP_TONGA || info->family == CHIP_ICELAND) {
      /* SGPRInitBug: Due to a HW bug, we always have to allocate the same amount of SGPRs. */
      out->num_physical_sgprs_per_simd = 800;
      out->min_sgpr_alloc = 96;
      out->max_sgpr_alloc = 96;
      out->sgpr_alloc_granularity = 96;
   } else if (info->gfx_level >= GFX8) {
      out->num_physical_sgprs_per_simd = 800;
      out->min_sgpr_alloc = 16;
      out->max_sgpr_alloc = 102;
      out->sgpr_alloc_granularity = 16;
   } else {
      out->num_physical_sgprs_per_simd = 512;
      out->min_sgpr_alloc = 8;
      out->max_sgpr_alloc = 104;
      out->sgpr_alloc_granularity = 8;
   }

   if (device_info && device_info->num_shader_visible_vgprs) {
      /* The Gfx10 VGPR count is in Wave32, so divide it by 2 for Wave64.
       * Gfx6-9 numbers are in Wave64. CDNA also includes Accumulation VGPRs.
       */
      if (info->gfx_level >= GFX10 || (info->gfx_level == GFX9 && info->family >= CHIP_MI100))
         out->num_physical_wave64_vgprs_per_simd = device_info->num_shader_visible_vgprs / 2;
      else
         out->num_physical_wave64_vgprs_per_simd = device_info->num_shader_visible_vgprs;
   } else {
      if (info->family == CHIP_NAVI31 || info->family == CHIP_NAVI32 ||
          info->family == CHIP_STRIX_HALO || info->gfx_level == GFX12) {
         out->num_physical_wave64_vgprs_per_simd = 768;
      } else if (info->gfx_level >= GFX10) {
         out->num_physical_wave64_vgprs_per_simd = 512;
      } else {
         out->num_physical_wave64_vgprs_per_simd = 256;
      }
   }
   if (info->gfx_level >= GFX10_3) {
      out->wave64_vgpr_alloc_granularity = out->num_physical_wave64_vgprs_per_simd / 64;
      out->wave64_vgpr_encode_granularity = 4;
   } else if (info->gfx_level == GFX9 && info->family >= CHIP_MI200) {
      out->wave64_vgpr_alloc_granularity = 8;
      out->wave64_vgpr_encode_granularity = 8;
   } else {
      out->wave64_vgpr_alloc_granularity = 4;
      out->wave64_vgpr_encode_granularity = 4;
   }
   out->min_wave64_vgpr_alloc = out->wave64_vgpr_alloc_granularity;
   out->max_vgpr_alloc = 256;

   out->num_simd_per_compute_unit = info->gfx_level >= GFX10 ? 2 : 4;

   /* LDS is 64KB per CU (4 SIMDs on GFX6-9, which is 16KB per SIMD).
    *
    * GFX10+: LDS is 128KB in WGP mode, but a workgroup can only use up to 64KB.
    * GFX7+:  Workgroups can use up to 64KB.
    * GFX6:   There is 64KB LDS per CU, but a workgroup can only use up to 32KB.
    */
   out->lds_size_per_workgroup = info->gfx_level >= GFX7 ? 64 * 1024 : 32 * 1024;

   out->hs_offchip_workgroup_dw_size = info->hs_offchip_workgroup_dw_size;

   /* Flags */
   out->has_lds_bank_count_16 = info->family == CHIP_KABINI || info->family == CHIP_STONEY;
   out->has_sram_ecc_enabled = info->family == CHIP_VEGA20 || info->family == CHIP_MI100 ||
                               info->family == CHIP_MI200 || info->family == CHIP_GFX940;
   out->has_point_sample_accel = info->family == CHIP_STRIX1 || info->family == CHIP_STRIX_HALO ||
                                 info->family == CHIP_KRACKAN1 || info->gfx_level == GFX11_7;
   out->has_fast_fma32 = info->gfx_level >= GFX9 || info->family == CHIP_TAHITI ||
                         info->family == CHIP_HAWAII || info->family == CHIP_CARRIZO;
   out->has_fma_mix = info->gfx_level >= GFX10 || info->family == CHIP_VEGA12 ||
                      info->family == CHIP_VEGA20 || info->family == CHIP_MI100 ||
                      info->family == CHIP_MI200 || info->family == CHIP_GFX940;
   out->has_mad32 =
      info->gfx_level == GFX9 ? info->family <= CHIP_MI200 : info->gfx_level < GFX10_3;
   out->has_packed_math_16bit = info->gfx_level >= GFX9;
   out->has_accelerated_dot_product =
      info->family == CHIP_VEGA20 ||
      (info->family >= CHIP_MI100 && info->family != CHIP_NAVI10 && info->family != CHIP_GFX1013);
   /* GFX1013 is GFX10 plus ray tracing instructions */
   out->has_image_bvh_intersect_ray = info->gfx_level >= GFX10_3 || info->family == CHIP_GFX1013;

   /* On newer chips, it is not necessary for NGG shaders to request
    * the allocation of GS space in passthrough mode, when they set
    * PRIMGEN_PASSTHRU_NO_MSG.
    */
   out->has_ngg_passthru_no_msg = info->family >= CHIP_NAVI23;

   out->local_invocation_ids_packed =
      info->gfx_level >= GFX11 || (!info->has_graphics && info->family >= CHIP_MI200);
   out->has_fmask = info->gfx_level <= GFX10_3;

   out->has_3d_cube_border_color_mipmap = info->has_graphics || info->family == CHIP_MI100;

   out->conformant_trunc_coord = device_info &&
                                 device_info->ids_flags & AMDGPU_IDS_FLAGS_CONFORMANT_TRUNC_COORD;

   out->has_attr_ring = info->gfx_level >= GFX11;

   /* When distributed tessellation is unsupported, switch between SEs
    * at a higher frequency to manually balance the workload between SEs.
    */
   out->smaller_tcs_workgroups = !info->has_distributed_tess && info->max_se > 1;

   out->has_gfx6_mrt_export_bug =
      info->family == CHIP_TAHITI || info->family == CHIP_PITCAIRN || info->family == CHIP_VERDE;
   out->has_vtx_format_alpha_adjust_bug = info->gfx_level <= GFX8 && info->family != CHIP_STONEY;

   /* On GFX6-7, SMEM instructions access memory when num_records == 0 or offset >= num_records,
    * which causes VM faults when reading a page that isn't mapped. To prevent the VM faults:
    * - Use a mapped VA instead of zeroes for null descriptors
    * - Make sure the offset stays within mapped VA ranges
    */
   out->has_smem_oob_access_bug = info->gfx_level <= GFX7;

   /* Whether chips are affected by the image load/sample/gather hw bug when
    * DCC is enabled (ie. WRITE_COMPRESS_ENABLE should be 0).
    */
   out->has_image_load_dcc_bug =
      info->family == CHIP_NAVI23 || info->family == CHIP_VANGOGH || info->family == CHIP_REMBRANDT;

   out->has_ls_vgpr_init_bug = info->family == CHIP_VEGA10 || info->family == CHIP_RAVEN;

   /* On GFX6 and GFX7 except Hawaii, the CB doesn't clamp outputs
    * to the range supported by the type if a channel has less
    * than 16 bits and the export format is 16_ABGR.
    * See waCbNoLt16BitIntClamp in PAL.
    */
   out->has_cb_lt16bit_int_clamp_bug = info->gfx_level <= GFX7 && info->family != CHIP_HAWAII;

   out->has_vrs_frag_pos_z_bug =
      info->family == CHIP_NAVI21 || info->family == CHIP_NAVI22 || info->family == CHIP_VANGOGH;

   /* Some GFX10 chips can hang when NGG exports zero vertices and primitives.
    * The workaround is to always export a single degenerate triangle.
    */
   out->has_ngg_fully_culled_bug = info->gfx_level == GFX10;

   /* The hw starts culling after all exports are finished,
    * not when all waves in an NGG workgroup are finished,
    * and if all primitives are culled, the hw deallocates the attribute ring
    * for the NGG workgroup and reuses it for next one while the previous NGG
    * workgroup might still be issuing attribute stores.
    * When there are 2 NGG workgroups in the system with the same attribute ring address,
    * attributes may be corrupted.
    * The workaround is to issue and wait for attribute stores before the last export.
    */
   out->has_attr_ring_wait_bug = info->gfx_level >= GFX11 && info->gfx_level < GFX12;

   out->has_primid_instancing_bug = info->gfx_level == GFX6 && info->max_se == 1;

   /* HW bug workaround when CS threadgroups > 256 threads and async compute
    * isn't used, i.e. only one compute job can run at a time.  If async
    * compute is possible, the threadgroup size must be limited to 256 threads
    * on all queues to avoid the bug.
    * Only GFX6 and certain GFX7 chips are affected.
    */
   out->has_cs_regalloc_hang_bug = info->gfx_level == GFX6 ||
                                   info->family == CHIP_BONAIRE ||
                                   info->family == CHIP_KABINI;

   /* On GFX6-8, SMEM loads on a NULL PRT page return garbage instead of zero.
    * On GFX10-12, SMEM loads on a NULL PRT page throws a VM fault and hangs the GPU.
    *
    * Only GFX9 works as expected.
    */
   out->has_smem_with_null_prt_bug = info->gfx_level <= GFX12 && info->gfx_level != GFX9 && info->family != CHIP_GFX1156;

   if (compat_mode && info->family == CHIP_REMBRANDT) {
      out->has_ngg_passthru_no_msg = false;
      out->has_vrs_frag_pos_z_bug = true;
   }

   out->has_desc_resource_level = (info->gfx_level >= GFX10 && info->gfx_level < GFX11) ||
                                  info->family == CHIP_GFX1156;
}
