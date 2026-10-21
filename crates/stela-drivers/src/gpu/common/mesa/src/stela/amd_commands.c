/* SPDX-License-Identifier: MIT */
#include "amd_commands.h"
#include "amd/common/ac_cmdbuf.h"
#include "amd/common/ac_pm4.h"
#include "amd/common/sid.h"

#include <string.h>

static bool
valid_gpu_va(uint64_t va)
{
   /* DRM/native VA allocators can represent the upper half of the 48-bit
    * GPU address space either zero-extended or canonically sign-extended. */
   return va >> 48 == 0 || (va >> 48 == UINT16_MAX && (va & (UINT64_C(1) << 47)));
}

static enum stela_amd_command_status
validate_device(const struct radeon_info *info)
{
   if (!info)
      return STELA_AMD_COMMAND_INVALID;
   if (info->gfx_level < GFX6 || info->gfx_level >= NUM_GFX_VERSIONS)
      return STELA_AMD_COMMAND_UNSUPPORTED;
   if (!info->max_se || info->max_se > AMD_MAX_SE || !info->spi_cu_en ||
       info->spi_cu_en > UINT16_MAX ||
       (info->address32_hi > UINT16_MAX && info->address32_hi < 0xffff8000))
      return STELA_AMD_COMMAND_INVALID;
   return STELA_AMD_COMMAND_OK;
}

static enum stela_amd_command_status
validate_pipeline(const struct radeon_info *info,
                  const struct stela_amd_compute_pipeline *pipeline)
{
   enum stela_amd_command_status status = validate_device(info);
   if (status != STELA_AMD_COMMAND_OK)
      return status;
   if (!pipeline || !pipeline->program_va || (pipeline->program_va & 255) ||
       !valid_gpu_va(pipeline->program_va) ||
       ((pipeline->program_va >> 40) & 0xff) != ((info->address32_hi >> 8) & 0xff) ||
       pipeline->user_sgpr_count > STELA_AMD_COMPUTE_USER_SGPRS)
      return STELA_AMD_COMMAND_INVALID;
   if ((pipeline->wave_size != 32 && pipeline->wave_size != 64) ||
       (pipeline->wave_size == 32 && info->gfx_level < GFX10))
      return STELA_AMD_COMMAND_UNSUPPORTED;
   if (pipeline->rsrc3 && info->gfx_level < GFX10 &&
       (info->has_graphics || info->family < CHIP_GFX940))
      return STELA_AMD_COMMAND_UNSUPPORTED;
   uint64_t threads = 1;
   for (unsigned axis = 0; axis < 3; axis++) {
      const uint32_t limit = info->gfx_level >= GFX12 && axis < 2 ? 0x1fff : 0xffff;
      if (!pipeline->block_size[axis] || pipeline->block_size[axis] > limit)
         return STELA_AMD_COMMAND_INVALID;
      threads *= pipeline->block_size[axis];
   }
   if (threads > UINT32_MAX)
      return STELA_AMD_COMMAND_INVALID;
   return STELA_AMD_COMMAND_OK;
}

static enum stela_amd_command_status
copy_commands(const struct ac_pm4_state *pm4, uint32_t *output,
              uint32_t capacity, uint32_t *written)
{
   *written = pm4->ndw;
   if (capacity < pm4->ndw)
      return STELA_AMD_COMMAND_BUFFER_TOO_SMALL;
   if (pm4->ndw && !output) {
      *written = 0;
      return STELA_AMD_COMMAND_INVALID;
   }
   if (pm4->ndw)
      memcpy(output, pm4->pm4, pm4->ndw * sizeof(uint32_t));
   return STELA_AMD_COMMAND_OK;
}

static void
set_thread_dimensions(struct ac_pm4_state *pm4, const uint32_t full[3],
                      const uint32_t partial[3])
{
   uint32_t x, y;
   if (pm4->info->gfx_level >= GFX12) {
      x = S_00B81C_NUM_THREAD_FULL_GFX12(full[0]);
      y = S_00B820_NUM_THREAD_FULL_GFX12(full[1]);
   } else {
      x = S_00B81C_NUM_THREAD_FULL_GFX6(full[0]);
      y = S_00B820_NUM_THREAD_FULL_GFX6(full[1]);
   }
   ac_pm4_set_reg(pm4, R_00B81C_COMPUTE_NUM_THREAD_X,
                  x | S_00B81C_NUM_THREAD_PARTIAL(partial[0]));
   ac_pm4_set_reg(pm4, R_00B820_COMPUTE_NUM_THREAD_Y,
                  y | S_00B820_NUM_THREAD_PARTIAL(partial[1]));
   ac_pm4_set_reg(pm4, R_00B824_COMPUTE_NUM_THREAD_Z,
                  S_00B824_NUM_THREAD_FULL(full[2]) |
                  S_00B824_NUM_THREAD_PARTIAL(partial[2]));
}

enum stela_amd_command_status
stela_amd_compute_preamble(const struct radeon_info *info,
                          const struct ac_preamble_state *state,
                          uint32_t *output, uint32_t capacity, uint32_t *written)
{
   if (!written)
      return STELA_AMD_COMMAND_INVALID;
   *written = 0;
   enum stela_amd_command_status status = validate_device(info);
   if (status != STELA_AMD_COMMAND_OK)
      return status;
   if (!state || (state->border_color_va & 255) || !valid_gpu_va(state->border_color_va))
      return STELA_AMD_COMMAND_INVALID;
   if (info->gfx_level == GFX6 && ((state->border_color_va >> 40) & 0xff))
      return STELA_AMD_COMMAND_UNSUPPORTED;
   if (!info->has_graphics && info->family != CHIP_MI100 && state->border_color_va)
      return STELA_AMD_COMMAND_UNSUPPORTED;
   const uint32_t interleave = state->gfx11.compute_dispatch_interleave;
   if (interleave != 0 && interleave != 64 && interleave != 128 &&
       interleave != 256 && interleave != 512)
      return STELA_AMD_COMMAND_INVALID;
   if (interleave && (info->gfx_level < GFX11 || info->gfx_level >= GFX12 || !info->has_graphics))
      return STELA_AMD_COMMAND_UNSUPPORTED;

   struct ac_pm4_state pm4 = {0};
   ac_pm4_clear_state(&pm4, info, false, true);
   ac_init_compute_preamble_state(state, &pm4);
   ac_pm4_finalize(&pm4);
   return copy_commands(&pm4, output, capacity, written);
}

enum stela_amd_command_status
stela_amd_compute_pipeline(const struct radeon_info *info,
                          const struct stela_amd_compute_pipeline *pipeline,
                          uint32_t *output, uint32_t capacity, uint32_t *written)
{
   if (!written)
      return STELA_AMD_COMMAND_INVALID;
   *written = 0;
   enum stela_amd_command_status status = validate_pipeline(info, pipeline);
   if (status != STELA_AMD_COMMAND_OK)
      return status;

   struct ac_pm4_state pm4 = {0};
   ac_pm4_clear_state(&pm4, info, false, true);
   ac_pm4_set_reg(&pm4, R_00B830_COMPUTE_PGM_LO, pipeline->program_va >> 8);
   ac_pm4_set_reg(&pm4, R_00B848_COMPUTE_PGM_RSRC1, pipeline->rsrc1);
   ac_pm4_set_reg(&pm4, R_00B84C_COMPUTE_PGM_RSRC2, pipeline->rsrc2);
   if (info->gfx_level >= GFX10)
      ac_pm4_set_reg(&pm4, R_00B8A0_COMPUTE_PGM_RSRC3, pipeline->rsrc3);
   else if (!info->has_graphics && info->family >= CHIP_GFX940)
      ac_pm4_set_reg(&pm4, R_00B8B4_COMPUTE_PGM_RSRC3, pipeline->rsrc3);
   ac_pm4_set_reg(&pm4, R_00B854_COMPUTE_RESOURCE_LIMITS, pipeline->resource_limits);
   const uint32_t partial[3] = {0};
   set_thread_dimensions(&pm4, pipeline->block_size, partial);
   for (unsigned i = 0; i < pipeline->user_sgpr_count; i++)
      ac_pm4_set_reg(&pm4, R_00B900_COMPUTE_USER_DATA_0 + i * 4, pipeline->user_sgprs[i]);
   ac_pm4_finalize(&pm4);
   return copy_commands(&pm4, output, capacity, written);
}

enum stela_amd_command_status
stela_amd_compute_dispatch(const struct radeon_info *info,
                          const struct stela_amd_compute_pipeline *pipeline,
                          const struct stela_amd_compute_dispatch *dispatch,
                          uint32_t *output, uint32_t capacity, uint32_t *written)
{
   if (!written)
      return STELA_AMD_COMMAND_INVALID;
   *written = 0;
   enum stela_amd_command_status status = validate_pipeline(info, pipeline);
   if (status != STELA_AMD_COMMAND_OK)
      return status;
   if (!dispatch)
      return STELA_AMD_COMMAND_INVALID;
   if (dispatch->tunnel && info->gfx_level < GFX10)
      return STELA_AMD_COMMAND_UNSUPPORTED;

   uint32_t groups[3], partial[3] = {0};
   for (unsigned i = 0; i < 3; i++) {
      /* Zero work is an intentional empty dispatch, after input validation. */
      if (!dispatch->size[i])
         return STELA_AMD_COMMAND_OK;
      const uint32_t block = pipeline->block_size[i];
      if (dispatch->threads) {
         groups[i] = dispatch->size[i] / block + (dispatch->size[i] % block != 0);
         partial[i] = (dispatch->size[i] - 1) % block + 1;
         /* Partial fields contain 16 bits on every generation. */
      } else {
         groups[i] = dispatch->size[i];
      }
      if (info->has_async_compute_threadgroup_bug) {
         const uint64_t threads = dispatch->threads ? dispatch->size[i] : (uint64_t)groups[i] * block;
         if (threads > UINT32_MAX)
            return STELA_AMD_COMMAND_INVALID;
         groups[i] = threads;
      }
   }

   struct ac_pm4_state pm4 = {0};
   ac_pm4_clear_state(&pm4, info, false, true);
   /* Restore full dimensions as well, so alternating partial/full dispatches
    * cannot inherit stale remainder fields from an earlier command. */
   set_thread_dimensions(&pm4, pipeline->block_size, partial);
   uint32_t initiator = S_00B800_COMPUTE_SHADER_EN(1) | S_00B800_FORCE_START_AT_000(1);
   if (pipeline->wave_size == 32)
      initiator |= S_00B800_CS_W32_EN(1);
   if (!dispatch->ordered && info->gfx_level >= GFX7 &&
       (info->has_graphics || info->family < CHIP_GFX940))
      initiator |= S_00B800_ORDER_MODE(1);
   if (dispatch->tunnel)
      initiator |= S_00B800_TUNNEL_ENABLE(1);
   if (dispatch->threads)
      initiator |= S_00B800_PARTIAL_TG_EN(1);
   if (info->has_async_compute_threadgroup_bug)
      initiator |= S_00B800_USE_THREAD_DIMENSIONS(1);
   ac_pm4_cmd_add(&pm4, PKT3(PKT3_DISPATCH_DIRECT, 3, 0) | PKT3_SHADER_TYPE_S(1));
   for (unsigned i = 0; i < 3; i++)
      ac_pm4_cmd_add(&pm4, groups[i]);
   ac_pm4_cmd_add(&pm4, initiator);
   ac_pm4_finalize(&pm4);
   return copy_commands(&pm4, output, capacity, written);
}

enum stela_amd_command_status
stela_amd_compute_preamble_native(const struct radeon_info *info,
                                 uint64_t border_color_va, uint32_t dispatch_interleave,
                                 uint32_t *output, uint32_t capacity, uint32_t *written)
{
   const struct ac_preamble_state state = {
      .border_color_va = border_color_va,
      .gfx11.compute_dispatch_interleave = dispatch_interleave,
   };
   return stela_amd_compute_preamble(info, &state, output, capacity, written);
}
