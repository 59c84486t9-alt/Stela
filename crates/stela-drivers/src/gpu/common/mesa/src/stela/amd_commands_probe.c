/* SPDX-License-Identifier: MIT */
#include "amd_commands.h"
#include "amd/common/ac_cmdbuf.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/sid.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
   if (!(condition)) { \
      fprintf(stderr, "%s:%u: %s\n", __func__, __LINE__, #condition); \
      return false; \
   } \
} while (0)

struct register_write {
   uint32_t offset;
   uint32_t value;
};

struct decoded {
   struct register_write regs[128];
   uint32_t num_regs;
   uint32_t dispatch[3];
   uint32_t initiator;
   bool dispatched;
};

static bool
record_register(struct decoded *result, uint32_t offset, uint32_t value)
{
   for (unsigned i = 0; i < result->num_regs; i++) {
      if (result->regs[i].offset == offset) {
         result->regs[i].value = value;
         return true;
      }
   }
   CHECK(result->num_regs < ARRAY_SIZE(result->regs));
   result->regs[result->num_regs++] = (struct register_write){offset, value};
   return true;
}

/* Independent PM4 packet decoder: reconstruct the hardware register writes,
 * rather than compare command bytes with a second call to the encoder. */
static bool
decode(struct decoded *result, const uint32_t *words, uint32_t count)
{
   for (unsigned cursor = 0; cursor < count;) {
      const uint32_t header = words[cursor];
      CHECK(header >> 30 == 3);
      const uint32_t length = ((header >> 16) & 0x3fff) + 2;
      CHECK(length <= count - cursor);
      const uint32_t opcode = (header >> 8) & 0xff;
      const uint32_t *packet = words + cursor;
      uint32_t base;
      switch (opcode) {
      case PKT3_SET_CONFIG_REG: base = 0x8000; break;
      case PKT3_SET_CONTEXT_REG: base = 0x28000; break;
      case PKT3_SET_SH_REG: base = 0xb000; break;
      case PKT3_SET_UCONFIG_REG: base = 0x30000; break;
      case PKT3_SET_CONTEXT_REG_PAIRS:
      case PKT3_SET_SH_REG_PAIRS:
      case PKT3_SET_UCONFIG_REG_PAIRS:
         base = opcode == PKT3_SET_CONTEXT_REG_PAIRS ? 0x28000 :
                opcode == PKT3_SET_SH_REG_PAIRS ? 0xb000 : 0x30000;
         CHECK((length - 1) % 2 == 0);
         for (unsigned i = 1; i < length; i += 2)
            CHECK(record_register(result, base + 4 * packet[i], packet[i + 1]));
         goto next;
      case PKT3_SET_CONTEXT_REG_PAIRS_PACKED:
      case PKT3_SET_SH_REG_PAIRS_PACKED:
      case PKT3_SET_SH_REG_PAIRS_PACKED_N:
         base = opcode == PKT3_SET_CONTEXT_REG_PAIRS_PACKED ? 0x28000 : 0xb000;
         CHECK(length >= 5 && (length - 2) % 3 == 0);
         CHECK(packet[1] == 2 * ((length - 2) / 3));
         for (unsigned i = 2; i < length; i += 3) {
            CHECK(record_register(result, base + 4 * (packet[i] & 0xffff), packet[i + 1]));
            CHECK(record_register(result, base + 4 * (packet[i] >> 16), packet[i + 2]));
         }
         goto next;
      case PKT3_DISPATCH_DIRECT:
         CHECK(length == 5 && (header & 2));
         CHECK(!result->dispatched);
         memcpy(result->dispatch, packet + 1, sizeof(result->dispatch));
         result->initiator = packet[4];
         result->dispatched = true;
         goto next;
      default:
         CHECK(false);
      }
      CHECK(length >= 3);
      for (unsigned i = 2; i < length; i++)
         CHECK(record_register(result, base + 4 * ((packet[1] & 0xffff) + i - 2), packet[i]));
next:
      cursor += length;
   }
   return true;
}

static bool
check_register(const struct decoded *result, uint32_t offset, uint32_t expected)
{
   for (unsigned i = 0; i < result->num_regs; i++) {
      if (result->regs[i].offset == offset) {
         if (result->regs[i].value == expected)
            return true;
         fprintf(stderr, "register %06x: got %08x expected %08x\n",
                 offset, result->regs[i].value, expected);
         return false;
      }
   }
   fprintf(stderr, "register %06x was not written\n", offset);
   return false;
}

static struct radeon_info
gpu(enum amd_gfx_level level, enum radeon_family family, bool graphics, bool packed)
{
   return (struct radeon_info){
      .gfx_level = level,
      .family = family,
      .has_graphics = graphics,
      .spi_cu_en = 0x00f3,
      .max_se = level >= GFX12 ? 9 : level >= GFX11 ? 8 : level == GFX6 ? 2 : 4,
      .address32_hi = 0x1234,
      .has_set_sh_pairs_packed = packed,
      .has_set_sh_pairs = !packed && level >= GFX12,
      .has_set_uconfig_pairs = level >= GFX12,
   };
}

static struct stela_amd_compute_pipeline
pipeline(void)
{
   struct stela_amd_compute_pipeline result = {
      .program_va = UINT64_C(0x123402000000),
      .rsrc1 = 0x13579,
      .rsrc2 = 0x24680,
      .rsrc3 = 0,
      .resource_limits = 0x456,
      .block_size = {8, 4, 2},
      .wave_size = 64,
      .user_sgpr_count = STELA_AMD_COMPUTE_USER_SGPRS,
   };
   for (unsigned i = 0; i < ARRAY_SIZE(result.user_sgprs); i++)
      result.user_sgprs[i] = 0xabc00000 + i;
   return result;
}

static bool
check_target(enum amd_gfx_level level, enum radeon_family family, bool graphics, bool packed,
             uint32_t cu_mask)
{
   struct radeon_info info = gpu(level, family, graphics, packed);
   info.spi_cu_en = cu_mask;
   struct stela_amd_compute_pipeline shader = pipeline();
   shader.wave_size = level >= GFX10 ? 32 : 64;
   if (level >= GFX10 || (!graphics && family >= CHIP_GFX940))
      shader.rsrc3 = 0x7654;
   const struct ac_preamble_state preamble = {
      .border_color_va = graphics || family == CHIP_MI100 ? 0x100000 : 0,
   };
   uint32_t words[128], written;
   struct decoded decoded = {0};
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
   CHECK(written && decode(&decoded, words, written));
   CHECK(check_register(&decoded, 0xb834, 0x12));
   CHECK(check_register(&decoded, 0xb858, (cu_mask & 0xffff) * 0x10001));
   if (level >= GFX12)
      CHECK(check_register(&decoded, 0xb88c, (cu_mask & 0xffff) * 0x10001));
   if (!graphics && family >= CHIP_GFX940)
      CHECK(check_register(&decoded, 0xb8b4, 0));

   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
   CHECK(written && decode(&decoded, words, written));
   CHECK(check_register(&decoded, 0xb830, 0x34020000));
   CHECK(check_register(&decoded, 0xb848, shader.rsrc1));
   CHECK(check_register(&decoded, 0xb84c, shader.rsrc2));
   CHECK(check_register(&decoded, 0xb854, shader.resource_limits));
   for (unsigned i = 0; i < 3; i++)
      CHECK(check_register(&decoded, 0xb81c + i * 4, shader.block_size[i]));
   for (unsigned i = 0; i < shader.user_sgpr_count; i++)
      CHECK(check_register(&decoded, 0xb900 + i * 4, shader.user_sgprs[i]));
   if (shader.rsrc3)
      CHECK(check_register(&decoded, level >= GFX10 ? 0xb8a0 : 0xb8b4, shader.rsrc3));

   struct stela_amd_compute_dispatch dispatch = {.size = {19, 7, 3}, .threads = true};
   CHECK(stela_amd_compute_dispatch(&info, &shader, &dispatch, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
   CHECK(decode(&decoded, words, written));
   CHECK(check_register(&decoded, 0xb81c, 8 | 3 << 16));
   CHECK(check_register(&decoded, 0xb820, 4 | 3 << 16));
   CHECK(check_register(&decoded, 0xb824, 2 | 1 << 16));
   CHECK(decoded.dispatched);
   CHECK(decoded.dispatch[0] == 3 && decoded.dispatch[1] == 2 && decoded.dispatch[2] == 2);
   CHECK(decoded.initiator & 1);
   CHECK(decoded.initiator & (1u << 1)); /* PARTIAL_TG_EN */
   CHECK(!!(decoded.initiator & (1u << 15)) == (shader.wave_size == 32));

   /* A later full-group dispatch must clear the partial threadgroup fields. */
   dispatch = (struct stela_amd_compute_dispatch){.size = {3, 2, 2}, .ordered = true};
   decoded.dispatched = false;
   CHECK(stela_amd_compute_dispatch(&info, &shader, &dispatch, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
   CHECK(decode(&decoded, words, written));
   for (unsigned i = 0; i < 3; i++)
      CHECK(check_register(&decoded, 0xb81c + i * 4, shader.block_size[i]));
   CHECK(!(decoded.initiator & (1u << 1)));
   CHECK(!(decoded.initiator & (1u << 6))); /* ORDER_MODE */
   printf("PM4 target gfx=%u family=%u graphics=%u packed=%u cu_mask=%08x validated\n",
          level, family, graphics, packed, cu_mask);
   return true;
}

static bool
check_failures_and_workaround(void)
{
   struct radeon_info info = gpu(GFX10, CHIP_NAVI10, true, false);
   struct stela_amd_compute_pipeline shader = pipeline();
   struct stela_amd_compute_dispatch dispatch = {.size = {3, 2, 2}};
   uint32_t words[128], before[128], written = 99;
   memset(words, 0xa5, sizeof(words));
   memcpy(before, words, sizeof(words));
   CHECK(stela_amd_compute_pipeline(&info, &shader, NULL, 0, &written) == STELA_AMD_COMMAND_BUFFER_TOO_SMALL);
   CHECK(written > 0 && written < ARRAY_SIZE(words));
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, written - 1, &written) == STELA_AMD_COMMAND_BUFFER_TOO_SMALL);
   CHECK(memcmp(words, before, sizeof(words)) == 0);
   CHECK(stela_amd_compute_pipeline(&info, &shader, NULL, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   CHECK(written == 0);
   shader.program_va++;
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   shader.program_va--;
   shader.program_va ^= UINT64_C(1) << 40;
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   shader = pipeline();
   shader.user_sgpr_count++;
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   shader = pipeline();
   shader.block_size[1] = 0;
   CHECK(stela_amd_compute_dispatch(&info, &shader, &dispatch, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   shader = pipeline();
   info.gfx_level = GFX8;
   shader.wave_size = 32;
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_UNSUPPORTED);
   shader = pipeline();
   shader.rsrc3 = 1;
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_UNSUPPORTED);
   CHECK(memcmp(words, before, sizeof(words)) == 0);
   info = gpu(GFX10, CHIP_NAVI10, true, false);
   shader = pipeline();
   /* Accept both hardware-valid representations of an upper-half GPU VA. */
   info.address32_hi = 0xffff9234;
   shader.program_va = UINT64_C(0xffff923402000000);
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
   shader.program_va = UINT64_C(0x923402000000);
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
   info = gpu(GFX10, CHIP_NAVI10, true, false);
   shader = pipeline();
   info.has_async_compute_threadgroup_bug = true;
   struct decoded decoded = {0};
   CHECK(stela_amd_compute_dispatch(&info, &shader, &dispatch, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
   CHECK(decode(&decoded, words, written));
   CHECK(decoded.dispatch[0] == 24 && decoded.dispatch[1] == 8 && decoded.dispatch[2] == 4);
   CHECK(decoded.initiator & (1u << 5)); /* USE_THREAD_DIMENSIONS */
   dispatch.size[0] = UINT32_MAX;
   memcpy(before, words, sizeof(words));
   CHECK(stela_amd_compute_dispatch(&info, &shader, &dispatch, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   CHECK(written == 0 && memcmp(words, before, sizeof(words)) == 0);
   dispatch.size[0] = 0;
   CHECK(stela_amd_compute_dispatch(&info, &shader, &dispatch, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
   CHECK(written == 0 && memcmp(words, before, sizeof(words)) == 0);
   return true;
}

static bool
check_preamble_and_limits(void)
{
   struct radeon_info info = gpu(GFX11, CHIP_NAVI31, true, false);
   struct ac_preamble_state preamble = {.border_color_va = 0x100000};
   uint32_t words[128], before[128], written;
   memset(words, 0x3c, sizeof(words));
   memcpy(before, words, sizeof(words));
   CHECK(stela_amd_compute_preamble(&info, &preamble, NULL, 0, &written) == STELA_AMD_COMMAND_BUFFER_TOO_SMALL);
   CHECK(written > 0);
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, written - 1, &written) == STELA_AMD_COMMAND_BUFFER_TOO_SMALL);
   CHECK(!memcmp(words, before, sizeof(words)));
   info.spi_cu_en = 0;
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   CHECK(written == 0 && !memcmp(words, before, sizeof(words)));
   info.spi_cu_en = 0x00f3;
   preamble.gfx11.compute_dispatch_interleave = 63;
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   preamble.gfx11.compute_dispatch_interleave = 256;
   info.gfx_level = GFX12;
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_UNSUPPORTED);
   preamble.gfx11.compute_dispatch_interleave = 0;
   info = gpu(GFX9, CHIP_MI200, false, false);
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_UNSUPPORTED);
   info = gpu(GFX6, CHIP_TAHITI, true, false);
   preamble.border_color_va = UINT64_C(1) << 40;
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_UNSUPPORTED);
   preamble.border_color_va = 1;
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   preamble.border_color_va = 0;
   info.gfx_level = (enum amd_gfx_level)(GFX6 - 1);
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_UNSUPPORTED);
   info = gpu(GFX12, CHIP_GFX1200, true, false);
   struct stela_amd_compute_pipeline shader = pipeline();
   shader.block_size[0] = 0x2000;
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   shader = pipeline();
   shader.program_va = UINT64_C(0x1234123402000000);
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_INVALID);
   CHECK(written == 0 && !memcmp(words, before, sizeof(words)));
   CHECK(stela_amd_compute_pipeline(&info, &shader, words, ARRAY_SIZE(words), NULL) == STELA_AMD_COMMAND_INVALID);

   info = gpu(GFX11, CHIP_NAVI31, true, true);
   preamble.gfx11.compute_dispatch_interleave = 256;
   struct decoded decoded = {0};
   CHECK(stela_amd_compute_preamble(&info, &preamble, words, ARRAY_SIZE(words), &written) == STELA_AMD_COMMAND_OK);
   CHECK(decode(&decoded, words, written));
   CHECK(check_register(&decoded, 0xb8bc, 256));
   return true;
}

int
main(void)
{
   const struct {
      enum amd_gfx_level level;
      enum radeon_family family;
      bool graphics;
   } targets[] = {
      {GFX6, CHIP_TAHITI, true}, {GFX7, CHIP_BONAIRE, true},
      {GFX8, CHIP_CARRIZO, true}, {GFX9, CHIP_RAVEN, true},
      {GFX9, CHIP_MI100, false}, {GFX9, CHIP_MI200, false}, {GFX9, CHIP_GFX940, false},
      {GFX10, CHIP_NAVI10, true}, {GFX10_3, CHIP_REMBRANDT, true},
      {GFX11, CHIP_NAVI31, true}, {GFX11_5, CHIP_STRIX1, true},
      {GFX11_7, CHIP_GFX1170, true}, {GFX12, CHIP_GFX1200, true},
      {GFX12_1, CHIP_GFX1210, true},
   };
   const uint32_t masks[] = {0x00f3, UINT32_MAX};
   for (unsigned i = 0; i < ARRAY_SIZE(targets); i++) {
      for (unsigned m = 0; m < ARRAY_SIZE(masks); m++) {
         if (!check_target(targets[i].level, targets[i].family, targets[i].graphics,
                           false, masks[m]))
            return 1;
         if (targets[i].level >= GFX11 &&
             !check_target(targets[i].level, targets[i].family, targets[i].graphics,
                           true, masks[m]))
            return 1;
      }
   }
   if (!check_failures_and_workaround() || !check_preamble_and_limits())
      return 1;
   puts("AMD command generation validated; physical GPU and Metal execution unverified");
   return 0;
}
