/* SPDX-License-Identifier: MIT */
/* Stela's BAR policy in Stela's Linux environment; CPU only. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../native_bar.h"

static struct stela_amd_bar_layout layout(uint32_t asic, uint64_t bar_bytes,
                                          uint32_t max_assignment, uint64_t page)
{
   struct stela_amd_bar_layout result;
   assert(stela_amd_native_bar_layout(asic, bar_bytes, max_assignment, page, &result) ==
          STELA_AMD_BAR_OK);
   return result;
}

int main(void)
{
   /* SI has no doorbells and keeps its registers in BAR2; CIK+ use BAR5. */
   uint32_t bar = UINT32_MAX;
   assert(stela_amd_native_register_bar(CHIP_TAHITI, &bar) == STELA_AMD_BAR_OK && bar == 2);
   assert(stela_amd_native_register_bar(CHIP_BONAIRE, &bar) == STELA_AMD_BAR_OK && bar == 5);
   struct stela_amd_bar_layout si = layout(CHIP_TAHITI, 0, 0, 4096);
   assert(si.register_bar == 2 && !si.kernel_doorbells && !si.kernel_doorbell_bytes);

   /* max_assignment + 1 doorbells, page aligned, plus MES's page. */
   struct stela_amd_bar_layout cik = layout(CHIP_BONAIRE, 0x100000, 1023, 4096);
   assert(cik.register_bar == 5 && cik.kernel_doorbell_bytes == 8192);
   assert(cik.kernel_doorbells == 2048);
   cik = layout(CHIP_BONAIRE, 0x100000, 1023, 65536);
   assert(cik.kernel_doorbell_bytes == 131072 && cik.kernel_doorbells == 32768);
   /* Vega+ adds the SDMA paging queue's page. */
   struct stela_amd_bar_layout vega = layout(CHIP_VEGA10, 0x100000, 1023, 4096);
   assert(vega.kernel_doorbell_bytes == 12288 && vega.kernel_doorbells == 3072);
   assert(layout(CHIP_IP_DISCOVERY, 0x100000, 1023, 4096).kernel_doorbells == 3072);

   /* Refusals leave the output unchanged. */
   struct stela_amd_bar_layout output, saved;
   memset(&output, 0xa5, sizeof(output));
   saved = output;
   const struct {
      uint32_t asic;
      uint64_t bytes;
      uint32_t max;
      uint64_t page;
   } bad[] = {
      {CHIP_LAST, 65536, 1023, 4096}, {CHIP_BONAIRE, 65536, 1023, 0},
      {CHIP_BONAIRE, 65536, 1023, 8191}, {CHIP_BONAIRE, 65536, 1023, UINT64_MAX},
      {CHIP_BONAIRE, 0, 1023, 4096}, {CHIP_BONAIRE, 3, 1023, 4096},
      {CHIP_BONAIRE, UINT64_MAX, 1023, 4096}, {CHIP_BONAIRE, 65536, UINT32_MAX, 4096},
      {CHIP_VEGA10, 65536, UINT32_MAX - 1, 4096}, {CHIP_VEGA10, 4096, 1023, 4096},
      {CHIP_BONAIRE, UINT64_C(0xffffffff) * 4, UINT32_C(0x7ffffffe), 4096},
      {CHIP_TAHITI, 4096, 0, 4096}, {CHIP_TAHITI, 0, 1, 4096},
   };
   for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
      assert(stela_amd_native_bar_layout(bad[i].asic, bad[i].bytes, bad[i].max,
                                         bad[i].page, &output) != STELA_AMD_BAR_OK);
      assert(!memcmp(&output, &saved, sizeof(output)));
   }
   assert(stela_amd_native_bar_layout(CHIP_TAHITI, 0, 0, 4096, NULL) == STELA_AMD_BAR_INVALID);
   bar = UINT32_MAX;
   assert(stela_amd_native_register_bar(CHIP_LAST, &bar) == STELA_AMD_BAR_INVALID);
   assert(bar == UINT32_MAX);
   assert(stela_amd_native_register_bar(CHIP_TAHITI, NULL) == STELA_AMD_BAR_INVALID);
   printf("AMD native BAR: register BARs, doorbell layouts and refusals\n");
   return 0;
}
