/* SPDX-License-Identifier: MIT */
#include "fixtures.h"
#include "amdgpu.h"
#include "discovery.h"
#include "soc15_hw_ip.h"

uint32_t stela_amd_test_asic(unsigned which)
{
   const uint32_t values[] = {CHIP_TAHITI, CHIP_BONAIRE, CHIP_VEGA10, CHIP_IP_DISCOVERY};
   return which < sizeof(values) / sizeof(values[0]) ? values[which] : CHIP_LAST;
}

static uint16_t sum(const uint8_t *data, size_t bytes)
{
   uint16_t result = 0;
   while (bytes--)
      result = (uint16_t)(result + *data++);
   return result;
}

/* Append one IP with 32-bit bases; returns the next IP's offset. */
static size_t add_ip(uint8_t *binary, size_t at, uint16_t hw_id, uint8_t instance,
                     const uint8_t version[4], const uint32_t *bases, uint8_t count)
{
   struct ip_v4 *entry = (struct ip_v4 *)(binary + at);
   entry->hw_id = hw_id;
   entry->instance_number = instance;
   entry->num_base_address = count;
   entry->major = version[0];
   entry->minor = version[1];
   entry->revision = version[2];
   entry->sub_revision = version[3] & 0xf;
   memcpy(entry->base_address, bases, count * sizeof(*bases));
   return at + sizeof(*entry) + count * sizeof(*bases);
}

static void set_table(struct binary_header *header, uint8_t *binary, unsigned id, size_t at,
                      size_t bytes)
{
   header->table_list[id] = (struct table_info){
      .offset = (uint16_t)at, .checksum = sum(binary + at, bytes), .size = (uint16_t)bytes};
}

size_t stela_amd_test_discovery(uint8_t *binary, size_t capacity)
{
   enum { DISCOVERY = 0x40, GC_AT = 0x100, HARVEST_AT = 0x160, VCN_AT = 0x1f0,
          MALL_AT = 0x260, END = 0x290 };
   if (!binary || capacity < END)
      return 0;
   memset(binary, 0, END);

   struct ip_discovery_header *ips = (void *)(binary + DISCOVERY);
   size_t at = DISCOVERY + sizeof(*ips);
   ips->signature = DISCOVERY_TABLE_SIGNATURE;
   ips->version = 3;
   ips->num_dies = 1;
   ips->die_info[0] = (struct die_info){.die_id = 0, .die_offset = (uint16_t)at};
   struct die_header *die = (void *)(binary + at);
   die->num_ips = 5;
   at += sizeof(*die);
   at = add_ip(binary, at, GC_HWID, 0, (const uint8_t[]){10, 3, 0, 1},
               (const uint32_t[]){0x1260, 0xa000}, 2);
   at = add_ip(binary, at, SDMA0_HWID, 0, (const uint8_t[]){5, 2, 0, 0},
               (const uint32_t[]){0x12c0}, 1);
   /* Revision bits 7:6 carry VCN's codec capability: encode disabled. */
   at = add_ip(binary, at, VCN_HWID, 0, (const uint8_t[]){3, 0, 0x80, 0},
               (const uint32_t[]){0x7800}, 1);
   at = add_ip(binary, at, UMC_HWID, 0, (const uint8_t[]){8, 7, 0, 0},
               (const uint32_t[]){0x14000}, 1);
   at = add_ip(binary, at, UMC_HWID, 1, (const uint8_t[]){8, 7, 0, 0},
               (const uint32_t[]){0x54000}, 1);
   ips->size = (uint16_t)(at - DISCOVERY);

   struct gc_info_v1_0 *gc = (void *)(binary + GC_AT);
   *gc = (struct gc_info_v1_0){
      .header = {.table_id = GC_TABLE_ID, .version_major = 1, .size = sizeof(*gc)},
      .gc_num_se = 4, .gc_num_wgp0_per_sa = 5, .gc_num_rb_per_se = 4, .gc_num_gl2c = 16,
      .gc_num_gprs = 1024, .gc_num_max_gs_thds = 32, .gc_gs_table_depth = 32,
      .gc_gsprim_buff_depth = 1792, .gc_parameter_cache_depth = 1024,
      .gc_double_offchip_lds_buffer = 1, .gc_wave_size = 32, .gc_max_waves_per_simd = 16,
      .gc_max_scratch_slots_per_cu = 32, .gc_lds_size = 64, .gc_num_sc_per_se = 4,
      .gc_num_sa_per_se = 2, .gc_num_packer_per_sc = 4, .gc_num_gl2a = 4,
   };
   struct harvest_table *harvest = (void *)(binary + HARVEST_AT);
   harvest->header.signature = HARVEST_TABLE_SIGNATURE;
   harvest->list[0] = (struct harvest_info){.hw_id = UMC_HWID, .number_instance = 1};
   struct vcn_info_v1_0 *vcn = (void *)(binary + VCN_AT);
   vcn->header = (struct vcn_info_header){
      .table_id = VCN_INFO_TABLE_ID, .version_major = 1, .size_bytes = sizeof(*vcn)};
   vcn->num_of_instances = 1;
   vcn->instance_info[0].fuse_data.all_bits = 0x5;
   struct mall_info_v2_0 *mall = (void *)(binary + MALL_AT);
   mall->header = (struct mall_info_header){
      .table_id = MALL_INFO_TABLE_ID, .version_major = 2, .size_bytes = sizeof(*mall)};
   mall->mall_size_per_umc = 2 << 20;

   struct binary_header *header = (void *)binary;
   header->binary_signature = BINARY_SIGNATURE;
   header->version_major = 1;
   header->binary_size = END;
   set_table(header, binary, IP_DISCOVERY, DISCOVERY, ips->size);
   set_table(header, binary, GC, GC_AT, sizeof(*gc));
   set_table(header, binary, HARVEST_INFO, HARVEST_AT, sizeof(*harvest));
   set_table(header, binary, VCN_INFO, VCN_AT, sizeof(*vcn));
   set_table(header, binary, MALL_INFO, MALL_AT, sizeof(*mall));
   const size_t checked = offsetof(struct binary_header, binary_checksum) +
                          sizeof(header->binary_checksum);
   header->binary_checksum = sum(binary + checked, END - checked);
   return END;
}
