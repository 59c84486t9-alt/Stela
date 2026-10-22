/* SPDX-License-Identifier: MIT */
/* CPU-only original-driver metadata fixtures; no device or acquisition hooks. */
#include "../stela/discovery_binary.h"
#include "../amdgpu/amdgpu_ip_limits.h"
#include "../include/soc15_hw_ip.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static void reference_log(void *device, const char *format, ...)
{
   (void)device;
   (void)format;
}

/* Original Linux donors intentionally retain signed comparisons. Their native
 * tests use Linux's signed-overflow policy (-fwrapv), not a rewritten policy. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#include "discovery_reference.h"
#pragma GCC diagnostic pop

struct fixture {
   uint8_t binary[8192];
   size_t size, directory, offset[TOTAL_TABLES], length[TOTAL_TABLES];
   unsigned version, dies, wide;
};
static unsigned comparisons, mutations, accepted_mutations, official;
static void put16(void *p, uint16_t value)
{
   uint8_t *bytes = p;
   bytes[0] = value;
   bytes[1] = value >> 8;
}
static void put32(void *p, uint32_t value)
{
   uint8_t *bytes = p;
   for (unsigned i = 0; i < 4; i++)
      bytes[i] = value >> (i * 8);
}
static void put64(void *p, uint64_t value)
{
   put32(p, value);
   put32((uint8_t *)p + 4, value >> 32);
}
static struct table_info *directory_entry(struct fixture *f, unsigned id)
{
   return (void *)(f->binary + f->directory + id * sizeof(struct table_info));
}
static void checksums(struct fixture *f)
{
   for (unsigned i = 0; i < TOTAL_TABLES; i++) {
      if (f->length[i]) {
         struct table_info *entry = directory_entry(f, i);
         put16(&entry->checksum, donor_checksum(f->binary + f->offset[i], f->length[i]));
      }
   }
   struct binary_header *h = (void *)f->binary;
   size_t start = offsetof(struct binary_header, binary_checksum) + sizeof(h->binary_checksum);
   put16(&h->binary_checksum, donor_checksum(f->binary + start, f->size - start));
}
static void declare_table(struct fixture *f, unsigned id, size_t bytes)
{
   f->size = (f->size + 3) & ~(size_t)3;
   assert(f->size + bytes <= sizeof(f->binary));
   f->offset[id] = f->size;
   f->length[id] = bytes;
   struct table_info *entry = directory_entry(f, id);
   put16(&entry->offset, f->size);
   put16(&entry->size, bytes);
   f->size += bytes;
}
static size_t gfx_bytes(unsigned major, unsigned minor)
{
   if (major == 1)
      return minor >= 3 ? sizeof(struct gc_info_v1_3) :
             minor == 2 ? sizeof(struct gc_info_v1_2) :
             minor == 1 ? sizeof(struct gc_info_v1_1) : sizeof(struct gc_info_v1_0);
   return minor == 1 ? sizeof(struct gc_info_v2_1) : sizeof(struct gc_info_v2_0);
}
static struct fixture make_fixture(unsigned version, unsigned ip_version, unsigned wide,
                                   unsigned gc_major, unsigned gc_minor, unsigned variant)
{
   struct fixture f = {.version = version, .dies = 2, .wide = wide};
   f.directory = version == 2 ? offsetof(struct binary_header_v2, table_list) :
                 offsetof(struct binary_header, table_list);
   f.size = f.directory + TOTAL_TABLES * sizeof(struct table_info);
   struct binary_header *header = (void *)f.binary;
   put32(&header->binary_signature, BINARY_SIGNATURE);
   put16(&header->version_major, version);
   if (version == 2)
      put16(&((struct binary_header_v2 *)header)->num_tables, TOTAL_TABLES);
   struct { unsigned hwid, instance, bases, revision; } ips[] = {
      {GC_HWID, 0, 4, 3}, {SDMA0_HWID, 0, 3, 1}, {SDMA1_HWID, 3, 2, 1},
      {VCN_HWID, 0, 2, 0x42}, {VCN_HWID, 1, 1, 0x82},
      {UMC_HWID, 0, 1, 1}, {UMC_HWID, 3, 2, 1}, {DMU_HWID, 0, 1, 1},
      {WAFLC_HWID, 0, 2, 5}, {HW_ID_MAX + 1, 1, 3, 1}, {GC_HWID, 255, 0, 1},
   };
   size_t ip_bytes = 0;
   for (unsigned i = 0; i < sizeof(ips) / sizeof(ips[0]); i++)
      ip_bytes += offsetof(struct ip_v4, base_address) + ips[i].bases * (wide ? 8 : 4);
   declare_table(&f, IP_DISCOVERY, sizeof(struct ip_discovery_header) +
                 f.dies * (sizeof(struct die_header) + ip_bytes));
   struct ip_discovery_header *ip_header = (void *)(f.binary + f.offset[IP_DISCOVERY]);
   put32(&ip_header->signature, DISCOVERY_TABLE_SIGNATURE);
   put16(&ip_header->version, ip_version);
   put16(&ip_header->size, f.length[IP_DISCOVERY]);
   put16(&ip_header->num_dies, f.dies);
   ip_header->base_addr_64_bit = wide;
   size_t at = f.offset[IP_DISCOVERY] + sizeof(*ip_header);
   for (unsigned d = 0; d < f.dies; d++) {
      put16(&ip_header->die_info[d].die_id, d);
      put16(&ip_header->die_info[d].die_offset, at);
      struct die_header *die = (void *)(f.binary + at);
      put16(&die->die_id, d);
      put16(&die->num_ips, sizeof(ips) / sizeof(ips[0]));
      at += sizeof(*die);
      for (unsigned i = 0; i < sizeof(ips) / sizeof(ips[0]); i++) {
         struct ip_v4 *ip = (void *)(f.binary + at);
         put16(&ip->hw_id, ips[i].hwid);
         ip->instance_number = ips[i].instance;
         ip->num_base_address = ips[i].bases;
         ip->major = i == 0 ? 9 : 4;
         ip->minor = d;
         ip->revision = ips[i].revision;
         ip->variant = ip_version >= 3 ? 2 : 0;
         ip->sub_revision = ip_version >= 3 ? 3 : 1; /* Original harvest nibble. */
         for (unsigned k = 0; k < ips[i].bases; k++) {
            uint64_t address = 0xc0000100u + d * 0x4000 + i * 0x100 + k * 0x10;
            if (wide)
               put64(&ip->base_address_64[k], UINT64_C(0xabcde00000000) | address);
            else
               put32(&ip->base_address[k], address);
         }
         at += offsetof(struct ip_v4, base_address) + ips[i].bases * (wide ? 8 : 4);
      }
   }
   declare_table(&f, GC, gfx_bytes(gc_major, gc_minor));
   struct gpu_info_header *gc = (void *)(f.binary + f.offset[GC]);
   put32(&gc->table_id, GC_TABLE_ID);
   put16(&gc->version_major, gc_major);
   put16(&gc->version_minor, gc_minor);
   put32(&gc->size, f.length[GC]);
   for (size_t i = sizeof(*gc); i < f.length[GC]; i += 4)
      put32((uint8_t *)gc + i, 4 + i / 4);
   declare_table(&f, HARVEST_INFO, sizeof(struct harvest_table));
   struct harvest_table *harvest = (void *)(f.binary + f.offset[HARVEST_INFO]);
   put32(&harvest->header.signature, HARVEST_TABLE_SIGNATURE);
   put16(&harvest->list[0].hw_id, VCN_HWID);
   harvest->list[0].number_instance = 1;
   put16(&harvest->list[1].hw_id, UMC_HWID);
   harvest->list[1].number_instance = 3;
   declare_table(&f, VCN_INFO, sizeof(struct vcn_info_v1_0));
   struct vcn_info_v1_0 *vcn = (void *)(f.binary + f.offset[VCN_INFO]);
   put32(&vcn->header.table_id, VCN_INFO_TABLE_ID);
   put16(&vcn->header.version_major, 1);
   put32(&vcn->header.size_bytes, f.length[VCN_INFO]);
   put32(&vcn->num_of_instances, 4);
   for (unsigned i = 0; i < VCN_INFO_TABLE_MAX_NUM_INSTANCES; i++)
      put32(&vcn->instance_info[i].fuse_data.all_bits, i + 1);
   declare_table(&f, MALL_INFO, sizeof(struct mall_info_v1_0));
   struct mall_info_v1_0 *mall = (void *)(f.binary + f.offset[MALL_INFO]);
   put32(&mall->header.table_id, MALL_INFO_TABLE_ID);
   put16(&mall->header.version_major, 1 + (variant & 1));
   put32(&mall->header.size_bytes, f.length[MALL_INFO]);
   put32(&mall->mall_size_per_m, 1024);
   put32(&mall->m_s_present, 1);
   put32(&mall->m_half_use, 2);
   declare_table(&f, NPS_INFO, sizeof(struct nps_info_v1_0));
   struct nps_info_v1_0 *nps = (void *)(f.binary + f.offset[NPS_INFO]);
   put32(&nps->header.table_id, NPS_INFO_TABLE_ID);
   put16(&nps->header.version_major, 1);
   put32(&nps->header.size_bytes, f.length[NPS_INFO]);
   put32(&nps->count, 2);
   put64(&nps->instance_info[0].base_address, 0x1000);
   put64(&nps->instance_info[0].limit_address, 0x1fff);
   put64(&nps->instance_info[1].base_address, 0x4000);
   put64(&nps->instance_info[1].limit_address, 0x8fff);
   put16(&header->binary_size, f.size);
   checksums(&f);
   return f;
}

static void normalize(struct amdgpu_device *device)
{
   for (unsigned ip = 0; ip < MAX_HWIP; ip++) {
      for (unsigned i = 0; i < HWIP_MAX_INSTANCE; i++) {
         if (device->reg_offset[ip][i]) {
            size_t offset = (uint8_t *)device->reg_offset[ip][i] - device->discovery.bin;
            device->reg_offset[ip][i] = (void *)(uintptr_t)(offset + 1);
         }
      }
   }
   device->discovery.bin = NULL;
}
static void compare_original(const uint8_t *binary, size_t bytes)
{
   uint8_t *left = malloc(bytes), *right = malloc(bytes);
   assert(left && right);
   memcpy(left, binary, bytes);
   memcpy(right, binary, bytes);
   struct amdgpu_device old, next;
   memset(&old, 0, sizeof(old));
   memset(&next, 0, sizeof(next));
   old.discovery.bin = left;
   next.discovery.bin = right;
   old.discovery.size = next.discovery.size = bytes;
   checked = 0;
   assert(!reference_validation(&old));
   checked = 1;
   assert(!reference_validation(&next));
   checked = 0;
   assert(!amdgpu_discovery_reg_base_init(&old));
   checked = 1;
   assert(!amdgpu_discovery_reg_base_init(&next));
   checked = 0;
   int gfx = amdgpu_discovery_get_gfx_info(&old);
   int mall = amdgpu_discovery_get_mall_info(&old);
   int vcn = amdgpu_discovery_get_vcn_info(&old);
   checked = 1;
   assert(gfx == amdgpu_discovery_get_gfx_info(&next));
   assert(mall == amdgpu_discovery_get_mall_info(&next));
   assert(vcn == amdgpu_discovery_get_vcn_info(&next));
   unsigned left_count = 0, right_count = 0, left_umc = 0, right_umc = 0;
   checked = 0;
   amdgpu_discovery_read_from_harvest_table(&old, &left_count, &left_umc);
   checked = 1;
   amdgpu_discovery_read_from_harvest_table(&next, &right_count, &right_umc);
   assert(left_count == right_count && left_umc == right_umc);
   struct amdgpu_gmc_memrange old_ranges[NPS_INFO_TABLE_MAX_NUM_INSTANCES];
   struct amdgpu_gmc_memrange next_ranges[NPS_INFO_TABLE_MAX_NUM_INSTANCES];
   memset(old_ranges, 0x5a, sizeof(old_ranges));
   memset(next_ranges, 0x5a, sizeof(next_ranges));
   uint32_t old_type = UINT32_MAX, next_type = UINT32_MAX;
   int old_count = NPS_INFO_TABLE_MAX_NUM_INSTANCES, next_count = old_count;
   checked = 0;
   int nps = amdgpu_discovery_get_nps_info(&old, &old_type, old_ranges, &old_count, false);
   checked = 1;
   assert(nps == amdgpu_discovery_get_nps_info(&next, &next_type, next_ranges, &next_count, false));
   assert(old_type == next_type && old_count == next_count);
   assert(!memcmp(old_ranges, next_ranges, sizeof(old_ranges)));
   assert(!memcmp(left, right, bytes));
   normalize(&old);
   normalize(&next);
   assert(!memcmp(&old, &next, sizeof(old)));
   free(left);
   free(right);
   comparisons++;
}
static void harvest_lookup(void)
{
   for (unsigned version = 0; version <= 2; version++) {
      struct fixture f = make_fixture(version, 2, 0, 1, 0, 0);
      uint8_t old_bytes[sizeof(f.binary)], next_bytes[sizeof(f.binary)];
      memcpy(old_bytes, f.binary, sizeof(old_bytes));
      memcpy(next_bytes, f.binary, sizeof(next_bytes));
      struct amdgpu_device old, next;
      memset(&old, 0, sizeof(old));
      memset(&next, 0, sizeof(next));
      old.discovery.bin = old_bytes;
      next.discovery.bin = next_bytes;
      old.discovery.size = next.discovery.size = f.size;
      checked = 0;
      assert(!amdgpu_discovery_reg_base_init(&old));
      checked = 1;
      assert(!amdgpu_discovery_reg_base_init(&next));
      uint32_t count = 0;
      checked_harvest(&next, &count);
      assert(count == 4);
      assert(next.vcn.harvest_config == 3 && next.vcn.inst_mask == 0);
      assert(next.jpeg.inst_mask == 0 && next.harvest_ip_mask == AMD_HARVEST_IP_DMU_MASK);
      if (version < 2) {
         uint32_t old_count = 0;
         checked = 0;
         amdgpu_discovery_read_harvest_bit_per_ip(&old, &old_count);
         assert(old_count == count);
         normalize(&old);
         normalize(&next);
         assert(!memcmp(&old, &next, sizeof(old)));
      } else {
         /* Explicit corrected behavior: the old fixed directory would choose
          * offset6 (num_tables), not this valid v2 IP offset64. Never execute
          * that unsafe old walk as a successful native result. */
         const struct binary_header *fixed = (const void *)f.binary;
         assert(fixed->table_list[IP_DISCOVERY].offset == TOTAL_TABLES);
         assert(fixed->table_list[IP_DISCOVERY].offset != f.offset[IP_DISCOVERY]);
      }
   }
}

static void boundary_layouts(void)
{
   struct fixture f = make_fixture(2, 4, 1, 2, 1, 1);
   struct ip_discovery_header *ip = (void *)(f.binary + f.offset[IP_DISCOVERY]);
   put16(&ip->num_dies, 16);
   size_t at = f.offset[IP_DISCOVERY] + sizeof(*ip);
   for (unsigned i = 0; i < 16; i++) {
      put16(&ip->die_info[i].die_id, i);
      put16(&ip->die_info[i].die_offset, at);
      struct die_header *die = (void *)(f.binary + at);
      put16(&die->die_id, i);
      put16(&die->num_ips, 0);
      at += sizeof(*die);
   }
   checksums(&f);
   assert(!amdgpu_discovery_binary_validate(f.binary, f.size));
   compare_original(f.binary, f.size);
   put16(&ip->num_dies, 0);
   checksums(&f);
   assert(!amdgpu_discovery_binary_validate(f.binary, f.size));
   compare_original(f.binary, f.size);
   put16(&ip->num_dies, 1);
   struct die_header *die = (void *)(f.binary + ip->die_info[0].die_offset);
   put16(&die->num_ips, 63);
   at = ip->die_info[0].die_offset + sizeof(*die);
   for (unsigned i = 0; i < 64; i++) {
      struct ip_v4 *entry = (void *)(f.binary + at);
      memset(entry, 0, offsetof(struct ip_v4, base_address));
      put16(&entry->hw_id, UMC_HWID);
      entry->instance_number = i % HWIP_MAX_INSTANCE;
      at += offsetof(struct ip_v4, base_address);
   }
   checksums(&f);
   assert(!amdgpu_discovery_binary_validate(f.binary, f.size));
   compare_original(f.binary, f.size);
   put16(&die->num_ips, 64);
   checksums(&f);
   assert(amdgpu_discovery_binary_validate(f.binary, f.size) == AMDGPU_DISCOVERY_BINARY_INVALID);
   mutations++;
   /* Five real v2 directory entries are sufficient for original initialization;
    * optional NPS directory access is now bounded instead of indexing past it. */
   f = make_fixture(2, 4, 0, 1, 0, 0);
   put16(&((struct binary_header_v2 *)f.binary)->num_tables, 5);
   checksums(&f);
   assert(!amdgpu_discovery_binary_validate(f.binary, f.size));
   assert(!amdgpu_discovery_binary_table(f.binary, f.size, NPS_INFO));
}

static void refused(struct fixture *f)
{
   uint8_t saved[sizeof(f->binary)];
   memcpy(saved, f->binary, sizeof(saved));
   assert(amdgpu_discovery_binary_validate(f->binary, f->size) != AMDGPU_DISCOVERY_BINARY_OK);
   assert(!memcmp(saved, f->binary, sizeof(saved)));
   mutations++;
}
static void malformed(void)
{
   const struct fixture good = make_fixture(2, 4, 1, 1, 3, 0);
   struct fixture f;
   for (size_t bytes = 0; bytes < good.size; bytes++) {
      uint8_t *shortened = malloc(bytes ? bytes : 1);
      assert(shortened);
      memcpy(shortened, good.binary, bytes);
      assert(amdgpu_discovery_binary_validate(shortened, bytes));
      free(shortened);
      mutations++;
   }
   for (unsigned which = 0; which < 22; which++) {
      f = good;
      struct binary_header *header = (void *)f.binary;
      struct ip_discovery_header *ip = (void *)(f.binary + f.offset[IP_DISCOVERY]);
      struct die_header *die = (void *)(f.binary + ip->die_info[0].die_offset);
      struct ip_v4 *first = (void *)((uint8_t *)die + sizeof(*die));
      switch (which) {
      case 0: put16(&header->binary_size, 9); break;
      case 1: put16(&header->binary_size, UINT16_MAX); break;
      case 2: put16(&header->version_major, 3); break;
      case 3: put16(&((struct binary_header_v2 *)header)->num_tables, 4); break;
      case 4: put16(&((struct binary_header_v2 *)header)->num_tables, UINT16_MAX); break;
      case 5: put16(&directory_entry(&f, IP_DISCOVERY)->offset, 0); break;
      case 6: put16(&directory_entry(&f, IP_DISCOVERY)->offset, f.size - 1); break;
      case 7: put16(&ip->size, 79); break;
      case 8: put16(&ip->size, UINT16_MAX); break;
      case 9: put16(&ip->num_dies, 17); break;
      case 10: put16(&ip->die_info[0].die_offset, 1); break;
      case 11: put16(&ip->die_info[0].die_offset, f.size - 1); break;
      case 12: put16(&die->die_id, 3); break;
      case 13: put16(&die->num_ips, UINT16_MAX); break;
      case 14: first->num_base_address = 255; break;
      case 15: first->instance_number = 32; break;
      case 16: put16(&ip->version, 2); break;
      case 17: put32(f.binary + f.offset[GC] + offsetof(struct gc_info_v1_0, gc_num_sa_per_se), 0); break;
      case 18: put32(f.binary + f.offset[GC] + offsetof(struct gpu_info_header, size), UINT32_MAX); break;
      case 19: put32(f.binary + f.offset[VCN_INFO] + offsetof(struct vcn_info_header, size_bytes), 12); break;
      case 20: put32(f.binary + f.offset[NPS_INFO] + offsetof(struct nps_info_v1_0, count), 13); break;
      case 21: put16(&directory_entry(&f, GC)->offset, f.offset[IP_DISCOVERY]); break;
      }
      checksums(&f); /* Uses only builder-owned original spans, never mutated offsets. */
      refused(&f);
   }
   assert(amdgpu_discovery_binary_validate(NULL, 0) == AMDGPU_DISCOVERY_BINARY_INVALID);
   /* Optional integrity failures retain original nonfatal/lazy policy. */
   f = good;
   put16(&directory_entry(&f, NPS_INFO)->checksum, 0);
   size_t start = offsetof(struct binary_header, binary_checksum) + 2;
   put16(f.binary + offsetof(struct binary_header, binary_checksum),
         donor_checksum(f.binary + start, f.size - start));
   assert(!amdgpu_discovery_binary_validate(f.binary, f.size));
   compare_original(f.binary, f.size);
   /* Deterministic field/byte mutation with repaired original checksums. */
   for (unsigned i = 0; i < 4096; i++) {
      f = good;
      size_t at = (i * 127u + 37u) % f.size;
      f.binary[at] ^= 1u << (i % 8);
      checksums(&f);
      uint8_t saved[sizeof(f.binary)];
      memcpy(saved, f.binary, sizeof(saved));
      enum amdgpu_discovery_binary_status result = amdgpu_discovery_binary_validate(f.binary, f.size);
      assert(!memcmp(saved, f.binary, sizeof(saved)));
      if (!result) {
         compare_original(f.binary, f.size);
         accepted_mutations++;
      }
      mutations++;
   }
}
int main(int argc, char **argv)
{
   for (unsigned binary = 0; binary <= 2; binary++) {
      for (unsigned layout = 1; layout <= 5; layout++) {
         for (unsigned gfx = 0; gfx < 8; gfx++) {
            for (unsigned variant = 0; variant < 2; variant++) {
               struct fixture f = make_fixture(binary, layout == 5 ? 4 : layout, layout == 5,
                                                gfx < 5 ? 1 : 2, gfx < 5 ? gfx : gfx - 5, variant);
               assert(!amdgpu_discovery_binary_validate(f.binary, f.size));
               compare_original(f.binary, f.size);
            }
         }
      }
   }
   harvest_lookup();
   boundary_layouts();
   malformed();
   for (int i = 1; i < argc; i++) {
      FILE *file = fopen(argv[i], "rb");
      assert(file);
      uint8_t bytes[UINT16_MAX + 1];
      size_t count = fread(bytes, 1, sizeof(bytes), file);
      assert(!ferror(file) && feof(file) && count < sizeof(bytes));
      assert(!fclose(file));
      assert(!amdgpu_discovery_binary_validate(bytes, count));
      compare_original(bytes, count);
      official++;
   }
   printf("AMD discovery: %u original consumer comparisons (%u external inputs), %u mutations/truncations (%u accepted); no hardware\n",
          comparisons, official, mutations, accepted_mutations);
   return 0;
}
