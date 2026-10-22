/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2018-2024 Advanced Micro Devices, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "discovery_binary.h"
#include "../amdgpu/amdgpu_ip_limits.h"
#include "../include/soc15_hw_ip.h"

_Static_assert(sizeof(struct binary_header) == 60, "original fixed directory ABI");
_Static_assert(sizeof(struct binary_header_v2) == 16, "original variable directory ABI");
_Static_assert(sizeof(struct ip_discovery_header) == 80, "original die directory ABI");
_Static_assert(offsetof(struct ip_v4, base_address) == 8, "original IP32 prefix ABI");
_Static_assert(offsetof(struct ip_v4, base_address_64) == 8, "original IP64 prefix ABI");

/* Original function body; const qualification only tightens the shared API.
 * Preserve its signed loop exactly; validated callers bound size to u16. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
uint16_t amdgpu_discovery_calculate_checksum(const uint8_t *data, uint32_t size)
{
	uint16_t checksum = 0;
	int i;

	for (i = 0; i < size; i++)
		checksum += data[i];

	return checksum;
}

#pragma GCC diagnostic pop

static uint16_t read16(const void *pointer)
{
   const uint8_t *p = pointer;
   return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static uint32_t read32(const void *pointer)
{
   const uint8_t *p = pointer;
   return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
          (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#define FIELD16(p, type, field) read16((p) + offsetof(struct type, field))
#define FIELD32(p, type, field) read32((p) + offsetof(struct type, field))

static int fits(size_t bytes, size_t offset, size_t count)
{
   return offset <= bytes && count <= bytes - offset;
}

/* Share directory geometry with bounded live refresh, without pretending a
 * stack prefix contains the variable directory's trailing entries. */
enum amdgpu_discovery_binary_status
amdgpu_discovery_binary_directory(const uint8_t *binary, size_t prefix_bytes,
                                  size_t available_bytes, uint16_t id,
                                  struct amdgpu_discovery_directory *output)
{
   if (!binary || !output)
      return AMDGPU_DISCOVERY_BINARY_INVALID;
   if (!fits(prefix_bytes, 0, offsetof(struct binary_header, table_list)))
      return AMDGPU_DISCOVERY_BINARY_BOUNDS;
   size_t size = FIELD16(binary, binary_header, binary_size);
   if (size > available_bytes)
      return AMDGPU_DISCOVERY_BINARY_BOUNDS;
   size_t offset, count;
   switch (FIELD16(binary, binary_header, version_major)) {
   case 0:
   case 1:
      offset = offsetof(struct binary_header, table_list);
      count = TOTAL_TABLES;
      break;
   case 2:
      if (!fits(prefix_bytes, 0, sizeof(struct binary_header_v2)))
         return AMDGPU_DISCOVERY_BINARY_BOUNDS;
      offset = offsetof(struct binary_header_v2, table_list);
      count = FIELD16(binary, binary_header_v2, num_tables);
      break;
   default:
      return AMDGPU_DISCOVERY_BINARY_VERSION;
   }
   if (id >= count || !fits(size, offset, count * sizeof(struct table_info)))
      return AMDGPU_DISCOVERY_BINARY_BOUNDS;
   *output = (struct amdgpu_discovery_directory){
      size, offset + count * sizeof(struct table_info), offset + id * sizeof(struct table_info)
   };
   return AMDGPU_DISCOVERY_BINARY_OK;
}

const struct table_info *
amdgpu_discovery_binary_table(const uint8_t *binary, size_t bytes, uint16_t id)
{
   struct amdgpu_discovery_directory directory;
   if (amdgpu_discovery_binary_directory(binary, bytes, bytes, id, &directory))
      return NULL;
   return (const struct table_info *)(binary + directory.entry_offset);
}

struct span {
   size_t offset, bytes;
};

static int disjoint(struct span a, struct span b)
{
   return a.offset + a.bytes <= b.offset || b.offset + b.bytes <= a.offset;
}

static enum amdgpu_discovery_binary_status
ip_spans(const uint8_t *binary, struct span table, unsigned *umc_count)
{
   const uint8_t *header = binary + table.offset;
   unsigned dies = FIELD16(header, ip_discovery_header, num_dies);
   const struct ip_discovery_header *original = (const void *)header;
   int wide = original->base_addr_64_bit;
   if (dies > sizeof(original->die_info) / sizeof(original->die_info[0]) ||
       (wide && FIELD16(header, ip_discovery_header, version) < 4))
      return AMDGPU_DISCOVERY_BINARY_INVALID;
   struct span previous[sizeof(original->die_info) / sizeof(original->die_info[0])];
   for (unsigned i = 0; i < dies; i++) {
      const uint8_t *entry = header + offsetof(struct ip_discovery_header, die_info) +
                             i * sizeof(struct die_info);
      size_t die = FIELD16(entry, die_info, die_offset);
      if (die < table.offset + sizeof(struct ip_discovery_header) ||
          !fits(table.offset + table.bytes, die, sizeof(struct die_header)))
         return AMDGPU_DISCOVERY_BINARY_BOUNDS;
      const uint8_t *dhdr = binary + die;
      if (FIELD16(dhdr, die_header, die_id) != i)
         return AMDGPU_DISCOVERY_BINARY_INVALID;
      unsigned ips = FIELD16(dhdr, die_header, num_ips);
      size_t position = die + sizeof(struct die_header);
      for (unsigned j = 0; j < ips; j++) {
         if (!fits(table.offset + table.bytes, position,
                   offsetof(struct ip_v4, base_address)))
            return AMDGPU_DISCOVERY_BINARY_BOUNDS;
         const struct ip_v4 *ip = (const void *)(binary + position);
         size_t bytes = offsetof(struct ip_v4, base_address) +
                        ip->num_base_address * (wide ? sizeof(uint64_t) : sizeof(uint32_t));
         if (!fits(table.offset + table.bytes, position, bytes))
            return AMDGPU_DISCOVERY_BINARY_BOUNDS;
         unsigned id = read16(&ip->hw_id);
         /* Original validate_ip skips unknown/out-of-array IPs. Preserve that
          * policy, but validate every entry's stride before the next walk. */
         if (ip->instance_number < HWIP_MAX_INSTANCE && id < HW_ID_MAX) {
            if ((id == GC_HWID || id == VCN_HWID || id == SDMA0_HWID ||
                 id == SDMA1_HWID || id == SDMA2_HWID || id == SDMA3_HWID) &&
                ip->instance_number >= 32)
               return AMDGPU_DISCOVERY_BINARY_INVALID;
            if (id == UMC_HWID)
               (*umc_count)++;
         }
         position += bytes;
      }
      previous[i] = (struct span){die, position - die};
      for (unsigned k = 0; k < i; k++) {
         if (!disjoint(previous[i], previous[k]))
            return AMDGPU_DISCOVERY_BINARY_INVALID;
      }
   }
   /* Original harvest mask computes (1ULL << node_inst_num) - 1. */
   return *umc_count < 64 ? AMDGPU_DISCOVERY_BINARY_OK : AMDGPU_DISCOVERY_BINARY_INVALID;
}

static enum amdgpu_discovery_binary_status
consumer_span(const uint8_t *data, size_t size, unsigned id)
{
   size_t minimum = 0;
   if (id == GC) {
      if (!fits(size, 0, sizeof(struct gpu_info_header)))
         return AMDGPU_DISCOVERY_BINARY_BOUNDS;
      unsigned major = FIELD16(data, gpu_info_header, version_major);
      unsigned minor = FIELD16(data, gpu_info_header, version_minor);
      if (major == 1) {
         minimum = minor >= 3 ? sizeof(struct gc_info_v1_3) :
                    minor == 2 ? sizeof(struct gc_info_v1_2) :
                    minor == 1 ? sizeof(struct gc_info_v1_1) : sizeof(struct gc_info_v1_0);
         if (!fits(size, 0, minimum))
            return AMDGPU_DISCOVERY_BINARY_BOUNDS;
         if (!FIELD32(data, gc_info_v1_0, gc_num_sa_per_se))
            return AMDGPU_DISCOVERY_BINARY_INVALID;
      } else if (major == 2) {
         minimum = minor == 1 ? sizeof(struct gc_info_v2_1) : sizeof(struct gc_info_v2_0);
         if (!fits(size, 0, minimum))
            return AMDGPU_DISCOVERY_BINARY_BOUNDS;
         if (!FIELD32(data, gc_info_v2_0, gc_num_sh_per_se))
            return AMDGPU_DISCOVERY_BINARY_INVALID;
      }
   } else if (id == MALL_INFO) {
      unsigned major = FIELD16(data, mall_info_header, version_major);
      minimum = major == 1 ? sizeof(struct mall_info_v1_0) :
                 major == 2 ? sizeof(struct mall_info_v2_0) : sizeof(struct mall_info_header);
   } else if (id == VCN_INFO) {
      minimum = FIELD16(data, vcn_info_header, version_major) == 1 ?
                 sizeof(struct vcn_info_v1_0) : sizeof(struct vcn_info_header);
   }
   return fits(size, 0, minimum) ? AMDGPU_DISCOVERY_BINARY_OK : AMDGPU_DISCOVERY_BINARY_BOUNDS;
}

enum amdgpu_discovery_binary_status
amdgpu_discovery_binary_validate(const uint8_t *binary, size_t bytes)
{
   if (!binary)
      return AMDGPU_DISCOVERY_BINARY_INVALID;
   if (!fits(bytes, 0, offsetof(struct binary_header, table_list)))
      return AMDGPU_DISCOVERY_BINARY_BOUNDS;
   if (FIELD32(binary, binary_header, binary_signature) != BINARY_SIGNATURE)
      return AMDGPU_DISCOVERY_BINARY_INVALID;
   unsigned version = FIELD16(binary, binary_header, version_major);
   if (version > 2)
      return AMDGPU_DISCOVERY_BINARY_VERSION;
   size_t size = FIELD16(binary, binary_header, binary_size);
   size_t checksum_start = offsetof(struct binary_header, binary_checksum) + sizeof(uint16_t);
   if (size < checksum_start || size > bytes)
      return AMDGPU_DISCOVERY_BINARY_BOUNDS;
   if (amdgpu_discovery_calculate_checksum(binary + checksum_start, size - checksum_start) !=
       FIELD16(binary, binary_header, binary_checksum))
      return AMDGPU_DISCOVERY_BINARY_CHECKSUM;
   if (!amdgpu_discovery_binary_table(binary, size, MALL_INFO))
      return AMDGPU_DISCOVERY_BINARY_BOUNDS;
   size_t directory = version == 2 ? offsetof(struct binary_header_v2, table_list) +
                      FIELD16(binary, binary_header_v2, num_tables) * sizeof(struct table_info) :
                      sizeof(struct binary_header);
   struct span tables[TOTAL_TABLES] = {{0}};
   unsigned umc_count = 0;
   for (unsigned id = IP_DISCOVERY; id < TOTAL_TABLES; id++) {
      const struct table_info *info = amdgpu_discovery_binary_table(binary, size, id);
      if (!info) /* Optional NPS may be absent from a v2 counted directory. */
         continue;
      size_t offset = read16(&info->offset);
      if (!offset) {
         if (id == IP_DISCOVERY)
            return AMDGPU_DISCOVERY_BINARY_INVALID;
         continue;
      }
      if (offset < directory || !fits(size, offset, sizeof(struct gpu_info_header)))
         return AMDGPU_DISCOVERY_BINARY_BOUNDS;
      const uint8_t *data = binary + offset;
      size_t length;
      uint32_t expected, actual;
      int checksum = 1;
      switch (id) {
      case IP_DISCOVERY:
         actual = FIELD32(data, ip_discovery_header, signature);
         expected = DISCOVERY_TABLE_SIGNATURE;
         length = FIELD16(data, ip_discovery_header, size);
         break;
      case GC:
         actual = FIELD32(data, gpu_info_header, table_id);
         expected = GC_TABLE_ID;
         length = FIELD32(data, gpu_info_header, size);
         break;
      case HARVEST_INFO:
         actual = FIELD32(data, harvest_info_header, signature);
         expected = HARVEST_TABLE_SIGNATURE;
         length = sizeof(struct harvest_table);
         break;
      case VCN_INFO:
         actual = FIELD32(data, vcn_info_header, table_id);
         expected = VCN_INFO_TABLE_ID;
         length = FIELD32(data, vcn_info_header, size_bytes);
         break;
      case MALL_INFO:
         /* Original policy deliberately does not check MALL integrity. */
         actual = expected = 0;
         length = FIELD32(data, mall_info_header, size_bytes);
         checksum = 0;
         break;
      default: /* Original NPS integrity check is lazy and nonfatal. */
         actual = FIELD32(data, nps_info_header, table_id);
         expected = actual;
         length = actual == NPS_INFO_TABLE_ID ? FIELD32(data, nps_info_header, size_bytes) :
                  sizeof(struct nps_info_header);
         checksum = 0;
         break;
      }
      if (!fits(size, offset, length) || length < sizeof(struct gpu_info_header))
         return AMDGPU_DISCOVERY_BINARY_BOUNDS;
      if (checksum && (actual != expected))
         return AMDGPU_DISCOVERY_BINARY_INVALID;
      if (checksum && amdgpu_discovery_calculate_checksum(data, length) != read16(&info->checksum))
         return AMDGPU_DISCOVERY_BINARY_CHECKSUM;
      if (id == IP_DISCOVERY) {
         if (length < sizeof(struct ip_discovery_header))
            return AMDGPU_DISCOVERY_BINARY_BOUNDS;
         enum amdgpu_discovery_binary_status status = ip_spans(binary, (struct span){offset, length},
                                                            &umc_count);
         if (status)
            return status;
      } else if (id == NPS_INFO && actual == NPS_INFO_TABLE_ID &&
                 amdgpu_discovery_calculate_checksum(data, length) == read16(&info->checksum) &&
                 FIELD16(data, nps_info_header, version_major) == 1) {
         if (length < offsetof(struct nps_info_v1_0, instance_info) ||
             FIELD32(data, nps_info_v1_0, count) > NPS_INFO_TABLE_MAX_NUM_INSTANCES ||
             !fits(length, offsetof(struct nps_info_v1_0, instance_info),
                   FIELD32(data, nps_info_v1_0, count) * sizeof(struct nps_instance_info_v1_0)))
            return AMDGPU_DISCOVERY_BINARY_BOUNDS;
      } else {
         enum amdgpu_discovery_binary_status status = consumer_span(data, length, id);
         if (status)
            return status;
         if (id == MALL_INFO && FIELD16(data, mall_info_header, version_major) == 1 && umc_count > 32)
            return AMDGPU_DISCOVERY_BINARY_INVALID;
      }
      tables[id] = (struct span){offset, length};
      for (unsigned previous = 0; previous < id; previous++) {
         if (tables[previous].bytes && !disjoint(tables[id], tables[previous]))
            return AMDGPU_DISCOVERY_BINARY_INVALID;
      }
   }
   return AMDGPU_DISCOVERY_BINARY_OK;
}
