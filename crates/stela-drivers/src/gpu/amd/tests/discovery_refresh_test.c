/* SPDX-License-Identifier: MIT */
/* Actual retained refresh function compiled against a bounded CPU acquisition
 * model. This is not a production amdgpu_device, MMIO or reset provider. */
#ifdef NDEBUG
#error "discovery refresh checks require active assertions"
#endif
#include "../stela/discovery_binary.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t loff_t;
#define U32_MAX UINT32_MAX
#define __aligned(bytes) __attribute__((__aligned__(bytes)))
#define ALIGN(value, bytes) (((value) + (bytes) - 1) & ~((bytes) - 1))
#define mmRCC_CONFIG_MEMSIZE 0
#define DISCOVERY_TMR_OFFSET (64u * 1024u)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define RREG32(reg) ((void)(reg), adev->memory_mib)
union nps_info { struct nps_info_v1_0 v1; };
struct amdgpu_device {
   struct { uint8_t *bin; uint64_t offset; size_t size; bool reserve_tmr; } discovery;
   uint8_t vram[1024];
   uint64_t region;
   uint32_t memory_mib;
   bool skip, mm_fallback;
   unsigned reads, omit_read, change_read;
};
static bool amdgpu_device_skip_hw_access(struct amdgpu_device *adev) { return adev->skip; }
static void amdgpu_device_vram_access(struct amdgpu_device *adev, loff_t pos,
                                     void *bytes, size_t size, bool write)
{
   assert(!write && pos >= 0 && (uint64_t)pos >= adev->region);
   uint64_t offset = (uint64_t)pos - adev->region;
   assert(offset <= adev->discovery.size && size <= adev->discovery.size - offset);
   assert(offset <= sizeof(adev->vram) && size <= sizeof(adev->vram) - offset);
   unsigned read = ++adev->reads;
   assert(read <= 6);
   if (adev->mm_fallback && ((pos & 3) || (size & 3))) return;
   if (adev->mm_fallback) assert(!((uintptr_t)bytes & 3));
   if (read == adev->change_read) adev->vram[0] ^= 1;
   if (read != adev->omit_read) memcpy(bytes, adev->vram + offset, size);
}
static bool amdgpu_discovery_verify_checksum(struct amdgpu_device *adev,
                                             uint8_t *data, uint32_t bytes,
                                             uint16_t expected)
{
   (void)adev;
   assert(bytes <= sizeof(union nps_info));
   return amdgpu_discovery_calculate_checksum(data, bytes) == expected;
}
/* Generated from amdgpu_discovery.c by the Make dependency, without replacing
 * its function body or importing Linux allocation/IO implementations. */
#include "discovery-refresh.inc"

static unsigned accepted, refused, mutation_accept, mutation_refuse, transfer_cases;
static void put16(void *pointer, uint16_t value) { memcpy(pointer, &value, sizeof(value)); }
static void put32(void *pointer, uint32_t value) { memcpy(pointer, &value, sizeof(value)); }
static size_t directory_offset(unsigned version)
{
   return version == 2 ? offsetof(struct binary_header_v2, table_list) :
                         offsetof(struct binary_header, table_list);
}
static struct table_info *entry(struct amdgpu_device *device, unsigned version)
{
   return (void *)(device->vram + directory_offset(version) + NPS_INFO * sizeof(struct table_info));
}
static struct nps_info_v1_0 *nps(struct amdgpu_device *device)
{
   return (void *)(device->vram + 128);
}
static void checksum(struct amdgpu_device *device, unsigned version)
{
   put16(&entry(device,version)->checksum,
         amdgpu_discovery_calculate_checksum((uint8_t *)nps(device),nps(device)->header.size_bytes));
}
static struct amdgpu_device fixture(unsigned version, unsigned count, bool dynamic)
{
   struct amdgpu_device device = {0};
   device.memory_mib = 4;
   device.region = dynamic ? 0x240000 : (4u << 20) - DISCOVERY_TMR_OFFSET;
   device.discovery.offset = device.region;
   device.discovery.size = sizeof(device.vram);
   device.discovery.reserve_tmr = true;
   /* Only non-NULL initialization evidence; never dereferenced by refresh. */
   device.discovery.bin = (uint8_t *)(uintptr_t)1;
   struct binary_header_v2 *h = (void *)device.vram;
   put32(&h->binary_signature,BINARY_SIGNATURE);
   put16(&h->version_major,version);
   put16(&h->binary_size,sizeof(device.vram));
   if (version == 2) put16(&h->num_tables,TOTAL_TABLES);
   put16(&entry(&device,version)->offset,128);
   put16(&entry(&device,version)->size,sizeof(struct nps_info_v1_0));
   struct nps_info_v1_0 *data = nps(&device);
   data->header.table_id = NPS_INFO_TABLE_ID;
   data->header.version_major = 1;
   data->header.size_bytes = (uint32_t)(offsetof(struct nps_info_v1_0,instance_info) +
                                      count * sizeof(struct nps_instance_info_v1_0));
   data->nps_type = 3;
   data->count = count;
   for (unsigned i = 0; i < count; i++) {
      data->instance_info[i].base_address = (uint64_t)i << 24;
      data->instance_info[i].limit_address = ((uint64_t)i + 1) << 24;
   }
   checksum(&device,version);
   return device;
}
static void reject(struct amdgpu_device *device)
{
   union nps_info output, before;
   memset(&output,0xa5,sizeof(output)); before = output;
   assert(amdgpu_discovery_refresh_nps_info(device,&output) < 0);
   assert(!memcmp(&output,&before,sizeof(output)));
   refused++;
}
int main(void)
{
   for (unsigned version = 1; version <= 2; version++) {
      for (unsigned count = 0; count <= NPS_INFO_TABLE_MAX_NUM_INSTANCES; count++) {
         for (unsigned dynamic = 0; dynamic <= 1; dynamic++) {
            struct amdgpu_device device = fixture(version,count,dynamic);
            union nps_info output;
            memset(&output,0xa5,sizeof(output));
            assert(!amdgpu_discovery_refresh_nps_info(&device,&output));
            assert(device.reads == 6);
            assert(!memcmp(&output,nps(&device),nps(&device)->header.size_bytes));
            for (size_t i = nps(&device)->header.size_bytes; i < sizeof(output); i++)
               assert(!((uint8_t *)&output)[i]);
            accepted++;
         }
      }
      for (unsigned omitted = 1; omitted <= 6; omitted++) {
         struct amdgpu_device device = fixture(version,2,true);
         device.omit_read = omitted; reject(&device);
      }
      struct amdgpu_device device;
#define RESET() (device = fixture(version,2,true))
      for (unsigned bytes = 20; bytes <= sizeof(union nps_info); bytes++) {
         RESET(); device.mm_fallback = true;
         nps(&device)->count = 0;
         nps(&device)->header.size_bytes = bytes;
         checksum(&device,version);
         /* The padded transfer can exceed the declared binary span, but
          * must stay in the actually acquired region. Checksum remains exact. */
         put16(device.vram + offsetof(struct binary_header,binary_size),128 + bytes);
         union nps_info output;
         assert(!amdgpu_discovery_refresh_nps_info(&device,&output));
         assert(output.v1.header.size_bytes == bytes && !output.v1.count);
         for (size_t i = bytes; i < sizeof(output); i++) assert(!((uint8_t *)&output)[i]);
         transfer_cases++;
      }
      RESET(); device.skip = true; reject(&device); assert(!device.reads);
      RESET(); device.discovery.bin = NULL; reject(&device); assert(!device.reads);
      RESET(); device.discovery.reserve_tmr = false; reject(&device); assert(!device.reads);
      RESET(); device.memory_mib = 0; reject(&device); assert(!device.reads);
      RESET(); device.memory_mib = U32_MAX; reject(&device); assert(!device.reads);
      RESET(); device.discovery.offset = UINT64_MAX; reject(&device); assert(!device.reads);
      RESET(); device.discovery.offset = (4u << 20) - 8; reject(&device); assert(!device.reads);
      RESET(); device.discovery.size = 15; reject(&device); assert(!device.reads);
      RESET(); device.vram[0] ^= 1; reject(&device);
      RESET(); put16(device.vram + offsetof(struct binary_header,version_major),3); reject(&device);
      RESET(); put16(device.vram + offsetof(struct binary_header,binary_size),1025); reject(&device);
      RESET(); put16(device.vram + offsetof(struct binary_header,binary_size),16); reject(&device);
      RESET(); put16(&entry(&device,version)->offset,0); reject(&device);
      RESET(); put16(&entry(&device,version)->offset,8); reject(&device);
      RESET(); put16(&entry(&device,version)->offset,1020); reject(&device);
      RESET(); nps(&device)->header.table_id = 0; reject(&device);
      RESET(); nps(&device)->header.version_major = 2; reject(&device);
      const uint32_t invalid_sizes[] = {0, 12, 19, sizeof(union nps_info)+1, UINT32_MAX};
      for (size_t i = 0; i < sizeof(invalid_sizes)/sizeof(invalid_sizes[0]); i++) {
         RESET(); nps(&device)->header.size_bytes = invalid_sizes[i]; reject(&device);
      }
      RESET(); nps(&device)->count = UINT32_MAX; checksum(&device,version); reject(&device);
      RESET(); nps(&device)->count = 3; checksum(&device,version); reject(&device);
      RESET(); entry(&device,version)->checksum ^= 1; reject(&device);
      RESET(); device.change_read = 4; reject(&device);
      RESET(); device.change_read = 5; reject(&device);
      RESET(); nps(&device)->count = 0; nps(&device)->header.size_bytes = 21;
      checksum(&device,version); device.discovery.size = 149;
      put16(device.vram + offsetof(struct binary_header,binary_size),149); reject(&device);
      if (version == 2) {
         RESET(); put16(&((struct binary_header_v2 *)device.vram)->num_tables,NPS_INFO); reject(&device);
         RESET(); put16(&((struct binary_header_v2 *)device.vram)->num_tables,UINT16_MAX); reject(&device);
      }
#undef RESET
      uint32_t state = 0x4e505300u + version;
      for (unsigned i = 0; i < 4096; i++) {
         device = fixture(version,NPS_INFO_TABLE_MAX_NUM_INSTANCES,true);
         state = state * 1664525u + 1013904223u;
         size_t at = (state >> 16) % sizeof(device.vram);
         state = state * 1664525u + 1013904223u;
         device.vram[at] ^= (uint8_t)(1u << (state >> 29));
         union nps_info output, before;
         memset(&output,0xa5,sizeof(output)); before = output;
         int status = amdgpu_discovery_refresh_nps_info(&device,&output);
         if (status) {
            assert(!memcmp(&output,&before,sizeof(output)));
            mutation_refuse++;
         } else {
            assert(output.v1.header.table_id == NPS_INFO_TABLE_ID);
            assert(output.v1.header.version_major == 1);
            assert(output.v1.header.size_bytes <= sizeof(output));
            assert(output.v1.count <= NPS_INFO_TABLE_MAX_NUM_INSTANCES);
            mutation_accept++;
         }
      }
   }
   printf("AMD actual refresh: %u accepted, %u refused, %u MM transfer sizes, mutations %u accepted/%u refused; bounded CPU acquisition model, no hardware\n",
          accepted,refused,transfer_cases,mutation_accept,mutation_refuse);
}
