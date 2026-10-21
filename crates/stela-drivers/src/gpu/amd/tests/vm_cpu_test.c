/* SPDX-License-Identifier: MIT */
/* CPU-only fixtures: no BO, DMA map, GMC policy or hardware is initialized. */
#include "../stela/vm_cpu.h"
#include "../amdgpu/amdgpu_gmc_pte.h"
#include "../amdgpu/amdgpu_vm_cpu_entries.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct event { unsigned kind, index; uint64_t address, flags; };
struct model {
   uint64_t table[64];
   uint64_t mask;
   uint64_t map_offset, map_bytes;
   unsigned maps, count;
   bool map_fails;
   struct event events[128];
};

static void record(struct model *model, unsigned kind, unsigned index,
                   uint64_t address, uint64_t flags)
{
   assert(model->count < 128);
   model->events[model->count++] = (struct event){kind, index, address, flags};
}

static void *map_table(void *context, uint64_t offset, uint64_t bytes)
{
   struct model *model = context;
   model->maps++;
   model->map_offset = offset;
   model->map_bytes = bytes;
   return model->map_fails ? NULL : (unsigned char *)model->table + offset;
}

static void override_flags(void *context, uint64_t address, uint64_t *flags)
{
   struct model *model = context;
   record(model, 1, 0, address, *flags);
   /* Deliberately address-dependent fixture policy, not a hardware flag model.
    * Detects repeated/cumulative overrides or use of unmapped addresses. */
   *flags ^= ((address >> 12) & 3) << 4;
}

static void set_pte_pde(void *context, void *mapping, uint32_t index,
                        uint64_t address, uint64_t flags)
{
   struct model *model = context;
   record(model, 2, index, address, flags);
   ((uint64_t *)mapping)[index] = amdgpu_gmc_pte_value(address, model->mask, flags);
}

static const struct stela_amd_vm_cpu_ops ops = {map_table, override_flags, set_pte_pde};

/* Functions consumed by the immutable pre-extraction loop below. Their context
 * is this CPU model; these are never linked as platform service replacements. */
typedef uint64_t u64;
struct reference_params {
   const uint64_t *pages_addr;
   bool override_pte;
   struct model *adev;
   struct model *vm;
};
static unsigned reference_page_shift;
static uint64_t amdgpu_vm_map_gart(const uint64_t *pages_addr, uint64_t addr)
{
   uint64_t result = pages_addr[addr >> reference_page_shift];
   result |= addr & ((UINT64_C(1) << reference_page_shift) - 1);
   result &= UINT64_C(0xFFFFFFFFFFFFF000);
   return result;
}
static void amdgpu_gmc_override_vm_pte_flags(struct model *adev, struct model *vm,
                                            uint64_t addr, uint64_t *flags)
{
   assert(adev == vm);
   override_flags(adev, addr, flags);
}
static void amdgpu_gmc_set_pte_pde(struct model *adev, void *pe, unsigned i,
                                  uint64_t value, uint64_t flags)
{
   set_pte_pde(adev, pe, i, value, flags);
}

#include "vm_cpu_reference.h"

static struct model model(void)
{
   struct model result = {.mask = UINT64_C(0x0000FFFFFFFFF000)};
   for (unsigned i = 0; i < 64; i++)
      result.table[i] = UINT64_C(0xa5a5a5a5a5a5a5a5);
   return result;
}

static void test_fixed(void)
{
   struct model actual = model();
   struct stela_amd_vm_cpu_update request = {
      .table_bytes = sizeof(actual.table), .table_offset = 8,
      .address = 0x201000, .flags = 3, .count = 4, .increment = 0x1000,
      .override_pte = true,
   };
   uint32_t written = 99;
   assert(stela_amd_vm_cpu_write(&request, &ops, &actual, &written) == STELA_AMD_VM_CPU_OK);
   assert(written == 4 && actual.maps == 1 && actual.count == 5);
   assert(actual.map_offset == 8 && actual.map_bytes == 32);
   for (unsigned i = 0; i < 4; i++)
      assert(actual.table[i + 1] == 0x201013 + i * 0x1000);
   assert(actual.table[0] == UINT64_C(0xa5a5a5a5a5a5a5a5));
   assert(actual.table[5] == actual.table[0]);

   actual = model();
   const uint64_t pages[] = {0x100000, 0x300000};
   request.pages_addr = pages;
   request.num_pages = 2;
   request.cpu_page_shift = 14;
   request.address = 0x3000;
   request.count = 3;
   assert(stela_amd_vm_cpu_write(&request, &ops, &actual, &written) == STELA_AMD_VM_CPU_OK);
   assert(written == 3 && actual.count == 6);
   assert(actual.table[1] == 0x103033 && actual.table[2] == 0x300003 && actual.table[3] == 0x301013);
   for (unsigned i = 0; i < 3; i++) {
      assert(actual.events[i * 2].kind == 1 && actual.events[i * 2 + 1].kind == 2);
      assert(actual.events[i * 2].flags == 3);
   }
   /* Actual generation masks from GMC6/8, GMC9/10/11 and GMC12 initialization. */
   assert(amdgpu_gmc_pte_value(UINT64_C(0xabcdef123456789a), UINT64_C(0x000000FFFFFFF000), 3) == UINT64_C(0x1234567003));
   assert(amdgpu_gmc_pte_value(UINT64_C(0xabcdef123456789a), UINT64_C(0x0000FFFFFFFFF000), 3) == UINT64_C(0xef1234567003));
   assert(amdgpu_gmc_pte_value(UINT64_C(0xabcdef123456789a), UINT64_C(0x000FFFFFFFFFF000), 3) == UINT64_C(0xdef1234567003));
}

static void rejected(struct stela_amd_vm_cpu_update request)
{
   struct model actual = model(), before = actual;
   uint32_t written = 99;
   assert(stela_amd_vm_cpu_write(&request, &ops, &actual, &written) == STELA_AMD_VM_CPU_INVALID);
   assert(written == 0 && !memcmp(&actual, &before, sizeof(actual)));
}

static void test_errors(void)
{
   struct stela_amd_vm_cpu_update request = {
      .table_bytes = 64, .address = 0x1000, .count = 2, .increment = 4096,
   };
   struct stela_amd_vm_cpu_update bad = request;
   bad.table_offset = 1; rejected(bad);
   bad = request; bad.table_offset = 72; rejected(bad);
   bad = request; bad.count = 9; rejected(bad);
   bad = request; bad.address = UINT64_MAX - 1024; rejected(bad);
   uint64_t pages[] = {0x100000, 0x200000};
   bad = request; bad.pages_addr = pages; bad.cpu_page_shift = 12; bad.num_pages = 2; rejected(bad);
   bad = request; bad.pages_addr = pages; bad.cpu_page_shift = 11; bad.num_pages = 2; rejected(bad);
   bad.cpu_page_shift = 64; rejected(bad);
   bad.cpu_page_shift = 12; bad.num_pages = UINT64_MAX; rejected(bad);
   bad = request; bad.num_pages = 1; rejected(bad);
   struct model actual = model(), before = actual;
   struct stela_amd_vm_cpu_ops missing = ops;
   missing.override_flags = NULL;
   uint32_t written = 99;
   assert(stela_amd_vm_cpu_write(&request, &missing, &actual, &written) == STELA_AMD_VM_CPU_INVALID);
   assert(written == 0 && !memcmp(&actual, &before, sizeof(actual)));
   assert(stela_amd_vm_cpu_write(NULL, &ops, &actual, &written) == STELA_AMD_VM_CPU_INVALID);
   assert(stela_amd_vm_cpu_write(&request, &ops, &actual, NULL) == STELA_AMD_VM_CPU_INVALID);
   actual.map_fails = true;
   assert(stela_amd_vm_cpu_write(&request, &ops, &actual, &written) == STELA_AMD_VM_CPU_MAPPING_UNAVAILABLE);
   assert(written == 0 && actual.maps == 1 && !actual.count);
   assert(!memcmp(actual.table, before.table, sizeof(actual.table)));
   missing = ops;
   missing.map_table = NULL;
   assert(stela_amd_vm_cpu_write(&request, &missing, &actual, &written) == STELA_AMD_VM_CPU_INVALID);
   missing = ops;
   missing.set_pte_pde = NULL;
   assert(stela_amd_vm_cpu_write(&request, &missing, &actual, &written) == STELA_AMD_VM_CPU_INVALID);
   actual = model();
   request.count = 0;

   assert(stela_amd_vm_cpu_write(&request, &ops, &actual, &written) == STELA_AMD_VM_CPU_OK);
   assert(written == 0 && !actual.maps && !actual.count);
   /* Preserve the original Linux core's zero-count override semantics too;
    * the public bounded native adapter explicitly defines an empty operation. */
   const struct amdgpu_vm_cpu_entry_ops zero_ops = {.override_flags = override_flags};
   amdgpu_vm_cpu_write_entries(&actual, &zero_ops, false, true, 0x1000, 0, 4096, 3);
   assert(actual.count == 1 && actual.events[0].kind == 1);

}

static void test_original_loop(void)
{
   unsigned runs = 0;
   const uint64_t pages[] = {0x400000, 0x900000, 0x1200000, 0x1800000};
   for (unsigned shift = 12; shift <= 16; shift += 2) {
      for (unsigned mapped = 0; mapped < 2; mapped++) {
         for (unsigned override = 0; override < 2; override++) {
            for (unsigned count = 1; count <= 16; count++) {
               for (unsigned increment = 0; increment <= 4096; increment += 2048) {
                  struct model actual = model(), expected = model();
                  struct stela_amd_vm_cpu_update request = {
                     .table_bytes = sizeof(actual.table), .table_offset = 16,
                     .address = mapped ? 0 : 0x100000,
                     .flags = 3, .count = count, .increment = increment,
                     .pages_addr = mapped ? pages : NULL,
                     .num_pages = mapped ? 4 : 0, .cpu_page_shift = shift,
                     .override_pte = override,
                  };
                  if (mapped && (uint64_t)(count - 1) * increment >= (UINT64_C(4) << shift))
                     continue;
                  uint32_t written;
                  assert(stela_amd_vm_cpu_write(&request, &ops, &actual, &written) == STELA_AMD_VM_CPU_OK);
                  reference_page_shift = shift;
                  struct reference_params params = {request.pages_addr, override, &expected, &expected};
                  reference_cpu_update(&params, (uintptr_t)&expected.table[2], request.address,
                                        count, increment, request.flags);
                  assert(written == count && actual.count == expected.count);
                  assert(!memcmp(actual.table, expected.table, sizeof(actual.table)));
                  assert(!memcmp(actual.events, expected.events, actual.count * sizeof(actual.events[0])));
                  runs++;
               }
            }
         }
      }
   }
   printf("AMD CPU VM: %u pre-extraction loop comparisons passed; physical mappings unverified\n", runs);
}

int main(void)
{
   test_fixed();
   test_errors();
   test_original_loop();
   return 0;
}
