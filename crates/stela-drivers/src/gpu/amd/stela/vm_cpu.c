/* SPDX-License-Identifier: MIT */
#include "vm_cpu.h"
#include "../amdgpu/amdgpu_vm_cpu_entries.h"

struct entry_context {
   const struct stela_amd_vm_cpu_update *update;
   const struct stela_amd_vm_cpu_ops *ops;
   void *owner;
   void *mapping;
};

static uint64_t
map_gart(void *context, uint64_t address)
{
   const struct entry_context *entry = context;
   const struct stela_amd_vm_cpu_update *update = entry->update;
   return amdgpu_vm_cpu_gart_address(update->pages_addr[address >> update->cpu_page_shift],
                                     address, update->cpu_page_shift);
}

static void
override_flags(void *context, uint64_t address, uint64_t *flags)
{
   const struct entry_context *entry = context;
   entry->ops->override_flags(entry->owner, address, flags);
}

static void
set_pte_pde(void *context, unsigned int index, uint64_t address, uint64_t flags)
{
   const struct entry_context *entry = context;
   entry->ops->set_pte_pde(entry->owner, entry->mapping, index, address, flags);
}

enum stela_amd_vm_cpu_status
stela_amd_vm_cpu_write(const struct stela_amd_vm_cpu_update *update,
                       const struct stela_amd_vm_cpu_ops *ops, void *context,
                       uint32_t *written)
{
   if (!written)
      return STELA_AMD_VM_CPU_INVALID;
   *written = 0;
   if (!update || !ops || !ops->map_table || !ops->override_flags || !ops->set_pte_pde ||
       (update->table_offset & 7) || update->table_offset > update->table_bytes ||
       update->count > (update->table_bytes - update->table_offset) / sizeof(uint64_t))
      return STELA_AMD_VM_CPU_INVALID;
   if (!update->count)
      return STELA_AMD_VM_CPU_OK;
   if (update->increment &&
       update->count - 1 > (UINT64_MAX - update->address) / update->increment)
      return STELA_AMD_VM_CPU_INVALID;
   if (update->pages_addr) {
      if (update->cpu_page_shift < 12 || update->cpu_page_shift > 52 ||
          update->num_pages > SIZE_MAX / sizeof(uint64_t))
         return STELA_AMD_VM_CPU_INVALID;
      const uint64_t last = update->address + (uint64_t)(update->count - 1) * update->increment;
      if ((last >> update->cpu_page_shift) >= update->num_pages)
         return STELA_AMD_VM_CPU_INVALID;
   } else if (update->num_pages) {
      return STELA_AMD_VM_CPU_INVALID;
   }
   struct entry_context entry = {.update = update, .ops = ops, .owner = context};
   entry.mapping = ops->map_table(context, update->table_offset,
                                  (uint64_t)update->count * sizeof(uint64_t));
   if (!entry.mapping)
      return STELA_AMD_VM_CPU_MAPPING_UNAVAILABLE;
   static const struct amdgpu_vm_cpu_entry_ops entry_ops = {
      .map_gart = map_gart,
      .override_flags = override_flags,
      .set_pte_pde = set_pte_pde,
   };
   amdgpu_vm_cpu_write_entries(&entry, &entry_ops, update->pages_addr != NULL,
                               update->override_pte, update->address, update->count,
                               update->increment, update->flags);
   *written = update->count;
   return STELA_AMD_VM_CPU_OK;
}
