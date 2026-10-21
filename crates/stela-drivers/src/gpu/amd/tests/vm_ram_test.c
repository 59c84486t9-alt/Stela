/* SPDX-License-Identifier: MIT */
/* Test-only retained GMC value encoding and C/Rust CPUVM layout checks.
 * This does not initialize a GMC or establish hardware-safe RAM policy. */
#include "../amdgpu/amdgpu_gmc_pte.h"
#include "../stela/vm_cpu.h"
#include <stddef.h>

_Static_assert(sizeof(struct stela_amd_vm_cpu_update) == 64, "CPUVM update size");
_Static_assert(offsetof(struct stela_amd_vm_cpu_update, count) == 32, "count offset");
_Static_assert(offsetof(struct stela_amd_vm_cpu_update, pages_addr) == 40, "pages offset");
_Static_assert(offsetof(struct stela_amd_vm_cpu_update, override_pte) == 60, "override offset");
_Static_assert(sizeof(struct stela_amd_vm_cpu_ops) == 3 * sizeof(void *), "CPUVM ops size");

uint64_t stela_amd_test_gmc_pte_value(uint64_t address, uint64_t mask, uint64_t flags)
{
   return amdgpu_gmc_pte_value(address, mask, flags);
}
