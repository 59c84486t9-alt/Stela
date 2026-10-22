/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_NATIVE_BAR_H
#define STELA_AMD_NATIVE_BAR_H
#include <stdint.h>

enum stela_amd_bar_status {
   STELA_AMD_BAR_OK,
   STELA_AMD_BAR_INVALID,
   STELA_AMD_BAR_UNREPRESENTABLE,
};

struct stela_amd_bar_layout {
   uint32_t register_bar;
   uint32_t kernel_doorbells; /* DWORDs of the kernel's doorbell range. */
   uint64_t kernel_doorbell_bytes;
};

/* asic_type is an enum amd_asic_type. Facts come from the matched PCI
 * function and the initialized doorbell-index owner, never from Mesa's family
 * or display inventory. SI passes zero doorbell facts; CIK and later pass
 * their doorbell BAR's size and the highest kernel doorbell assignment.
 * Outputs are unchanged on error. Neither call reserves, maps or writes
 * anything. */
enum stela_amd_bar_status
stela_amd_native_register_bar(uint32_t asic_type, uint32_t *bar);

enum stela_amd_bar_status
stela_amd_native_bar_layout(uint32_t asic_type, uint64_t doorbell_bar_bytes,
                            uint32_t max_assignment, uint64_t page_bytes,
                            struct stela_amd_bar_layout *layout);
#endif
