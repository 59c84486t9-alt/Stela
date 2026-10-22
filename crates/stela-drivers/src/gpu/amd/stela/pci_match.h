/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_PCI_MATCH_H
#define STELA_AMD_PCI_MATCH_H
#include <stdint.h>

/* A type-0 function's configuration identity; class is the 24-bit class
 * code. */
struct stela_amd_pci_identity {
   uint32_t vendor, device, subvendor, subdevice, class_code, revision;
};
/* amdgpu's module parameters that decide matching and discovery. */
struct stela_amd_pci_policy {
   int32_t exp_hw_support, discovery, force_asic_type;
};
/* How Linux brings up the matched ASIC's IP blocks. */
enum stela_amd_ip_path {
   STELA_AMD_IP_VI_STATIC,
   STELA_AMD_IP_SOC_STATIC,
   STELA_AMD_IP_DYNAMIC,
};
struct stela_amd_pci_match {
   uint32_t row, flags, asic_type, apu_flags, ip_path;
};

/* Run amdgpu's probe admission for a function: its device table, unsupported
 * IDs, ASIC quirks and support policy. Returns 0, or the negative status the
 * probe returns; out is unchanged on failure. policy sets amdgpu's module
 * parameters, which, as in Linux, apply to every device and every later
 * call. */
int stela_amd_pci_match(const struct stela_amd_pci_identity *identity,
                        const struct stela_amd_pci_policy *policy,
                        struct stela_amd_pci_match *out);
#endif
