/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_PCI_MATCH_H
#define STELA_AMD_PCI_MATCH_H
#include <stdint.h>

/* Actual type-0 configuration values; class is base/subclass/prog-if (24 bits).
 * Header kind is checked by the Rust config owner before subsystem-ID reads.
 * This is a scalar query ABI, not an alternate PCI/device/resource owner. */
struct stela_amd_pci_identity {
   uint32_t vendor, device, subvendor, subdevice, class_code, revision;
};
struct stela_amd_pci_policy {
   uint32_t si_built, cik_built, radeon_built;
   int32_t si_support, cik_support, experimental, discovery, force_asic;
   /* Actual original platform policy, not readiness/capability assertions. */
   uint32_t memory_encrypted, firmware_drivers_only;
   int32_t modeset;
};
enum stela_amd_pci_status {
   STELA_AMD_PCI_OK,
   STELA_AMD_PCI_INVALID,
   STELA_AMD_PCI_NO_MATCH,
   STELA_AMD_PCI_UNSUPPORTED_ID,
   STELA_AMD_PCI_EXPERIMENTAL_DISABLED,
   STELA_AMD_PCI_RAVEN_ENCRYPTION,
   STELA_AMD_PCI_SUPPORT_DISABLED,
   STELA_AMD_PCI_FIRMWARE_ONLY,
   STELA_AMD_PCI_OVERRIDE_UNAVAILABLE,
};
enum stela_amd_ip_path {
   STELA_AMD_IP_SI_STATIC,
   STELA_AMD_IP_CIK_STATIC,
   STELA_AMD_IP_VI_STATIC,
   STELA_AMD_IP_SOC_STATIC,
   STELA_AMD_IP_DYNAMIC,
};
enum stela_amd_discovery_source {
   STELA_AMD_DISCOVERY_NOT_USED,
   STELA_AMD_DISCOVERY_HARDWARE,
   STELA_AMD_DISCOVERY_FILE,
};
struct stela_amd_pci_match {
   uint32_t row, original_flags, asic_type, initial_apu_flags;
   uint32_t ip_path, discovery_source;
   /* C static original filename; NULL for hardware/not-used. */
   const char *filename;
};

/* No allocation, config/MMIO access, publication or resource reservation.
 * Genuine PCI/config and platform/build options are owner prerequisites.
 * Normal retained table only: Linux dynamic IDs/driver_override and forced
 * ASIC debug emulation do not establish this route. Output unchanged on error.
 * A selected file is required by the dynamic path (optional inventory for the
 * original static path); this result never authorizes substituting hardware.
 */
int stela_amd_pci_match(const struct stela_amd_pci_identity *identity,
                      const struct stela_amd_pci_policy *policy,
                      struct stela_amd_pci_match *out);
#endif
