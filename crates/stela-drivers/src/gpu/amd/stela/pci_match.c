/* SPDX-License-Identifier: GPL-2.0-only */
#include "pci_match.h"
#include "../amdgpu/amdgpu_pci_match_core.h"
#include "../amdgpu/amdgpu_apu_flags_core.h"
#include "../amdgpu/amdgpu_discovery_source_core.h"
#include <stddef.h>

_Static_assert(sizeof(struct stela_amd_pci_identity) == 24, "PCI identity ABI");
_Static_assert(sizeof(struct stela_amd_pci_policy) == 44, "PCI policy ABI");
_Static_assert(sizeof(struct stela_amd_pci_match) == 32, "PCI match ABI");
_Static_assert(offsetof(struct stela_amd_pci_match, filename) == 24, "PCI filename ABI");

/* Exact Linux 8d3ae592 drivers/pci/pci.h:pci_match_one_device predicate,
 * binding only original dev fields to this synchronous scalar query. */
static const struct pci_device_id *
match_one(const struct pci_device_id *id, const struct stela_amd_pci_identity *dev)
{
   if ((id->vendor == (uint32_t)PCI_ANY_ID || id->vendor == dev->vendor) &&
       (id->device == (uint32_t)PCI_ANY_ID || id->device == dev->device) &&
       (id->subvendor == (uint32_t)PCI_ANY_ID || id->subvendor == dev->subvendor) &&
       (id->subdevice == (uint32_t)PCI_ANY_ID || id->subdevice == dev->subdevice) &&
       !((id->class ^ dev->class_code) & id->class_mask))
      return id;
   return NULL;
}

int
stela_amd_pci_match(const struct stela_amd_pci_identity *identity,
                   const struct stela_amd_pci_policy *policy,
                   struct stela_amd_pci_match *out)
{
   if (!identity || !policy || !out || identity->vendor > UINT16_MAX ||
       identity->device > UINT16_MAX || identity->subvendor > UINT16_MAX ||
       identity->subdevice > UINT16_MAX || identity->class_code > 0xffffff ||
       identity->revision > UINT8_MAX || policy->si_built > 1 ||
       policy->cik_built > 1 || policy->radeon_built > 1 ||
       policy->memory_encrypted > 1 || policy->firmware_drivers_only > 1)
      return STELA_AMD_PCI_INVALID;

   const struct pci_device_id *id = pciidlist;
   /* Original pci_match_id first-match/sentinel algorithm. */
   while (id->vendor || id->subvendor || id->class_mask) {
      /* Original pci_match_device normal static-table route also skips
       * override_only rows; dynamic IDs and driver_override are not this API. */
      if (match_one(id, identity) && !id->override_only)
         break;
      id++;
   }
   if (!(id->vendor || id->subvendor || id->class_mask))
      return STELA_AMD_PCI_NO_MATCH;

   if ((identity->class_code >> 8) == PCI_CLASS_DISPLAY_VGA ||
       (identity->class_code >> 8) == PCI_CLASS_DISPLAY_OTHER) {
      if (policy->firmware_drivers_only && policy->modeset == -1)
         return STELA_AMD_PCI_FIRMWARE_ONLY;
   }
   for (size_t i = 0; i < sizeof(amdgpu_unsupported_pciidlist) /
                                 sizeof(amdgpu_unsupported_pciidlist[0]); i++)
      if (amdgpu_unsupported_pciidlist[i] == identity->device)
         return STELA_AMD_PCI_UNSUPPORTED_ID;
   if (id->driver_data > UINT32_MAX)
      return STELA_AMD_PCI_INVALID;
   unsigned long flags = id->driver_data;
   if (!amdgpu_pci_experimental_allowed(flags, policy->experimental))
      return STELA_AMD_PCI_EXPERIMENTAL_DISABLED;
   flags = amdgpu_pci_fix_asic_type(identity->device, identity->revision, flags);
   if (policy->memory_encrypted && (flags & AMD_ASIC_MASK) == CHIP_RAVEN)
      return STELA_AMD_PCI_RAVEN_ENCRYPTION;
   const enum amd_asic_type asic = flags & AMD_ASIC_MASK;
   struct amdgpu_pci_support_policy support;
   if (amdgpu_pci_support_policy(asic, policy->si_built, policy->cik_built,
                                policy->si_support, policy->cik_support, &support) &&
       !amdgpu_pci_support_allowed(&support, policy->radeon_built))
      return STELA_AMD_PCI_SUPPORT_DISABLED;
   /* Original nonnegative in-range override is a separate debug path, not a
    * native physical ASIC assertion. Invalid values are ignored originally. */
   if (policy->force_asic >= 0 && policy->force_asic < CHIP_LAST)
      return STELA_AMD_PCI_OVERRIDE_UNAVAILABLE;

   struct stela_amd_pci_match result = {
      .row = (uint32_t)(id - pciidlist), .original_flags = flags, .asic_type = asic,
      .initial_apu_flags = amdgpu_initial_apu_flags(flags, asic, identity->device, 0),
      .discovery_source = STELA_AMD_DISCOVERY_NOT_USED,
   };
   switch (amdgpu_initial_ip_path(asic)) {
   case AMDGPU_INITIAL_IP_SI: result.ip_path = STELA_AMD_IP_SI_STATIC; break;
   case AMDGPU_INITIAL_IP_CIK: result.ip_path = STELA_AMD_IP_CIK_STATIC; break;
   case AMDGPU_INITIAL_IP_VI: result.ip_path = STELA_AMD_IP_VI_STATIC; break;
   case AMDGPU_INITIAL_IP_DISCOVERY:
      result.ip_path = amdgpu_discovery_static_asic(asic) != CHIP_LAST &&
                       !(asic == CHIP_CYAN_SKILLFISH &&
                         amdgpu_discovery_cyan_skillfish2(result.initial_apu_flags))
                          ? STELA_AMD_IP_SOC_STATIC : STELA_AMD_IP_DYNAMIC;
      /* Original static CyanSkillfish never calls discovery_init, including
       * option2. Other SOC-static arms acquire optional inventory only. */
      if (asic == CHIP_CYAN_SKILLFISH && result.ip_path == STELA_AMD_IP_SOC_STATIC)
         break;
      result.filename = amdgpu_discovery_fw_name(asic, result.initial_apu_flags,
                                                policy->discovery);
      result.discovery_source = result.filename ? STELA_AMD_DISCOVERY_FILE
                                                : STELA_AMD_DISCOVERY_HARDWARE;
      break;
   }
   *out = result;
   return STELA_AMD_PCI_OK;
}
