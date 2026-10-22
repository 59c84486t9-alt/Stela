/* SPDX-License-Identifier: MIT */
/* The unchanged amdgpu_drv.c's probe admission in Stela's environment; CPU
 * only. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../stela/pci_match.c"

static const struct stela_amd_pci_policy defaults = {.discovery = -1, .force_asic_type = -1};

static int admit(uint32_t device, uint32_t class_code, uint32_t revision,
                 const struct stela_amd_pci_policy *policy, struct stela_amd_pci_match *out)
{
   const struct stela_amd_pci_identity identity = {
      .vendor = 0x1002, .device = device, .subvendor = 0x1002, .subdevice = 0x0e3a,
      .class_code = class_code, .revision = revision,
   };
   return stela_amd_pci_match(&identity, policy, out);
}
static struct stela_amd_pci_match admitted(uint32_t device, uint32_t class_code,
                                           uint32_t revision)
{
   struct stela_amd_pci_match out;
   assert(!admit(device, class_code, revision, &defaults, &out));
   return out;
}
static int refused(uint32_t device, uint32_t class_code, uint32_t revision,
                   const struct stela_amd_pci_policy *policy)
{
   struct stela_amd_pci_match out, saved;
   memset(&out, 0xa5, sizeof(out));
   saved = out;
   const int status = admit(device, class_code, revision, policy, &out);
   assert(status < 0 && !memcmp(&out, &saved, sizeof(out)));
   return status;
}

int main(void)
{
   /* A listed Navi 10 and unlisted parts of each class Linux accepts; the
    * discovered ASICs take the dynamic path. */
   struct stela_amd_pci_match navi = admitted(0x731f, 0x030000, 0xc1);
   assert(pciidlist[navi.row].device == 0x731f && navi.asic_type == CHIP_NAVI10);
   assert(navi.ip_path == STELA_AMD_IP_DYNAMIC && !navi.apu_flags);
   const uint32_t classes[] = {0x030000, 0x038000, 0x120000};
   for (unsigned i = 0; i < 3; i++) {
      struct stela_amd_pci_match match = admitted(0x7550, classes[i], 0);
      assert(match.asic_type == CHIP_IP_DISCOVERY && match.ip_path == STELA_AMD_IP_DYNAMIC);
      assert(pciidlist[match.row].class == (classes[i] & 0xffff00));
   }

   /* Fixed tables, the Polaris revision quirk and APU flags. */
   assert(admitted(0x67df, 0x030000, 0xe7).ip_path == STELA_AMD_IP_VI_STATIC);
   assert(admitted(0x67ff, 0x030000, 0xcf).asic_type == CHIP_POLARIS11);
   assert(admitted(0x67ff, 0x030000, 0xe3).asic_type == CHIP_POLARIS10);
   struct stela_amd_pci_match vega = admitted(0x6860, 0x030000, 0);
   assert(vega.asic_type == CHIP_VEGA10 && vega.ip_path == STELA_AMD_IP_SOC_STATIC);
   struct stela_amd_pci_match picasso = admitted(0x15d8, 0x030000, 0xc1);
   assert(picasso.flags & AMD_IS_APU && picasso.apu_flags == AMD_APU_IS_PICASSO);
   assert(picasso.ip_path == STELA_AMD_IP_SOC_STATIC);
   assert(admitted(0x13db, 0x030000, 0).ip_path == STELA_AMD_IP_SOC_STATIC);
   struct stela_amd_pci_match skillfish2 = admitted(0x13fe, 0x030000, 0);
   assert(skillfish2.apu_flags == AMD_APU_IS_CYAN_SKILLFISH2);
   assert(skillfish2.ip_path == STELA_AMD_IP_DYNAMIC);

   /* Refusals leave the output unchanged: SI and CIK, which Stela builds
    * without, radeon's parts, other classes and vendors, and a forced ASIC. */
   assert(refused(0x6780, 0x030000, 0, &defaults) == -ENODEV);
   assert(refused(0x6640, 0x030000, 0, &defaults) == -ENODEV);
   assert(refused(0x4354, 0x030000, 0, &defaults) == -ENODEV);
   assert(refused(0x7550, 0x020000, 0, &defaults) == -ENODEV);
   const struct stela_amd_pci_identity intel = {.vendor = 0x8086, .device = 0x56a0,
                                                .class_code = 0x030000};
   struct stela_amd_pci_match out;
   assert(stela_amd_pci_match(&intel, &defaults, &out) == -ENODEV);
   const struct stela_amd_pci_policy forced = {.discovery = -1, .force_asic_type = CHIP_NAVI10};
   assert(refused(0x731f, 0x030000, 0, &forced) == -EOPNOTSUPP);
   assert(refused(0x731f, 0x030000, 0x100, &defaults) == -EINVAL);
   assert(stela_amd_pci_match(NULL, &defaults, &out) == -EINVAL);

   /* The policy sets amdgpu's module parameters, as in Linux. */
   const struct stela_amd_pci_policy file = {.discovery = 2, .force_asic_type = -1};
   assert(!admit(0x731f, 0x030000, 0, &file, &out) && amdgpu_discovery == 2);
   printf("AMD PCI admission: listed and class matches, IP paths, quirks and refusals\n");
   return 0;
}
