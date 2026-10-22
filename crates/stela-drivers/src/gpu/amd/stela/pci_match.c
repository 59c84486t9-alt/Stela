/* SPDX-License-Identifier: MIT */
/* Stela's environment for the unchanged Linux amdgpu_drv.c, which follows.
 * Matching runs the driver's own device tables, ASIC quirks and generation
 * support policy; nothing of the DRM driver itself is reachable. */
#include "pci_match.h"
#include "unsupported.h"
#include "amdgpu.h"
#include "amdgpu_dma_buf.h"

/* Support policy reports through these; its return value carries the answer. */
static void _dev_printk(const char *level, const struct device *dev, const char *fmt, ...)
{
   (void)level; (void)dev; (void)fmt;
}
/* Linux's nomodeset parameter; Stela has none, so no display is left to
 * firmware drivers. */
static bool drm_firmware_drivers_only(void)
{
   return false;
}

/* The DRM driver's ioctls, file operations and partition driver, which
 * amdgpu_drv.c defines with external linkage. Stela registers no DRM driver,
 * so nothing reaches them. */
STELA_UNSUPPORTED(int, amdgpu_bo_list_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_cs_fence_to_handle_ioctl, struct drm_device *, void *,
                  struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_cs_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_cs_wait_fences_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_cs_wait_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_ctx_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_gem_create_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_gem_list_handles_ioctl, struct drm_device *, void *,
                  struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_gem_metadata_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_gem_mmap_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_gem_op_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_gem_userptr_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_gem_va_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_gem_wait_idle_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_info_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_sched_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_userq_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_userq_signal_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_userq_wait_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_vm_ioctl, struct drm_device *, void *, struct drm_file *)
STELA_UNSUPPORTED(int, amdgpu_driver_open_kms, struct drm_device *, struct drm_file *)
STELA_UNSUPPORTED(void, amdgpu_driver_postclose_kms, struct drm_device *, struct drm_file *)
STELA_UNSUPPORTED(void, amdgpu_driver_release_kms, struct drm_device *)
STELA_UNSUPPORTED(struct drm_gem_object *, amdgpu_gem_prime_import, struct drm_device *,
                  struct dma_buf *)
STELA_UNSUPPORTED(int, amdgpu_mode_dumb_create, struct drm_file *, struct drm_device *,
                  struct drm_mode_create_dumb *)
STELA_UNSUPPORTED(int, amdgpu_mode_dumb_mmap, struct drm_file *, struct drm_device *, uint32_t,
                  uint64_t *)
STELA_UNSUPPORTED(long, amdgpu_ctx_mgr_entity_flush, struct amdgpu_ctx_mgr *, long)
STELA_UNSUPPORTED(long, amdgpu_vm_wait_idle, struct amdgpu_vm *, long)
STELA_UNSUPPORTED(void, amdgpu_evf_mgr_fini, struct amdgpu_eviction_fence_mgr *)
STELA_UNSUPPORTED(void, amdgpu_evf_mgr_flush_suspend, struct amdgpu_eviction_fence_mgr *)
STELA_UNSUPPORTED(void, amdgpu_evf_mgr_shutdown, struct amdgpu_eviction_fence_mgr *)
STELA_UNSUPPORTED(void, amdgpu_userq_mgr_cancel_resume, struct amdgpu_userq_mgr *)
STELA_UNSUPPORTED(void, amdgpu_userq_mgr_fini, struct amdgpu_userq_mgr *)
STELA_UNSUPPORTED(bool, drm_dev_enter, struct drm_device *, int *)
STELA_UNSUPPORTED(void, drm_dev_exit, int)
STELA_UNSUPPORTED(int, drm_gem_mmap, struct file *, struct vm_area_struct *)
STELA_UNSUPPORTED(int, drm_open, struct inode *, struct file *)
STELA_UNSUPPORTED(__poll_t, drm_poll, struct file *, struct poll_table_struct *)
STELA_UNSUPPORTED(ssize_t, drm_read, struct file *, char __user *, size_t, loff_t *)
STELA_UNSUPPORTED(int, drm_release, struct inode *, struct file *)
STELA_UNSUPPORTED(unsigned long, msecs_to_jiffies, const unsigned int)
STELA_UNSUPPORTED(int, pm_runtime_get_sync, struct device *)
STELA_UNSUPPORTED(int, pm_runtime_put_autosuspend, struct device *)
STELA_UNSUPPORTED_EXTERN(long, drm_ioctl, struct file *, unsigned int, unsigned long)

#include "amdgpu_drv.c"

/* Linux's pci_match_device over the static table: pci_match_one_device's
 * predicate, first match wins, and override-only rows are skipped because
 * Stela sets no driver_override. */
static const struct pci_device_id *match(const struct pci_dev *dev)
{
   for (const struct pci_device_id *id = pciidlist; id->vendor || id->subvendor || id->class_mask;
        id++)
      if ((id->vendor == (__u32)PCI_ANY_ID || id->vendor == dev->vendor) &&
          (id->device == (__u32)PCI_ANY_ID || id->device == dev->device) &&
          (id->subvendor == (__u32)PCI_ANY_ID || id->subvendor == dev->subsystem_vendor) &&
          (id->subdevice == (__u32)PCI_ANY_ID || id->subdevice == dev->subsystem_device) &&
          !((id->class ^ dev->class) & id->class_mask) && !id->override_only)
         return id;
   return NULL;
}

/* amdgpu_device_init_apu_flags, from the matched flags and device ID. */
static unsigned long apu_flags(enum amd_asic_type asic, unsigned long flags,
                               unsigned short device)
{
   if (!(flags & AMD_IS_APU) || asic < CHIP_RAVEN)
      return 0;
   switch (asic) {
   case CHIP_RAVEN:
      return (device == 0x15dd ? AMD_APU_IS_RAVEN : 0) |
             (device == 0x15d8 ? AMD_APU_IS_PICASSO : 0);
   case CHIP_RENOIR:
      return device == 0x1636 || device == 0x164c ? AMD_APU_IS_RENOIR
                                                  : AMD_APU_IS_GREEN_SARDINE;
   case CHIP_VANGOGH:
      return AMD_APU_IS_VANGOGH;
   case CHIP_CYAN_SKILLFISH:
      return device == 0x13FE || device == 0x143F ? AMD_APU_IS_CYAN_SKILLFISH2 : 0;
   default:
      return 0;
   }
}

/* amdgpu_device_ip_early_init's choice between the VI tables and discovery,
 * and amdgpu_discovery_set_ip_blocks's choice between fixed SOC15 tables and
 * the discovered ones. */
static enum stela_amd_ip_path ip_path(enum amd_asic_type asic, unsigned long apu)
{
   switch (asic) {
   case CHIP_TOPAZ:
   case CHIP_TONGA:
   case CHIP_FIJI:
   case CHIP_POLARIS10:
   case CHIP_POLARIS11:
   case CHIP_POLARIS12:
   case CHIP_VEGAM:
   case CHIP_CARRIZO:
   case CHIP_STONEY:
      return STELA_AMD_IP_VI_STATIC;
   case CHIP_VEGA10:
   case CHIP_VEGA12:
   case CHIP_RAVEN:
   case CHIP_VEGA20:
   case CHIP_ARCTURUS:
   case CHIP_ALDEBARAN:
      return STELA_AMD_IP_SOC_STATIC;
   case CHIP_CYAN_SKILLFISH:
      return apu & AMD_APU_IS_CYAN_SKILLFISH2 ? STELA_AMD_IP_DYNAMIC : STELA_AMD_IP_SOC_STATIC;
   default:
      return STELA_AMD_IP_DYNAMIC;
   }
}

int stela_amd_pci_match(const struct stela_amd_pci_identity *identity,
                        const struct stela_amd_pci_policy *policy,
                        struct stela_amd_pci_match *out)
{
   if (!identity || !policy || !out || identity->vendor > U16_MAX ||
       identity->device > U16_MAX || identity->subvendor > U16_MAX ||
       identity->subdevice > U16_MAX || identity->class_code > 0xffffff ||
       identity->revision > U8_MAX)
      return -EINVAL;
   amdgpu_exp_hw_support = policy->exp_hw_support;
   amdgpu_discovery = policy->discovery;
   amdgpu_force_asic_type = policy->force_asic_type;
   struct pci_dev pdev = {
      .vendor = (unsigned short)identity->vendor,
      .device = (unsigned short)identity->device,
      .subsystem_vendor = (unsigned short)identity->subvendor,
      .subsystem_device = (unsigned short)identity->subdevice,
      .revision = (u8)identity->revision,
      .class = identity->class_code,
   };
   const struct pci_device_id *ent = match(&pdev);
   if (!ent)
      return -ENODEV;

   /* amdgpu_pci_probe's admission, before it creates the device. */
   unsigned long flags = ent->driver_data;
   if (((pdev.class >> 8) == PCI_CLASS_DISPLAY_VGA ||
        (pdev.class >> 8) == PCI_CLASS_DISPLAY_OTHER) &&
       drm_firmware_drivers_only() && amdgpu_modeset == -1)
      return -EINVAL;
   for (size_t i = 0; i < ARRAY_SIZE(amdgpu_unsupported_pciidlist); i++)
      if (amdgpu_unsupported_pciidlist[i] == pdev.device)
         return -ENODEV;
   if ((flags & AMD_EXP_HW_SUPPORT) && !amdgpu_exp_hw_support)
      return -ENODEV;
   flags = amdgpu_fix_asic_type(&pdev, flags);
   if (cc_platform_has(CC_ATTR_MEM_ENCRYPT) && (flags & AMD_ASIC_MASK) == CHIP_RAVEN)
      return -ENOTSUPP;
   if (!amdgpu_support_enabled(&pdev.dev, flags & AMD_ASIC_MASK))
      return -ENODEV;
   /* amdgpu_device_init's forced ASIC type emulates another chip on this
    * one; Stela drives the chip that is present. */
   if (amdgpu_force_asic_type >= 0 && amdgpu_force_asic_type < CHIP_LAST)
      return -EOPNOTSUPP;

   const enum amd_asic_type asic = (enum amd_asic_type)(flags & AMD_ASIC_MASK);
   const unsigned long apu = apu_flags(asic, flags, pdev.device);
   *out = (struct stela_amd_pci_match){
      .row = (uint32_t)(ent - pciidlist), .flags = (uint32_t)flags, .asic_type = asic,
      .apu_flags = (uint32_t)apu, .ip_path = ip_path(asic, apu),
   };
   return 0;
}
