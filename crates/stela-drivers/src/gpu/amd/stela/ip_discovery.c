/* SPDX-License-Identifier: MIT */
/* Stela's environment for the unchanged Linux amdgpu_discovery.c, which
 * follows. Discovery acquires and checks the IP discovery binary and decodes
 * it as the dynamic path of amdgpu_discovery_set_ip_blocks does; no IP block
 * is registered or initialized. */
#include "ip_discovery.h"
#include "unsupported.h"
#include "amdgpu.h"
#include <linux/firmware.h>

struct stela_amd_discovery {
   const struct stela_amd_discovery_io *io;
   void *context;
   uint64_t register_bytes;
   /* The first operation Stela could not perform, which fails the call. */
   const char *unsupported;
   struct firmware firmware;
   struct pci_dev pdev;
   struct amdgpu_device adev;
};

size_t stela_amd_discovery_size(void) { return sizeof(struct stela_amd_discovery); }
size_t stela_amd_discovery_alignment(void) { return _Alignof(struct stela_amd_discovery); }

static struct stela_amd_discovery *state_of(struct amdgpu_device *adev)
{
   return container_of(adev, struct stela_amd_discovery, adev);
}
static void unsupported(struct amdgpu_device *adev, const char *operation)
{
   struct stela_amd_discovery *state = state_of(adev);
   if (!state->unsupported)
      state->unsupported = operation;
}

/* Discovery reports through these; its return values carry each failure. */
static void _dev_printk(const char *level, const struct device *dev, const char *fmt, ...)
{
   (void)level; (void)dev; (void)fmt;
}
static void stela_drm_printk(const struct drm_device *drm, enum stela_drm_level level,
                             const char *format, ...)
{
   (void)drm; (void)level; (void)format;
}

/* Discovery's sysfs tree, its dump and NPS queries are not reached: Stela
 * publishes no sysfs and reads no memory partitions from discovery. */
STELA_UNSUPPORTED(void, drm_printf, struct drm_printer *, const char *, ...)
STELA_UNSUPPORTED(int, kobject_set_name, struct kobject *, const char *, ...)
STELA_UNSUPPORTED(void, kobject_init, struct kobject *, const struct kobj_type *)
STELA_UNSUPPORTED(int, kobject_add, struct kobject *, struct kobject *, const char *, ...)
STELA_UNSUPPORTED(int, kobject_init_and_add, struct kobject *, const struct kobj_type *,
                  struct kobject *, const char *, ...)
STELA_UNSUPPORTED(void, kobject_put, struct kobject *)
STELA_UNSUPPORTED(int, kset_register, struct kset *)

/* Linux's msleep names no device; discovery calls it where adev is in scope,
 * as RREG32 relies on, so the owner's clock serves the device it waits for. */
static void stela_amd_msleep(struct amdgpu_device *adev, unsigned int msecs)
{
   struct stela_amd_discovery *state = state_of(adev);
   state->io->sleep_ms(state->context, msecs);
}
#define msleep(msecs) stela_amd_msleep(adev, msecs)

/* A discovery table in system memory belongs to an APU or a virtual function,
 * whose memory owners Stela does not have yet; discovery maps it with adev in
 * scope. */
static void *stela_amd_memremap(struct amdgpu_device *adev)
{
   unsupported(adev, "system memory discovery table");
   return NULL;
}
#define memremap(offset, size, flags) stela_amd_memremap(adev)

#include "amdgpu_discovery.c"
#include "nbif/nbif_6_1_offset.h"

/* Register access through the owner's BAR. Linux reaches registers beyond it
 * through the PCIe index/data pair, which Stela does not implement yet. */
static bool direct(struct amdgpu_device *adev, uint32_t reg)
{
   if ((uint64_t)reg * 4 + 4 <= state_of(adev)->register_bytes)
      return true;
   unsupported(adev, "indirect register access");
   return false;
}
static uint32_t amdgpu_device_rreg(struct amdgpu_device *adev, uint32_t reg, uint32_t acc_flags)
{
   struct stela_amd_discovery *state = state_of(adev);
   (void)acc_flags;
   return direct(adev, reg) ? state->io->read32(state->context, reg) : UINT32_MAX;
}
static void amdgpu_device_wreg(struct amdgpu_device *adev, uint32_t reg, uint32_t v,
                               uint32_t acc_flags)
{
   struct stela_amd_discovery *state = state_of(adev);
   (void)acc_flags;
   if (direct(adev, reg))
      state->io->write32(state->context, reg, v);
}
/* Linux's amdgpu_device_mm_access, which amdgpu_device_vram_access uses
 * before the VRAM aperture is mapped, as it is not during discovery. */
static void amdgpu_device_vram_access(struct amdgpu_device *adev, loff_t pos, void *buf,
                                      size_t size, bool write)
{
   uint32_t hi = ~0u, *data = buf;
   if (pos % 4 || size % 4) {
      unsupported(adev, "unaligned VRAM access");
      return;
   }
   for (uint64_t last = (uint64_t)pos + size, at = (uint64_t)pos; at < last; at += 4) {
      uint32_t tmp = (uint32_t)(at >> 31);
      WREG32(mmMM_INDEX, (uint32_t)at | 0x80000000);
      if (tmp != hi) {
         WREG32(mmMM_INDEX_HI, tmp);
         hi = tmp;
      }
      if (write)
         WREG32(mmMM_DATA, *data++);
      else
         *data++ = RREG32(mmMM_DATA);
   }
}


/* Linux's allocator is Stela's global heap; discovery allocates its binary. */
void *stela_amd_kzalloc(size_t size);
void stela_amd_kfree(const void *object);
static void *kzalloc(size_t size, gfp_t flags)
{
   (void)flags;
   return stela_amd_kzalloc(size);
}
static void kfree(const void *object)
{
   stela_amd_kfree(object);
}

/* The firmware Linux prefers for the binary, from the owner's provider. */
static int firmware_request_nowarn(const struct firmware **fw, const char *name,
                                   struct device *device)
{
   struct stela_amd_discovery *state = container_of(device, struct stela_amd_discovery, pdev.dev);
   const uint8_t *data = NULL;
   size_t size = 0;
   if (state->io->firmware(state->context, name, &data, &size))
      return -ENOENT;
   state->firmware = (struct firmware){.size = size, .data = data};
   *fw = &state->firmware;
   return 0;
}
static void release_firmware(const struct firmware *fw)
{
   (void)fw;
}

/* Unreached: memremap maps nothing. */
static void memunmap(void *addr)
{
   (void)addr;
}
/* After a failed acquisition Linux only logs the firmware's boot errors from
 * RAS registers; the returned status reports the failure itself. */
static void amdgpu_ras_query_boot_status(struct amdgpu_device *adev, u32 num_instances)
{
   (void)adev;
   (void)num_instances;
}

static bool usable(const struct stela_amd_discovery_io *io)
{
   return io && io->read32 && io->write32 && io->sleep_ms && io->firmware;
}

int stela_amd_discovery_init(void *storage, size_t bytes,
                             const struct stela_amd_discovery_io *io, void *context,
                             const struct stela_amd_discovery_device *device)
{
   if (!storage || bytes < sizeof(struct stela_amd_discovery) ||
       (uintptr_t)storage % _Alignof(struct stela_amd_discovery) || !usable(io) || !device ||
       device->asic_type >= CHIP_LAST)
      return -EINVAL;
   /* The device state is large; build it in place rather than on the stack. */
   struct stela_amd_discovery *state = storage;
   memset(state, 0, sizeof(*state));
   state->io = io;
   state->context = context;
   state->register_bytes = device->register_bytes;
   state->pdev.vendor = PCI_VENDOR_ID_ATI;
   state->pdev.device = device->pci_device;
   state->pdev.revision = device->pci_revision;
   struct amdgpu_device *adev = &state->adev;
   adev->dev = &state->pdev.dev;
   adev->pdev = &state->pdev;
   adev->ddev.dev = adev->dev;
   adev->asic_type = (enum amd_asic_type)device->asic_type;
   adev->flags = device->flags;
   adev->apu_flags = device->apu_flags;

   /* Linux's amdgpu_virt_init_detect_asic for the dynamic path's ASICs: a
    * virtual function's discovery comes from its host, which Stela lacks. */
   if (RREG32(mmRCC_IOV_FUNC_IDENTIFIER) & 1)
      unsupported(adev, "SR-IOV virtual function");
   int r = state->unsupported ? -EOPNOTSUPP : amdgpu_discovery_reg_base_init(adev);
   if (!r) {
      amdgpu_discovery_harvest_ip(adev);
      amdgpu_discovery_get_gfx_info(adev);
      amdgpu_discovery_get_mall_info(adev);
      amdgpu_discovery_get_vcn_info(adev);
   }
   /* Every value read where Stela lacked a service is invented. */
   if (!r && state->unsupported)
      r = -EOPNOTSUPP;
   if (r)
      amdgpu_discovery_fini(adev);
   return r;
}

const char *stela_amd_discovery_unsupported(const struct stela_amd_discovery *state)
{
   return state->unsupported;
}

void stela_amd_discovery_facts(const struct stela_amd_discovery *state,
                               struct stela_amd_discovery_facts *out)
{
   const struct amdgpu_device *adev = &state->adev;
   const struct amdgpu_gfx_config *config = &adev->gfx.config;
   const struct amdgpu_cu_info *cu = &adev->gfx.cu_info;
   *out = (struct stela_amd_discovery_facts){
      .mall_size = adev->gmc.mall_size, .umc_active_mask = adev->umc.active_mask,
      .harvest_ip_mask = adev->harvest_ip_mask, .vcn_harvest = adev->vcn.harvest_config,
      .jpeg_harvest = adev->jpeg.harvest_config, .m_half_use = adev->gmc.m_half_use,
      .sdma_mask = adev->sdma.sdma_mask, .vpe_count = adev->vpe.num_instances,
      .umc_nodes = adev->umc.node_inst_num, .sdma_count = adev->sdma.num_instances,
      .umc_count = adev->gmc.num_umc, .xcc_mask = adev->gfx.xcc_mask,
      .vcn_mask = adev->vcn.inst_mask, .jpeg_mask = adev->jpeg.inst_mask,
      .vcn_count = adev->vcn.num_vcn_inst,
      .gfx = {
         [STELA_AMD_GFX_MAX_SHADER_ENGINES] = config->max_shader_engines,
         [STELA_AMD_GFX_MAX_CU_PER_SH] = config->max_cu_per_sh,
         [STELA_AMD_GFX_MAX_SH_PER_SE] = config->max_sh_per_se,
         [STELA_AMD_GFX_MAX_BACKENDS_PER_SE] = config->max_backends_per_se,
         [STELA_AMD_GFX_MAX_TEXTURE_CHANNEL_CACHES] = config->max_texture_channel_caches,
         [STELA_AMD_GFX_MAX_GPRS] = config->max_gprs,
         [STELA_AMD_GFX_MAX_GS_THREADS] = config->max_gs_threads,
         [STELA_AMD_GFX_GS_VGT_TABLE_DEPTH] = config->gs_vgt_table_depth,
         [STELA_AMD_GFX_GS_PRIM_BUFFER_DEPTH] = config->gs_prim_buffer_depth,
         [STELA_AMD_GFX_DOUBLE_OFFCHIP_LDS_BUF] = config->double_offchip_lds_buf,
         [STELA_AMD_GFX_WAVE_FRONT_SIZE] = cu->wave_front_size,
         [STELA_AMD_GFX_MAX_WAVES_PER_SIMD] = cu->max_waves_per_simd,
         [STELA_AMD_GFX_MAX_SCRATCH_SLOTS_PER_CU] = cu->max_scratch_slots_per_cu,
         [STELA_AMD_GFX_LDS_SIZE] = cu->lds_size,
         [STELA_AMD_GFX_NUM_SC_PER_SH] = config->num_sc_per_sh,
         [STELA_AMD_GFX_NUM_PACKER_PER_SC] = config->num_packer_per_sc,
         [STELA_AMD_GFX_GC_NUM_TCP_PER_SA] = config->gc_num_tcp_per_sa,
         [STELA_AMD_GFX_GC_NUM_SDP_INTERFACE] = config->gc_num_sdp_interface,
         [STELA_AMD_GFX_GC_NUM_TCPS] = config->gc_num_tcps,
         [STELA_AMD_GFX_GC_NUM_TCP_PER_WPG] = config->gc_num_tcp_per_wpg,
         [STELA_AMD_GFX_GC_TCP_L1_SIZE] = config->gc_tcp_l1_size,
         [STELA_AMD_GFX_GC_NUM_SQC_PER_WGP] = config->gc_num_sqc_per_wgp,
         [STELA_AMD_GFX_GC_L1_INSTRUCTION_CACHE_SIZE_PER_SQC] =
            config->gc_l1_instruction_cache_size_per_sqc,
         [STELA_AMD_GFX_GC_L1_DATA_CACHE_SIZE_PER_SQC] = config->gc_l1_data_cache_size_per_sqc,
         [STELA_AMD_GFX_GC_GL1C_PER_SA] = config->gc_gl1c_per_sa,
         [STELA_AMD_GFX_GC_GL1C_SIZE_PER_INSTANCE] = config->gc_gl1c_size_per_instance,
         [STELA_AMD_GFX_GC_GL2C_PER_GPU] = config->gc_gl2c_per_gpu,
         [STELA_AMD_GFX_GC_TCP_SIZE_PER_CU] = config->gc_tcp_size_per_cu,
         [STELA_AMD_GFX_GC_TCP_CACHE_LINE_SIZE] = config->gc_tcp_cache_line_size,
         [STELA_AMD_GFX_GC_INSTRUCTION_CACHE_SIZE_PER_SQC] =
            config->gc_instruction_cache_size_per_sqc,
         [STELA_AMD_GFX_GC_INSTRUCTION_CACHE_LINE_SIZE] = config->gc_instruction_cache_line_size,
         [STELA_AMD_GFX_GC_SCALAR_DATA_CACHE_SIZE_PER_SQC] =
            config->gc_scalar_data_cache_size_per_sqc,
         [STELA_AMD_GFX_GC_SCALAR_DATA_CACHE_LINE_SIZE] = config->gc_scalar_data_cache_line_size,
         [STELA_AMD_GFX_GC_TCC_SIZE] = config->gc_tcc_size,
         [STELA_AMD_GFX_GC_TCC_CACHE_LINE_SIZE] = config->gc_tcc_cache_line_size,
         [STELA_AMD_GFX_GC_NUM_CU_PER_SQC] = config->gc_num_cu_per_sqc,
      },
   };
   for (unsigned i = 0; i < AMDGPU_MAX_VCN_INSTANCES; i++) {
      out->vcn_config[i] = adev->vcn.inst[i].vcn_config;
      out->vcn_codec_disable[i] = adev->vcn.inst[i].vcn_codec_disable_mask;
   }
}

uint32_t stela_amd_discovery_version(const struct stela_amd_discovery *state, uint32_t hw_ip,
                                     uint32_t instance)
{
   if (hw_ip >= MAX_HWIP || instance >= HWIP_MAX_INSTANCE)
      return 0;
   return amdgpu_ip_version_full(&state->adev, (uint8_t)hw_ip, (uint8_t)instance);
}

int stela_amd_discovery_registers(const struct stela_amd_discovery *state, uint32_t hw_ip,
                                  uint32_t instance, uint32_t segment, uint32_t *base)
{
   if (hw_ip >= MAX_HWIP || instance >= HWIP_MAX_INSTANCE || !state->adev.reg_offset[hw_ip][instance])
      return -1;
   /* reg_offset points at the base addresses of a packed ip_v4 entry, which
    * reg_base_init converted to 32-bit values in place. */
   const uint8_t *bases = (const uint8_t *)state->adev.reg_offset[hw_ip][instance];
   const struct ip_v4 *ip = (const void *)(bases - offsetof(struct ip_v4, base_address));
   if (segment < ip->num_base_address && base)
      memcpy(base, bases + segment * sizeof(uint32_t), sizeof(uint32_t));
   return ip->num_base_address;
}

void stela_amd_discovery_fini(struct stela_amd_discovery *state)
{
   amdgpu_discovery_fini(&state->adev);
}
