/* SPDX-License-Identifier: MIT */
/* The unchanged Linux amdgpu_discovery.c, run on a device whose registers,
 * clock and firmware belong to the native owner. Discovery acquires and
 * checks the IP discovery binary and decodes it as the dynamic path of
 * amdgpu_discovery_set_ip_blocks does; no IP block is registered or
 * initialized. */
#include "ip_discovery.h"
#include <stela/linux.h>
#include "amdgpu_discovery.c"
#include "nbif/nbif_6_1_offset.h"
#include <unsupported.h>

/* Every amdgpu_device Stela creates is a discovery's. */
struct stela_amd_discovery {
   const struct stela_amd_discovery_io *io;
   void *context;
   uint64_t register_bytes;
   /* The first operation Stela could not perform. */
   const char *unsupported;
   struct pci_dev pdev;
   struct amdgpu_device adev;
};

size_t stela_amd_discovery_size(void) { return sizeof(struct stela_amd_discovery); }
size_t stela_amd_discovery_alignment(void) { return _Alignof(struct stela_amd_discovery); }

static struct stela_amd_discovery *state_of(struct amdgpu_device *adev)
{
   return container_of(adev, struct stela_amd_discovery, adev);
}

/* The owner's services for Linux code run on the discovery's behalf. The
 * owner may sleep during discovery, so every delay sleeps whole milliseconds,
 * never shorter than asked. */
static void delay_us(void *context, u64 minimum, u64 maximum, bool atomic)
{
   struct stela_amd_discovery *state = context;
   (void)maximum;
   (void)atomic;
   state->io->sleep_ms(state->context, (uint32_t)min_t(u64, DIV_ROUND_UP(minimum, 1000), U32_MAX));
}
static int firmware(void *context, const char *name, const u8 **data, size_t *size)
{
   struct stela_amd_discovery *state = context;
   return state->io->firmware(state->context, name, data, size) ? -ENOENT : 0;
}
static void unsupported(void *context, const char *operation)
{
   struct stela_amd_discovery *state = context;
   if (!state->unsupported)
      state->unsupported = operation;
}
static const struct stela_linux_services services = {
   .delay_us = delay_us, .firmware = firmware, .unsupported = unsupported,
};

/* Register access through the owner's BAR. Linux reaches registers beyond it
 * through the PCIe index/data pair, which Stela does not implement yet. */
static bool direct(struct amdgpu_device *adev, uint32_t reg)
{
   if ((uint64_t)reg * 4 + 4 <= state_of(adev)->register_bytes)
      return true;
   stela_linux_unsupported("indirect register access");
   return false;
}
uint32_t amdgpu_device_rreg(struct amdgpu_device *adev, uint32_t reg, uint32_t acc_flags)
{
   struct stela_amd_discovery *state = state_of(adev);
   (void)acc_flags;
   return direct(adev, reg) ? state->io->read32(state->context, reg) : U32_MAX;
}
void amdgpu_device_wreg(struct amdgpu_device *adev, uint32_t reg, uint32_t v, uint32_t acc_flags)
{
   struct stela_amd_discovery *state = state_of(adev);
   (void)acc_flags;
   if (direct(adev, reg))
      state->io->write32(state->context, reg, v);
}

/* VRAM through the MM register window, the one way to reach it before its
 * aperture is mapped, as it is not during discovery. MM_INDEX selects bits
 * 0-30 of a DWORD's address, with bit 31 set for memory, and MM_INDEX_HI the
 * bits above them; MM_DATA then transfers that DWORD. */
void amdgpu_device_vram_access(struct amdgpu_device *adev, loff_t pos, void *buf, size_t size,
                               bool write)
{
   if (pos < 0 || !IS_ALIGNED(pos, 4) || !IS_ALIGNED(size, 4)) {
      stela_linux_unsupported("unaligned VRAM access");
      return;
   }
   const u64 first = (u64)pos;
   u32 *words = buf;
   for (size_t word = 0; word < size / 4; word++) {
      const u64 address = first + word * 4;
      WREG32(mmMM_INDEX, BIT(31) | (u32)(address & GENMASK_ULL(30, 0)));
      if (!word || !(address & GENMASK_ULL(30, 0)))
         WREG32(mmMM_INDEX_HI, (u32)(address >> 31));
      if (write)
         WREG32(mmMM_DATA, words[word]);
      else
         words[word] = RREG32(mmMM_DATA);
   }
}

/* After a failed acquisition Linux logs the firmware's boot errors, which it
 * reads through SMN, an indirect path Stela does not implement yet; the
 * failure itself is discovery's status. */
void amdgpu_ras_query_boot_status(struct amdgpu_device *adev, u32 num_instances)
{
   (void)adev;
   (void)num_instances;
   stela_linux_unsupported("indirect register access");
}

/* What amdgpu_discovery_set_ip_blocks registers and configures. Stela decodes
 * discovery without registering IP blocks, so none of their code runs and
 * their descriptors hold nothing. */
STELA_UNSUPPORTED(int, amdgpu_device_ip_block_add, struct amdgpu_device *,
                  const struct amdgpu_ip_block_version *)
STELA_UNSUPPORTED(bool, amdgpu_device_has_dc_support, struct amdgpu_device *)
STELA_UNSUPPORTED(int, aldebaran_reg_base_init, struct amdgpu_device *)
STELA_UNSUPPORTED(int, aqua_vanjaram_init_soc_config, struct amdgpu_device *)
STELA_UNSUPPORTED(int, arct_reg_base_init, struct amdgpu_device *)
STELA_UNSUPPORTED(int, cyan_skillfish_reg_base_init, struct amdgpu_device *)
STELA_UNSUPPORTED(int, soc_v1_0_init_soc_config, struct amdgpu_device *)
STELA_UNSUPPORTED(int, vega10_reg_base_init, struct amdgpu_device *)
STELA_UNSUPPORTED(int, vega20_reg_base_init, struct amdgpu_device *)
#define IP_BLOCK(name) \
   STELA_UNSUPPORTED_OBJECT(const struct amdgpu_ip_block_version, name##_ip_block)
IP_BLOCK(amdgpu_vkms); IP_BLOCK(gfx_v10_0); IP_BLOCK(gfx_v11_0); IP_BLOCK(gfx_v12_0);
IP_BLOCK(gfx_v12_1); IP_BLOCK(gfx_v9_0); IP_BLOCK(gfx_v9_4_3); IP_BLOCK(gmc_v10_0);
IP_BLOCK(gmc_v11_0); IP_BLOCK(gmc_v12_0); IP_BLOCK(gmc_v9_0); IP_BLOCK(ih_v6_0);
IP_BLOCK(ih_v6_1); IP_BLOCK(ih_v7_0); IP_BLOCK(jpeg_v2_0); IP_BLOCK(jpeg_v2_5);
IP_BLOCK(jpeg_v2_6); IP_BLOCK(jpeg_v3_0); IP_BLOCK(jpeg_v4_0_3); IP_BLOCK(jpeg_v4_0_5);
IP_BLOCK(jpeg_v4_0); IP_BLOCK(jpeg_v5_0_0); IP_BLOCK(jpeg_v5_0_1); IP_BLOCK(jpeg_v5_0_2);
IP_BLOCK(jpeg_v5_3_0); IP_BLOCK(mes_v11_0); IP_BLOCK(mes_v12_0); IP_BLOCK(mes_v12_1);
IP_BLOCK(navi10_ih); IP_BLOCK(nv_common); IP_BLOCK(pp_smu); IP_BLOCK(psp_v10_0);
IP_BLOCK(psp_v11_0_8); IP_BLOCK(psp_v11_0); IP_BLOCK(psp_v12_0); IP_BLOCK(psp_v13_0_4);
IP_BLOCK(psp_v13_0); IP_BLOCK(psp_v14_0); IP_BLOCK(psp_v15_0_8); IP_BLOCK(psp_v15_0);
IP_BLOCK(psp_v3_1); IP_BLOCK(ras_v1_0); IP_BLOCK(sdma_v4_0); IP_BLOCK(sdma_v4_4_2);
IP_BLOCK(sdma_v5_0); IP_BLOCK(sdma_v5_2); IP_BLOCK(sdma_v6_0); IP_BLOCK(sdma_v7_0);
IP_BLOCK(sdma_v7_1); IP_BLOCK(smu_v11_0); IP_BLOCK(smu_v12_0); IP_BLOCK(smu_v13_0);
IP_BLOCK(smu_v14_0); IP_BLOCK(smu_v15_0); IP_BLOCK(soc21_common); IP_BLOCK(soc24_common);
IP_BLOCK(soc_v1_0_common); IP_BLOCK(umsch_mm_v4_0); IP_BLOCK(uvd_v7_0); IP_BLOCK(vce_v4_0);
IP_BLOCK(vcn_v1_0); IP_BLOCK(vcn_v2_0); IP_BLOCK(vcn_v2_5); IP_BLOCK(vcn_v2_6);
IP_BLOCK(vcn_v3_0); IP_BLOCK(vcn_v4_0_3); IP_BLOCK(vcn_v4_0_5); IP_BLOCK(vcn_v4_0);
IP_BLOCK(vcn_v5_0_0); IP_BLOCK(vcn_v5_0_1); IP_BLOCK(vcn_v5_0_2); IP_BLOCK(vega10_common);
IP_BLOCK(vega10_ih); IP_BLOCK(vega20_ih); IP_BLOCK(vpe_v2_0); IP_BLOCK(vpe_v6_1);
#undef IP_BLOCK
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_df_funcs, df_v1_7_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_df_funcs, df_v3_6_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_df_funcs, df_v4_15_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_df_funcs, df_v4_3_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_df_funcs, df_v4_6_2_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_hdp_funcs, hdp_v4_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_hdp_funcs, hdp_v5_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_hdp_funcs, hdp_v5_2_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_hdp_funcs, hdp_v6_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_hdp_funcs, hdp_v7_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_lsdma_funcs, lsdma_v6_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_lsdma_funcs, lsdma_v7_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_lsdma_funcs, lsdma_v7_1_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbif_v6_3_1_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbif_v6_3_1_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v2_3_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbio_v2_3_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v4_3_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbio_v4_3_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v4_3_sriov_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v6_1_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbio_v6_1_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v6_3_2_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v7_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbio_v7_0_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v7_11_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbio_v7_11_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v7_2_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbio_v7_2_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v7_4_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbio_v7_4_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v7_7_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbio_v7_7_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_nbio_funcs, nbio_v7_9_funcs);
STELA_UNSUPPORTED_OBJECT(const struct nbio_hdp_flush_reg, nbio_v7_9_hdp_flush_reg);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_smuio_funcs, smuio_v11_0_6_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_smuio_funcs, smuio_v11_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_smuio_funcs, smuio_v13_0_3_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_smuio_funcs, smuio_v13_0_6_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_smuio_funcs, smuio_v13_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_smuio_funcs, smuio_v14_0_2_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_smuio_funcs, smuio_v15_0_0_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_smuio_funcs, smuio_v15_0_8_funcs);
STELA_UNSUPPORTED_OBJECT(const struct amdgpu_smuio_funcs, smuio_v9_0_funcs);

static bool usable(const struct stela_amd_discovery_io *io)
{
   return io && io->read32 && io->write32 && io->sleep_ms && io->firmware;
}

static int discover(struct stela_amd_discovery *state)
{
   struct amdgpu_device *adev = &state->adev;
   /* Linux's amdgpu_virt_init_detect_asic for the dynamic path's ASICs: a
    * virtual function's discovery comes from its host, which Stela lacks. */
   if (RREG32(mmRCC_IOV_FUNC_IDENTIFIER) & 1)
      stela_linux_unsupported("SR-IOV virtual function");
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

   const struct stela_linux_owner owner = {.services = &services, .context = state};
   stela_linux_enter(&owner);
   int r = discover(state);
   stela_linux_exit();
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
   stela_linux_enter(&stela_linux_bare);
   amdgpu_discovery_fini(&state->adev);
   stela_linux_exit();
}
