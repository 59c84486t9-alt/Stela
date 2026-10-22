/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_IP_DISCOVERY_H
#define STELA_AMD_IP_DISCOVERY_H
#include <stddef.h>
#include <stdint.h>

/* Services the native owner provides for Linux's IP discovery on one PF.
 * read32 and write32 access the register BAR by DWORD index; the adapter never
 * passes an index outside register_bytes. sleep_ms waits at least that long.
 * firmware returns an image, which stays valid while the discovery does, or
 * nonzero when the provider has none. The binary itself comes from Stela's
 * heap through stela_amd_kzalloc. */
struct stela_amd_discovery_io {
   uint32_t (*read32)(void *, uint32_t reg);
   void (*write32)(void *, uint32_t reg, uint32_t value);
   void (*sleep_ms)(void *, uint32_t milliseconds);
   int (*firmware)(void *, const char *name, const uint8_t **data, size_t *bytes);
};

/* The matched function, from stela_amd_pci_match. */
struct stela_amd_discovery_device {
   uint64_t register_bytes;
   uint32_t asic_type, flags, apu_flags;
   uint16_t pci_device;
   uint8_t pci_revision;
};

/* Linux's results, before any IP block is initialized. Each gfx field has the
 * index of its enum stela_amd_gfx_field; zero is a value the GC table did not
 * provide, as in Linux. */
enum stela_amd_gfx_field {
   STELA_AMD_GFX_MAX_SHADER_ENGINES,
   STELA_AMD_GFX_MAX_CU_PER_SH,
   STELA_AMD_GFX_MAX_SH_PER_SE,
   STELA_AMD_GFX_MAX_BACKENDS_PER_SE,
   STELA_AMD_GFX_MAX_TEXTURE_CHANNEL_CACHES,
   STELA_AMD_GFX_MAX_GPRS,
   STELA_AMD_GFX_MAX_GS_THREADS,
   STELA_AMD_GFX_GS_VGT_TABLE_DEPTH,
   STELA_AMD_GFX_GS_PRIM_BUFFER_DEPTH,
   STELA_AMD_GFX_DOUBLE_OFFCHIP_LDS_BUF,
   STELA_AMD_GFX_WAVE_FRONT_SIZE,
   STELA_AMD_GFX_MAX_WAVES_PER_SIMD,
   STELA_AMD_GFX_MAX_SCRATCH_SLOTS_PER_CU,
   STELA_AMD_GFX_LDS_SIZE,
   STELA_AMD_GFX_NUM_SC_PER_SH,
   STELA_AMD_GFX_NUM_PACKER_PER_SC,
   STELA_AMD_GFX_GC_NUM_TCP_PER_SA,
   STELA_AMD_GFX_GC_NUM_SDP_INTERFACE,
   STELA_AMD_GFX_GC_NUM_TCPS,
   STELA_AMD_GFX_GC_NUM_TCP_PER_WPG,
   STELA_AMD_GFX_GC_TCP_L1_SIZE,
   STELA_AMD_GFX_GC_NUM_SQC_PER_WGP,
   STELA_AMD_GFX_GC_L1_INSTRUCTION_CACHE_SIZE_PER_SQC,
   STELA_AMD_GFX_GC_L1_DATA_CACHE_SIZE_PER_SQC,
   STELA_AMD_GFX_GC_GL1C_PER_SA,
   STELA_AMD_GFX_GC_GL1C_SIZE_PER_INSTANCE,
   STELA_AMD_GFX_GC_GL2C_PER_GPU,
   STELA_AMD_GFX_GC_TCP_SIZE_PER_CU,
   STELA_AMD_GFX_GC_TCP_CACHE_LINE_SIZE,
   STELA_AMD_GFX_GC_INSTRUCTION_CACHE_SIZE_PER_SQC,
   STELA_AMD_GFX_GC_INSTRUCTION_CACHE_LINE_SIZE,
   STELA_AMD_GFX_GC_SCALAR_DATA_CACHE_SIZE_PER_SQC,
   STELA_AMD_GFX_GC_SCALAR_DATA_CACHE_LINE_SIZE,
   STELA_AMD_GFX_GC_TCC_SIZE,
   STELA_AMD_GFX_GC_TCC_CACHE_LINE_SIZE,
   STELA_AMD_GFX_GC_NUM_CU_PER_SQC,
   STELA_AMD_GFX_FIELDS
};
struct stela_amd_discovery_facts {
   uint64_t mall_size, umc_active_mask;
   uint32_t harvest_ip_mask, vcn_harvest, jpeg_harvest, m_half_use;
   uint32_t sdma_mask, vpe_count, umc_nodes, vcn_codec_disable[4];
   int32_t sdma_count, umc_count;
   uint16_t xcc_mask, vcn_mask, jpeg_mask;
   uint8_t vcn_count, vcn_config[4];
   uint32_t gfx[STELA_AMD_GFX_FIELDS];
};
_Static_assert(sizeof(struct stela_amd_discovery_facts) == 224, "facts ABI");

struct stela_amd_discovery;
size_t stela_amd_discovery_size(void);
size_t stela_amd_discovery_alignment(void);
/* Run Linux's discovery for an ASIC on its dynamic path: acquire the binary
 * from VRAM, or from the firmware Linux prefers, check it, then decode IP
 * versions and register bases, harvesting and the GC, MALL and VCN tables.
 * storage is owned and aligned host memory. Returns 0 or Linux's negative
 * status; on failure stela_amd_discovery_unsupported names the service Stela
 * lacked, if one was needed, and storage holds nothing to release. */
int stela_amd_discovery_init(void *storage, size_t bytes,
                             const struct stela_amd_discovery_io *io, void *context,
                             const struct stela_amd_discovery_device *device);
const char *stela_amd_discovery_unsupported(const struct stela_amd_discovery *);
void stela_amd_discovery_facts(const struct stela_amd_discovery *,
                               struct stela_amd_discovery_facts *);
/* The full IP version, including variant and subrevision; zero if absent. */
uint32_t stela_amd_discovery_version(const struct stela_amd_discovery *, uint32_t hw_ip,
                                     uint32_t instance);
/* Register base segments of one IP instance: returns the segment count, or -1
 * when the instance has no register binding. */
int stela_amd_discovery_registers(const struct stela_amd_discovery *, uint32_t hw_ip,
                                  uint32_t instance, uint32_t segment, uint32_t *base);
/* Release the binary. */
void stela_amd_discovery_fini(struct stela_amd_discovery *);
#endif
