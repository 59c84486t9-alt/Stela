/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_DISCOVERY_INFO_H
#define STELA_AMD_DISCOVERY_INFO_H
#include "discovery_ip.h"
enum stela_amd_discovery_gfx_field {
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
 STELA_AMD_GFX_FIELD_COUNT
};
/* Schema status: absent offset => present=0,status=0; supplied unknown schema
 * => present=1,status=-EINVAL, with original partial effects retained. */
struct stela_amd_discovery_info_table { int32_t status; uint16_t major, minor; uint32_t present; };
struct stela_amd_discovery_info {
 struct stela_amd_ip_counts counts;
 uint32_t harvest_mask, vcn_harvest, jpeg_harvest, isp_harvest;
 uint64_t active_umc_mask, mall_size;
 uint32_t half_use, codec_disable[4];
 struct stela_amd_discovery_info_table gfx, mall, vcn;
 uint64_t gfx_supplied;
 uint32_t gfx_values[STELA_AMD_GFX_FIELD_COUNT];
 uint32_t isp_build_enabled;
 uint32_t harvest_errors, harvest_warnings;
};
/* Internal original-consumer boundary, NOT acquisition/admission. Inputs are
 * the immutable raw acquisition and actual same-source original decode outputs,
 * all disjoint owned CPU spans. PCI values are actual matched observed values.
 * Original read-only consumers ignore converted bases/revision capability bits,
 * so reading immutable raw data preserves the original post-walk results.
 * Native UMC active_mask explicitly retains Linux x86-64 width on COFF too.
 * Preflight errors leave output untouched; successful execution records each
 * original nonfatal helper status, and actual schema-supplied fields only.
 * No pointer is retained or device/allocator/log/firmware service synthesized. */
int stela_amd_discovery_info_decode(const uint8_t *raw, size_t bytes,
 const uint32_t *versions, size_t version_count,
 const struct stela_amd_ip_counts *counts, uint16_t pci_device, uint8_t pci_revision,
 struct stela_amd_discovery_info *out);
size_t stela_amd_discovery_info_bytes(void);
#endif
