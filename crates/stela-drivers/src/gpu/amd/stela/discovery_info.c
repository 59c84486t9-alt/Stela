/* SPDX-License-Identifier: MIT */
#include "discovery_info.h"
#include "discovery_binary.h"
#include "../amdgpu/amdgpu_discovery_info_core.h"

_Static_assert(sizeof(int) == sizeof(int32_t), "original int ABI");
_Static_assert(sizeof(unsigned) == sizeof(uint32_t), "original unsigned ABI");
_Static_assert(sizeof(amdgpu_discovery_umc_mask) == 8, "native Linux x86-64 UMC mask");
_Static_assert(STELA_AMD_GFX_FIELD_COUNT <= 64, "supplied field mask");
_Static_assert(sizeof(struct stela_amd_discovery_info_table)==12,"table ABI");
_Static_assert(sizeof(struct stela_amd_discovery_info)==288,"information ABI");
_Static_assert(offsetof(struct stela_amd_discovery_info,active_umc_mask)==48,"UMC ABI");
_Static_assert(offsetof(struct stela_amd_discovery_info,gfx_supplied)==120,"supplied ABI");
_Static_assert(offsetof(struct stela_amd_discovery_info,gfx_values)==128,"field array ABI");
_Static_assert(STELA_AMD_GFX_GC_NUM_CU_PER_SQC==35,"field enum ABI");
_Static_assert(offsetof(struct gpu_info_header,version_major)==offsetof(struct mall_info_header,version_major),"MALL schema major ABI");
_Static_assert(offsetof(struct gpu_info_header,version_minor)==offsetof(struct mall_info_header,version_minor),"MALL schema minor ABI");
_Static_assert(offsetof(struct gpu_info_header,version_major)==offsetof(struct vcn_info_header,version_major),"VCN schema major ABI");
_Static_assert(offsetof(struct gpu_info_header,version_minor)==offsetof(struct vcn_info_header,version_minor),"VCN schema minor ABI");
size_t stela_amd_discovery_info_bytes(void) { return sizeof(struct stela_amd_discovery_info); }
struct info_context { const uint8_t *raw; size_t bytes; uint32_t errors, warnings; };
/* Preserve observable void-harvest diagnostic calls without inventing a return
 * status or converting nonfatal errors into an initialization decision. */
static void error(void *context, const char *format, ...) { (void)format; ((struct info_context *)context)->errors++; }
static void warn(void *context, const char *format, ...) { (void)format; ((struct info_context *)context)->warnings++; }
static int lookup_table(void *context, struct table_info **out, uint16_t id)
{
 const struct info_context *c = context;
 *out = (struct table_info *)amdgpu_discovery_binary_table(c->raw, c->bytes, id);
 return *out ? 0 : -EINVAL;
}
static int valid(void *context, uint8_t instance, uint16_t hw_id)
{
 const struct amdgpu_discovery_ip_ops ops = {.context=context,.error=error};
 return amdgpu_discovery_ip_valid(&ops, instance, hw_id);
}
static int range(const void *p, size_t bytes, uintptr_t *start, uintptr_t *end)
{
 *start = (uintptr_t)p;
 if (!p || bytes > UINTPTR_MAX - *start) return 0;
 *end = *start + bytes;
 return 1;
}
static struct stela_amd_discovery_info_table schema(const struct info_context *c, uint16_t id)
{
 struct stela_amd_discovery_info_table out={0};
 const struct table_info *t=amdgpu_discovery_binary_table(c->raw,c->bytes,id);
 if (!t) {out.status=-EINVAL; return out;}
 if (!t->offset) return out;
 const struct gpu_info_header *h=(const void *)(c->raw+t->offset);
 out.present=1; out.major=h->version_major;out.minor=h->version_minor;
 return out;
}
int stela_amd_discovery_info_decode(const uint8_t *raw, size_t bytes,
 const uint32_t *versions, size_t version_count,
 const struct stela_amd_ip_counts *counts, uint16_t pci_device, uint8_t pci_revision,
 struct stela_amd_discovery_info *out)
{
 uintptr_t start[4],end[4];
 const size_t cells=MAX_HWIP*HWIP_MAX_INSTANCE;
 if (version_count<cells || (uintptr_t)versions%_Alignof(uint32_t) ||
     (uintptr_t)counts%_Alignof(struct stela_amd_ip_counts) ||
     (uintptr_t)out%_Alignof(struct stela_amd_discovery_info) ||
     !range(raw,bytes,&start[0],&end[0]) ||
     !range(versions,cells*sizeof(*versions),&start[1],&end[1]) ||
     !range(counts,sizeof(*counts),&start[2],&end[2]) ||
     !range(out,sizeof(*out),&start[3],&end[3])) return -EINVAL;
 for (unsigned i=0;i<4;i++) for (unsigned j=i+1;j<4;j++)
  if (start[i]<end[j] && start[j]<end[i]) return -EINVAL;
 if (amdgpu_discovery_binary_validate(raw,bytes) ||
     counts->vcn_count>AMDGPU_MAX_VCN_INSTANCES || counts->umc_count<0 ||
     counts->umc_count>=64 || counts->node_count>=64) return -EINVAL;
 const struct table_info *mall=amdgpu_discovery_binary_table(raw,bytes,MALL_INFO);
 if (mall && mall->offset && counts->umc_count>32 &&
     ((const struct mall_info_header *)(raw+mall->offset))->version_major==1) return -EINVAL;
 struct stela_amd_discovery_info result={0};
 result.counts=*counts;
 struct amdgpu_gfx_config config={0};
 struct amdgpu_cu_info cu_info={0};
 struct info_context context={.raw=raw,.bytes=bytes};
 struct amdgpu_discovery_info_targets t={
  .binary=(uint8_t *)raw, .ip_versions=(const uint32_t (*)[HWIP_MAX_INSTANCE])versions,
  .pci_device=pci_device,.pci_revision=pci_revision,
  .xcc_mask=&result.counts.xcc_mask,.vcn_mask=&result.counts.vcn_mask,
  .jpeg_mask=&result.counts.jpeg_mask,.sdma_mask=&result.counts.sdma_mask,
  .vcn_count=&result.counts.vcn_count,.node_count=&result.counts.node_count,
  .umc_count=&result.counts.umc_count,.active_mask=&result.active_umc_mask,
  .vcn_harvest=&result.vcn_harvest,.jpeg_harvest=&result.jpeg_harvest,
  .isp_harvest=&result.isp_harvest,.harvest_mask=&result.harvest_mask,
  .mall_size=&result.mall_size,.half_use=&result.half_use,
  .config=&config,.cu_info=&cu_info,
 };
 for (unsigned i=0;i<AMDGPU_MAX_VCN_INSTANCES;i++) t.codec_disable[i]=&result.codec_disable[i];
 const struct amdgpu_discovery_info_ops ops={.context=&context,.table=lookup_table,.valid_ip=valid,.error=error,.warn=warn};
 /* Preserve original order and nonfatal helper returns. */
 amdgpu_discovery_harvest_ip_core(&t,&ops);
 result.harvest_errors=context.errors;result.harvest_warnings=context.warnings;
 result.gfx=schema(&context,GC);
 result.gfx.status=amdgpu_discovery_get_gfx_info_core(&t,&ops);
 result.mall=schema(&context,MALL_INFO);
 result.mall.status=amdgpu_discovery_get_mall_info_core(&t,&ops);
 result.vcn=schema(&context,VCN_INFO);
 result.vcn.status=amdgpu_discovery_get_vcn_info_core(&t,&ops);
#if defined(CONFIG_DRM_AMD_ISP)
 result.isp_build_enabled=1;
#endif
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_MAX_SHADER_ENGINES;
 result.gfx_values[STELA_AMD_GFX_MAX_SHADER_ENGINES]=config.max_shader_engines;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_MAX_CU_PER_SH;
 result.gfx_values[STELA_AMD_GFX_MAX_CU_PER_SH]=config.max_cu_per_sh;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_MAX_SH_PER_SE;
 result.gfx_values[STELA_AMD_GFX_MAX_SH_PER_SE]=config.max_sh_per_se;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_MAX_BACKENDS_PER_SE;
 result.gfx_values[STELA_AMD_GFX_MAX_BACKENDS_PER_SE]=config.max_backends_per_se;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_MAX_TEXTURE_CHANNEL_CACHES;
 result.gfx_values[STELA_AMD_GFX_MAX_TEXTURE_CHANNEL_CACHES]=config.max_texture_channel_caches;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_MAX_GPRS;
 result.gfx_values[STELA_AMD_GFX_MAX_GPRS]=config.max_gprs;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_MAX_GS_THREADS;
 result.gfx_values[STELA_AMD_GFX_MAX_GS_THREADS]=config.max_gs_threads;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GS_VGT_TABLE_DEPTH;
 result.gfx_values[STELA_AMD_GFX_GS_VGT_TABLE_DEPTH]=config.gs_vgt_table_depth;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GS_PRIM_BUFFER_DEPTH;
 result.gfx_values[STELA_AMD_GFX_GS_PRIM_BUFFER_DEPTH]=config.gs_prim_buffer_depth;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_DOUBLE_OFFCHIP_LDS_BUF;
 result.gfx_values[STELA_AMD_GFX_DOUBLE_OFFCHIP_LDS_BUF]=config.double_offchip_lds_buf;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_WAVE_FRONT_SIZE;
 result.gfx_values[STELA_AMD_GFX_WAVE_FRONT_SIZE]=cu_info.wave_front_size;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_MAX_WAVES_PER_SIMD;
 result.gfx_values[STELA_AMD_GFX_MAX_WAVES_PER_SIMD]=cu_info.max_waves_per_simd;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_MAX_SCRATCH_SLOTS_PER_CU;
 result.gfx_values[STELA_AMD_GFX_MAX_SCRATCH_SLOTS_PER_CU]=cu_info.max_scratch_slots_per_cu;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_LDS_SIZE;
 result.gfx_values[STELA_AMD_GFX_LDS_SIZE]=cu_info.lds_size;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_NUM_SC_PER_SH;
 result.gfx_values[STELA_AMD_GFX_NUM_SC_PER_SH]=config.num_sc_per_sh;
 if (result.gfx.present && !result.gfx.status && (result.gfx.major==1 || result.gfx.major==2)) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_NUM_PACKER_PER_SC;
 result.gfx_values[STELA_AMD_GFX_NUM_PACKER_PER_SC]=config.num_packer_per_sc;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=1) || (result.gfx.major==2 && result.gfx.minor==1))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_NUM_TCP_PER_SA;
 result.gfx_values[STELA_AMD_GFX_GC_NUM_TCP_PER_SA]=config.gc_num_tcp_per_sa;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=1) || (result.gfx.major==2 && result.gfx.minor==1))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_NUM_SDP_INTERFACE;
 result.gfx_values[STELA_AMD_GFX_GC_NUM_SDP_INTERFACE]=config.gc_num_sdp_interface;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=1))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_NUM_TCPS;
 result.gfx_values[STELA_AMD_GFX_GC_NUM_TCPS]=config.gc_num_tcps;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=2))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_NUM_TCP_PER_WPG;
 result.gfx_values[STELA_AMD_GFX_GC_NUM_TCP_PER_WPG]=config.gc_num_tcp_per_wpg;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=2))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_TCP_L1_SIZE;
 result.gfx_values[STELA_AMD_GFX_GC_TCP_L1_SIZE]=config.gc_tcp_l1_size;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=2))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_NUM_SQC_PER_WGP;
 result.gfx_values[STELA_AMD_GFX_GC_NUM_SQC_PER_WGP]=config.gc_num_sqc_per_wgp;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=2) || (result.gfx.major==2 && result.gfx.minor==1))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_L1_INSTRUCTION_CACHE_SIZE_PER_SQC;
 result.gfx_values[STELA_AMD_GFX_GC_L1_INSTRUCTION_CACHE_SIZE_PER_SQC]=config.gc_l1_instruction_cache_size_per_sqc;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=2) || (result.gfx.major==2 && result.gfx.minor==1))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_L1_DATA_CACHE_SIZE_PER_SQC;
 result.gfx_values[STELA_AMD_GFX_GC_L1_DATA_CACHE_SIZE_PER_SQC]=config.gc_l1_data_cache_size_per_sqc;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=2))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_GL1C_PER_SA;
 result.gfx_values[STELA_AMD_GFX_GC_GL1C_PER_SA]=config.gc_gl1c_per_sa;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=2))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_GL1C_SIZE_PER_INSTANCE;
 result.gfx_values[STELA_AMD_GFX_GC_GL1C_SIZE_PER_INSTANCE]=config.gc_gl1c_size_per_instance;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=2))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_GL2C_PER_GPU;
 result.gfx_values[STELA_AMD_GFX_GC_GL2C_PER_GPU]=config.gc_gl2c_per_gpu;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=3) || (result.gfx.major==2 && result.gfx.minor==1))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_TCP_SIZE_PER_CU;
 result.gfx_values[STELA_AMD_GFX_GC_TCP_SIZE_PER_CU]=config.gc_tcp_size_per_cu;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=3))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_TCP_CACHE_LINE_SIZE;
 result.gfx_values[STELA_AMD_GFX_GC_TCP_CACHE_LINE_SIZE]=config.gc_tcp_cache_line_size;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=3))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_INSTRUCTION_CACHE_SIZE_PER_SQC;
 result.gfx_values[STELA_AMD_GFX_GC_INSTRUCTION_CACHE_SIZE_PER_SQC]=config.gc_instruction_cache_size_per_sqc;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=3))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_INSTRUCTION_CACHE_LINE_SIZE;
 result.gfx_values[STELA_AMD_GFX_GC_INSTRUCTION_CACHE_LINE_SIZE]=config.gc_instruction_cache_line_size;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=3))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_SCALAR_DATA_CACHE_SIZE_PER_SQC;
 result.gfx_values[STELA_AMD_GFX_GC_SCALAR_DATA_CACHE_SIZE_PER_SQC]=config.gc_scalar_data_cache_size_per_sqc;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=3))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_SCALAR_DATA_CACHE_LINE_SIZE;
 result.gfx_values[STELA_AMD_GFX_GC_SCALAR_DATA_CACHE_LINE_SIZE]=config.gc_scalar_data_cache_line_size;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=3) || (result.gfx.major==2 && result.gfx.minor==1))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_TCC_SIZE;
 result.gfx_values[STELA_AMD_GFX_GC_TCC_SIZE]=config.gc_tcc_size;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==1 && result.gfx.minor>=3))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_TCC_CACHE_LINE_SIZE;
 result.gfx_values[STELA_AMD_GFX_GC_TCC_CACHE_LINE_SIZE]=config.gc_tcc_cache_line_size;
 if (result.gfx.present && !result.gfx.status && ((result.gfx.major==2 && result.gfx.minor==1))) result.gfx_supplied|=UINT64_C(1)<<STELA_AMD_GFX_GC_NUM_CU_PER_SQC;
 result.gfx_values[STELA_AMD_GFX_GC_NUM_CU_PER_SQC]=config.gc_num_cu_per_sqc;
 *out=result;
 return 0;
}
