/* SPDX-License-Identifier: MIT */
/* CPU-only full original/current consumer oracle; no hardware/provider calls. */
#include "../stela/discovery_info.h"
#include "../stela/discovery_binary.h"
#include "../amdgpu/amdgpu_discovery_info_core.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
struct va_format { const char *fmt; va_list *va; };
struct amdgpu_device {
 void *dev;
 struct { uint16_t device; uint8_t revision; } *pdev;
 struct { uint8_t *bin; size_t size; } discovery;
 struct { uint16_t xcc_mask; struct amdgpu_gfx_config config; struct amdgpu_cu_info cu_info; } gfx;
 struct { uint16_t inst_mask; unsigned harvest_config; uint8_t num_vcn_inst;
  struct {uint32_t vcn_codec_disable_mask;} inst[4]; } vcn;
 struct { uint16_t inst_mask; unsigned harvest_config; } jpeg;
 struct {unsigned harvest_config;} isp;
 struct {uint32_t sdma_mask;} sdma;
 struct {int num_umc;uint64_t mall_size;uint32_t m_half_use;} gmc;
 struct {uint32_t node_inst_num;amdgpu_discovery_umc_mask active_mask;} umc;
 uint32_t harvest_ip_mask;
 uint32_t ip_versions[MAX_HWIP][HWIP_MAX_INSTANCE];
};
_Static_assert(sizeof(unsigned long)==8,"original modeled x86-64 Linux ABI");
static char logs[2][32768];static size_t log_at[2];static unsigned current;
static unsigned errors[2],warnings[2],harvest_errors[2],harvest_warnings[2];
static int fail_table=-1;static unsigned lookups[2];
static void log_message(const char *format, va_list args)
{
 if (!strcmp(format,"%pV")) {
  struct va_format *v=va_arg(args,struct va_format *);
  log_at[current]+=(size_t)vsnprintf(logs[current]+log_at[current],sizeof(logs[current])-log_at[current],v->fmt,*v->va);
 } else log_at[current]+=(size_t)vsnprintf(logs[current]+log_at[current],sizeof(logs[current])-log_at[current],format,args);
 assert(log_at[current]<sizeof(logs[current]));
}
static void log_debug(const char *format,...) {va_list a;va_start(a,format);log_message(format,a);va_end(a);}
static void log_error(void *device,const char *format,...) {errors[current]++;(void)device;va_list a;va_start(a,format);log_message(format,a);va_end(a);}
#define DRM_ERROR(...) log_debug(__VA_ARGS__)
#define dev_err(...) log_error(__VA_ARGS__)
static void log_warn(void *device,const char *format,...) {warnings[current]++;(void)device;va_list a;va_start(a,format);log_message(format,a);va_end(a);}
#define dev_warn(...) log_warn(__VA_ARGS__)
static uint32_t amdgpu_ip_version(const struct amdgpu_device *a,uint8_t ip,uint8_t inst) {return a->ip_versions[ip][inst]&~0xffU;}
static int amdgpu_discovery_validate_ip(struct amdgpu_device *a,uint8_t inst,uint16_t id)
{const struct amdgpu_discovery_ip_ops ops={.context=a,.error=log_error};return amdgpu_discovery_ip_valid(&ops,inst,id);}
static int amdgpu_discovery_get_table_info(struct amdgpu_device *a,struct table_info **out,uint16_t id)
{lookups[current]++;if (id==fail_table)return -EINVAL;*out=(void*)amdgpu_discovery_binary_table(a->discovery.bin,a->discovery.size,id);return *out?0:-EINVAL;}
#include "discovery_info_reference.h"
#include "discovery_info_legacy_reference.h"
#include "info-linux.inc"
size_t stela_amd_info_fixture(uint8_t*,size_t,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned);
static unsigned comparisons,native_cases,refused,upstream_legacy;
static void run(struct amdgpu_device *a,int status[3],bool donor)
{
 errors[current]=warnings[current]=0;
 if(donor) {
 donor_amdgpu_discovery_harvest_ip(a);
 harvest_errors[current]=errors[current];harvest_warnings[current]=warnings[current];
 status[0]=donor_amdgpu_discovery_get_gfx_info(a);
 status[1]=donor_amdgpu_discovery_get_mall_info(a);
 status[2]=donor_amdgpu_discovery_get_vcn_info(a);
 } else {
 amdgpu_discovery_harvest_ip(a);
 harvest_errors[current]=errors[current];harvest_warnings[current]=warnings[current];
 status[0]=amdgpu_discovery_get_gfx_info(a);
 status[1]=amdgpu_discovery_get_mall_info(a);
 status[2]=amdgpu_discovery_get_vcn_info(a);
 }
}
static void compare(const uint8_t *raw,size_t bytes,unsigned device,unsigned revision,unsigned state)
{
 uint8_t *work=malloc(bytes);assert(work);memcpy(work,raw,bytes);
 uint32_t versions[MAX_HWIP][HWIP_MAX_INSTANCE];struct stela_amd_ip_binding bindings[MAX_HWIP*HWIP_MAX_INSTANCE];
 struct stela_amd_ip_counts counts;
 assert(!stela_amd_discovery_ip_decode(work,bytes,&versions[0][0],MAX_HWIP*HWIP_MAX_INSTANCE,bindings,MAX_HWIP*HWIP_MAX_INSTANCE,&counts));
 struct amdgpu_device a={0};
 a.discovery.bin=work;a.discovery.size=bytes;
 __typeof__(*a.pdev) pci={(uint16_t)device,(uint8_t)revision};a.pdev=&pci;
 a.gfx.xcc_mask=counts.xcc_mask;a.vcn.inst_mask=counts.vcn_mask;a.jpeg.inst_mask=counts.jpeg_mask;
 a.vcn.num_vcn_inst=counts.vcn_count;a.sdma.sdma_mask=counts.sdma_mask;
 a.gmc.num_umc=counts.umc_count;a.umc.node_inst_num=counts.node_count;
 memcpy(a.ip_versions,versions,sizeof(versions));
 if(state) {
  memset(&a.gfx.config,0xa5,sizeof(a.gfx.config));memset(&a.gfx.cu_info,0x56,sizeof(a.gfx.cu_info));
  a.vcn.harvest_config=0xa011;a.jpeg.harvest_config=0x400;a.harvest_ip_mask=0x20;
  a.umc.active_mask=0xa5;a.gmc.mall_size=123;a.gmc.m_half_use=456;
  for(unsigned i=0;i<4;i++)a.vcn.inst[i].vcn_codec_disable_mask=0xfeed+i;
 }
 struct amdgpu_device b=a;int left[3],right[3];
 memset(logs,0,sizeof(logs));memset(log_at,0,sizeof(log_at));memset(lookups,0,sizeof(lookups));
 current=0;run(&a,left,true);current=1;run(&b,right,false);
 assert(!memcmp(left,right,sizeof(left)));assert(!memcmp(&a,&b,sizeof(a)));
 assert(lookups[0]==lookups[1]);assert(log_at[0]==log_at[1]&&!memcmp(logs[0],logs[1],log_at[0]));comparisons++;
 if(!state && fail_table<0) {
  struct stela_amd_discovery_info out;
  memset(&out,0xc1,sizeof(out));
  assert(!stela_amd_discovery_info_decode(raw,bytes,&versions[0][0],MAX_HWIP*HWIP_MAX_INSTANCE,&counts,pci.device,pci.revision,&out));
  assert(out.counts.xcc_mask==a.gfx.xcc_mask && out.counts.vcn_mask==a.vcn.inst_mask && out.counts.jpeg_mask==a.jpeg.inst_mask);
  assert(out.counts.umc_count==a.gmc.num_umc && out.counts.sdma_mask==a.sdma.sdma_mask);
  assert(out.vcn_harvest==a.vcn.harvest_config && out.jpeg_harvest==a.jpeg.harvest_config && out.harvest_mask==a.harvest_ip_mask);
  assert(out.active_umc_mask==a.umc.active_mask && out.mall_size==a.gmc.mall_size && out.half_use==a.gmc.m_half_use);
  assert(out.gfx.status==left[0] && out.mall.status==left[1] && out.vcn.status==left[2]);
  for(unsigned i=0;i<4;i++)assert(out.codec_disable[i]==a.vcn.inst[i].vcn_codec_disable_mask);
  assert(out.gfx_values[0]==a.gfx.config.max_shader_engines);
  assert(out.gfx_values[1]==a.gfx.config.max_cu_per_sh);
  assert(out.gfx_values[2]==a.gfx.config.max_sh_per_se);
  assert(out.gfx_values[3]==a.gfx.config.max_backends_per_se);
  assert(out.gfx_values[4]==a.gfx.config.max_texture_channel_caches);
  assert(out.gfx_values[5]==a.gfx.config.max_gprs);
  assert(out.gfx_values[6]==a.gfx.config.max_gs_threads);
  assert(out.gfx_values[7]==a.gfx.config.gs_vgt_table_depth);
  assert(out.gfx_values[8]==a.gfx.config.gs_prim_buffer_depth);
  assert(out.gfx_values[9]==a.gfx.config.double_offchip_lds_buf);
  assert(out.gfx_values[10]==a.gfx.cu_info.wave_front_size);
  assert(out.gfx_values[11]==a.gfx.cu_info.max_waves_per_simd);
  assert(out.gfx_values[12]==a.gfx.cu_info.max_scratch_slots_per_cu);
  assert(out.gfx_values[13]==a.gfx.cu_info.lds_size);
  assert(out.gfx_values[14]==a.gfx.config.num_sc_per_sh);
  assert(out.gfx_values[15]==a.gfx.config.num_packer_per_sc);
  assert(out.gfx_values[16]==a.gfx.config.gc_num_tcp_per_sa);
  assert(out.gfx_values[17]==a.gfx.config.gc_num_sdp_interface);
  assert(out.gfx_values[18]==a.gfx.config.gc_num_tcps);
  assert(out.gfx_values[19]==a.gfx.config.gc_num_tcp_per_wpg);
  assert(out.gfx_values[20]==a.gfx.config.gc_tcp_l1_size);
  assert(out.gfx_values[21]==a.gfx.config.gc_num_sqc_per_wgp);
  assert(out.gfx_values[22]==a.gfx.config.gc_l1_instruction_cache_size_per_sqc);
  assert(out.gfx_values[23]==a.gfx.config.gc_l1_data_cache_size_per_sqc);
  assert(out.gfx_values[24]==a.gfx.config.gc_gl1c_per_sa);
  assert(out.gfx_values[25]==a.gfx.config.gc_gl1c_size_per_instance);
  assert(out.gfx_values[26]==a.gfx.config.gc_gl2c_per_gpu);
  assert(out.gfx_values[27]==a.gfx.config.gc_tcp_size_per_cu);
  assert(out.gfx_values[28]==a.gfx.config.gc_tcp_cache_line_size);
  assert(out.gfx_values[29]==a.gfx.config.gc_instruction_cache_size_per_sqc);
  assert(out.gfx_values[30]==a.gfx.config.gc_instruction_cache_line_size);
  assert(out.gfx_values[31]==a.gfx.config.gc_scalar_data_cache_size_per_sqc);
  assert(out.gfx_values[32]==a.gfx.config.gc_scalar_data_cache_line_size);
  assert(out.gfx_values[33]==a.gfx.config.gc_tcc_size);
  assert(out.gfx_values[34]==a.gfx.config.gc_tcc_cache_line_size);
  assert(out.gfx_values[35]==a.gfx.config.gc_num_cu_per_sqc);
  struct amdgpu_device supplied=a;
  memset(&supplied.gfx.config,0x5a,sizeof(supplied.gfx.config));
  memset(&supplied.gfx.cu_info,0x5a,sizeof(supplied.gfx.cu_info));
  (void)donor_amdgpu_discovery_get_gfx_info(&supplied);
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<0))==(supplied.gfx.config.max_shader_engines!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<1))==(supplied.gfx.config.max_cu_per_sh!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<2))==(supplied.gfx.config.max_sh_per_se!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<3))==(supplied.gfx.config.max_backends_per_se!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<4))==(supplied.gfx.config.max_texture_channel_caches!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<5))==(supplied.gfx.config.max_gprs!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<6))==(supplied.gfx.config.max_gs_threads!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<7))==(supplied.gfx.config.gs_vgt_table_depth!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<8))==(supplied.gfx.config.gs_prim_buffer_depth!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<9))==(supplied.gfx.config.double_offchip_lds_buf!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<10))==(supplied.gfx.cu_info.wave_front_size!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<11))==(supplied.gfx.cu_info.max_waves_per_simd!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<12))==(supplied.gfx.cu_info.max_scratch_slots_per_cu!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<13))==(supplied.gfx.cu_info.lds_size!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<14))==(supplied.gfx.config.num_sc_per_sh!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<15))==(supplied.gfx.config.num_packer_per_sc!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<16))==(supplied.gfx.config.gc_num_tcp_per_sa!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<17))==(supplied.gfx.config.gc_num_sdp_interface!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<18))==(supplied.gfx.config.gc_num_tcps!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<19))==(supplied.gfx.config.gc_num_tcp_per_wpg!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<20))==(supplied.gfx.config.gc_tcp_l1_size!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<21))==(supplied.gfx.config.gc_num_sqc_per_wgp!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<22))==(supplied.gfx.config.gc_l1_instruction_cache_size_per_sqc!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<23))==(supplied.gfx.config.gc_l1_data_cache_size_per_sqc!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<24))==(supplied.gfx.config.gc_gl1c_per_sa!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<25))==(supplied.gfx.config.gc_gl1c_size_per_instance!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<26))==(supplied.gfx.config.gc_gl2c_per_gpu!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<27))==(supplied.gfx.config.gc_tcp_size_per_cu!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<28))==(supplied.gfx.config.gc_tcp_cache_line_size!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<29))==(supplied.gfx.config.gc_instruction_cache_size_per_sqc!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<30))==(supplied.gfx.config.gc_instruction_cache_line_size!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<31))==(supplied.gfx.config.gc_scalar_data_cache_size_per_sqc!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<32))==(supplied.gfx.config.gc_scalar_data_cache_line_size!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<33))==(supplied.gfx.config.gc_tcc_size!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<34))==(supplied.gfx.config.gc_tcc_cache_line_size!=UINT32_C(0x5a5a5a5a)));
  assert(!!(out.gfx_supplied&(UINT64_C(1)<<35))==(supplied.gfx.config.gc_num_cu_per_sqc!=UINT32_C(0x5a5a5a5a)));
  assert(out.harvest_errors==harvest_errors[0] && out.harvest_warnings==harvest_warnings[0]);
  native_cases++;
 }
 const struct binary_header *bh=(const void*)raw;
 const struct table_info *ti=amdgpu_discovery_binary_table(raw,bytes,IP_DISCOVERY);
 const struct ip_discovery_header *ih=(const void*)(raw+ti->offset);
 if(fail_table<0 && bh->version_major<=1 && ih->version<=2 && !ih->base_addr_64_bit) {
  uint32_t lc=0,rc=0;struct amdgpu_device x=a,y=a;
  current=0;log_at[0]=0;upstream_amdgpu_discovery_read_harvest_bit_per_ip(&x,&lc);
  current=1;log_at[1]=0;donor_amdgpu_discovery_read_harvest_bit_per_ip(&y,&rc);
  assert(lc==rc && !memcmp(&x,&y,sizeof(x)));assert(log_at[0]==log_at[1]&&!memcmp(logs[0],logs[1],log_at[0]));upstream_legacy++;
 }
 free(work);
}
void stela_amd_info_oracle(const uint8_t *raw,size_t bytes,uint16_t device,uint8_t revision,struct stela_amd_discovery_info *out)
{
 uint8_t *work=malloc(bytes);assert(work);memcpy(work,raw,bytes);
 struct stela_amd_ip_counts counts;struct stela_amd_ip_binding bindings[MAX_HWIP*HWIP_MAX_INSTANCE];
 struct amdgpu_device a={0};__typeof__(*a.pdev) pci={device,revision};
 a.pdev=&pci;a.discovery.bin=work;a.discovery.size=bytes;
 assert(!stela_amd_discovery_ip_decode(work,bytes,&a.ip_versions[0][0],MAX_HWIP*HWIP_MAX_INSTANCE,bindings,MAX_HWIP*HWIP_MAX_INSTANCE,&counts));
 a.gfx.xcc_mask=counts.xcc_mask;a.vcn.inst_mask=counts.vcn_mask;a.jpeg.inst_mask=counts.jpeg_mask;
 a.vcn.num_vcn_inst=counts.vcn_count;a.sdma.sdma_mask=counts.sdma_mask;a.gmc.num_umc=counts.umc_count;a.umc.node_inst_num=counts.node_count;
 int statuses[3];current=0;log_at[0]=0;run(&a,statuses,true);
 memset(out,0,sizeof(*out));out->counts=counts;
 out->counts.xcc_mask=a.gfx.xcc_mask;out->counts.vcn_mask=a.vcn.inst_mask;out->counts.jpeg_mask=a.jpeg.inst_mask;
 out->counts.sdma_mask=a.sdma.sdma_mask;out->counts.umc_count=a.gmc.num_umc;
 out->harvest_errors=harvest_errors[0];out->harvest_warnings=harvest_warnings[0];
 out->harvest_mask=a.harvest_ip_mask;out->vcn_harvest=a.vcn.harvest_config;out->jpeg_harvest=a.jpeg.harvest_config;out->isp_harvest=a.isp.harvest_config;
 out->active_umc_mask=a.umc.active_mask;out->mall_size=a.gmc.mall_size;out->half_use=a.gmc.m_half_use;
 for(unsigned i=0;i<4;i++)out->codec_disable[i]=a.vcn.inst[i].vcn_codec_disable_mask;
 struct stela_amd_discovery_info_table *tables[]={&out->gfx,&out->mall,&out->vcn};unsigned ids[]={GC,MALL_INFO,VCN_INFO};
 for(unsigned i=0;i<3;i++) {
  tables[i]->status=statuses[i];const struct table_info *t=amdgpu_discovery_binary_table(raw,bytes,ids[i]);
  if(t && t->offset) {const struct gpu_info_header *h=(const void*)(raw+t->offset);tables[i]->present=1;tables[i]->major=h->version_major;tables[i]->minor=h->version_minor;}
 }
 struct amdgpu_device supplied=a;memset(&supplied.gfx.config,0x5a,sizeof(supplied.gfx.config));memset(&supplied.gfx.cu_info,0x5a,sizeof(supplied.gfx.cu_info));
 (void)donor_amdgpu_discovery_get_gfx_info(&supplied);
 out->gfx_values[0]=a.gfx.config.max_shader_engines;if(supplied.gfx.config.max_shader_engines!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<0;
 out->gfx_values[1]=a.gfx.config.max_cu_per_sh;if(supplied.gfx.config.max_cu_per_sh!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<1;
 out->gfx_values[2]=a.gfx.config.max_sh_per_se;if(supplied.gfx.config.max_sh_per_se!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<2;
 out->gfx_values[3]=a.gfx.config.max_backends_per_se;if(supplied.gfx.config.max_backends_per_se!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<3;
 out->gfx_values[4]=a.gfx.config.max_texture_channel_caches;if(supplied.gfx.config.max_texture_channel_caches!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<4;
 out->gfx_values[5]=a.gfx.config.max_gprs;if(supplied.gfx.config.max_gprs!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<5;
 out->gfx_values[6]=a.gfx.config.max_gs_threads;if(supplied.gfx.config.max_gs_threads!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<6;
 out->gfx_values[7]=a.gfx.config.gs_vgt_table_depth;if(supplied.gfx.config.gs_vgt_table_depth!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<7;
 out->gfx_values[8]=a.gfx.config.gs_prim_buffer_depth;if(supplied.gfx.config.gs_prim_buffer_depth!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<8;
 out->gfx_values[9]=a.gfx.config.double_offchip_lds_buf;if(supplied.gfx.config.double_offchip_lds_buf!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<9;
 out->gfx_values[10]=a.gfx.cu_info.wave_front_size;if(supplied.gfx.cu_info.wave_front_size!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<10;
 out->gfx_values[11]=a.gfx.cu_info.max_waves_per_simd;if(supplied.gfx.cu_info.max_waves_per_simd!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<11;
 out->gfx_values[12]=a.gfx.cu_info.max_scratch_slots_per_cu;if(supplied.gfx.cu_info.max_scratch_slots_per_cu!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<12;
 out->gfx_values[13]=a.gfx.cu_info.lds_size;if(supplied.gfx.cu_info.lds_size!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<13;
 out->gfx_values[14]=a.gfx.config.num_sc_per_sh;if(supplied.gfx.config.num_sc_per_sh!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<14;
 out->gfx_values[15]=a.gfx.config.num_packer_per_sc;if(supplied.gfx.config.num_packer_per_sc!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<15;
 out->gfx_values[16]=a.gfx.config.gc_num_tcp_per_sa;if(supplied.gfx.config.gc_num_tcp_per_sa!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<16;
 out->gfx_values[17]=a.gfx.config.gc_num_sdp_interface;if(supplied.gfx.config.gc_num_sdp_interface!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<17;
 out->gfx_values[18]=a.gfx.config.gc_num_tcps;if(supplied.gfx.config.gc_num_tcps!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<18;
 out->gfx_values[19]=a.gfx.config.gc_num_tcp_per_wpg;if(supplied.gfx.config.gc_num_tcp_per_wpg!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<19;
 out->gfx_values[20]=a.gfx.config.gc_tcp_l1_size;if(supplied.gfx.config.gc_tcp_l1_size!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<20;
 out->gfx_values[21]=a.gfx.config.gc_num_sqc_per_wgp;if(supplied.gfx.config.gc_num_sqc_per_wgp!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<21;
 out->gfx_values[22]=a.gfx.config.gc_l1_instruction_cache_size_per_sqc;if(supplied.gfx.config.gc_l1_instruction_cache_size_per_sqc!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<22;
 out->gfx_values[23]=a.gfx.config.gc_l1_data_cache_size_per_sqc;if(supplied.gfx.config.gc_l1_data_cache_size_per_sqc!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<23;
 out->gfx_values[24]=a.gfx.config.gc_gl1c_per_sa;if(supplied.gfx.config.gc_gl1c_per_sa!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<24;
 out->gfx_values[25]=a.gfx.config.gc_gl1c_size_per_instance;if(supplied.gfx.config.gc_gl1c_size_per_instance!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<25;
 out->gfx_values[26]=a.gfx.config.gc_gl2c_per_gpu;if(supplied.gfx.config.gc_gl2c_per_gpu!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<26;
 out->gfx_values[27]=a.gfx.config.gc_tcp_size_per_cu;if(supplied.gfx.config.gc_tcp_size_per_cu!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<27;
 out->gfx_values[28]=a.gfx.config.gc_tcp_cache_line_size;if(supplied.gfx.config.gc_tcp_cache_line_size!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<28;
 out->gfx_values[29]=a.gfx.config.gc_instruction_cache_size_per_sqc;if(supplied.gfx.config.gc_instruction_cache_size_per_sqc!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<29;
 out->gfx_values[30]=a.gfx.config.gc_instruction_cache_line_size;if(supplied.gfx.config.gc_instruction_cache_line_size!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<30;
 out->gfx_values[31]=a.gfx.config.gc_scalar_data_cache_size_per_sqc;if(supplied.gfx.config.gc_scalar_data_cache_size_per_sqc!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<31;
 out->gfx_values[32]=a.gfx.config.gc_scalar_data_cache_line_size;if(supplied.gfx.config.gc_scalar_data_cache_line_size!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<32;
 out->gfx_values[33]=a.gfx.config.gc_tcc_size;if(supplied.gfx.config.gc_tcc_size!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<33;
 out->gfx_values[34]=a.gfx.config.gc_tcc_cache_line_size;if(supplied.gfx.config.gc_tcc_cache_line_size!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<34;
 out->gfx_values[35]=a.gfx.config.gc_num_cu_per_sqc;if(supplied.gfx.config.gc_num_cu_per_sqc!=UINT32_C(0x5a5a5a5a))out->gfx_supplied|=UINT64_C(1)<<35;
#if defined(CONFIG_DRM_AMD_ISP)
 out->isp_build_enabled=1;
#endif
 free(work);
}
static void atomic_cases(const uint8_t *raw,size_t bytes)
{
 uint8_t *data=malloc(bytes);assert(data);memcpy(data,raw,bytes);
 uint32_t versions[MAX_HWIP*HWIP_MAX_INSTANCE]={0};struct stela_amd_ip_counts c={0};
 struct stela_amd_discovery_info out,old;memset(&out,0xb7,sizeof(out));memcpy(&old,&out,sizeof(old));
 for(size_t size=0;size<bytes;size++) {
  assert(stela_amd_discovery_info_decode(data,size,versions,MAX_HWIP*HWIP_MAX_INSTANCE,&c,0,0,&out));assert(!memcmp(&out,&old,sizeof(out)));refused++;
 }
 for(size_t i=0;i<bytes;i++) {
  data[i]^=1;int s=stela_amd_discovery_info_decode(data,bytes,versions,MAX_HWIP*HWIP_MAX_INSTANCE,&c,0,0,&out);
  if(s){assert(!memcmp(&out,&old,sizeof(out)));refused++;}else memcpy(&out,&old,sizeof(out));data[i]^=1;
 }
 assert(stela_amd_discovery_info_decode(raw,bytes,versions,0,&c,0,0,&out));
 assert(!memcmp(&out,&old,sizeof(out)));refused++;
 assert(stela_amd_discovery_info_decode(raw,bytes,versions,MAX_HWIP*HWIP_MAX_INSTANCE,&c,0,0,(void*)raw));refused++;
 c.node_count=64;assert(stela_amd_discovery_info_decode(raw,bytes,versions,MAX_HWIP*HWIP_MAX_INSTANCE,&c,0,0,&out));assert(!memcmp(&out,&old,sizeof(out)));refused++;
 struct stela_amd_ip_counts invalid[]={ {.vcn_count=5}, {.umc_count=-1}, {.umc_count=64}, {.node_count=64} };
 for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
  assert(stela_amd_discovery_info_decode(raw,bytes,versions,MAX_HWIP*HWIP_MAX_INSTANCE,&invalid[i],0,0,&out));
  assert(!memcmp(&out,&old,sizeof(out)));refused++;
 }
 assert(stela_amd_discovery_info_decode(raw,bytes,versions,MAX_HWIP*HWIP_MAX_INSTANCE,&c,0,0,(void*)versions));refused++;
 assert(stela_amd_discovery_info_decode(raw,bytes,(void*)((uint8_t*)versions+1),MAX_HWIP*HWIP_MAX_INSTANCE,&c,0,0,&out));refused++;
 assert(!memcmp(&out,&old,sizeof(out)));
 free(data);
}
int main(int argc,char **argv)
{
 uint8_t raw[65536];
 unsigned gc[][2]={{1,0},{1,1},{1,2},{1,3},{1,9},{2,0},{2,1},{2,2},{3,0}};
 unsigned devices[]={0,0x731e,0x7340,0x7360};unsigned revisions[]={0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xcf,0xdf,0xff};
 for(unsigned v=0;v<3;v++)for(unsigned ip=1;ip<=4;ip++)for(unsigned g=0;g<9;g++)for(unsigned p=0;p<128;p++) {
  size_t bytes=stela_amd_info_fixture(raw,sizeof(raw),v,ip,0,gc[g][0],gc[g][1],p);
  assert(!amdgpu_discovery_binary_validate(raw,bytes));
  compare(raw,bytes,devices[p%4],revisions[p%11],0);
  if(!p){for(int e=-1;e<TOTAL_TABLES;e++){fail_table=e;compare(raw,bytes,0,0,1);}fail_table=-1;}
 }
 for(unsigned ip=1;ip<=4;ip++) {
  size_t n=stela_amd_info_fixture(raw,sizeof(raw),2,ip,0,1,3,128);
  for(unsigned rev=0;rev<256;rev++)compare(raw,n,0x73bf,rev,0);
 }
 for(unsigned p=0;p<4;p++) {
  size_t n=stela_amd_info_fixture(raw,sizeof(raw),2,4,0,1,3,256|(p&1?512:0));
  compare(raw,n,0,0,0);compare(raw,n,0,0,1);
 }
 size_t legacy=stela_amd_info_fixture(raw,sizeof(raw),1,2,0,1,0,0);
 for(unsigned d=0;d<4;d++)for(unsigned rev=0;rev<256;rev++)compare(raw,legacy,devices[d],rev,0);
 size_t bytes=stela_amd_info_fixture(raw,sizeof(raw),2,4,1,2,1,0);
 atomic_cases(raw,bytes);
 uint8_t *unaligned=malloc(bytes+1);assert(unaligned);memcpy(unaligned+1,raw,bytes);compare(unaligned+1,bytes,0,0,0);free(unaligned);
 /* Existing raw geometry validator refuses old-version wide records before
  * any original consumer runs; no second native stride parser is needed. */
 {
  size_t n=stela_amd_info_fixture(raw,sizeof(raw),1,2,1,1,0,0);
  uint32_t versions[MAX_HWIP*HWIP_MAX_INSTANCE]={0};struct stela_amd_ip_counts counts={0};
  struct stela_amd_discovery_info out,old;memset(&out,0xca,sizeof(out));memcpy(&old,&out,sizeof(old));
  assert(stela_amd_discovery_info_decode(raw,n,versions,MAX_HWIP*HWIP_MAX_INSTANCE,&counts,0x731e,0xc6,&out));
  assert(!memcmp(&out,&old,sizeof(out)));refused++;
 }
 bytes=stela_amd_info_fixture(raw,sizeof(raw),2,4,1,2,1,0);
 for(unsigned d=0;d<4;d++)for(unsigned rev=0;rev<256;rev++) compare(raw,bytes,devices[d],rev,0);
 for(int arg=1;arg<argc;arg++) {
  FILE *f=fopen(argv[arg],"rb");assert(f);size_t n=fread(raw,1,sizeof(raw),f);assert(!ferror(f)&&feof(f));fclose(f);
  assert(!amdgpu_discovery_binary_validate(raw,n));compare(raw,n,0,0,0);compare(raw,n,0,0,1);
 }
 printf("AMD information original/current comparisons=%u native-projections=%u atomic-refusals=%u gfx-fields=%u ABI=%zu\n",comparisons,native_cases,refused,STELA_AMD_GFX_FIELD_COUNT,sizeof(struct stela_amd_discovery_info));
 printf("Official uncorrected-pin legacy v0/v1 state/log comparisons=%u\n",upstream_legacy);
 return 0;
}
