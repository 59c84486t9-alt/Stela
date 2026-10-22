/* SPDX-License-Identifier: MIT */
/* The existing unrelated fixture donor has no ISP model field. Only disable
 * that unused embedded donor in this TU; actual info algorithms/tests compile
 * with the real requested ISP configuration in their own TUs. */
#ifdef CONFIG_DRM_AMD_ISP
#define STELA_FIXTURE_RESTORE_ISP
#undef CONFIG_DRM_AMD_ISP
#endif
#define main stela_amd_info_existing_fixture_main
#include "discovery_binary_test.c"
#undef main
#ifdef STELA_FIXTURE_RESTORE_ISP
#define CONFIG_DRM_AMD_ISP 1
#endif
size_t stela_amd_info_fixture(uint8_t *out, size_t capacity, unsigned version,
 unsigned ip_version, unsigned wide, unsigned major, unsigned minor, unsigned policy)
{
 struct fixture f=make_fixture(version,ip_version,wide,major,minor,policy);
 if (policy&2) put16(&((struct mall_info_v1_0 *)(f.binary+f.offset[MALL_INFO]))->header.version_major,3);
 if (policy&4) put16(&((struct vcn_info_v1_0 *)(f.binary+f.offset[VCN_INFO]))->header.version_major,2);
 if (policy&8) put16(&directory_entry(&f,GC)->offset,0);
 if (policy&16) put16(&directory_entry(&f,MALL_INFO)->offset,0);
 if (policy&32) put16(&directory_entry(&f,VCN_INFO)->offset,0);
 if (policy&64) put16(&directory_entry(&f,HARVEST_INFO)->offset,0);
 if (policy&128) {
  struct ip_discovery_header *h=(void*)(f.binary+f.offset[IP_DISCOVERY]);
  for(unsigned d=0;d<h->num_dies;d++) {
   size_t pos=h->die_info[d].die_offset;struct die_header *die=(void*)(f.binary+pos);pos+=sizeof(*die);
   for(unsigned i=0;i<die->num_ips;i++) {
    struct ip_v4 *ip=(void*)(f.binary+pos);
    if(ip->hw_id==GC_HWID && !ip->instance_number){ip->major=10;ip->minor=3;ip->revision=2;}
    if(ip->hw_id==VCN_HWID && ip->instance_number==1){ip->major=3;ip->minor=0;ip->revision=1;}
    pos+=sizeof(*ip)+ip->num_base_address*(wide?8:4);
   }
  }
 }
 if (policy&256) {
  struct harvest_table *h=(void*)(f.binary+f.offset[HARVEST_INFO]);
  unsigned ids[]={ISP_HWID,GC_HWID,SDMA0_HWID,DMU_HWID,UMC_HWID,VCN_HWID,VCN_HWID};
  unsigned inst[]={1,31,31,0,31,0,32};
  for(unsigned i=0;i<7;i++){put16(&h->list[i+2].hw_id,ids[i]);h->list[i+2].number_instance=inst[i];}
 }
 if (policy&512) {
  struct mall_info_v1_0 *m=(void*)(f.binary+f.offset[MALL_INFO]);
  put32(&m->mall_size_per_m,UINT32_MAX);put32(&m->m_s_present,UINT32_MAX);put32(&m->m_half_use,UINT32_MAX);
 }
 checksums(&f);
 assert(capacity>=f.size);memcpy(out,f.binary,f.size);return f.size;
}
