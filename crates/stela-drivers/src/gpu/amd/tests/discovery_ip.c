/* SPDX-License-Identifier: MIT */
/* Actual shared/current Linux consumer and independent frozen original oracle. */
#include "../stela/discovery_ip.h"
#include "../stela/discovery_binary.h"
#include "../amdgpu/amdgpu_discovery_ip_core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <limits.h>

struct va_format { const char *fmt; va_list *va; };
struct amdgpu_device {
   void *dev;
   struct { uint8_t *bin; size_t size; } discovery;
   struct { uint16_t xcc_mask; } gfx;
   struct { int num_instances; uint32_t sdma_mask; } sdma;
   struct { uint8_t num_vcn_inst; struct {uint8_t vcn_config;} inst[AMDGPU_MAX_VCN_INSTANCES]; uint16_t inst_mask; } vcn;
   struct {uint16_t inst_mask;} jpeg;
   struct {uint32_t num_instances;} vpe;
   struct {int num_umc;} gmc;
   struct {uint32_t node_inst_num;} umc;
   uint32_t *reg_offset[MAX_HWIP][HWIP_MAX_INSTANCE];
   uint32_t ip_versions[MAX_HWIP][HWIP_MAX_INSTANCE];
};
static const char *hw_id_names[HW_ID_MAX];
static char logs[2][262144];static size_t log_at[2];static unsigned current;
static void log_message(const char *format, va_list args)
{
   if (!strcmp(format,"%pV")) {
      struct va_format *vaf=va_arg(args,struct va_format *);
      log_at[current]+=(size_t)vsnprintf(logs[current]+log_at[current],sizeof(logs[current])-log_at[current],vaf->fmt,*vaf->va);
   } else log_at[current]+=(size_t)vsnprintf(logs[current]+log_at[current],sizeof(logs[current])-log_at[current],format,args);
   assert(log_at[current]<sizeof(logs[current]));
}
static void log_debug(const char *format,...) {va_list a;va_start(a,format);log_message(format,a);va_end(a);}
static void log_error(void *device,const char *format,...) {(void)device;va_list a;va_start(a,format);log_message(format,a);va_end(a);}
#define DRM_DEBUG(...) log_debug(__VA_ARGS__)
#define DRM_ERROR(...) log_debug(__VA_ARGS__)
#define dev_err(...) log_error(__VA_ARGS__)
static int acquisition_error, table_error, acquisitions[2], lookups[2];
static int amdgpu_discovery_init(struct amdgpu_device *a) {(void)a;acquisitions[current]++;return acquisition_error;}
static int amdgpu_discovery_get_table_info(struct amdgpu_device *a,struct table_info **out,uint16_t id)
{lookups[current]++;if(table_error)return table_error;*out=(void*)amdgpu_discovery_binary_table(a->discovery.bin,a->discovery.size,id);return *out?0:-EINVAL;}
#include "discovery_ip_reference.h"
#include "discovery-ip-linux.inc"

size_t stela_amd_ip_fixture(uint8_t *,size_t,unsigned,unsigned,unsigned);
static unsigned comparisons, native_cases, malformed;
static void seed(struct amdgpu_device *a,unsigned seed)
{
   a->gfx.xcc_mask=0xf1f1;a->vcn.inst_mask=0xfffa;a->jpeg.inst_mask=0xf0ff;a->sdma.sdma_mask=0xff00ff00;
   a->vcn.num_vcn_inst=seed%5;a->sdma.num_instances=(int)seed-1;
   a->vpe.num_instances=seed%3;a->gmc.num_umc=seed;a->umc.node_inst_num=seed;
   for(unsigned i=0;i<AMDGPU_MAX_VCN_INSTANCES;i++)a->vcn.inst[i].vcn_config=(uint8_t)(seed+i);
   a->ip_versions[XGMI_HWIP][0]=seed&1?0x09040100:0;
   if(seed==8){a->vcn.num_vcn_inst=255;a->sdma.num_instances=INT_MAX;
      a->vpe.num_instances=UINT32_MAX;a->gmc.num_umc=INT_MAX;a->umc.node_inst_num=UINT32_MAX;}
}
static void compare(const uint8_t *binary,size_t bytes,unsigned state)
{
   uint8_t *left=malloc(bytes),*right=malloc(bytes);assert(left&&right);
   memcpy(left,binary,bytes);memcpy(right,binary,bytes);
   struct amdgpu_device a={0},b={0};seed(&a,state);b=a;
   a.discovery.bin=left;b.discovery.bin=right;a.discovery.size=b.discovery.size=bytes;
   memset(logs,0,sizeof(logs));memset(log_at,0,sizeof(log_at));memset(acquisitions,0,sizeof(acquisitions));memset(lookups,0,sizeof(lookups));
   current=0;int expected=ip_donor_amdgpu_discovery_reg_base_init(&a);
   current=1;int status=amdgpu_discovery_reg_base_init(&b);
   assert(expected==status && acquisitions[0]==acquisitions[1]&&lookups[0]==lookups[1]);
   assert(!memcmp(left,right,bytes));assert(log_at[0]==log_at[1]&&!memcmp(logs[0],logs[1],log_at[0]));
   for(unsigned ip=0;ip<MAX_HWIP;ip++)for(unsigned i=0;i<HWIP_MAX_INSTANCE;i++){
      if(a.reg_offset[ip][i]){assert(b.reg_offset[ip][i]);assert((uintptr_t)a.reg_offset[ip][i]-(uintptr_t)left==(uintptr_t)b.reg_offset[ip][i]-(uintptr_t)right);}
      else assert(!b.reg_offset[ip][i]);
      a.reg_offset[ip][i]=b.reg_offset[ip][i]=NULL;
   }
   a.discovery.bin=b.discovery.bin=NULL;assert(!memcmp(&a,&b,sizeof(a)));
   free(left);free(right);comparisons++;
}
static unsigned count_for(const uint8_t *binary,size_t bytes,uint32_t offset)
{
 const struct table_info *t=amdgpu_discovery_binary_table(binary,bytes,IP_DISCOVERY);
 const struct ip_discovery_header *h=(const void*)(binary+t->offset);
 for(unsigned d=0;d<h->num_dies;d++){
  size_t pos=h->die_info[d].die_offset;const struct die_header *die=(const void*)(binary+pos);pos+=sizeof(*die);
  for(unsigned n=0;n<die->num_ips;n++){
   const struct ip_v4 *ip=(const void*)(binary+pos);
   if(pos+offsetof(struct ip_v4,base_address)==offset)return ip->num_base_address;
   pos+=sizeof(*ip)+ip->num_base_address*(h->base_addr_64_bit?8:4);
  }
 }
 assert(0);return 0;
}
static void native(const uint8_t *binary,size_t bytes)
{
 struct stela_amd_ip_shape shape=stela_amd_discovery_ip_shape();size_t cells=shape.hw_ip_count*shape.instances;
 assert(shape.hw_ip_count==MAX_HWIP&&shape.instances==HWIP_MAX_INSTANCE);
 uint8_t *work=malloc(bytes+1),*raw=malloc(bytes);uint32_t *versions=malloc(cells*4);
 struct stela_amd_ip_binding *bindings=malloc(cells*sizeof(*bindings));assert(work&&raw&&versions&&bindings);
 memcpy(work+1,binary,bytes);memcpy(raw,binary,bytes); // Entire allocation deliberately unaligned.
 struct stela_amd_ip_counts counts;
 int result=stela_amd_discovery_ip_decode(work+1,bytes,versions,cells,bindings,cells,&counts);assert(!result);
 struct amdgpu_device a={0};a.discovery.bin=raw;a.discovery.size=bytes;
 current=0;log_at[0]=0;assert(!ip_donor_amdgpu_discovery_reg_base_init(&a));
 assert(!memcmp(work+1,raw,bytes));assert(!memcmp(versions,a.ip_versions,cells*4));
 assert(counts.xcc_mask==a.gfx.xcc_mask&&counts.vcn_mask==a.vcn.inst_mask&&counts.jpeg_mask==a.jpeg.inst_mask);
 assert(counts.vcn_count==a.vcn.num_vcn_inst&&counts.sdma_count==a.sdma.num_instances&&counts.sdma_mask==a.sdma.sdma_mask);
 assert(counts.vpe_count==a.vpe.num_instances&&counts.umc_count==a.gmc.num_umc&&counts.node_count==a.umc.node_inst_num);
 for(unsigned i=0;i<AMDGPU_MAX_VCN_INSTANCES;i++)assert(counts.vcn_config[i]==a.vcn.inst[i].vcn_config);
 for(unsigned ip=0;ip<MAX_HWIP;ip++)for(unsigned i=0;i<HWIP_MAX_INSTANCE;i++){
  struct stela_amd_ip_binding *b=&bindings[ip*HWIP_MAX_INSTANCE+i];
  if(a.reg_offset[ip][i]){assert(b->offset==(uintptr_t)a.reg_offset[ip][i]-(uintptr_t)raw);assert(b->count==count_for(binary,bytes,b->offset));}
  else assert(b->offset==UINT32_MAX&&b->count==0);
 }
 free(work);free(raw);free(versions);free(bindings);native_cases++;
}
static void checksum(uint8_t *binary,size_t bytes)
{
 struct binary_header *h=(void*)binary;
 for(unsigned i=0;i<TOTAL_TABLES;i++){
  struct table_info *t=(void*)amdgpu_discovery_binary_table(binary,bytes,i);
  if(t&&t->size)t->checksum=amdgpu_discovery_calculate_checksum(binary+t->offset,t->size);
 }
 size_t start=offsetof(struct binary_header,binary_checksum)+2;
 h->binary_checksum=amdgpu_discovery_calculate_checksum(binary+start,h->binary_size-start);
}
static struct ip_v4 *record(uint8_t *binary,size_t bytes,unsigned die,unsigned index)
{
 const struct table_info *t=amdgpu_discovery_binary_table(binary,bytes,IP_DISCOVERY);
 struct ip_discovery_header *h=(void*)(binary+t->offset);
 size_t pos=h->die_info[die].die_offset+sizeof(struct die_header);
 for(unsigned i=0;i<index;i++){struct ip_v4 *ip=(void*)(binary+pos);pos+=sizeof(*ip)+ip->num_base_address*(h->base_addr_64_bit?8:4);}
 return (void*)(binary+pos);
}
static void atomic_refusal(uint8_t *binary,size_t bytes,unsigned kind)
{
 struct stela_amd_ip_shape shape=stela_amd_discovery_ip_shape();size_t cells=shape.hw_ip_count*shape.instances;
 uint8_t *raw=malloc(bytes?bytes:1);memcpy(raw,binary,bytes);
 uint32_t *versions=malloc(cells*4);struct stela_amd_ip_binding *bindings=malloc(cells*sizeof(*bindings));
 struct stela_amd_ip_counts counts,before;
 memset(versions,0xa5,cells*4);memset(bindings,0xa5,cells*sizeof(*bindings));memset(&counts,0xa5,sizeof(counts));before=counts;
 uint32_t *vp=versions;struct stela_amd_ip_binding *bp=bindings;struct stela_amd_ip_counts *cp=&counts;
 size_t vc=cells,bc=cells;
 switch(kind){case 1:vc--;break;case 2:bc--;break;case 3:vp=NULL;break;case 4:bp=NULL;break;case 5:cp=NULL;break;
 case 6:vp=(void*)((uint8_t*)versions+1);break;case 7:bp=(void*)((uint8_t*)bindings+1);break;case 8:cp=(void*)((uint8_t*)&counts+1);break;
 case 9:vp=(void*)binary;break;case 10:cp=(void*)bindings;break;case 11:bp=(void*)versions;break;}
 assert(stela_amd_discovery_ip_decode(binary,bytes,vp,vc,bp,bc,cp));
 assert(!memcmp(binary,raw,bytes)&&!memcmp(&counts,&before,sizeof(counts)));
 for(size_t i=0;i<cells*4;i++)assert(((uint8_t*)versions)[i]==0xa5);
 for(size_t i=0;i<cells*sizeof(*bindings);i++)assert(((uint8_t*)bindings)[i]==0xa5);
 free(raw);free(versions);free(bindings);malformed++;
}
int main(int argc,char **argv)
{
 for(unsigned i=0;i<HW_ID_MAX;i++)hw_id_names[i]="original-name";
 const unsigned instances[]={0,47,48,255}, ids[]={0,299,300,65535};
 struct amdgpu_device dummy={0};
 for(unsigned i=0;i<4;i++)for(unsigned j=0;j<4;j++) {
  log_at[0]=log_at[1]=0;current=0;
  int expected=ip_donor_amdgpu_discovery_validate_ip(&dummy,instances[i],ids[j]);
  current=1;assert(amdgpu_discovery_validate_ip(&dummy,instances[i],ids[j])==expected);
  assert(log_at[0]==log_at[1]&&!memcmp(logs[0],logs[1],log_at[0]));
 }
 uint8_t binary[65536],original[65536];
 for(unsigned directory=0;directory<=2;directory++)for(unsigned wide=0;wide<2;wide++)for(unsigned ver=wide?4:1;ver<=4;ver++){
  size_t bytes=stela_amd_ip_fixture(binary,sizeof(binary),directory,ver,wide);
  assert(!amdgpu_discovery_binary_validate(binary,bytes));
  for(unsigned s=0;s<9;s++)compare(binary,bytes,s);
  native(binary,bytes);
  for(unsigned k=1;k<=11;k++)atomic_refusal(binary,bytes,k);
  memcpy(original,binary,bytes);
  for(size_t n=0;n<bytes;n++)atomic_refusal(binary,n,0);
  for(size_t at=0;at<bytes;at+=7){binary[at]^=1;if(amdgpu_discovery_binary_validate(binary,bytes))atomic_refusal(binary,bytes,0);else{compare(binary,bytes,0);native(binary,bytes);}binary[at]^=1;}
  /* Actual version bits above signed-int positive domain; no major<128 gate. */
  const struct table_info *t=amdgpu_discovery_binary_table(binary,bytes,IP_DISCOVERY);
  struct ip_discovery_header *h=(void*)(binary+t->offset);
  struct ip_v4 *ip=(void*)(binary+h->die_info[0].die_offset+sizeof(struct die_header));
  ip->major=255;ip->minor=254;ip->revision=253;checksum(binary,bytes);compare(binary,bytes,0);native(binary,bytes);
  memcpy(binary,original,bytes);
  for(unsigned variant=0;variant<5;variant++) {
   memcpy(binary,original,bytes);
   for(unsigned d=0;d<2;d++) {
    if(variant==0){record(binary,bytes,d,0)->instance_number=31;record(binary,bytes,d,3)->instance_number=31;record(binary,bytes,d,2)->instance_number=31;}
    if(variant==1){record(binary,bytes,d,2)->hw_id=NBIF_HWID;record(binary,bytes,d,2)->instance_number=0;record(binary,bytes,d,10)->hw_id=NBIF_HWID;record(binary,bytes,d,10)->instance_number=0;}
    if(variant==2){struct ip_v4 *x=record(binary,bytes,d,9);x->hw_id=XGMI_HWID;x->instance_number=0;x->major=x->minor=x->revision=x->variant=x->sub_revision=0;}
    if(variant==3)record(binary,bytes,d,7)->hw_id=VPE_HWID;
    if(variant==4)record(binary,bytes,d,7)->hw_id=AUDIO_AZ_HWID;
   }
   if(variant==2){struct ip_v4 *w=record(binary,bytes,0,8);w->major=w->minor=w->revision=0;}
   checksum(binary,bytes);assert(!amdgpu_discovery_binary_validate(binary,bytes));
   for(unsigned seed=0;seed<9;seed++)compare(binary,bytes,seed);native(binary,bytes);
  }
  memcpy(binary,original,bytes);
  /* Preserve original partial first-die effects and global DRM error route. */
  struct ip_discovery_header *ph=(void*)(binary+amdgpu_discovery_binary_table(binary,bytes,IP_DISCOVERY)->offset);
  ((struct die_header*)(binary+ph->die_info[1].die_offset))->die_id=5;checksum(binary,bytes);
  compare(binary,bytes,0);atomic_refusal(binary,bytes,0);
  memcpy(binary,original,bytes);
  /* Original outer failures/partial masks remain in Linux caller. */
  acquisition_error=-EIO;compare(binary,bytes,0);acquisition_error=0;
  table_error=-EINVAL;compare(binary,bytes,3);table_error=0;
 }
 for(int n=1;n<argc;n++){
  FILE *f=fopen(argv[n],"rb");assert(f);size_t bytes=fread(binary,1,sizeof(binary),f);assert(bytes&&bytes<sizeof(binary)&&feof(f));fclose(f);
  assert(!amdgpu_discovery_binary_validate(binary,bytes));for(unsigned s=0;s<8;s++)compare(binary,bytes,s);native(binary,bytes);
 }
 printf("AMD IP: %u whole original/current consumers, %u native packed copies, %u atomic malformed/storage refusals; CPU only\n",comparisons,native_cases,malformed);
 return 0;
}
