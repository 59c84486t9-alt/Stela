/* SPDX-License-Identifier: MIT */
#include "pat_donor.h"
#include "../pat.h"
#include "regs/xe_reg_defs.h"
#include <linux/build_bug.h>
#include <drm/intel/pick.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <linux/array_size.h>
struct diagnostics {bool warning,missing;};
#define XE_PAT_SELECT_WARN(context, condition) (((struct diagnostics *)(context))->warning |= !!(condition))
#define XE_PAT_SELECT_MISSING(context, version) ((void)(version), ((struct diagnostics *)(context))->missing=true)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#include "xe_pat_select.h"
#pragma clang diagnostic pop
static void record(void *context,struct xe_reg reg,u32 value)
{
 struct stela_pat_trace *out=context;assert(out->count<34);
 out->offset[out->count]=reg.addr;out->value[out->count++]=value;
}
#define XE_PAT_PROGRAM_WRITE(context,reg,value) record(context,reg,value)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#include "xe_pat_program.h"
#pragma clang diagnostic pop
static void selected(enum xe_platform platform,uint32_t graphics,bool discrete,bool llc,
                     struct stela_pat_test_policy *out,struct xe_pat_selection *selection)
{
 struct diagnostics d={0};
 *selection=(struct xe_pat_selection){.profile=XE_PAT_PROFILE_XE2};
 bool known=xe_pat_select(selection,platform,graphics,discrete,llc,&d);
 assert(known!=d.missing);
 *out=(struct stela_pat_test_policy){.profile=selection->profile,.count=(uint32_t)selection->n_entries,
  .warning=d.warning,.missing=d.missing};
 memcpy(out->indices,selection->idx,sizeof(out->indices));
 if(selection->n_entries)memcpy(out->entries,selection->table,(size_t)selection->n_entries*sizeof(*selection->table));
 if(selection->pat_ats){out->special|=1;out->ats=*selection->pat_ats;}
 if(selection->pat_primary_pta){out->special|=2;out->primary=*selection->pat_primary_pta;}
 if(selection->pat_media_pta){out->special|=4;out->media=*selection->pat_media_pta;}
}
static int check(void *context){return *(int*)context;}
static struct stela_pat_trace native;
static void native_write(void *context,uint32_t offset,uint32_t value)
{(void)context;assert(native.count<34);native.offset[native.count]=offset;native.value[native.count++]=value;}
int main(void)
{
 const uint32_t versions[]={0,1100,1200,1210,1211,1250,1255,1260,1270,1271,1274,
  1999,2000,2001,2002,2004,2099,3000,3001,3003,3004,3005,3099,3500,3510,3511,3512,3599,3600,4000};
 _Static_assert(_PAT_INDEX(7)==0x481c, "original first range end");
 _Static_assert(_PAT_INDEX(8)==0x4848, "original second range start");
 _Static_assert(_PAT_INDEX(31)==0x48a4, "original 32-entry span");
 unsigned cases=0,traces=0,held=0;
 for(unsigned p=0;p<=XE_NOVALAKE_P;p++)for(unsigned v=0;v<ARRAY_SIZE(versions);v++)
 for(unsigned d=0;d<2;d++)for(unsigned llc=0;llc<2;llc++) {
  // These cross-products do not describe any retained matched device and
  // violate the original ops->entry_dump debug postcondition. Keep them
  // explicit holds, not a successful policy/hardware qualification.
  unsigned generation=versions[v]/100;
  if(generation>=20 && generation!=20 && generation!=30 && generation!=35 &&
     (p==XE_METEORLAKE || p==XE_PVC || p==XE_DG2)) {++held;continue;}
  struct stela_pat_test_policy expected,actual;
  struct xe_pat_selection selection;
  stela_pat_donor_policy((enum xe_platform)p,versions[v],d!=0,llc!=0,&expected);
  selected((enum xe_platform)p,versions[v],d!=0,llc!=0,&actual,&selection);
  assert(!memcmp(&actual,&expected,sizeof(actual)));++cases;
  if(actual.missing)continue;
  struct stela_pat_trace a,b={0};
  stela_pat_donor_program(&expected,&a);
  xe_pat_program_direct(&b,selection.table,selection.n_entries,selection.pat_ats,selection.pat_primary_pta);
  assert(!memcmp(&a,&b,sizeof(a)));++traces;
  if(versions[v]==2001)assert(actual.count==28);
  if(versions[v]/100==20 || versions[v]/100==30) {
   for(unsigned i=16;i<20;i++) {
    if(i==16 && versions[v]/100==30)assert(actual.entries[i].valid==1);
    else assert(actual.entries[i].value==0 && actual.entries[i].valid==0 && actual.entries[i].coh_mode==0);
   }
  } // Original CLOS3 workaround.
  if(versions[v]==3511)assert(actual.count==32 && actual.indices[XE_CACHE_WT]==3 && actual.special==7);
  if(versions[v]<=1210 && p!=XE_METEORLAKE && p!=XE_PVC && p!=XE_DG2) {
   assert(actual.count==4 && !actual.special && actual.indices[XE_CACHE_WB]==0);
   assert(actual.indices[XE_CACHE_NONE_COMPRESSION]==UINT16_MAX && actual.indices[XE_CACHE_WB_COMPRESSION]==UINT16_MAX);
   assert(actual.entries[0].value==3 && actual.entries[1].value==1 && actual.entries[2].value==2 && actual.entries[3].value==0);
   for(unsigned i=0;i<4;i++)assert(a.offset[i]==0x4800+4*i);
  }
 }
 int context=0;struct stela_intel_activation_io io={.check_context=check,.write32=native_write};
 struct stela_intel_activation_facts facts={.platform=XE_TIGERLAKE,.graphics_verx100=1200,
  .has_llc=1,.gt_type=1,.initialized=1,.awake=1};
 struct stela_intel_pat_result out,before;memset(&before,0xa5,sizeof(before));
 unsigned refusals=0;
 for(unsigned variant=0;variant<10;variant++) {
  struct stela_intel_activation_facts f=facts;out=before;native=(struct stela_pat_trace){0};int expected=-95;
  switch(variant){case 0:f.gt_type=2;break;case 1:f.has_llc=0;break;case 2:f.awake=0;break;
   case 3:f.platform=XE_DG2;f.graphics_verx100=1255;f.discrete=1;break;
   case 4:f.platform=XE_METEORLAKE;f.graphics_verx100=1270;break;
   case 5:f.graphics_verx100=4000;break;case 6:context=-16;expected=-16;break;
   case 7:f.awake=2;break;case 8:f.has_llc=2;break;case 9:f.platform=XE_METEORLAKE;f.graphics_verx100=4000;break;}
  assert(stela_intel_pat_program(&io,&context,&f,&out)==expected);
  assert(!native.count && !memcmp(&out,&before,sizeof(out)));context=0;++refusals;
 }
 out=before;native=(struct stela_pat_trace){0};
 assert(!stela_intel_pat_program(&io,&context,&facts,&out));
 assert(native.count==4 && out.writes==4 && out.n_entries==4 && out.cache_none==3 && out.cache_wt==2 && out.cache_wb==0);
 assert(out.cache_none_compression==UINT16_MAX && out.cache_wb_compression==UINT16_MAX);
 const uint32_t values[]={3,1,2,0};
 for(unsigned i=0;i<4;i++)assert(native.offset[i]==0x4800+4*i && native.value[i]==values[i] && out.entries[i]==values[i]);
 printf("Intel PAT: %u whole original policies, %u full direct/ATS/PTA traces, %u zero-I/O refusals; %u impossible platform/version holds; independent XeLP values/order/cache and modern limits; CPU only\n",cases,traces,refusals,held);
 return 0;
}
