/* SPDX-License-Identifier: MIT */
/* Independent original ordered-policy and instrumented shipping-C RAM model.
 * No callback below is a production provider or hardware-state claim. */
#include "../stela/discovery_tmr.h"
#include "../stela/discovery_binary.h"
#include "../amdgpu/amdgpu_discovery_tmr_core.h"
#include "../amdgpu/amdgpu_virt_bootstrap_core.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define U32_MAX UINT32_MAX
#define le32_to_cpu(value) (value)
#define AMD_SRIOV_MSG_IPD_TABLE_ID 0
#define GFP_KERNEL 0
struct event { unsigned kind, reg; uint64_t value; size_t bytes; };
struct model {
 uint32_t regs[0x16062];
 struct event events[20000]; unsigned count, polls, ready_after;
 uint32_t signature; int acpi_status; uint64_t acpi_offset, acpi_size;
 bool oom, corrupt;
 uint64_t mm_position;
 const uint8_t *vram; size_t vram_size; uint64_t vram_offset;
 volatile uint32_t *register_base;
};
static struct model *active;
static void event(unsigned kind, unsigned reg, uint64_t value, size_t bytes)
{
 assert(active->count < sizeof(active->events)/sizeof(active->events[0]));
 active->events[active->count++] = (struct event){kind,reg,value,bytes};
}
static uint32_t model_read(uint32_t reg)
{
 uint32_t value=active->regs[reg];
 if(reg==mmMP0_SMN_C2PMSG_33) value=active->polls++ >= active->ready_after ? 0x80000000u : 0;
 event(1,reg,value,4); return value;
}
struct amdgpu_device {
 struct { uint64_t offset; uint32_t size; void *bin;
  struct {void *data; size_t size;} debugfs_blob; } discovery;
 enum amd_asic_type asic_type;
 struct { uint32_t caps; bool is_vf, is_dynamic_crit_regn_enabled;
  struct {uint64_t offset;uint32_t size_kb;} crit_regn_tbl[1]; } virt;
};
#define amdgpu_sriov_vf(adev) ((adev)->virt.is_vf)
#define RREG32(reg) ((void)adev, model_read(reg))
static void msleep(unsigned milliseconds) {event(2,0,milliseconds,0);}
static void amdgpu_device_vram_access(void *owner, uint64_t offset, void *data, size_t bytes, bool write)
{ (void)owner;assert(!write && bytes==4);event(3,0,offset,bytes);memcpy(data,&active->signature,4); }
static int amdgpu_acpi_get_tmr_info(void *owner, uint64_t *offset, uint64_t *size)
{ (void)owner;event(4,0,0,0);*offset=active->acpi_offset;*size=active->acpi_size;return active->acpi_status; }
static void *kzalloc(size_t size, int flags)
{ (void)flags;event(5,0,0,size);return active->oom ? NULL : calloc(1,size); }
#define amdgpu_discovery_get_tmr_info donor_get_tmr
#include "discovery_tmr_reference.h"
#undef amdgpu_discovery_get_tmr_info
#define amdgpu_discovery_get_tmr_info actual_get_tmr
#include "discovery-tmr-wrapper.inc"
#undef amdgpu_discovery_get_tmr_info

#define AMDGPU_SRIOV_CAPS_IS_VF (1 << 2)
#define AMDGPU_SRIOV_CAPS_ENABLE_IOV (1 << 1)
#define AMDGPU_PASSTHROUGH_MODE (1 << 3)
static bool is_virtual_machine(void) {return false;}
static bool xen_initial_domain(void) {return false;}
#include "discovery_tmr_virt_reference.h"
static unsigned selector_cases;
static __attribute__((unused)) void selectors(void)
{
 for(unsigned a=0;a<CHIP_LAST;a++) {
  struct model m={0};active=&m;
  m.regs[mmRCC_IOV_FUNC_IDENTIFIER]=0x80000001u;
  m.regs[mmBIF_IOV_FUNC_IDENTIFIER]=0x80000000u;
  struct amdgpu_device d={.asic_type=a};
  uint32_t original=amdgpu_virt_init_detect_asic(&d), reg=0;
  bool has=amdgpu_virt_bootstrap_iov_register(a,&reg);
  assert(original==(has?m.regs[reg]:0));
  assert(m.count==(unsigned)has);
  if(has)assert(m.events[0].reg==reg);
  ++selector_cases;
 }
}
static unsigned comparisons;
static __attribute__((unused)) void compare(unsigned variant)
{
 struct model a={.ready_after=variant%4==0?2000:variant%7,.signature=variant&1?BINARY_SIGNATURE:0,
  .acpi_offset=0x100000,.acpi_size=0x10000,.oom=(variant%9==0),.acpi_status=variant%11==0?-ENXIO:0};
 a.regs[mmRCC_CONFIG_MEMSIZE]=variant%5==0?UINT32_MAX:variant%3==0?0:1024;
 a.regs[mmDRIVER_SCRATCH_2]=variant%4==0?0:10240;
 a.regs[mmDRIVER_SCRATCH_0]=0x1000;a.regs[mmDRIVER_SCRATCH_1]=2;
 struct model b=a;
 struct amdgpu_device d={.discovery={.offset=variant%2?0x1000:0,.size=123},
  .virt={.is_vf=variant%4==1,.is_dynamic_crit_regn_enabled=variant%3==0,
   .crit_regn_tbl={{0x9000, variant%7==0?0:16}}}};
 struct amdgpu_device n=d;bool expected=variant%2,actual=expected;
 active=&a;int e=donor_get_tmr(&d,&expected);
 active=&b;int r=actual_get_tmr(&n,&actual);
 assert(e==r && expected==actual && d.discovery.offset==n.discovery.offset && d.discovery.size==n.discovery.size);
 assert(a.count==b.count && !memcmp(a.events,b.events,a.count*sizeof(struct event)));
 assert(!!d.discovery.bin==!!n.discovery.bin);
 if(!r) {assert(n.discovery.debugfs_blob.data==n.discovery.bin && n.discovery.debugfs_blob.size==n.discovery.size);}
 free(d.discovery.bin);free(n.discovery.bin);++comparisons;
}
/* Instrumented original native leaf: only actual leaf volatile expressions are
 * replaced by these test counters. Production has no injectable I/O provider. */
uint32_t stela_amd_tmr_test_read(const volatile uint32_t *pointer)
{
 uintptr_t base=(uintptr_t)(active->register_base?active->register_base:active->regs), address=(uintptr_t)pointer;
 assert(address>=base && address-base<sizeof(active->regs) && (address-base)%4==0);
 uint32_t reg=(uint32_t)((address-base)/4);
 if(reg==1) {
  event(6,reg,active->mm_position,4);
  if(active->vram) {assert(active->mm_position>=active->vram_offset && active->mm_position-active->vram_offset+4<=active->vram_size);uint32_t v;memcpy(&v,active->vram+active->mm_position-active->vram_offset,4);if(active->corrupt && active->mm_position==active->vram_offset+32)v^=1;return v;}
  return active->signature;
 }
 return model_read(reg);
}
void stela_amd_tmr_test_write(volatile uint32_t *pointer,uint32_t value)
{
 uintptr_t base=(uintptr_t)(active->register_base?active->register_base:active->regs),address=(uintptr_t)pointer;
 assert(address>=base && address-base<sizeof(active->regs) && (address-base)%4==0);
 uint32_t reg=(uint32_t)((address-base)/4);assert(reg==0||reg==6);
 event(7,reg,value,4);
 if(reg==0) active->mm_position=(active->mm_position&~UINT64_C(0x7fffffff))|(value&0x7fffffff);
 else active->mm_position=((uint64_t)value<<31)|(active->mm_position&UINT64_C(0x7fffffff));
}
static void native_sleep(void *context,unsigned milliseconds)
{assert(context==active);msleep(milliseconds);}
extern int stela_amd_discovery_tmr_test_query(void *,size_t,uint32_t,void *,void(*)(void *,unsigned),struct stela_amd_discovery_tmr *);
static unsigned native_cases;
static __attribute__((unused)) void native_case(unsigned which)
{
 struct model m={.ready_after=0,.signature=BINARY_SIGNATURE};active=&m;
 m.regs[mmRCC_CONFIG_MEMSIZE]=64;
 struct stela_amd_discovery_tmr out,before;memset(&before,0xa5,sizeof(before));out=before;
 size_t bytes=sizeof(m.regs);void *regs=m.regs;unsigned asic=CHIP_IP_DISCOVERY;
 void(*sleep)(void *,unsigned)=native_sleep;int expected=0;
 struct stela_amd_discovery_tmr *outp=&out;
 switch(which) {
 case 1:bytes-=1;expected=STELA_AMD_TMR_BOUNDS;break;
 case 2:regs=NULL;expected=STELA_AMD_TMR_INVALID;break;
 case 3:regs=(uint8_t*)regs+1;expected=STELA_AMD_TMR_INVALID;break;
 case 4:bytes=SIZE_MAX;expected=STELA_AMD_TMR_BOUNDS;break;
 case 5:sleep=NULL;expected=STELA_AMD_TMR_INVALID;break;
 case 6:asic=CHIP_LAST;expected=STELA_AMD_TMR_INVALID;break;
 case 7:m.regs[mmRCC_IOV_FUNC_IDENTIFIER]=1;expected=STELA_AMD_TMR_VF_OWNER_UNAVAILABLE;break;
 case 8:m.regs[mmRCC_CONFIG_MEMSIZE]=UINT32_MAX;expected=-ENXIO;break;
 case 9:m.regs[mmRCC_CONFIG_MEMSIZE]=0;expected=STELA_AMD_TMR_SYSTEM_OWNER_UNAVAILABLE;break;
 case 10:m.regs[mmRCC_CONFIG_MEMSIZE]=0;m.regs[mmDRIVER_SCRATCH_2]=1024;expected=STELA_AMD_TMR_SYSTEM_OWNER_UNAVAILABLE;break;
 case 11:m.signature=0;m.regs[mmDRIVER_SCRATCH_2]=1024;m.regs[mmDRIVER_SCRATCH_0]=4096;break;
 case 12:m.signature=0;m.regs[mmDRIVER_SCRATCH_2]=1023;expected=STELA_AMD_TMR_BOUNDS;break;
 case 13:m.signature=0;m.regs[mmDRIVER_SCRATCH_2]=1024;m.regs[mmDRIVER_SCRATCH_0]=4097;expected=STELA_AMD_TMR_BOUNDS;break;
 case 14:m.signature=0;m.regs[mmDRIVER_SCRATCH_2]=1024;m.regs[mmDRIVER_SCRATCH_1]=1;expected=STELA_AMD_TMR_BOUNDS;break;
 case 15:m.ready_after=2000;break;
 case 16:outp=NULL;expected=STELA_AMD_TMR_INVALID;break;
 case 17:outp=(void*)((uint8_t*)&out+1);expected=STELA_AMD_TMR_INVALID;break;
 case 18:outp=(void*)m.regs;expected=STELA_AMD_TMR_BOUNDS;break;
 case 19:outp=(void*)(UINTPTR_MAX&~(uintptr_t)7);expected=STELA_AMD_TMR_BOUNDS;break;
 case 20:regs=(void*)(UINTPTR_MAX&~(uintptr_t)3);expected=STELA_AMD_TMR_BOUNDS;break;
 case 21:bytes=0;expected=STELA_AMD_TMR_BOUNDS;break;
 case 22:m.signature=0;m.regs[mmDRIVER_SCRATCH_2]=1024;m.regs[mmDRIVER_SCRATCH_0]=(64<<20)-1024;break;
 case 23:m.signature=0;m.regs[mmDRIVER_SCRATCH_2]=1028;m.regs[mmDRIVER_SCRATCH_0]=(64<<20)-1024;expected=STELA_AMD_TMR_BOUNDS;break;
 case 24:m.signature=0;m.regs[mmDRIVER_SCRATCH_2]=4;m.regs[mmDRIVER_SCRATCH_0]=UINT32_MAX-3;m.regs[mmDRIVER_SCRATCH_1]=UINT32_MAX;expected=STELA_AMD_TMR_BOUNDS;break;
 }
 int r=stela_amd_discovery_tmr_test_query(regs,bytes,asic,&m,sleep,outp);
 assert(r==expected);
 if(r) assert(!memcmp(&out,&before,sizeof(out)));
 else {assert(out.size && out.offset+out.size<=out.vram_bytes && out.reserved==0);}
 if((which>=1&&which<=6)||(which>=16&&which<=21))assert(m.count==0);
 if(which==7)assert(m.count==1);
 if(which==15)assert(m.polls==2000); /* No invented timeout/READY. */
 ++native_cases;
}
#ifndef STELA_TMR_RUST_MODEL
int main(void)
{
 selectors();
 for(unsigned i=0;i<256;i++)compare(i);
 for(unsigned i=0;i<25;i++)native_case(i);
 /* Selector fixture is exhaustive over actual original enum values. */
 for(unsigned a=0;a<CHIP_LAST;a++) {uint32_t r=0;bool has=amdgpu_virt_bootstrap_iov_register(a,&r);if(has)assert(r==0xde5||r==0x1503);}
 printf("AMD TMR: %u exact original ASIC selectors; %u original complete query/allocator/ordered-trace comparisons; %u native cases incl zero-I/O preflight, absent owners, mailbox bounds and2000 neverready; CPU models only\n",selector_cases,comparisons,native_cases);
}

#else
static struct model rust_model;
void stela_amd_tmr_model_begin(volatile uint32_t *registers, const uint8_t *vram, size_t bytes)
{
 rust_model=(struct model){.register_base=registers,.vram=vram,.vram_size=bytes,
  .vram_offset=(UINT64_C(64)<<20)-DISCOVERY_TMR_OFFSET};
 rust_model.regs[mmRCC_CONFIG_MEMSIZE]=64;
 active=&rust_model;
}
unsigned stela_amd_tmr_model_accesses(void) { return rust_model.count; }
void stela_amd_tmr_model_delay(void) {rust_model.ready_after=1;}
void stela_amd_tmr_model_vf(void) {rust_model.regs[mmRCC_IOV_FUNC_IDENTIFIER]=1;}
void stela_amd_tmr_model_system(void) {rust_model.regs[mmRCC_CONFIG_MEMSIZE]=0;}
void stela_amd_tmr_model_corrupt(void) {rust_model.corrupt=true;}
void stela_amd_tmr_model_end(void) { active=NULL; }
#endif
