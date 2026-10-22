/* SPDX-License-Identifier: MIT */
/* Original frozen driver versus actual retained wrapper/shared core. Explicit
 * CPU register/lifetime model only; no real VRAM, guard, PCI or MMIO provider. */
#ifdef NDEBUG
#error "VRAM MM protocol tests require active assertions"
#endif
#include "../stela/vram_mm.h"
#include "vram_mm_test_io.h"
#include "../include/asic_reg/bif/bif_4_1_d.h"
#include "../amdgpu/amdgpu_mm_access_core.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(enum stela_amd_vram_mm_status) == 4, "native status ABI");
_Static_assert(sizeof(size_t) == 8 && sizeof(void *) == 8, "native x86-64 ABI");
static unsigned native_reads, native_writes;
uint32_t stela_amd_test_io_read(volatile uint32_t *pointer)
{
   native_reads++; return *pointer;
}
void stela_amd_test_io_write(volatile uint32_t *pointer, uint32_t value)
{
   native_writes++; *pointer=value;
}
struct event { uint32_t reg, value; bool write; };
struct model {
   uint32_t low, high;
   struct event events[512];
   unsigned count, enter, exit, lock, unlock, diagnostics;
   bool available;
};
struct amdgpu_device { struct model *model; int mmio_idx_lock; };
typedef int64_t loff_t;
static uint32_t pattern(uint64_t position)
{
   return (uint32_t)(position * UINT64_C(0x9e3779b97f4a7c15) ^ (position >> 32)) ^ 0x56abc012u;
}
static void record(struct model *m, uint32_t reg, uint32_t value, bool write)
{
   assert(m->lock == m->unlock+1 && m->count < 512);
   m->events[m->count++] = (struct event){reg,value,write};
}
static uint32_t model_read(struct model *m, uint32_t reg)
{
   assert(reg == mmMM_DATA);
   uint64_t position = ((uint64_t)m->high << 31) | (m->low & 0x7fffffffu);
   uint32_t value = pattern(position);
   record(m,reg,value,false); return value;
}
static void model_write(struct model *m, uint32_t reg, uint32_t value)
{
   assert(reg == mmMM_INDEX || reg == mmMM_INDEX_HI || reg == mmMM_DATA);
   record(m,reg,value,true);
   if (reg == mmMM_INDEX) m->low = value;
   if (reg == mmMM_INDEX_HI) m->high = value;
}
static bool enter(struct amdgpu_device *adev, int *index)
{
   adev->model->enter++; *index=0; return adev->model->available;
}
static struct model *active;
#define adev_to_drm(adev) (adev)
#define drm_dev_enter(adev, index) enter(adev,index)
#define drm_dev_exit(index) ((void)(index), active->exit++)
#define spin_lock_irqsave(lockptr, flags) ((void)(lockptr), (flags)=0, active->lock++)
#define spin_unlock_irqrestore(lockptr, flags) ((void)(lockptr), (void)(flags), active->unlock++)
#define IS_ALIGNED(value, alignment) (!((value) & ((alignment)-1)))
#define dev_err(...) ((void)active->diagnostics++)
#define WREG32_NO_KIQ(reg, value) model_write(adev->model,reg,value)
#define RREG32_NO_KIQ(reg) model_read(adev->model,reg)
#define amdgpu_device_mm_access frozen_mm_access
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#include "vram_mm_reference.h"
#pragma GCC diagnostic pop
#undef amdgpu_device_mm_access
/* Generated mechanically by the original Make recipe from the current actual
 * Linux wrapper, including its real callback and service-call ordering. */
#include "vram-mm-wrapper.inc"

static void compare(const struct model *a, const struct model *b)
{
   assert(a->low==b->low && a->high==b->high && a->count==b->count);
   assert(a->enter==b->enter && a->exit==b->exit && a->lock==b->lock &&
          a->unlock==b->unlock && a->diagnostics==b->diagnostics);
   for (unsigned i=0; i<a->count; i++) {
      assert(a->events[i].reg==b->events[i].reg &&
             a->events[i].value==b->events[i].value && a->events[i].write==b->events[i].write);
   }
}
static void traces(void)
{
   const uint64_t positions[] = {0,4,28,0x7ffffff8,0x80000000,0xfffffffc,
      0x100000000,0x17ffffff8,UINT64_C(0x123456787ffffff8),
      UINT64_C(0x7fffffff7ffffffc),INT64_MAX-3};
   const size_t sizes[] = {0,4,8,12,64,128};
   unsigned cases=0;
   for (unsigned a=0; a<sizeof(positions)/sizeof(*positions); a++)
      for (unsigned b=0; b<sizeof(sizes)/sizeof(*sizes); b++) {
         if (sizes[b] > (uint64_t)INT64_MAX-positions[a]) continue;
         for (unsigned write=0; write<2; write++) {
            uint32_t before[32], after[32];
            for (unsigned i=0; i<32; i++) before[i]=after[i]=0x12345000u+i;
            struct model old={.available=true,.high=0xdeadbeef}, fresh=old;
            struct amdgpu_device original={&old,0}, current={&fresh,0};
            active=&old; frozen_mm_access(&original,(loff_t)positions[a],before,sizes[b],write!=0);
            active=&fresh; amdgpu_device_mm_access(&current,(loff_t)positions[a],after,sizes[b],write!=0);
            compare(&old,&fresh); assert(!memcmp(before,after,sizeof(before)));
            if (!write) for (size_t i=0; i<sizes[b]/4; i++) assert(after[i]==pattern(positions[a]+i*4));
            assert(fresh.enter==1 && fresh.exit==1 && fresh.lock==1 && fresh.unlock==1);
            cases++;
         }
      }
   /* Original lifetime refusal and unaligned-input diagnostic precede locking. */
   for (unsigned mode=0; mode<3; mode++) {
      uint32_t a=99,b=99;
      struct model old={.available=mode!=0},fresh=old;
      struct amdgpu_device original={&old,0},current={&fresh,0};
      active=&old; frozen_mm_access(&original,mode==1?1:0,&a,mode==2?1:4,false);
      active=&fresh; amdgpu_device_mm_access(&current,mode==1?1:0,&b,mode==2?1:4,false);
      compare(&old,&fresh); assert(a==99 && b==99 && !fresh.count && !fresh.lock);
      cases++;
   }
   printf("AMD MM-index: %u independent original-wrapper ordered traces/data/lifetime cases\n",cases);
}
static void native_bounds(void)
{
   uint32_t registers[16], before[16], data[16], prior[16];
   for (unsigned i=0; i<16; i++) registers[i]=before[i]=data[i]=prior[i]=0x55aa00ff;
   unsigned refusals=0;
#define REFUSE(base, window, extent, at, output, bytes, expected) do { \
   native_reads=native_writes=0; \
   assert(stela_amd_vram_mm_test_read(base,window,extent,at,output,bytes)==(expected)); \
   assert(!native_reads && !native_writes); \
   assert(stela_amd_vram_mm_read(base,window,extent,at,output,bytes)==(expected)); \
   assert(!memcmp(registers,before,sizeof(registers)) && !memcmp(data,prior,sizeof(data))); refusals++; \
} while (0)
   REFUSE(NULL,64,256,0,data,4,STELA_AMD_VRAM_MM_INVALID);
   REFUSE((uint8_t *)registers+1,63,256,0,data,4,STELA_AMD_VRAM_MM_INVALID);
   REFUSE(registers,27,256,0,data,4,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE(registers,64,256,0,NULL,4,STELA_AMD_VRAM_MM_INVALID);
   REFUSE(registers,64,256,0,(uint32_t *)((uint8_t *)data+1),4,STELA_AMD_VRAM_MM_INVALID);
   REFUSE(registers,64,256,1,data,4,STELA_AMD_VRAM_MM_INVALID);
   REFUSE(registers,64,256,0,data,3,STELA_AMD_VRAM_MM_INVALID);
   REFUSE(registers,64,256,256,data,4,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE(registers,64,256,260,data,0,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE(registers,64,UINT64_MAX,0,data,4,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE(registers,64,INT64_MAX,INT64_MAX-3,data,4,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE(registers,64,INT64_MAX,INT64_MAX-7,data,4,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE(registers,SIZE_MAX-3,256,0,data,4,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE(registers,64,INT64_MAX,0,data,SIZE_MAX-3,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE((void *)(UINTPTR_MAX-3),28,256,0,data,4,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE(registers,64,256,0,(uint32_t *)(UINTPTR_MAX-3),8,STELA_AMD_VRAM_MM_BOUNDS);
   REFUSE(registers,64,256,0,registers,4,STELA_AMD_VRAM_MM_INVALID);
   REFUSE(registers,64,256,0,registers+15,8,STELA_AMD_VRAM_MM_INVALID);
#undef REFUSE
   assert(!stela_amd_vram_mm_read(registers,28,256,256,NULL,0));
   assert(!memcmp(registers,before,sizeof(registers)));
   assert(!stela_amd_vram_mm_read(registers,28,UINT64_C(0x180000004),UINT64_C(0x17ffffffc),data,8));
   assert(registers[mmMM_INDEX]==0x80000000 && registers[mmMM_INDEX_HI]==3);
   assert(data[0]==before[mmMM_DATA] && data[1]==before[mmMM_DATA]);
   for (unsigned i=2; i<16; i++) assert(data[i]==prior[i]);
   for (unsigned i=0; i<16; i++)
      if (i!=mmMM_INDEX && i!=mmMM_INDEX_HI) assert(registers[i]==before[i]);
   /* Highest first-HI value that differs from the original cache sentinel.
    * A later transition to all ones IS programmed by the original algorithm. */
   assert(!stela_amd_vram_mm_read(registers,28,INT64_MAX,
      UINT64_C(0x7fffffff7ffffffc),data,4));
   assert(registers[mmMM_INDEX_HI]==UINT32_MAX-1 && registers[mmMM_INDEX]==UINT32_MAX-3);
   assert(!stela_amd_vram_mm_read(registers,28,INT64_MAX,
      UINT64_C(0x7fffffff7ffffffc),data,8));
   assert(registers[mmMM_INDEX_HI]==UINT32_MAX && registers[mmMM_INDEX]==0x80000000u);
   native_reads=native_writes=0;
   assert(!stela_amd_vram_mm_test_read(registers,28,INT64_MAX,
      UINT64_C(0x7fffffff7ffffffc),data,4));
   assert(native_reads==1 && native_writes==2);
   native_reads=native_writes=0;
   assert(!stela_amd_vram_mm_test_read(registers,28,INT64_MAX,
      UINT64_C(0x7fffffff7ffffffc),data,8));
   assert(native_reads==2 && native_writes==4);
   printf("AMD MM-index: %u atomic native preflight refusals; empty/exact-window/high-index RAM binding checks, no hardware\n",refusals);
}
int main(void) { traces(); native_bounds(); }
