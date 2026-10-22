/* SPDX-License-Identifier: MIT */
/* Original C records and private input ABI; compile-only layout arrays on every
 * native target. Host main uses only bounded CPU config, never RM/hardware. */
#include "../device.h"
#include "../pci.h"
const NvU64 stela_nvidia_device_layout[] = {
    sizeof(struct stela_nvidia_device_bar), _Alignof(struct stela_nvidia_device_bar),
    offsetof(struct stela_nvidia_device_bar, bytes), offsetof(struct stela_nvidia_device_bar, index),
    offsetof(struct stela_nvidia_device_bar, prefetchable),
    sizeof(struct stela_nvidia_device_identity), _Alignof(struct stela_nvidia_device_identity),
    offsetof(struct stela_nvidia_device_identity, subsystem),
    sizeof(nv_state_t), _Alignof(nv_state_t), offsetof(nv_state_t, bars),
    offsetof(nv_state_t, handle), offsetof(nv_state_t, regs), offsetof(nv_state_t, fb),
    sizeof(nv_aperture_t), offsetof(nv_aperture_t, offset),
    NV_GPU_NUM_BARS, NV_GPU_BAR_INDEX_REGS, NV_GPU_BAR_INDEX_FB, NV_GPU_BAR_INDEX_IMEM,
};
#ifdef STELA_NVIDIA_DEVICE_TEST_MAIN
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct config { NvU32 words[NVRM_PCICFG_NUM_DWORDS], reads; };
static NvU32 read_config(void *p, NvU32 offset, NvU32 width, NvU32 *out)
{
    struct config *c = p;
    assert(width == 4 && offset < sizeof(c->words) && !(offset & 3));
    ++c->reads; *out = c->words[offset / 4]; return 1;
}
static NvU32 write_config(void *p, NvU32 offset, NvU32 width, NvU32 value)
{ (void)p; (void)offset; (void)width; (void)value; assert(0); return 0; }
int main(void)
{
    const struct config original = {.words = {[0]=0x268410de, [2]=0x03000001,
        [4]=0x10000004, [5]=1, [6]=0x2000000c, [7]=2, [8]=0x30000004, [9]=3,
        [11]=0x123410de}};
    const struct stela_nvidia_device_identity id = {3,0x42,5,0,0x10de,0x2684,0x10de,0x1234};
    const struct stela_nvidia_device_bar original_bars[3] = {
        {0x110000000,0x10000,0,0},{0x220000000,0x200000,2,1},{0x330000000,0x10000,4,0}};
    unsigned refused = 0;
    for (unsigned mode=0; mode<13; ++mode) {
        struct config config=original;
        struct stela_nvidia_pci handle={&config,read_config,write_config};
        struct stela_nvidia_device_identity identity=id;
        struct stela_nvidia_device_bar bars[3]; memcpy(bars,original_bars,sizeof(bars));
        nv_state_t state, before; memset(&state,0,sizeof(state)); memcpy(&before,&state,sizeof(state));
        switch(mode) {
        case 0: break; case 1:config.words[0]^=1;break;case 2:config.words[11]^=1;break;
        case 3:config.words[3]=0x10000;break;case 4:bars[0].physical^=0x10000;break;
        case 5:bars[1].index=4;break;case 6:bars[0].prefetchable=1;break;
        case 7:bars[1].bytes=NV_U64_MAX;break;case 8:identity.function=8;break;
        case 9:config.words[4]|=1;break;case 10:config.words[8]=0;config.words[9]=0;break;
        case 11: { struct stela_nvidia_device_bar tmp=bars[0];bars[0]=bars[2];bars[2]=tmp; break; }
        case 12:
            /* A generic ordered-memory scan would accept this, but the
             * original second loop skips index0 then repeats index1 as FB. */
            memset(&config.words[4],0,6*sizeof(NvU32));
            config.words[5]=0x10000000;config.words[6]=0x20000008;config.words[7]=0x30000000;
            bars[0]=(struct stela_nvidia_device_bar){0x10000000,0x10000,1,0};
            bars[1]=(struct stela_nvidia_device_bar){0x20000000,0x200000,2,1};
            bars[2]=(struct stela_nvidia_device_bar){0x30000000,0x10000,3,0};
            break;
        }
        NV_STATUS status=stela_nvidia_prepare_device(&state,&handle,&identity,bars,3);
        if(mode) {assert(status!=NV_OK);assert(!memcmp(&state,&before,sizeof(state)));++refused;continue;}
        assert(status==NV_OK && config.reads==NVRM_PCICFG_NUM_DWORDS);
        assert(state.handle==&handle && !state.priv && !state.os_state && !state.dma_dev && !state.flags);
        assert(state.pci_info.domain==3 && state.pci_info.bus==0x42 && state.pci_info.slot==5);
        assert(state.regs==&state.bars[NV_GPU_BAR_INDEX_REGS]);assert(state.fb==&state.bars[NV_GPU_BAR_INDEX_FB]);
        for(unsigned i=0;i<NV_GPU_NUM_BARS;++i){assert(state.bars[i].cpu_address==bars[i].physical);
            assert(state.bars[i].size==bars[i].bytes && state.bars[i].offset==NVRM_PCICFG_BAR_OFFSET(bars[i].index));
            assert(!state.bars[i].map&&!state.bars[i].map_u);}
        assert(!memcmp(state.pci_cfg_space,original.words,sizeof(original.words)));
        assert(stela_nvidia_prepared_device_retirable(&state,&handle)==NV_OK);
        state.flags=NV_FLAG_INITIALIZED;assert(stela_nvidia_prepared_device_retirable(&state,&handle)==NV_ERR_INVALID_STATE);
        state.flags=0;state.priv=&config;assert(stela_nvidia_prepared_device_retirable(&state,&handle)==NV_ERR_INVALID_STATE);
    }
    printf("original C nv_state/BAR roles+layout, %u atomic refusals; CPU-only preparation\n",refused);
    return 0;
}
#endif
