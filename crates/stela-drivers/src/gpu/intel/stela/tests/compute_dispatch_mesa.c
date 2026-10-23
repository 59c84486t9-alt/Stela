/* SPDX-License-Identifier: MIT */
#include "../compute_dispatch.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define __gen_address_type uint64_t
#define __gen_user_data void
static inline uint64_t combine_address(void *data, void *location, uint64_t address, uint32_t delta)
{
    (void)data; (void)location;
    return address + delta;
}
#define __gen_combine_address combine_address
#include "intel/genxml/gen_macros.h"
#include "intel/genxml/genX_pack.h"

static uint32_t random_u32(uint32_t *value)
{
    *value ^= *value << 13; *value ^= *value >> 17; *value ^= *value << 5;
    return *value;
}

int main(void)
{
    uint32_t random = 0x125c0de;
    for (unsigned i = 0; i < 10000; ++i) {
        struct stela_intel_compute_dispatch dispatch = {
            .gfx_verx10 = GFX_VERx10,
            .local_size = {1 + random_u32(&random) % 32, 1 + random_u32(&random) % 8,
                1 + random_u32(&random) % 4},
            .simd_size = GFX_VERx10 == 125 ? 8u << (random_u32(&random) % 3) :
                                             16u << (random_u32(&random) % 2),
            .groups = {random_u32(&random) | 1, random_u32(&random) | 1, random_u32(&random) | 1},
            .kernel_offset = random_u32(&random) & ~63u,
            .binding_table_offset = random_u32(&random) & 0x1fffe0,
            .binding_table_entry_count = random_u32(&random) % 32,
            .sampler_offset = random_u32(&random) & ~31u,
            .sampler_count = random_u32(&random) % 5,
            .uses_sampler = 1,
            .slm_encoding = random_u32(&random) % (GFX_VERx10 == 125 ? 8 : 15),
            .preferred_slm_encoding = GFX_VERx10 == 125 ? 8 + random_u32(&random) % 8 :
                                                          random_u32(&random) % 11,
            .barrier_encoding = random_u32(&random) % 8,
            .thread_group_dispatch_size = random_u32(&random) % 4,
            .walk_order = random_u32(&random) % 6,
            .post_sync_mocs = 1 + random_u32(&random) % 127,
        };
        if (!dispatch.sampler_count)
            dispatch.uses_sampler = random_u32(&random) % 2;
        if (!(dispatch.local_size[0] & (dispatch.local_size[0] - 1)) &&
            !(dispatch.local_size[1] & (dispatch.local_size[1] - 1)))
            dispatch.generate_local_id = dispatch.local_size[2] > 1 ? 7 :
                                         dispatch.local_size[1] > 1 ? 3 :
                                         dispatch.local_size[0] > 1 ? 1 : 0;
#if GFX_VERx10 >= 300
        dispatch.register_blocks = random_u32(&random) % 7;
        if (dispatch.register_blocks == 6) dispatch.register_blocks = 7;
#endif
        uint32_t count = dispatch.local_size[0] * dispatch.local_size[1] * dispatch.local_size[2];
        dispatch.threads = (count + dispatch.simd_size - 1) / dispatch.simd_size;
        dispatch.right_mask = UINT32_MAX >>
            (32 - (count - (dispatch.threads - 1) * dispatch.simd_size));
        uint32_t actual[44], expected[44];
        memset(actual, 0xa5, sizeof(actual)); memset(expected, 0xa5, sizeof(expected));
        struct stela_intel_commands commands = {actual, 44, 1, 48};
        assert(stela_intel_compute_dispatch(&commands, &dispatch) == 0);
        /* Independent original hosted full packers, including descriptor and
         * PostSync. Random fields test encoding, not valid live device policy. */
        struct GENX(COMPUTE_WALKER) walker = {
            GENX(COMPUTE_WALKER_header),
            .body = {
                .SIMDSize = dispatch.simd_size / 16, .MessageSIMD = dispatch.simd_size / 16,
                .LocalXMaximum = dispatch.local_size[0] - 1,
                .LocalYMaximum = dispatch.local_size[1] - 1,
                .LocalZMaximum = dispatch.local_size[2] - 1,
                .ThreadGroupIDXDimension = dispatch.groups[0],
                .ThreadGroupIDYDimension = dispatch.groups[1],
                .ThreadGroupIDZDimension = dispatch.groups[2],
                .ExecutionMask = dispatch.right_mask,
                .PostSync.MOCS = dispatch.post_sync_mocs,
                .InterfaceDescriptor = {
                    .KernelStartPointer = dispatch.kernel_offset,
                    .NumberofThreadsinGPGPUThreadGroup = dispatch.threads,
                    .ThreadGroupDispatchSize = dispatch.thread_group_dispatch_size,
                    .SharedLocalMemorySize = dispatch.slm_encoding,
                    .PreferredSLMAllocationSize = dispatch.preferred_slm_encoding,
                    .SamplerStatePointer = dispatch.sampler_offset,
                    .SamplerCount = dispatch.sampler_count,
                    .BindingTablePointer = dispatch.binding_table_offset,
                    .BindingTableEntryCount = dispatch.binding_table_entry_count,
                    .NumberOfBarriers = dispatch.barrier_encoding,
#if GFX_VERx10 >= 300
                    .RegistersPerThread = dispatch.register_blocks,
#endif
                },
                .GenerateLocalID = dispatch.generate_local_id != 0,
                .EmitLocal = dispatch.generate_local_id, .WalkOrder = dispatch.walk_order,
                .TileLayout = dispatch.walk_order == 2 ? TileY32bpe : Linear,
#if GFX_VERx10 >= 300
                .DispatchWalkOrder = dispatch.uses_sampler ? MortonWalk : LinearWalk,
                .ThreadGroupBatchSize = dispatch.uses_sampler ? TG_BATCH_4 : TG_BATCH_1,
#endif
            },
        };
        GENX(COMPUTE_WALKER_pack)(NULL, expected + 1, &walker);
        assert(commands.used == 1 + GENX(COMPUTE_WALKER_length));
        assert(!memcmp(actual, expected, sizeof(actual)));
    }
    printf("Native COMPUTE_WALKER vs hosted Mesa GFX_VERx10=%d: 10000 packets passed\n",
        GFX_VERx10);
    return 0;
}
