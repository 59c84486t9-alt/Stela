/* SPDX-License-Identifier: MIT */
#include "../compute_dispatch_internal.h"
#include "../genxml_native.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wsign-conversion"
#include STELA_PACK_HEADER
#pragma clang diagnostic pop

static void pack(uint32_t *words, const struct stela_intel_compute_dispatch *dispatch)
{
    /* Field selection from Iris iris_upload_compute_walker(). All dynamic
     * shader/resource policy is explicit; encodings stay in original XML. */
    struct GENX(INTERFACE_DESCRIPTOR_DATA) descriptor = {
        .KernelStartPointer = dispatch->kernel_offset,
        .NumberofThreadsinGPGPUThreadGroup = dispatch->threads,
        .ThreadGroupDispatchSize = dispatch->thread_group_dispatch_size,
        .SharedLocalMemorySize = dispatch->slm_encoding,
#if STELA_GFX_VERx10 >= 200
        .PreferredSLMAllocationSize = (enum GENX(PREF_SLM_ALLOCATION_SIZE))dispatch->preferred_slm_encoding,
#else
        .PreferredSLMAllocationSize = dispatch->preferred_slm_encoding,
#endif
        .SamplerStatePointer = dispatch->sampler_offset,
        .SamplerCount = dispatch->sampler_count,
        .BindingTablePointer = dispatch->binding_table_offset,
        .BindingTableEntryCount = dispatch->binding_table_entry_count,
        .NumberOfBarriers = dispatch->barrier_encoding,
#if STELA_GFX_VERx10 >= 300
        .RegistersPerThread = dispatch->register_blocks,
#endif
    };
    struct GENX(COMPUTE_WALKER) walker = {
        GENX(COMPUTE_WALKER_header),
        .body = {
            .SIMDSize = dispatch->simd_size / 16,
            .MessageSIMD = dispatch->simd_size / 16,
            .LocalXMaximum = dispatch->local_size[0] - 1,
            .LocalYMaximum = dispatch->local_size[1] - 1,
            .LocalZMaximum = dispatch->local_size[2] - 1,
            .ThreadGroupIDXDimension = dispatch->groups[0],
            .ThreadGroupIDYDimension = dispatch->groups[1],
            .ThreadGroupIDZDimension = dispatch->groups[2],
            .ExecutionMask = dispatch->right_mask,
            .PostSync.MOCS = dispatch->post_sync_mocs,
            .InterfaceDescriptor = descriptor,
            .GenerateLocalID = dispatch->generate_local_id != 0,
            .EmitLocal = dispatch->generate_local_id,
            .WalkOrder = dispatch->walk_order,
            .TileLayout = dispatch->walk_order == 2 ? TileY32bpe : Linear,
#if STELA_GFX_VERx10 >= 300
            /* Iris HSD 14016252163 policy, including bindless sampler use. */
            .DispatchWalkOrder = dispatch->uses_sampler ? MortonWalk : LinearWalk,
            .ThreadGroupBatchSize = dispatch->uses_sampler ? TG_BATCH_4 : TG_BATCH_1,
#endif
        },
    };
    GENX(COMPUTE_WALKER_pack)(NULL, words, &walker);
}

const struct stela_intel_compute_encoder STELA_ENCODER = {
    .words = GENX(COMPUTE_WALKER_length), .pack = pack,
};
