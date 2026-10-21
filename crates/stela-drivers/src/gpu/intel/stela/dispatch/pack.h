/* SPDX-License-Identifier: MIT */
#include "../dispatch_internal.h"

/* One translation unit per hardware generation, as in Mesa. Original XML
 * packers contain global enum constants and must not be combined in one TU.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wsign-conversion"
#include STELA_PACK_HEADER
#pragma clang diagnostic pop

static void pack(uint32_t *words, const struct stela_intel_gpgpu_dispatch *dispatch)
{
    /* Same complete walker field selection as Iris's direct dispatch path. */
    struct GENX(GPGPU_WALKER) walker = {
        GENX(GPGPU_WALKER_header),
        .SIMDSize = dispatch->simd_size / 16,
        .ThreadDepthCounterMaximum = 0, .ThreadHeightCounterMaximum = 0,
        .ThreadWidthCounterMaximum = dispatch->threads - 1,
        .ThreadGroupIDXDimension = dispatch->groups[0],
        .ThreadGroupIDYDimension = dispatch->groups[1],
        .ThreadGroupIDZDimension = dispatch->groups[2],
        .RightExecutionMask = dispatch->right_mask, .BottomExecutionMask = UINT32_MAX,
    };
    struct GENX(MEDIA_STATE_FLUSH) flush = {GENX(MEDIA_STATE_FLUSH_header)};
    GENX(GPGPU_WALKER_pack)(NULL, words, &walker);
    GENX(MEDIA_STATE_FLUSH_pack)(NULL, words + GENX(GPGPU_WALKER_length), &flush);
}

const struct stela_intel_gpgpu_encoder STELA_ENCODER = {
    .words = GENX(GPGPU_WALKER_length) + GENX(MEDIA_STATE_FLUSH_length), .pack = pack,
};
