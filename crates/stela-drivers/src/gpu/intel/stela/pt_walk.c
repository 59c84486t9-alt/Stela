/* SPDX-License-Identifier: GPL-2.0-only */
#include "pt_walk.h"

#define INTEL_PT_MAX_LEVEL 4U
#define INTEL_PT_INDEX_BITS 9U
#define INVALID_ARGUMENT (-22)

int stela_intel_pt_walk(struct xe_ptw *parent, unsigned int level,
                       u64 addr, u64 end, struct xe_pt_walk *walk, bool shared)
{
    if (!parent || !walk || !walk->ops || !walk->ops->pt_entry || !walk->shifts ||
        walk->max_level > INTEL_PT_MAX_LEVEL || level > walk->max_level || addr > end)
        return INVALID_ARGUMENT;

    if (walk->shifts[0] != 12 && walk->shifts[0] != 16)
        return INVALID_ARGUMENT;
    for (unsigned int i = 1; i <= walk->max_level; ++i) {
        if (walk->shifts[i] != 12 + INTEL_PT_INDEX_BITS * i)
            return INVALID_ARGUMENT;
    }
    if (addr == end)
        return 0;

    u64 parent_shift = level < walk->max_level ? walk->shifts[level + 1] :
                      walk->shifts[level] + INTEL_PT_INDEX_BITS;
    if (level == walk->max_level) {
        if (end > (1ULL << parent_shift))
            return INVALID_ARGUMENT;
    } else if ((addr >> parent_shift) != ((end - 1) >> parent_shift)) {
        return INVALID_ARGUMENT;
    }

    if (shared)
        return xe_pt_walk_shared(parent, level, addr, end, walk);
    return xe_pt_walk_range(parent, level, addr, end, walk);
}
