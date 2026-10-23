/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_AIR_THREADGROUP_ELK_H
#define STELA_INTEL_AIR_THREADGROUP_ELK_H

#include <assert.h>

struct elk_compiler;
struct stela_intel_shared_stats {
    unsigned loads, stores, fences, barriers, waits;
    unsigned first_load, first_store, first_fence, first_barrier, first_wait;
};

static inline void stela_intel_shared_order(struct stela_intel_shared_stats *stats,
    unsigned ordinal)
{
    assert(ordinal);
    if (stats->stores && !stats->first_store) stats->first_store = ordinal;
    if (stats->fences && !stats->first_fence) stats->first_fence = ordinal;
    if (stats->barriers && !stats->first_barrier) stats->first_barrier = ordinal;
    if (stats->waits && !stats->first_wait) stats->first_wait = ordinal;
    if (stats->loads && !stats->first_load) stats->first_load = ordinal;
}

void stela_intel_elk_shared_stats(const struct elk_compiler *, const void *, unsigned,
                                 struct stela_intel_shared_stats *);

#endif
