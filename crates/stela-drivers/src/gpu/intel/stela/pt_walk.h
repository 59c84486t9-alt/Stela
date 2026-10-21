/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef STELA_INTEL_PT_WALK_H
#define STELA_INTEL_PT_WALK_H

#include "../xe/xe_pt_walk.h"

/* Native, kernel-owned page trees only. The caller owns every node/children
 * array and serializes edits. Callbacks preserve the validated geometry and
 * their borrowed data until completion; they may return errors. No allocation,
 * physical DMA mapping, PTE write, TLB invalidation or GPU completion is implied.
 *
 * The wrapper validates Intel's normal/compact page geometry, root bounds and
 * range before entering the unchanged Xe algorithm. Malformed input returns
 * -22; callback errors pass through unchanged. Empty ranges visit no nodes.
 */
int stela_intel_pt_walk(struct xe_ptw *parent, unsigned int level,
                       u64 addr, u64 end, struct xe_pt_walk *walk, bool shared);

#endif
