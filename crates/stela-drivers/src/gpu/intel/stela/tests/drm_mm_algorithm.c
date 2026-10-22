/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "drm_mm_bind.h"
#include "rbtree-body-full.inc"
#include "drm-mm-body.inc"
const unsigned int stela_mm_layout[] = {
    sizeof(void *), sizeof(long), sizeof(struct drm_mm), _Alignof(struct drm_mm),
    sizeof(struct drm_mm_node), _Alignof(struct drm_mm_node),
    offsetof(struct drm_mm_node, rb), offsetof(struct drm_mm_node, rb_hole_size),
    offsetof(struct drm_mm_node, rb_hole_addr), offsetof(struct drm_mm_node, flags),
    sizeof(((struct drm_mm_node *)0)->color), sizeof(((struct drm_mm_node *)0)->flags)
};
/* Source-bound admission limit witness, not a claimed generic native fix. */
int stela_mm_wide_alignment_limit(void)
{
    u64 alignment = 0x100000002ULL;
    return is_power_of_2(alignment);
}
