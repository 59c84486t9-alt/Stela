/*
 * Copyright © 2017 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * on the rights to use, copy, modify, merge, publish, distribute, sub
 * license, and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHOR(S) AND/OR THEIR SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef CROCUS_BINDING_TABLE_H
#define CROCUS_BINDING_TABLE_H
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include "util/bitscan.h"

enum crocus_surface_group {
   CROCUS_SURFACE_GROUP_RENDER_TARGET,
   CROCUS_SURFACE_GROUP_RENDER_TARGET_READ,
   CROCUS_SURFACE_GROUP_SOL,
   CROCUS_SURFACE_GROUP_CS_WORK_GROUPS,
   CROCUS_SURFACE_GROUP_TEXTURE,
   CROCUS_SURFACE_GROUP_TEXTURE_GATHER,
   CROCUS_SURFACE_GROUP_IMAGE,
   CROCUS_SURFACE_GROUP_UBO,
   CROCUS_SURFACE_GROUP_SSBO,

   CROCUS_SURFACE_GROUP_COUNT,
};

enum {
   /* Invalid value for a binding table index. */
   CROCUS_SURFACE_NOT_USED = 0xa0a0a0a0,
};

struct crocus_binding_table {
   uint32_t size_bytes;

   /** Number of surfaces in each group, before compacting. */
   uint32_t sizes[CROCUS_SURFACE_GROUP_COUNT];

   /** Initial offset of each group. */
   uint32_t offsets[CROCUS_SURFACE_GROUP_COUNT];

   /** Mask of surfaces used in each group. */
   uint64_t used_mask[CROCUS_SURFACE_GROUP_COUNT];
};

/**
 * Map a <group, index> pair to a binding table index.
 *
 * For example: <UBO, 5> => binding table index 12
 */
static inline uint32_t crocus_group_index_to_bti(const struct crocus_binding_table *bt,
                                                 enum crocus_surface_group group,
                                                 uint32_t index)
{
   assert(index < bt->sizes[group]);
   uint64_t mask = bt->used_mask[group];
   uint64_t bit = 1ull << index;
   if (bit & mask) {
      return bt->offsets[group] + util_bitcount64((bit - 1) & mask);
   } else {
      return CROCUS_SURFACE_NOT_USED;
   }
}

/**
 * Map a binding table index back to a <group, index> pair.
 *
 * For example: binding table index 12 => <UBO, 5>
 */
static inline uint32_t
crocus_bti_to_group_index(const struct crocus_binding_table *bt,
                          enum crocus_surface_group group, uint32_t bti)
{
   uint64_t used_mask = bt->used_mask[group];
   assert(bti >= bt->offsets[group]);

   uint32_t c = bti - bt->offsets[group];
   while (used_mask) {
      int i = u_bit_scan64(&used_mask);
      if (c == 0)
         return i;
      c--;
   }

   return CROCUS_SURFACE_NOT_USED;
}


struct intel_device_info;
struct nir_shader;
struct elk_sampler_prog_key_data;
void crocus_setup_binding_table(const struct intel_device_info *, struct nir_shader *,
                                struct crocus_binding_table *, unsigned, unsigned, unsigned,
                                const struct elk_sampler_prog_key_data *);

#endif
