/*
 * Copyright © 2017 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef IRIS_BINDING_TABLE_H
#define IRIS_BINDING_TABLE_H
#include <stdbool.h>
#include <stdint.h>

enum iris_surface_group {
   IRIS_SURFACE_GROUP_RENDER_TARGET,
   IRIS_SURFACE_GROUP_RENDER_TARGET_READ,
   IRIS_SURFACE_GROUP_CS_WORK_GROUPS,
   IRIS_SURFACE_GROUP_TEXTURE_LOW64,
   IRIS_SURFACE_GROUP_TEXTURE_HIGH64,
   IRIS_SURFACE_GROUP_IMAGE,
   IRIS_SURFACE_GROUP_UBO,
   IRIS_SURFACE_GROUP_SSBO,

   IRIS_SURFACE_GROUP_COUNT,
};

enum {
   /* Workaround index to HSDES #22020184996 */
   IRIS_SURFACE_NULL_PUSH_TBIMR_WA = UINT16_MAX,

   /* Invalid value for a binding table index. */
   IRIS_SURFACE_NOT_USED = 0xa0a0a0a0,
};

struct iris_binding_table {
   uint32_t size_bytes;

   /** Number of surfaces in each group, before compacting. */
   uint32_t surf_count[IRIS_SURFACE_GROUP_COUNT];

   /** Initial offset of each group. */
   uint32_t offsets[IRIS_SURFACE_GROUP_COUNT];

   /** Mask of surfaces used in each group. */
   uint64_t used_mask[IRIS_SURFACE_GROUP_COUNT];

   uint64_t samplers_used_mask;

   /** Whether the first render target is a null fb surface */
   uint8_t use_null_rt;
};

struct intel_device_info;
struct nir_shader;
uint32_t iris_group_index_to_bti(const struct iris_binding_table *, enum iris_surface_group, uint32_t);
uint32_t iris_bti_to_group_index(const struct iris_binding_table *, enum iris_surface_group, uint32_t);
void iris_setup_binding_table(const struct intel_device_info *, struct nir_shader *,
                              struct iris_binding_table *, unsigned, unsigned, unsigned, bool);

#endif
