/* SPDX-License-Identifier: MIT */
#include "discovery_ip.h"
#include "discovery_binary.h"
#include "../amdgpu/amdgpu_discovery_ip_core.h"

_Static_assert(sizeof(int) == sizeof(int32_t), "original int fields");
_Static_assert(sizeof(struct stela_amd_ip_binding) == 8, "IP binding ABI");
_Static_assert(sizeof(struct stela_amd_ip_counts) == 32, "IP counts ABI");
_Static_assert(offsetof(struct stela_amd_ip_counts, sdma_count) == 12, "IP int ABI");
_Static_assert(offsetof(struct stela_amd_ip_counts, node_count) == 28, "IP node ABI");
_Static_assert(AMDGPU_MAX_VCN_INSTANCES == 4, "explicit VCN configuration ABI");

struct stela_amd_ip_shape stela_amd_discovery_ip_shape(void)
{
   return (struct stela_amd_ip_shape){MAX_HWIP, HWIP_MAX_INSTANCE};
}
struct binding_context { uintptr_t base; struct stela_amd_ip_binding *bindings; };
static void bind(void *context, unsigned hw_ip, unsigned instance, uint32_t *base, unsigned count)
{
   struct binding_context *c = context;
   /* Validated original geometry and private callback guarantee same allocation.
    * Convert pointer representation only; never dereference packed u32*. */
   c->bindings[hw_ip * HWIP_MAX_INSTANCE + instance] =
      (struct stela_amd_ip_binding){(uint32_t)((uintptr_t)base - c->base), count};
}
static int range(const void *pointer, size_t bytes, uintptr_t *start, uintptr_t *end)
{
   *start = (uintptr_t)pointer;
   if (!pointer || bytes > UINTPTR_MAX - *start)
      return 0;
   *end = *start + bytes;
   return 1;
}
int stela_amd_discovery_ip_decode(uint8_t *work, size_t bytes,
                                 uint32_t *versions, size_t version_count,
                                 struct stela_amd_ip_binding *bindings, size_t binding_count,
                                 struct stela_amd_ip_counts *counts)
{
   const size_t cells = MAX_HWIP * HWIP_MAX_INSTANCE;
   uintptr_t start[4], end[4];
   if (version_count < cells || binding_count < cells ||
       (uintptr_t)versions % _Alignof(uint32_t) ||
       (uintptr_t)bindings % _Alignof(struct stela_amd_ip_binding) ||
       (uintptr_t)counts % _Alignof(struct stela_amd_ip_counts) ||
       !range(work, bytes, &start[0], &end[0]) ||
       !range(versions, cells * sizeof(*versions), &start[1], &end[1]) ||
       !range(bindings, cells * sizeof(*bindings), &start[2], &end[2]) ||
       !range(counts, sizeof(*counts), &start[3], &end[3]))
      return -EINVAL;
   for (unsigned i = 0; i < 4; i++)
      for (unsigned j = i + 1; j < 4; j++)
         if (start[i] < end[j] && start[j] < end[i])
            return -EINVAL;
   int status = amdgpu_discovery_binary_validate(work, bytes);
   if (status)
      return -EINVAL;
   const struct table_info *info = amdgpu_discovery_binary_table(work, bytes, IP_DISCOVERY);
   if (!info)
      return -EINVAL;
   struct ip_discovery_header *ihdr = (void *)(work + le16_to_cpu(info->offset));
   /* All bounds/errors complete before the first output/working-copy write. */
   *counts = (struct stela_amd_ip_counts){0};
   for (size_t i = 0; i < cells; i++) {
      versions[i] = 0;
      bindings[i] = (struct stela_amd_ip_binding){UINT32_MAX, 0};
   }
   struct binding_context context = {(uintptr_t)work, bindings};
   struct amdgpu_discovery_ip_targets targets = {
      .xcc_mask=&counts->xcc_mask, .sdma_mask=&counts->sdma_mask,
      .vcn_mask=&counts->vcn_mask, .jpeg_mask=&counts->jpeg_mask,
      .vcn_count=&counts->vcn_count, .sdma_count=&counts->sdma_count,
      .vpe_count=&counts->vpe_count, .umc_count=&counts->umc_count,
      .node_count=&counts->node_count,
      .ip_versions=(uint32_t (*)[HWIP_MAX_INSTANCE])versions,
   };
   for (unsigned i = 0; i < AMDGPU_MAX_VCN_INSTANCES; i++)
      targets.vcn_config[i] = &counts->vcn_config[i];
   const struct amdgpu_discovery_ip_ops ops = {.context=&context, .bind=bind};
   /* Validated die IDs/geometry make the original walk's only failure
    * unreachable; no success/failure hardware hook or allocator exists. */
   return amdgpu_discovery_ip_walk(work, ihdr, &targets, &ops);
}
