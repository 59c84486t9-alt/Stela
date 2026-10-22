/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_DISCOVERY_IP_H
#define STELA_AMD_DISCOVERY_IP_H
#include <stdint.h>
#include <stddef.h>
struct stela_amd_ip_binding { uint32_t offset, count; };
struct stela_amd_ip_counts {
   uint16_t xcc_mask, vcn_mask, jpeg_mask;
   uint8_t vcn_count, vcn_config[4];
   int32_t sdma_count;
   uint32_t sdma_mask, vpe_count;
   int32_t umc_count;
   uint32_t node_count;
};
struct stela_amd_ip_shape { uint32_t hw_ip_count, instances; };
struct stela_amd_ip_shape stela_amd_discovery_ip_shape(void);
/* One validated fresh private copy, run once. Not an acquisition/admission API.
 * No pointer retained. All arrays are real disjoint CPU allocations. Error
 * leaves work/output bytes untouched. Counts correspond to the original fresh
 * zeroed device, before harvest/final topology. No device services performed. */
int stela_amd_discovery_ip_decode(uint8_t *work, size_t bytes,
                                 uint32_t *versions, size_t version_count,
                                 struct stela_amd_ip_binding *bindings, size_t binding_count,
                                 struct stela_amd_ip_counts *counts);
#endif
