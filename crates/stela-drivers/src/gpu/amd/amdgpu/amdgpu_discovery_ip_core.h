/*
 * Copyright 2018-2024 Advanced Micro Devices, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef AMDGPU_DISCOVERY_IP_CORE_H
#define AMDGPU_DISCOVERY_IP_CORE_H
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/errno.h>
#else
#include <stdint.h>
#include <stddef.h>
#include "../../common/linux/include/uapi/asm-generic/errno-base.h"
/* Native Stela owns these little-endian snapshots. */
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Native AMD discovery requires little-endian target"
#endif
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define lower_32_bits(x) ((uint32_t)(x))
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
#endif
#include "../include/discovery.h"
#include "../include/soc15_hw_ip.h"
#include "amdgpu_ip_types.h"
#include "amdgpu_ip_limits.h"
#include "amdgpu_ip_instance_limits.h"

static int hw_id_map[MAX_HWIP] = {
	[GC_HWIP]	= GC_HWID,
	[HDP_HWIP]	= HDP_HWID,
	[SDMA0_HWIP]	= SDMA0_HWID,
	[SDMA1_HWIP]	= SDMA1_HWID,
	[SDMA2_HWIP]    = SDMA2_HWID,
	[SDMA3_HWIP]    = SDMA3_HWID,
	[LSDMA_HWIP]    = LSDMA_HWID,
	[MMHUB_HWIP]	= MMHUB_HWID,
	[ATHUB_HWIP]	= ATHUB_HWID,
	[NBIO_HWIP]	= NBIF_HWID,
	[MP0_HWIP]	= MP0_HWID,
	[MP1_HWIP]	= MP1_HWID,
	[UVD_HWIP]	= UVD_HWID,
	[VCE_HWIP]	= VCE_HWID,
	[DF_HWIP]	= DF_HWID,
	[DCE_HWIP]	= DMU_HWID,
	[OSSSYS_HWIP]	= OSSSYS_HWID,
	[SMUIO_HWIP]	= SMUIO_HWID,
	[PWR_HWIP]	= PWR_HWID,
	[NBIF_HWIP]	= NBIF_HWID,
	[THM_HWIP]	= THM_HWID,
	[CLK_HWIP]	= CLKA_HWID,
	[UMC_HWIP]	= UMC_HWID,
	[XGMI_HWIP]	= XGMI_HWID,
	[DCI_HWIP]	= DCI_HWID,
	[PCIE_HWIP]	= PCIE_HWID,
	[VPE_HWIP]	= VPE_HWID,
	[ISP_HWIP]	= ISP_HWID,
	[ATU_HWIP]	= ATU_HWID,
};

/* Direct pointers preserve actual original field types and intermediate writes.
 * This is a bounded decode target, not an amdgpu_device or hardware owner. */
struct amdgpu_discovery_ip_targets {
	uint16_t *xcc_mask, *vcn_mask, *jpeg_mask;
	uint32_t *sdma_mask, *vpe_count, *node_count;
	int *sdma_count, *umc_count;
	uint8_t *vcn_count, *vcn_config[AMDGPU_MAX_VCN_INSTANCES];
	uint32_t (*ip_versions)[HWIP_MAX_INSTANCE];
};
struct amdgpu_discovery_ip_ops {
	void *context;
	void (*bind)(void *context, unsigned hw_ip, unsigned instance,
		     uint32_t *base, unsigned count);
	/* NULL diagnostic callbacks explicitly disable diagnostic output only. */
	void (*debug)(void *context, const char *format, ...);
	void (*error)(void *context, const char *format, ...);
	void (*drm_error)(void *context, const char *format, ...);
	const char *const *hw_id_names;
};
#define AMDGPU_IP_DEBUG(ops, ...) do { if ((ops)->debug) (ops)->debug((ops)->context, __VA_ARGS__); } while (0)
#define AMDGPU_IP_ERROR(ops, ...) do { if ((ops)->error) (ops)->error((ops)->context, __VA_ARGS__); } while (0)
#define AMDGPU_IP_DRM_ERROR(ops, ...) do { if ((ops)->drm_error) (ops)->drm_error((ops)->context, __VA_ARGS__); } while (0)

static inline int amdgpu_discovery_ip_valid(const struct amdgpu_discovery_ip_ops *ops,
					  uint8_t instance, uint16_t hw_id)
{
	if (instance >= HWIP_MAX_INSTANCE) {
		AMDGPU_IP_ERROR(ops,
			"Unexpected instance_number (%d) from ip discovery blob\n",
			instance);
		return -EINVAL;
	}
	if (hw_id >= HW_ID_MAX) {
		AMDGPU_IP_ERROR(ops,
			"Unexpected hw_id (%d) from ip discovery blob\n",
			hw_id);
		return -EINVAL;
	}

	return 0;
}

/* Caller has validated immutable original geometry before its private copy is
 * mutated. Run once; preserve original32/64 strides and packed accesses. Linux
 * caller retains its acquisition/mask reset/table-error ordering and targets. */
static inline int amdgpu_discovery_ip_walk(uint8_t *discovery_bin,
		struct ip_discovery_header *ihdr,
		const struct amdgpu_discovery_ip_targets *targets,
		const struct amdgpu_discovery_ip_ops *ops)
{
	uint8_t num_base_address, subrev, variant;
	struct die_header *dhdr;
	struct ip_v4 *ip;
	uint16_t die_offset, ip_offset, num_dies, num_ips, hw_id;
	uint32_t wafl_ver = 0;
	uint8_t inst;
	int hw_ip, i, j, k;
	num_dies = le16_to_cpu(ihdr->num_dies);

	AMDGPU_IP_DEBUG(ops, "number of dies: %d\n", num_dies);

	for (i = 0; i < num_dies; i++) {
		die_offset = le16_to_cpu(ihdr->die_info[i].die_offset);
		dhdr = (struct die_header *)(discovery_bin + die_offset);
		num_ips = le16_to_cpu(dhdr->num_ips);
		ip_offset = die_offset + sizeof(*dhdr);

		if (le16_to_cpu(dhdr->die_id) != i) {
			AMDGPU_IP_DRM_ERROR(ops, "invalid die id %d, expected %d\n",
					le16_to_cpu(dhdr->die_id), i);
			return -EINVAL;
		}

		AMDGPU_IP_DEBUG(ops, "number of hardware IPs on die%d: %d\n",
				le16_to_cpu(dhdr->die_id), num_ips);

		for (j = 0; j < num_ips; j++) {
			ip = (struct ip_v4 *)(discovery_bin + ip_offset);

			inst = ip->instance_number;
			hw_id = le16_to_cpu(ip->hw_id);
			if (amdgpu_discovery_ip_valid(ops, inst, hw_id))
				goto next_ip;

			num_base_address = ip->num_base_address;

			AMDGPU_IP_DEBUG(ops, "%s(%d) #%d v%d.%d.%d:\n",
				  ops->hw_id_names[le16_to_cpu(ip->hw_id)],
				  le16_to_cpu(ip->hw_id),
				  ip->instance_number,
				  ip->major, ip->minor,
				  ip->revision);

			if (le16_to_cpu(ip->hw_id) == VCN_HWID) {
				/* Bit [5:0]: original revision value
				 * Bit [7:6]: en/decode capability:
				 *     0b00 : VCN function normally
				 *     0b10 : encode is disabled
				 *     0b01 : decode is disabled
				 */
				if ((*targets->vcn_count) <
				    AMDGPU_MAX_VCN_INSTANCES) {
					(*targets->vcn_config[(*targets->vcn_count)]) =
						ip->revision & 0xc0;
					(*targets->vcn_count)++;
					(*targets->vcn_mask) |=
						(1U << ip->instance_number);
					(*targets->jpeg_mask) |=
						(1U << ip->instance_number);
				} else {
					AMDGPU_IP_ERROR(ops, "Too many VCN instances: %d vs %d\n",
						(*targets->vcn_count) + 1,
						AMDGPU_MAX_VCN_INSTANCES);
				}
				ip->revision &= ~0xc0;
			}
			if (le16_to_cpu(ip->hw_id) == SDMA0_HWID ||
			    le16_to_cpu(ip->hw_id) == SDMA1_HWID ||
			    le16_to_cpu(ip->hw_id) == SDMA2_HWID ||
			    le16_to_cpu(ip->hw_id) == SDMA3_HWID) {
				if ((*targets->sdma_count) <
				    AMDGPU_MAX_SDMA_INSTANCES) {
					(*targets->sdma_count)++;
					(*targets->sdma_mask) |=
						(1U << ip->instance_number);
				} else {
					AMDGPU_IP_ERROR(ops, "Too many SDMA instances: %d vs %d\n",
						(*targets->sdma_count) + 1,
						AMDGPU_MAX_SDMA_INSTANCES);
				}
			}

			if (le16_to_cpu(ip->hw_id) == VPE_HWID) {
				if ((*targets->vpe_count) < AMDGPU_MAX_VPE_INSTANCES)
					(*targets->vpe_count)++;
				else
					AMDGPU_IP_ERROR(ops, "Too many VPE instances: %d vs %d\n",
						(*targets->vpe_count) + 1,
						AMDGPU_MAX_VPE_INSTANCES);
			}

			if (le16_to_cpu(ip->hw_id) == UMC_HWID) {
				(*targets->umc_count)++;
				(*targets->node_count)++;
			}

			if (le16_to_cpu(ip->hw_id) == GC_HWID)
				(*targets->xcc_mask) |=
					(1U << ip->instance_number);

			if (!wafl_ver && le16_to_cpu(ip->hw_id) == WAFLC_HWID)
				wafl_ver = IP_VERSION_FULL((uint32_t)ip->major, (uint32_t)ip->minor,
							   (uint32_t)ip->revision, 0, 0);

			for (k = 0; k < num_base_address; k++) {
				/*
				 * convert the endianness of base addresses in place,
				 * so that we don't need to convert them when accessing adev->reg_offset.
				 */
				if (ihdr->base_addr_64_bit)
					/* Truncate the 64bit base address from ip discovery
					 * and only store lower 32bit ip base in reg_offset[].
					 * Bits > 32 follows ASIC specific format, thus just
					 * discard them and handle it within specific ASIC.
					 * By this way reg_offset[] and related helpers can
					 * stay unchanged.
					 * The base address is in dwords, thus clear the
					 * highest 2 bits to store.
					 */
					ip->base_address[k] =
						lower_32_bits(le64_to_cpu(ip->base_address_64[k])) & 0x3FFFFFFF;
				else
					ip->base_address[k] = le32_to_cpu(ip->base_address[k]);
				AMDGPU_IP_DEBUG(ops, "\t0x%08x\n", ip->base_address[k]);
			}

			for (hw_ip = 0; hw_ip < MAX_HWIP; hw_ip++) {
				if (hw_id_map[hw_ip] == le16_to_cpu(ip->hw_id) &&
				    hw_id_map[hw_ip] != 0) {
					AMDGPU_IP_DEBUG(ops, "set register base offset for %s\n",
							ops->hw_id_names[le16_to_cpu(ip->hw_id)]);
					ops->bind(ops->context, hw_ip, ip->instance_number,
						  ip->base_address, num_base_address);
					/* Instance support is somewhat inconsistent.
					 * SDMA is a good example.  Sienna cichlid has 4 total
					 * SDMA instances, each enumerated separately (HWIDs
					 * 42, 43, 68, 69).  Arcturus has 8 total SDMA instances,
					 * but they are enumerated as multiple instances of the
					 * same HWIDs (4x HWID 42, 4x HWID 43).  UMC is another
					 * example.  On most chips there are multiple instances
					 * with the same HWID.
					 */

					if (ihdr->version < 3) {
						subrev = 0;
						variant = 0;
					} else {
						subrev = ip->sub_revision;
						variant = ip->variant;
					}

					targets->ip_versions[hw_ip]
							 [ip->instance_number] =
						IP_VERSION_FULL((uint32_t)ip->major,
								(uint32_t)ip->minor,
								(uint32_t)ip->revision,
								variant,
								subrev);
				}
			}

next_ip:
			if (ihdr->base_addr_64_bit)
				ip_offset += struct_size(ip, base_address_64, ip->num_base_address);
			else
				ip_offset += struct_size(ip, base_address, ip->num_base_address);
		}
	}

	if (wafl_ver && !targets->ip_versions[XGMI_HWIP][0])
		targets->ip_versions[XGMI_HWIP][0] = wafl_ver;

	return 0;
}
#undef AMDGPU_IP_DEBUG
#undef AMDGPU_IP_ERROR
#undef AMDGPU_IP_DRM_ERROR
#endif
