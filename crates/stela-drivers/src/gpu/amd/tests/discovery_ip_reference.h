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

/* Frozen original consumer, exact92d3 body identical to Linux8d3ae592.
 * Test-only real-field prototype, not a production device. */
#define hw_id_map ip_donor_hw_id_map
#define amdgpu_discovery_validate_ip ip_donor_amdgpu_discovery_validate_ip
#define amdgpu_discovery_reg_base_init ip_donor_amdgpu_discovery_reg_base_init
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

static int amdgpu_discovery_validate_ip(struct amdgpu_device *adev,
					uint8_t instance, uint16_t hw_id)
{
	if (instance >= HWIP_MAX_INSTANCE) {
		dev_err(adev->dev,
			"Unexpected instance_number (%d) from ip discovery blob\n",
			instance);
		return -EINVAL;
	}
	if (hw_id >= HW_ID_MAX) {
		dev_err(adev->dev,
			"Unexpected hw_id (%d) from ip discovery blob\n",
			hw_id);
		return -EINVAL;
	}

	return 0;
}

static int amdgpu_discovery_reg_base_init(struct amdgpu_device *adev)
{
	uint8_t num_base_address, subrev, variant;
	struct table_info *info;
	struct ip_discovery_header *ihdr;
	struct die_header *dhdr;
	uint8_t *discovery_bin;
	struct ip_v4 *ip;
	uint16_t die_offset;
	uint16_t ip_offset;
	uint16_t num_dies;
	uint32_t wafl_ver;
	uint16_t num_ips;
	uint16_t hw_id;
	uint8_t inst;
	int hw_ip;
	int i, j, k;
	int r;

	r = amdgpu_discovery_init(adev);
	if (r)
		return r;
	discovery_bin = adev->discovery.bin;
	wafl_ver = 0;
	adev->gfx.xcc_mask = 0;
	adev->sdma.sdma_mask = 0;
	adev->vcn.inst_mask = 0;
	adev->jpeg.inst_mask = 0;
	r = amdgpu_discovery_get_table_info(adev, &info, IP_DISCOVERY);
	if (r)
		return r;
	ihdr = (struct ip_discovery_header
			*)(discovery_bin +
			   le16_to_cpu(info->offset));
	num_dies = le16_to_cpu(ihdr->num_dies);

	DRM_DEBUG("number of dies: %d\n", num_dies);

	for (i = 0; i < num_dies; i++) {
		die_offset = le16_to_cpu(ihdr->die_info[i].die_offset);
		dhdr = (struct die_header *)(discovery_bin + die_offset);
		num_ips = le16_to_cpu(dhdr->num_ips);
		ip_offset = die_offset + sizeof(*dhdr);

		if (le16_to_cpu(dhdr->die_id) != i) {
			DRM_ERROR("invalid die id %d, expected %d\n",
					le16_to_cpu(dhdr->die_id), i);
			return -EINVAL;
		}

		DRM_DEBUG("number of hardware IPs on die%d: %d\n",
				le16_to_cpu(dhdr->die_id), num_ips);

		for (j = 0; j < num_ips; j++) {
			ip = (struct ip_v4 *)(discovery_bin + ip_offset);

			inst = ip->instance_number;
			hw_id = le16_to_cpu(ip->hw_id);
			if (amdgpu_discovery_validate_ip(adev, inst, hw_id))
				goto next_ip;

			num_base_address = ip->num_base_address;

			DRM_DEBUG("%s(%d) #%d v%d.%d.%d:\n",
				  hw_id_names[le16_to_cpu(ip->hw_id)],
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
				if (adev->vcn.num_vcn_inst <
				    AMDGPU_MAX_VCN_INSTANCES) {
					adev->vcn.inst[adev->vcn.num_vcn_inst].vcn_config =
						ip->revision & 0xc0;
					adev->vcn.num_vcn_inst++;
					adev->vcn.inst_mask |=
						(1U << ip->instance_number);
					adev->jpeg.inst_mask |=
						(1U << ip->instance_number);
				} else {
					dev_err(adev->dev, "Too many VCN instances: %d vs %d\n",
						adev->vcn.num_vcn_inst + 1,
						AMDGPU_MAX_VCN_INSTANCES);
				}
				ip->revision &= ~0xc0;
			}
			if (le16_to_cpu(ip->hw_id) == SDMA0_HWID ||
			    le16_to_cpu(ip->hw_id) == SDMA1_HWID ||
			    le16_to_cpu(ip->hw_id) == SDMA2_HWID ||
			    le16_to_cpu(ip->hw_id) == SDMA3_HWID) {
				if (adev->sdma.num_instances <
				    AMDGPU_MAX_SDMA_INSTANCES) {
					adev->sdma.num_instances++;
					adev->sdma.sdma_mask |=
						(1U << ip->instance_number);
				} else {
					dev_err(adev->dev, "Too many SDMA instances: %d vs %d\n",
						adev->sdma.num_instances + 1,
						AMDGPU_MAX_SDMA_INSTANCES);
				}
			}

			if (le16_to_cpu(ip->hw_id) == VPE_HWID) {
				if (adev->vpe.num_instances < AMDGPU_MAX_VPE_INSTANCES)
					adev->vpe.num_instances++;
				else
					dev_err(adev->dev, "Too many VPE instances: %d vs %d\n",
						adev->vpe.num_instances + 1,
						AMDGPU_MAX_VPE_INSTANCES);
			}

			if (le16_to_cpu(ip->hw_id) == UMC_HWID) {
				adev->gmc.num_umc++;
				adev->umc.node_inst_num++;
			}

			if (le16_to_cpu(ip->hw_id) == GC_HWID)
				adev->gfx.xcc_mask |=
					(1U << ip->instance_number);

			if (!wafl_ver && le16_to_cpu(ip->hw_id) == WAFLC_HWID)
				wafl_ver = IP_VERSION_FULL(ip->major, ip->minor,
							   ip->revision, 0, 0);

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
				DRM_DEBUG("\t0x%08x\n", ip->base_address[k]);
			}

			for (hw_ip = 0; hw_ip < MAX_HWIP; hw_ip++) {
				if (hw_id_map[hw_ip] == le16_to_cpu(ip->hw_id) &&
				    hw_id_map[hw_ip] != 0) {
					DRM_DEBUG("set register base offset for %s\n",
							hw_id_names[le16_to_cpu(ip->hw_id)]);
					adev->reg_offset[hw_ip][ip->instance_number] =
						ip->base_address;
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

					adev->ip_versions[hw_ip]
							 [ip->instance_number] =
						IP_VERSION_FULL(ip->major,
								ip->minor,
								ip->revision,
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

	if (wafl_ver && !adev->ip_versions[XGMI_HWIP][0])
		adev->ip_versions[XGMI_HWIP][0] = wafl_ver;

	return 0;
}
#undef hw_id_map
#undef amdgpu_discovery_validate_ip
#undef amdgpu_discovery_reg_base_init
