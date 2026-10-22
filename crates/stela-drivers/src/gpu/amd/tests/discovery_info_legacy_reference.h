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

/* Exact official pin8d3ae592 legacy fixed-v0/v1 directory donor. Never use
 * for v2; retained3eb correction explicitly changed that directory access. */
static void upstream_amdgpu_discovery_read_harvest_bit_per_ip(struct amdgpu_device *adev,
						uint32_t *vcn_harvest_count)
{
	uint8_t *discovery_bin = adev->discovery.bin;
	struct binary_header *bhdr;
	struct ip_discovery_header *ihdr;
	struct die_header *dhdr;
	struct ip *ip;
	uint16_t die_offset, ip_offset, num_dies, num_ips;
	uint16_t hw_id;
	uint8_t inst;
	int i, j;

	bhdr = (struct binary_header *)discovery_bin;
	ihdr = (struct ip_discovery_header
			*)(discovery_bin +
			   le16_to_cpu(bhdr->table_list[IP_DISCOVERY].offset));
	num_dies = le16_to_cpu(ihdr->num_dies);

	/* scan harvest bit of all IP data structures */
	for (i = 0; i < num_dies; i++) {
		die_offset = le16_to_cpu(ihdr->die_info[i].die_offset);
		dhdr = (struct die_header *)(discovery_bin + die_offset);
		num_ips = le16_to_cpu(dhdr->num_ips);
		ip_offset = die_offset + sizeof(*dhdr);

		for (j = 0; j < num_ips; j++) {
			ip = (struct ip *)(discovery_bin + ip_offset);
			inst = ip->number_instance;
			hw_id = le16_to_cpu(ip->hw_id);
			if (amdgpu_discovery_validate_ip(adev, inst, hw_id))
				goto next_ip;

			if (ip->harvest == 1) {
				switch (hw_id) {
				case VCN_HWID:
					(*vcn_harvest_count)++;
					if (inst == 0) {
						adev->vcn.harvest_config |= AMDGPU_VCN_HARVEST_VCN0;
						adev->vcn.inst_mask &=
							~AMDGPU_VCN_HARVEST_VCN0;
						adev->jpeg.inst_mask &=
							~AMDGPU_VCN_HARVEST_VCN0;
					} else {
						adev->vcn.harvest_config |= AMDGPU_VCN_HARVEST_VCN1;
						adev->vcn.inst_mask &=
							~AMDGPU_VCN_HARVEST_VCN1;
						adev->jpeg.inst_mask &=
							~AMDGPU_VCN_HARVEST_VCN1;
					}
					break;
				case DMU_HWID:
					adev->harvest_ip_mask |= AMD_HARVEST_IP_DMU_MASK;
					break;
				default:
					break;
				}
			}
next_ip:
			ip_offset += struct_size(ip, base_address,
						 ip->num_base_address);
		}
	}
}
