/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2018-2024 Advanced Micro Devices, Inc. All rights reserved.
 * Copyright 2025 Advanced Micro Devices, Inc.
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

/* CPU-only model: unchanged original functions, not a production device.
 * Linux8d3ae59288f1e7d58d76558a6ee96d533bc5019f; source SHA256 2a53ce988fe75f16a00bd010c5c199449596936d7869223e65fc39917ae52be8. */

enum amd_hw_ip_block_type {
	GC_HWIP = 1,
	HDP_HWIP,
	SDMA0_HWIP,
	SDMA1_HWIP,
	SDMA2_HWIP,
	SDMA3_HWIP,
	SDMA4_HWIP,
	SDMA5_HWIP,
	SDMA6_HWIP,
	SDMA7_HWIP,
	LSDMA_HWIP,
	MMHUB_HWIP,
	ATHUB_HWIP,
	NBIO_HWIP,
	MP0_HWIP,
	MP1_HWIP,
	UVD_HWIP,
	VCN_HWIP = UVD_HWIP,
	JPEG_HWIP = VCN_HWIP,
	VCN1_HWIP,
	VCE_HWIP,
	VPE_HWIP,
	DF_HWIP,
	DCE_HWIP,
	OSSSYS_HWIP,
	SMUIO_HWIP,
	PWR_HWIP,
	NBIF_HWIP,
	THM_HWIP,
	CLK_HWIP,
	UMC_HWIP,
	RSMU_HWIP,
	XGMI_HWIP,
	DCI_HWIP,
	PCIE_HWIP,
	ISP_HWIP,
	ATU_HWIP,
	AIGC_HWIP,
	MAX_HWIP
};
#define AMDGPU_MAX_VCN_INSTANCES	4
#define AMDGPU_VCN_HARVEST_VCN0 (1 << 0)
#define AMDGPU_VCN_HARVEST_VCN1 (1 << 1)
#define AMDGPU_MAX_SDMA_INSTANCES		16
#define AMDGPU_MAX_VPE_INSTANCES 2

#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define lower_32_bits(x) ((uint32_t)(x))
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
#define IP_VERSION_FULL(mj, mn, rv, var, srev) \
   (((mj) << 24) | ((mn) << 16) | ((rv) << 8) | ((var) << 4) | (srev))
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define AMD_HARVEST_IP_DMU_MASK 0x4
#define dev_err(...) reference_log(__VA_ARGS__)
#define dev_warn(...) reference_log(__VA_ARGS__)
#define dev_dbg(...) reference_log(__VA_ARGS__)
#define DRM_DEBUG(...) ((void)0)
#define DRM_ERROR(...) ((void)0)
#define DRM_INFO(...) ((void)0)
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint64_t u64;
struct amdgpu_device {
   void *dev, *ddev;
   struct { uint8_t *bin; size_t size; } discovery;
   struct {
      uint32_t xcc_mask;
      struct {
         uint32_t double_offchip_lds_buf;
         uint32_t gc_gl1c_per_sa;
         uint32_t gc_gl1c_size_per_instance;
         uint32_t gc_gl2c_per_gpu;
         uint32_t gc_instruction_cache_line_size;
         uint32_t gc_instruction_cache_size_per_sqc;
         uint32_t gc_l1_data_cache_size_per_sqc;
         uint32_t gc_l1_instruction_cache_size_per_sqc;
         uint32_t gc_num_cu_per_sqc;
         uint32_t gc_num_sdp_interface;
         uint32_t gc_num_sqc_per_wgp;
         uint32_t gc_num_tcp_per_sa;
         uint32_t gc_num_tcp_per_wpg;
         uint32_t gc_num_tcps;
         uint32_t gc_scalar_data_cache_line_size;
         uint32_t gc_scalar_data_cache_size_per_sqc;
         uint32_t gc_tcc_cache_line_size;
         uint32_t gc_tcc_size;
         uint32_t gc_tcp_cache_line_size;
         uint32_t gc_tcp_l1_size;
         uint32_t gc_tcp_size_per_cu;
         uint32_t gs_prim_buffer_depth;
         uint32_t gs_vgt_table_depth;
         uint32_t max_backends_per_se;
         uint32_t max_cu_per_sh;
         uint32_t max_gprs;
         uint32_t max_gs_threads;
         uint32_t max_sh_per_se;
         uint32_t max_shader_engines;
         uint32_t max_texture_channel_caches;
         uint32_t num_packer_per_sc;
         uint32_t num_sc_per_sh;
      } config;
      struct {
         uint32_t lds_size;
         uint32_t max_scratch_slots_per_cu;
         uint32_t max_waves_per_simd;
         uint32_t wave_front_size;
      } cu_info;
   } gfx;
   struct { uint32_t num_instances, sdma_mask; } sdma;
   struct {
      uint32_t num_vcn_inst, inst_mask, harvest_config;
      struct { uint32_t vcn_config, vcn_codec_disable_mask; } inst[AMDGPU_MAX_VCN_INSTANCES];
   } vcn;
   struct { uint32_t inst_mask, harvest_config; } jpeg;
   struct { uint32_t num_instances; } vpe;
   struct { uint32_t num_umc, m_half_use; uint64_t mall_size; } gmc;
   struct { uint32_t node_inst_num; uint64_t active_mask; } umc;
   uint32_t harvest_ip_mask;
   uint32_t *reg_offset[MAX_HWIP][HWIP_MAX_INSTANCE];
   uint32_t ip_versions[MAX_HWIP][HWIP_MAX_INSTANCE];
};
union gc_info {
   struct gc_info_v1_0 v1;
   struct gc_info_v1_1 v1_1;
   struct gc_info_v1_2 v1_2;
   struct gc_info_v1_3 v1_3;
   struct gc_info_v2_0 v2;
   struct gc_info_v2_1 v2_1;
};
union mall_info { struct mall_info_v1_0 v1; struct mall_info_v2_0 v2; };
union vcn_info { struct vcn_info_v1_0 v1; };
static int checked;
static int reference_validation(struct amdgpu_device *adev);
static int fixture_table(struct amdgpu_device *adev, struct table_info **info, uint16_t id);
#define amdgpu_discovery_get_table_info fixture_table
#define amdgpu_discovery_init reference_validation
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
#define amdgpu_discovery_calculate_checksum donor_checksum

/* Original amdgpu_discovery_calculate_checksum SHA256 372aab607b140694bfdaad72d341f34e5232627c4c90575a11fa769482d47b44 */
static uint16_t amdgpu_discovery_calculate_checksum(uint8_t *data, uint32_t size)
{
	uint16_t checksum = 0;
	int i;

	for (i = 0; i < size; i++)
		checksum += data[i];

	return checksum;
}


/* Original amdgpu_discovery_verify_checksum SHA256 c035ae88a58005e267458c731d2857b70723250d0c892358b2b17c77637b6c35 */
static inline bool amdgpu_discovery_verify_checksum(struct amdgpu_device *adev,
							uint8_t *data, uint32_t size,
						    uint16_t expected)
{
	uint16_t calculated;

	calculated = amdgpu_discovery_calculate_checksum(data, size);

	if (calculated != expected) {
		dev_err(adev->dev, "Discovery checksum failed: calc 0x%04x != exp 0x%04x, size %u.\n",
				calculated, expected, size);
		return false;
	}

	return true;
}


/* Original amdgpu_discovery_verify_binary_signature SHA256 c82abb6e99bac7f1186a5389e76e023aa67bfdb22a112a9b35485d5e5077afa0 */
static inline bool amdgpu_discovery_verify_binary_signature(uint8_t *binary)
{
	struct binary_header *bhdr;
	bhdr = (struct binary_header *)binary;

	return (le32_to_cpu(bhdr->binary_signature) == BINARY_SIGNATURE);
}


static int donor_table(struct amdgpu_device *adev,
					   struct table_info **info,
					   uint16_t table_id)
{
	struct binary_header *bhdr =
		(struct binary_header *)adev->discovery.bin;
	struct binary_header_v2 *bhdrv2;

	switch (bhdr->version_major) {
	case 2:
		bhdrv2 = (struct binary_header_v2 *)adev->discovery.bin;
		*info = &bhdrv2->table_list[table_id];
		break;
	case 1:
	case 0:
		*info = &bhdr->table_list[table_id];
		break;
	default:
		dev_err(adev->dev, "Invalid ip discovery table version %d\n",bhdr->version_major);
		return -EINVAL;
	}

	return 0;
}


/* Original amdgpu_discovery_table_check SHA256 c9a06491e12cc34646f325f8269432b2b69a63e278f90ddb296e98034644df76 */
static int amdgpu_discovery_table_check(struct amdgpu_device *adev,
					uint8_t *discovery_bin,
					uint16_t table_id)
{
	int r, act_val, exp_val, table_size;
	uint16_t offset, checksum;
	struct table_info *info;
	bool check_table = true;
	char *table_name;

	r = amdgpu_discovery_get_table_info(adev, &info, table_id);
	if (r)
		return r;
	offset = le16_to_cpu(info->offset);
	checksum = le16_to_cpu(info->checksum);

	switch (table_id) {
	case IP_DISCOVERY: {
		struct ip_discovery_header *ihdr =
			(struct ip_discovery_header *)(discovery_bin + offset);
		act_val = le32_to_cpu(ihdr->signature);
		exp_val = DISCOVERY_TABLE_SIGNATURE;
		table_size = le16_to_cpu(ihdr->size);
		table_name = "data table";
		break;
	}
	case GC: {
		struct gpu_info_header *ghdr =
			(struct gpu_info_header *)(discovery_bin + offset);
		act_val = le32_to_cpu(ghdr->table_id);
		exp_val = GC_TABLE_ID;
		table_size = le16_to_cpu(ghdr->size);
		table_name = "gc table";
		break;
	}
	case HARVEST_INFO: {
		struct harvest_info_header *hhdr =
			(struct harvest_info_header *)(discovery_bin + offset);
		act_val = le32_to_cpu(hhdr->signature);
		exp_val = HARVEST_TABLE_SIGNATURE;
		table_size = sizeof(struct harvest_table);
		table_name = "harvest table";
		break;
	}
	case VCN_INFO: {
		struct vcn_info_header *vhdr =
			(struct vcn_info_header *)(discovery_bin + offset);
		act_val = le32_to_cpu(vhdr->table_id);
		exp_val = VCN_INFO_TABLE_ID;
		table_size = le32_to_cpu(vhdr->size_bytes);
		table_name = "vcn table";
		break;
	}
	case MALL_INFO: {
		struct mall_info_header *mhdr =
			(struct mall_info_header *)(discovery_bin + offset);
		act_val = le32_to_cpu(mhdr->table_id);
		exp_val = MALL_INFO_TABLE_ID;
		table_size = le32_to_cpu(mhdr->size_bytes);
		table_name = "mall table";
		check_table = false;
		break;
	}
	default:
		dev_err(adev->dev, "invalid ip discovery table id %d specified\n", table_id);
		check_table = false;
		break;
	}

	if (check_table && offset) {
		if (act_val != exp_val) {
			dev_err(adev->dev, "invalid ip discovery %s signature\n", table_name);
			return -EINVAL;
		}

		if (!amdgpu_discovery_verify_checksum(adev, discovery_bin + offset,
						      table_size, checksum)) {
			dev_err(adev->dev, "invalid ip discovery %s checksum\n", table_name);
			return -EINVAL;
		}
	}

	return 0;
}


/* Original amdgpu_discovery_validate_ip SHA256 86be3ff15479a5f206add82800a9c9457b3f950323caff44bab04f08b78179a7 */
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


/* Original amdgpu_discovery_reg_base_init SHA256 0a87709612fa439b0ed1fd44db839e36c5d9599c57ad6bead561e61424ff1453 */
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


/* Original amdgpu_discovery_read_harvest_bit_per_ip SHA256 c8959dbfe679bc3fa371ca0c379f4b8b9d7b471ad4362e7173b584a366b14a76 */
static void amdgpu_discovery_read_harvest_bit_per_ip(struct amdgpu_device *adev,
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


/* Original amdgpu_discovery_read_from_harvest_table SHA256 14ecf4f63472af489ca55eca624d5dd2a559756f1db7d626d86c9f49b3946b90 */
static void amdgpu_discovery_read_from_harvest_table(struct amdgpu_device *adev,
						     uint32_t *vcn_harvest_count,
						     uint32_t *umc_harvest_count)
{
	uint8_t *discovery_bin = adev->discovery.bin;
	struct table_info *info;
	struct harvest_table *harvest_info;
	u16 offset;
	int i;
	u64 umc_harvest_config = 0;

	if (amdgpu_discovery_get_table_info(adev, &info, HARVEST_INFO))
		return;
	offset = le16_to_cpu(info->offset);

	if (!offset) {
		dev_err(adev->dev, "invalid harvest table offset\n");
		return;
	}

	harvest_info = (struct harvest_table *)(discovery_bin + offset);

	for (i = 0; i < 32; i++) {
		u16 hw_id = le16_to_cpu(harvest_info->list[i].hw_id);
		u8 inst = harvest_info->list[i].number_instance;

		if (hw_id == 0)
			break;

		if (inst >= 32) {
			dev_warn(adev->dev,
				 "bogus harvest instance %u for hw_id %u\n",
				 inst, hw_id);
			continue;
		}

		switch (hw_id) {
		case VCN_HWID:
			(*vcn_harvest_count)++;
			adev->vcn.harvest_config |= BIT(inst);
			adev->jpeg.harvest_config |= BIT(inst);

			adev->vcn.inst_mask &= ~BIT(inst);
			adev->jpeg.inst_mask &= ~BIT(inst);
			break;
		case DMU_HWID:
			adev->harvest_ip_mask |= AMD_HARVEST_IP_DMU_MASK;
			break;
		case UMC_HWID:
			umc_harvest_config |= BIT_ULL(inst);
			(*umc_harvest_count)++;
			break;
		case GC_HWID:
			adev->gfx.xcc_mask &= ~BIT(inst);
			break;
		case SDMA0_HWID:
			adev->sdma.sdma_mask &= ~BIT(inst);
			break;
#if defined(CONFIG_DRM_AMD_ISP)
		case ISP_HWID:
			adev->isp.harvest_config |= ~BIT(inst);
			break;
#endif
		default:
			break;
		}
	}

	adev->umc.active_mask = ((1ULL << adev->umc.node_inst_num) - 1ULL) &
				~umc_harvest_config;
}


/* Original amdgpu_discovery_get_gfx_info SHA256 5ea837ac1840d60ecd843136fa366c21803e8b6ebf2fb653f4db697a654a2757 */
static int amdgpu_discovery_get_gfx_info(struct amdgpu_device *adev)
{
	uint8_t *discovery_bin = adev->discovery.bin;
	struct table_info *info;
	union gc_info *gc_info;
	u16 offset;

	if (!discovery_bin) {
		DRM_ERROR("ip discovery uninitialized\n");
		return -EINVAL;
	}

	if (amdgpu_discovery_get_table_info(adev, &info, GC))
		return -EINVAL;
	offset = le16_to_cpu(info->offset);

	if (!offset)
		return 0;

	gc_info = (union gc_info *)(discovery_bin + offset);

	switch (le16_to_cpu(gc_info->v1.header.version_major)) {
	case 1:
		adev->gfx.config.max_shader_engines = le32_to_cpu(gc_info->v1.gc_num_se);
		adev->gfx.config.max_cu_per_sh = 2 * (le32_to_cpu(gc_info->v1.gc_num_wgp0_per_sa) +
						      le32_to_cpu(gc_info->v1.gc_num_wgp1_per_sa));
		adev->gfx.config.max_sh_per_se = le32_to_cpu(gc_info->v1.gc_num_sa_per_se);
		adev->gfx.config.max_backends_per_se = le32_to_cpu(gc_info->v1.gc_num_rb_per_se);
		adev->gfx.config.max_texture_channel_caches = le32_to_cpu(gc_info->v1.gc_num_gl2c);
		adev->gfx.config.max_gprs = le32_to_cpu(gc_info->v1.gc_num_gprs);
		adev->gfx.config.max_gs_threads = le32_to_cpu(gc_info->v1.gc_num_max_gs_thds);
		adev->gfx.config.gs_vgt_table_depth = le32_to_cpu(gc_info->v1.gc_gs_table_depth);
		adev->gfx.config.gs_prim_buffer_depth = le32_to_cpu(gc_info->v1.gc_gsprim_buff_depth);
		adev->gfx.config.double_offchip_lds_buf = le32_to_cpu(gc_info->v1.gc_double_offchip_lds_buffer);
		adev->gfx.cu_info.wave_front_size = le32_to_cpu(gc_info->v1.gc_wave_size);
		adev->gfx.cu_info.max_waves_per_simd = le32_to_cpu(gc_info->v1.gc_max_waves_per_simd);
		adev->gfx.cu_info.max_scratch_slots_per_cu = le32_to_cpu(gc_info->v1.gc_max_scratch_slots_per_cu);
		adev->gfx.cu_info.lds_size = le32_to_cpu(gc_info->v1.gc_lds_size);
		adev->gfx.config.num_sc_per_sh = le32_to_cpu(gc_info->v1.gc_num_sc_per_se) /
			le32_to_cpu(gc_info->v1.gc_num_sa_per_se);
		adev->gfx.config.num_packer_per_sc = le32_to_cpu(gc_info->v1.gc_num_packer_per_sc);
		if (le16_to_cpu(gc_info->v1.header.version_minor) >= 1) {
			adev->gfx.config.gc_num_tcp_per_sa = le32_to_cpu(gc_info->v1_1.gc_num_tcp_per_sa);
			adev->gfx.config.gc_num_sdp_interface = le32_to_cpu(gc_info->v1_1.gc_num_sdp_interface);
			adev->gfx.config.gc_num_tcps = le32_to_cpu(gc_info->v1_1.gc_num_tcps);
		}
		if (le16_to_cpu(gc_info->v1.header.version_minor) >= 2) {
			adev->gfx.config.gc_num_tcp_per_wpg = le32_to_cpu(gc_info->v1_2.gc_num_tcp_per_wpg);
			adev->gfx.config.gc_tcp_l1_size = le32_to_cpu(gc_info->v1_2.gc_tcp_l1_size);
			adev->gfx.config.gc_num_sqc_per_wgp = le32_to_cpu(gc_info->v1_2.gc_num_sqc_per_wgp);
			adev->gfx.config.gc_l1_instruction_cache_size_per_sqc = le32_to_cpu(gc_info->v1_2.gc_l1_instruction_cache_size_per_sqc);
			adev->gfx.config.gc_l1_data_cache_size_per_sqc = le32_to_cpu(gc_info->v1_2.gc_l1_data_cache_size_per_sqc);
			adev->gfx.config.gc_gl1c_per_sa = le32_to_cpu(gc_info->v1_2.gc_gl1c_per_sa);
			adev->gfx.config.gc_gl1c_size_per_instance = le32_to_cpu(gc_info->v1_2.gc_gl1c_size_per_instance);
			adev->gfx.config.gc_gl2c_per_gpu = le32_to_cpu(gc_info->v1_2.gc_gl2c_per_gpu);
		}
		if (le16_to_cpu(gc_info->v1.header.version_minor) >= 3) {
			adev->gfx.config.gc_tcp_size_per_cu = le32_to_cpu(gc_info->v1_3.gc_tcp_size_per_cu);
			adev->gfx.config.gc_tcp_cache_line_size = le32_to_cpu(gc_info->v1_3.gc_tcp_cache_line_size);
			adev->gfx.config.gc_instruction_cache_size_per_sqc = le32_to_cpu(gc_info->v1_3.gc_instruction_cache_size_per_sqc);
			adev->gfx.config.gc_instruction_cache_line_size = le32_to_cpu(gc_info->v1_3.gc_instruction_cache_line_size);
			adev->gfx.config.gc_scalar_data_cache_size_per_sqc = le32_to_cpu(gc_info->v1_3.gc_scalar_data_cache_size_per_sqc);
			adev->gfx.config.gc_scalar_data_cache_line_size = le32_to_cpu(gc_info->v1_3.gc_scalar_data_cache_line_size);
			adev->gfx.config.gc_tcc_size = le32_to_cpu(gc_info->v1_3.gc_tcc_size);
			adev->gfx.config.gc_tcc_cache_line_size = le32_to_cpu(gc_info->v1_3.gc_tcc_cache_line_size);
		}
		break;
	case 2:
		adev->gfx.config.max_shader_engines = le32_to_cpu(gc_info->v2.gc_num_se);
		adev->gfx.config.max_cu_per_sh = le32_to_cpu(gc_info->v2.gc_num_cu_per_sh);
		adev->gfx.config.max_sh_per_se = le32_to_cpu(gc_info->v2.gc_num_sh_per_se);
		adev->gfx.config.max_backends_per_se = le32_to_cpu(gc_info->v2.gc_num_rb_per_se);
		adev->gfx.config.max_texture_channel_caches = le32_to_cpu(gc_info->v2.gc_num_tccs);
		adev->gfx.config.max_gprs = le32_to_cpu(gc_info->v2.gc_num_gprs);
		adev->gfx.config.max_gs_threads = le32_to_cpu(gc_info->v2.gc_num_max_gs_thds);
		adev->gfx.config.gs_vgt_table_depth = le32_to_cpu(gc_info->v2.gc_gs_table_depth);
		adev->gfx.config.gs_prim_buffer_depth = le32_to_cpu(gc_info->v2.gc_gsprim_buff_depth);
		adev->gfx.config.double_offchip_lds_buf = le32_to_cpu(gc_info->v2.gc_double_offchip_lds_buffer);
		adev->gfx.cu_info.wave_front_size = le32_to_cpu(gc_info->v2.gc_wave_size);
		adev->gfx.cu_info.max_waves_per_simd = le32_to_cpu(gc_info->v2.gc_max_waves_per_simd);
		adev->gfx.cu_info.max_scratch_slots_per_cu = le32_to_cpu(gc_info->v2.gc_max_scratch_slots_per_cu);
		adev->gfx.cu_info.lds_size = le32_to_cpu(gc_info->v2.gc_lds_size);
		adev->gfx.config.num_sc_per_sh = le32_to_cpu(gc_info->v2.gc_num_sc_per_se) /
			le32_to_cpu(gc_info->v2.gc_num_sh_per_se);
		adev->gfx.config.num_packer_per_sc = le32_to_cpu(gc_info->v2.gc_num_packer_per_sc);
		if (le16_to_cpu(gc_info->v2.header.version_minor) == 1) {
			adev->gfx.config.gc_num_tcp_per_sa = le32_to_cpu(gc_info->v2_1.gc_num_tcp_per_sh);
			adev->gfx.config.gc_tcp_size_per_cu = le32_to_cpu(gc_info->v2_1.gc_tcp_size_per_cu);
			adev->gfx.config.gc_num_sdp_interface = le32_to_cpu(gc_info->v2_1.gc_num_sdp_interface); /* per XCD */
			adev->gfx.config.gc_num_cu_per_sqc = le32_to_cpu(gc_info->v2_1.gc_num_cu_per_sqc);
			adev->gfx.config.gc_l1_instruction_cache_size_per_sqc = le32_to_cpu(gc_info->v2_1.gc_instruction_cache_size_per_sqc);
			adev->gfx.config.gc_l1_data_cache_size_per_sqc = le32_to_cpu(gc_info->v2_1.gc_scalar_data_cache_size_per_sqc);
			adev->gfx.config.gc_tcc_size = le32_to_cpu(gc_info->v2_1.gc_tcc_size); /* per XCD */
		}
		break;
	default:
		dev_err(adev->dev,
			"Unhandled GC info table %d.%d\n",
			le16_to_cpu(gc_info->v1.header.version_major),
			le16_to_cpu(gc_info->v1.header.version_minor));
		return -EINVAL;
	}
	return 0;
}


/* Original amdgpu_discovery_get_mall_info SHA256 0ec5e667ccd6a14bc5db1c91a85db16898e79a2f1e08a602e28cd996ba76d114 */
static int amdgpu_discovery_get_mall_info(struct amdgpu_device *adev)
{
	uint8_t *discovery_bin = adev->discovery.bin;
	struct table_info *info;
	union mall_info *mall_info;
	u32 u, mall_size_per_umc, m_s_present, half_use;
	u64 mall_size;
	u16 offset;

	if (!discovery_bin) {
		DRM_ERROR("ip discovery uninitialized\n");
		return -EINVAL;
	}

	if (amdgpu_discovery_get_table_info(adev, &info, MALL_INFO))
		return -EINVAL;
	offset = le16_to_cpu(info->offset);

	if (!offset)
		return 0;

	mall_info = (union mall_info *)(discovery_bin + offset);

	switch (le16_to_cpu(mall_info->v1.header.version_major)) {
	case 1:
		mall_size = 0;
		mall_size_per_umc = le32_to_cpu(mall_info->v1.mall_size_per_m);
		m_s_present = le32_to_cpu(mall_info->v1.m_s_present);
		half_use = le32_to_cpu(mall_info->v1.m_half_use);
		for (u = 0; u < adev->gmc.num_umc; u++) {
			if (m_s_present & (1 << u))
				mall_size += mall_size_per_umc * 2;
			else if (half_use & (1 << u))
				mall_size += mall_size_per_umc / 2;
			else
				mall_size += mall_size_per_umc;
		}
		adev->gmc.mall_size = mall_size;
		adev->gmc.m_half_use = half_use;
		break;
	case 2:
		mall_size_per_umc = le32_to_cpu(mall_info->v2.mall_size_per_umc);
		adev->gmc.mall_size = (uint64_t)mall_size_per_umc * adev->gmc.num_umc;
		break;
	default:
		dev_err(adev->dev,
			"Unhandled MALL info table %d.%d\n",
			le16_to_cpu(mall_info->v1.header.version_major),
			le16_to_cpu(mall_info->v1.header.version_minor));
		return -EINVAL;
	}
	return 0;
}


/* Original amdgpu_discovery_get_vcn_info SHA256 e51c76188fc0c90a2fcd31a675ad77b1bf46895742187f2ba58138a9334eff31 */
static int amdgpu_discovery_get_vcn_info(struct amdgpu_device *adev)
{
	uint8_t *discovery_bin = adev->discovery.bin;
	struct table_info *info;
	union vcn_info *vcn_info;
	u16 offset;
	int v;

	if (!discovery_bin) {
		DRM_ERROR("ip discovery uninitialized\n");
		return -EINVAL;
	}

	/* num_vcn_inst is currently limited to AMDGPU_MAX_VCN_INSTANCES
	 * which is smaller than VCN_INFO_TABLE_MAX_NUM_INSTANCES
	 * but that may change in the future with new GPUs so keep this
	 * check for defensive purposes.
	 */
	if (adev->vcn.num_vcn_inst > VCN_INFO_TABLE_MAX_NUM_INSTANCES) {
		dev_err(adev->dev, "invalid vcn instances\n");
		return -EINVAL;
	}

	if (amdgpu_discovery_get_table_info(adev, &info, VCN_INFO))
		return -EINVAL;
	offset = le16_to_cpu(info->offset);

	if (!offset)
		return 0;

	vcn_info = (union vcn_info *)(discovery_bin + offset);

	switch (le16_to_cpu(vcn_info->v1.header.version_major)) {
	case 1:
		/* num_vcn_inst is currently limited to AMDGPU_MAX_VCN_INSTANCES
		 * so this won't overflow.
		 */
		for (v = 0; v < adev->vcn.num_vcn_inst; v++) {
			adev->vcn.inst[v].vcn_codec_disable_mask =
				le32_to_cpu(vcn_info->v1.instance_info[v].fuse_data.all_bits);
		}
		break;
	default:
		dev_err(adev->dev,
			"Unhandled VCN info table %d.%d\n",
			le16_to_cpu(vcn_info->v1.header.version_major),
			le16_to_cpu(vcn_info->v1.header.version_minor));
		return -EINVAL;
	}
	return 0;
}


#undef amdgpu_discovery_calculate_checksum

/* Intentional corrected v2 directory lookup only. */
static void checked_harvest(struct amdgpu_device *adev,
						uint32_t *vcn_harvest_count)
{
	uint8_t *discovery_bin = adev->discovery.bin;
	struct table_info *info;
	struct ip_discovery_header *ihdr;
	struct die_header *dhdr;
	struct ip *ip;
	uint16_t die_offset, ip_offset, num_dies, num_ips;
	uint16_t hw_id;
	uint8_t inst;
	int i, j;

	if (amdgpu_discovery_get_table_info(adev, &info, IP_DISCOVERY))
		return;
	ihdr = (struct ip_discovery_header *)(discovery_bin +
					      le16_to_cpu(info->offset));

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


static int fixture_table(struct amdgpu_device *adev, struct table_info **info, uint16_t id)
{
   if (!checked)
      return donor_table(adev, info, id);
   const struct table_info *entry = amdgpu_discovery_binary_table(adev->discovery.bin,
                                                               adev->discovery.size, id);
   if (!entry)
      return -EINVAL;
   *info = (struct table_info *)entry;
   return 0;
}

static int reference_validation(struct amdgpu_device *adev)
{
   if (checked)
      return amdgpu_discovery_binary_validate(adev->discovery.bin, adev->discovery.size) ? -EINVAL : 0;
   uint8_t *discovery_bin = adev->discovery.bin;
   struct binary_header *bhdr;
   uint16_t offset, size, checksum, table_id;
   int r;
	/* check the ip discovery binary signature */
	if (!amdgpu_discovery_verify_binary_signature(discovery_bin)) {
		dev_err(adev->dev,
			"get invalid ip discovery binary signature\n");
		r = -EINVAL;
		return r;
	}

	bhdr = (struct binary_header *)discovery_bin;

	offset = offsetof(struct binary_header, binary_checksum) +
		sizeof(bhdr->binary_checksum);
	size = le16_to_cpu(bhdr->binary_size) - offset;
	checksum = le16_to_cpu(bhdr->binary_checksum);

	if (!amdgpu_discovery_verify_checksum(adev, discovery_bin + offset, size,
					      checksum)) {
		dev_err(adev->dev, "invalid ip discovery binary checksum\n");
		r = -EINVAL;
		return r;
	}

	for (table_id = 0; table_id <= MALL_INFO; table_id++) {
		r = amdgpu_discovery_table_check(adev, discovery_bin, table_id);
		if (r)
			return r;
	}

   return 0;
}

#undef amdgpu_discovery_get_table_info
#undef amdgpu_discovery_init

/* NPS snapshot consumer only. Hardware refresh is deliberately unavailable in
 * this CPU model and must never be called; its known stack-FAM bug is separate. */
union nps_info { struct nps_info_v1_0 v1; };
struct amdgpu_gmc_memrange {
   uint64_t base_address, limit_address;
   uint32_t flags;
   int nid_mask;
};
static int amdgpu_discovery_refresh_nps_info(struct amdgpu_device *adev, union nps_info *info)
{
   (void)adev;
   (void)info;
   assert(!"hardware refresh is outside the snapshot model");
   return -EINVAL;
}
#define amdgpu_discovery_get_table_info fixture_table

static int amdgpu_discovery_verify_npsinfo(struct amdgpu_device *adev,
					   struct table_info *info)
{
	uint8_t *discovery_bin = adev->discovery.bin;
	uint16_t checksum;
	uint16_t offset;

	offset = le16_to_cpu(info->offset);
	checksum = le16_to_cpu(info->checksum);

	struct nps_info_header *nhdr =
		(struct nps_info_header *)(discovery_bin + offset);

	if (le32_to_cpu(nhdr->table_id) != NPS_INFO_TABLE_ID) {
		dev_dbg(adev->dev, "invalid ip discovery nps info table id\n");
		return -EINVAL;
	}

	if (!amdgpu_discovery_verify_checksum(adev, discovery_bin + offset,
					      le32_to_cpu(nhdr->size_bytes),
					      checksum)) {
		dev_dbg(adev->dev, "invalid nps info data table checksum\n");
		return -EINVAL;
	}

	return 0;
}


int amdgpu_discovery_get_nps_info(struct amdgpu_device *adev,
				  uint32_t *nps_type,
				  struct amdgpu_gmc_memrange *ranges,
				  int *range_cnt, bool refresh)
{
	uint8_t *discovery_bin = adev->discovery.bin;
	struct table_info *info;
	union nps_info *nps_info;
	union nps_info nps_data;
	u16 offset;
	int i, r;

	if (!nps_type || !range_cnt || !ranges)
		return -EINVAL;

	if (refresh) {
		r = amdgpu_discovery_refresh_nps_info(adev, &nps_data);
		if (r)
			return r;
		nps_info = &nps_data;
	} else {
		if (!discovery_bin) {
			dev_err(adev->dev,
				"fetch mem range failed, ip discovery uninitialized\n");
			return -EINVAL;
		}

		if (amdgpu_discovery_get_table_info(adev, &info, NPS_INFO))
			return -EINVAL;
		offset = le16_to_cpu(info->offset);

		if (!offset)
			return -ENOENT;

		/* If verification fails, return as if NPS table doesn't exist */
		if (amdgpu_discovery_verify_npsinfo(adev, info))
			return -ENOENT;

		nps_info = (union nps_info *)(discovery_bin + offset);
	}

	switch (le16_to_cpu(nps_info->v1.header.version_major)) {
	case 1:
		*nps_type = nps_info->v1.nps_type;
		if (*range_cnt < nps_info->v1.count) {
			dev_dbg(adev->dev,
				"not enough space for nps ranges: %d < %d\n",
				*range_cnt, nps_info->v1.count);
			return -ENOSPC;
		}
		*range_cnt = nps_info->v1.count;
		for (i = 0; i < *range_cnt; i++) {
			ranges[i].base_address =
				nps_info->v1.instance_info[i].base_address;
			ranges[i].limit_address =
				nps_info->v1.instance_info[i].limit_address;
			ranges[i].nid_mask = -1;
			ranges[i].flags = 0;
		}
		break;
	default:
		dev_err(adev->dev, "Unhandled NPS info table %d.%d\n",
			le16_to_cpu(nps_info->v1.header.version_major),
			le16_to_cpu(nps_info->v1.header.version_minor));
		return -EINVAL;
	}

	return 0;
}


#undef amdgpu_discovery_get_table_info
