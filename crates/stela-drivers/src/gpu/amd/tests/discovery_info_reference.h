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

/* Frozen retained guarded bodies at8b87f5b28. Six functions match official
 * Linux8d3ae592 byte-for-byte; legacy read_harvest_bit_per_ip retains the prior
 * 3eb checked-v2-directory prefix correction. Symbols renamed only. Exact
 * uncorrected original legacy donor is separately compared on valid v0/v1. */
static void donor_amdgpu_discovery_harvest_config_quirk(struct amdgpu_device *adev)
{
	/*
	 * So far, apply this quirk only on those Navy Flounder boards which
	 * have a bad harvest table of VCN config.
	 */
	if ((amdgpu_ip_version(adev, UVD_HWIP, 1) == IP_VERSION(3, 0, 1)) &&
	    (amdgpu_ip_version(adev, GC_HWIP, 0) == IP_VERSION(10, 3, 2))) {
		switch (adev->pdev->revision) {
		case 0xC1:
		case 0xC2:
		case 0xC3:
		case 0xC5:
		case 0xC7:
		case 0xCF:
		case 0xDF:
			adev->vcn.harvest_config |= AMDGPU_VCN_HARVEST_VCN1;
			adev->vcn.inst_mask &= ~AMDGPU_VCN_HARVEST_VCN1;
			break;
		default:
			break;
		}
	}
}

static void donor_amdgpu_discovery_read_harvest_bit_per_ip(struct amdgpu_device *adev,
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

static void donor_amdgpu_discovery_read_from_harvest_table(struct amdgpu_device *adev,
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

static void donor_amdgpu_discovery_harvest_ip(struct amdgpu_device *adev)
{
	uint8_t *discovery_bin = adev->discovery.bin;
	struct ip_discovery_header *ihdr;
	struct table_info *info;
	int vcn_harvest_count = 0;
	int umc_harvest_count = 0;
	uint16_t ihdr_ver;

	if (amdgpu_discovery_get_table_info(adev, &info, IP_DISCOVERY))
		return;
	ihdr = (struct ip_discovery_header *)(discovery_bin +
					      le16_to_cpu(info->offset));
	ihdr_ver = le16_to_cpu(ihdr->version);
	/*
	 * Harvest table does not fit Navi1x and legacy GPUs,
	 * so read harvest bit per IP data structure to set
	 * harvest configuration.
	 */
	if (amdgpu_ip_version(adev, GC_HWIP, 0) < IP_VERSION(10, 2, 0) &&
	    ihdr_ver <= 2) {
		if ((adev->pdev->device == 0x731E &&
			(adev->pdev->revision == 0xC6 ||
			 adev->pdev->revision == 0xC7)) ||
			(adev->pdev->device == 0x7340 &&
			 adev->pdev->revision == 0xC9) ||
			(adev->pdev->device == 0x7360 &&
			 adev->pdev->revision == 0xC7))
			donor_amdgpu_discovery_read_harvest_bit_per_ip(adev,
				&vcn_harvest_count);
	} else {
		donor_amdgpu_discovery_read_from_harvest_table(adev,
							 &vcn_harvest_count,
							 &umc_harvest_count);
	}

	donor_amdgpu_discovery_harvest_config_quirk(adev);

	if (vcn_harvest_count == adev->vcn.num_vcn_inst) {
		adev->harvest_ip_mask |= AMD_HARVEST_IP_VCN_MASK;
		adev->harvest_ip_mask |= AMD_HARVEST_IP_JPEG_MASK;
	}

	if (umc_harvest_count < adev->gmc.num_umc) {
		adev->gmc.num_umc -= umc_harvest_count;
	}
}

static int donor_amdgpu_discovery_get_gfx_info(struct amdgpu_device *adev)
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

static int donor_amdgpu_discovery_get_mall_info(struct amdgpu_device *adev)
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

static int donor_amdgpu_discovery_get_vcn_info(struct amdgpu_device *adev)
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

