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

#ifndef AMDGPU_DISCOVERY_INFO_CORE_H
#define AMDGPU_DISCOVERY_INFO_CORE_H
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "amdgpu_discovery_ip_core.h"
#include "amdgpu_gfx_config.h"
#include "../include/amd_harvest_masks.h"
#ifndef __KERNEL__
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#endif
#ifdef __KERNEL__
typedef unsigned long amdgpu_discovery_umc_mask;
#else
typedef uint64_t amdgpu_discovery_umc_mask;
#endif
/* Actual caller-owned original field types; no synthetic amdgpu_device.
 * binary is the once-converted private copy, table services retain source policy.
 * Read once after the original IP walk; harvesting is not idempotent. */
struct amdgpu_discovery_info_targets {
 uint8_t *binary;
 const uint32_t (*ip_versions)[HWIP_MAX_INSTANCE];
 uint16_t pci_device;
 uint8_t pci_revision;
 uint16_t *xcc_mask, *vcn_mask, *jpeg_mask;
 unsigned *vcn_harvest, *jpeg_harvest, *isp_harvest;
 uint32_t *harvest_mask, *sdma_mask, *node_count, *half_use;
 int *umc_count;
 uint8_t *vcn_count;
 amdgpu_discovery_umc_mask *active_mask;
 uint64_t *mall_size;
 uint32_t *codec_disable[AMDGPU_MAX_VCN_INSTANCES];
 struct amdgpu_gfx_config *config;
 struct amdgpu_cu_info *cu_info;
};
struct amdgpu_discovery_info_ops {
 void *context;
 int (*table)(void *, struct table_info **, uint16_t);
 int (*valid_ip)(void *, uint8_t, uint16_t);
 void (*error)(void *, const char *, ...);
 void (*warn)(void *, const char *, ...);
 void (*drm_error)(void *, const char *, ...);
};
#define AMDGPU_INFO_ERROR(o, ...) do { if ((o)->error) (o)->error((o)->context, __VA_ARGS__); } while (0)
#define AMDGPU_INFO_WARN(o, ...) do { if ((o)->warn) (o)->warn((o)->context, __VA_ARGS__); } while (0)
#define AMDGPU_INFO_DRM_ERROR(o, ...) do { if ((o)->drm_error) (o)->drm_error((o)->context, __VA_ARGS__); } while (0)
static inline uint32_t amdgpu_discovery_info_version(const struct amdgpu_discovery_info_targets *targets, uint8_t ip, uint8_t inst)
{
 return targets->ip_versions[ip][inst] & ~0xFFU;
}
static inline void amdgpu_discovery_harvest_config_quirk_core(const struct amdgpu_discovery_info_targets *targets,
		const struct amdgpu_discovery_info_ops *ops)
{
	/*
	 * So far, apply this quirk only on those Navy Flounder boards which
	 * have a bad harvest table of VCN config.
	 */
	if ((amdgpu_discovery_info_version(targets, UVD_HWIP, 1) == IP_VERSION(3, 0, 1)) &&
	    (amdgpu_discovery_info_version(targets, GC_HWIP, 0) == IP_VERSION(10, 3, 2))) {
		switch (targets->pci_revision) {
		case 0xC1:
		case 0xC2:
		case 0xC3:
		case 0xC5:
		case 0xC7:
		case 0xCF:
		case 0xDF:
			(*targets->vcn_harvest) |= AMDGPU_VCN_HARVEST_VCN1;
			(*targets->vcn_mask) &= ~AMDGPU_VCN_HARVEST_VCN1;
			break;
		default:
			break;
		}
	}
}

static inline void amdgpu_discovery_read_harvest_bit_per_ip_core(const struct amdgpu_discovery_info_targets *targets,
		const struct amdgpu_discovery_info_ops *ops,
						uint32_t *vcn_harvest_count)
{
	uint8_t *discovery_bin = targets->binary;
	struct table_info *info;
	struct ip_discovery_header *ihdr;
	struct die_header *dhdr;
	struct ip *ip;
	uint16_t die_offset, ip_offset, num_dies, num_ips;
	uint16_t hw_id;
	uint8_t inst;
	int i, j;

	if (ops->table(ops->context, &info, IP_DISCOVERY))
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
			if (ops->valid_ip(ops->context, inst, hw_id))
				goto next_ip;

			if (ip->harvest == 1) {
				switch (hw_id) {
				case VCN_HWID:
					(*vcn_harvest_count)++;
					if (inst == 0) {
						(*targets->vcn_harvest) |= AMDGPU_VCN_HARVEST_VCN0;
						(*targets->vcn_mask) &=
							~AMDGPU_VCN_HARVEST_VCN0;
						(*targets->jpeg_mask) &=
							~AMDGPU_VCN_HARVEST_VCN0;
					} else {
						(*targets->vcn_harvest) |= AMDGPU_VCN_HARVEST_VCN1;
						(*targets->vcn_mask) &=
							~AMDGPU_VCN_HARVEST_VCN1;
						(*targets->jpeg_mask) &=
							~AMDGPU_VCN_HARVEST_VCN1;
					}
					break;
				case DMU_HWID:
					(*targets->harvest_mask) |= AMD_HARVEST_IP_DMU_MASK;
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

static inline void amdgpu_discovery_read_from_harvest_table_core(const struct amdgpu_discovery_info_targets *targets,
		const struct amdgpu_discovery_info_ops *ops,
						     uint32_t *vcn_harvest_count,
						     uint32_t *umc_harvest_count)
{
	uint8_t *discovery_bin = targets->binary;
	struct table_info *info;
	struct harvest_table *harvest_info;
	u16 offset;
	int i;
	u64 umc_harvest_config = 0;

	if (ops->table(ops->context, &info, HARVEST_INFO))
		return;
	offset = le16_to_cpu(info->offset);

	if (!offset) {
		AMDGPU_INFO_ERROR(ops, "invalid harvest table offset\n");
		return;
	}

	harvest_info = (struct harvest_table *)(discovery_bin + offset);

	for (i = 0; i < 32; i++) {
		u16 hw_id = le16_to_cpu(harvest_info->list[i].hw_id);
		u8 inst = harvest_info->list[i].number_instance;

		if (hw_id == 0)
			break;

		if (inst >= 32) {
			AMDGPU_INFO_WARN(ops,
				 "bogus harvest instance %u for hw_id %u\n",
				 inst, hw_id);
			continue;
		}

		switch (hw_id) {
		case VCN_HWID:
			(*vcn_harvest_count)++;
			(*targets->vcn_harvest) |= BIT(inst);
			(*targets->jpeg_harvest) |= BIT(inst);

			(*targets->vcn_mask) &= ~BIT(inst);
			(*targets->jpeg_mask) &= ~BIT(inst);
			break;
		case DMU_HWID:
			(*targets->harvest_mask) |= AMD_HARVEST_IP_DMU_MASK;
			break;
		case UMC_HWID:
			umc_harvest_config |= BIT_ULL(inst);
			(*umc_harvest_count)++;
			break;
		case GC_HWID:
			(*targets->xcc_mask) &= ~BIT(inst);
			break;
		case SDMA0_HWID:
			(*targets->sdma_mask) &= ~BIT(inst);
			break;
#if defined(CONFIG_DRM_AMD_ISP)
		case ISP_HWID:
			(*targets->isp_harvest) |= ~BIT(inst);
			break;
#endif
		default:
			break;
		}
	}

	(*targets->active_mask) = ((1ULL << (*targets->node_count)) - 1ULL) &
				~umc_harvest_config;
}

static inline void amdgpu_discovery_harvest_ip_core(const struct amdgpu_discovery_info_targets *targets,
		const struct amdgpu_discovery_info_ops *ops)
{
	uint8_t *discovery_bin = targets->binary;
	struct ip_discovery_header *ihdr;
	struct table_info *info;
	int vcn_harvest_count = 0;
	int umc_harvest_count = 0;
	uint16_t ihdr_ver;

	if (ops->table(ops->context, &info, IP_DISCOVERY))
		return;
	ihdr = (struct ip_discovery_header *)(discovery_bin +
					      le16_to_cpu(info->offset));
	ihdr_ver = le16_to_cpu(ihdr->version);
	/*
	 * Harvest table does not fit Navi1x and legacy GPUs,
	 * so read harvest bit per IP data structure to set
	 * harvest configuration.
	 */
	if (amdgpu_discovery_info_version(targets, GC_HWIP, 0) < IP_VERSION(10, 2, 0) &&
	    ihdr_ver <= 2) {
		if ((targets->pci_device == 0x731E &&
			(targets->pci_revision == 0xC6 ||
			 targets->pci_revision == 0xC7)) ||
			(targets->pci_device == 0x7340 &&
			 targets->pci_revision == 0xC9) ||
			(targets->pci_device == 0x7360 &&
			 targets->pci_revision == 0xC7))
			amdgpu_discovery_read_harvest_bit_per_ip_core(targets, ops,
				&vcn_harvest_count);
	} else {
		amdgpu_discovery_read_from_harvest_table_core(targets, ops,
							 &vcn_harvest_count,
							 &umc_harvest_count);
	}

	amdgpu_discovery_harvest_config_quirk_core(targets, ops);

	if (vcn_harvest_count == (*targets->vcn_count)) {
		(*targets->harvest_mask) |= AMD_HARVEST_IP_VCN_MASK;
		(*targets->harvest_mask) |= AMD_HARVEST_IP_JPEG_MASK;
	}

	if (umc_harvest_count < (*targets->umc_count)) {
		(*targets->umc_count) -= umc_harvest_count;
	}
}

union gc_info {
	struct gc_info_v1_0 v1;
	struct gc_info_v1_1 v1_1;
	struct gc_info_v1_2 v1_2;
	struct gc_info_v1_3 v1_3;
	struct gc_info_v2_0 v2;
	struct gc_info_v2_1 v2_1;
};

static inline int amdgpu_discovery_get_gfx_info_core(const struct amdgpu_discovery_info_targets *targets,
		const struct amdgpu_discovery_info_ops *ops)
{
	uint8_t *discovery_bin = targets->binary;
	struct table_info *info;
	union gc_info *gc_info;
	u16 offset;

	if (!discovery_bin) {
		AMDGPU_INFO_DRM_ERROR(ops,"ip discovery uninitialized\n");
		return -EINVAL;
	}

	if (ops->table(ops->context, &info, GC))
		return -EINVAL;
	offset = le16_to_cpu(info->offset);

	if (!offset)
		return 0;

	gc_info = (union gc_info *)(discovery_bin + offset);

	switch (le16_to_cpu(gc_info->v1.header.version_major)) {
	case 1:
		targets->config->max_shader_engines = le32_to_cpu(gc_info->v1.gc_num_se);
		targets->config->max_cu_per_sh = 2 * (le32_to_cpu(gc_info->v1.gc_num_wgp0_per_sa) +
						      le32_to_cpu(gc_info->v1.gc_num_wgp1_per_sa));
		targets->config->max_sh_per_se = le32_to_cpu(gc_info->v1.gc_num_sa_per_se);
		targets->config->max_backends_per_se = le32_to_cpu(gc_info->v1.gc_num_rb_per_se);
		targets->config->max_texture_channel_caches = le32_to_cpu(gc_info->v1.gc_num_gl2c);
		targets->config->max_gprs = le32_to_cpu(gc_info->v1.gc_num_gprs);
		targets->config->max_gs_threads = le32_to_cpu(gc_info->v1.gc_num_max_gs_thds);
		targets->config->gs_vgt_table_depth = le32_to_cpu(gc_info->v1.gc_gs_table_depth);
		targets->config->gs_prim_buffer_depth = le32_to_cpu(gc_info->v1.gc_gsprim_buff_depth);
		targets->config->double_offchip_lds_buf = le32_to_cpu(gc_info->v1.gc_double_offchip_lds_buffer);
		targets->cu_info->wave_front_size = le32_to_cpu(gc_info->v1.gc_wave_size);
		targets->cu_info->max_waves_per_simd = le32_to_cpu(gc_info->v1.gc_max_waves_per_simd);
		targets->cu_info->max_scratch_slots_per_cu = le32_to_cpu(gc_info->v1.gc_max_scratch_slots_per_cu);
		targets->cu_info->lds_size = le32_to_cpu(gc_info->v1.gc_lds_size);
		targets->config->num_sc_per_sh = le32_to_cpu(gc_info->v1.gc_num_sc_per_se) /
			le32_to_cpu(gc_info->v1.gc_num_sa_per_se);
		targets->config->num_packer_per_sc = le32_to_cpu(gc_info->v1.gc_num_packer_per_sc);
		if (le16_to_cpu(gc_info->v1.header.version_minor) >= 1) {
			targets->config->gc_num_tcp_per_sa = le32_to_cpu(gc_info->v1_1.gc_num_tcp_per_sa);
			targets->config->gc_num_sdp_interface = le32_to_cpu(gc_info->v1_1.gc_num_sdp_interface);
			targets->config->gc_num_tcps = le32_to_cpu(gc_info->v1_1.gc_num_tcps);
		}
		if (le16_to_cpu(gc_info->v1.header.version_minor) >= 2) {
			targets->config->gc_num_tcp_per_wpg = le32_to_cpu(gc_info->v1_2.gc_num_tcp_per_wpg);
			targets->config->gc_tcp_l1_size = le32_to_cpu(gc_info->v1_2.gc_tcp_l1_size);
			targets->config->gc_num_sqc_per_wgp = le32_to_cpu(gc_info->v1_2.gc_num_sqc_per_wgp);
			targets->config->gc_l1_instruction_cache_size_per_sqc = le32_to_cpu(gc_info->v1_2.gc_l1_instruction_cache_size_per_sqc);
			targets->config->gc_l1_data_cache_size_per_sqc = le32_to_cpu(gc_info->v1_2.gc_l1_data_cache_size_per_sqc);
			targets->config->gc_gl1c_per_sa = le32_to_cpu(gc_info->v1_2.gc_gl1c_per_sa);
			targets->config->gc_gl1c_size_per_instance = le32_to_cpu(gc_info->v1_2.gc_gl1c_size_per_instance);
			targets->config->gc_gl2c_per_gpu = le32_to_cpu(gc_info->v1_2.gc_gl2c_per_gpu);
		}
		if (le16_to_cpu(gc_info->v1.header.version_minor) >= 3) {
			targets->config->gc_tcp_size_per_cu = le32_to_cpu(gc_info->v1_3.gc_tcp_size_per_cu);
			targets->config->gc_tcp_cache_line_size = le32_to_cpu(gc_info->v1_3.gc_tcp_cache_line_size);
			targets->config->gc_instruction_cache_size_per_sqc = le32_to_cpu(gc_info->v1_3.gc_instruction_cache_size_per_sqc);
			targets->config->gc_instruction_cache_line_size = le32_to_cpu(gc_info->v1_3.gc_instruction_cache_line_size);
			targets->config->gc_scalar_data_cache_size_per_sqc = le32_to_cpu(gc_info->v1_3.gc_scalar_data_cache_size_per_sqc);
			targets->config->gc_scalar_data_cache_line_size = le32_to_cpu(gc_info->v1_3.gc_scalar_data_cache_line_size);
			targets->config->gc_tcc_size = le32_to_cpu(gc_info->v1_3.gc_tcc_size);
			targets->config->gc_tcc_cache_line_size = le32_to_cpu(gc_info->v1_3.gc_tcc_cache_line_size);
		}
		break;
	case 2:
		targets->config->max_shader_engines = le32_to_cpu(gc_info->v2.gc_num_se);
		targets->config->max_cu_per_sh = le32_to_cpu(gc_info->v2.gc_num_cu_per_sh);
		targets->config->max_sh_per_se = le32_to_cpu(gc_info->v2.gc_num_sh_per_se);
		targets->config->max_backends_per_se = le32_to_cpu(gc_info->v2.gc_num_rb_per_se);
		targets->config->max_texture_channel_caches = le32_to_cpu(gc_info->v2.gc_num_tccs);
		targets->config->max_gprs = le32_to_cpu(gc_info->v2.gc_num_gprs);
		targets->config->max_gs_threads = le32_to_cpu(gc_info->v2.gc_num_max_gs_thds);
		targets->config->gs_vgt_table_depth = le32_to_cpu(gc_info->v2.gc_gs_table_depth);
		targets->config->gs_prim_buffer_depth = le32_to_cpu(gc_info->v2.gc_gsprim_buff_depth);
		targets->config->double_offchip_lds_buf = le32_to_cpu(gc_info->v2.gc_double_offchip_lds_buffer);
		targets->cu_info->wave_front_size = le32_to_cpu(gc_info->v2.gc_wave_size);
		targets->cu_info->max_waves_per_simd = le32_to_cpu(gc_info->v2.gc_max_waves_per_simd);
		targets->cu_info->max_scratch_slots_per_cu = le32_to_cpu(gc_info->v2.gc_max_scratch_slots_per_cu);
		targets->cu_info->lds_size = le32_to_cpu(gc_info->v2.gc_lds_size);
		targets->config->num_sc_per_sh = le32_to_cpu(gc_info->v2.gc_num_sc_per_se) /
			le32_to_cpu(gc_info->v2.gc_num_sh_per_se);
		targets->config->num_packer_per_sc = le32_to_cpu(gc_info->v2.gc_num_packer_per_sc);
		if (le16_to_cpu(gc_info->v2.header.version_minor) == 1) {
			targets->config->gc_num_tcp_per_sa = le32_to_cpu(gc_info->v2_1.gc_num_tcp_per_sh);
			targets->config->gc_tcp_size_per_cu = le32_to_cpu(gc_info->v2_1.gc_tcp_size_per_cu);
			targets->config->gc_num_sdp_interface = le32_to_cpu(gc_info->v2_1.gc_num_sdp_interface); /* per XCD */
			targets->config->gc_num_cu_per_sqc = le32_to_cpu(gc_info->v2_1.gc_num_cu_per_sqc);
			targets->config->gc_l1_instruction_cache_size_per_sqc = le32_to_cpu(gc_info->v2_1.gc_instruction_cache_size_per_sqc);
			targets->config->gc_l1_data_cache_size_per_sqc = le32_to_cpu(gc_info->v2_1.gc_scalar_data_cache_size_per_sqc);
			targets->config->gc_tcc_size = le32_to_cpu(gc_info->v2_1.gc_tcc_size); /* per XCD */
		}
		break;
	default:
		AMDGPU_INFO_ERROR(ops,
			"Unhandled GC info table %d.%d\n",
			le16_to_cpu(gc_info->v1.header.version_major),
			le16_to_cpu(gc_info->v1.header.version_minor));
		return -EINVAL;
	}
	return 0;
}

union mall_info {
	struct mall_info_v1_0 v1;
	struct mall_info_v2_0 v2;
};

static inline int amdgpu_discovery_get_mall_info_core(const struct amdgpu_discovery_info_targets *targets,
		const struct amdgpu_discovery_info_ops *ops)
{
	uint8_t *discovery_bin = targets->binary;
	struct table_info *info;
	union mall_info *mall_info;
	u32 u, mall_size_per_umc, m_s_present, half_use;
	u64 mall_size;
	u16 offset;

	if (!discovery_bin) {
		AMDGPU_INFO_DRM_ERROR(ops,"ip discovery uninitialized\n");
		return -EINVAL;
	}

	if (ops->table(ops->context, &info, MALL_INFO))
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
		for (u = 0; u < (*targets->umc_count); u++) {
			if (m_s_present & (1 << u))
				mall_size += mall_size_per_umc * 2;
			else if (half_use & (1 << u))
				mall_size += mall_size_per_umc / 2;
			else
				mall_size += mall_size_per_umc;
		}
		(*targets->mall_size) = mall_size;
		(*targets->half_use) = half_use;
		break;
	case 2:
		mall_size_per_umc = le32_to_cpu(mall_info->v2.mall_size_per_umc);
		(*targets->mall_size) = (uint64_t)mall_size_per_umc * (*targets->umc_count);
		break;
	default:
		AMDGPU_INFO_ERROR(ops,
			"Unhandled MALL info table %d.%d\n",
			le16_to_cpu(mall_info->v1.header.version_major),
			le16_to_cpu(mall_info->v1.header.version_minor));
		return -EINVAL;
	}
	return 0;
}

union vcn_info {
	struct vcn_info_v1_0 v1;
};

static inline int amdgpu_discovery_get_vcn_info_core(const struct amdgpu_discovery_info_targets *targets,
		const struct amdgpu_discovery_info_ops *ops)
{
	uint8_t *discovery_bin = targets->binary;
	struct table_info *info;
	union vcn_info *vcn_info;
	u16 offset;
	int v;

	if (!discovery_bin) {
		AMDGPU_INFO_DRM_ERROR(ops,"ip discovery uninitialized\n");
		return -EINVAL;
	}

	/* num_vcn_inst is currently limited to AMDGPU_MAX_VCN_INSTANCES
	 * which is smaller than VCN_INFO_TABLE_MAX_NUM_INSTANCES
	 * but that may change in the future with new GPUs so keep this
	 * check for defensive purposes.
	 */
	if ((*targets->vcn_count) > VCN_INFO_TABLE_MAX_NUM_INSTANCES) {
		AMDGPU_INFO_ERROR(ops, "invalid vcn instances\n");
		return -EINVAL;
	}

	if (ops->table(ops->context, &info, VCN_INFO))
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
		for (v = 0; v < (*targets->vcn_count); v++) {
			(*targets->codec_disable[v]) =
				le32_to_cpu(vcn_info->v1.instance_info[v].fuse_data.all_bits);
		}
		break;
	default:
		AMDGPU_INFO_ERROR(ops,
			"Unhandled VCN info table %d.%d\n",
			le16_to_cpu(vcn_info->v1.header.version_major),
			le16_to_cpu(vcn_info->v1.header.version_minor));
		return -EINVAL;
	}
	return 0;
}

#pragma GCC diagnostic pop
#undef AMDGPU_INFO_ERROR
#undef AMDGPU_INFO_WARN
#undef AMDGPU_INFO_DRM_ERROR
#endif
