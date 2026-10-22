/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_VIRT_H
#define STELA_AMDGPU_VIRT_H
#include <linux/types.h>
#include "amdgv_sriovmsg.h"
/* Copyright 2016 Advanced Micro Devices, Inc.; from amdgpu_virt.h. */

#define AMDGPU_SRIOV_CAPS_SRIOV_VBIOS  (1 << 0) /* vBIOS is sr-iov ready */
#define AMDGPU_SRIOV_CAPS_ENABLE_IOV   (1 << 1) /* sr-iov is enabled on this GPU */
#define AMDGPU_SRIOV_CAPS_IS_VF        (1 << 2) /* this GPU is a virtual function */
#define AMDGPU_PASSTHROUGH_MODE        (1 << 3) /* thw whole GPU is pass through for VM */
#define AMDGPU_SRIOV_CAPS_RUNTIME      (1 << 4) /* is out of full access mode */

enum AMDGIM_FEATURE_FLAG {
	/* GIM supports feature of Error log collecting */
	AMDGIM_FEATURE_ERROR_LOG_COLLECT = 0x1,
	/* GIM supports feature of loading uCodes */
	AMDGIM_FEATURE_GIM_LOAD_UCODES   = 0x2,
	/* VRAM LOST by GIM */
	AMDGIM_FEATURE_GIM_FLR_VRAMLOST = 0x4,
	/* MM bandwidth */
	AMDGIM_FEATURE_GIM_MM_BW_MGR = 0x8,
	/* PP ONE VF MODE in GIM */
	AMDGIM_FEATURE_PP_ONE_VF = (1 << 4),
	/* Indirect Reg Access enabled */
	AMDGIM_FEATURE_INDIRECT_REG_ACCESS = (1 << 5),
	/* AV1 Support MODE*/
	AMDGIM_FEATURE_AV1_SUPPORT = (1 << 6),
	/* VCN RB decouple */
	AMDGIM_FEATURE_VCN_RB_DECOUPLE = (1 << 7),
	/* MES info */
	AMDGIM_FEATURE_MES_INFO_ENABLE = (1 << 8),
	AMDGIM_FEATURE_RAS_CAPS = (1 << 9),
	AMDGIM_FEATURE_RAS_TELEMETRY = (1 << 10),
	AMDGIM_FEATURE_RAS_CPER = (1 << 11),
	AMDGIM_FEATURE_XGMI_TA_EXT_PEER_LINK = (1 << 12),
	AMDGIM_FEATURE_XGMI_CONNECTED_TO_CPU = (1 << 13),
	AMDGIM_FEATURE_PTL_SUPPORT = (1 << 14),
	AMDGIM_FEATURE_UNITID_SUPPORT = (1 << 15),
};

struct amdgpu_virt_region {
	uint32_t offset;
	uint32_t size_kb;
};

/* The virtualization state unchanged sources read. */
struct amdgpu_virt {
	uint32_t caps;
	uint32_t gim_feature;
	struct amdgpu_virt_region crit_regn_tbl[AMD_SRIOV_MSG_MAX_TABLE_ID];
	bool is_dynamic_crit_regn_enabled;
};

#define amdgpu_sriov_vf(adev) \
((adev)->virt.caps & AMDGPU_SRIOV_CAPS_IS_VF)

#define amdgpu_passthrough(adev) \
((adev)->virt.caps & AMDGPU_PASSTHROUGH_MODE)

#define amdgpu_sriov_xgmi_connected_to_cpu(adev) \
((adev)->virt.gim_feature & AMDGIM_FEATURE_XGMI_CONNECTED_TO_CPU)
#endif
