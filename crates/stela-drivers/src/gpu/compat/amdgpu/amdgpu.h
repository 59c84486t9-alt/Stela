/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_H
#define STELA_AMDGPU_H
struct amdgpu_device;
/* Stela's owners bring up each IP block themselves, so discovery's block
 * registration stays internal to the adapters that include it, and unused. */
static int amdgpu_discovery_set_ip_blocks(struct amdgpu_device *adev);
#include <drm/drm_device.h>
#include <drm/drm_print.h>
#include <linux/array_size.h>
#include <linux/bitops.h>
#include <linux/container_of.h>
#include <linux/delay.h>
#include <linux/dev_printk.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/kobject.h>
#include <linux/limits.h>
#include <linux/panic.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/suspend.h>
#include <linux/types.h>
#include <linux/xarray.h>
#include <asm/byteorder.h>
#include <asm/page.h>
#include <drm/amdgpu_drm.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <uapi/linux/agpgart.h>
#include "amd_shared.h"
#include "kgd_pp_interface.h"
#include "amdgpu_ctx.h"
#include "amdgpu_debugfs.h"
#include "amdgpu_dpm.h"
#include "amdgpu_eviction_fence.h"
#include "amdgpu_gem.h"
#include "amdgpu_gfx.h"
#include "amdgpu_gmc.h"
#include "amdgpu_discovery.h"
#include "amdgpu_ip.h"
#include "amdgpu_lockdep.h"
#include "amdgpu_mode.h"
#include "amdgpu_psp.h"
#include "amdgpu_ras_eeprom.h"
#include "amdgpu_ring.h"
#include "amdgpu_sdma.h"
#include "amdgpu_smuio.h"
#include "amdgpu_sync.h"
#include "amdgpu_ucode.h"
#include "amdgpu_umsch_mm.h"
#include "amdgpu_userq.h"
#include "amdgpu_vcn.h"
#include "amdgpu_virt.h"
#include "amdgpu_vm.h"
#include "amdgpu_vpe.h"
#include "amdgpu_xcp.h"
struct amdgpu_reset_domain;

/* Copyright 2012-16 Advanced Micro Devices, Inc. and Copyright 2019 Raptor
 * Engineering, LLC; from display's
 * dc/os_types.h, which amdgpu.h reaches through amdgpu_mode.h. */
#if defined(__BIG_ENDIAN) && !defined(BIGENDIAN_CPU)
#define BIGENDIAN_CPU
#elif defined(__LITTLE_ENDIAN) && !defined(LITTLEENDIAN_CPU)
#define LITTLEENDIAN_CPU
#endif

/* Copyright 2008 Advanced Micro Devices, Inc., Red Hat Inc. and Jerome
 * Glisse; from amdgpu.h. */
#define MAX_GPU_INSTANCE		64

struct amdgpu_gpu_instance {
	struct amdgpu_device		*adev;
	int				mgpu_fan_enabled;
};

struct amdgpu_mgpu_info {
	struct amdgpu_gpu_instance	gpu_ins[MAX_GPU_INSTANCE];
	struct mutex			mutex;
	uint32_t			num_gpu;
	uint32_t			num_dgpu;
	uint32_t			num_apu;
};

struct amdgpu_watchdog_timer {
	bool timeout_fatal_disable;
	uint32_t period; /* maxCycles = (1 << period), the number of cycles before a timeout */
};

#define AMDGPU_MAX_TIMEOUT_PARAM_LENGTH	256

/* A file's driver state, holding only the members unchanged sources name. */
struct amdgpu_fpriv {
	struct amdgpu_vm	vm;
	struct amdgpu_ctx_mgr	ctx_mgr;
	struct amdgpu_userq_mgr	userq_mgr;
	struct amdgpu_eviction_fence_mgr evf_mgr;
};

/* The ASIC operations unchanged sources call; Stela's owners bind none. */
struct amdgpu_asic_funcs {
	int (*reset)(struct amdgpu_device *adev);
	int (*update_umd_stable_pstate)(struct amdgpu_device *adev, bool enter);
};

/* The device state unchanged amdgpu sources read and write; each member has
 * upstream's name and type, and nested structures hold only the members those
 * sources use. */
struct amdgpu_device {
	struct device *dev;
	struct pci_dev *pdev;
	struct drm_device ddev;
	enum amd_asic_type asic_type;
	uint32_t family;
	unsigned long flags;
	unsigned long apu_flags;
	const struct amdgpu_asic_funcs *asic_funcs;
	struct amdgpu_reset_domain *reset_domain;
	struct amdgpu_ring *rings[AMDGPU_MAX_RINGS];
	struct amdgpu_mode_info mode_info;
	struct amdgpu_pm pm;
	enum pp_mp1_state mp1_state;
	struct xarray userq_doorbell_xa;
	suspend_state_t last_suspend_state;
	bool in_suspend;
	bool in_s3;
	bool in_s4;
	bool in_s0ix;
	bool in_runpm;
	bool no_hw_access;
	bool dc_enabled;
	bool debug_vm;
	bool debug_largebar;
	bool debug_disable_soft_recovery;
	bool debug_use_vram_fw_buf;
	bool debug_enable_ras_aca;
	bool debug_exp_resets;
	bool debug_disable_gpu_ring_reset;
	bool debug_vm_userptr;
	bool debug_disable_ce_logs;
	bool debug_enable_ce_cs;
	bool enable_virtual_display;
	bool enable_umsch_mm;
	bool enable_mes;
	bool enable_mes_kiq;
	bool enable_uni_mes;
	uint32_t harvest_ip_mask;
	uint32_t *reg_offset[MAX_HWIP][HWIP_MAX_INSTANCE];
	uint32_t ip_versions[MAX_HWIP][HWIP_MAX_INSTANCE];
	struct amdgpu_discovery_info discovery;
	struct amdgpu_firmware firmware;
	struct amdgpu_virt virt;
	struct {
		struct amdgpu_gfx_config config;
		struct amdgpu_cu_info cu_info;
		uint16_t xcc_mask;
	} gfx;
	struct {
		u64 real_vram_size;
		u64 mall_size;
		uint32_t m_half_use;
		int num_umc;
	} gmc;
	struct {
		uint32_t node_inst_num;
		unsigned long active_mask;
	} umc;
	struct {
		uint8_t num_vcn_inst;
		struct {
			uint8_t vcn_config;
			uint32_t vcn_codec_disable_mask;
		} inst[AMDGPU_MAX_VCN_INSTANCES];
		unsigned harvest_config;
		uint16_t inst_mask;
	} vcn;
	struct {
		unsigned harvest_config;
		uint16_t inst_mask;
	} jpeg;
	struct {
		int num_instances;
		uint32_t sdma_mask;
	} sdma;
	struct {
		uint32_t num_instances;
	} vpe;
	struct {
		unsigned int harvest_config;
	} isp;
	struct {
		const struct amdgpu_df_funcs *funcs;
	} df;
	struct {
		const struct amdgpu_hdp_funcs *funcs;
	} hdp;
	struct {
		const struct amdgpu_lsdma_funcs *funcs;
	} lsdma;
	struct {
		const struct amdgpu_nbio_funcs *funcs;
		const struct nbio_hdp_flush_reg *hdp_flush_reg;
	} nbio;
	struct {
		const struct amdgpu_smuio_funcs *funcs;
	} smuio;
};

/* Copyright 2008 Advanced Micro Devices, Inc., Red Hat Inc. and Jerome
 * Glisse; from amdgpu.h. */
extern int amdgpu_modeset;
extern int amdgpu_dpm;
extern int amdgpu_exp_hw_support;
extern int amdgpu_discovery;
extern int amdgpu_uni_mes;
extern int amdgpu_force_asic_type;
extern int amdgpu_si_support;
extern int amdgpu_cik_support;
extern int amdgpu_umsch_mm;

static inline uint32_t amdgpu_ip_version(const struct amdgpu_device *adev,
					 uint8_t ip, uint8_t inst)
{
	/* This considers only major/minor/rev and ignores
	 * subrevision/variant fields.
	 */
	return adev->ip_versions[ip][inst] & ~0xFFU;
}

static inline uint32_t amdgpu_ip_version_full(const struct amdgpu_device *adev,
					      uint8_t ip, uint8_t inst)
{
	/* This returns full version - major/minor/rev/variant/subrevision */
	return adev->ip_versions[ip][inst];
}

static inline struct amdgpu_device *drm_to_adev(struct drm_device *ddev)
{
	return container_of(ddev, struct amdgpu_device, ddev);
}

static inline struct drm_device *adev_to_drm(struct amdgpu_device *adev)
{
	return &adev->ddev;
}

extern const struct attribute_group amdgpu_vram_mgr_attr_group;
extern const struct attribute_group amdgpu_gtt_mgr_attr_group;
extern const struct attribute_group amdgpu_flash_attr_group;

#define amdgpu_asic_reset(adev) (adev)->asic_funcs->reset((adev))
#define amdgpu_asic_update_umd_stable_pstate(adev, enter) \
	((adev)->asic_funcs->update_umd_stable_pstate ? (adev)->asic_funcs->update_umd_stable_pstate((adev), (enter)) : 0)

#define AMDGPU_REGS_NO_KIQ    (1<<1)
#define RREG32(reg) amdgpu_device_rreg(adev, (reg), 0)
#define WREG32(reg, v) amdgpu_device_wreg(adev, (reg), (v), 0)

/* Services the sources call, which each adapter defines. */
static uint32_t amdgpu_device_rreg(struct amdgpu_device *adev, uint32_t reg,
				   uint32_t acc_flags);
static void amdgpu_device_wreg(struct amdgpu_device *adev, uint32_t reg,
			       uint32_t v, uint32_t acc_flags);
static void amdgpu_device_vram_access(struct amdgpu_device *adev, loff_t pos,
				      void *buf, size_t size, bool write);
static bool amdgpu_device_has_dc_support(struct amdgpu_device *adev);
static bool amdgpu_device_asic_has_dc_support(struct pci_dev *pdev,
					      enum amd_asic_type asic_type);
static bool amdgpu_device_supports_px(struct amdgpu_device *adev);
static bool amdgpu_device_supports_boco(struct amdgpu_device *adev);
static int amdgpu_device_supports_baco(struct amdgpu_device *adev);
static int amdgpu_device_baco_enter(struct amdgpu_device *adev);
static int amdgpu_device_baco_exit(struct amdgpu_device *adev);
static int amdgpu_device_prepare(struct drm_device *dev);
static void amdgpu_device_complete(struct drm_device *dev);
static int amdgpu_device_suspend(struct drm_device *dev, bool fbcon);
static int amdgpu_device_resume(struct drm_device *dev, bool fbcon);
static bool amdgpu_device_cache_pci_state(struct pci_dev *pdev);
static bool amdgpu_device_load_pci_state(struct pci_dev *pdev);
static int amdgpu_driver_load_kms(struct amdgpu_device *adev, unsigned long flags);
static void amdgpu_driver_unload_kms(struct drm_device *dev);
static int amdgpu_driver_open_kms(struct drm_device *dev, struct drm_file *file_priv);
static void amdgpu_driver_postclose_kms(struct drm_device *dev, struct drm_file *file_priv);
static void amdgpu_driver_release_kms(struct drm_device *dev);
static int amdgpu_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_cs_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_cs_fence_to_handle_ioctl(struct drm_device *dev, void *data,
					   struct drm_file *filp);
static int amdgpu_cs_wait_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static int amdgpu_cs_wait_fences_ioctl(struct drm_device *dev, void *data,
				       struct drm_file *filp);
static int amdgpu_bo_list_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
static pci_ers_result_t amdgpu_pci_error_detected(struct pci_dev *pdev,
						  pci_channel_state_t state);
static pci_ers_result_t amdgpu_pci_mmio_enabled(struct pci_dev *pdev);
static pci_ers_result_t amdgpu_pci_slot_reset(struct pci_dev *pdev);
static void amdgpu_pci_resume(struct pci_dev *pdev);

/* Copyright 2008 Advanced Micro Devices, Inc., Red Hat Inc. and Jerome
 * Glisse; from amdgpu.h, without CONFIG_ACPI, CONFIG_SUSPEND and
 * CONFIG_VGA_SWITCHEROO as Stela builds it. */
static inline int amdgpu_acpi_get_tmr_info(struct amdgpu_device *adev,
					   u64 *tmr_offset, u64 *tmr_size)
{
	return -EINVAL;
}
static inline bool amdgpu_acpi_should_gpu_reset(struct amdgpu_device *adev) { return false; }
static inline void amdgpu_acpi_detect(void) { }
static inline void amdgpu_acpi_release(void) { }
static inline bool amdgpu_acpi_is_s0ix_active(struct amdgpu_device *adev) { return false; }
static inline bool amdgpu_acpi_is_s3_active(struct amdgpu_device *adev) { return false; }
static inline void amdgpu_register_atpx_handler(void) {}
static inline void amdgpu_unregister_atpx_handler(void) {}
#endif
