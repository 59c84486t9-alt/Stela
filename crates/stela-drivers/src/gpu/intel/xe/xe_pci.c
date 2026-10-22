// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Intel Corporation
 */

#include "xe_pci.h"

#include <kunit/static_stub.h>
#include <linux/device/driver.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>

#include <drm/drm_color_mgmt.h>
#include <drm/drm_drv.h>
#include <drm/intel/pciids.h>

#include "display/xe_display.h"
#include "regs/xe_gt_regs.h"
#include "regs/xe_regs.h"
#include "xe_configfs.h"
#include "xe_device.h"
#include "xe_drv.h"
#include "xe_gt.h"
#include "xe_gt_sriov_vf.h"
#include "xe_guc.h"
#include "xe_mmio.h"
#include "xe_module.h"
#include "xe_pci_rebar.h"
#include "xe_pci_sriov.h"
#include "xe_pci_types.h"
#include "xe_pm.h"
#include "xe_printk.h"
#include "xe_sriov.h"
#include "xe_step.h"
#include "xe_survivability_mode.h"
#include "xe_tile.h"

enum toggle_d3cold {
	D3COLD_DISABLE,
	D3COLD_ENABLE,
};

#include "xe_pci_device_info.h"
MODULE_DEVICE_TABLE(pci, pciidlist);

/* is device_id present in comma separated list of ids */
static bool device_id_in_list(u16 device_id, const char *devices, bool negative)
{
	char *s, *p, *tok;
	bool ret;

	if (!devices || !*devices)
		return false;

	/* match everything */
	if (negative && strcmp(devices, "!*") == 0)
		return true;
	if (!negative && strcmp(devices, "*") == 0)
		return true;

	s = kstrdup(devices, GFP_KERNEL);
	if (!s)
		return false;

	for (p = s, ret = false; (tok = strsep(&p, ",")) != NULL; ) {
		u16 val;

		if (negative && tok[0] == '!')
			tok++;
		else if ((negative && tok[0] != '!') ||
			 (!negative && tok[0] == '!'))
			continue;

		if (kstrtou16(tok, 16, &val) == 0 && val == device_id) {
			ret = true;
			break;
		}
	}

	kfree(s);

	return ret;
}

static bool id_forced(u16 device_id)
{
	return device_id_in_list(device_id, xe_modparam.force_probe, false);
}

static bool id_blocked(u16 device_id)
{
	return device_id_in_list(device_id, xe_modparam.force_probe, true);
}

#include "xe_pci_runtime.h"

enum xe_gmdid_type {
	GMDID_GRAPHICS,
	GMDID_MEDIA
};

static int read_gmdid(struct xe_device *xe, enum xe_gmdid_type type, u32 *ver, u32 *revid)
{
	struct xe_mmio *mmio = xe_root_tile_mmio(xe);
	struct xe_reg gmdid_reg = xe_pci_gmdid_register(type == GMDID_MEDIA);
	u32 val;

	KUNIT_STATIC_STUB_REDIRECT(read_gmdid, xe, type, ver, revid);

	if (IS_SRIOV_VF(xe)) {
		/*
		 * To get the value of the GMDID register, VFs must obtain it
		 * from the GuC using MMIO communication.
		 *
		 * Note that at this point the GTs are not initialized and only
		 * tile-level access to MMIO registers is possible. To use our
		 * existing GuC communication functions we must create a dummy
		 * GT structure and perform at least basic xe_gt and xe_guc
		 * initialization.
		 */
		struct xe_gt *gt __free(kfree) = NULL;
		int err;

		/* Don't try to read media ver if media GT is not allowed */
		if (type == GMDID_MEDIA && !xe_configfs_media_gt_allowed(to_pci_dev(xe->drm.dev))) {
			*ver = *revid = 0;
			return 0;
		}

		gt = kzalloc(sizeof(*gt), GFP_KERNEL);
		if (!gt)
			return -ENOMEM;

		gt->tile = &xe->tiles[0];
		if (type == GMDID_MEDIA) {
			gt->info.id = 1;
			gt->info.type = XE_GT_TYPE_MEDIA;
		} else {
			gt->info.id = 0;
			gt->info.type = XE_GT_TYPE_MAIN;
		}

		xe_gt_mmio_init(gt);
		xe_guc_comm_init_early(&gt->uc.guc);

		err = xe_gt_sriov_vf_bootstrap(gt);
		if (err)
			return err;

		val = xe_gt_sriov_vf_gmdid(gt);
	} else {
		/*
		 * GMD_ID is a GT register, but at this point in the driver
		 * init we haven't fully initialized the GT yet so we need to
		 * read the register with the tile's MMIO accessor.  That means
		 * we need to apply the GSI offset manually since it won't get
		 * automatically added as it would if we were using a GT mmio
		 * accessor.
		 */
		val = xe_mmio_read32(mmio, gmdid_reg);
	}

	xe_pci_decode_gmdid(val, ver, revid);

	return 0;
}

/*
 * Read IP version from hardware and select graphics/media IP descriptors
 * based on the result.
 */
static int handle_gmdid(struct xe_device *xe,
			const struct xe_ip **graphics_ip,
			const struct xe_ip **media_ip,
			u32 *graphics_revid,
			u32 *media_revid)
{
	u32 ver;
	int ret;

	*graphics_ip = NULL;
	*media_ip = NULL;

	ret = read_gmdid(xe, GMDID_GRAPHICS, &ver, graphics_revid);
	if (ret)
		return ret;

	*graphics_ip = find_graphics_ip(ver);
	if (!*graphics_ip) {
		drm_err(&xe->drm, "Hardware reports unknown graphics version %u.%02u\n",
			ver / 100, ver % 100);
	}

	ret = read_gmdid(xe, GMDID_MEDIA, &ver, media_revid);
	if (ret)
		return ret;

	/* Media may legitimately be fused off / not present */
	if (ver == 0)
		return 0;

	*media_ip = find_media_ip(ver);
	if (!*media_ip) {
		drm_err(&xe->drm, "Hardware reports unknown media version %u.%02u\n",
			ver / 100, ver % 100);
	}

	return 0;
}

static void init_devid(struct xe_device *xe)
{
	struct pci_dev *pdev = to_pci_dev(xe->drm.dev);

	KUNIT_STATIC_STUB_REDIRECT(init_devid, xe);

	xe->info.devid = pdev->device;
	xe->info.revid = pdev->revision;
}

/*
 * Initialize device info content that only depends on static driver_data
 * passed to the driver at probe time from PCI ID table.
 */
static int xe_info_init_early(struct xe_device *xe,
			      const struct xe_device_desc *desc,
			      const struct xe_subplatform_desc *subplatform_desc)
{
	int err;

	xe->info.platform_name = desc->platform_name;
	xe->info.platform = desc->platform;
	xe->info.subplatform = subplatform_desc ?
		subplatform_desc->subplatform : XE_SUBPLATFORM_NONE;

	init_devid(xe);

	xe->info.dma_mask_size = desc->dma_mask_size;
	xe->info.va_bits = desc->va_bits;
	xe->info.vm_max_level = desc->vm_max_level;
	xe->info.vram_flags = desc->vram_flags;

	xe->info.is_dgfx = desc->is_dgfx;
	xe->info.has_cached_pt = desc->has_cached_pt;
	xe->info.has_fan_control = desc->has_fan_control;
	/* runtime fusing may force flat_ccs to disabled later */
	xe->info.has_flat_ccs = desc->has_flat_ccs;
	xe->info.has_mbx_power_limits = desc->has_mbx_power_limits;
	xe->info.has_mbx_thermal_info = desc->has_mbx_thermal_info;
	xe->info.has_gsc_nvm = desc->has_gsc_nvm;
	xe->info.has_heci_gscfi = desc->has_heci_gscfi;
	xe->info.has_heci_cscfi = desc->has_heci_cscfi;
	xe->info.has_i2c = desc->has_i2c;
	xe->info.has_late_bind = desc->has_late_bind;
	xe->info.has_llc = desc->has_llc;
	xe->info.has_mert = desc->has_mert;
	xe->info.has_page_reclaim_hw_assist = desc->has_page_reclaim_hw_assist;
	xe->info.has_pre_prod_wa = desc->has_pre_prod_wa;
	xe->info.has_pxp = desc->has_pxp;
	xe->info.has_soc_remapper_sysctrl = desc->has_soc_remapper_sysctrl;
	xe->info.has_soc_remapper_telem = desc->has_soc_remapper_telem;
	xe->info.has_sriov = xe_configfs_primary_gt_allowed(to_pci_dev(xe->drm.dev)) &&
		desc->has_sriov;
	xe->info.has_sysctrl = desc->has_sysctrl;
	xe->info.skip_guc_pc = desc->skip_guc_pc;
	xe->info.skip_pcode = desc->skip_pcode;
	xe->info.needs_scratch = desc->needs_scratch;
	xe->info.needs_shared_vf_gt_wq = desc->needs_shared_vf_gt_wq;
	xe->info.multi_lrc_mask = desc->multi_lrc_mask;

	xe->info.probe_display = IS_ENABLED(CONFIG_DRM_XE_DISPLAY) &&
				 xe_modparam.probe_display &&
				 desc->has_display &&
				 !xe_device_is_admin_only(xe);
	xe->info.force_execlist = xe_modparam.force_execlist;

	xe_assert(xe, desc->max_gt_per_tile > 0);
	xe_assert(xe, desc->max_gt_per_tile <= XE_MAX_GT_PER_TILE);
	xe->info.max_gt_per_tile = desc->max_gt_per_tile;
	xe->info.tile_count = 1 + desc->max_remote_tiles;

	xe_step_platform_get(xe);

	err = xe_tile_init_early(xe_device_get_root_tile(xe), xe, 0);
	if (err)
		return err;

	return 0;
}

/*
 * Possibly override number of tile based on configuration register.
 */
static void xe_info_probe_tile_count(struct xe_device *xe)
{
	struct xe_mmio *mmio;
	u8 tile_count;
	u32 mtcfg;

	KUNIT_STATIC_STUB_REDIRECT(xe_info_probe_tile_count, xe);

	/*
	 * Probe for tile count only for platforms that support multiple
	 * tiles.
	 */
	if (xe->info.tile_count == 1)
		return;

	mmio = xe_root_tile_mmio(xe);

	/*
	 * Although the per-tile mmio regs are not yet initialized, this
	 * is fine as it's going to the root tile's mmio, that's
	 * guaranteed to be initialized earlier in xe_mmio_probe_early()
	 */
	mtcfg = xe_mmio_read32(mmio, XEHP_MTCFG_ADDR);
	tile_count = xe_pci_runtime_tile_count(xe->info.tile_count, mtcfg);

	if (tile_count < xe->info.tile_count) {
		drm_info(&xe->drm, "tile_count: %d, reduced_tile_count %d\n",
			 xe->info.tile_count, tile_count);
		xe->info.tile_count = tile_count;
	}
}

static struct xe_gt *alloc_primary_gt(struct xe_tile *tile,
				      const struct xe_graphics_desc *graphics_desc,
				      const struct xe_media_desc *media_desc)
{
	struct xe_device *xe = tile_to_xe(tile);
	struct xe_gt *gt;

	if (!xe_configfs_primary_gt_allowed(to_pci_dev(xe->drm.dev))) {
		xe_info(xe, "Primary GT disabled via configfs\n");
		return NULL;
	}

	gt = xe_gt_alloc(tile);
	if (IS_ERR(gt))
		return gt;

	gt->info.type = XE_GT_TYPE_MAIN;
	gt->info.id = tile->id * xe->info.max_gt_per_tile;
	gt->info.has_indirect_ring_state = graphics_desc->has_indirect_ring_state;
	gt->info.multi_queue_engine_class_mask = graphics_desc->multi_queue_engine_class_mask;
	gt->info.engine_mask = graphics_desc->hw_engine_mask;
	gt->info.num_geometry_xecore_fuse_regs = graphics_desc->num_geometry_xecore_fuse_regs;
	gt->info.num_compute_xecore_fuse_regs = graphics_desc->num_compute_xecore_fuse_regs;

	/*
	 * Even if the service copy engines wind up being fused off, their
	 * presence in the IP descriptor indicates that the platform supports
	 * Xe2-style MEM_SET and MEM_COPY functionality.
	 */
	if (graphics_desc->hw_engine_mask & GENMASK(XE_HW_ENGINE_BCS8,
						    XE_HW_ENGINE_BCS1))
		gt->info.has_xe2_blt_instructions = true;

	/*
	 * Before media version 13, the media IP was part of the primary GT
	 * so we need to add the media engines to the primary GT's engine list.
	 */
	if (MEDIA_VER(xe) < 13 && media_desc)
		gt->info.engine_mask |= media_desc->hw_engine_mask;

	return gt;
}

static struct xe_gt *alloc_media_gt(struct xe_tile *tile,
				    const struct xe_media_desc *media_desc)
{
	struct xe_device *xe = tile_to_xe(tile);
	struct xe_gt *gt;

	if (!xe_configfs_media_gt_allowed(to_pci_dev(xe->drm.dev))) {
		xe_info(xe, "Media GT disabled via configfs\n");
		return NULL;
	}

	if (MEDIA_VER(xe) < 13 || !media_desc)
		return NULL;

	gt = xe_gt_alloc(tile);
	if (IS_ERR(gt))
		return gt;

	gt->info.type = XE_GT_TYPE_MEDIA;
	gt->info.id = tile->id * xe->info.max_gt_per_tile + 1;
	gt->info.has_indirect_ring_state = media_desc->has_indirect_ring_state;
	gt->info.engine_mask = media_desc->hw_engine_mask;

	return gt;
}

/*
 * Initialize device info content that does require knowledge about
 * graphics / media IP version.
 * Make sure that GT / tile structures allocated by the driver match the data
 * present in device info.
 */
static int xe_info_init(struct xe_device *xe,
			const struct xe_device_desc *desc)
{
	u32 graphics_gmdid_revid = 0, media_gmdid_revid = 0;
	const struct xe_ip *graphics_ip;
	const struct xe_ip *media_ip;
	const struct xe_graphics_desc *graphics_desc;
	const struct xe_media_desc *media_desc;
	struct xe_tile *tile;
	struct xe_gt *gt;
	int ret;
	u8 id;

	/*
	 * If this platform supports GMD_ID, we'll detect the proper IP
	 * descriptor to use from hardware registers.
	 * desc->pre_gmdid_graphics_ip will only ever be set at this point for
	 * platforms before GMD_ID. In that case the IP descriptions and
	 * versions are simply derived from that.
	 */
	if (desc->pre_gmdid_graphics_ip) {
		graphics_ip = desc->pre_gmdid_graphics_ip;
		media_ip = desc->pre_gmdid_media_ip;
		xe_step_pre_gmdid_get(xe);
	} else {
		xe_assert(xe, !desc->pre_gmdid_media_ip);
		ret = handle_gmdid(xe, &graphics_ip, &media_ip,
				   &graphics_gmdid_revid, &media_gmdid_revid);
		if (ret)
			return ret;

		xe_step_gmdid_get(xe, graphics_gmdid_revid, media_gmdid_revid);
	}

	/*
	 * If we couldn't detect the graphics IP, that's considered a fatal
	 * error and we should abort driver load.  Failing to detect media
	 * IP is non-fatal; we'll just proceed without enabling media support.
	 */
	if (!graphics_ip)
		return -ENODEV;

	xe->info.graphics_verx100 = graphics_ip->verx100;
	xe->info.graphics_name = graphics_ip->name;
	graphics_desc = graphics_ip->desc;

	if (media_ip) {
		xe->info.media_verx100 = media_ip->verx100;
		xe->info.media_name = media_ip->name;
		media_desc = media_ip->desc;
	} else {
		xe->info.media_name = "none";
		media_desc = NULL;
	}

	xe->info.has_access_counter = graphics_desc->has_access_counter;
	xe->info.has_asid = graphics_desc->has_asid;
	xe->info.has_atomic_enable_pte_bit = graphics_desc->has_atomic_enable_pte_bit;
	if (xe->info.platform != XE_PVC)
		xe->info.has_device_atomics_on_smem = 1;

	xe->info.has_range_tlb_inval = graphics_desc->has_range_tlb_inval;
	xe->info.has_ctx_tlb_inval = graphics_desc->has_ctx_tlb_inval;
	xe->info.has_usm = graphics_desc->has_usm;
	xe->info.has_64bit_timestamp = graphics_desc->has_64bit_timestamp;
	xe->info.has_mem_copy_instr = GRAPHICS_VER(xe) >= 20;

	if (IS_SRIOV_VF(xe)) {
		xe->info.has_sysctrl = 0;
		xe->info.has_soc_remapper_sysctrl = 0;
		xe->info.has_soc_remapper_telem = 0;
	}

	xe_info_probe_tile_count(xe);

	for_each_remote_tile(tile, xe, id) {
		int err;

		err = xe_tile_init_early(tile, xe, id);
		if (err)
			return err;
	}

	/* Allocate any GT and VRAM structures necessary for the platform. */
	for_each_tile(tile, xe, id) {
		int err;

		err = xe_tile_alloc_vram(tile);
		if (err)
			return err;

		tile->primary_gt = alloc_primary_gt(tile, graphics_desc, media_desc);
		if (IS_ERR(tile->primary_gt))
			return PTR_ERR(tile->primary_gt);

		/*
		 * It's not currently possible to probe a device with the
		 * primary GT disabled.  With some work, this may be future in
		 * the possible for igpu platforms (although probably not for
		 * dgpu's since access to the primary GT's BCS engines is
		 * required for VRAM management).
		 */
		if (!tile->primary_gt) {
			drm_err(&xe->drm, "Cannot probe device with without a primary GT\n");
			return -ENODEV;
		}

		tile->media_gt = alloc_media_gt(tile, media_desc);
		if (IS_ERR(tile->media_gt))
			return PTR_ERR(tile->media_gt);
	}

	/*
	 * Now that we have tiles and GTs defined, let's loop over valid GTs
	 * in order to define gt_count.
	 */
	for_each_gt(gt, xe, id)
		xe->info.gt_count++;

	return 0;
}

static void xe_pci_remove(struct pci_dev *pdev)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);

	if (IS_SRIOV_PF(xe))
		xe_pci_sriov_configure(pdev, 0);

	if (xe_survivability_mode_is_boot_enabled(xe))
		return;

	xe_device_remove(xe);

	/*
	 * Preserve remove-time flush after moving destroy work to module
	 * lifetime.
	 */
	xe_destroy_wq_flush();
	xe_pm_fini(xe);
}

/*
 * Probe the PCI device, initialize various parts of the driver.
 *
 * Fault injection is used to test the error paths of some initialization
 * functions called either directly from xe_pci_probe() or indirectly for
 * example through xe_device_probe(). Those functions use the kernel fault
 * injection capabilities infrastructure, see
 * Documentation/fault-injection/fault-injection.rst for details. The macro
 * ALLOW_ERROR_INJECTION() is used to conditionally skip function execution
 * at runtime and use a provided return value. The first requirement for
 * error injectable functions is proper handling of the error code by the
 * caller for recovery, which is always the case here. The second
 * requirement is that no state is changed before the first error return.
 * It is not strictly fulfilled for all initialization functions using the
 * ALLOW_ERROR_INJECTION() macro but this is acceptable because for those
 * error cases at probe time, the error code is simply propagated up by the
 * caller. Therefore there is no consequence on those specific callers when
 * function error injection skips the whole function.
 */
static int xe_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	const struct xe_device_desc *desc = (const void *)ent->driver_data;
	const struct xe_subplatform_desc *subplatform_desc;
	struct xe_device *xe;
	int err;

	subplatform_desc = find_subplatform(desc, pdev->device);

	xe_configfs_check_device(pdev);

	if (desc->require_force_probe && !id_forced(pdev->device)) {
		dev_info(&pdev->dev,
			 "Your graphics device %04x is not officially supported\n"
			 "by xe driver in this kernel version. To force Xe probe,\n"
			 "use xe.force_probe='%04x' and i915.force_probe='!%04x'\n"
			 "module parameters or CONFIG_DRM_XE_FORCE_PROBE='%04x' and\n"
			 "CONFIG_DRM_I915_FORCE_PROBE='!%04x' configuration options.\n",
			 pdev->device, pdev->device, pdev->device,
			 pdev->device, pdev->device);
		return -ENODEV;
	}

	if (id_blocked(pdev->device)) {
		dev_info(&pdev->dev, "Probe blocked for device [%04x:%04x].\n",
			 pdev->vendor, pdev->device);
		return -ENODEV;
	}

	if (xe_display_driver_probe_defer(pdev))
		return -EPROBE_DEFER;

	err = pcim_enable_device(pdev);
	if (err)
		return err;

	xe = xe_device_create(pdev);
	if (IS_ERR(xe))
		return PTR_ERR(xe);

	pci_set_drvdata(pdev, &xe->drm);

	xe_pm_assert_unbounded_bridge(xe);

	pci_set_master(pdev);

	err = xe_info_init_early(xe, desc, subplatform_desc);
	if (err)
		return err;

	xe_pci_rebar_resize(xe);

	err = xe_device_probe_early(xe);
	/*
	 * In Boot Survivability mode, no drm card is exposed and driver
	 * is loaded with bare minimum to allow for firmware to be
	 * flashed through mei. Return success, if survivability mode
	 * is enabled due to pcode failure or configfs being set
	 */
	if (xe_survivability_mode_is_boot_enabled(xe))
		return 0;

	if (err)
		return err;

	err = xe_info_init(xe, desc);
	if (err)
		return err;

	err = xe_display_probe(xe);
	if (err)
		return err;

	drm_dbg(&xe->drm, "%s %s %04x:%04x dgfx:%d gfx:%s (%d.%02d) media:%s (%d.%02d) display:%s dma_m_s:%d tc:%d gscfi:%d cscfi:%d",
		desc->platform_name,
		subplatform_desc ? subplatform_desc->name : "",
		xe->info.devid, xe->info.revid,
		xe->info.is_dgfx,
		xe->info.graphics_name,
		xe->info.graphics_verx100 / 100,
		xe->info.graphics_verx100 % 100,
		xe->info.media_name,
		xe->info.media_verx100 / 100,
		xe->info.media_verx100 % 100,
		str_yes_no(xe->info.probe_display),
		xe->info.dma_mask_size, xe->info.tile_count,
		xe->info.has_heci_gscfi, xe->info.has_heci_cscfi);

	drm_dbg(&xe->drm, "Stepping = (G:%s, M:%s, B:%s)\n",
		xe_step_name(xe->info.step.graphics),
		xe_step_name(xe->info.step.media),
		xe_step_name(xe->info.step.basedie));

	drm_dbg(&xe->drm, "SR-IOV support: %s (mode: %s)\n",
		str_yes_no(xe_device_has_sriov(xe)),
		xe_sriov_mode_to_string(xe_device_sriov_mode(xe)));

	err = xe_pm_probe(xe);
	if (err)
		return err;

	err = xe_device_probe(xe);
	if (err)
		return err;

	err = xe_pm_init(xe);
	if (err)
		goto err_driver_cleanup;

	return 0;

err_driver_cleanup:
	xe_pci_remove(pdev);
	return err;
}

static void xe_pci_shutdown(struct pci_dev *pdev)
{
	xe_device_shutdown(pdev_to_xe_device(pdev));
}

#ifdef CONFIG_PM_SLEEP
static void d3cold_toggle(struct pci_dev *pdev, enum toggle_d3cold toggle)
{
	struct xe_device *xe = pdev_to_xe_device(pdev);
	struct pci_dev *root_pdev;

	if (!xe->d3cold.capable)
		return;

	root_pdev = pcie_find_root_port(pdev);
	if (!root_pdev)
		return;

	switch (toggle) {
	case D3COLD_DISABLE:
		pci_d3cold_disable(root_pdev);
		break;
	case D3COLD_ENABLE:
		pci_d3cold_enable(root_pdev);
		break;
	}
}

static int xe_pci_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct xe_device *xe = pdev_to_xe_device(pdev);
	int err;

	if (xe_survivability_mode_is_boot_enabled(xe))
		return -EBUSY;

	err = xe_pm_suspend(xe);
	if (err)
		return err;

	/*
	 * Enabling D3Cold is needed for S2Idle/S0ix.
	 * It is save to allow here since xe_pm_suspend has evicted
	 * the local memory and the direct complete optimization is disabled.
	 */
	d3cold_toggle(pdev, D3COLD_ENABLE);

	pci_save_state(pdev);
	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3cold);

	return 0;
}

static int xe_pci_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	int err;

	/* Give back the D3Cold decision to the runtime P M*/
	d3cold_toggle(pdev, D3COLD_DISABLE);

	err = pci_set_power_state(pdev, PCI_D0);
	if (err)
		return err;

	pci_restore_state(pdev);

	err = pci_enable_device(pdev);
	if (err)
		return err;

	pci_set_master(pdev);

	err = xe_pm_resume(pdev_to_xe_device(pdev));
	if (err)
		return err;

	return 0;
}

static int xe_pci_runtime_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct xe_device *xe = pdev_to_xe_device(pdev);
	int err;

	/*
	 * We hold an additional reference to the runtime PM to keep PF in D0
	 * during VFs lifetime, as our VFs do not implement the PM capability.
	 * This means we should never be runtime suspending as long as VFs are
	 * enabled.
	 */
	xe_assert(xe, !IS_SRIOV_VF(xe));
	xe_assert(xe, !pci_num_vf(pdev));

	err = xe_pm_runtime_suspend(xe);
	if (err)
		return err;

	pci_save_state(pdev);

	if (xe->d3cold.allowed) {
		d3cold_toggle(pdev, D3COLD_ENABLE);
		pci_disable_device(pdev);
		pci_ignore_hotplug(pdev);
		pci_set_power_state(pdev, PCI_D3cold);
	} else {
		d3cold_toggle(pdev, D3COLD_DISABLE);
		pci_set_power_state(pdev, PCI_D3hot);
	}

	return 0;
}

static int xe_pci_runtime_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct xe_device *xe = pdev_to_xe_device(pdev);
	int err;

	err = pci_set_power_state(pdev, PCI_D0);
	if (err)
		return err;

	pci_restore_state(pdev);

	if (xe->d3cold.allowed) {
		err = pci_enable_device(pdev);
		if (err)
			return err;

		pci_set_master(pdev);
	}

	return xe_pm_runtime_resume(xe);
}

static int xe_pci_runtime_idle(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct xe_device *xe = pdev_to_xe_device(pdev);

	xe_pm_d3cold_allowed_toggle(xe);

	return 0;
}

static const struct dev_pm_ops xe_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(xe_pci_suspend, xe_pci_resume)
	SET_RUNTIME_PM_OPS(xe_pci_runtime_suspend, xe_pci_runtime_resume, xe_pci_runtime_idle)
};
#endif

static struct pci_driver xe_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = pciidlist,
	.probe = xe_pci_probe,
	.remove = xe_pci_remove,
	.shutdown = xe_pci_shutdown,
	.sriov_configure = xe_pci_sriov_configure,
#ifdef CONFIG_PM_SLEEP
	.driver.pm = &xe_pm_ops,
#endif
};

/**
 * xe_pci_to_pf_device() - Get PF &xe_device.
 * @pdev: the VF &pci_dev device
 *
 * Return: pointer to PF &xe_device, NULL otherwise.
 */
struct xe_device *xe_pci_to_pf_device(struct pci_dev *pdev)
{
	struct drm_device *drm;

	drm = pci_iov_get_pf_drvdata(pdev, &xe_pci_driver);
	if (IS_ERR(drm))
		return NULL;

	return to_xe_device(drm);
}

int xe_register_pci_driver(void)
{
	return pci_register_driver(&xe_pci_driver);
}

void xe_unregister_pci_driver(void)
{
	pci_unregister_driver(&xe_pci_driver);
}

#if IS_ENABLED(CONFIG_DRM_XE_KUNIT_TEST)
#include "tests/xe_pci.c"
#endif
