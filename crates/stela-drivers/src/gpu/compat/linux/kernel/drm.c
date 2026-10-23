// SPDX-License-Identifier: MIT
/* Linux's DRM core as drivers reach it under Stela: messages and module
 * parameters. Stela registers no DRM device and serves no DRM file, so the
 * device and file services are unreached. */
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_gem.h>
#include <drm/drm_managed.h>
#include <drm/drm_print.h>
#include <video/nomodeset.h>
#include <unsupported.h>

/* drm.debug, as if Stela booted with drm.debug=0x2: drivers' debug messages
 * reach the running owner's log at KERN_DEBUG, for owners that diagnose
 * with them; the others discard them by level. */
unsigned long __drm_debug = BIT(DRM_UT_DRIVER);

/* nomodeset, which Stela has no command line to set. */
bool video_firmware_drivers_only(void)
{
	return false;
}

void drm_dev_printk(const struct device *dev, const char *level, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	struct va_format vaf = {.fmt = format, .va = &args};
	if (dev)
		dev_printk(level, dev, "[" DRM_NAME ":%ps] %pV", __builtin_return_address(0), &vaf);
	else
		printk("%s[" DRM_NAME ":%ps] %pV", level, __builtin_return_address(0), &vaf);
	va_end(args);
}

void __drm_dev_dbg(struct _ddebug *desc, const struct device *dev,
		   enum drm_debug_category category, const char *format, ...)
{
	(void)desc;
	if (!drm_debug_enabled_raw(category))
		return;
	va_list args;
	va_start(args, format);
	struct va_format vaf = {.fmt = format, .va = &args};
	if (dev)
		dev_printk(KERN_DEBUG, dev, "[" DRM_NAME ":%ps] %pV",
			   __builtin_return_address(0), &vaf);
	else
		printk(KERN_DEBUG "[" DRM_NAME ":%ps] %pV", __builtin_return_address(0), &vaf);
	va_end(args);
}

void __drm_err(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	struct va_format vaf = {.fmt = format, .va = &args};
	printk(KERN_ERR "[" DRM_NAME ":%ps] *ERROR* %pV", __builtin_return_address(0), &vaf);
	va_end(args);
}

void drm_printf(struct drm_printer *p, const char *f, ...)
{
	va_list args;
	va_start(args, f);
	drm_vprintf(p, f, &args);
	va_end(args);
}

/* The DRM device's lifecycle, which only a registered driver enters. */
STELA_UNSUPPORTED(void *, __devm_drm_dev_alloc, struct device *, const struct drm_driver *,
		  size_t, size_t)
STELA_UNSUPPORTED(int, drm_dev_register, struct drm_device *, unsigned long)
STELA_UNSUPPORTED(void, drm_dev_unplug, struct drm_device *)
STELA_UNSUPPORTED(bool, drm_dev_enter, struct drm_device *, int *)
STELA_UNSUPPORTED(void, drm_dev_exit, int)
/* Managed resources, released with a DRM device that Stela never creates. */
STELA_UNSUPPORTED(int, __drmm_add_action_or_reset, struct drm_device *, drmres_release_t, void *,
		  const char *)
/* A DRM file's operations, which only an opened DRM file runs. */
STELA_UNSUPPORTED(int, drm_open, struct inode *, struct file *)
STELA_UNSUPPORTED(int, drm_release, struct inode *, struct file *)
STELA_UNSUPPORTED(ssize_t, drm_read, struct file *, char __user *, size_t, loff_t *)
STELA_UNSUPPORTED(__poll_t, drm_poll, struct file *, struct poll_table_struct *)
STELA_UNSUPPORTED(long, drm_ioctl, struct file *, unsigned int, unsigned long)
STELA_UNSUPPORTED(int, drm_gem_mmap, struct file *, struct vm_area_struct *)

#ifdef STELA_LINUX_DRM_FORMAT_TEST
#include <drm/drm_mode_config.h>
#include <stela/linux.h>
#include <stela/test.h>

static unsigned int warnings;

static void format_warning(void *context, const char *file, int line, const char *condition)
{
	(void)context;
	assert(file && line > 0 && condition);
	warnings++;
}

static void rgb_and_pitch(void)
{
	const struct drm_format_info *rgb = drm_format_info(DRM_FORMAT_XRGB8888);
	const struct drm_format_info *rgba = drm_format_info(DRM_FORMAT_ABGR8888);
	assert(rgb && rgba && rgb->num_planes == 1 && !rgb->has_alpha && rgba->has_alpha);
	assert(drm_format_info_bpp(rgb, 0) == 32);
	assert(drm_format_info_block_width(rgb, 0) == 1);
	assert(drm_format_info_block_height(rgb, 0) == 1);
	assert(drm_format_info_min_pitch(rgb, 0, 1920) == 7680);
	assert(drm_format_info_min_pitch(rgb, 0, U32_MAX) == 17179869180ULL);
	assert(drm_format_info_min_pitch(rgb, 0, 0) == 0);
	assert(drm_mode_legacy_fb_format(16, 16) == DRM_FORMAT_RGB565);
	assert(drm_mode_legacy_fb_format(32, 30) == DRM_FORMAT_XRGB2101010);
	assert(drm_mode_legacy_fb_format(24, 24) == DRM_FORMAT_RGB888);
	assert(drm_mode_legacy_fb_format(24, 16) == DRM_FORMAT_INVALID);
}

static void yuv_and_subbyte_formats(void)
{
	const struct drm_format_info *nv12 = drm_format_info(DRM_FORMAT_NV12);
	const struct drm_format_info *yuv = drm_format_info(DRM_FORMAT_YUV420);
	const struct drm_format_info *packed = drm_format_info(DRM_FORMAT_YUYV);
	assert(nv12 && nv12->num_planes == 2 && drm_format_info_is_yuv_semiplanar(nv12));
	assert(nv12->hsub == 2 && nv12->vsub == 2);
	assert(drm_format_info_plane_width(nv12, 1920, 1) == 960);
	assert(drm_format_info_plane_height(nv12, 1080, 1) == 540);
	assert(drm_format_info_min_pitch(nv12, 0, 1920) == 1920);
	assert(drm_format_info_min_pitch(nv12, 1, 960) == 1920);
	assert(yuv && yuv->num_planes == 3 && drm_format_info_is_yuv_planar(yuv));
	assert(drm_format_info_min_pitch(yuv, 2, 960) == 960);
	assert(packed && drm_format_info_is_yuv_packed(packed));
	assert(drm_format_info_min_pitch(packed, 0, 1920) == 3840);
	const struct drm_format_info *c1 = drm_format_info(DRM_FORMAT_C1);
	assert(c1 && c1->is_color_indexed);
	assert(drm_format_info_block_width(c1, 0) == 8);
	assert(drm_format_info_bpp(c1, 0) == 1);
	assert(drm_format_info_min_pitch(c1, 0, 9) == 2);
	assert(drm_format_info_min_pitch(c1, 0, U32_MAX) == 536870912ULL);
}

static const struct drm_format_info modifier_format = {
	.format = DRM_FORMAT_XRGB8888,
	.num_planes = 1,
	.char_per_block = {16},
	.block_w = {2},
	.block_h = {2},
};

static const struct drm_format_info *modifier_lookup(u32 format, u64 modifier)
{
	return format == DRM_FORMAT_XRGB8888 && modifier == I915_FORMAT_MOD_X_TILED
		? &modifier_format : NULL;
}

static void device_format_lookup(void)
{
	static const struct drm_mode_config_funcs funcs = {.get_format_info = modifier_lookup};
	struct drm_device device = {.mode_config = {.funcs = &funcs}};
	assert(drm_get_format_info(&device, DRM_FORMAT_XRGB8888, I915_FORMAT_MOD_X_TILED) ==
	       &modifier_format);
	assert(drm_get_format_info(&device, DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR) ==
	       drm_format_info(DRM_FORMAT_XRGB8888));
	assert(drm_get_format_info(&device, DRM_FORMAT_RGB565, I915_FORMAT_MOD_X_TILED) ==
	       drm_format_info(DRM_FORMAT_RGB565));
	assert(drm_format_info_min_pitch(&modifier_format, 0, 3) == 12);
	device.mode_config.quirk_addfb_prefer_xbgr_30bpp = true;
	assert(drm_driver_legacy_fb_format(&device, 32, 30) == DRM_FORMAT_XBGR2101010);
	assert(drm_driver_color_mode_format(&device, 15) == DRM_FORMAT_XRGB1555);
	assert(drm_driver_color_mode_format(&device, 32) == DRM_FORMAT_XRGB8888);
}

static void invalid_inputs(void)
{
	const struct drm_format_info *info = drm_format_info(DRM_FORMAT_RGB565);
	assert(!__drm_format_info(DRM_FORMAT_INVALID));
	assert(!drm_format_info(DRM_FORMAT_INVALID));
	assert(warnings == 1);
	for (int plane = -1; plane <= 2; plane++) {
		if (plane == 0)
			continue;
		assert(drm_format_info_block_width(info, plane) == 0);
		assert(drm_format_info_block_height(info, plane) == 0);
		assert(drm_format_info_bpp(info, plane) == 0);
		assert(drm_format_info_min_pitch(info, plane, 1920) == 0);
	}
	assert(drm_format_info_block_width(NULL, 0) == 0);
	assert(drm_format_info_block_height(NULL, 0) == 0);
	assert(drm_format_info_bpp(NULL, 0) == 0);
	assert(drm_format_info_min_pitch(NULL, 0, 1920) == 0);
}

int main(void)
{
	const struct stela_linux_services services = {.warn = format_warning};
	const struct stela_linux_owner owner = {.services = &services};
	stela_linux_enter(&owner);
	rgb_and_pitch();
	yuv_and_subbyte_formats();
	device_format_lookup();
	invalid_inputs();
	stela_linux_exit();
	printf("Linux DRM formats: RGB, YUV, sub-byte, modifiers, bounds and 64-bit pitches\n");
	return 0;
}
#endif
