// SPDX-License-Identifier: MIT
/* The video command line options DRM reads, from drivers/video/cmdline.c and
 * nomodeset.c, which Stela has no command line to set. */
#include <video/cmdline.h>
#include <video/nomodeset.h>

bool video_firmware_drivers_only(void)
{
	return false;
}

/* video=, likewise: every connector keeps its mode from EDID. */
const char *video_get_options(const char *name)
{
	(void)name;
	return NULL;
}

#ifdef STELA_LINUX_DRM_FORMAT_TEST
#include <drm/drm_device.h>
#include <drm/drm_fourcc.h>
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
