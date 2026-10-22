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
/* Framebuffer formats, which only mode setting describes. */
STELA_UNSUPPORTED(const struct drm_format_info *, drm_format_info, u32)
