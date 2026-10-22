/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_DRM_DRM_DRV_H
#define STELA_DRM_DRM_DRV_H
#include <linux/bits.h>
#include <linux/stddef.h>
#include <linux/types.h>
struct device;
struct drm_device;
struct drm_fb_helper;
struct drm_fb_helper_surface_size;
struct drm_file;
struct drm_gem_object;
struct drm_ioctl_desc;
struct drm_mode_create_dumb;
struct drm_printer;
struct dma_buf;
struct file_operations;

/* Copyright 1999 Precision Insight, Inc., 2000 VA Linux Systems, Inc. and
 * 2016 Intel Corporation; from drm_drv.h. */
enum drm_driver_feature {
	DRIVER_GEM			= BIT(0),
	DRIVER_MODESET			= BIT(1),
	DRIVER_RENDER			= BIT(3),
	DRIVER_ATOMIC			= BIT(4),
	DRIVER_SYNCOBJ                  = BIT(5),
	DRIVER_SYNCOBJ_TIMELINE         = BIT(6),
};

/* The driver description a source defines; Stela registers no DRM driver, so
 * it holds only the members those sources fill in. */
struct drm_driver {
	int (*open) (struct drm_device *, struct drm_file *);
	void (*postclose) (struct drm_device *, struct drm_file *);
	void (*release) (struct drm_device *);
	struct drm_gem_object * (*gem_prime_import)(struct drm_device *dev,
				struct dma_buf *dma_buf);
	int (*dumb_create)(struct drm_file *file_priv,
			   struct drm_device *dev,
			   struct drm_mode_create_dumb *args);
	int (*dumb_map_offset)(struct drm_file *file_priv,
			       struct drm_device *dev, uint32_t handle,
			       uint64_t *offset);
	int (*fbdev_probe)(struct drm_fb_helper *fbdev_helper,
			   struct drm_fb_helper_surface_size *sizes);
	void (*show_fdinfo)(struct drm_printer *p, struct drm_file *f);
	int major;
	int minor;
	int patchlevel;
	char *name;
	char *desc;
	u32 driver_features;
	const struct drm_ioctl_desc *ioctls;
	int num_ioctls;
	const struct file_operations *fops;
};

/* Services the sources call, which each adapter defines. */
static void *__devm_drm_dev_alloc(struct device *parent,
				  const struct drm_driver *driver,
				  size_t size, size_t offset);
static int drm_dev_register(struct drm_device *dev, unsigned long flags);
static bool drm_dev_enter(struct drm_device *dev, int *idx);
static void drm_dev_exit(int idx);
static void drm_dev_unplug(struct drm_device *dev);
/* Whether the kernel's nomodeset parameter leaves displays to firmware. */
static bool drm_firmware_drivers_only(void);

/* Copyright 1999 Precision Insight, Inc., 2000 VA Linux Systems, Inc. and
 * 2016 Intel Corporation; from drm_drv.h. */
#define devm_drm_dev_alloc(parent, driver, type, member) \
	((type *) __devm_drm_dev_alloc(parent, driver, sizeof(type), \
				       offsetof(type, member)))
#endif
