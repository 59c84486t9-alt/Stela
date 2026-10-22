/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_FILE_H
#define STELA_DRM_FILE_H
#include <linux/fs.h>
#include <linux/types.h>
struct drm_device;
/* The DRM file state unchanged sources read; Stela opens no DRM files, and a
 * source that names a file operation declares it. */
struct drm_minor {
	struct drm_device *dev;
};
struct drm_file {
	struct drm_minor *minor;
	void *driver_priv;
};
static int drm_open(struct inode *inode, struct file *filp);
static ssize_t drm_read(struct file *filp, char __user *buffer, size_t count,
			loff_t *offset);
static int drm_release(struct inode *inode, struct file *filp);
static __poll_t drm_poll(struct file *filp, struct poll_table_struct *wait);
#endif
