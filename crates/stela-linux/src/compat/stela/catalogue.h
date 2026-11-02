/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_CATALOGUE_H
#define STELA_LINUX_CATALOGUE_H
#include <linux/types.h>
struct device;
struct stela_linux_owner;
/* One mount-lifetime kernel owner. A failed claim is never reset. */
int stela_linux_kernel_claim(const struct stela_linux_owner *owner);
/* Actual native producer only, exact fresh claimed owner before Environment. */
int stela_linux_kernel_geometry_bind(const struct stela_linux_owner *owner,
                                   unsigned int actual_levels);
int stela_linux_kernel_geometry_ready(const struct stela_linux_owner *owner);
int stela_linux_kernel_geometry_storage(const struct stela_linux_owner *owner,
                                      unsigned long *addresses);
unsigned int stela_linux_task_initial_root_levels(void);
int stela_linux_kernel_ready(const struct stela_linux_owner *owner);
/* A refused partial Environment is not reusable; no global reset is proven. */
int stela_linux_kernel_environment(const struct stela_linux_owner *owner);
bool stela_linux_kernel_owner_allowed(const struct stela_linux_owner *owner);
int stela_linux_kernel_entry(const struct stela_linux_owner *owner);
/* Pre-entry task/WQ allocation also forbids adopting a legacy kernel later. */
int stela_linux_kernel_prepare_resource(void);
bool stela_linux_kernel_catalogue_active(void);
/* Root binding takes authority only on success. It retains no self-device ref.
 * Caller owns the initialized original device through publication/final put. */
int stela_linux_device_bind(struct device *dev, void *authority,
                           void (*release_authority)(void *));
int stela_linux_device_inherit(struct device *dev);
bool stela_linux_device_publish_allowed(struct device *dev);
void stela_linux_device_close(struct device *dev);
/* These are actual get_device/kobject references, not a context-lifetime grant.
 * A lease keeps an enrolled child's actual original root through final put. */
struct stela_linux_device_lease { struct device *device; const void *authority; };
int stela_linux_device_acquire(struct device *dev, struct stela_linux_device_lease *lease);
int stela_linux_device_release(struct stela_linux_device_lease *lease);
/* Remove lookup membership before foreign device release; finish afterwards
 * without touching the device, which the foreign callback may have freed. */
struct stela_linux_device_retirement { void *entry; };
bool stela_linux_device_release_begin(struct device *dev,
                                     struct stela_linux_device_retirement *retired);
void stela_linux_device_release_end(struct stela_linux_device_retirement *retired);
u64 stela_linux_device_quarantined_releases(void);
#endif
