/* SPDX-License-Identifier: MIT */
#ifndef STELA_I915_GEM_H
#define STELA_I915_GEM_H
#include <linux/build_bug.h>
#include <linux/bug.h>
#include <linux/types.h>
/* Linux's release configuration: CONFIG_DRM_I915_DEBUG_GEM is off. */
#define GEM_BUG_ON(expr) ((void)sizeof((long)(expr)))
#define GEM_WARN_ON(expr) ({ unlikely(!!(expr)); })
#endif
