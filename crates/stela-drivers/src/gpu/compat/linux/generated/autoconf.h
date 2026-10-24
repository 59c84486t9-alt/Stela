/* SPDX-License-Identifier: MIT */
/* Stela's Kconfig. Linux code runs on 64-bit x86 for one owner at a time,
 * without preemption or interrupts (see stela/linux.h): Linux's
 * uniprocessor, non-preemptible configuration of Stela's own arch. Options
 * not listed are disabled, so debug, tracing, KUnit and fault-injection
 * hooks compile out exactly as in a kernel built without them. */
#define CONFIG_64BIT 1
#define CONFIG_MMU 1
#define CONFIG_PCI 1
#define CONFIG_PRINTK 1
#define CONFIG_MESSAGE_LOGLEVEL_DEFAULT 4
#define CONFIG_FW_LOADER 1
/* Real generic IEEE/CRC32C library; no architecture dispatch. */
#define CONFIG_CRC32 1
/* Original XArray ordered/multi-index algorithms, not a layout substitute. */
#define CONFIG_XARRAY_MULTI 1
#define CONFIG_BUG 1
/* x86's WARN flags; asm/bug.h reports each site without a bug table. */
#define CONFIG_GENERIC_BUG 1
#define CONFIG_TINY_RCU 1
#define CONFIG_TINY_SRCU 1
/* Record balanced atomic/RCU sections; this enables no scheduling. */
#define CONFIG_PREEMPT_COUNT 1
#define CONFIG_ARCH_DMA_ADDR_T_64BIT 1
#define CONFIG_PHYS_ADDR_T_64BIT 1
#define CONFIG_NR_CPUS 1
#define CONFIG_HZ 1000
#define CONFIG_PAGE_SHIFT 12
#define CONFIG_PGTABLE_LEVELS 4
#define CONFIG_ILLEGAL_POINTER_VALUE 0xdead000000000000

/* The drivers' parameter and scheduling defaults, as Linux's Kconfig sets them. */
#define CONFIG_DRM_XE_FORCE_PROBE ""
#define CONFIG_DRM_I915_REQUEST_TIMEOUT 20000
#define CONFIG_DRM_I915_FENCE_TIMEOUT 10000
#define CONFIG_DRM_I915_USERFAULT_AUTOSUSPEND 250
#define CONFIG_DRM_I915_HEARTBEAT_INTERVAL 2500
#define CONFIG_DRM_I915_PREEMPT_TIMEOUT 640
#define CONFIG_DRM_I915_PREEMPT_TIMEOUT_COMPUTE 7500
#define CONFIG_DRM_I915_MAX_REQUEST_BUSYWAIT 8000
#define CONFIG_DRM_I915_STOP_TIMEOUT 100
#define CONFIG_DRM_I915_TIMESLICE_DURATION 1
#define CONFIG_DRM_XE_JOB_TIMEOUT_MAX 10000
#define CONFIG_DRM_XE_JOB_TIMEOUT_MIN 1
#define CONFIG_DRM_XE_TIMESLICE_MAX 10000000
#define CONFIG_DRM_XE_TIMESLICE_MIN 1
#define CONFIG_DRM_XE_PREEMPT_TIMEOUT 640000
#define CONFIG_DRM_XE_PREEMPT_TIMEOUT_MAX 10000000
#define CONFIG_DRM_XE_PREEMPT_TIMEOUT_MIN 1
