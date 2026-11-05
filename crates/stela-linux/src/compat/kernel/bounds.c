// SPDX-License-Identifier: MIT
/* Kbuild generates generated/bounds.h by compiling Linux's kernel/bounds.c.
 * Stela keeps the header and checks it here against the definitions that
 * file reports. */
#include <linux/build_bug.h>
#include <linux/mmzone.h>
#include <linux/page-flags.h>
#include <linux/spinlock_types.h>

static_assert(NR_PAGEFLAGS == __NR_PAGEFLAGS);
static_assert(MAX_NR_ZONES == __MAX_NR_ZONES);
static_assert(SPINLOCK_SIZE == sizeof(spinlock_t));
/* Without CONFIG_LRU_GEN, kernel/bounds.c reports no LRU generation bits. */
static_assert(!IS_ENABLED(CONFIG_LRU_GEN) && LRU_GEN_WIDTH == 0 && __LRU_REFS_WIDTH == 0);
