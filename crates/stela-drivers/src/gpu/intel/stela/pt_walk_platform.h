/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef STELA_INTEL_PT_WALK_PLATFORM_H
#define STELA_INTEL_PT_WALK_PLATFORM_H

/* Only the scalar/math dependencies of xe_pt_walk.c. This is not a Linux
 * service implementation: tree storage and callbacks belong to the caller.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t u64;
/* Linux x86-64 pgoff_t is 64-bit; UEFI's unsigned long is only 32-bit. */
typedef uint64_t pgoff_t;

/* These values match enum page_walk_action in Linux's pagewalk.h. */
enum page_walk_action {
    ACTION_SUBTREE = 0,
    ACTION_CONTINUE = 1,
    ACTION_AGAIN = 2,
};

static inline u64 stela_xe_round_up(u64 value, u64 size)
{
    return ((value - 1) | (size - 1)) + 1;
}

static inline u64 stela_xe_round_down(u64 value, u64 size)
{
    return value & ~(size - 1);
}

static inline u64 stela_xe_min(u64 a, u64 b)
{
    return a < b ? a : b;
}

#define round_up(value, size) stela_xe_round_up((value), (size))
#define round_down(value, size) stela_xe_round_down((value), (size))
#define min_t(type, a, b) ((type)stela_xe_min((a), (b)))
#define IS_ALIGNED(value, size) (((value) & ((size) - 1)) == 0)
#define likely(value) __builtin_expect(!!(value), 1)
#define unlikely(value) __builtin_expect(!!(value), 0)

_Static_assert(sizeof(pgoff_t) == 8, "GPU page offsets must not truncate on UEFI");

#endif
