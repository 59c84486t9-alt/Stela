/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Test-only scalar/ordered/diagnostic bindings, never a native OS provider. */
#include "rbtree_bind.h"
typedef unsigned long long u64;
typedef unsigned int u32;
typedef __SIZE_TYPE__ size_t;
#define __force
#define __maybe_unused __attribute__((unused))
#define likely(x) __builtin_expect(!!(x), 1)
#define __PASTE_INNER(a, b) a##b
#define __PASTE(a, b) __PASTE_INNER(a, b)
#define __UNIQUE_ID(prefix) __PASTE(prefix, __COUNTER__)
#define statically_true(x) (__builtin_constant_p(x) && (x))
#define is_signed_type(t) (((t)(-1)) < (t)1)
#define compiletime_assert(condition, message) _Static_assert(condition, message)
#define BIT(n) (1UL << (n))
#define BITS_PER_LONG (__SIZEOF_LONG__ * 8)
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define _LINUX_BITOPS_H
#define smp_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#include "list_types.inc"
#include "poison.inc"
#include "list.inc"
#include "generic-non-atomic.inc"
#define __set_bit generic___set_bit
#define __clear_bit generic___clear_bit
#define test_bit generic_test_bit
/* Real release RMW for the actual word size; no fabricated lock service. */
#define clear_bit_unlock(n, p) ((void)__atomic_fetch_and((p), ~BIT(n), __ATOMIC_RELEASE))
#undef static_assert
#include "build_bug.inc"
#include "auto-compat.inc"
#include "minmax.inc"
#include "div64.inc"
#include "power2.inc"
#include "limits.inc"
#include "interval_tree_generic.inc"
#include "drm_mm.inc"
#define ENOSPC 28
struct drm_printer;
void drm_printf(struct drm_printer *, const char *, ...);
int stela_test_mm_warn(const char *, ...);
#define WARN(condition, ...) ((condition) ? stela_test_mm_warn(__VA_ARGS__) : 0)
#include "export.inc"
