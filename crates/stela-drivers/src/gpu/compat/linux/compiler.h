/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_COMPILER_H
#define STELA_LINUX_COMPILER_H
#include <linux/compiler_types.h>
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define __must_be_array(a) \
	((int)sizeof(struct { _Static_assert(!__same_type((a), &(a)[0]), "must be an array"); }))
/* Copyright Linux kernel contributors; from asm-generic/rwonce.h, which
 * compiler.h includes, without its KASAN/KCSAN checks. */
#define __READ_ONCE(x)	(*(const volatile typeof(x) *)&(x))
#define READ_ONCE(x)	__READ_ONCE(x)
#define __WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)
#define WRITE_ONCE(x, val)	__WRITE_ONCE(x, val)
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#endif
