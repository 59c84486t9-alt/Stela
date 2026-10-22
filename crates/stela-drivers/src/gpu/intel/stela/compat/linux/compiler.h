/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_COMPILER_H
#define STELA_LINUX_COMPILER_H
#include <linux/compiler_types.h>
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define __must_be_array(a) \
	((int)sizeof(struct { _Static_assert(!__same_type((a), &(a)[0]), "must be an array"); }))
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#endif
