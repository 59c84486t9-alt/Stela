/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_BUILD_BUG_H
#define STELA_LINUX_BUILD_BUG_H
#define BUILD_BUG_ON_ZERO(e, ...) \
	((int)sizeof(struct { _Static_assert(!(e), "BUILD_BUG_ON_ZERO(" #e ")"); }))
#define BUILD_BUG_ON(c) _Static_assert(!(c), "BUILD_BUG_ON(" #c ")")
#define __static_assert_1(c) _Static_assert(c, #c)
#define __static_assert_2(c, m) _Static_assert(c, m)
#define __static_assert_pick(_1, _2, name, ...) name
#undef static_assert
#define static_assert(...) \
	__static_assert_pick(__VA_ARGS__, __static_assert_2, __static_assert_1)(__VA_ARGS__)
#endif
