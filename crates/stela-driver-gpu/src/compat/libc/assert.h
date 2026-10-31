/* SPDX-License-Identifier: MIT */
#include <sys/cdefs.h>
#undef assert
__BEGIN_DECLS
_Noreturn void __assert_fail(const char *condition, const char *file, unsigned int line,
			     const char *function);
__END_DECLS
#ifdef NDEBUG
#define assert(condition) ((void)0)
#else
#define assert(condition) \
	((condition) ? (void)0 : __assert_fail(#condition, __FILE__, __LINE__, __func__))
#endif
#if !defined(__cplusplus) && !defined(static_assert)
#define static_assert _Static_assert
#endif
