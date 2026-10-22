/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_ATOMIC_H
#define _ASM_STELA_ATOMIC_H
/* The operations arch/x86/include/asm/atomic.h and atomic64_64.h provide, as
 * the compiler's atomics. The value-returning ones are fully ordered and the
 * others relaxed, as Linux requires; linux/atomic.h derives the rest. */
#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/cmpxchg.h>

#define ATOMIC64_INIT(i)	{ (i) }

#define STELA_ATOMIC_OPS(prefix, type, int_type)				\
static __always_inline int_type prefix##_read(const type *v)		\
{									\
	return __atomic_load_n(&v->counter, __ATOMIC_RELAXED);		\
}									\
static __always_inline void prefix##_set(type *v, int_type i)		\
{									\
	__atomic_store_n(&v->counter, i, __ATOMIC_RELAXED);		\
}									\
static __always_inline int_type prefix##_xchg(type *v, int_type i)	\
{									\
	return arch_xchg(&v->counter, i);				\
}									\
static __always_inline int_type prefix##_cmpxchg(type *v, int_type old,	\
						  int_type new)		\
{									\
	return arch_cmpxchg(&v->counter, old, new);			\
}									\
static __always_inline bool prefix##_try_cmpxchg(type *v, int_type *old,	\
						  int_type new)		\
{									\
	return arch_try_cmpxchg(&v->counter, old, new);			\
}									\
STELA_ATOMIC_OP(prefix, type, int_type, add)				\
STELA_ATOMIC_OP(prefix, type, int_type, sub)				\
STELA_ATOMIC_OP(prefix, type, int_type, and)				\
STELA_ATOMIC_OP(prefix, type, int_type, or)				\
STELA_ATOMIC_OP(prefix, type, int_type, xor)				\
static __always_inline int_type prefix##_add_return(int_type i, type *v)	\
{									\
	return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);	\
}									\
static __always_inline int_type prefix##_sub_return(int_type i, type *v)	\
{									\
	return __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST);	\
}

#define STELA_ATOMIC_OP(prefix, type, int_type, op)				\
static __always_inline void prefix##_##op(int_type i, type *v)		\
{									\
	(void)__atomic_fetch_##op(&v->counter, i, __ATOMIC_RELAXED);	\
}									\
static __always_inline int_type prefix##_fetch_##op(int_type i, type *v)	\
{									\
	return __atomic_fetch_##op(&v->counter, i, __ATOMIC_SEQ_CST);	\
}

STELA_ATOMIC_OPS(arch_atomic, atomic_t, int)
STELA_ATOMIC_OPS(arch_atomic64, atomic64_t, s64)

#undef STELA_ATOMIC_OP
#undef STELA_ATOMIC_OPS

#define arch_atomic_read arch_atomic_read
#define arch_atomic_set arch_atomic_set
#define arch_atomic_xchg arch_atomic_xchg
#define arch_atomic_cmpxchg arch_atomic_cmpxchg
#define arch_atomic_try_cmpxchg arch_atomic_try_cmpxchg
#define arch_atomic_add arch_atomic_add
#define arch_atomic_sub arch_atomic_sub
#define arch_atomic_and arch_atomic_and
#define arch_atomic_or arch_atomic_or
#define arch_atomic_xor arch_atomic_xor
#define arch_atomic_fetch_add arch_atomic_fetch_add
#define arch_atomic_fetch_sub arch_atomic_fetch_sub
#define arch_atomic_fetch_and arch_atomic_fetch_and
#define arch_atomic_fetch_or arch_atomic_fetch_or
#define arch_atomic_fetch_xor arch_atomic_fetch_xor
#define arch_atomic_add_return arch_atomic_add_return
#define arch_atomic_sub_return arch_atomic_sub_return

#define arch_atomic64_read arch_atomic64_read
#define arch_atomic64_set arch_atomic64_set
#define arch_atomic64_xchg arch_atomic64_xchg
#define arch_atomic64_cmpxchg arch_atomic64_cmpxchg
#define arch_atomic64_try_cmpxchg arch_atomic64_try_cmpxchg
#define arch_atomic64_add arch_atomic64_add
#define arch_atomic64_sub arch_atomic64_sub
#define arch_atomic64_and arch_atomic64_and
#define arch_atomic64_or arch_atomic64_or
#define arch_atomic64_xor arch_atomic64_xor
#define arch_atomic64_fetch_add arch_atomic64_fetch_add
#define arch_atomic64_fetch_sub arch_atomic64_fetch_sub
#define arch_atomic64_fetch_and arch_atomic64_fetch_and
#define arch_atomic64_fetch_or arch_atomic64_fetch_or
#define arch_atomic64_fetch_xor arch_atomic64_fetch_xor
#define arch_atomic64_add_return arch_atomic64_add_return
#define arch_atomic64_sub_return arch_atomic64_sub_return
#endif
