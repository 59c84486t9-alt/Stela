/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STELA_CMPXCHG_H
#define _ASM_STELA_CMPXCHG_H
/* The exchanges arch/x86/include/asm/cmpxchg.h provides, as the compiler's
 * sequentially consistent atomics: fully ordered, as Linux requires of
 * xchg() and cmpxchg(), on objects of 1, 2, 4 or 8 bytes. */
#define arch_xchg(ptr, value) \
	__atomic_exchange_n((ptr), (value), __ATOMIC_SEQ_CST)

#define arch_cmpxchg(ptr, old, new) ({					\
	__typeof__(*(ptr)) __stela_old = (old);				\
	__atomic_compare_exchange_n((ptr), &__stela_old, (new), false,	\
				    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);	\
	__stela_old;							\
})

#define arch_try_cmpxchg(ptr, oldp, new)				\
	__atomic_compare_exchange_n((ptr), (oldp), (new), false,	\
				    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)

#define arch_cmpxchg64 arch_cmpxchg
#define arch_cmpxchg_local arch_cmpxchg
#define arch_cmpxchg64_local arch_cmpxchg
#define arch_try_cmpxchg64 arch_try_cmpxchg
#define arch_try_cmpxchg_local arch_try_cmpxchg
#define arch_try_cmpxchg64_local arch_try_cmpxchg
#endif
