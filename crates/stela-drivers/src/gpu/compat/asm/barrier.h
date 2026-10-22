/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_ASM_BARRIER_H
#define STELA_ASM_BARRIER_H
/* x86-64's barriers, from arch/x86/include/asm/barrier.h without its runtime
 * alternatives: every CPU Stela runs on has SSE2's fences.
 */
#define mb() __asm__ __volatile__("mfence" ::: "memory")
#define rmb() __asm__ __volatile__("lfence" ::: "memory")
#define wmb() __asm__ __volatile__("sfence" ::: "memory")
#define smp_mb() __asm__ __volatile__("lock addl $0,-4(%%rsp)" ::: "memory", "cc")
#define smp_rmb() __asm__ __volatile__("" ::: "memory")
#define smp_wmb() __asm__ __volatile__("" ::: "memory")
/* x86-64 is TSO: acquire and release order only against the compiler. */
#define smp_store_release(p, v) \
	do { __asm__ __volatile__("" ::: "memory"); WRITE_ONCE(*(p), (v)); } while (0)
#define smp_load_acquire(p) \
	({ typeof(*(p)) ___p1 = READ_ONCE(*(p)); __asm__ __volatile__("" ::: "memory"); ___p1; })
#define smp_store_mb(var, value) \
	do { (void)__atomic_exchange_n(&(var), (value), __ATOMIC_SEQ_CST); } while (0)
#endif
