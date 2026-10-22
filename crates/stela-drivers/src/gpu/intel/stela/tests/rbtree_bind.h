/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Test-only primitive bindings; no concurrent/RCU execution is admitted. */
#ifndef STELA_RBTREE_TEST_BIND_H
#define STELA_RBTREE_TEST_BIND_H
#ifndef bool
#define bool _Bool
#define true 1
#define false 0
#endif
#ifndef NULL
#define NULL ((void *)0)
#endif
#ifndef offsetof
#define offsetof(t, m) __builtin_offsetof(t, m)
#endif
#ifndef static_assert
#define static_assert _Static_assert
#endif
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define unlikely(x) __builtin_expect(!!(x), 0)
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile typeof(x) *)&(x) = (v))
/* Refuse RCU calls: single-owner tests supply no grace-period service. */
#define rcu_assign_pointer(p, v) do { (void)sizeof(p); (void)sizeof(v); __builtin_trap(); } while (0)
#define rcu_dereference_raw(p) ({ __builtin_trap(); (typeof(p))0; })
#include "rbtree_types.inc"
#include "container_of.inc"
#include "rbtree.inc"
#include "rbtree_augmented.inc"
#endif
