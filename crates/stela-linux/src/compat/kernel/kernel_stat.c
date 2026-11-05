// SPDX-License-Identifier: GPL-2.0-only
/* Softirq statistics storage from Linux kernel/sched/core.c at
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
 * Copyright (C) 1991-2002 Linus Torvalds
 * Copyright (C) 1998-2024 Ingo Molnar, Red Hat
 */
#include <linux/kernel_stat.h>

DEFINE_PER_CPU(struct kernel_stat, kstat);
EXPORT_PER_CPU_SYMBOL(kstat);
