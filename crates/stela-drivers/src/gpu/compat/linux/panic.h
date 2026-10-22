/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_PANIC_H
#define STELA_LINUX_PANIC_H
/* Copyright Linux kernel contributors; from panic.h. */
#define TAINT_CPU_OUT_OF_SPEC		2

enum lockdep_ok {
	LOCKDEP_STILL_OK,
	LOCKDEP_NOW_UNRELIABLE,
};

/* Stela keeps no taint flags; a source that sets one declares it. */
static void add_taint(unsigned flag, enum lockdep_ok);
#endif
