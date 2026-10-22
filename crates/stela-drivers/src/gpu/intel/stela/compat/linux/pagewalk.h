/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_PAGEWALK_H
#define STELA_LINUX_PAGEWALK_H
/* Linux's pagewalk.h reaches these helpers through linux/mm.h. */
#include <linux/compiler.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <vdso/align.h>
/* The values of Linux's enum page_walk_action. */
enum page_walk_action {
	ACTION_SUBTREE = 0,
	ACTION_CONTINUE = 1,
	ACTION_AGAIN = 2,
};
#endif
