/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_DELAY_H
#define STELA_LINUX_DELAY_H
/* Delays are services of the adapter, which owns the clock. */
static void msleep(unsigned int msecs);
static void udelay(unsigned long usecs);
#endif
