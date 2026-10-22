/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_MM_H
#define STELA_LINUX_MM_H
#include <asm/page.h>
#define offset_in_page(p) ((unsigned long)(p) & ~PAGE_MASK)
#endif
