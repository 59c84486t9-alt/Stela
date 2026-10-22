/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_MATH_H
#define STELA_LINUX_MATH_H
/* Linux's power-of-two rounding helpers, with the same types. */
#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif
