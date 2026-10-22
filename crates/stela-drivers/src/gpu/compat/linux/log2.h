/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_LOG2_H
#define STELA_LINUX_LOG2_H
#define ilog2(n) (63 - __builtin_clzll((unsigned long long)(n)))
#define const_ilog2(n) ilog2(n)
#define is_power_of_2(n) ((n) != 0 && (((n) & ((n) - 1)) == 0))
#endif
