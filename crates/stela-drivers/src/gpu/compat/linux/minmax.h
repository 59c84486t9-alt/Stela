/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_MINMAX_H
#define STELA_LINUX_MINMAX_H
/* Single-evaluation min and max; Linux's versions also reject mixed signs. */
#define min(x, y) ({ __auto_type _x = (x); __auto_type _y = (y); _x < _y ? _x : _y; })
#define max(x, y) ({ __auto_type _x = (x); __auto_type _y = (y); _x > _y ? _x : _y; })
#define min_t(type, x, y) ({ type _x = (type)(x); type _y = (type)(y); _x < _y ? _x : _y; })
#define max_t(type, x, y) ({ type _x = (type)(x); type _y = (type)(y); _x > _y ? _x : _y; })
#endif
