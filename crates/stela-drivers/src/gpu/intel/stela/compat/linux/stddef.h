/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_STDDEF_H
#define STELA_LINUX_STDDEF_H
/* Linux's version declares false and true itself; Stela uses <stdbool.h>. */
#include <stddef.h>
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#endif
