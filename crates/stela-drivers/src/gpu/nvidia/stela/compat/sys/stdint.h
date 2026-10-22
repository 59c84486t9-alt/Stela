/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_SYS_STDINT_H
#define STELA_NVIDIA_SYS_STDINT_H
/* NVIDIA's FreeBSD interface layer reads the kernel's stdint, and the
 * __aligned spelling FreeBSD's sys/cdefs.h supplies with it, through here. */
#include <stdint.h>
#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#endif
