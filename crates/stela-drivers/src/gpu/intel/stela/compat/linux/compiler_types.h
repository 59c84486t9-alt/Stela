/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_COMPILER_TYPES_H
#define STELA_LINUX_COMPILER_TYPES_H
/* Kbuild force-includes this header into every translation unit. */
#include <linux/compiler_attributes.h>
/* Sparse annotations and context analysis, empty outside those checks. */
#define __iomem
#define __user
#define __force
#define __kernel
#define __no_context_analysis
#endif
