/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_COMPILER_TYPES_H
#define STELA_LINUX_COMPILER_TYPES_H
/* Kbuild force-includes this header into every translation unit. */
#define __packed __attribute__((packed))
#define __iomem
#define __always_inline inline __attribute__((always_inline))
#define __maybe_unused __attribute__((unused))
#define __must_check __attribute__((warn_unused_result))
#define fallthrough __attribute__((fallthrough))
#endif
