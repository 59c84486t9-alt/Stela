/* SPDX-License-Identifier: MIT */
/* Host-only immutable-image classifier for hosted C tests that bind no image;
 * compile outside the Linux header environment, beside stela/test.c. A test
 * defining its own fixture classifier takes precedence over this archive
 * member. Never part of a native image, where Rust's registered consumer
 * answers. */
#include <stdbool.h>

/* No hosted test address belongs to a registered immutable image, so Linux's
 * const-string helpers copy and free every string they are given. */
bool stela_linux_is_rodata(const void *address)
{
	(void)address;
	return false;
}
