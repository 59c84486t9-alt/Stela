/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_KREF_H
#define STELA_LINUX_KREF_H
/* Reference counts named by driver structures. A source that takes or drops
 * one declares the operation it uses as an adapter service.
 */
struct kref {
	unsigned int refcount;
};
#endif
