/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_RCUPDATE_H
#define STELA_LINUX_RCUPDATE_H
/* Without lockdep, Linux's protected dereference is the plain pointer: the
 * caller's condition proves no concurrent update.
 */
#define rcu_dereference_protected(p, c) (p)
#endif
