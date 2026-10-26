// SPDX-License-Identifier: GPL-2.0
/* The complete mechanically separated original nonbatched helpers. Only the
 * public entry is namespaced so its native broker can preflight real owners. */
#define kvfree_call_rcu stela_original_kvfree_call_rcu
#include "kvfree_rcu.c"
#undef kvfree_call_rcu
