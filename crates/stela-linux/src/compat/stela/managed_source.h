/* SPDX-License-Identifier: MIT */
#ifndef STELA_MANAGED_SOURCE_H
#define STELA_MANAGED_SOURCE_H
#include <stela/managed.h>
/* Original private create_info/self lifetime hooks. Every caller already owns
 * the actual lease; source get/put do not adopt a raw task or kernel identity. */
void stela_linux_managed_source_get(struct stela_linux_managed_lease *);
void stela_linux_managed_source_put(struct stela_linux_managed_lease *);
void stela_linux_managed_source_queued(struct stela_linux_managed_lease *);
void stela_linux_managed_source_outcome(struct stela_linux_managed_lease *,
    unsigned int event, int result);
#endif
