/* SPDX-License-Identifier: MIT */
#ifndef STELA_RESOURCES_H
#define STELA_RESOURCES_H
#include <linux/types.h>
#define STELA_LINUX_RESOURCES_V1 1U
struct stela_linux_resource_request {
    u32 version;
    u32 bytes;
    u64 page_generation;
};
/* One kernel lifetime, on its actual exclusive native owner. Requires an
 * entered quiescent C lease and the retained canonical catalog. This initializes
 * the original UID/exec-state caches only, never a current or task resource graph.
 * A started initialization retains its catalog even on fatal/partial failure;
 * another instance cannot reset these globals. No teardown is provided until
 * complete original kernel-resource and producer shutdown exists. */
int stela_linux_resources_initialize(const struct stela_linux_resource_request *request);
#endif
