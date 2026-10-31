// SPDX-License-Identifier: MIT
/* Explicit native initialization order for original kernel resource caches. */
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/sched/exec_state.h>
#include <linux/string.h>
#include <linux/user_namespace.h>
#include <stela/linux.h>
#include <stela/page.h>
#include <stela/resources.h>

/* Stela's owners assign device resources, so nothing is requested from this
 * tree; its span is x86-64's 52 physical address bits. */
struct resource iomem_resource = {
	.name = "PCI mem",
	.end = BIT_ULL(52) - 1,
	.flags = IORESOURCE_MEM,
};

static_assert(!IS_ENABLED(CONFIG_USER_NS));
static_assert(sizeof(struct stela_linux_resource_request) == 16);
static_assert(offsetof(struct stela_linux_resource_request, page_generation) == 8);
/* Original kernel/user.c body, also retained by its normal subsys_initcall. */
int uid_cache_init(void);

enum resource_state { UNINITIALIZED, INITIALIZING, INITIALIZED, FAILED };
static enum resource_state state;

int stela_linux_resources_initialize(const struct stela_linux_resource_request *request)
{
    (void)stela_linux_owner();
    if (!stela_linux_quiescent())
        return -EBUSY;
    if (!request)
        return -EINVAL;
    u32 header[2];
    memcpy(header, request, sizeof(header));
    if (header[0] != STELA_LINUX_RESOURCES_V1 || header[1] != sizeof(*request))
        return -EINVAL;
    if (state != UNINITIALIZED)
        return -EBUSY;
    int error = stela_linux_page_catalog_retain_kernel(request->page_generation);
    if (error)
        return error;
    /* Every subsequent path retains the catalog and initial root objects.
     * Original SLAB_PANIC failures stop; they are not retryable partial init. */
    state = INITIALIZING;
    error = uid_cache_init();
    if (error) {
        state = FAILED;
        return error;
    }
    exec_state_init();
    state = INITIALIZED;
    return 0;
}
