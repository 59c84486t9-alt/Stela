// SPDX-License-Identifier: MIT
/* Sanitized original-resource leaf lifecycle and fixed-header admission. */
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>
#include <linux/sched/exec_state.h>
#include <linux/sched/user.h>
#include <linux/string.h>
#include <linux/user_namespace.h>
#include <stela/allocation.h>
#include <stela/linux.h>
#include <stela/page.h>
#include <stela/resources.h>
#include <stela/test.h>
#define PAGES 16U
#define BYTES ((size_t)PAGES * PAGE_SIZE)
#define PHYSICAL 0x400000000ULL
struct pin { bool live; size_t first, count; u64 physical[PAGES]; };
static struct { u8 *cpu; bool used[PAGES]; struct pin pins[PAGES]; bool exhausted; size_t allocations; } memory;
static int validate(void *context, u32 gfp, unsigned int order, bool atomic)
{
    assert(context == &memory);
    if (atomic || order > 4 || !stela_linux_page_request_basic(gfp))
        return -EOPNOTSUPP;
    return 0;
}
static int allocate(void *context, u32 gfp, unsigned int order, bool atomic,
                    struct stela_linux_page_allocation *output)
{
    int error = validate(context, gfp, order, atomic);
    if (error)
        return error;
    if (memory.exhausted)
        return -ENOMEM;
    size_t count = (size_t)1 << order;
    size_t first = PAGES;
    for (size_t i = 0; i + count <= PAGES; i += count) {
        bool free_range = true;
        for (size_t j = 0; j < count; j++)
            free_range &= !memory.used[i + j];
        if (free_range) { first = i; break; }
    }
    if (first == PAGES)
        return -ENOMEM;
    struct pin *pin = NULL;
    for (size_t i = 0; i < PAGES; i++)
        if (!memory.pins[i].live) { pin = memory.pins + i; break; }
    assert(pin);
    pin->live = true; pin->first = first; pin->count = count;
    for (size_t i = 0; i < count; i++) {
        memory.used[first + i] = true;
        pin->physical[i] = PHYSICAL + (u64)(first + i) * PAGE_SIZE;
    }
    memory.allocations++;
    *output = (struct stela_linux_page_allocation){ .pin=pin,
        .cpu_base=memory.cpu+first*PAGE_SIZE, .physical_pages=pin->physical,
        .page_count=count };
    return 0;
}
static void release(void *context, void *value)
{
    assert(context == &memory && stela_linux_quiescent());
    struct pin *pin = value;
    assert(pin->live);
    for (size_t i = 0; i < pin->count; i++) {
        assert(memory.used[pin->first+i]); memory.used[pin->first+i]=false;
    }
    pin->live=false;
}
int main(void)
{
    memory.cpu = aligned_alloc(BYTES, BYTES);
    assert(memory.cpu);
    stela_linux_enter(&stela_linux_bare);
    const struct stela_linux_page_ops ops={.validate=validate,.allocate=allocate,.release=release};
    struct stela_linux_page_reservation reservation={.generation=1,.physical_base=PHYSICAL,.cpu_base=memory.cpu,.page_count=PAGES};
    assert(!stela_linux_page_catalog_register(&reservation,&ops,&memory));
    u32 short_header[2]={STELA_LINUX_RESOURCES_V1,8};
    assert(stela_linux_resources_initialize((const void *)short_header)==-EINVAL);
    const struct stela_linux_resource_request wrong={.version=1,.bytes=sizeof(wrong),.page_generation=2};
    assert(stela_linux_resources_initialize(&wrong)==-EINVAL);
    assert(!stela_linux_page_catalog_unregister(1));
    reservation.generation=2;
    assert(!stela_linux_page_catalog_register(&reservation,&ops,&memory));
    const struct stela_linux_resource_request request={.version=1,.bytes=sizeof(request),.page_generation=2};
    assert(!stela_linux_resources_initialize(&request));
    assert(!memory.allocations);
    assert(stela_linux_page_catalog_unregister(2)==-EBUSY);
    assert(stela_linux_resources_initialize(&request)==-EBUSY);
    struct user_struct *root=alloc_uid(GLOBAL_ROOT_UID);
    assert(root==&root_user && refcount_read(&root->__count)==2);
    free_uid(root);
    assert(refcount_read(&root_user.__count)==1);
    memory.exhausted=true;
    assert(!alloc_task_exec_state(&init_user_ns));
    memory.exhausted=false;
    struct task_exec_state *value=alloc_task_exec_state(&init_user_ns);
    assert(value && value->user_ns==&init_user_ns && value->dumpable==TASK_DUMPABLE_OFF);
    refcount_inc(&value->count); put_task_exec_state(value);
    assert(refcount_read(&value->count)==1);
    unsigned long address=(unsigned long)value;
    rcu_read_lock(); put_task_exec_state(value);
    struct stela_linux_allocation allocation;
    assert(stela_linux_allocation_range(value,sizeof(*value),&allocation));
    rcu_read_unlock(); stela_linux_rcu_finish();
    assert(!stela_linux_allocation_range((void *)address,sizeof(*value),&allocation));
    assert(refcount_read(&init_task_exec_state.count)==2);
    assert(stela_linux_page_catalog_unregister(2)==-EBUSY);
    stela_linux_exit();
    /* The one kernel retains its initial caches/catalog/backing until process
     * termination. Per-object refs and RCU cleanup above still ran normally. */
    printf("Linux resources: original allocation/ref/RCU, fixed headers and kernel retention passed\n");
    return 0;
}
