// SPDX-License-Identifier: MIT
/* Original UID/exec-state paths on an actually attached hosted Runtime task.
 * The CPU/physical provider is a test model; no native current is installed. */
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/sched/exec_state.h>
#include <linux/sched/user.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <stela/allocation.h>
#include <stela/linux.h>
#include <stela/test.h>

struct resource_control {
    void *context;
    void (*exhaust)(void *context, bool enabled);
    size_t heap_bytes;
};
void stela_linux_resource_fixture(void *context);

void stela_linux_resource_fixture(void *context)
{
    const struct resource_control *control = context;
    stela_linux_enter(&stela_linux_bare);
    struct task_struct *parent = current;
    assert(parent->exec_state == NULL);
    assert(init_task_exec_state.user_ns == &init_user_ns);
    assert(refcount_read(&init_task_exec_state.count) == 2);
    assert(init_task_exec_state.dumpable == TASK_DUMPABLE_OWNER);
    assert(init_user_ns.uid_map.nr_extents == 1);
    assert(init_user_ns.uid_map.extent[0].count == 4294967295U);
    assert(init_user_ns.gid_map.extent[0].count == 4294967295U);
    assert(init_user_ns.projid_map.extent[0].count == 4294967295U);

    struct user_struct *root = alloc_uid(GLOBAL_ROOT_UID);
    assert(root == &root_user && refcount_read(&root->__count) == 2);
    free_uid(root);
    assert(refcount_read(&root_user.__count) == 1);
    if (IS_ENABLED(CONFIG_MULTIUSER)) {
        kuid_t uid = KUIDT_INIT(1000);
        control->exhaust(control->context, true);
        assert(!alloc_uid(uid));
        control->exhaust(control->context, false);
        struct user_struct *user = alloc_uid(uid);
        assert(user && refcount_read(&user->__count) == 1);
        assert(find_user(uid) == user && refcount_read(&user->__count) == 2);
        assert(alloc_uid(uid) == user && refcount_read(&user->__count) == 3);
        free_uid(user);
        free_uid(user);
        assert(refcount_read(&user->__count) == 1);
        unsigned long user_address = (unsigned long)user;
        free_uid(user);
        struct stela_linux_allocation allocation;
        assert(!stela_linux_allocation_range((void *)user_address, sizeof(*user), &allocation));
        assert(!find_user(uid));
        free_uid(NULL);
    } else {
        /* Original !MULTIUSER uidgid.h deliberately collapses every ID to0. */
        struct user_struct *alias = alloc_uid(KUIDT_INIT(1000));
        assert(alias == &root_user && refcount_read(&alias->__count) == 2);
        assert(find_user(KUIDT_INIT(1000)) == &root_user);
        free_uid(alias);
        free_uid(alias);
        assert(refcount_read(&root_user.__count) == 1);
    }
    struct stela_linux_allocation allocation;
    spinlock_t lock;
    spin_lock_init(&lock);
    refcount_t reference = REFCOUNT_INIT(2);
    unsigned long flags = ~0UL;
    assert(!refcount_dec_and_lock_irqsave(&reference, &lock, &flags));
    assert(refcount_read(&reference) == 1 && !irqs_disabled());
    assert(refcount_dec_and_lock_irqsave(&reference, &lock, &flags));
    assert(!refcount_read(&reference) && irqs_disabled());
    spin_unlock_irqrestore(&lock, flags);
    assert(!irqs_disabled());
    struct mutex mutex;
    mutex_init(&mutex);
    refcount_set(&reference, 2);
    assert(!refcount_dec_and_mutex_lock(&reference, &mutex));
    assert(refcount_read(&reference) == 1);
    assert(refcount_dec_and_mutex_lock(&reference, &mutex));
    assert(!refcount_read(&reference));
    mutex_unlock(&mutex);

    control->exhaust(control->context, true);
    assert(!alloc_task_exec_state(&init_user_ns));
    control->exhaust(control->context, false);
    struct task_exec_state *source = alloc_task_exec_state(&init_user_ns);
    assert(source && refcount_read(&source->count) == 1);
    assert(source->dumpable == TASK_DUMPABLE_OFF && source->user_ns == &init_user_ns);
    refcount_inc(&source->count);
    put_task_exec_state(source);
    assert(refcount_read(&source->count) == 1);

    /* This destination is unpublished metadata, never current or a child. The
     * original copy helper writes only its owned exec_state field. */
    struct task_struct *destination = kzalloc(sizeof(*destination), GFP_KERNEL);
    assert(destination);
    size_t capacity = control->heap_bytes / sizeof(struct task_exec_state) + 1;
    struct task_exec_state **held = kcalloc(capacity, sizeof(*held), GFP_KERNEL);
    assert(held);
    size_t count = 0;
    for (; count < capacity; count++) {
        held[count] = alloc_task_exec_state(&init_user_ns);
        if (!held[count])
            break;
    }
    assert(count && count < capacity);
    parent->exec_state = source;
    task_exec_state_set_dumpable(TASK_DUMPABLE_OWNER);
    assert(source->dumpable == TASK_DUMPABLE_OWNER);
    assert(task_exec_state_copy(destination) == -ENOMEM);
    assert(!destination->exec_state && refcount_read(&source->count) == 1);
    for (size_t i = 0; i < count; i++)
        put_task_exec_state(held[i]);
    stela_linux_rcu_finish();
    assert(task_exec_state_copy(destination) == 0);
    assert(destination->exec_state && destination->exec_state != source);
    assert(destination->exec_state->user_ns == &init_user_ns);
    assert(task_exec_state_get_dumpable(destination) == TASK_DUMPABLE_OWNER);
    task_exec_state_set_dumpable(TASK_DUMPABLE_ROOT);
    assert(source->dumpable == TASK_DUMPABLE_ROOT);
    assert(destination->exec_state->dumpable == TASK_DUMPABLE_OWNER);
    parent->exec_state = &init_task_exec_state;
    task_exec_state_set_dumpable(TASK_DUMPABLE_OFF);
    assert(init_task_exec_state.dumpable == TASK_DUMPABLE_OWNER);
    parent->exec_state = NULL;

    struct task_exec_state *copied = destination->exec_state;
    destination->exec_state = NULL;
    kfree(destination);
    kfree(held);
    put_task_exec_state(copied);
    rcu_read_lock();
    put_task_exec_state(source);
    assert(stela_linux_allocation_range(source, sizeof(*source), &allocation));
    assert(!refcount_read(&source->count));
    rcu_read_unlock();
    unsigned long source_address = (unsigned long)source;
    stela_linux_rcu_finish();
    assert(!stela_linux_allocation_range((void *)source_address, sizeof(*source), &allocation));
    assert(refcount_read(&init_task_exec_state.count) == 2);
    assert(parent->exec_state == NULL);
    stela_linux_exit();
}
