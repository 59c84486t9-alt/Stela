// SPDX-License-Identifier: GPL-2.0-only
/* Selected original kernel-thread resource roots, ordered from init/main.c.
 * The native machine owns CPU/root/heap/pages/clock/IRQs, not start_kernel or
 * a second Linux scheduler. Every resource operation below is original code.
 * No callback-presence/flag-only producer or successful missing-resource shim.
 */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/irqflags.h>
#include <linux/interrupt.h>
#include <linux/radix-tree.h>
#include <linux/sched/isolation.h>
#include <linux/rcupdate.h>
#include <linux/srcu.h>
#include <linux/workqueue.h>
#include <linux/pid_namespace.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/wait_api.h>
#include <uapi/linux/wait.h>
#include <linux/gfp.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/numa.h>
#include <linux/cred.h>
#include <linux/cpuset.h>
#include <linux/sched/task.h>
#include <linux/utsname.h>
#include <linux/time_namespace.h>
#include <linux/key.h>
#include <linux/security.h>
#include <net/net_namespace.h>
#include <linux/fs.h>
#include <linux/writeback.h>
#include <linux/signal.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/pidfs.h>
#include <stela/file.h>
#include <stela/linux.h>
#include <stela/srcu.h>
#include <stela/task.h>
#include <stela/task_bootstrap.h>
#include <internal.h>

/* Original init/main.c globals have one native bootstrap owner. The original
 * machine start_kernel/main.o must NOT also be activated with this adapter. */
bool early_boot_irqs_disabled __read_mostly;
enum system_states system_state __read_mostly = SYSTEM_BOOTING;

/* The selected machine does not link init/main.c or calibrate a second clock. */
unsigned long loops_per_jiffy __read_mostly;

enum resource_phase { COLD, INITIALIZING, COMPLETE, FAILED };
static enum resource_phase resource_phase;
static const struct stela_linux_owner *resource_owner;

bool stela_linux_task_resource_roots_complete(const struct stela_linux_owner *owner)
{
    return resource_phase == COMPLETE && resource_owner == owner;
}

int stela_linux_task_bootstrap_resources(const struct stela_linux_owner *owner)
{
    int error = stela_linux_require_current(owner);
    if (error)
        return error;
    if (current != &init_task || !stela_linux_quiescent())
        return -EPERM;
    if (resource_phase != COLD)
        return -EALREADY;
    if (!owner->services->calibrated_tsc_hz)
        return -ENODEV;
    u64 tsc_hz = owner->services->calibrated_tsc_hz(owner->context);
    if (tsc_hz < HZ)
        return -ENODEV;

    /* Commit retaining attempt BEFORE any one-shot external/source effect.
     * A failed bind/unknown unwind never authorizes root reinitialization. */
    resource_owner = owner;
    resource_phase = INITIALIZING;
    error = stela_linux_srcu_bind_initial(owner);
    if (error) {
        resource_phase = FAILED;
        return error;
    }

    /* Match x86 get_loops_per_jiffy() using the retained calibrated rate.
     * The workqueue threshold uses this before any worker starts. */
    loops_per_jiffy = tsc_hz / HZ;

    /* Original early phase: queue metadata/boot-list may exist before any
     * original child can execute. This initializes no second native timer or
     * scheduler. The caller's actual native providers own those boundaries. */
    unsigned long flags;
    local_irq_save(flags);
    early_boot_irqs_disabled = true;
    boot_cpu_init();
    radix_tree_init();
    housekeeping_init();
    workqueue_init_early();
    softirq_init();
    rcu_init();
    kvfree_rcu_init();
    srcu_init();
    early_boot_irqs_disabled = false;
    local_irq_restore(flags);

    /* Original source sequence (init/main.c1150..), for genuine kernel-thread
     * resources. User-mm/anon-vma/exec and architecture stack caches are not
     * substituted: the native clone boundary rejects those consumers before
     * effects, and one actual native prepared-stack owner supplies stacks. */
    pid_idr_init();
    cred_init();
    fork_init();
    proc_caches_init();
    uts_ns_init();
    time_ns_init();
    key_init();
    security_init();
    net_ns_init();
    /* Native hash allocation needs the quiescent, IRQ-enabled owner. */
    vfs_caches_init_early();
    stela_linux_file_cache_init();
    vfs_caches_init();
    pagecache_init();
    signals_init();
    seq_file_init();
    proc_root_init();
    nsfs_init();
    pidfs_init();
    /* Run the original built-in initcall before publishing root readiness. */
    error = workingset_init();
    if (error) {
        resource_phase = FAILED;
        return error;
    }

    /* This means ONLY these actual helpers returned on the retained Initial.
     * PID1/kthreadd, scheduler start, full original WQ/rescuers, SRCU probes and
     * exact native callback/physical successor joins remain separate. */
    resource_phase = COMPLETE;
    return 0;
}

/* The actual source equivalents of rest_init's two children. These are not
 * synthetic task structs: kernel_thread reaches original kernel_clone and
 * copy_process, the one native frame factory, genuine source PID/task lists,
 * then the exact pre-reserved native Dormant activation. No user init/exec,
 * CPU idle loop or second original scheduler is substituted here. */
static DECLARE_COMPLETION(kthreadd_published);
static DECLARE_COMPLETION(kthreadd_entered);
enum thread_phase { THREADS_COLD, THREADS_STARTING, THREADS_PUBLISHED, THREADS_FAILED };
static enum thread_phase thread_phase;
static struct task_struct *native_supervisor;
static DECLARE_WAIT_QUEUE_HEAD(supervisor_requests);

int stela_linux_task_source_broker_wake(const struct stela_linux_owner *owner)
{
    int error = stela_linux_require_current(owner);
    if (error)
        return error;
    if (!stela_linux_quiescent() || resource_owner != owner ||
        thread_phase != THREADS_PUBLISHED)
        return -EBUSY;
    wake_up(&supervisor_requests);
    return 0;
}

void __noreturn stela_linux_task_native_supervisor(const struct stela_linux_owner *owner)
{
    if (stela_linux_require_current(owner) || current != native_supervisor ||
        current != init_pid_ns.child_reaper || !stela_linux_quiescent())
        __builtin_trap();
    for (;;) {
        /* Genuine original waitqueue owns sleep/wake publication. Actual
         * native events are delivered by retained canonical process service;
         * callback presence or a periodic timer never implies a request. */
        wait_event(supervisor_requests, stela_linux_task_native_pending(owner));
        int result = stela_linux_task_native_process_one(owner);
        if (result < 0)
            __builtin_trap(); /* adapter retains actual partial graph */
        /* PID1 is the genuine original namespace child reaper. Source
         * release_task/RCU ownership stays in the original wait implementation,
         * independently of the native physical-return/ref reaper above. All
         * native-admitted deaths produce a real terminal event; this is not a
         * timer poll. NULL stat/rusage never dereferences a userspace pointer. */
        long pid;
        do {
            pid = kernel_wait4(-1, NULL, WNOHANG | __WALL, NULL);
        } while (pid > 0);
        if (pid < 0 && pid != -ECHILD && pid != -ERESTARTSYS)
            __builtin_trap();
        if (result)
            cond_resched();
    }
}


static int native_kernel_supervisor(void *argument)
{
    const struct stela_linux_owner *owner = argument;
    if (stela_linux_require_current(owner) || task_pid_nr(current) != 1 ||
        current != init_pid_ns.child_reaper)
        __builtin_trap();
    /* Genuine completion waits drop all transient native process permits;
     * only the actual source task and retained callback/request owners remain.
     * Kthreadd must have reached its real original create-info loop first. */
    wait_for_completion(&kthreadd_published);
    wait_for_completion(&kthreadd_entered);
    if (current != native_supervisor)
        __builtin_trap();
    gfp_allowed_mask = __GFP_BITS_MASK;
    set_mems_allowed(node_states[N_MEMORY]);
    rcu_assign_pointer(cad_pid, get_pid(task_pid(current)));

    /* Original source allocates real pools, early MEM_RECLAIM rescuers and
     * worker tasks. Its genuine failures remain BUG/ENOMEM/source behavior;
     * this call returning is NOT a callback/native-join FullReady receipt. */
    workqueue_init();
    init_mm_internals();
    workqueue_init_topology();

    /* REQUIRED actual retained native request/reaper service on THIS real
     * source process. It owns original fork/kthread request execution and
     * terminal source cleanup; no callback-presence or flag-only success. */
    stela_linux_task_native_supervisor(owner);
    __builtin_trap();
}

void stela_linux_task_kthreadd_started(void)
{
    const struct stela_linux_owner *owner = stela_linux_owner();
    if (stela_linux_require_current(owner) || task_pid_nr(current) != 2 ||
        !stela_linux_task_resource_roots_complete(owner))
        __builtin_trap();
    wait_for_completion(&kthreadd_published);
    if (current != kthreadd_task || thread_phase != THREADS_PUBLISHED)
        __builtin_trap();
    /* Called from genuine original kthreadd after its source context setup,
     * immediately before the original create-info service loop. */
    complete(&kthreadd_entered);
}

int stela_linux_task_bootstrap_threads(const struct stela_linux_owner *owner)
{
    int error = stela_linux_require_current(owner);
    if (error)
        return error;
    if (current != &init_task || !stela_linux_quiescent() ||
        !stela_linux_task_resource_roots_complete(owner))
        return -EPERM;
    if (thread_phase != THREADS_COLD)
        return -EALREADY;
    thread_phase = THREADS_STARTING;
    /* Original rest_init ordering: end the single-original-task inactive RCU
     * phase BEFORE a second child may run. This is no public SRCU readiness. */
    rcu_scheduler_starting();
    /* All selected kernel clients share the original initial fdtable. */
    int pid = kernel_thread(native_kernel_supervisor, (void *)owner,
        "stela-init", CLONE_FS | CLONE_FILES);
    if (pid < 0) {
        thread_phase = THREADS_FAILED;
        return pid; /* actual original constructor unwind/cancel must join */
    }
    if (pid != 1)
        __builtin_trap();
    rcu_read_lock();
    native_supervisor = find_task_by_pid_ns(pid, &init_pid_ns);
    if (!native_supervisor)
        __builtin_trap();
    /* A real original reference retains the borrowed source process identity;
     * permanent mount lifetime is not inferred from its numerical PID. */
    get_task_struct(native_supervisor);
    native_supervisor->flags |= PF_NO_SETAFFINITY;
    rcu_read_unlock();

    pid = kernel_thread(kthreadd, NULL, "kthreadd", CLONE_FS | CLONE_FILES);
    if (pid < 0) {
        thread_phase = THREADS_FAILED;
        return pid; /* retain actual PID1 awaiting its original completion */
    }
    if (pid != 2)
        __builtin_trap();
    rcu_read_lock();
    kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
    if (!kthreadd_task)
        __builtin_trap();
    get_task_struct(kthreadd_task);
    rcu_read_unlock();
    system_state = SYSTEM_SCHEDULING;
    thread_phase = THREADS_PUBLISHED;
    complete_all(&kthreadd_published);
    /* Only actual source child/PID publication completed. Execution of the
     * original kthreadd body, WQ progress/probes, native return tails and full
     * required root joins are NOT implied by this synchronous return. */
    return 0;
}
