//! The pthread kernel support (libpthread `kern/kern_support.c`, xnu
//! `bsd/pthread/pthread_workqueue.c` `bsdthread_ctl`) for the guest's
//! threads. The host process's own libpthread already registered with the
//! host kernel, so the guest's `bsdthread_register` is serviced here with
//! the kext's semantics: the registration data is validated, clamped to
//! the pthread size, answered with the main thread's QoS, stack hint and
//! mutex policy, and the kext's feature set is returned.
//!
//! `bsdthread_create` starts a host thread with its own PE at the
//! registered thread start (`crate::hosted::threads`), and
//! `bsdthread_terminate` ends one. The workqueue's calls are
//! [`super::workqueue`]'s.
use super::{
    Call, EFAULT, EINVAL, Kernel, Outcome, Pe, forward,
    priority::{self, THREAD_QOS_BACKGROUND, THREAD_QOS_LEGACY, THREAD_QOS_MAINTENANCE},
    signal::WORKQ_THREADMASK,
};
use crate::hosted::{
    kernel::{End, status},
    memory::{self, Protection, round_page, trunc_page},
    threads::{self, Entry, lock},
};
use anyhow::{Result, bail};
use std::sync::Mutex;

/// `MAX_PTHREAD_SIZE`.
const MAX_PTHREAD_SIZE: u64 = 64 << 10;
/// `PTHREAD_FEATURE_SUPPORTED`.
const FEATURES: u64 = 0x01 // DISPATCHFUNC
    | 0x02 // FINEPRIO
    | 0x04 // BSDTHREADCTL
    | 0x08 // SETSELF
    | 0x10 // QOS_MAINTENANCE
    | 0x40 // KEVENT
    | 0x80 // WORKLOOP
    | 0x100 // COOPERATIVE_WORKQ
    | 0x4000_0000; // QOS_DEFAULT
/// `struct _pthread_registration_data` field offsets (packed).
const VERSION: u64 = 0;
const DISPATCH_QUEUE_OFFSET: u64 = 8;
const MAIN_QOS: u64 = 16;
const TSD_OFFSET: u64 = 24;
const RETURN_TO_KERNEL_OFFSET: u64 = 28;
const MACH_THREAD_SELF_OFFSET: u64 = 32;
const STACK_ADDRESS_HINT: u64 = 36;
const MUTEX_DEFAULT_POLICY: u64 = 44;
const WQ_QUANTUM_EXPIRY_OFFSET: u64 = 52;
const REGISTRATION_BYTES: u64 = 56;
const TSD_SLOT_BYTES: u64 = 8;

/// `PTHREAD_START_*` (`kern_support.c`).
const PTHREAD_START_CUSTOM: u64 = 0x0100_0000;
const PTHREAD_START_SETSCHED: u64 = 0x0200_0000;
const PTHREAD_START_QOSCLASS: u64 = 0x0800_0000;
const PTHREAD_START_TSD_BASE_SET: u64 = 0x1000_0000;
const PTHREAD_START_SUSPENDED: u64 = 0x2000_0000;
const PTHREAD_START_QOSCLASS_MASK: u64 = 0x00ff_ffff;
const PTHREAD_START_POLICY_SHIFT: u32 = 16;
const PTHREAD_START_POLICY_MASK: u64 = 0xff;
const PTHREAD_START_IMPORTANCE_MASK: u64 = 0xffff;
/// `SCHED_OTHER`, `BASEPRI_DEFAULT`.
const SCHED_OTHER: u64 = 1;
const BASEPRI_DEFAULT: i32 = 31;
/// `thread_policy_set` flavors and counts (`mach/thread_policy.h`).
const THREAD_EXTENDED_POLICY: u32 = 1;
const THREAD_PRECEDENCE_POLICY: u32 = 3;
const POLICY_COUNT: u32 = 1;
/// `BSDTHREAD_CTL_*` (`bsd/pthread/bsdthread_private.h`).
const CTL_SET_QOS: u64 = 0x10;
const CTL_QOS_OVERRIDE_START: u64 = 0x40;
const CTL_QOS_OVERRIDE_END: u64 = 0x80;
const CTL_SET_SELF: u64 = 0x100;
const CTL_QOS_OVERRIDE_RESET: u64 = 0x200;
const CTL_QOS_OVERRIDE_DISPATCH: u64 = 0x400;
const CTL_QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_ADD: u64 = 0x401;
const CTL_QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_RESET: u64 = 0x402;
const CTL_QOS_MAX_PARALLELISM: u64 = 0x800;
const CTL_WORKQ_ALLOW_KILL: u64 = 0x1000;
const CTL_DISPATCH_APPLY_ATTR: u64 = 0x2000;
const CTL_WORKQ_ALLOW_SIGMASK: u64 = 0x4000;
/// `QOS_PARALLELISM_*` (`osfmk/kern/sched_prim.h`).
const PARALLELISM_COUNT_LOGICAL: u64 = 0x1;
const PARALLELISM_REALTIME: u64 = 0x2;
const PARALLELISM_CLUSTER_SHARED_RESOURCE: u64 = 0x4;
/// `workq_set_self_flags`.
pub(super) const SET_SELF_QOS_FLAG: u64 = 0x01;
pub(super) const SET_SELF_VOUCHER_FLAG: u64 = 0x02;
pub(super) const SET_SELF_WQ_KEVENT_UNBIND: u64 = 0x10;
pub(super) const SET_SELF_QOS_OVERRIDE_FLAG: u64 = 0x40;
const ENOTSUP: u64 = 45;
const ESRCH: u64 = 3;
/// `semaphore_signal_trap`, `_kernelrpc_mach_port_deallocate_trap`.
const SEMAPHORE_SIGNAL_TRAP: &str = "semaphore_signal_trap";
const PORT_DEALLOCATE_TRAP: &str = "_kernelrpc_mach_port_deallocate_trap";
/// `MADV_FREE_REUSABLE`: the main thread's stack is kept, its pages
/// reusable (`VM_BEHAVIOR_REUSABLE`).
const MADV_FREE_REUSABLE: i32 = 7;

/// The process's pthread registration, as the kext keeps it.
#[derive(Debug, Default)]
pub(crate) struct Threads {
    registration: Mutex<Option<Registration>>,
}

impl Threads {
    /// The registration's lock, held across a host `fork`: the child keeps
    /// the registration, as `forkproc` copies it.
    pub(crate) fn hold_for_fork(&self) -> Option<std::sync::MutexGuard<'_, Option<Registration>>> {
        crate::hosted::threads::try_lock(&self.registration)
    }

    /// The registration, once `bsdthread_register` succeeded
    /// (`P_LREGISTER`).
    pub(crate) fn registration(&self) -> Option<Registration> {
        *lock(&self.registration)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Registration {
    /// `threadstart` and `wqthread`, authenticated.
    pub(crate) thread_start: u64,
    pub(crate) workqueue_thread: u64,
    pub(crate) pthread_size: u64,
    pub(crate) tsd_offset: u32,
    pub(crate) dispatch_queue_offset: u64,
    pub(crate) return_to_kernel_offset: u32,
    pub(crate) mach_thread_self_offset: u32,
    pub(crate) quantum_expiry_offset: u32,
    /// Where workqueue thread stacks are placed (`stack_addr_hint`).
    pub(crate) stack_hint: u64,
}

pub(super) const CALLS: &[&str] = &[
    "bsdthread_register",
    "bsdthread_create",
    "bsdthread_terminate",
    "bsdthread_ctl",
];

pub(super) fn call(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "bsdthread_register" => register(kernel, call)?,
        "bsdthread_create" => create(kernel, call)?,
        "bsdthread_terminate" => terminate(kernel, pe, call)?,
        "bsdthread_ctl" => control(kernel, call)?,
        _ => return Ok(None),
    }))
}

/// `_bsdthread_register(threadstart, wqthread, pthsize, data, data_size,
/// dispatchqueue_offset)`.
fn register(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [
        thread_start,
        workqueue_thread,
        pthread_size,
        data,
        data_size,
        queue_offset,
        ..,
    ] = call.arguments;
    let pthread_size = pthread_size as u32 as i32;
    if pthread_size < 0 || pthread_size as u64 > MAX_PTHREAD_SIZE {
        return Ok(Outcome::Error(EINVAL));
    }
    let pthread_size = pthread_size as u64;
    let mut registration = [0u8; REGISTRATION_BYTES as usize];
    let mut copied = 0;
    if data != 0 {
        if data_size < 8 {
            return Ok(Outcome::Error(EINVAL));
        }
        copied = data_size.min(REGISTRATION_BYTES) as usize;
        let Some(bytes) = memory::read(data, copied) else {
            return Ok(Outcome::Error(EFAULT));
        };
        registration[..copied].copy_from_slice(&bytes);
        if field64(&registration, VERSION) != data_size {
            return Ok(Outcome::Error(EINVAL));
        }
    } else {
        set64(&mut registration, DISPATCH_QUEUE_OFFSET, queue_offset);
    }
    let stack_hint = trunc_page(kernel.process.user_stack);
    let mut registered = lock(&kernel.process.threads.registration);
    if registered.is_some() {
        return Ok(Outcome::Error(EINVAL));
    }
    // Both entries are function pointers: authenticated, or poisoned so
    // that a thread entering one faults.
    let signer = kernel.process.signer.as_ref();
    let (thread_start, workqueue_thread) = (
        status::function_pointer_from_user(signer, thread_start)?,
        status::function_pointer_from_user(signer, workqueue_thread)?,
    );
    let mut tsd_offset = field32(&registration, TSD_OFFSET);
    let maximum = if pthread_size >= TSD_SLOT_BYTES
        && u64::from(tsd_offset) <= pthread_size - TSD_SLOT_BYTES
    {
        pthread_size - u64::from(tsd_offset) - TSD_SLOT_BYTES
    } else {
        tsd_offset = 0;
        0
    };
    let clamp = |value: u64| if value > maximum { 0 } else { value };
    let dispatch_queue_offset = clamp(field64(&registration, DISPATCH_QUEUE_OFFSET));
    let return_to_kernel_offset =
        clamp(field32(&registration, RETURN_TO_KERNEL_OFFSET).into()) as u32;
    let mach_thread_self_offset =
        clamp(field32(&registration, MACH_THREAD_SELF_OFFSET).into()) as u32;
    let quantum_expiry_offset =
        clamp(field32(&registration, WQ_QUANTUM_EXPIRY_OFFSET).into()) as u32;
    let registration_state = Registration {
        stack_hint,
        thread_start,
        workqueue_thread,
        pthread_size,
        tsd_offset,
        dispatch_queue_offset,
        return_to_kernel_offset,
        mach_thread_self_offset,
        quantum_expiry_offset,
    };
    if kernel.trace {
        let Registration {
            thread_start,
            workqueue_thread,
            pthread_size,
            tsd_offset,
            dispatch_queue_offset,
            return_to_kernel_offset,
            mach_thread_self_offset,
            quantum_expiry_offset,
            ..
        } = registration_state;
        eprintln!(
            "stela: pthread registration: start {thread_start:#x}, workqueue \
             {workqueue_thread:#x}, size {pthread_size:#x}, tsd {tsd_offset:#x}, dispatch \
             {dispatch_queue_offset:#x}, return-to-kernel {return_to_kernel_offset:#x}, \
             thread-self {mach_thread_self_offset:#x}, quantum {quantum_expiry_offset:#x}"
        );
    }
    *registered = Some(registration_state);
    drop(registered);
    if data != 0 {
        set64(&mut registration, VERSION, REGISTRATION_BYTES);
        set64(&mut registration, MAIN_QOS, main_thread_priority());
        set64(&mut registration, STACK_ADDRESS_HINT, stack_hint);
        set32(
            &mut registration,
            MUTEX_DEFAULT_POLICY,
            mutex_default_policy()?,
        );
        if !memory::write(data, &registration[..copied]) {
            return Ok(Outcome::Error(EINVAL));
        }
    }
    Ok(Outcome::value(FEATURES))
}

/// The calling thread's QoS as a `pthread_priority_t`: the host thread is
/// the guest's main thread, and the host's own registration already
/// imposed `THREAD_QOS_LEGACY` if it had none.
fn main_thread_priority() -> u64 {
    unsafe extern "C" {
        fn pthread_get_qos_class_np(
            thread: libc::pthread_t,
            class: *mut u32,
            relative: *mut libc::c_int,
        ) -> libc::c_int;
    }
    let mut class = 0u32;
    let mut relative = 0;
    // SAFETY: the out-parameters are this frame's.
    unsafe { pthread_get_qos_class_np(libc::pthread_self(), &raw mut class, &raw mut relative) };
    // `qos_class_t` values (`sys/qos.h`) to thread QoS tiers.
    let tier = match class {
        0x21 => 6,
        0x19 => 5,
        0x11 => 3,
        0x09 => 2,
        0x05 => 1,
        _ => THREAD_QOS_LEGACY,
    };
    priority::from_thread_qos(tier, 0, 0)
}

/// The kext's `pthread_mutex_default_policy`, which it publishes as
/// `kern.pthread_mutex_default_policy`.
fn mutex_default_policy() -> Result<u32> {
    let mut value = 0u32;
    let mut length = size_of::<u32>();
    // SAFETY: the name is NUL-terminated and the buffer is this frame's.
    let status = unsafe {
        libc::sysctlbyname(
            c"kern.pthread_mutex_default_policy".as_ptr(),
            (&raw mut value).cast(),
            &raw mut length,
            core::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        bail!("the host kernel does not publish kern.pthread_mutex_default_policy");
    }
    Ok(value)
}

/// `bsdthread_create(func, func_arg, stack, pthread, flags)`: a thread
/// entering `threadstart(pthread, port, func, func_arg, stack, flags)` on
/// `stack`, its TSD base `pthread + tsd_offset`.
fn create(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [function, argument, stack, pthread, flags, ..] = call.arguments;
    let flags = flags as u32 as u64;
    let Some(registration) = kernel.process.threads.registration() else {
        return Ok(Outcome::Error(EINVAL));
    };
    if flags & PTHREAD_START_CUSTOM == 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    if flags & PTHREAD_START_SUSPENDED != 0 {
        bail!(
            "bsdthread_create with PTHREAD_START_SUSPENDED: a thread held until \
             thread_resume is not implemented"
        );
    }
    let schedule = if flags & PTHREAD_START_SETSCHED != 0 {
        Schedule::Policy {
            timeshare: (flags >> PTHREAD_START_POLICY_SHIFT) & PTHREAD_START_POLICY_MASK
                == SCHED_OTHER,
            importance: (flags & PTHREAD_START_IMPORTANCE_MASK) as i32 - BASEPRI_DEFAULT,
        }
    } else if flags & PTHREAD_START_QOSCLASS != 0 {
        let priority = flags & PTHREAD_START_QOSCLASS_MASK;
        if priority::to_policy(priority).is_none() {
            return Ok(Outcome::Error(EINVAL));
        }
        Schedule::Qos(priority)
    } else {
        Schedule::Inherit
    };
    let tsd_offset = u64::from(registration.tsd_offset);
    let start_flags = if tsd_offset != 0 {
        flags | PTHREAD_START_TSD_BASE_SET
    } else {
        flags
    } & !PTHREAD_START_SUSPENDED;
    let thread_self_offset = u64::from(registration.mach_thread_self_offset);
    let created = threads::spawn(
        &kernel.process,
        registration.thread_start,
        kernel.signals.creation_mask(),
        move |kernel, pe| {
            let port = kernel.thread_port;
            if tsd_offset != 0
                && thread_self_offset != 0
                && !memory::write_u64(pthread + tsd_offset + thread_self_offset, port.into())
            {
                return Ok(Err(EFAULT));
            }
            schedule.apply(port);
            Entry {
                arguments: vec![pthread, port.into(), function, argument, stack, start_flags],
                sp: stack,
                thread_pointer: (tsd_offset != 0).then_some(pthread + tsd_offset),
            }
            .apply(pe);
            Ok(Ok(()))
        },
    )?;
    Ok(match created {
        Ok(_) => Outcome::value(pthread),
        Err(errno) => Outcome::Error(errno),
    })
}

/// The scheduling a new thread's flags ask for.
#[derive(Debug, Clone, Copy)]
enum Schedule {
    Inherit,
    /// `PTHREAD_START_SETSCHED`: timeshare or fixed, and the importance
    /// relative to `BASEPRI_DEFAULT`.
    Policy {
        timeshare: bool,
        importance: i32,
    },
    /// `PTHREAD_START_QOSCLASS`: a valid `pthread_priority_t`.
    Qos(u64),
}

impl Schedule {
    /// Apply to the calling host thread, which `port` names, as the kext
    /// applies it to the new thread. The kext ignores the results.
    fn apply(self, port: u32) {
        unsafe extern "C" {
            fn thread_policy_set(thread: u32, flavor: u32, policy: *const i32, count: u32) -> i32;
        }
        match self {
            Self::Inherit => {}
            Self::Policy {
                timeshare,
                importance,
            } => {
                let timeshare = i32::from(timeshare);
                // SAFETY: one-word policies from this frame for this thread.
                unsafe {
                    thread_policy_set(
                        port,
                        THREAD_EXTENDED_POLICY,
                        &raw const timeshare,
                        POLICY_COUNT,
                    );
                    thread_policy_set(
                        port,
                        THREAD_PRECEDENCE_POLICY,
                        &raw const importance,
                        POLICY_COUNT,
                    );
                }
            }
            Self::Qos(priority) => {
                set_self(priority, 0, SET_SELF_QOS_FLAG);
            }
        }
    }
}

/// `bsdthread_ctl(BSDTHREAD_CTL_SET_SELF, ...)` on the calling host
/// thread: its QoS, voucher and scheduling flags.
pub(super) fn set_self(
    priority: u64,
    voucher: u64,
    flags: u64,
) -> crate::hosted::forward::Returned {
    crate::hosted::forward::bsd(
        super::number_of("bsdthread_ctl"),
        &[CTL_SET_SELF, priority, voucher, flags],
    )
}

/// `bsdthread_terminate(stackaddr, freesize, port, semaphore)`: release the
/// stack, end the thread, signal the semaphore a joiner of a custom-stack
/// thread waits on and drop the creation's port reference.
fn terminate(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Outcome> {
    let [address, size, port, semaphore, ..] = call.arguments;
    let (port, semaphore) = (port as u32, semaphore as u32);
    if address != 0 && size != 0 {
        let start = trunc_page(address);
        if kernel.thread == threads::MAIN_THREAD {
            // The main thread's stack stays reserved, its pages reusable
            // and inaccessible.
            let last = trunc_page(size - 1);
            if last != 0 {
                // SAFETY: guest pages of the exiting main thread's stack.
                unsafe {
                    libc::madvise(
                        start as *mut libc::c_void,
                        last as usize,
                        MADV_FREE_REUSABLE,
                    )
                };
                let _ = memory::protect(start, last, Protection::NONE);
            }
        } else if let Some(end) = address.checked_add(size).and_then(round_page) {
            kernel.unslid_change(start, end - start, |_| None);
            let _ = memory::deallocate(start, end - start);
            kernel.invalidate_code(pe, start, end - start);
        }
    }
    if let Some(worker) = kernel.worker.take() {
        kernel.process.workqueue.terminated(&worker);
    }
    if semaphore != 0 {
        crate::hosted::forward::mach(
            super::super::mach::index_of(SEMAPHORE_SIGNAL_TRAP),
            &[u64::from(semaphore)],
        );
    }
    if port != 0 {
        crate::hosted::forward::mach(
            super::super::mach::index_of(PORT_DEALLOCATE_TRAP),
            &[u64::from(kernel.process.task_port()), u64::from(port)],
        );
    }
    kernel.end = Some(End::Thread);
    Ok(Outcome::JustReturn)
}

/// `bsdthread_ctl(cmd, arg1, arg2, arg3)`.
fn control(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let [command, first, second, third, ..] = call.arguments;
    let ensure_unused = |argument: u64| argument == 0;
    Ok(match command {
        CTL_QOS_OVERRIDE_START | CTL_QOS_OVERRIDE_END => forward(kernel, call)?,
        CTL_QOS_OVERRIDE_DISPATCH => {
            let qos = priority::thread_qos(second);
            if qos == priority::THREAD_QOS_UNSPECIFIED {
                return Ok(Outcome::Error(EINVAL));
            }
            let port = first as u32;
            if !kernel.process.runtime.registry.contains_port(port) {
                return Ok(Outcome::Error(ESRCH));
            }
            match kernel.process.workqueue.add_override(port, qos, third) {
                true => Outcome::value(0),
                false => Outcome::Error(super::EPERM),
            }
        }
        CTL_QOS_OVERRIDE_RESET => match &kernel.worker {
            Some(worker) => {
                kernel.process.workqueue.reset_override(worker);
                Outcome::value(0)
            }
            None => Outcome::Error(super::EPERM),
        },
        CTL_SET_SELF => super::workqueue::set_self(kernel, first, second, third)?,
        CTL_QOS_MAX_PARALLELISM => {
            if !ensure_unused(third) {
                return Ok(Outcome::Error(EINVAL));
            }
            max_parallelism(kernel, first, second)?
        }
        CTL_WORKQ_ALLOW_KILL => {
            if !ensure_unused(second) || !ensure_unused(third) {
                return Ok(Outcome::Error(EINVAL));
            }
            if let Some(worker) = &kernel.worker {
                kernel.process.workqueue.allow_kill(worker, first != 0);
            }
            Outcome::value(0)
        }
        CTL_WORKQ_ALLOW_SIGMASK => {
            let mask = first as u32;
            if mask & WORKQ_THREADMASK != 0 {
                return Ok(Outcome::Error(EINVAL));
            }
            kernel.process.workqueue.allow_signals(mask);
            Outcome::value(0)
        }
        CTL_DISPATCH_APPLY_ATTR => bail!(
            "bsdthread_ctl BSDTHREAD_CTL_DISPATCH_APPLY_ATTR({first:#x}, {second:#x}): cluster \
             shared-resource policies are not modeled"
        ),
        CTL_SET_QOS
        | CTL_QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_ADD
        | CTL_QOS_DISPATCH_ASYNCHRONOUS_OVERRIDE_RESET => Outcome::Error(ENOTSUP),
        _ => Outcome::Error(EINVAL),
    })
}

/// `bsdthread_get_max_parallelism(qos, flags)` with the edge scheduler's
/// `sched_edge_qos_max_parallelism` over the modeled clusters: every QoS
/// but background and maintenance may use every CPU and cluster; those two
/// only the efficiency cores.
fn max_parallelism(kernel: &Kernel, qos: u64, flags: u64) -> Result<Outcome> {
    let known =
        PARALLELISM_REALTIME | PARALLELISM_COUNT_LOGICAL | PARALLELISM_CLUSTER_SHARED_RESOURCE;
    if flags & !known != 0 {
        return Ok(Outcome::Error(EINVAL));
    }
    // The M2 has no SME units, so no cluster shared resource.
    if flags & PARALLELISM_CLUSTER_SHARED_RESOURCE != 0 {
        return Ok(Outcome::Error(ENOTSUP));
    }
    if flags & PARALLELISM_REALTIME != 0 {
        if qos != 0 {
            return Ok(Outcome::Error(EINVAL));
        }
        bail!(
            "bsdthread_ctl QOS_MAX_PARALLELISM for realtime threads: the M2's realtime spill \
             order is not modeled"
        );
    }
    let qos = qos as u8;
    if qos == priority::THREAD_QOS_UNSPECIFIED || qos >= priority::THREAD_QOS_LAST {
        return Ok(Outcome::Error(EINVAL));
    }
    Ok(Outcome::value(u64::from(parallelism(
        &kernel.process.hardware,
        qos,
    ))))
}

/// The CPUs threads of `qos` may run on at once
/// (`sched_edge_qos_max_parallelism` with `QOS_PARALLELISM_COUNT_LOGICAL`).
pub(super) fn parallelism(hardware: &crate::hosted::hardware::Hardware, qos: u8) -> u32 {
    hardware
        .clusters
        .iter()
        .filter(|cluster| {
            !cluster.performance || !matches!(qos, THREAD_QOS_BACKGROUND | THREAD_QOS_MAINTENANCE)
        })
        .map(|cluster| u32::from(cluster.cores))
        .sum()
}

fn field64(bytes: &[u8], at: u64) -> u64 {
    u64::from_le_bytes(
        bytes[at as usize..at as usize + 8]
            .try_into()
            .expect("eight bytes"),
    )
}

fn field32(bytes: &[u8], at: u64) -> u32 {
    u32::from_le_bytes(
        bytes[at as usize..at as usize + 4]
            .try_into()
            .expect("four bytes"),
    )
}

fn set64(bytes: &mut [u8], at: u64, value: u64) {
    bytes[at as usize..at as usize + 8].copy_from_slice(&value.to_le_bytes());
}

fn set32(bytes: &mut [u8], at: u64, value: u32) {
    bytes[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hosted::hardware::Hardware, machine::Chip};

    #[test]
    fn parallelism_follows_the_edge_scheduler_over_the_m2() {
        let hardware = Hardware::of(Chip::AppleM2, 1 << 34).unwrap();
        assert_eq!(parallelism(&hardware, THREAD_QOS_LEGACY), 8);
        assert_eq!(
            parallelism(&hardware, priority::THREAD_QOS_USER_INTERACTIVE),
            8
        );
        assert_eq!(parallelism(&hardware, THREAD_QOS_BACKGROUND), 4);
        assert_eq!(parallelism(&hardware, THREAD_QOS_MAINTENANCE), 4);
    }

    #[test]
    fn host_publishes_the_registration_inputs() {
        mutex_default_policy().unwrap();
        let priority = main_thread_priority();
        assert_ne!(priority::thread_qos(priority), 0);
        assert_eq!(priority::relative_priority(priority), 0);
    }
}
