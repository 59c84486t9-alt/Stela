//! The pthread kernel support (`libpthread` `kern/kern_support.c`) for the
//! guest's threads. The host process's own libpthread already registered
//! with the host kernel, so the guest's `bsdthread_register` is serviced
//! here with the kext's semantics: the registration data is validated,
//! clamped to the pthread size, answered with the main thread's QoS, stack
//! hint and mutex policy, and the kext's feature set is returned.
//!
//! `bsdthread_ctl` operates on the calling thread, which is the host thread
//! running the guest, and is forwarded. Creating threads and workqueue
//! threads needs one PE per host thread and stays refused by name until the
//! hosted runtime runs more than one.
use super::{Call, EFAULT, EINVAL, Kernel, Outcome, Pe, forward};
use crate::hosted::memory;
use anyhow::{Result, bail};

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
/// `_PTHREAD_PRIORITY_QOS_CLASS_SHIFT`.
const QOS_CLASS_SHIFT: u32 = 8;
/// `THREAD_QOS_LEGACY`: the kernel imposes it on an unspecified main thread.
const THREAD_QOS_LEGACY: u32 = 4;

/// The process's pthread registration, as the kext keeps it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Threads {
    pub(crate) registration: Option<Registration>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Registration {
    pub(crate) thread_start: u64,
    pub(crate) workqueue_thread: u64,
    pub(crate) pthread_size: u64,
    pub(crate) tsd_offset: u32,
    pub(crate) dispatch_queue_offset: u64,
    pub(crate) return_to_kernel_offset: u32,
    pub(crate) mach_thread_self_offset: u32,
    pub(crate) quantum_expiry_offset: u32,
}

pub(super) fn call(kernel: &mut Kernel, _pe: &mut Pe, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "bsdthread_register" => register(kernel, call)?,
        "bsdthread_ctl" => forward(kernel, call)?,
        "bsdthread_create" | "bsdthread_terminate" | "workq_open" | "workq_kernreturn" => bail!(
            "{}: guest threads need one PE per host thread, which the hosted runtime does not \
             run yet",
            call.entry.name
        ),
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
    let stack_hint = memory::trunc_page(kernel.user_stack);
    if kernel.threads.registration.is_some() {
        return Ok(Outcome::Error(EINVAL));
    }
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
        } = registration_state;
        eprintln!(
            "stela: pthread registration: start {thread_start:#x}, workqueue \
             {workqueue_thread:#x}, size {pthread_size:#x}, tsd {tsd_offset:#x}, dispatch \
             {dispatch_queue_offset:#x}, return-to-kernel {return_to_kernel_offset:#x}, \
             thread-self {mach_thread_self_offset:#x}, quantum {quantum_expiry_offset:#x}"
        );
    }
    kernel.threads.registration = Some(registration_state);
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
    1 << (QOS_CLASS_SHIFT + tier - 1)
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

    #[test]
    fn host_publishes_the_registration_inputs() {
        mutex_default_policy().unwrap();
        let priority = main_thread_priority();
        assert_eq!(priority.count_ones(), 1);
        assert!(priority >= 1 << QOS_CLASS_SHIFT);
    }
}
