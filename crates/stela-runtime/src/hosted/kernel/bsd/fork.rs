//! `fork` and `vfork` (`bsd/kern/kern_fork.c`): the host kernel forks the
//! host process, whose memory is the guest's, so the child has a copy of
//! the parent's address space, its descriptors and its credentials as XNU's
//! `forkproc` and `vm_map_fork` give it. The child has one thread, the
//! caller's: the hosted runtime's state for every other thread and for the
//! workqueue, the workqueue kqueue and the workloops (none of which a new
//! process inherits) is reset, and its task, thread and host ports are the
//! child's own. Every process lock is taken before the host fork so that
//! no lock the child needs is held by a thread it does not have.
//!
//! The parent returns the child's process ID with X1 clear; the child
//! returns its own with X1 set (`thread_set_child`), which libsyscall's
//! wrapper turns into 0. `vfork` suspends the parent until the child execs
//! or exits (`vfork_return`): the parent waits on the host for the child's
//! `NOTE_EXEC` or `NOTE_EXIT`. The child of `vfork` has its own copy of
//! memory rather than the parent's, which POSIX permits.
use super::{Call, Kernel, Outcome, signal};
use crate::hosted::darwin::{HOST_SELF_TRAP, TASK_SELF_TRAP, THREAD_SELF_TRAP};
use crate::hosted::forward;
use crate::hosted::threads::try_lock;
use anyhow::Result;
use core::sync::atomic::Ordering;

/// Anything held across the fork.
trait Held {}
impl<T> Held for T {}

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    Ok(match call.entry.name {
        "fork" => Some(fork(kernel, false)?),
        "vfork" => Some(fork(kernel, true)?),
        _ => None,
    })
}

/// The errno of the last host call.
fn errno() -> u64 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EAGAIN) as u64
}

fn fork(kernel: &mut Kernel, vfork: bool) -> Result<Outcome> {
    let process = kernel.process.clone();
    // The child of `vfork` waits for the parent to watch it.
    let mut handshake = [-1; 2];
    // SAFETY: a two-descriptor array.
    if vfork && unsafe { libc::pipe(handshake.as_mut_ptr()) } != 0 {
        return Ok(Outcome::Error(errno()));
    }
    process
        .exception_ports
        .inheritable(if vfork { "vfork" } else { "fork" })?;
    let control = process.runtime.registry.control(kernel.thread);
    let pid = loop {
        let held = (|| {
            let runtime = process.runtime.hold_for_fork()?;
            let others: Vec<Box<dyn Held + '_>> = vec![
                Box::new(try_lock(&process.shared_region)?),
                Box::new(try_lock(&process.executable)?),
                Box::new(try_lock(&process.counts)?),
                Box::new(try_lock(&process.actions)?),
                Box::new(try_lock(&process.signatures)?),
                Box::new(try_lock(&process.restartable_ranges)?),
                Box::new(try_lock(&process.reclaim)?),
                Box::new(process.files.hold_for_fork()?),
                Box::new(process.threads.hold_for_fork()?),
            ];
            let workqueue = process.workqueue.hold_for_fork()?;
            let kqworkq = process.kqworkq.hold_for_fork()?;
            let workloops = process.workloops.hold_for_fork()?;
            let aio = process.aio.hold_for_fork()?;
            let task = (
                try_lock(&process.task_debug)?,
                process.exception_ports.hold_for_fork()?,
            );
            let control = match &control {
                Some(control) => Some(control.hold_for_fork()?),
                None => None,
            };
            Some((
                runtime, others, workqueue, kqworkq, workloops, aio, task, control,
            ))
        })();
        let Some((runtime, others, workqueue, kqworkq, workloops, mut aio, task, held_control)) =
            held
        else {
            std::thread::yield_now();
            continue;
        };
        // SAFETY: the host fork; the child continues on this thread alone,
        // with every hosted-runtime lock held by it.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let port = |trap| forward::mach(trap, &[]).rax as u32;
            let thread_port = port(THREAD_SELF_TRAP);
            process
                .task_port
                .store(port(TASK_SELF_TRAP), Ordering::SeqCst);
            process
                .host_port
                .store(port(HOST_SELF_TRAP), Ordering::SeqCst);
            process
                .runtime
                .fork_child(runtime, kernel.thread, thread_port);
            workqueue.child();
            kqworkq.child();
            workloops.child();
            // The child has no asynchronous I/O (`forkproc`).
            process.aio.fork_child(&mut aio);
            drop(aio);
            // The child's task has no debug state of its own
            // (`machine_task_init`) and inherits the exception actions
            // its host task holds.
            let (mut debug, exceptions) = task;
            *debug = None;
            drop(debug);
            exceptions.child();
            // XNU's fork leaves the child's thread unsuspended.
            if let Some(held_control) = held_control {
                held_control.child();
            }
            drop(others);
            // The child keeps the commpage, shared with the parent, but
            // not the parent's thread that follows the host calendar.
            crate::hosted::commpage::watch_calendar();
            signal::fork_child(kernel);
            kernel.thread_port = thread_port;
            kernel.mig_relay = None;
            kernel.worker = None;
            // The child's working directory is the thread's (`fdt_fork`).
            kernel.thread_directory = false;
            // A new thread carries no scheduler marks.
            kernel.shared_resource_heavy = false;
        } else {
            drop((
                runtime,
                others,
                workqueue,
                kqworkq,
                workloops,
                aio,
                task,
                held_control,
            ));
        }
        break pid;
    };
    if pid < 0 {
        let error = errno();
        close(&handshake);
        return Ok(Outcome::Error(error));
    }
    if pid == 0 {
        if vfork {
            let mut byte = 0u8;
            // SAFETY: one byte into this frame; the parent writes it once
            // it watches this process, or closes the pipe.
            unsafe {
                libc::close(handshake[1]);
                libc::read(handshake[0], (&raw mut byte).cast(), 1);
                libc::close(handshake[0]);
            }
        }
        if kernel.trace {
            eprintln!("stela: fork child {} of {}", std::process::id(), {
                // SAFETY: no arguments.
                unsafe { libc::getppid() }
            });
        }
        return Ok(Outcome::Return(u64::from(std::process::id()), 1));
    }
    if vfork {
        wait_for_exec_or_exit(pid, &handshake);
    }
    Ok(Outcome::Return(pid as u64, 0))
}

fn close(descriptors: &[i32; 2]) {
    for &descriptor in descriptors {
        if descriptor >= 0 {
            // SAFETY: a descriptor this call opened.
            unsafe { libc::close(descriptor) };
        }
    }
}

/// Block until the `vfork` child `pid` execs or exits.
fn wait_for_exec_or_exit(pid: libc::pid_t, handshake: &[i32; 2]) {
    // SAFETY: a new kqueue this function owns.
    let queue = unsafe { libc::kqueue() };
    let mut change: libc::kevent = unsafe { core::mem::zeroed() };
    change.ident = pid as usize;
    change.filter = libc::EVFILT_PROC;
    change.flags = libc::EV_ADD | libc::EV_ONESHOT;
    change.fflags = libc::NOTE_EXEC | libc::NOTE_EXIT;
    // SAFETY: one change and no events; a child that already exited fails
    // the registration with ESRCH, which ends the wait.
    let watching = queue >= 0
        && unsafe {
            libc::kevent(
                queue,
                &change,
                1,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
            )
        } == 0;
    // SAFETY: the handshake's descriptors, which this call opened.
    unsafe {
        libc::close(handshake[0]);
        libc::write(handshake[1], [0u8].as_ptr().cast(), 1);
        libc::close(handshake[1]);
    }
    if watching {
        let mut event: libc::kevent = unsafe { core::mem::zeroed() };
        // SAFETY: one event into this frame; EINTR retries.
        while unsafe {
            libc::kevent(
                queue,
                core::ptr::null(),
                0,
                &mut event,
                1,
                core::ptr::null(),
            )
        } < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {}
    }
    if queue >= 0 {
        // SAFETY: the kqueue this function opened.
        unsafe { libc::close(queue) };
    }
}
