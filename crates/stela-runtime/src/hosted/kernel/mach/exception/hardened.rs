//! One frozen task registration backed by the actual host kernel's
//! exception-port object and donated send right. Holder threads never
//! execute: native flavor zero is only a resource-validation encoding;
//! ARM flavors and signed-PC keys are used by guest delivery alone.
use super::*;

unsafe extern "C" {
    fn task_register_hardened_exception_handler(
        task: u32,
        signed_pc_key: u32,
        exceptions: u32,
        behaviors: u32,
        flavors: u32,
        port: u32,
    ) -> i32;
    fn thread_adopt_exception_handler(
        thread: u32,
        port: u32,
        exceptions: u32,
        behaviors: u32,
        flavors: u32,
    ) -> i32;
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Registration {
    key: u32,
    exceptions: u32,
    behaviors: u32,
    flavors: u32,
}

impl Registration {
    /// Bit-subset checks, not enum equality (`ipc_tt.c`). Port object
    /// equality is checked by native adoption, never by a remembered name.
    fn permits(self, exceptions: u32, behaviors: u32, flavors: u32) -> bool {
        exceptions & !self.exceptions == 0
            && behaviors & !self.behaviors == 0
            && flavors & !self.flavors == 0
    }
}

fn native_flavor(flavor: u32) -> u32 {
    if flavor == 0 || VALID_FLAVORS.contains(&flavor) {
        0
    } else {
        // Invalid on both ABIs. Preserve the kernel's port/type/right
        // checks before its architecture-dependent flavor validation.
        u32::MAX
    }
}

fn available(status: u32) -> Result<u32> {
    const MIG_BAD_ID: u32 = (-303i32) as u32;
    if status == MIG_BAD_ID || status == crate::hosted::darwin::KERN_NOT_SUPPORTED {
        unsupported::refuse!(
            Failure::Kern(KERN_FAILURE),
            "the host kernel lacks hardened exception resource registration/adoption"
        );
    }
    if status == KERN_DENIED {
        unsupported::refuse!(
            Failure::Kern(KERN_DENIED),
            "the host kernel's hardened exception resource policy denied this operation"
        );
    }
    Ok(status)
}

/// Register, including the kernel's ordering of port provenance,
/// validation and its irreversible frozen check. Native MIG copies the
/// carried send right; success donates that copy to the real task.
fn register_resource(state: &mut State, name: u32, registration: Registration) -> Result<u32> {
    // SAFETY: the actual task and a carried send/null/dead right of this
    // space. No x86 state is requested; native flavor zero is never run.
    let status = unsafe {
        task_register_hardened_exception_handler(
            host::task(),
            registration.key,
            registration.exceptions,
            registration.behaviors,
            native_flavor(registration.flavors),
            name,
        ) as u32
    };
    let status = available(status)?;
    if status == 0 {
        anyhow::ensure!(
            state.hardened.is_none(),
            "native hardened registration lost its frozen state"
        );
        state.hardened = Some(registration);
        state.changed = true;
    }
    Ok(status)
}

/// MIG 3465: one port descriptor, NDR, key and three masks.
pub(in super::super) fn register(kernel: &mut Kernel, request: &Request) -> Result<Reply> {
    let name = match carried_send(
        kernel,
        "task_register_hardened_exception_handler",
        request,
        40,
    )? {
        Ok(name) => name,
        Err(reply) => return Ok(reply),
    };
    let reply = register_carried(kernel, request, name);
    release_send(name);
    reply
}

fn register_carried(kernel: &Kernel, request: &Request, name: u32) -> Result<Reply> {
    let registration = Registration {
        key: request.word(24).expect("checked request length"),
        exceptions: request.word(28).expect("checked request length"),
        behaviors: request.word(32).expect("checked request length"),
        flavors: request.word(36).expect("checked request length"),
    };
    let base = registration.behaviors & !MACH_EXCEPTION_MASK;
    // Invalid fields go to the native validator so its earlier port/type
    // checks retain their ordering. Guest fatal policy is an explicit
    // pre-admission limit, not a committed native frozen registration.
    if registration.exceptions & !EXC_MASK_VALID == 0
        && (!valid(name)
            || (EXCEPTION_DEFAULT..=EXCEPTION_STATE_IDENTITY_PROTECTED).contains(&base))
        && native_flavor(registration.flavors) == 0
        && (!(base == EXCEPTION_IDENTITY_PROTECTED
            || registration.behaviors & MACH_EXCEPTION_BACKTRACE_PREFERRED != 0)
            || registration.behaviors & MACH_EXCEPTION_CODES != 0)
        && let Err(code) = policy(
            kernel,
            "task_register_hardened_exception_handler",
            registration.exceptions,
            name,
            registration.behaviors,
            true,
        )?
    {
        return Ok(Reply::Failure(code));
    }
    let status = register_resource(
        &mut kernel.process.exception_ports.lock(),
        name,
        registration,
    )?;
    Ok(super::super::server::status(status))
}

/// Native adoption is an authoritative comparison with the frozen
/// registration's actual object. It accepts null independently of the
/// registered object and never compares numeric names or mutable context.
fn adopt_resource(thread: u32, name: u32, mask: u32, behavior: u32) -> Result<u32> {
    // SAFETY: a never-started holder thread of this task and a carried
    // right. Native flavor zero is a subset of every registered flavor.
    let status = unsafe { thread_adopt_exception_handler(thread, name, mask, behavior, 0) as u32 };
    // KERN_DENIED is adoption's ordinary identity/subset failure.
    if status == KERN_DENIED {
        return Ok(status);
    }
    available(status)
}

/// MIG 3631: one port descriptor, NDR and three masks.
pub(in super::super) fn adopt(
    kernel: &mut Kernel,
    request: &Request,
    thread: u32,
) -> Result<Reply> {
    let name = match carried_send(kernel, "thread_adopt_exception_handler", request, 36)? {
        Ok(name) => name,
        Err(reply) => return Ok(reply),
    };
    let reply = adopt_carried(kernel, request, thread, name);
    release_send(name);
    reply
}

fn adopt_carried(kernel: &Kernel, request: &Request, thread: u32, name: u32) -> Result<Reply> {
    let mask = request.word(24).expect("checked request length");
    let behavior = request.word(28).expect("checked request length");
    let flavor = request.word(32).expect("checked request length");
    let mut state = kernel.process.exception_ports.lock();
    let Some(registration) = state.hardened else {
        return Ok(Reply::Failure(KERN_DENIED));
    };
    if !registration.permits(mask, behavior, flavor) {
        return Ok(Reply::Failure(KERN_DENIED));
    }
    // A zero-mask adoption checks real object identity without installing
    // actions or retaining additional port rights on the checker.
    let checker = task_holder(&mut state)?.thread;
    let checked = adopt_resource(checker, name, 0, behavior)?;
    if checked != 0 {
        return Ok(Reply::Failure(checked));
    }
    if !kernel
        .process
        .runtime
        .registry
        .control_by_port(thread)
        .is_some_and(|control| control.active())
    {
        return Ok(Reply::Failure(KERN_FAILURE));
    }
    let holder = match state.threads.entry(thread) {
        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::btree_map::Entry::Vacant(entry) => entry.insert(Holder::new()?),
    };
    let status = adopt_resource(holder.thread, name, mask, behavior)?;
    if status == 0 {
        for slot in bits(mask) {
            holder.actions[slot] = Action {
                behavior,
                flavor,
                hardened: Some(registration.key),
            };
        }
    }
    Ok(super::super::server::status(status))
}

#[cfg(test)]
mod tests {
    use super::super::super::server::COPY_SEND;
    use super::*;
    use crate::hosted::darwin::{MACH_RCV_MSG, MACH_SEND_MSG, mach_msg};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CHILD: &str = "STELA_HARDENED_RESOURCE_TEST";
    const INSERT_SEND: u32 = 0x10;
    const EXCEPTION_PORT: u32 = 0x8000;
    const EXC_MASK_BAD_ACCESS: u32 = 1 << EXC_BAD_ACCESS;

    #[repr(C)]
    struct Options {
        flags: u32,
        queue_limit: u32,
        reserved: u64,
    }

    unsafe extern "C" {
        fn mach_port_construct(
            task: u32,
            options: *const Options,
            context: u64,
            port: *mut u32,
        ) -> i32;
        fn mach_port_destroy(task: u32, name: u32) -> i32;
        fn mach_port_allocate_name(task: u32, right: u32, name: u32) -> i32;
        fn mach_port_get_refs(task: u32, name: u32, right: u32, refs: *mut u32) -> i32;
    }

    fn port(exception: bool) -> u32 {
        let options = Options {
            flags: INSERT_SEND | if exception { EXCEPTION_PORT } else { 0 },
            queue_limit: 0,
            reserved: 0,
        };
        let mut name = 0;
        // SAFETY: initialized options and a local output name.
        assert_eq!(
            unsafe { mach_port_construct(host::task(), &options, 0, &mut name) },
            0
        );
        name
    }

    fn send_refs(name: u32) -> u32 {
        let mut refs = 0;
        // SAFETY: a local output word and a name of this test's space.
        unsafe { mach_port_get_refs(host::task(), name, 0, &mut refs) };
        refs
    }

    /// Freezing a task is irreversible. Exercise native resources in a
    /// bounded child running this exact test alone, never in the shared
    /// Rust test runner's task or in another test's IPC namespace.
    fn isolated(test: &str) -> bool {
        if std::env::var(CHILD).as_deref() == Ok(test) {
            return true;
        }
        let full = format!("{}::{test}", module_path!());
        let name = full.split_once("::").unwrap().1;
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(CHILD, test)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(20) {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "native hardened resource test timed out: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "native child failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    fn registration() -> Registration {
        Registration {
            key: 0xa800_0000,
            exceptions: EXC_MASK_BAD_ACCESS,
            behaviors: EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES,
            flavors: 6,
        }
    }

    /// Transfer a real send right through a native queue, removing its
    /// caller reference while queued. Registration's retained right is
    /// independent of this namespace's references and this transfer.
    fn transfer(name: u32) -> u32 {
        let queue = port(false);
        let mut message = [0u32; 32];
        // Header, descriptor count, port descriptor (COPY_SEND).
        message[0] = 0x8000_0000 | u32::from(COPY_SEND);
        message[1] = 40;
        message[2] = queue;
        message[5] = 1;
        message[6] = 1;
        message[7] = name;
        message[9] = u32::from(COPY_SEND) << 16;
        // SAFETY: the message's declared size is within this owned buffer.
        assert_eq!(
            unsafe { mach_msg(message.as_mut_ptr().cast(), MACH_SEND_MSG, 40, 0, 0, 0, 0) },
            0
        );
        release_send(name);
        assert_eq!(send_refs(name), 0);
        // SAFETY: this private queue and the owned receive buffer.
        assert_eq!(
            unsafe {
                mach_msg(
                    message.as_mut_ptr().cast(),
                    MACH_RCV_MSG,
                    0,
                    std::mem::size_of_val(&message) as u32,
                    queue,
                    0,
                    0,
                )
            },
            0
        );
        let moved = message[7];
        // SAFETY: the test's private queue; the received descriptor is
        // already copied into this space and survives queue destruction.
        assert_eq!(unsafe { mach_port_destroy(host::task(), queue) }, 0);
        moved
    }

    #[test]
    fn native_registration_and_adoption_preserve_rights_identity_and_freeze() {
        if !isolated("native_registration_and_adoption_preserve_rights_identity_and_freeze") {
            return;
        }
        let mut state = State::default();
        let allowed = registration();
        let ordinary = port(false);
        // The ordinary and kernel-object ports fail their type check even
        // before the later flavor validation; neither freezes the task.
        for name in [ordinary, host::task()] {
            for flavors in [allowed.flavors, u32::MAX] {
                assert_eq!(
                    register_resource(&mut state, name, Registration { flavors, ..allowed })
                        .unwrap(),
                    KERN_INVALID_ARGUMENT
                );
                assert!(state.hardened.is_none());
            }
        }
        let exception = port(true);
        for invalid in [
            Registration {
                flavors: u32::MAX,
                ..allowed
            },
            Registration {
                exceptions: 1,
                ..allowed
            },
            Registration {
                behaviors: 7,
                ..allowed
            },
            Registration {
                behaviors: EXCEPTION_IDENTITY_PROTECTED,
                ..allowed
            },
        ] {
            assert_eq!(
                register_resource(&mut state, exception, invalid).unwrap(),
                KERN_INVALID_ARGUMENT
            );
            assert!(state.hardened.is_none());
        }
        assert_eq!(
            register_resource(&mut state, exception, allowed).unwrap(),
            0
        );
        assert!(state.changed);
        assert_eq!(state.hardened.unwrap().key, allowed.key);
        assert_eq!(send_refs(exception), 1);
        assert_eq!(
            register_resource(&mut state, exception, allowed).unwrap(),
            KERN_INVALID_ARGUMENT
        );
        let holder = Holder::new().unwrap();
        assert_eq!(
            adopt_resource(
                holder.thread,
                ordinary,
                allowed.exceptions,
                allowed.behaviors
            )
            .unwrap(),
            KERN_DENIED
        );
        assert_eq!(
            adopt_resource(
                holder.thread,
                exception,
                allowed.exceptions | (1 << EXC_BREAKPOINT),
                allowed.behaviors
            )
            .unwrap(),
            KERN_DENIED
        );
        let transferred = transfer(exception);
        assert_eq!(transferred, exception);
        assert_eq!(
            adopt_resource(
                holder.thread,
                transferred,
                allowed.exceptions,
                allowed.behaviors
            )
            .unwrap(),
            0
        );
        assert_eq!(send_refs(exception), 1);
        let groups = host_groups(false, holder.thread, allowed.exceptions).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            (groups[0].name, groups[0].flavor),
            (exception, 0),
            "native holder has no ARM or x86 state flavor"
        );
        for group in groups {
            release_send(group.name);
        }
        drop(holder);
        assert_eq!(send_refs(exception), 1);
        // Destroying all rights frees this name. Reusing exactly that
        // numeric name must not adopt the frozen registration's old object.
        assert_eq!(unsafe { mach_port_destroy(host::task(), exception) }, 0);
        assert_eq!(
            unsafe { mach_port_allocate_name(host::task(), 1, exception) },
            0
        );
        assert_eq!(
            unsafe {
                crate::hosted::darwin::mach_port_insert_right(
                    host::task(),
                    exception,
                    exception,
                    20,
                )
            },
            0
        );
        let holder = Holder::new().unwrap();
        assert_eq!(
            adopt_resource(
                holder.thread,
                exception,
                allowed.exceptions,
                allowed.behaviors
            )
            .unwrap(),
            KERN_DENIED
        );
        assert_eq!(
            adopt_resource(holder.thread, 0, allowed.exceptions, allowed.behaviors).unwrap(),
            0
        );
        assert_eq!(unsafe { mach_port_destroy(host::task(), exception) }, 0);
        assert_eq!(unsafe { mach_port_destroy(host::task(), ordinary) }, 0);
    }

    #[test]
    fn native_null_registration_is_still_frozen_and_masks_are_subsets() {
        if !isolated("native_null_registration_is_still_frozen_and_masks_are_subsets") {
            return;
        }
        let mut state = State::default();
        let allowed = registration();
        assert_eq!(register_resource(&mut state, 0, allowed).unwrap(), 0);
        assert_eq!(
            register_resource(&mut state, 0, allowed).unwrap(),
            KERN_INVALID_ARGUMENT
        );
        let holder = Holder::new().unwrap();
        assert_eq!(
            adopt_resource(holder.thread, 0, allowed.exceptions, allowed.behaviors).unwrap(),
            0
        );
        let ordinary = port(false);
        assert_eq!(
            adopt_resource(
                holder.thread,
                ordinary,
                allowed.exceptions,
                allowed.behaviors
            )
            .unwrap(),
            KERN_DENIED
        );
        assert!(allowed.permits(allowed.exceptions, allowed.behaviors, allowed.flavors));
        assert!(allowed.permits(0, 0, 0));
        assert!(!allowed.permits(allowed.exceptions | 1, allowed.behaviors, allowed.flavors));
        assert!(!allowed.permits(allowed.exceptions, allowed.behaviors | 8, allowed.flavors));
        assert!(!allowed.permits(allowed.exceptions, allowed.behaviors, allowed.flavors | 8));
        assert_eq!(unsafe { mach_port_destroy(host::task(), ordinary) }, 0);
    }

    #[test]
    fn fork_child_drop_does_not_use_the_parent_holders_port_name() {
        if !isolated("fork_child_drop_does_not_use_the_parent_holders_port_name") {
            return;
        }
        let holder = Holder::new().unwrap();
        // SAFETY: after fork the child only drops a stack-only holder,
        // whose PID guard performs getpid, and calls async-safe _exit.
        // It neither allocates nor enters inherited runtime/library locks.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            drop(holder);
            // SAFETY: end this owned native control child immediately.
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        // SAFETY: wait for this test's child and write one status word.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0);
        assert!(host_groups(false, holder.thread, EXC_MASK_VALID).is_ok());
        let name = holder.thread;
        drop(holder);
        unsafe extern "C" {
            fn mach_port_type(task: u32, name: u32, kind: *mut u32) -> i32;
        }
        let mut kind = 0;
        // SAFETY: query the just-retired owned control-port name.
        assert_ne!(unsafe { mach_port_type(host::task(), name, &mut kind) }, 0);
    }
}
