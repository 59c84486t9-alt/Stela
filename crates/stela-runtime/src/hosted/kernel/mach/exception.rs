//! The task's and its threads' exception actions (`osfmk/kern/ipc_tt.c`):
//! the port, behavior and flavor the `task_` and `thread_`
//! `set_exception_ports`, `swap_exception_ports`, `get_exception_ports`
//! and `get_exception_ports_info` routines act on, one action per
//! exception type. A thread has none until one is first set
//! (`ipc_thread_init_exc_actions`); its actions end with it.
//!
//! The host task and threads must not hold them: the host kernel would deliver the
//! host faults the hosted runtime recovers from (every guest memory fault
//! is one) to the guest's ports, with x86 state. A host Mach thread that
//! never starts (`thread_create`) holds them instead: its exception ports
//! keep the send rights as the arm64 kernel's actions do, outside this IPC
//! space's user references, and the host kernel checks each new port as
//! the arm64 kernel does (`ipc_is_valid_exception_port`). The behaviors
//! and flavors, which the host kernel would validate as x86's, are kept
//! here. The task's actions begin as the host task inherited them, each
//! flavor restated as the arm64 flavor of the same state: a native process
//! started alike inherits the same actions with its parent's arm64
//! flavors.
//!
//! Known limits: a guest exception for which this task holds a port stops
//! the run, as delivering Mach exceptions is not implemented; the
//! EXC_CRASH, EXC_RESOURCE and EXC_GUARD reports the host kernel raises go
//! to the ports the host task inherited; a fork, exec or spawn after this
//! process changed its actions stops the run, as the child would not
//! inherit them.
use super::super::Kernel;
use super::server::{
    Descriptor, KERN_INVALID_ARGUMENT, MACH_PORT_DEAD, MIG_BAD_ARGUMENTS, MOVE_SEND, Reply,
    Request, release_send,
};
use crate::hosted::host;
use crate::hosted::threads::{lock, try_lock};
use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

/// `EXC_TYPES_COUNT` with the illegal exception 0, and `FIRST_EXCEPTION`.
const EXC_TYPES_COUNT: usize = 14;
const FIRST_EXCEPTION: usize = 1;
/// `EXC_MASK_VALID`: `EXC_MASK_ALL`, `EXC_MASK_CRASH` and
/// `EXC_MASK_CORPSE_NOTIFY` (`EXC_MASK_MACHINE` is 0 on arm64).
const EXC_MASK_VALID: u32 = 0x3ffe;
/// Exception types the hosted kernel raises for guest exceptions.
pub(crate) const EXC_BAD_ACCESS: usize = 1;
pub(crate) const EXC_BREAKPOINT: usize = 6;
/// Exception names, by type, for diagnostics.
const NAMES: [&str; EXC_TYPES_COUNT] = [
    "exception 0",
    "EXC_BAD_ACCESS",
    "EXC_BAD_INSTRUCTION",
    "EXC_ARITHMETIC",
    "EXC_EMULATION",
    "EXC_SOFTWARE",
    "EXC_BREAKPOINT",
    "EXC_SYSCALL",
    "EXC_MACH_SYSCALL",
    "EXC_RPC_ALERT",
    "EXC_CRASH",
    "EXC_RESOURCE",
    "EXC_GUARD",
    "EXC_CORPSE_NOTIFY",
];
/// `exception_behavior_t` values and flags.
const EXCEPTION_DEFAULT: u32 = 1;
const EXCEPTION_STATE: u32 = 2;
const EXCEPTION_IDENTITY_PROTECTED: u32 = 4;
const EXCEPTION_STATE_IDENTITY_PROTECTED: u32 = 5;
const MACH_EXCEPTION_CODES: u32 = 0x8000_0000;
const MACH_EXCEPTION_BACKTRACE_PREFERRED: u32 = 0x2000_0000;
const MACH_EXCEPTION_MASK: u32 = 0xe000_0000;
/// How a holder keeps each port on the host: an identity-protected
/// behavior, which every task's policy allows, and no flavor.
const HELD_BEHAVIOR: u32 = EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES;
/// The arm64 `VALID_THREAD_STATE_FLAVOR`s (`mach/arm/thread_status.h`).
const VALID_FLAVORS: [u32; 14] = [1, 2, 3, 4, 5, 6, 7, 9, 10, 14, 15, 16, 17, 27];
/// The reply arrays' bound (`exception_handler_array_t`), which the
/// kernel's MIG server passes as the count.
const REPLY_ENTRIES: usize = 32;
const KERN_INVALID_RIGHT: u32 = 17;
const KERN_DENIED: u32 = 53;
/// `MIG_TYPE_ERROR`: a request's right is not the routine's type.
const MIG_TYPE_ERROR: u32 = (-300i32) as u32;
/// Received rights' dispositions: `MACH_MSG_TYPE_PORT_RECEIVE` and
/// `MACH_MSG_TYPE_PORT_SEND_ONCE`.
const PORT_RECEIVE: u8 = 16;
const PORT_SEND_ONCE: u8 = 18;
/// `SET_EXCEPTION_ENTITLEMENT` and `IPC_ONLY_ONE_EXCEPTION_PORT`.
const SET_EXCEPTION_ENTITLEMENT: &str = "com.apple.private.set-exception-port";
const ONLY_ONE_EXCEPTION_PORT: &str = "com.apple.security.only-one-exception-port";

unsafe extern "C" {
    fn thread_create(task: u32, thread: *mut u32) -> i32;
    fn thread_terminate(thread: u32) -> i32;
    fn thread_set_exception_ports(
        thread: u32,
        mask: u32,
        port: u32,
        behavior: u32,
        flavor: u32,
    ) -> i32;
    fn thread_get_exception_ports(
        thread: u32,
        mask: u32,
        masks: *mut u32,
        count: *mut u32,
        ports: *mut u32,
        behaviors: *mut u32,
        flavors: *mut u32,
    ) -> i32;
    fn thread_get_exception_ports_info(
        thread: u32,
        mask: u32,
        masks: *mut u32,
        count: *mut u32,
        info: *mut [u32; 2],
        behaviors: *mut u32,
        flavors: *mut u32,
    ) -> i32;
    fn task_get_exception_ports(
        task: u32,
        mask: u32,
        masks: *mut u32,
        count: *mut u32,
        ports: *mut u32,
        behaviors: *mut u32,
        flavors: *mut u32,
    ) -> i32;
    fn mach_port_mod_refs(task: u32, name: u32, right: u32, delta: i32) -> i32;
}

/// One exception type's behavior and flavor; its port is the holder's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Action {
    behavior: u32,
    flavor: u32,
}

/// One object's actions: the never-started host thread whose exception
/// ports hold their rights, and their behaviors and flavors.
#[derive(Debug)]
struct Holder {
    thread: u32,
    actions: [Action; EXC_TYPES_COUNT],
}

/// The process's exception actions.
#[derive(Debug, Default)]
pub(crate) struct ExceptionPorts(Mutex<State>);

#[derive(Debug, Default)]
struct State {
    /// The task's actions, once first used.
    task: Option<Holder>,
    /// Whether this process changed them from those it inherited.
    changed: bool,
    /// The actions of the threads that have any, by thread port.
    threads: BTreeMap<u32, Holder>,
}

/// Whose actions a routine acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Target {
    Task,
    /// The guest thread of this port.
    Thread(u32),
}

impl Target {
    fn routine(self, name: &str) -> String {
        match self {
            Self::Task => format!("task_{name}"),
            Self::Thread(_) => format!("thread_{name}"),
        }
    }
}

/// One action group the host kernel reports for a mask.
#[derive(Debug, Clone, Copy)]
struct Group {
    mask: u32,
    name: u32,
    behavior: u32,
    flavor: u32,
}

/// One entry of a reply's arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    mask: u32,
    /// A send right this space holds for the reply, or null or dead.
    name: u32,
    behavior: u32,
    flavor: u32,
}

/// Which port an action names, as XNU compares them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identity {
    Null,
    /// The port of the host's group at this index.
    Group(usize),
    /// A dead port compared by its copied right, which matches nothing.
    Dead(usize),
}

fn valid(name: u32) -> bool {
    name != 0 && name != MACH_PORT_DEAD
}

fn bits(mask: u32) -> impl Iterator<Item = usize> {
    (FIRST_EXCEPTION..EXC_TYPES_COUNT).filter(move |&slot| mask & (1 << slot) != 0)
}

/// The arm64 flavor of the same state as an x86 flavor the host task
/// inherited (`mach/i386/thread_status.h`).
fn arm64_flavor(x86: u32) -> Option<u32> {
    Some(match x86 {
        0 => 0,
        // x86_THREAD_STATE (MACHINE_THREAD_STATE), x86_FLOAT_STATE,
        // x86_EXCEPTION_STATE, x86_DEBUG_STATE.
        7 => 1,
        8 => 2,
        9 => 3,
        12 => 4,
        // THREAD_STATE_NONE.
        13 => 5,
        // The 64-bit thread, exception, debug and float states.
        4 => 6,
        6 => 7,
        11 => 15,
        5 => 17,
        _ => return None,
    })
}

/// The host kernel's action groups of `target`, a task or a thread, for
/// `mask`: each valid port with a send right this space now holds.
fn host_groups(task: bool, target: u32, mask: u32) -> Result<Vec<Group>> {
    let mut masks = [0u32; REPLY_ENTRIES];
    let mut ports = [0u32; REPLY_ENTRIES];
    let mut behaviors = [0u32; REPLY_ENTRIES];
    let mut flavors = [0u32; REPLY_ENTRIES];
    let mut count = REPLY_ENTRIES as u32;
    let get = if task {
        task_get_exception_ports
    } else {
        thread_get_exception_ports
    };
    // SAFETY: arrays of the count passed, in this frame.
    let status = unsafe {
        get(
            target,
            mask,
            masks.as_mut_ptr(),
            &raw mut count,
            ports.as_mut_ptr(),
            behaviors.as_mut_ptr(),
            flavors.as_mut_ptr(),
        )
    };
    if status != 0 {
        bail!("the host's exception actions of {target:#x} could not be read: {status:#x}");
    }
    Ok((0..count as usize)
        .map(|index| Group {
            mask: masks[index],
            name: ports[index],
            behavior: behaviors[index],
            flavor: flavors[index],
        })
        .collect())
}

/// Hold `name` (null, dead or a send right of this space, which stays
/// this space's) for the exception types of `mask` on `holder`: the host
/// kernel's `kern_return_t`. A mask of 0 only checks the port.
fn hold(holder: u32, mask: u32, name: u32) -> u32 {
    // SAFETY: plain values; the kernel copies the send right.
    unsafe { thread_set_exception_ports(holder, mask, name, HELD_BEHAVIOR, 0) as u32 }
}

impl Holder {
    fn new() -> Result<Self> {
        let mut thread = 0u32;
        // SAFETY: an out-parameter in this frame.
        let status = unsafe { thread_create(host::task(), &raw mut thread) };
        if status != 0 {
            bail!("a host thread to hold exception ports could not be created: {status:#x}");
        }
        Ok(Self {
            thread,
            actions: [Action::default(); EXC_TYPES_COUNT],
        })
    }

    /// The task's actions as the host task inherited them.
    fn inherited() -> Result<Self> {
        let mut holder = Self::new()?;
        for group in host_groups(true, host::task(), EXC_MASK_VALID)? {
            let Some(flavor) = arm64_flavor(group.flavor) else {
                release_send(group.name);
                bail!(
                    "the host task inherited exception ports with x86 flavor {} (mask {:#x}), \
                     which has no arm64 counterpart",
                    group.flavor,
                    group.mask
                );
            };
            for slot in bits(group.mask) {
                holder.actions[slot] = Action {
                    behavior: group.behavior,
                    flavor,
                };
            }
            if group.name != 0 {
                let status = hold(holder.thread, group.mask, group.name);
                release_send(group.name);
                if status != 0 {
                    bail!("an inherited exception port could not be held: {status:#x}");
                }
            }
        }
        Ok(holder)
    }

    /// The entries XNU's loop lists for `mask`: one per distinct port,
    /// behavior and flavor, in exception order, each with a send right to
    /// its port. A swap compares each type's copied right, which for a
    /// dead port matches no other (`distinct_dead`).
    fn entries(&self, mask: u32, distinct_dead: bool) -> Result<Vec<Entry>> {
        let groups = host_groups(false, self.thread, mask)?;
        let mut taken = vec![false; groups.len()];
        let mut entries: Vec<(Identity, Entry)> = Vec::new();
        for slot in bits(mask) {
            let bit = 1 << slot;
            let group = groups.iter().position(|group| group.mask & bit != 0);
            let name = group.map_or(0, |group| groups[group].name);
            let identity = match (group, name) {
                (_, 0) | (None, _) => Identity::Null,
                (Some(_), MACH_PORT_DEAD) if distinct_dead => Identity::Dead(slot),
                (Some(group), _) => Identity::Group(group),
            };
            let Action { behavior, flavor } = self.actions[slot];
            if let Some((_, entry)) = entries.iter_mut().find(|(other, entry)| {
                *other == identity && entry.behavior == behavior && entry.flavor == flavor
            }) {
                entry.mask |= bit;
                continue;
            }
            if let Identity::Group(group) = identity
                && valid(name)
            {
                if taken[group] {
                    // SAFETY: one more user reference to a send right
                    // this space holds.
                    unsafe { mach_port_mod_refs(host::task(), name, 0, 1) };
                } else {
                    taken[group] = true;
                }
            }
            entries.push((
                identity,
                Entry {
                    mask: bit,
                    name,
                    behavior,
                    flavor,
                },
            ));
        }
        for (group, taken) in groups.iter().zip(taken) {
            if !taken {
                release_send(group.name);
            }
        }
        Ok(entries.into_iter().map(|(_, entry)| entry).collect())
    }
}

impl ExceptionPorts {
    fn lock(&self) -> MutexGuard<'_, State> {
        lock(&self.0)
    }

    /// Held across a host `fork`, so that the child finds it free.
    pub(crate) fn hold_for_fork(&self) -> Option<ForkHeld<'_>> {
        try_lock(&self.0).map(ForkHeld)
    }

    /// Whether a new process would inherit this one's actions as the host
    /// task holds them; otherwise the run stops naming `call`.
    pub(crate) fn inheritable(&self, call: &str) -> Result<()> {
        if self.lock().changed {
            bail!(
                "{call} after this process set its task exception ports: the new process would \
                 not inherit them, which is not implemented"
            );
        }
        Ok(())
    }

    /// Stop the run if the thread `thread` or its task holds a port for
    /// `exception`, which XNU would deliver to it before any signal.
    pub(crate) fn deliverable(&self, thread: u32, exception: usize) -> Result<()> {
        let state = self.lock();
        let mut groups = match state.threads.get(&thread) {
            Some(holder) => host_groups(false, holder.thread, 1 << exception)?,
            None => Vec::new(),
        };
        groups.extend(match &state.task {
            Some(holder) => host_groups(false, holder.thread, 1 << exception)?,
            None => host_groups(true, host::task(), 1 << exception)?,
        });
        let held = groups.iter().any(|group| valid(group.name));
        for group in &groups {
            release_send(group.name);
        }
        if held {
            bail!(
                "{} with an exception port set for it: Mach exception delivery is not implemented",
                NAMES[exception]
            );
        }
        Ok(())
    }

    /// The guest thread of port `thread` ended: its actions' rights are
    /// released (`ipc_thread_terminate`).
    pub(crate) fn thread_ended(&self, thread: u32) {
        if let Some(holder) = self.lock().threads.remove(&thread) {
            // SAFETY: the holder thread never started; ending it releases
            // the rights its exception ports hold.
            unsafe { thread_terminate(holder.thread) };
        }
    }
}

/// `_TASK_EXC_GUARD_ALL_FATAL`: delivered, fatal Mach port and VM guard
/// exceptions, the release kernel's `task_exc_guard_default`.
const EXC_GUARD_ALL_FATAL: u32 = 0x99;

/// `task_set_exc_guard_default` at exec: a platform-restricted task's
/// EXC_GUARD behavior is the release default, any other's the third-party
/// default, none, which the host task (a third-party process's) already
/// has. The host kernel raises the guard exceptions of the calls it
/// serves, so the host task takes the arm64 task's behavior, which the
/// forwarded `task_get_exc_guard_behavior` then reports.
pub(crate) fn set_guard_default(restricted: bool) {
    unsafe extern "C" {
        fn task_set_exc_guard_behavior(task: u32, behavior: u32) -> i32;
    }
    if restricted {
        // SAFETY: plain values for this task.
        unsafe { task_set_exc_guard_behavior(host::task(), EXC_GUARD_ALL_FATAL) };
    }
}

/// The actions held across a host `fork`.
pub(crate) struct ForkHeld<'a>(MutexGuard<'a, State>);

impl ForkHeld<'_> {
    /// In the child, whose host task inherited the host actions and none
    /// of the parent's holder threads: the inherited actions, read anew.
    pub(crate) fn child(mut self) {
        *self.0 = State::default();
    }
}

/// `set_exception_ports_validation` for this task and the carried `name`,
/// then `set_exception_behavior_allowed`.
fn validate(
    kernel: &Kernel,
    routine: &str,
    holder: u32,
    mask: u32,
    name: u32,
    behavior: u32,
    flavor: u32,
) -> Result<std::result::Result<(), u32>> {
    if mask & !EXC_MASK_VALID != 0 {
        return Ok(Err(KERN_INVALID_ARGUMENT));
    }
    let base = behavior & !MACH_EXCEPTION_MASK;
    if valid(name) && !(EXCEPTION_DEFAULT..=EXCEPTION_STATE_IDENTITY_PROTECTED).contains(&base) {
        return Ok(Err(KERN_INVALID_ARGUMENT));
    }
    // `ipc_is_valid_exception_port`: the host kernel's own check, through
    // the holder with no exception type.
    if valid(name) {
        match hold(holder, 0, name) {
            0 => {}
            KERN_INVALID_RIGHT => return Ok(Err(KERN_INVALID_RIGHT)),
            status => bail!("an exception port could not be checked: {status:#x}"),
        }
    }
    if flavor != 0 && !VALID_FLAVORS.contains(&flavor) {
        return Ok(Err(KERN_INVALID_ARGUMENT));
    }
    if (base == EXCEPTION_IDENTITY_PROTECTED || behavior & MACH_EXCEPTION_BACKTRACE_PREFERRED != 0)
        && behavior & MACH_EXCEPTION_CODES == 0
    {
        return Ok(Err(KERN_INVALID_ARGUMENT));
    }
    let executable = lock(&kernel.process.executable);
    let Some(signature) = executable.signature.as_ref() else {
        return Ok(Ok(()));
    };
    if signature.entitled(SET_EXCEPTION_ENTITLEMENT) || !signature.platform_restricted() {
        return Ok(Ok(()));
    }
    // A platform-restricted task's space takes `IPC_POLICY_ENHANCED_V1`.
    let protected = matches!(
        base,
        EXCEPTION_IDENTITY_PROTECTED | EXCEPTION_STATE | EXCEPTION_STATE_IDENTITY_PROTECTED
    );
    if signature.entitled(ONLY_ONE_EXCEPTION_PORT) || (valid(name) && !protected) {
        bail!(
            "{routine}: behavior {behavior:#x} breaks this platform-restricted task's exception \
             policy: the KERN_DENIED and fatal EXC_GUARD (kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE) \
             are not implemented"
        );
    }
    Ok(Ok(()))
}

/// The request's one port descriptor, carried in as the kernel copies the
/// request in: the send right's name (which the caller releases, as the
/// kernel consumes it), or the reply when the request fails first.
pub(super) fn carried_send(
    kernel: &mut Kernel,
    routine: &str,
    request: &Request,
    body_bytes: usize,
) -> Result<std::result::Result<u32, Reply>> {
    const PORT_DESCRIPTOR: u8 = 0;
    let (Some(1), Some(name), Some(&disposition), Some(&PORT_DESCRIPTOR)) = (
        request.word(0),
        request.word(4),
        request.body.get(14),
        request.body.get(15),
    ) else {
        bail!("{routine}: a request without its one port descriptor is not implemented");
    };
    let (name, received) = match super::message::carry_port(kernel, routine, name, disposition)? {
        Ok(carried) => carried,
        Err(status) => return Ok(Err(Reply::NotSent(status))),
    };
    if received != MOVE_SEND {
        match received {
            PORT_RECEIVE => {
                // SAFETY: the carried receive right, which this space now
                // holds; destroying the request destroys it.
                unsafe { mach_port_mod_refs(host::task(), name, 1, -1) };
            }
            PORT_SEND_ONCE => release_send(name),
            _ => {}
        }
        return Ok(Err(Reply::Failure(MIG_TYPE_ERROR)));
    }
    if request.body.len() != body_bytes {
        release_send(name);
        return Ok(Err(Reply::Failure(MIG_BAD_ARGUMENTS)));
    }
    Ok(Ok(name))
}

/// The reply of `task_get_exception_ports` and `task_swap_exception_ports`:
/// 32 port descriptors, then the count and the masks, behaviors and
/// flavors arrays, each of the count.
fn ports_reply(entries: &[Entry]) -> Reply {
    let mut descriptors: Vec<Descriptor> = entries
        .iter()
        .map(|entry| Descriptor::Port {
            name: entry.name,
            disposition: MOVE_SEND,
        })
        .collect();
    descriptors.resize(
        REPLY_ENTRIES,
        Descriptor::Port {
            name: 0,
            disposition: MOVE_SEND,
        },
    );
    let mut body = (entries.len() as u32).to_le_bytes().to_vec();
    for field in [
        |entry: &Entry| entry.mask,
        |entry: &Entry| entry.behavior,
        |entry: &Entry| entry.flavor,
    ] {
        for entry in entries {
            body.extend(field(entry).to_le_bytes());
        }
    }
    Reply::Complex { descriptors, body }
}

/// The task's holder, created from the inherited actions at first use.
fn task_holder<'a>(state: &'a mut MutexGuard<'_, State>) -> Result<&'a mut Holder> {
    if state.task.is_none() {
        state.task = Some(Holder::inherited()?);
    }
    Ok(state.task.as_mut().expect("just created"))
}

/// `set_exception_ports(new_port; exception_mask, behavior, new_flavor)`
/// of the task or a thread, or `swap_exception_ports`, whose reply also
/// lists the replaced actions.
pub(super) fn set(
    kernel: &mut Kernel,
    request: &Request,
    swap: bool,
    target: Target,
) -> Result<Reply> {
    let routine = target.routine(if swap {
        "swap_exception_ports"
    } else {
        "set_exception_ports"
    });
    // The descriptor count, the descriptor, the NDR record, three words.
    let name = match carried_send(kernel, &routine, request, 36)? {
        Ok(name) => name,
        Err(reply) => return Ok(reply),
    };
    let reply = set_carried(kernel, &routine, request, swap, name, target);
    release_send(name);
    reply
}

fn set_carried(
    kernel: &Kernel,
    routine: &str,
    request: &Request,
    swap: bool,
    name: u32,
    target: Target,
) -> Result<Reply> {
    let (Some(mask), Some(behavior), Some(flavor)) =
        (request.word(24), request.word(28), request.word(32))
    else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    let ports = &kernel.process.exception_ports;
    let mut state = ports.lock();
    // The task's holder checks the port, so that a thread without actions
    // keeps none when the check fails.
    let checker = task_holder(&mut state)?.thread;
    if let Err(code) = validate(kernel, routine, checker, mask, name, behavior, flavor)? {
        return Ok(Reply::Failure(code));
    }
    let holder = match target {
        Target::Task => task_holder(&mut state)?,
        Target::Thread(port) => match state.threads.entry(port) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => entry.insert(Holder::new()?),
        },
    };
    let replaced = if swap {
        Some(holder.entries(mask, true)?)
    } else {
        None
    };
    let status = hold(holder.thread, mask, name);
    if status != 0 {
        for entry in replaced.iter().flatten() {
            release_send(entry.name);
        }
        // The sandbox's `mac_task_check_set_*_exception_ports`.
        return Ok(Reply::Failure(status));
    }
    for slot in bits(mask) {
        holder.actions[slot] = Action { behavior, flavor };
    }
    if mask != 0 && target == Target::Task {
        state.changed = true;
    }
    Ok(match replaced {
        Some(entries) => ports_reply(&entries),
        None => Reply::Success(Vec::new()),
    })
}

/// The holder of `target`'s actions, if it has any.
fn holder<'a>(state: &'a mut MutexGuard<'_, State>, target: Target) -> Result<Option<&'a Holder>> {
    Ok(match target {
        Target::Task => Some(task_holder(state)?),
        Target::Thread(port) => state.threads.get(&port),
    })
}

/// `get_exception_ports_from_user(exception_mask)` of the task or a thread.
pub(super) fn get(kernel: &Kernel, request: &Request, target: Target) -> Result<Reply> {
    let (Some(mask), 12) = (request.word(8), request.body.len()) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    if mask & !EXC_MASK_VALID != 0 {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    let mut state = kernel.process.exception_ports.lock();
    let entries = match holder(&mut state, target)? {
        Some(holder) => holder.entries(mask, false)?,
        None => Vec::new(),
    };
    Ok(ports_reply(&entries))
}

/// `get_exception_ports_info(exception_mask)` of the task or a thread:
/// each entry's port and receiving task as the host kernel hashes them
/// (`VM_KERNEL_ADDRHASH`), for the same ports.
pub(super) fn info(kernel: &Kernel, request: &Request, target: Target) -> Result<Reply> {
    let (Some(mask), 12) = (request.word(8), request.body.len()) else {
        return Ok(Reply::Failure(MIG_BAD_ARGUMENTS));
    };
    if mask & !EXC_MASK_VALID != 0 {
        return Ok(Reply::Failure(KERN_INVALID_ARGUMENT));
    }
    let mut state = kernel.process.exception_ports.lock();
    let Some(holder) = holder(&mut state, target)? else {
        return Ok(Reply::Success(0u32.to_le_bytes().to_vec()));
    };
    let mut masks = [0u32; REPLY_ENTRIES];
    let mut hashes = [[0u32; 2]; REPLY_ENTRIES];
    let mut behaviors = [0u32; REPLY_ENTRIES];
    let mut flavors = [0u32; REPLY_ENTRIES];
    let mut count = REPLY_ENTRIES as u32;
    // SAFETY: arrays of the count passed, in this frame.
    let status = unsafe {
        thread_get_exception_ports_info(
            holder.thread,
            mask,
            masks.as_mut_ptr(),
            &raw mut count,
            hashes.as_mut_ptr(),
            behaviors.as_mut_ptr(),
            flavors.as_mut_ptr(),
        )
    };
    if status != 0 {
        bail!("the held exception ports' information could not be read: {status:#x}");
    }
    let groups = &masks[..count as usize];
    // XNU's loop over the types, comparing each type's port pointer.
    let mut entries: Vec<(Option<usize>, u32, [u32; 2], Action)> = Vec::new();
    for slot in bits(mask) {
        let bit = 1 << slot;
        let group = groups
            .iter()
            .position(|mask| mask & bit != 0)
            .filter(|&group| hashes[group][0] != 0);
        let hash = group.map_or([0, 0], |group| hashes[group]);
        let action = holder.actions[slot];
        match entries
            .iter_mut()
            .find(|(other, _, _, other_action)| *other == group && *other_action == action)
        {
            Some(entry) => entry.1 |= bit,
            None => entries.push((group, bit, hash, action)),
        }
    }
    let mut body = (entries.len() as u32).to_le_bytes().to_vec();
    for (_, mask, _, _) in &entries {
        body.extend(mask.to_le_bytes());
    }
    for (_, _, [port, receiver], _) in &entries {
        body.extend(port.to_le_bytes());
        body.extend(receiver.to_le_bytes());
    }
    for (_, _, _, action) in &entries {
        body.extend(action.behavior.to_le_bytes());
    }
    for (_, _, _, action) in &entries {
        body.extend(action.flavor.to_le_bytes());
    }
    Ok(Reply::Success(body))
}

/// `thread_adopt_exception_handler(exc_port; exc_mask, behavior_mask,
/// flavor_mask)`: a task's exception ports are frozen only by
/// `task_register_hardened_exception_handler`, which stops the run, so
/// adoption is refused (`KERN_DENIED`), the port released.
pub(super) fn adopt(kernel: &mut Kernel, request: &Request) -> Result<Reply> {
    let name = match carried_send(kernel, "thread_adopt_exception_handler", request, 36)? {
        Ok(name) => name,
        Err(reply) => return Ok(reply),
    };
    release_send(name);
    Ok(Reply::Failure(KERN_DENIED))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive_right() -> u32 {
        unsafe extern "C" {
            fn mach_port_allocate(task: u32, right: u32, name: *mut u32) -> i32;
            fn mach_port_insert_right(task: u32, name: u32, port: u32, disposition: u32) -> i32;
        }
        let mut name = 0u32;
        // SAFETY: an out-parameter in this frame; a send right made from
        // the new receive right.
        unsafe {
            assert_eq!(mach_port_allocate(host::task(), 1, &raw mut name), 0);
            assert_eq!(mach_port_insert_right(host::task(), name, name, 20), 0);
        }
        name
    }

    fn send_refs(name: u32) -> u32 {
        unsafe extern "C" {
            fn mach_port_get_refs(task: u32, name: u32, right: u32, refs: *mut u32) -> i32;
        }
        let mut refs = 0u32;
        // SAFETY: an out-parameter in this frame.
        unsafe { mach_port_get_refs(host::task(), name, 0, &raw mut refs) };
        refs
    }

    #[test]
    fn inherited_flavors_are_restated_as_arm64_states() {
        assert_eq!(arm64_flavor(13), Some(5));
        assert_eq!(arm64_flavor(4), Some(6));
        assert_eq!(arm64_flavor(7), Some(1));
        assert_eq!(arm64_flavor(0), Some(0));
        assert_eq!(arm64_flavor(25), None);
    }

    #[test]
    fn a_holder_lists_its_actions_as_xnu_merges_them() {
        let mut holder = Holder::new().unwrap();
        let port = receive_right();
        let mask = (1 << EXC_BAD_ACCESS) | (1 << EXC_BREAKPOINT) | (1 << 10);
        assert_eq!(hold(holder.thread, mask, port), 0);
        for slot in bits(mask) {
            holder.actions[slot] = Action {
                behavior: EXCEPTION_DEFAULT,
                flavor: 6,
            };
        }
        // EXC_CRASH's action differs only in behavior: its own entry.
        holder.actions[10].behavior = EXCEPTION_STATE;
        // The held rights are outside this space's references.
        assert_eq!(send_refs(port), 1);
        let entries = holder.entries(EXC_MASK_VALID, false).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            Entry {
                mask: (1 << EXC_BAD_ACCESS) | (1 << EXC_BREAKPOINT),
                name: port,
                behavior: EXCEPTION_DEFAULT,
                flavor: 6
            }
        );
        // The null actions of every other type, then EXC_CRASH's.
        assert_eq!(entries[1].name, 0);
        assert_eq!(
            entries[1].mask,
            EXC_MASK_VALID & !mask,
            "the unheld types form one null entry"
        );
        assert_eq!((entries[2].mask, entries[2].name), (1 << 10, port));
        // One reference for each entry naming the port.
        assert_eq!(send_refs(port), 3);
        release_send(port);
        release_send(port);
        // A kernel object is not a valid exception port.
        assert_eq!(hold(holder.thread, 0, host::task()), KERN_INVALID_RIGHT);
    }

    #[test]
    fn get_replies_carry_32_port_descriptors() {
        let entries = [Entry {
            mask: 2,
            name: 0,
            behavior: EXCEPTION_DEFAULT,
            flavor: 5,
        }];
        let Reply::Complex { descriptors, body } = ports_reply(&entries) else {
            panic!("a complex reply");
        };
        assert_eq!(descriptors.len(), REPLY_ENTRIES);
        let words: Vec<u32> = body
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect();
        assert_eq!(words, [1, 2, EXCEPTION_DEFAULT, 5]);
    }
}
