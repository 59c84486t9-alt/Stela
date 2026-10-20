//! BSD system calls: decoded as XNU `bsd/dev/arm/systemcalls.c`
//! `unix_syscall` decodes them, bound by name to the pinned catalog, and
//! completed with its return munging.
//!
//! A call whose arguments and effects are the same in the x86-64 and arm64
//! LP64 ABIs, and which acts only on this process's own resources, is
//! forwarded to the host kernel unchanged ([`forwarded`]): guest pointers are
//! host pointers here and both kernels munge results alike. Calls whose
//! meaning depends on the CPU, the page size, the clock or the execution
//! state are serviced by their family. A call no family services, or an
//! unsupported request of one, fails as XNU fails it and is reported
//! ([`unsupported`]): an unknown call with `nosys`, an unsupported flavor
//! or option with the call's own error.
use crate::hosted::darwin::{EINTR, ENOSYS};
use crate::hosted::unsupported::{self, Failure, Kind};
// Kept for the MIG routines that still name it through this module.
use super::{Kernel, Pe, Trap};
use crate::darwin::{BsdReturnType, catalog};
use crate::hosted::forward;
use crate::machine::system::Register;
use anyhow::Result;

pub(super) mod additions;
pub(super) mod aio;
mod codesign;
pub(super) mod files;
mod fork;
mod forwarded;
pub(super) mod kqworkloop;
pub(super) mod kqworkq;
mod linking;
mod memory;
mod paths;
mod priority;
mod process;
pub(super) mod signal;
pub(super) mod signatures;
mod spawn;
pub(super) mod sysctl;
mod system;
pub(super) mod thread;
mod time;
mod timer;
pub(super) mod workqueue;

pub use codesign::Signature;

/// `ENOSYS`, for numbers past the table and its reserved rows.
const ENOSYS_ROUTINE: &str = "enosys";

/// How a call completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    /// `uu_rval[0..2]` already munged to X0 and X1.
    Return(u64, u64),
    Error(u64),
    /// Leave every register as the handler set it (`EJUSTRETURN`).
    JustReturn,
    /// Repeat the call once the thread's signals are delivered
    /// (`ERESTART`).
    Restart,
}

impl Outcome {
    pub(super) fn value(value: u64) -> Self {
        Self::Return(value, 0)
    }
}

/// One decoded call: its catalog row and argument registers.
pub(super) struct Call {
    pub(super) entry: &'static catalog::CatalogEntry,
    pub(super) arguments: [u64; forward::MAX_ARGUMENTS],
}

impl Call {
    pub(super) fn argument(&self, index: usize) -> u64 {
        self.arguments[index]
    }

    pub(super) fn arguments(&self) -> &[u64] {
        &self.arguments[..self.entry.argument_count]
    }
}

/// A call's number in the pinned catalog.
pub(super) fn number_of(name: &str) -> u16 {
    (0..=u16::MAX)
        .map_while(catalog::entry)
        .find(|entry| entry.name == name)
        .map(|entry| entry.number)
        .expect("the call is in the pinned catalog")
}

/// Forward `call` to the host kernel, interruptibly: a signal for the
/// thread's guest handlers that arrives before the host kernel takes the
/// call, or for which the host kernel would restart it, makes the guest
/// repeat it after its handler runs.
pub(super) fn forward(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    kernel.page_in_arguments(call.arguments())?;
    let interrupt = kernel.signals.interrupt_flag();
    // A terminated thread never sees the outcome.
    Ok(kernel
        .forwarding(|| forward::bsd_interruptible(call.entry.number, call.arguments(), interrupt))
        .map_or(Outcome::Error(EINTR), outcome))
}

/// Forward `call` to the host kernel uninterruptibly, for a model whose
/// effects before the call a repeat would duplicate.
pub(super) fn forward_uninterruptible(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    kernel.page_in_arguments(call.arguments())?;
    Ok(kernel
        .forwarding(|| forward::bsd(call.entry.number, call.arguments()))
        .map_or(Outcome::Error(EINTR), outcome))
}

fn outcome(returned: forward::Returned) -> Outcome {
    match returned {
        forward::Returned {
            carry: true,
            rax: forward::ERESTART,
            ..
        } => Outcome::Restart,
        forward::Returned {
            carry: true, rax, ..
        } => Outcome::Error(rax),
        forward::Returned { rax, rdx, .. } => Outcome::Return(rax, rdx),
    }
}

pub(super) fn call(kernel: &mut Kernel, pe: &mut Pe) -> Result<()> {
    // The SVC, before the return address.
    let pc = pe.cpu.read(Register::ELR_EL1).wrapping_sub(4);
    let registers = &pe.cpu.state.x;
    // A zero X16 is the indirect call: its number is X0 and its arguments
    // start at X1.
    let indirect = registers[16] == 0;
    let number = if indirect {
        registers[0]
    } else {
        registers[16]
    } as u16;
    let start = usize::from(indirect);
    let mut arguments = [0u64; forward::MAX_ARGUMENTS];
    arguments.copy_from_slice(&registers[start..start + forward::MAX_ARGUMENTS]);
    Trap { cpu: &mut pe.cpu }.set_carry(false);
    // The 26A434 additions lie at numbers the pinned catalog reserves.
    if let Some(name) = additions::addition(number) {
        kernel.count(name);
        let (return_type, outcome) = match additions::call(kernel, pe, number, name, &arguments) {
            Ok(serviced) => serviced,
            Err(error) => (
                BsdReturnType::Int,
                failed(unsupported::recover(error, Kind::BsdCall, pc, None)?),
            ),
        };
        if kernel.trace {
            eprintln!("stela: bsd {name}({arguments:x?}) = {outcome:x?}");
        }
        if kernel.end.is_some() {
            return Ok(());
        }
        return complete(&mut Trap { cpu: &mut pe.cpu }, return_type, outcome);
    }
    let mut trap = Trap { cpu: &mut pe.cpu };
    let entry = catalog::entry(number);
    let Some(entry) = entry.filter(|entry| entry.prototype().is_some()) else {
        // `enosys` rows fail quietly; `nosys` and numbers past the table
        // also raise SIGSYS (`bsd/kern/kern_sig.c` `nosys`).
        let outcome = if entry.is_some_and(|entry| entry.name == ENOSYS_ROUTINE) {
            Outcome::Error(ENOSYS)
        } else {
            nosys()
        };
        if kernel.trace {
            eprintln!("stela: bsd {number}({arguments:x?}) = {outcome:x?}");
        }
        return complete(&mut trap, BsdReturnType::Int, outcome);
    };
    let call = Call { entry, arguments };
    kernel.count(entry.name);
    let outcome = match dispatch(kernel, pe, &call) {
        Ok(outcome) => outcome,
        Err(error) => failed(unsupported::recover(error, Kind::BsdCall, pc, None)?),
    };
    if kernel.trace {
        eprintln!(
            "stela: bsd {}({}) = {outcome:x?}",
            entry.name,
            call.arguments()
                .iter()
                .map(|a| format!("{a:#x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if kernel.end.is_some() {
        return Ok(());
    }
    complete(&mut Trap { cpu: &mut pe.cpu }, entry.return_type, outcome)
}

/// XNU's `nosys`: SIGSYS to the calling thread, whose disposition acts on
/// it, and ENOSYS.
fn nosys() -> Outcome {
    super::signals::raise(signal::SIGSYS as i32);
    Outcome::Error(ENOSYS)
}

/// What a refused call returns.
fn failed(failure: Failure) -> Outcome {
    match failure {
        Failure::Errno(errno) => Outcome::Error(errno),
        _ => nosys(),
    }
}

/// `arm_prepare_u64_syscall_return`: an error sets X0 to the errno, X1 to
/// zero and the carry; a result writes X0 and X1 unless the call returns
/// nothing.
fn complete(trap: &mut Trap, return_type: BsdReturnType, outcome: Outcome) -> Result<()> {
    match outcome {
        Outcome::Return(first, second) => {
            if return_type != BsdReturnType::None {
                trap.set_x(0, first);
                trap.set_x(1, second);
            }
        }
        Outcome::Error(errno) => {
            trap.set_x(0, errno);
            trap.set_x(1, 0);
            trap.set_carry(true);
        }
        Outcome::JustReturn => {}
        // `arm_prepare_syscall_return`: back to the SVC.
        Outcome::Restart => {
            let elr = trap.cpu.read(Register::ELR_EL1);
            trap.cpu.registers.set_raw(Register::ELR_EL1, 0, elr - 4);
        }
    }
    Ok(())
}

/// Who services a BSD call: the host kernel unchanged, or one family of
/// the hosted kernel's own models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    Forwarded,
    Process,
    Memory,
    Time,
    Sysctl,
    CodeSigning,
    Threads,
    Workqueue,
    Signals,
    System,
    Files,
    AsynchronousIo,
    Additions,
}

impl Family {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Process => "process",
            Self::Memory => "memory",
            Self::Time => "time",
            Self::Sysctl => "sysctl",
            Self::CodeSigning => "code signing",
            Self::Threads => "threads",
            Self::Workqueue => "workqueue",
            Self::Signals => "signals",
            Self::System => "system",
            Self::Files => "descriptor table",
            Self::AsynchronousIo => "asynchronous I/O",
            Self::Additions => "26A434 additions",
        }
    }
}

/// The modeled families and the calls each services.
const MODELED: &[(Family, &[&str])] = &[
    (Family::Process, process::CALLS),
    (Family::Memory, memory::CALLS),
    (Family::Time, time::CALLS),
    (Family::Sysctl, sysctl::CALLS),
    (Family::CodeSigning, codesign::CALLS),
    (Family::Threads, thread::CALLS),
    (Family::Workqueue, workqueue::CALLS),
    (Family::Signals, signal::CALLS),
    (Family::System, system::CALLS),
    (Family::Files, files::CALLS),
    (Family::AsynchronousIo, aio::CALLS),
];

/// The family servicing the call `name`, or `None` for a call the hosted
/// kernel refuses.
pub(crate) fn family(name: &str) -> Option<Family> {
    if forwarded::forwarded(name) {
        return Some(Family::Forwarded);
    }
    MODELED
        .iter()
        .find(|(_, calls)| calls.contains(&name))
        .map(|&(family, _)| family)
}

/// The calls whose forwarding a model of part of their arguments
/// precedes, with that model: guest-root path resolution and file code
/// signatures.
pub(crate) fn overlay(name: &str) -> Option<&'static str> {
    if signatures::CALLS.contains(&name) {
        Some(signatures::OVERLAY)
    } else if aio::CLOSING.contains(&name) {
        Some(aio::OVERLAY)
    } else if paths::overlays(name) {
        Some(paths::OVERLAY)
    } else {
        None
    }
}

/// Calls serviced with a named limit: what of the arm64 kernel's contract
/// the hosted kernel does not provide.
pub(crate) const LIMITS: &[(&str, &str)] = &[
    (
        "ptrace",
        "PT_STEP fails with EINVAL and is reported: the host would single-step the target's x86 \
         host thread",
    ),
    (
        "sigaction",
        "a caught signal reaches a thread waiting in a Mach trap or a hosted-kernel wait only \
         when the wait ends",
    ),
    (
        "sigprocmask",
        "another thread's host mask follows at its next kernel exit or time slice",
    ),
    (
        "posix_spawn",
        "binary preferences naming an x86-64 slice fail with EBADARCH and are reported: the \
         slice runs under Rosetta on Apple silicon, and running it natively would show it the \
         x86 host instead; an exception-port action fails with EINVAL",
    ),
    (
        "vfork",
        "the child has its own copy of memory, not the parent's",
    ),
    (
        "mremap_encrypted",
        "decrypting a range fails with ENOTSUP, as XNU without a text crypter, and is \
         reported: the text crypter is Apple silicon's FairPlay kernel extension, which the host does not provide for arm64 images; an address with no guest \
         file mapping at or above it can find one of the hosted runtime's own",
    ),
    (
        "kqueue_workloop_ctl",
        "a workloop's fixed priority, policy and CPU limit are not applied to its servicer, \
         which is scheduled by QoS; a work interval or a bound thread fails with EINVAL and \
         is reported",
    ),
];

/// Calls the hosted kernel refuses, stopping the run with the reason.
pub(crate) const REFUSED: &[(&str, &str)] = &[];

fn dispatch(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Outcome> {
    let name = call.entry.name;
    let gated = files::gated(call).then(|| kernel.process.clone());
    let _gate = gated.as_ref().map(|process| process.files.gate());
    aio::closing(kernel, call);
    if let Some(outcome) = paths::call(kernel, call)? {
        return Ok(outcome);
    }
    if let Some(outcome) = signatures::call(kernel, call)? {
        return Ok(outcome);
    }
    let outcome = match family(name) {
        Some(Family::Forwarded) => Some(forward(kernel, call)?),
        Some(Family::Process) => process::call(kernel, pe, call)?,
        Some(Family::Memory) => memory::call(kernel, pe, call)?,
        Some(Family::Time) => time::call(kernel, call)?,
        Some(Family::Sysctl) => sysctl::call(kernel, call)?,
        Some(Family::CodeSigning) => codesign::call(kernel, call)?,
        Some(Family::Threads) => thread::call(kernel, pe, call)?,
        Some(Family::Workqueue) => workqueue::call(kernel, pe, call)?,
        Some(Family::Signals) => signal::call(kernel, pe, call)?,
        Some(Family::System) => system::call(kernel, call)?,
        Some(Family::Files) => files::call(kernel, call)?,
        Some(Family::AsynchronousIo) => aio::call(kernel, call)?,
        // The additions have no catalog row: [`call`] dispatches them by
        // number.
        Some(Family::Additions) | None => None,
    };
    let Some(outcome) = outcome else {
        let reason = REFUSED
            .iter()
            .find(|(refused, _)| *refused == name)
            .map_or("no family services it", |&(_, reason)| reason);
        unsupported::refuse!(
            Failure::Nosys,
            "BSD system call {name} ({}) is not implemented by the hosted kernel: {reason} \
             (arguments {:x?})",
            call.entry.number,
            call.arguments()
        );
    };
    Ok(outcome)
}
