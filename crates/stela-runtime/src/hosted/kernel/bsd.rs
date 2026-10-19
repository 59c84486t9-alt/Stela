//! BSD system calls: decoded as XNU `bsd/dev/arm/systemcalls.c`
//! `unix_syscall` decodes them, bound by name to the pinned catalog, and
//! completed with its return munging.
//!
//! A call whose arguments and effects are the same in the x86-64 and arm64
//! LP64 ABIs, and which acts only on this process's own resources, is
//! forwarded to the host kernel unchanged ([`forwarded`]): guest pointers are
//! host pointers here and both kernels munge results alike. Calls whose
//! meaning depends on the CPU, the page size, the clock or the execution
//! state are serviced by their family. Everything else stops the process
//! naming the call.
use super::{Kernel, Pe, Trap};
use crate::darwin::{BsdReturnType, catalog};
use crate::hosted::forward;
use anyhow::{Result, bail};

mod codesign;
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
pub(super) mod sysctl;
pub(super) mod thread;
mod time;
pub(super) mod workqueue;

pub use codesign::Signature;

/// `ENOSYS`, for numbers past the table and its reserved rows.
pub(super) const ENOSYS: u64 = 78;
const ENOSYS_ROUTINE: &str = "enosys";
pub(super) const EINVAL: u64 = 22;
pub(super) const EFAULT: u64 = 14;
pub(crate) const ENOMEM: u64 = 12;
pub(super) const ENOENT: u64 = 2;
pub(super) const EPERM: u64 = 1;
pub(crate) const EAGAIN: u64 = 35;

/// How a call completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    /// `uu_rval[0..2]` already munged to X0 and X1.
    Return(u64, u64),
    Error(u64),
    /// Leave every register as the handler set it (`EJUSTRETURN`).
    JustReturn,
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

/// Forward `call` to the host kernel.
pub(super) fn forward(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    kernel.page_in_arguments(call.arguments())?;
    let returned = forward::bsd(call.entry.number, call.arguments());
    Ok(if returned.carry {
        Outcome::Error(returned.rax)
    } else {
        Outcome::Return(returned.rax, returned.rdx)
    })
}

pub(super) fn call(kernel: &mut Kernel, pe: &mut Pe) -> Result<()> {
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
    let mut trap = Trap { cpu: &mut pe.cpu };
    trap.set_carry(false);
    let entry = catalog::entry(number);
    let Some(entry) = entry.filter(|entry| entry.prototype().is_some()) else {
        // `enosys` rows fail quietly; `nosys` and numbers past the table
        // also raise SIGSYS (`bsd/kern/kern_sig.c` `nosys`).
        if entry.is_some_and(|entry| entry.name == ENOSYS_ROUTINE) {
            return complete(&mut trap, BsdReturnType::Int, Outcome::Error(ENOSYS));
        }
        bail!("BSD system call {number} is unassigned: SIGSYS delivery is not implemented");
    };
    let call = Call { entry, arguments };
    kernel.count(entry.name);
    let outcome = dispatch(kernel, pe, &call)?;
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
    }
    Ok(())
}

fn dispatch(kernel: &mut Kernel, pe: &mut Pe, call: &Call) -> Result<Outcome> {
    let name = call.entry.name;
    if let Some(outcome) = paths::call(kernel, call)? {
        return Ok(outcome);
    }
    if let Some(outcome) = signatures::call(kernel, call)? {
        return Ok(outcome);
    }
    if forwarded::forwarded(name) {
        return forward(kernel, call);
    }
    if let Some(outcome) = process::call(kernel, pe, call)? {
        return Ok(outcome);
    }
    if let Some(outcome) = memory::call(kernel, pe, call)? {
        return Ok(outcome);
    }
    if let Some(outcome) = time::call(kernel, call)? {
        return Ok(outcome);
    }
    if let Some(outcome) = sysctl::call(kernel, call)? {
        return Ok(outcome);
    }
    if let Some(outcome) = codesign::call(kernel, call)? {
        return Ok(outcome);
    }
    if let Some(outcome) = thread::call(kernel, pe, call)? {
        return Ok(outcome);
    }
    if let Some(outcome) = workqueue::call(kernel, pe, call)? {
        return Ok(outcome);
    }
    if let Some(outcome) = signal::call(kernel, call)? {
        return Ok(outcome);
    }
    bail!(
        "BSD system call {name} ({}) is not implemented by the hosted kernel (arguments {:x?})",
        call.entry.number,
        call.arguments()
    )
}
