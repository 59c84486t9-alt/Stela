//! The Darwin kernel personality of the hosted process: every exception the
//! guest thread takes from EL0 arrives here, at the EL1 vector the host
//! stops at, and leaves through the exception return XNU would perform.
//!
//! `SVC` dispatches as XNU `osfmk/arm64/sleh.c` `handle_svc` does on X16:
//! `0x80000000` is the platform call, other negative values are Mach traps
//! (`-3` and `-4` the fast time traps), and the rest BSD system calls. Each
//! family binds its calls by name to the pinned catalogs
//! ([`crate::darwin::catalog`], [`crate::mach::catalog`]); a call no family
//! implements stops the process with its name rather than returning a
//! made-up result.
use super::{
    Termination, forward, hardware::Hardware, host::ProcessHost, shared_region::SharedRegion,
};
use crate::{
    machine::{Cpu, Machine, NoDevices, system::Register},
    pauth,
};
use anyhow::{Result, bail};
use std::collections::BTreeMap;

mod bsd;
mod mach;
mod platform;

pub use bsd::Signature;

pub(super) type Pe = Machine<ProcessHost, NoDevices>;

/// ESR_EL1 exception classes the personality handles.
const EC_SHIFT: u32 = 26;
const ISS_MASK: u64 = (1 << 25) - 1;
const EC_SVC64: u64 = 0x15;
const EC_INSTRUCTION_ABORT_LOWER: u64 = 0x20;
const EC_DATA_ABORT_LOWER: u64 = 0x24;
/// SPSR's C flag, which a BSD call's error sets (`PSR64_CF`).
const SPSR_CARRY: u64 = 1 << 29;
/// `PLATFORM_SYSCALL_TRAP_NO`.
const PLATFORM_CALL: i32 = i32::MIN;

/// The executable's kernel-side identity.
#[derive(Debug, Clone, Default)]
pub struct Executable {
    pub path: Vec<u8>,
    /// The process's code-signing flags (`p_csflags`).
    pub code_signing_flags: u32,
    pub signature: Option<Signature>,
    /// The executable's Mach header, slid.
    pub header: u64,
}

/// `task_self_trap`, `host_self_trap`, `thread_self_trap`.
const TASK_SELF_TRAP: u32 = 28;
const HOST_SELF_TRAP: u32 = 29;
const THREAD_SELF_TRAP: u32 = 27;

pub(super) struct Kernel {
    pub(super) shared_region: Option<SharedRegion>,
    pub(super) signer: pauth::Context,
    pub(super) executable: Executable,
    pub(super) hardware: Hardware,
    pub(super) trace: bool,
    pub(super) counts: BTreeMap<&'static str, u64>,
    pub(super) termination: Option<Termination>,
    pub(super) threads: bsd::thread::Threads,
    pub(super) sysctl: bsd::sysctl::Model,
    pub(super) signals: bsd::signal::Signals,
    /// The main thread's stack top (`p_usrstack`).
    pub(super) user_stack: u64,
    pub(super) map_with_linking_ended: bool,
    /// Guest system roots read-only absolute lookups resolve under first.
    pub(super) roots: Vec<std::path::PathBuf>,
    /// Code signatures attached to files.
    pub(super) signatures: bsd::signatures::Signatures,
    /// This task's, its thread's and the host's kernel-object port names.
    pub(super) kernel_objects: Vec<u32>,
    /// The port MIG reply rights are carried through, once allocated.
    pub(super) mig_relay: Option<u32>,
    /// The task's restartable ranges (`t_rr_ranges`): location, length,
    /// recovery offset and flags.
    pub(super) restartable_ranges: Option<Vec<(u64, u16, u16, u32)>>,
    /// The deferred-reclamation ring, once libmalloc registers one.
    pub(super) reclaim: Option<mach::reclaim::Ring>,
}

/// The trapped guest thread as the exception left it: X0..X30 in the
/// register bank, its PSTATE in SPSR_EL1 and its return address in ELR_EL1.
pub(super) struct Trap<'a> {
    pub(super) cpu: &'a mut Cpu,
}

impl Trap<'_> {
    pub(super) fn x(&self, index: usize) -> u64 {
        self.cpu.state.x[index]
    }

    pub(super) fn set_x(&mut self, index: usize, value: u64) {
        self.cpu.state.x[index] = value;
    }

    pub(super) fn set_carry(&mut self, carry: bool) {
        let spsr = self.cpu.read(Register::SPSR_EL1);
        let spsr = if carry {
            spsr | SPSR_CARRY
        } else {
            spsr & !SPSR_CARRY
        };
        self.cpu.registers.set_raw(Register::SPSR_EL1, 0, spsr);
    }
}

/// What the kernel personality is created from.
pub(super) struct Config {
    pub(super) shared_region: Option<SharedRegion>,
    pub(super) signer: pauth::Context,
    pub(super) hardware: Hardware,
    pub(super) features: Vec<(&'static str, bool)>,
    pub(super) executable: Executable,
    pub(super) user_stack: u64,
    pub(super) roots: Vec<std::path::PathBuf>,
    pub(super) trace: bool,
}

/// The return addresses of the frame records from `fp`, without their
/// pointer authentication codes, for diagnostics.
fn frames(mut fp: u64) -> Vec<u64> {
    const FRAMES: usize = 24;
    const ADDRESS: u64 = (1 << 47) - 1;
    let mut frames = Vec::new();
    while fp != 0 && frames.len() < FRAMES {
        let (Some(next), Some(lr)) = (super::memory::read_u64(fp), super::memory::read_u64(fp + 8))
        else {
            break;
        };
        frames.push(lr & ADDRESS);
        fp = next;
    }
    frames
}

impl Kernel {
    pub(super) fn new(config: Config) -> Self {
        let kernel_objects = [TASK_SELF_TRAP, THREAD_SELF_TRAP, HOST_SELF_TRAP]
            .iter()
            .map(|&trap| forward::mach(trap, &[]).rax as u32)
            .collect();
        Self {
            shared_region: config.shared_region,
            signer: config.signer,
            sysctl: bsd::sysctl::Model::new(&config.hardware, &config.features),
            executable: config.executable,
            hardware: config.hardware,
            trace: config.trace,
            counts: BTreeMap::new(),
            termination: None,
            threads: bsd::thread::Threads::default(),
            signals: bsd::signal::Signals::inherit(),
            user_stack: config.user_stack,
            roots: config.roots,
            signatures: Default::default(),
            map_with_linking_ended: false,
            kernel_objects,
            mig_relay: None,
            restartable_ranges: None,
            reclaim: None,
        }
    }

    pub(super) fn count(&mut self, name: &'static str) {
        *self.counts.entry(name).or_default() += 1;
    }

    /// Service the synchronous exception the guest took to EL1.
    pub(super) fn synchronous(&mut self, pe: &mut Pe) -> Result<()> {
        let esr = pe.cpu.read(Register::ESR_EL1);
        let class = esr >> EC_SHIFT;
        let iss = esr & ISS_MASK;
        let elr = pe.cpu.read(Register::ELR_EL1);
        if let Some(signal) = self.signals.deliverable() {
            bail!(
                "signal {signal} arrived for a guest handler: delivery onto the guest stack is \
                 not implemented"
            );
        }
        match class {
            EC_SVC64 => self.supervisor_call(pe),
            EC_DATA_ABORT_LOWER | EC_INSTRUCTION_ABORT_LOWER => {
                let address = pe.cpu.read(Register::FAR_EL1);
                if self.page_in(address)? {
                    return Ok(());
                }
                bail!(
                    "guest {} abort at pc {elr:#x}, address {address:#x} (ISS {iss:#x}, lr {:#x}, \
                     fp {:#x}, sp {:#x}, frames {:x?}): EXC_BAD_ACCESS signal delivery is not \
                     implemented",
                    if class == EC_DATA_ABORT_LOWER {
                        "data"
                    } else {
                        "instruction"
                    },
                    pe.cpu.state.x[30],
                    pe.cpu.state.x[29],
                    pe.cpu.sp(0),
                    frames(pe.cpu.state.x[29]),
                )
            }
            _ => bail!(
                "guest exception class {class:#x} (ESR {esr:#x}) at pc {elr:#x}: \
                 Mach exception and signal delivery are not implemented"
            ),
        }
    }

    /// Slide in a shared-region page the guest or a forwarded call touched.
    pub(super) fn page_in(&mut self, address: u64) -> Result<bool> {
        match &mut self.shared_region {
            Some(region) => region.resolve(address, &self.signer),
            None => Ok(false),
        }
    }

    /// The runs of a range whose host pages a protection change applies
    /// to: shared-region pages not yet slid keep the change (or, `None`,
    /// an unmapping forgets them) until they are slid.
    pub(super) fn unslid_change(
        &mut self,
        address: u64,
        size: u64,
        change: impl FnMut(super::memory::Protection) -> Option<super::memory::Protection>,
    ) -> Vec<(u64, u64)> {
        match &mut self.shared_region {
            Some(region) => region.update(address, size, change),
            None => vec![(address, size)],
        }
    }

    /// Page in the shared-region pages a call's pointer arguments reach,
    /// before the host kernel copies through them: the host cannot fault
    /// them in itself.
    pub(super) fn page_in_arguments(&mut self, arguments: &[u64]) -> Result<()> {
        let Some(region) = &self.shared_region else {
            return Ok(());
        };
        let pending: Vec<u64> = arguments
            .iter()
            .flat_map(|&argument| [argument, argument.wrapping_add(super::memory::PAGE_BYTES)])
            .filter(|&address| region.pending(address))
            .collect();
        for address in pending {
            self.page_in(address)?;
        }
        Ok(())
    }

    fn supervisor_call(&mut self, pe: &mut Pe) -> Result<()> {
        let selector = pe.cpu.state.x[16] as u32 as i32;
        if selector == PLATFORM_CALL {
            return platform::call(self, &mut Trap { cpu: &mut pe.cpu });
        }
        if selector < 0 {
            return mach::trap(self, pe, selector.unsigned_abs());
        }
        bsd::call(self, pe)
    }
}
