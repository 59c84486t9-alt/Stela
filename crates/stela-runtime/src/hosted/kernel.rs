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
    Termination, forward,
    hardware::Hardware,
    host::ProcessHost,
    shared_region::SharedRegion,
    threads::{Engine, Runtime, lock},
};
use crate::{
    machine::{Cpu, Machine, NoDevices, system::Register},
    pauth,
};
use anyhow::{Result, bail};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

mod bsd;
pub(crate) mod control;
mod mach;
mod platform;
pub mod services;
mod status;

pub use bsd::Signature;
pub(super) use bsd::signal::host as signals;
pub(super) use bsd::{EAGAIN, ENOMEM};

pub(super) type Pe = Machine<ProcessHost, NoDevices>;

/// ESR_EL1 exception classes the personality handles.
const EC_SHIFT: u32 = 26;
const ISS_MASK: u64 = (1 << 25) - 1;
const EC_SVC64: u64 = 0x15;
const EC_BRK64: u64 = 0x3c;
/// A pointer-authentication failure under FEAT_FPAC (`ESR_EC_PAC_FAIL`).
const EC_PAC_FAIL: u64 = 0x1c;
/// SIGKILL, which ends a PAC-hardened task's failure.
const SIGKILL: i32 = 9;
const EC_INSTRUCTION_ABORT_LOWER: u64 = 0x20;
const EC_DATA_ABORT_LOWER: u64 = 0x24;
/// A data abort's ISS WnR: the access was a write.
const ISS_WRITE_NOT_READ: u64 = 1 << 6;
/// An abort's ISS fault status code, and its alignment fault.
const ISS_FSC_MASK: u64 = 0x3f;
const FSC_ALIGNMENT: u64 = 0x21;
/// Data addresses ignore their top byte (`VM_USER_STRIP_TBI`).
const TBI_MASK: u64 = (1 << 56) - 1;
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

/// `task_self_trap`, `host_self_trap`.
const TASK_SELF_TRAP: u32 = 28;
const HOST_SELF_TRAP: u32 = 29;

/// The process's kernel state, shared by its threads: what exec fixed, and
/// each mutable family behind its own lock. No lock here is held while a
/// thread waits for the execution lock, except the descriptor-flag gate
/// ([`bsd::files`]), which no thread takes holding it; [`Kernel::page_in`]
/// takes the execution lock before the shared region's.
pub(super) struct Process {
    /// The signer of the user JOP key (IA and DA), `None` when exec
    /// disabled user JOP: the kernel then signs nothing with it.
    pub(super) signer: Option<pauth::Context>,
    pub(super) hardware: Hardware,
    pub(super) sysctl: bsd::sysctl::Model,
    /// The main thread's stack top (`p_usrstack`).
    pub(super) user_stack: u64,
    /// Guest system roots read-only absolute lookups resolve under first.
    pub(super) roots: Vec<std::path::PathBuf>,
    /// The host command `execve` activates the new image with.
    pub(super) reexec: Vec<std::ffi::OsString>,
    pub(super) trace: bool,
    /// This task's and the host's kernel-object port names.
    pub(super) task_port: AtomicU32,
    pub(super) host_port: AtomicU32,
    pub(super) engine: Engine,
    pub(super) runtime: Runtime,
    pub(super) shared_region: Mutex<Option<SharedRegion>>,
    pub(super) executable: Mutex<Executable>,
    pub(super) counts: Mutex<BTreeMap<&'static str, u64>>,
    pub(super) threads: bsd::thread::Threads,
    pub(super) workqueue: bsd::workqueue::Workqueue,
    /// The workqueue kqueue (`fd_wqkqueue`), once used.
    pub(super) kqworkq: bsd::kqworkq::Slot,
    /// The workloops (`fd_kqhash`).
    pub(super) workloops: bsd::kqworkloop::Workloops,
    pub(super) actions: Mutex<bsd::signal::Actions>,
    /// The file-creation mask and the descriptor-flag gate.
    pub(super) files: bsd::files::Files,
    /// Whether a pointer-authentication failure ends the process
    /// (`TFRO_PAC_EXC_FATAL`), fixed at exec.
    pub(super) pac_exception_fatal: bool,
    /// Its threads' signal slots.
    pub(super) signal_slots: bsd::signal::Slots,
    pub(super) map_with_linking_ended: AtomicBool,
    /// Code signatures attached to files.
    pub(super) signatures: Mutex<bsd::signatures::Signatures>,
    /// The task's restartable ranges (`t_rr_ranges`).
    pub(super) restartable_ranges: Mutex<Option<Vec<RestartableRange>>>,
    /// The deferred-reclamation ring, once libmalloc registers one.
    pub(super) reclaim: Mutex<Option<mach::reclaim::Ring>>,
    /// The task's exception actions.
    pub(super) exception_ports: mach::exception::ExceptionPorts,
    /// The debug state new threads take (`task_debug`), once set.
    pub(super) task_debug: Mutex<Option<Vec<u32>>>,
    /// Its asynchronous I/O queues and workers.
    pub(super) aio: Arc<bsd::aio::Aio>,
}

/// One `task_restartable_range_t`: location, length, recovery offset and
/// flags.
pub(super) type RestartableRange = (u64, u16, u16, u32);

/// How a thread's last call ended it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum End {
    /// `exit`: the whole process.
    Process(Termination),
    /// `bsdthread_terminate`: this thread.
    Thread,
}

/// One thread's view of the kernel: the process it belongs to and the
/// state XNU keeps in its uthread.
pub(super) struct Kernel {
    pub(super) process: Arc<Process>,
    /// The thread's identifier in the process's registry.
    pub(super) thread: u64,
    /// Its port name: its host thread's.
    pub(super) thread_port: u32,
    pub(super) trace: bool,
    pub(super) signals: bsd::signal::ThreadSignals,
    /// The port MIG reply rights are carried through, once allocated.
    pub(super) mig_relay: Option<u32>,
    /// Its workqueue thread state, when the workqueue created it.
    pub(super) worker: Option<bsd::workqueue::Worker>,
    /// Whether its host thread has its own working directory
    /// (`__pthread_chdir`), which [`bsd::files`] restores.
    pub(super) thread_directory: bool,
    /// Whether dispatch marked it a heavy user of its cluster's shared
    /// resource (`th_shared_rsrc_heavy_user`).
    pub(super) shared_resource_heavy: bool,
    pub(super) end: Option<End>,
    /// Its suspension and published state, which `thread_abort` and
    /// `thread_terminate` reach.
    control: Option<Arc<control::Control>>,
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
    pub(super) signer: Option<pauth::Context>,
    pub(super) hardware: Hardware,
    pub(super) features: Vec<(&'static str, bool)>,
    pub(super) executable: Executable,
    pub(super) user_stack: u64,
    pub(super) roots: Vec<std::path::PathBuf>,
    pub(super) reexec: Vec<std::ffi::OsString>,
    pub(super) trace: bool,
    pub(super) engine: Engine,
}

impl Process {
    pub(super) fn new(config: Config) -> Arc<Self> {
        let port = |trap| forward::mach(trap, &[]).rax as u32;
        let fpac = config
            .features
            .iter()
            .any(|&(name, present)| name == "FEAT_FPAC" && present);
        let pac_exception_fatal = config
            .executable
            .signature
            .as_ref()
            .is_some_and(|signature| signature.pac_exception_fatal(fpac));
        let restricted = config
            .executable
            .signature
            .as_ref()
            .is_some_and(Signature::platform_restricted);
        mach::exception::set_guard_default(restricted);
        Arc::new(Self {
            pac_exception_fatal,
            sysctl: bsd::sysctl::Model::new(&config.hardware, &config.features),
            signer: config.signer,
            hardware: config.hardware,
            user_stack: config.user_stack,
            roots: config.roots,
            reexec: config.reexec,
            trace: config.trace,
            task_port: AtomicU32::new(port(TASK_SELF_TRAP)),
            host_port: AtomicU32::new(port(HOST_SELF_TRAP)),
            engine: config.engine,
            runtime: Runtime::default(),
            shared_region: Mutex::new(config.shared_region),
            executable: Mutex::new(config.executable),
            counts: Mutex::new(BTreeMap::new()),
            threads: Default::default(),
            workqueue: Default::default(),
            kqworkq: Default::default(),
            workloops: Default::default(),
            actions: Mutex::new(bsd::signal::Actions::inherit()),
            files: bsd::files::Files::inherit(),
            aio: Arc::default(),
            signal_slots: Default::default(),
            map_with_linking_ended: AtomicBool::new(false),
            signatures: Default::default(),
            restartable_ranges: Mutex::new(None),
            reclaim: Mutex::new(None),
            exception_ports: Default::default(),
            task_debug: Mutex::new(None),
        })
    }

    /// This task's port name (a fork child's task has its own).
    pub(super) fn task_port(&self) -> u32 {
        self.task_port.load(Ordering::SeqCst)
    }

    /// The host port's name in this task.
    pub(super) fn host_port(&self) -> u32 {
        self.host_port.load(Ordering::SeqCst)
    }

    /// Pages of the shared region slid so far.
    pub(super) fn slid_pages(&self) -> u64 {
        lock(&self.shared_region)
            .as_ref()
            .map_or(0, SharedRegion::slid_pages)
    }
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
    /// The kernel of a new thread, on its host thread, with the signal mask
    /// `mask`.
    pub(super) fn new(process: Arc<Process>, thread: u64, thread_port: u32, mask: u32) -> Self {
        Self {
            trace: process.trace,
            signals: bsd::signal::ThreadSignals::new(&process.signal_slots, mask),
            control: process.runtime.registry.control(thread),
            process,
            thread,
            thread_port,
            mig_relay: None,
            worker: None,
            thread_directory: false,
            shared_resource_heavy: false,
            end: None,
        }
    }

    /// This thread's control, once it is a registered guest thread.
    pub(super) fn control(&self) -> Option<&Arc<control::Control>> {
        self.control.as_ref()
    }

    /// Perform `call`, which the host kernel serves for this thread, where
    /// another thread's `thread_abort` or `thread_terminate` interrupts it
    /// as it interrupts the arm64 kernel's wait: `None` without performing
    /// it once the thread is terminated.
    pub(super) fn forwarding<T>(&self, call: impl FnOnce() -> T) -> Option<T> {
        match &self.control {
            Some(control) => control.forwarding(call),
            None => Some(call()),
        }
    }

    pub(super) fn count(&mut self, name: &'static str) {
        *lock(&self.process.counts).entry(name).or_default() += 1;
    }

    /// This task's, this thread's and the host's kernel-object ports.
    pub(super) fn kernel_objects(&self) -> [u32; 3] {
        [
            self.process.task_port(),
            self.thread_port,
            self.process.host_port(),
        ]
    }

    /// Drop the compiled blocks of guest memory the hosted kernel changed:
    /// in this thread's engine now, in the others' before they next run.
    pub(super) fn invalidate_code(&self, pe: &mut Pe, address: u64, bytes: u64) {
        pe.invalidate_code(address, bytes);
        self.process
            .runtime
            .registry
            .invalidate(self.thread, address, bytes);
    }

    /// Before a new thread first executes guest code: a workqueue thread
    /// parks until it is bound to a request and enters `wqthread`.
    pub(super) fn begin(&mut self, pe: &mut Pe) -> Result<Option<End>> {
        bsd::workqueue::begin(self, pe)
    }

    /// The thread entered (`true`) or left a kernel call, during which the
    /// workqueue counts it blocked.
    pub(super) fn blocked(&self, blocked: bool) {
        if let Some(worker) = &self.worker {
            self.process.workqueue.blocked(worker, blocked);
        }
    }

    /// Run `section` while no thread executes guest code.
    pub(super) fn exclusive<T>(&self, section: impl FnOnce() -> T) -> T {
        self.process.runtime.exclusive(self.thread, section)
    }

    /// Service the synchronous exception the guest took to EL1, then, on
    /// the way back to the guest, deliver its deliverable signals (XNU's
    /// AST).
    pub(super) fn synchronous(&mut self, pe: &mut Pe) -> Result<()> {
        super::commpage::note_time();
        self.serve(pe)?;
        if self.end.is_none() {
            self.deliver_pending(pe)?;
        }
        Ok(())
    }

    fn serve(&mut self, pe: &mut Pe) -> Result<()> {
        let esr = pe.cpu.read(Register::ESR_EL1);
        let class = esr >> EC_SHIFT;
        let iss = esr & ISS_MASK;
        let elr = pe.cpu.read(Register::ELR_EL1);
        match class {
            EC_SVC64 => self.supervisor_call(pe),
            EC_DATA_ABORT_LOWER | EC_INSTRUCTION_ABORT_LOWER => {
                let address = pe.cpu.read(Register::FAR_EL1);
                if self.page_in(address)? {
                    return Ok(());
                }
                // Another thread changed the mapping while this one
                // accessed it (a protection change, or `VM_PROT_COPY`
                // replacing the range): as `vm_fault` after the map
                // settles, an access the mapping now permits runs again.
                let access = if class == EC_INSTRUCTION_ABORT_LOWER {
                    super::memory::Protection::READ_EXECUTE
                } else if iss & ISS_WRITE_NOT_READ != 0 {
                    super::memory::Protection::READ_WRITE
                } else {
                    super::memory::Protection::READ
                };
                if super::memory::permits(address, access) {
                    return Ok(());
                }
                // EXC_BAD_ACCESS, as `handle_user_abort` and `ux_exception`
                // turn it into a signal.
                self.process
                    .exception_ports
                    .deliverable(self.thread_port, mach::exception::EXC_BAD_ACCESS)?;
                let data = class == EC_DATA_ABORT_LOWER;
                let looked_up = if data { address & TBI_MASK } else { address };
                let fault = bsd::signal::FaultSignal::of(
                    looked_up,
                    super::memory::mapped(looked_up),
                    data && iss & ISS_FSC_MASK == FSC_ALIGNMENT,
                    self.process.user_stack,
                );
                let shared_cache_slide = self.shared_cache_slide();
                self.exception_signal(fault.signal, fault.code, fault.stack_overflow, || {
                    format!(
                        "guest {} abort at pc {elr:#x}, address {address:#x} (ISS {iss:#x}, lr \
                         {:#x}, fp {:#x}, sp {:#x}, frames {:x?}, shared cache slide \
                         {shared_cache_slide:#x})",
                        if data { "data" } else { "instruction" },
                        pe.cpu.state.x[30],
                        pe.cpu.state.x[29],
                        pe.cpu.sp(0),
                        frames(pe.cpu.state.x[29]),
                    )
                });
                Ok(())
            }
            // EXC_BREAKPOINT (`handle_user_breakpoint`): SIGTRAP, at the
            // BRK itself.
            EC_BRK64 => {
                self.process
                    .exception_ports
                    .deliverable(self.thread_port, mach::exception::EXC_BREAKPOINT)?;
                let shared_cache_slide = self.shared_cache_slide();
                self.exception_signal(bsd::signal::SIGTRAP, 0, false, || {
                    format!(
                        "guest BRK #{:#x} at pc {elr:#x} (lr {:#x}, frames {:x?}, shared cache \
                         slide {shared_cache_slide:#x})",
                        iss & 0xffff,
                        pe.cpu.state.x[30],
                        frames(pe.cpu.state.x[29]),
                    )
                });
                Ok(())
            }
            // `handle_pac_fail`: EXC_BAD_ACCESS with EXC_ARM_PAC_FAIL and the
            // instruction. `pac_exception_triage` ends a PAC-hardened task
            // with SIGKILL; any other takes SIGBUS (`ux_exception`).
            EC_PAC_FAIL => {
                self.process
                    .exception_ports
                    .deliverable(self.thread_port, mach::exception::EXC_BAD_ACCESS)?;
                let shared_cache_slide = self.shared_cache_slide();
                let describe = || {
                    format!(
                        "guest pointer-authentication failure at pc {elr:#x} (ESR {esr:#x}, lr \
                         {:#x}, frames {:x?}, shared cache slide {shared_cache_slide:#x})",
                        pe.cpu.state.x[30],
                        frames(pe.cpu.state.x[29]),
                    )
                };
                if self.process.pac_exception_fatal {
                    eprintln!(
                        "stela: {}: the process is PAC-hardened and is killed",
                        describe()
                    );
                    self.end = Some(End::Process(Termination::Signaled(SIGKILL)));
                } else {
                    // EXC_ARM_PAC_FAIL is neither an invalid address nor an
                    // alignment fault: the protection failure's si_code.
                    self.exception_signal(
                        bsd::signal::SIGBUS,
                        bsd::signal::SEGV_ACCERR,
                        false,
                        describe,
                    );
                }
                Ok(())
            }
            _ => bail!(
                "guest exception class {class:#x} (ESR {esr:#x}) at pc {elr:#x} (lr {:#x}, fp \
                 {:#x}, frames {:x?}, shared cache slide {:#x}): Mach exception and signal \
                 delivery for it are not implemented",
                pe.cpu.state.x[30],
                pe.cpu.state.x[29],
                frames(pe.cpu.state.x[29]),
                self.shared_cache_slide(),
            ),
        }
    }

    /// The shared cache's slide, for diagnostics.
    fn shared_cache_slide(&self) -> u64 {
        lock(&self.process.shared_region)
            .as_ref()
            .map_or(0, |region| region.slide())
    }

    /// Slide in a shared-region page the guest or a forwarded call touched.
    /// No thread executes guest code meanwhile, so none observes the page
    /// between its unprotection and its slid contents.
    pub(super) fn page_in(&mut self, address: u64) -> Result<bool> {
        let process = &self.process;
        self.exclusive(|| match lock(&process.shared_region).as_mut() {
            Some(region) => region.resolve(address, process.signer.as_ref()),
            None => Ok(false),
        })
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
        match lock(&self.process.shared_region).as_mut() {
            Some(region) => region.update(address, size, change),
            None => vec![(address, size)],
        }
    }

    /// Page in the shared-region pages a call's pointer arguments reach,
    /// before the host kernel copies through them: the host cannot fault
    /// them in itself.
    pub(super) fn page_in_arguments(&mut self, arguments: &[u64]) -> Result<()> {
        let pending: Vec<u64> = {
            let region = lock(&self.process.shared_region);
            let Some(region) = region.as_ref() else {
                return Ok(());
            };
            arguments
                .iter()
                .flat_map(|&argument| [argument, argument.wrapping_add(super::memory::PAGE_BYTES)])
                .filter(|&address| region.pending(address))
                .collect()
        };
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
