//! The dispatch loop: fetch translation, block cache, native execution and
//! every exit back from native code.
mod amx;
mod exclusive;
mod processors;
mod system;
mod unprivileged;
mod watch;

use super::{
    chip::Check,
    cpu::{
        Cpu, Exception, HCR_AMO, HCR_API, HCR_FMO, HCR_HCD, HCR_IMO, HCR_TGE, HCR_TSC, HCR_VF,
        HCR_VI, HCR_VSE,
    },
    debug,
    exception::{Class, DAIF_A, DAIF_F, DAIF_I, IllegalReturn, Vector, data_abort_iss},
    mmu::{self, Access, Controls, Outcome as Translated},
    pmu,
    registers::{self, CpuProfile, Lines, Outcome as RegisterOutcome, Refusal},
    streaming::{self, Denial},
    system::{Feature, Register as SystemRegister},
    timer, vgic,
};
use crate::pauth;
use alloc::{collections::BTreeMap, format, string::String, vec, vec::Vec};
use core::fmt;
use stela_compiler::{
    GuestAddress, GuestState, Lifter, TargetCpu,
    aarch64::{
        AddressMode, Decoder, FloatingPointOperation, Register, Width,
        register_offset::IndexExtend,
        system::{
            exception::{AuthenticationKey, Operation as ExceptionOperation},
            registers::{Direction, RegisterAccess},
            synchronization::{Operation as Synchronization, WaitKind},
        },
    },
    block::{
        self, BlockProfile, CompilationPlan, ExitKind, PointerAuthentication,
        PointerAuthenticationKey, PointerAuthenticationModifier, PointerAuthenticationOperation,
        el1_platform::{ScalarLoad, ScalarLoadAddress, ScalarStore},
        system::{GuardedOperation, SystemOperation},
    },
    x86_64::MemoryChecks,
};

const PROFILE: BlockProfile = BlockProfile::SystemModeV1;
const INSTRUCTION: u64 = 4;
const FETCH_PAGE: u64 = 4096;
const MAX_BLOCK_BYTES: u64 = block::MAX_BLOCK_INSTRUCTIONS as u64 * INSTRUCTION;
const FETCH_CACHE: usize = 1024;
const JUMP_CACHE: usize = 4096;
const ADMITTED: usize = 4096;
/// ISS CV=1 and COND=0b1110, as reported for trapped AArch64 instructions.
const TRAPPED_AARCH64: u32 = (1 << 24) | (0b1110 << 20);

/// A WFI, WFE, WFIT or WFET a PE waits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Wait {
    kind: WaitKind,
    /// WFIT and WFET only.
    timeout: Option<Timeout>,
}

/// The local timeout of WFIT and WFET (Arm `LocalTimeoutEvent`): it expires
/// once the virtual count, the physical count minus `offset`, reaches
/// `limit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Timeout {
    limit: u64,
    /// CNTVOFF_EL2 outside the host, 0 in it (Arm `VirtualCounterTimer`).
    offset: u64,
}

impl Timeout {
    fn expired(self, physical: u64) -> bool {
        physical.wrapping_sub(self.offset) >= self.limit
    }

    /// The physical count at which it expires, from a count `now` before it.
    fn deadline(self, now: u64) -> u64 {
        now.saturating_add(self.limit - now.wrapping_sub(self.offset))
    }
}
/// HFGITR_EL2 instruction traps (FEAT_FGT).
const HFGITR_ERET: u32 = 51;
const HFGITR_SVC_EL0: u32 = 52;
const HFGITR_SVC_EL1: u32 = 53;

/// The translation regime the host's shadow tables must reflect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Regime {
    pub controls: Controls,
    pub requester: mmu::Requester,
    /// Pages the shadow tables must leave unmapped for watchpoints.
    pub watch: Watch,
}

/// The virtual address ranges enabled watchpoints can match: a page that
/// overlaps one stays out of the shadow tables, so every access to it exits
/// with [`FaultCause::Watched`], unless it is one of the `pass` pages the
/// engine lets one instruction through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watch {
    /// (first, last) addresses; unused entries are empty (first > last).
    pub ranges: [(u64, u64); WATCH_RANGES],
    pub pass: [Option<u64>; 2],
}

/// Two ranges per watchpoint: the matched bits repeat with either value of
/// the bits above DebugAddrTop.
pub const WATCH_RANGES: usize = 2 * debug::WATCHPOINTS as usize;

impl Default for Watch {
    fn default() -> Self {
        Self::from_ranges(&[])
    }
}

impl Watch {
    /// Whether the 4 KiB page at `page` must stay unmapped.
    pub fn blocks(&self, page: u64) -> bool {
        let last = page | (FETCH_PAGE - 1);
        !self.pass.contains(&Some(page & !(FETCH_PAGE - 1)))
            && self
                .ranges
                .iter()
                .any(|&(first, end)| first <= end && first <= last && end >= page)
    }

    fn from_ranges(ranges: &[(u64, u64)]) -> Self {
        let mut watch = Self {
            ranges: [(1, 0); WATCH_RANGES],
            pass: [None; 2],
        };
        for (slot, range) in watch.ranges.iter_mut().zip(ranges) {
            *slot = *range;
        }
        watch
    }
}

/// Entry address of installed native code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeCode(pub usize);

/// Why native code stopped before its block exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultCause {
    /// The guest's translation refused the access.
    Guest(mmu::Fault),
    /// The access translated to a physical address that is not RAM.
    Device { physical: u64 },
    /// The guest configured translation this engine does not implement.
    Translation(mmu::Unsupported),
    /// An x86 #GP: the address is not canonical for x86 (tags, wild pointers).
    NonCanonical,
    /// An x86 #UD from a native check (16-byte SP alignment).
    InvalidOpcode,
    /// The access reached a page [`Watch`] keeps unmapped.
    Watched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeFault {
    /// Byte offset of the faulting instruction in the block's native code.
    pub offset: usize,
    pub address: u64,
    pub write: bool,
    pub cause: FaultCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeExit {
    Exit { next_pc: u64, kind: u64 },
    Fault(NativeFault),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    /// The code arena is full; discarding every block frees it.
    Full,
}

/// The x86 machine beneath the engine: guest RAM, native code, shadow
/// translation, time and waiting.
pub trait Host {
    /// Read guest RAM. False when any byte is not RAM.
    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool;
    /// Write guest RAM. False when any byte is not RAM.
    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool;
    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError>;
    /// Free every installed block.
    fn discard_code(&mut self);
    /// Run one native block on `state`.
    ///
    /// # Safety
    /// `code` was returned by [`Host::install`] since the last discard and
    /// was compiled for the system-mode block ABI.
    unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit;
    /// Make the shadow translation follow `regime`.
    fn set_regime(&mut self, regime: &Regime);
    /// Drop every cached translation (TLB maintenance).
    fn invalidate_translations(&mut self);
    /// The guest's system counter.
    fn counter(&mut self) -> u64;
    /// Interrupt the host at this counter value, or never.
    fn arm_timer(&mut self, deadline: Option<u64>);
    /// Block until a host interrupt arrives.
    fn wait_for_interrupt(&mut self);
    /// Progress events for the diagnostic log.
    fn report(&mut self, _event: &Event) {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    /// No device model covers this physical address.
    NoDevice,
    /// The device refused this register, width or state.
    Refused(String),
}

/// The board's devices on the guest physical bus. `cpu` is the number of the
/// PE making the access, as [`CpuProfile::processors`] numbers it, and `now`
/// is the system counter value (24 MHz ticks) of the access.
pub trait Devices {
    fn read(&mut self, cpu: usize, physical: u64, bytes: u8, now: u64) -> Result<u64, DeviceError>;
    fn write(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<(), DeviceError>;
    /// Bring time-driven state up to `now` and report the interrupt lines
    /// the devices drive into PE `cpu`.
    fn lines(&mut self, cpu: usize, now: u64) -> Lines;
    /// The next counter value at which a device changes state by itself.
    fn deadline(&mut self, _now: u64) -> Option<u64> {
        None
    }
    /// A reset or power-off the guest requested from a device, once.
    fn take_reset(&mut self) -> Option<String> {
        None
    }
    /// A PE the guest released from reset through a device, once.
    fn take_start(&mut self) -> Option<Start> {
        None
    }
    /// The physical region a memory controller has locked against writes,
    /// first and last byte.
    fn memory_lock(&self) -> Option<(u64, u64)> {
        None
    }
}

/// A powered-off PE leaves reset at `address` (its RVBAR) in EL2h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Start {
    pub cpu: usize,
    pub address: u64,
}

/// A bus with no devices: every access is [`DeviceError::NoDevice`].
pub struct NoDevices;

impl Devices for NoDevices {
    fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
        Err(DeviceError::NoDevice)
    }
    fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
        Err(DeviceError::NoDevice)
    }
    fn lines(&mut self, _: usize, _: u64) -> Lines {
        Lines::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Exception {
        vector: Vector,
        from_el: u8,
        syndrome: u64,
        return_address: u64,
        fault_address: Option<u64>,
    },
    /// An exception return, to a guarded level when `guarded`.
    Return { to_el: u8, guarded: bool, pc: u64 },
    /// GENTER (`enter`) or GEXIT, and the level the PE is now at.
    Guarded {
        enter: bool,
        el: u8,
        guarded: bool,
        pc: u64,
    },
}

/// A requirement this engine does not implement, with where it was met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub pc: u64,
    pub el: u8,
    pub kind: RequirementKind,
    /// The ESR_EL1 value the access would report if it were a guest exception.
    pub syndrome: Option<u64>,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementKind {
    Instruction {
        word: u32,
        detail: String,
    },
    SystemRegister {
        word: u32,
        refusal: Refusal,
    },
    SystemInstruction {
        word: u32,
        detail: &'static str,
    },
    Translation(mmu::Unsupported),
    Fetch {
        physical: u64,
    },
    Device {
        physical: u64,
        write: bool,
        detail: String,
    },
    IllegalReturn(IllegalReturn),
    Native(&'static str),
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pc={:#x} el={} ", self.pc, self.el)?;
        match &self.kind {
            RequirementKind::Instruction { word, detail } => {
                write!(f, "instruction {word:#010x}: {detail}")?
            }
            RequirementKind::SystemRegister { word, refusal } => {
                let access = stela_compiler::aarch64::system::registers::decode(*word);
                match access {
                    Some(access) => {
                        let e = access.encoding();
                        write!(
                            f,
                            "system register {} S{}_{}_C{}_C{}_{} ({word:#010x}): {refusal:?}",
                            if access.direction() == Direction::Read {
                                "read"
                            } else {
                                "write"
                            },
                            e.op0(),
                            e.op1(),
                            e.crn(),
                            e.crm(),
                            e.op2()
                        )?
                    }
                    None => write!(f, "system register {word:#010x}: {refusal:?}")?,
                }
            }
            RequirementKind::SystemInstruction { word, detail } => {
                write!(f, "system instruction {word:#010x}: {detail}")?
            }
            RequirementKind::Translation(unsupported) => {
                write!(f, "translation configuration {unsupported:?}")?
            }
            RequirementKind::Fetch { physical } => {
                write!(f, "instruction fetch from non-RAM PA {physical:#x}")?
            }
            RequirementKind::Device {
                physical,
                write,
                detail,
            } => write!(
                f,
                "device {} at PA {physical:#x}: {detail}",
                if *write { "write" } else { "read" }
            )?,
            RequirementKind::IllegalReturn(reason) => write!(f, "exception return {reason:?}")?,
            RequirementKind::Native(detail) => write!(f, "native execution: {detail}")?,
        }
        if let Some(syndrome) = self.syndrome {
            write!(f, " esr={syndrome:#x}")?;
        }
        if let Some(address) = self.address {
            write!(f, " far={address:#x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The block budget ran out.
    Budget,
    /// Every PE is off or waits in WFI or WFE with nothing able to wake it.
    Idle,
    /// A device carried out the guest's reset or power-off request.
    Reset(String),
    Unsupported(Requirement),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Statistics {
    pub blocks: u64,
    pub compiled: u64,
    pub exceptions: u64,
    pub interrupts: u64,
    pub system_exits: u64,
    pub device_accesses: u64,
    pub code_discards: u64,
    pub waits: u64,
    /// Changes of the running PE.
    pub switches: u64,
}

struct Block {
    pc: u64,
    physical: u64,
    code: NativeCode,
    /// Guest PC and native offset of every instruction, ascending.
    source_map: Vec<(u64, usize)>,
    /// The memory checks it was compiled with.
    checks: MemoryChecks,
}

#[derive(Clone, Copy)]
struct FetchEntry {
    page: u64,
    physical: u64,
    /// FEAT_BTI's guarded page (Arm `InGuardedPage`).
    guarded: bool,
    el: u8,
    generation: u64,
}

#[derive(Clone, Copy)]
struct JumpEntry {
    pc: u64,
    physical: u64,
    variant: Variant,
    generation: u64,
    block: usize,
}

/// What a block is compiled for besides its PC and PA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Variant {
    /// FP/SIMD enabled: otherwise the block ends before the first FP/SIMD
    /// instruction.
    fp: bool,
    /// SP and data alignment checks (SCTLR_ELx.SA or SA0, A and nAA).
    checks: MemoryChecks,
    /// One instruction only, for breakpoints and software step.
    single: bool,
    /// PE has SME, and PSTATE.SM: the block ends before the first
    /// instruction an SVE or SME access check (or, in streaming mode, any
    /// access check) applies to.
    scalable: Option<bool>,
}

/// A load or store addressed through Rn (bits 9:5) that names SP; literal
/// loads have no base register.
fn stack_based(word: u32) -> bool {
    word & 0x0a00_0000 == 0x0800_0000 && word & 0x3b00_0000 != 0x1800_0000 && (word >> 5) & 31 == 31
}

/// Floating-point and SIMD instructions, which CPACR_EL1.FPEN can trap:
/// SIMD&FP data processing (op0 x111) and SIMD&FP loads/stores (op0 x1x0, V=1).
fn is_floating_point(word: u32) -> bool {
    (word >> 25) & 7 == 7 || word & 0x0a00_0000 == 0x0800_0000 && word & (1 << 26) != 0
}

pub struct Machine<H: Host, D: Devices> {
    /// The running PE.
    pub cpu: Cpu,
    pub host: H,
    pub devices: D,
    pub profile: CpuProfile,
    pub statistics: Statistics,
    /// Exits to the engine from compiled code (System, FP, PAC and AMX), by
    /// the instruction word that took them: which words to compile inline.
    pub exit_words: BTreeMap<u32, u64>,
    target: TargetCpu,
    blocks: Vec<Block>,
    /// Blocks by PC, PA, FP enablement and SP alignment checking.
    index: BTreeMap<(u64, u64, Variant), usize>,
    fetch: Vec<Option<FetchEntry>>,
    jump: Vec<Option<JumpEntry>>,
    /// Advances when cached fetch translations become stale.
    translation_generation: u64,
    /// Advances when installed code is discarded.
    code_generation: u64,
    /// Identification registers the CPU profile has no value for.
    profile_missing: Vec<SystemRegister>,
    /// Accessors by encoding.
    lookup: super::system::Lookup,
    /// The earliest physical count at which a timer signals FIQ; `None` when
    /// a System register write may have changed it.
    timers: Option<Option<u64>>,
    /// The EL FP/SIMD traps to, if any; `None` when a System register write
    /// or an EL change may have changed it.
    floating_point: Option<Option<u8>>,
    /// The memory checks of the current regime's SCTLR_ELx, while valid.
    memory_checks: Option<MemoryChecks>,
    /// The physical count up to which the event streams have set the event
    /// register; `None` before the first sample.
    event_sample: Option<u64>,
    /// What self-hosted debug needs of each instruction, while valid.
    debug: Option<DebugMode>,
    /// Words `Chip::admit` has answered, by a hash of the word.
    admitted: Vec<Option<(u32, u32)>>,
    /// The watched pages the host keeps unmapped.
    watch: Watch,
    /// The number of the running PE.
    current: usize,
    /// The WFI, WFE, WFIT or WFET the running PE waits in, until it wakes.
    waiting: Option<Wait>,
    /// Every PE by number; the running one's state is `cpu`.
    peers: Vec<processors::Peer>,
    /// The block count at which the running PE's time slice ends.
    slice_end: u64,
    /// The instruction just completed wrote PSTATE.PACM (PACM, or an
    /// exception return), so it does not lapse.
    pacm_written: bool,
    /// The instruction the engine is completing, already counted as retired
    /// (`Machine::completing`).
    completing: Option<u64>,
}

/// Breakpoints that can match and an enabled software step make every
/// block a single instruction checked before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DebugMode {
    breakpoints: bool,
    step: bool,
}

enum Fetched {
    Block(usize),
    Exception(Exception),
    /// The first instruction makes access checks the engine applies before
    /// it runs (see [`Variant::scalable`]).
    Checked(u32),
}

type Step = Result<(), Stop>;

impl<H: Host, D: Devices> Machine<H, D> {
    pub fn new(cpu: Cpu, host: H, devices: D, profile: CpuProfile, target: TargetCpu) -> Self {
        assert_eq!(
            cpu.registers.chip(),
            profile.chip,
            "the boot PE is not the profile's chip"
        );
        let mut machine = Self {
            cpu,
            host,
            devices,
            profile,
            statistics: Statistics::default(),
            exit_words: BTreeMap::new(),
            target,
            blocks: Vec::new(),
            index: BTreeMap::new(),
            fetch: vec![None; FETCH_CACHE],
            jump: vec![None; JUMP_CACHE],
            translation_generation: 1,
            code_generation: 1,
            profile_missing: Vec::new(),
            lookup: super::system::Lookup::new(),
            timers: None,
            floating_point: None,
            memory_checks: None,
            event_sample: None,
            debug: None,
            admitted: vec![None; ADMITTED],
            watch: Watch::default(),
            current: 0,
            waiting: None,
            peers: Vec::new(),
            slice_end: processors::QUANTUM,
            pacm_written: false,
            completing: None,
        };
        machine.peers = processors::boot(&machine.profile);
        machine.load_profile();
        machine.sync_regime();
        machine
    }

    fn requirement(&self, kind: RequirementKind) -> Requirement {
        Requirement {
            pc: self.cpu.pc,
            el: self.cpu.pstate.el,
            kind,
            syndrome: None,
            address: None,
        }
    }

    fn unsupported(&self, kind: RequirementKind) -> Stop {
        Stop::Unsupported(self.requirement(kind))
    }

    /// Forget state derived from System registers and PSTATE.
    fn derived_changed(&mut self) {
        self.timers = None;
        self.floating_point = None;
        self.memory_checks = None;
        self.debug = None;
    }

    fn debug_mode(&mut self) -> DebugMode {
        *self.debug.get_or_insert_with(|| {
            let cpu = &self.cpu;
            DebugMode {
                breakpoints: debug::watching(cpu) && debug::any_breakpoint(cpu),
                step: debug::enabled(cpu) && cpu.field(SystemRegister::MDSCR_EL1, 0, 1) != 0,
            }
        })
    }

    /// A breakpoint, software step or watchpoint exception: to EL2 from EL2
    /// and, under HCR_EL2.TGE or MDCR_EL2.TDE, from EL0 and EL1; else to EL1
    /// (Arm `AArch64_BreakpointException` and the others).
    fn debug_exception(&self, lower: Class, same: Class, iss: u32, pc: u64) -> Exception {
        let el = self.cpu.pstate.el;
        let target = if el == 2 || debug::target(&self.cpu) == 2 {
            2
        } else {
            1
        };
        let class = if target > el { lower } else { same };
        Exception::synchronous(class, iss, pc).to(target)
    }

    /// Arm `SSAdvance` before SVC, HVC and SMC take their exception, so
    /// SPSR.SS records the step as complete.
    fn advance_step(&mut self) {
        if self.cpu.step_advance {
            self.cpu.step_advance = false;
            self.cpu.pstate.ss = false;
        }
    }

    /// Whether loads and stores through SP check its 16-byte alignment (Arm
    /// `CheckSPAlignment`): SCTLR_ELx.SA0 at EL0 and SA otherwise, of the
    /// current translation regime.
    fn stack_alignment_checked(&mut self) -> bool {
        self.memory_checks().stack_alignment
    }

    /// The checks native code makes for the current regime's SCTLR_ELx: SP
    /// alignment, A (Arm `AlignmentEnforced`) and nAA.
    fn memory_checks(&mut self) -> MemoryChecks {
        *self.memory_checks.get_or_insert_with(|| {
            let sctlr = self.cpu.controls(self.cpu.regime()).sctlr;
            let bit = if self.cpu.pstate.el == 0 { 4 } else { 3 };
            MemoryChecks {
                stack_alignment: sctlr & (1 << bit) != 0,
                alignment: sctlr & mmu::alignment::SCTLR_A != 0,
                ordered_granule: sctlr & mmu::alignment::SCTLR_NAA == 0,
            }
        })
    }

    fn sync_regime(&mut self) {
        self.derived_changed();
        self.sync_monitor();
        let watch = Watch {
            pass: self.watch.pass,
            ..Watch::from_ranges(&debug::watched(&self.cpu))
        };
        if watch.ranges != self.watch.ranges {
            // Newly watched pages must leave the shadow tables.
            self.translation_generation += 1;
            self.host.invalidate_translations();
        }
        self.watch = watch;
        let regime = Regime {
            controls: self.cpu.controls(self.cpu.regime()),
            requester: self.cpu.requester(),
            watch,
        };
        self.host.set_regime(&regime);
    }

    fn translations_changed(&mut self) {
        self.translation_generation += 1;
        self.host.invalidate_translations();
        self.sync_regime();
    }

    fn discard_code(&mut self) {
        self.host.discard_code();
        self.blocks.clear();
        self.index.clear();
        self.code_generation += 1;
        self.statistics.code_discards += 1;
    }

    fn take(&mut self, exception: Exception) {
        // The instruction being completed traps or faults: it does not
        // retire. SVC, HVC and SMC return after themselves and retire.
        if self
            .completing
            .take_if(|pc| {
                exception.vector == Vector::Synchronous && exception.return_address == *pc
            })
            .is_some()
        {
            self.cpu.retired -= 1;
        }
        let from_el = self.cpu.pstate.el;
        self.cpu.take(exception);
        self.statistics.exceptions += 1;
        self.host.report(&Event::Exception {
            vector: exception.vector,
            from_el,
            syndrome: exception.syndrome,
            return_address: exception.return_address,
            fault_address: exception.fault_address,
        });
        self.sync_regime();
    }

    fn lines(&mut self) -> Lines {
        let now = self.host.counter();
        let device = self.devices.lines(self.current, now);
        // A timer signals exactly when the count reaches its deadline, which
        // only System register writes change.
        let deadline = self.timer_deadline();
        self.cpu.core_lines(Lines {
            irq: device.irq,
            // Apple cores signal the generic timers and the PMI as FIQ.
            fiq: device.fiq
                || deadline.is_some_and(|deadline| now >= deadline)
                || monitor_asserted(&self.cpu, now),
        })
    }

    /// Bring the running PE's performance monitor up to now and continue
    /// counting in its current EL and wait state. Every change of either
    /// passes here: exception entry and return through `sync_regime`, and
    /// the start and end of a wait.
    pub(super) fn sync_monitor(&mut self) {
        let context = pmu::Context {
            el: self.cpu.pstate.el,
            waiting: self.waiting.is_some(),
        };
        let retired = self.cpu.retired;
        let Some(monitor) = self.cpu.pmu.as_mut() else {
            return;
        };
        // Without PMC0 nothing counts time, so the count need not be read.
        let now = if monitor.timed() {
            self.host.counter()
        } else {
            0
        };
        monitor.sync(now, retired, context);
    }

    /// Complete the instruction at `pc` in the engine, counting it as
    /// retired unless it takes a synchronous exception at its own address
    /// (`Machine::take`).
    fn completing(&mut self, pc: u64, complete: impl FnOnce(&mut Self) -> Step) -> Step {
        self.cpu.retired += 1;
        self.completing = Some(pc);
        let step = complete(self);
        self.completing = None;
        step
    }

    /// Count the instructions of block `index` before `pc` as retired.
    fn retire_before(&mut self, index: usize, pc: u64) {
        self.cpu.retired += (pc - self.blocks[index].pc) / INSTRUCTION;
    }

    /// Whether an interrupt routed to `target` is taken now: always when it
    /// goes to a higher EL, under its PSTATE mask at the same EL, never when
    /// it targets a lower EL (Arm ARM D1.3.6).
    fn taken(&self, target: u8, mask: u8) -> bool {
        let el = self.cpu.pstate.el;
        target > el || (target == el && self.cpu.pstate.daif & mask == 0)
    }

    /// Take a pending interrupt before the next instruction: the physical
    /// lines routed by HCR_EL2.{TGE,IMO,FMO}, then the virtual IRQ, FIQ and
    /// SError that HCR_EL2.{VI,VF,VSE} hold for EL1 and EL0 outside the host.
    fn deliver_interrupts(&mut self) -> bool {
        let lines = self.lines();
        let virtual_pending = self.cpu.pstate.el != 2
            && self.cpu.read(SystemRegister::HCR_EL2) & (1 << HCR_VI | 1 << HCR_VF | 1 << HCR_VSE)
                != 0;
        if !lines.irq && !lines.fiq && !virtual_pending {
            return false;
        }
        let mut exception = None;
        for (vector, pending, mask) in [
            (Vector::Fiq, lines.fiq, DAIF_F),
            (Vector::Irq, lines.irq, DAIF_I),
        ] {
            let target = self.cpu.interrupt_target(vector);
            if pending && self.taken(target, mask) {
                exception = Some((vector, target, 0));
                break;
            }
        }
        let guest = self.cpu.pstate.el != 2 && !self.cpu.in_host();
        if exception.is_none() && guest {
            for (vector, routing, virtual_bit, mask) in [
                (Vector::Fiq, HCR_FMO, HCR_VF, DAIF_F),
                (Vector::Irq, HCR_IMO, HCR_VI, DAIF_I),
                (Vector::SError, HCR_AMO, HCR_VSE, DAIF_A),
            ] {
                if self.cpu.hcr(routing)
                    && self.cpu.hcr(virtual_bit)
                    && self.cpu.pstate.daif & mask == 0
                {
                    let syndrome = if vector == Vector::SError {
                        // ESR_EL1 takes VSESR_EL2.{IDS,ISS} with EC 0x2F.
                        super::exception::syndrome(
                            Class::SError,
                            self.cpu.read(SystemRegister::VSESR_EL2) as u32,
                        )
                    } else {
                        0
                    };
                    exception = Some((vector, 1, syndrome));
                    break;
                }
            }
        }
        let Some((vector, target, syndrome)) = exception else {
            return false;
        };
        if vector == Vector::SError {
            // The virtual SError is taken once: HCR_EL2.VSE clears.
            let hcr = self.cpu.read(SystemRegister::HCR_EL2) & !(1 << HCR_VSE);
            self.cpu.registers.set(SystemRegister::HCR_EL2, 0, hcr);
        }
        self.statistics.interrupts += 1;
        self.take(Exception {
            vector,
            syndrome,
            fault_address: None,
            return_address: self.cpu.pc,
            target: Some(target),
        });
        true
    }

    /// Apply Arm `GenericCounterTick`'s event-stream tests to the counts since
    /// the last sample. Sampling before the event register is read and before
    /// every write that changes a stream gives each tick the controls it had.
    pub(crate) fn sample_events(&mut self, now: u64) {
        if let Some(previous) = self.event_sample
            && timer::event(&self.cpu, previous, now)
        {
            self.cpu.event = true;
        }
        self.event_sample = Some(now);
    }

    fn timer_deadline(&mut self) -> Option<u64> {
        *self
            .timers
            .get_or_insert_with(|| timer::deadline(&self.cpu))
    }

    /// Read `bytes.len()` bytes of RAM at `address` in the running PE's
    /// current regime, for diagnostics after a stop: a read that does not
    /// translate or reaches no RAM is `false`, and nothing is faulted or
    /// changed. The bytes must lie in one fetch page.
    pub fn read_virtual(&mut self, address: u64, bytes: &mut [u8]) -> bool {
        let controls = self.cpu.controls(self.cpu.regime());
        let requester = self.cpu.requester();
        let last = address.wrapping_add(bytes.len() as u64).wrapping_sub(1);
        if bytes.is_empty() || address & !(FETCH_PAGE - 1) != last & !(FETCH_PAGE - 1) {
            return false;
        }
        match mmu::translate(
            &controls,
            address,
            Access::Read,
            requester,
            &mut RamTables(&mut self.host),
        ) {
            Translated::Mapped(translation) => self.host.read_ram(translation.physical, bytes),
            _ => false,
        }
    }

    /// Run until a stop. `budget` limits executed blocks (0 = unlimited).
    pub fn run(&mut self, budget: u64) -> Stop {
        loop {
            if budget != 0 && self.statistics.blocks >= budget {
                return Stop::Budget;
            }
            if let Err(stop) = self.schedule().and_then(|()| self.step()) {
                return stop;
            }
        }
    }

    fn step(&mut self) -> Step {
        let delivered = self.deliver_interrupts();
        if let Some(reason) = self.devices.take_reset() {
            return Err(Stop::Reset(reason));
        }
        if delivered {
            return Ok(());
        }
        let pc = self.cpu.pc;
        let mode = self.debug_mode();
        // Active-pending software step comes before every other exception
        // of the instruction (Arm `CheckSoftwareStep`).
        if mode.step && !self.cpu.pstate.ss {
            let exception = self.debug_exception(Class::StepLower, Class::StepSame, 0x22, pc);
            self.take(exception);
            return Ok(());
        }
        if !pc.is_multiple_of(INSTRUCTION) {
            let mut exception = Exception::synchronous(Class::PcAlignment, 0, pc);
            exception.fault_address = Some(pc);
            self.take(exception);
            return Ok(());
        }
        if (mode.breakpoints || self.cpu.pstate.il)
            && let Some(exception) = self.instruction_checks(pc, mode.breakpoints)?
        {
            self.take(exception);
            return Ok(());
        }
        // Active-not-pending: this one instruction advances the step.
        self.cpu.step_advance = mode.step;
        // PSTATE.PACM applies to the one instruction after PACM.
        let pacm = self.cpu.pstate.pacm;
        let single = mode.breakpoints || mode.step || pacm;
        let index = match self.fetch_block(pc, single)? {
            Fetched::Block(index) => index,
            Fetched::Exception(exception) => {
                self.cpu.step_advance = false;
                self.take(exception);
                return Ok(());
            }
            Fetched::Checked(word) => return self.checked_instruction(pc, word),
        };
        if self.cpu.pstate.btype != 0 && self.fetch_guarded(pc) {
            let word = self.word(index, pc)?;
            if let Some(exception) = self.branch_target_exception(pc, word) {
                self.take(exception);
                return Ok(());
            }
        }
        let step = self.execute(index);
        if !core::mem::take(&mut self.pacm_written) && pacm {
            self.cpu.pstate.pacm = false;
        }
        self.advance_step();
        step
    }

    /// Arm `BranchTargetCheck`: the Branch Target exception (EC 0x0D)
    /// reports BTYPE in ISS and leaves it set for SPSR.
    fn branch_target_exception(&self, pc: u64, word: u32) -> Option<Exception> {
        let btype = self.cpu.pstate.btype;
        (!self.branch_target_compatible(word))
            .then(|| Exception::synchronous(Class::BranchTarget, u32::from(btype), pc))
    }

    /// An instruction whose FP, SVE and SME access checks the engine
    /// applies before it runs: after a Branch Target exception, the first
    /// check that fails traps. SVE and SME execution, and scalar FP in
    /// streaming mode (whose writes zero the upper Z bits), stop explicitly.
    #[cold]
    fn checked_instruction(&mut self, pc: u64, word: u32) -> Step {
        self.cpu.step_advance = false;
        if self.cpu.pstate.btype != 0
            && self.fetch_guarded(pc)
            && let Some(exception) = self.branch_target_exception(pc, word)
        {
            self.take(exception);
            return Ok(());
        }
        let checks = self.profile.chip.checks(word);
        let exception = match streaming::check(&self.cpu, checks) {
            Err(Denial::FloatingPoint(el)) => {
                Exception::synchronous(Class::FloatingPointAccess, TRAPPED_AARCH64, pc).to(el)
            }
            Err(Denial::Sme { el, smtc }) => {
                Exception::synchronous(Class::SmeAccess, smtc, pc).to(el)
            }
            Err(Denial::Unimplemented(feature)) => {
                return Err(self.unsupported(RequirementKind::Instruction {
                    word,
                    detail: format!("its access check needs {feature}, which the engine lacks"),
                }));
            }
            Ok(()) => {
                let detail = if checks.iter().all(|check| *check == Check::Fp) {
                    "scalar FP in streaming mode, which zeroes the upper Z bits it writes, is not run by the system engine"
                } else {
                    "SVE and SME instructions are not run by the system engine"
                };
                return Err(self.unsupported(RequirementKind::Instruction {
                    word,
                    detail: detail.into(),
                }));
            }
        };
        self.take(exception);
        Ok(())
    }

    /// Run one compiled block and complete its exit or fault.
    fn execute(&mut self, index: usize) -> Step {
        let code = self.blocks[index].code;
        // SAFETY: installed by this machine since the last discard, for the
        // system-mode block ABI.
        let exit = unsafe { self.host.execute(code, &mut self.cpu.state) };
        self.statistics.blocks += 1;
        match exit {
            NativeExit::Exit { next_pc, kind } => self.exit(index, next_pc, kind),
            NativeExit::Fault(fault) => self.native_fault(index, fault),
        }
    }

    /// The checks before an instruction executes, in Arm's priority after PC
    /// alignment: an Instruction Abort of its fetch, a breakpoint (Arm
    /// `AArch64_CheckBreakpoint`), then the Illegal Execution state (Arm
    /// `AArch64_CheckIllegalState`).
    #[cold]
    fn instruction_checks(
        &mut self,
        pc: u64,
        breakpoints: bool,
    ) -> Result<Option<Exception>, Stop> {
        match self.fetch_physical(pc) {
            Ok(_) => {}
            Err(Ok(exception)) => return Ok(Some(exception)),
            Err(Err(stop)) => return Err(stop),
        }
        if breakpoints && debug::breakpoint(&self.cpu, pc) {
            return Ok(Some(self.debug_exception(
                Class::BreakpointLower,
                Class::BreakpointSame,
                0x22,
                pc,
            )));
        }
        Ok(self
            .cpu
            .pstate
            .il
            .then(|| Exception::synchronous(Class::IllegalExecution, 0, pc)))
    }

    /// Translate a PC for execution at the current EL.
    fn fetch_physical(&mut self, pc: u64) -> Result<u64, Result<Exception, Stop>> {
        let page = pc & !(FETCH_PAGE - 1);
        let slot = (page / FETCH_PAGE) as usize % FETCH_CACHE;
        // The cache key folds the guarded level in with the EL.
        let el = self.cpu.pstate.el | u8::from(self.cpu.pstate.guarded) << 4;
        if let Some(entry) = self.fetch[slot]
            && entry.page == page
            && entry.el == el
            && entry.generation == self.translation_generation
        {
            return Ok(entry.physical | (pc & (FETCH_PAGE - 1)));
        }
        let requester = self.cpu.requester();
        let controls = self.cpu.controls(self.cpu.regime());
        let mut tables = RamTables(&mut self.host);
        match mmu::translate(&controls, pc, Access::Execute, requester, &mut tables) {
            Translated::Mapped(translation) => {
                let physical = translation.physical & !(FETCH_PAGE - 1);
                self.fetch[slot] = Some(FetchEntry {
                    page,
                    physical,
                    guarded: translation.guarded,
                    el,
                    generation: self.translation_generation,
                });
                Ok(translation.physical)
            }
            Translated::Fault(fault)
                if fault.kind == mmu::FaultKind::Permission
                    && requester.el != 0
                    && !requester.guarded
                    && controls.sprr.enabled()
                    && matches!(
                        mmu::translate(
                            &controls,
                            pc,
                            Access::Execute,
                            mmu::Requester {
                                guarded: true,
                                ..requester
                            },
                            &mut RamTables(&mut self.host),
                        ),
                        Translated::Mapped(_)
                    ) =>
            {
                // On hardware an EL fetch of GL-only code enters GL at
                // GXF_ABORT_EL1 (Sven Peter, for GL2); the saved state is
                // not documented.
                Err(Err(self.unsupported(RequirementKind::Native(
                    "kernel-level fetch of guarded-only code (GXF abort entry)",
                ))))
            }
            Translated::Fault(fault) => Err(Ok(self.abort(
                fault,
                [Class::InstructionAbortLower, Class::InstructionAbortSame],
                fault.instruction_syndrome(),
                pc,
                pc,
            ))),
            Translated::Unsupported(unsupported) => Err(Err(
                self.unsupported(RequirementKind::Translation(unsupported))
            )),
        }
    }

    /// Whether the page of `pc`, which executes at the current EL, is guarded
    /// (Arm `InGuardedPage`).
    fn fetch_guarded(&mut self, pc: u64) -> bool {
        if self.fetch_physical(pc).is_err() {
            return false;
        }
        let page = pc & !(FETCH_PAGE - 1);
        let slot = (page / FETCH_PAGE) as usize % FETCH_CACHE;
        self.fetch[slot].is_some_and(|entry| entry.page == page && entry.guarded)
    }

    /// FEAT_BTI's BTYPE after an indirect branch at `pc` through `register`
    /// (Arm BR, BLR, BRA* and BLRA*): BLR forms give 0b10; BR forms give
    /// 0b01 through X16 or X17 or from an unguarded page, else 0b11.
    fn indirect_branch_type(&mut self, pc: u64, register: u8, link: bool) -> u8 {
        if link {
            0b10
        } else if register == 16 || register == 17 || !self.fetch_guarded(pc) {
            0b01
        } else {
            0b11
        }
    }

    /// Whether the first instruction of a guarded-page target is compatible
    /// with PSTATE.BTYPE (Arm `BTypeCompatible_BTI`, `BTypeCompatible_PAC`):
    /// BTI with a matching target, PACIASP and PACIBSP unless BTYPE is 0b11
    /// and SCTLR_ELx.BT0 (EL0) or BT1 forbids it, BRK and HLT.
    fn branch_target_compatible(&self, word: u32) -> bool {
        const PACIASP: u32 = 0xd503_233f;
        const PACIBSP: u32 = 0xd503_237f;
        const SCTLR_BT0: u64 = 1 << 35;
        const SCTLR_BT1: u64 = 1 << 36;
        let btype = self.cpu.pstate.btype;
        if word & 0xffff_ff3f == 0xd503_241f {
            return match (word >> 6) & 3 {
                0b00 => btype == 0,
                0b01 => btype != 0b11,
                0b10 => btype != 0b10,
                _ => true,
            };
        }
        let sppc = matches!(
            block::pauth_lr::decode(word),
            Some(block::pauth_lr::Instruction::SignSpPc {
                implicit_bti: true,
                ..
            })
        );
        if word == PACIASP || word == PACIBSP || sppc {
            let sctlr = self.cpu.controls(self.cpu.regime()).sctlr;
            let forbid = if self.cpu.pstate.el == 0 {
                SCTLR_BT0
            } else {
                SCTLR_BT1
            };
            return btype != 0b11 || sctlr & forbid == 0;
        }
        // BRK and HLT.
        matches!(word & 0xffe0_001f, 0xd420_0000 | 0xd440_0000)
    }

    /// The EL an FP/SIMD access traps to, if it traps (Arm
    /// `AArch64_CheckFPEnabled`): CPACR_EL1.FPEN at EL0 and EL1 outside the
    /// host, then CPTR_EL2.FPEN, which has the CPACR layout because
    /// HCR_EL2.E2H is RES1.
    fn floating_point_trap(&mut self) -> Option<u8> {
        *self
            .floating_point
            .get_or_insert_with(|| self.cpu.floating_point_trap())
    }

    fn floating_point_enabled(&mut self) -> bool {
        self.floating_point_trap().is_none()
    }

    fn floating_point_exception(&mut self, pc: u64) -> Exception {
        let exception = Exception::synchronous(Class::FloatingPointAccess, TRAPPED_AARCH64, pc);
        match self.floating_point_trap() {
            Some(el) => exception.to(el),
            None => exception,
        }
    }
}

/// Arm `AArch64_InterruptPending`: a physical IRQ or FIQ line, or at EL0
/// and EL1 outside the host a virtual IRQ, FIQ or SError that
/// HCR_EL2.{IMO,FMO,AMO} route and {VI,VF,VSE} hold, masked or not.
/// Whether `cpu`'s performance monitor asserts its PMI at count `now`.
fn monitor_asserted(cpu: &Cpu, now: u64) -> bool {
    cpu.pmu
        .as_ref()
        .is_some_and(|monitor| monitor.asserted(now, cpu.retired))
}

fn interrupt_pending(cpu: &Cpu, lines: Lines) -> bool {
    if lines.irq || lines.fiq {
        return true;
    }
    let hcr = cpu.read(SystemRegister::HCR_EL2);
    let routed = |routing: u32, pending: u32| {
        hcr & (1 << routing | 1 << pending) == 1 << routing | 1 << pending
    };
    cpu.pstate.el != 2
        && hcr & (1 << HCR_TGE) == 0
        && (routed(HCR_IMO, HCR_VI) || routed(HCR_FMO, HCR_VF) || routed(HCR_AMO, HCR_VSE))
}

impl<H: Host, D: Devices> Machine<H, D> {
    fn fetch_block(&mut self, pc: u64, single: bool) -> Result<Fetched, Stop> {
        let physical = match self.fetch_physical(pc) {
            Ok(physical) => physical,
            Err(Ok(exception)) => return Ok(Fetched::Exception(exception)),
            Err(Err(stop)) => return Err(stop),
        };
        let variant = Variant {
            fp: self.floating_point_enabled(),
            checks: self.memory_checks(),
            single,
            scalable: self
                .cpu
                .scalable
                .is_some()
                .then(|| self.cpu.svcr() & 1 != 0),
        };
        let slot = (pc / INSTRUCTION) as usize % JUMP_CACHE;
        if let Some(entry) = self.jump[slot]
            && entry.pc == pc
            && entry.physical == physical
            && entry.variant == variant
            && entry.generation == self.code_generation
        {
            return Ok(Fetched::Block(entry.block));
        }
        let index = match self.index.get(&(pc, physical, variant)) {
            Some(&index) => index,
            None => match self.compile(pc, physical, variant)? {
                Fetched::Block(index) => index,
                other => return Ok(other),
            },
        };
        self.jump[slot] = Some(JumpEntry {
            pc,
            physical,
            variant,
            generation: self.code_generation,
            block: index,
        });
        Ok(Fetched::Block(index))
    }

    /// Compile the block at `pc`, unless its first instruction is a
    /// trapped FP/SIMD instruction or one whose access checks the engine
    /// applies.
    fn compile(&mut self, pc: u64, physical: u64, variant: Variant) -> Result<Fetched, Stop> {
        let Variant {
            fp,
            checks,
            single,
            scalable,
        } = variant;
        let available = if single {
            INSTRUCTION
        } else {
            (FETCH_PAGE - (pc & (FETCH_PAGE - 1))).min(MAX_BLOCK_BYTES)
        };
        let mut source = vec![0u8; available as usize];
        if !self.host.read_ram(physical, &mut source) {
            return Err(self.unsupported(RequirementKind::Fetch { physical }));
        }
        // A form the chip lacks compiles as the UDF or NOP it executes as.
        for bytes in source.as_chunks_mut::<4>().0 {
            *bytes = self.admit(u32::from_le_bytes(*bytes)).to_le_bytes();
        }
        let chip = self.profile.chip;
        let mut length = source.len();
        if !fp {
            let first = source
                .as_chunks::<4>()
                .0
                .iter()
                .position(|word| is_floating_point(u32::from_le_bytes(*word)));
            match first {
                Some(0) => return Ok(Fetched::Exception(self.floating_point_exception(pc))),
                Some(index) => length = index * 4,
                None => {}
            }
        }
        if let Some(streaming) = scalable {
            let first = source.as_chunks::<4>().0[..length / 4]
                .iter()
                .map(|word| u32::from_le_bytes(*word))
                .position(|word| {
                    let checks = chip.checks(word);
                    if streaming {
                        !checks.is_empty()
                    } else {
                        checks
                            .iter()
                            .any(|check| !matches!(check, Check::Fp | Check::FpAdvSimd))
                    }
                });
            match first {
                Some(0) => {
                    let word = u32::from_le_bytes(source[..4].try_into().expect("a word"));
                    return Ok(Fetched::Checked(word));
                }
                Some(index) => length = index * 4,
                None => {}
            }
        }
        let consumed =
            match block::analyze_with_profile(&source[..length], GuestAddress(pc), PROFILE) {
                Ok(analysis) => analysis.source_bytes,
                Err(error) if error.pc.0 > pc => {
                    length = (error.pc.0 - pc) as usize;
                    block::analyze_with_profile(&source[..length], GuestAddress(pc), PROFILE)
                        .map_err(|error| {
                            self.unsupported_word(&source, pc, error.pc.0, error.detail)
                        })?
                        .source_bytes
                }
                Err(error) => return Err(self.unsupported_word(&source, pc, pc, error.detail)),
            };
        let compiled = self.compile_prefix(&source[..consumed], pc, checks)?;
        let code = match self.host.install(&compiled.native.x86_64_code) {
            Ok(code) => code,
            Err(InstallError::Full) => {
                self.discard_code();
                self.host
                    .install(&compiled.native.x86_64_code)
                    .map_err(|_| {
                        self.unsupported(RequirementKind::Native("block exceeds the code arena"))
                    })?
            }
        };
        self.statistics.compiled += 1;
        self.blocks.push(Block {
            pc,
            physical,
            code,
            source_map: compiled
                .native
                .source_map
                .iter()
                .map(|(guest, offset)| (guest.0, *offset))
                .collect(),
            checks,
        });
        let index = self.blocks.len() - 1;
        self.index.insert((pc, physical, variant), index);
        Ok(Fetched::Block(index))
    }

    /// Compile the longest prefix the host target can emit.
    fn compile_prefix(
        &self,
        source: &[u8],
        pc: u64,
        checks: MemoryChecks,
    ) -> Result<stela_compiler::block::CompiledBlock, Stop> {
        let attempt = |bytes: &[u8]| {
            CompilationPlan::new(bytes, GuestAddress(pc), PROFILE, self.target)
                .and_then(|plan| plan.with_memory_checks(checks))
                .and_then(CompilationPlan::compile)
        };
        match attempt(source) {
            Ok(compiled) => Ok(compiled),
            Err(error) => {
                // A host-capability refusal names no PC; find the longest
                // prefix that compiles and report the first refused word.
                let words = source.len() / 4;
                let (mut good, mut bad) = (0, words);
                while bad - good > 1 {
                    let middle = (good + bad) / 2;
                    if attempt(&source[..middle * 4]).is_ok() {
                        good = middle;
                    } else {
                        bad = middle;
                    }
                }
                if good == 0 {
                    return Err(self.unsupported_word(source, pc, pc, error.0));
                }
                attempt(&source[..good * 4])
                    .map_err(|error| self.unsupported_word(source, pc, pc, error.0))
            }
        }
    }

    fn unsupported_word(&self, source: &[u8], base: u64, pc: u64, detail: String) -> Stop {
        let offset = (pc - base) as usize;
        let word = source.get(offset..offset + 4).map_or(0, |bytes| {
            u32::from_le_bytes(bytes.try_into().expect("four bytes"))
        });
        Stop::Unsupported(Requirement {
            pc,
            el: self.cpu.pstate.el,
            kind: RequirementKind::Instruction { word, detail },
            syndrome: Some(super::exception::syndrome(Class::Unknown, 0)),
            address: None,
        })
    }

    /// The word an exit at `pc` executes, counted in [`Self::exit_words`].
    fn exit_word(&mut self, index: usize, pc: u64) -> Result<u32, Stop> {
        let word = self.word(index, pc)?;
        *self.exit_words.entry(word).or_default() += 1;
        Ok(word)
    }

    /// The word an instruction inside a compiled block executes as: its
    /// original word, or the UDF or NOP of a form the chip lacks.
    fn word(&mut self, index: usize, pc: u64) -> Result<u32, Stop> {
        let block = &self.blocks[index];
        let physical = block.physical + (pc - block.pc);
        let mut bytes = [0; 4];
        if !self.host.read_ram(physical, &mut bytes) {
            return Err(self.unsupported(RequirementKind::Fetch { physical }));
        }
        Ok(self.admit(u32::from_le_bytes(bytes)))
    }

    /// `Chip::admit` of the profile's chip, remembered: a pure function of
    /// the word that searches every absent-form group, and every exit asks it
    /// again of the word that exited.
    fn admit(&mut self, word: u32) -> u32 {
        let slot = (word.wrapping_mul(0x9e37_79b1) >> 20) as usize % ADMITTED;
        match self.admitted[slot] {
            Some((raw, admitted)) if raw == word => admitted,
            _ => {
                let admitted = self.profile.chip.admit(word);
                self.admitted[slot] = Some((word, admitted));
                admitted
            }
        }
    }

    fn exit(&mut self, index: usize, next_pc: u64, kind: u64) -> Step {
        let kind = ExitKind::try_from(kind);
        // BTYPE belongs to the block's first instruction until it completes;
        // a branch ending the block gives the next one (Arm `BTypeNext`).
        if next_pc != self.blocks[index].pc {
            self.cpu.pstate.btype = 0;
        }
        match kind {
            Ok(
                ExitKind::Fallthrough
                | ExitKind::Direct
                | ExitKind::Indirect
                | ExitKind::Call
                | ExitKind::Return,
            ) => {
                // The block's last instruction is the branch that ends it.
                self.cpu.retired += self.blocks[index].source_map.len() as u64;
                self.cpu.pstate.btype = self.native_branch_type(index, kind)?;
                self.cpu.pc = next_pc;
                Ok(())
            }
            Ok(ExitKind::System) => {
                self.retire_before(index, next_pc);
                self.cpu.pc = next_pc;
                self.statistics.system_exits += 1;
                let word = self.exit_word(index, next_pc)?;
                self.completing(next_pc, |machine| machine.system_instruction(word))
            }
            Ok(ExitKind::FloatingPoint) => {
                self.retire_before(index, next_pc);
                self.cpu.pc = next_pc;
                let word = self.exit_word(index, next_pc)?;
                let Some(Ok(operation)) = FloatingPointOperation::decode(word) else {
                    return Err(self.unsupported(RequirementKind::Native(
                        "numerical exit at a word that is not numerical FP",
                    )));
                };
                match crate::floating::complete(&mut self.cpu.state, &operation) {
                    Ok(()) => self.completing(next_pc, Self::next),
                    Err(_) => Err(self.unsupported(RequirementKind::Instruction {
                        word,
                        detail: format!(
                            "FPCR {:#x} enables a trapped FP exception",
                            self.cpu.state.fpcr
                        ),
                    })),
                }
            }
            Ok(ExitKind::PointerAuthentication) => {
                self.retire_before(index, next_pc);
                self.cpu.pc = next_pc;
                let word = self.exit_word(index, next_pc)?;
                self.completing(next_pc, |machine| machine.pointer_authentication(word))
            }
            Ok(ExitKind::Amx) => {
                self.retire_before(index, next_pc);
                self.cpu.pc = next_pc;
                let word = self.exit_word(index, next_pc)?;
                self.completing(next_pc, |machine| machine.amx(word))
            }
            _ => Err(self.unsupported(RequirementKind::Native("unknown block exit kind"))),
        }
    }

    /// BTYPE after a block that a native branch or fallthrough ended: BR and
    /// BLR set it, every other instruction clears it.
    fn native_branch_type(&mut self, index: usize, kind: Result<ExitKind, ()>) -> Result<u8, Stop> {
        const REGISTER_BRANCH: u32 = 0xffff_fc1f;
        const BR: u32 = 0xd61f_0000;
        const BLR: u32 = 0xd63f_0000;
        if !matches!(kind, Ok(ExitKind::Indirect | ExitKind::Call)) {
            return Ok(0);
        }
        let Some(&(terminal, _)) = self.blocks[index].source_map.last() else {
            return Ok(0);
        };
        let word = self.word(index, terminal)?;
        let register = ((word >> 5) & 31) as u8;
        Ok(match word & REGISTER_BRANCH {
            BR => self.indirect_branch_type(terminal, register, false),
            BLR => self.indirect_branch_type(terminal, register, true),
            _ => 0,
        })
    }

    /// Whether the current regime's SCTLR enables a PAC key (EnIA 31, EnIB 30,
    /// EnDA 27, EnDB 13).
    fn key_enabled(&self, key: PointerAuthenticationKey) -> bool {
        let bit = match key {
            PointerAuthenticationKey::Ia => 31,
            PointerAuthenticationKey::Ib => 30,
            PointerAuthenticationKey::Da => 27,
            PointerAuthenticationKey::Db => 13,
        };
        self.cpu.controls(self.cpu.regime()).sctlr & (1 << bit) != 0
    }

    /// The PAC keys as (low, high) words in APIA, APIB, APDA, APDB, APGA order.
    fn pointer_keys(&self) -> [[u64; 2]; 5] {
        use SystemRegister as R;
        let pair = |low, high| [self.cpu.read(low), self.cpu.read(high)];
        [
            pair(R::APIAKeyLo_EL1, R::APIAKeyHi_EL1),
            pair(R::APIBKeyLo_EL1, R::APIBKeyHi_EL1),
            pair(R::APDAKeyLo_EL1, R::APDAKeyHi_EL1),
            pair(R::APDBKeyLo_EL1, R::APDBKeyHi_EL1),
            pair(R::APGAKeyLo_EL1, R::APGAKeyHi_EL1),
        ]
    }

    /// The PAC algorithm version of the profile's chip: FEAT_FPACCOMBINE,
    /// FEAT_FPAC, FEAT_PAuth2 or the classic FEAT_PAuth insertion and error
    /// code (the M1). A chip feature the engine does not implement yet stops.
    fn pointer_version(&self) -> Result<pauth::Version, Stop> {
        let chip = self.profile.chip;
        let has = |feature| {
            chip.implemented(feature)
                .map_err(|reason| self.unsupported(RequirementKind::Native(reason)))
        };
        Ok(if has(Feature::FEAT_FPACCOMBINE)? {
            pauth::Version::FaultingCombined
        } else if has(Feature::FEAT_FPAC)? {
            pauth::Version::Faulting
        } else if has(Feature::FEAT_PAuth2)? {
            pauth::Version::Enhanced
        } else {
            pauth::Version::Classic
        })
    }

    /// The guest's PAC keys and the current regime's TCR layout, with the
    /// chip's PAC version.
    fn pointer_context(&self) -> Result<pauth::Context, Stop> {
        let keys = self.pointer_keys();
        Ok(pauth::Context::new_with_version(
            0,
            pauth::Keys::from_words(keys[0], keys[1], keys[2], keys[3]).with_generic_words(keys[4]),
            self.pointer_version()?,
        )
        .with_translation_regime(self.cpu.controls(self.cpu.regime()).tcr))
    }

    /// Whether HCR_EL2.API clear traps the use of an enabled key, or PACGA,
    /// to EL2: from EL1, and from EL0 outside the host (Arm
    /// `IsAPIAKeyEnabled` and the other key checks, `AddPACGA`).
    fn pointer_authentication_trapped(&self) -> bool {
        let el = self.cpu.pstate.el;
        (el == 1 || (el == 0 && !self.cpu.in_host())) && !self.cpu.hcr(HCR_API)
    }

    /// Arm `TrapPACUse(EL2)`: EC 0x09 with ISS 0 at the instruction.
    fn pointer_authentication_trap(&mut self) -> Step {
        let pc = self.cpu.pc;
        self.take(Exception::synchronous(Class::PointerAuthenticationTrap, 0, pc).to(2));
        Ok(())
    }

    /// Complete one PAC instruction with the guest's own keys, laid out for
    /// the current TCR. The algorithm is the software QARMA5 service as
    /// FEAT_PAuth2 with FEAT_FPAC; Apple's hardware algorithm and AppleMode
    /// diversification are not reproduced, so values are self-consistent
    /// rather than equal to hardware's. A failed standalone AUT* takes the
    /// PAC Fail exception (EC 0x1C) to the current EL, or from EL0 to EL1 or
    /// the host's EL2 (Arm `AArch64_PACFailException`).
    fn pointer_authentication(&mut self, word: u32) -> Step {
        let pc = self.cpu.pc;
        let refuse = |machine: &Self, detail: String| {
            Err(machine.unsupported(RequirementKind::Instruction { word, detail }))
        };
        let instruction = match block::decode_pointer_authentication(GuestAddress(pc), word) {
            Ok(Some(instruction)) => instruction,
            _ => return refuse(self, "PAC exit at a word that is not PAC".into()),
        };
        let link_register = self
            .profile
            .chip
            .implemented(Feature::FEAT_PAuth_LR)
            .map_err(|reason| self.unsupported(RequirementKind::Native(reason)))?;
        // Without FEAT_PAuth_LR its hint-space form (PACM) is a NOP and the
        // others are UNDEFINED.
        if let PointerAuthenticationOperation::LinkRegister(form) = instruction.operation {
            if !link_register {
                return if word & 0xffff_f01f == 0xd503_201f {
                    self.next()
                } else {
                    self.undefined()
                };
            }
            if form == block::pauth_lr::Instruction::Pacm {
                self.cpu.pstate.pacm = self.cpu.pacm_enabled();
                self.pacm_written = true;
                return self.next();
            }
            let staged = pauth::lr_instruction::stage(
                form,
                pc,
                self.cpu.state.x[..31].try_into().expect("31 registers"),
                self.cpu.state.sp,
            );
            return match staged {
                Ok(pauth::lr_instruction::Staged::Pointer(operands)) => {
                    self.two_modifier_authentication(word, instruction, operands)
                }
                _ => refuse(self, "FEAT_PAuth_LR operands".into()),
            };
        }
        if link_register
            && self.cpu.pstate.pacm
            && let Some(operands) = self.pacm_operands(instruction)
        {
            return self.two_modifier_authentication(word, instruction, operands);
        }
        let uses_key = match instruction.operation.required_key() {
            Some(key) if !self.key_enabled(key) => {
                return self.disabled_pointer_authentication(word, instruction);
            }
            Some(_) => true,
            None => matches!(
                instruction.operation,
                PointerAuthenticationOperation::GenericCode(_)
            ),
        };
        if uses_key && self.pointer_authentication_trapped() {
            return self.pointer_authentication_trap();
        }
        let context = self.pointer_context()?;
        if let PointerAuthenticationOperation::Load(load) = instruction.operation {
            return self.authenticated_load(word, &context, load);
        }
        match crate::blocks::services::complete_pauth_with_memory(
            &context,
            &instruction,
            &mut self.cpu.state,
            None,
        ) {
            Ok((next, _)) => {
                self.cpu.pstate.btype = self.pointer_branch_type(pc, instruction.operation);
                self.cpu.pc = next.0;
                Ok(())
            }
            Err(error) => match error.downcast_ref::<pauth::AuthenticationError>() {
                Some(&pauth::AuthenticationError::Failure { code }) => {
                    self.take(Exception::synchronous(
                        Class::PointerAuthenticationFailure,
                        u32::from(code),
                        pc,
                    ));
                    Ok(())
                }
                _ => refuse(self, format!("{error:#}")),
            },
        }
    }

    /// The two-modifier operation PSTATE.PACM makes of a PAC*SP, AUT*SP,
    /// RETA* or HINT-space *1716 instruction (Arm PACIA, AUTIA and RETAA
    /// under FEAT_PAuth_LR): the signing forms take the instruction's PC as
    /// the second modifier, the authenticating forms X16, and the *1716
    /// forms X15.
    fn pacm_operands(
        &self,
        instruction: PointerAuthentication,
    ) -> Option<pauth::lr_instruction::Operands> {
        use PointerAuthenticationModifier::StackPointer;
        use PointerAuthenticationOperation as Operation;
        use pauth::lr_instruction::{Action, Key};
        let x = &self.cpu.state.x;
        let (sp, pc) = (self.cpu.state.sp, instruction.instruction_pc.0);
        let key = |key| match key {
            PointerAuthenticationKey::Ia => Some(Key::Ia),
            PointerAuthenticationKey::Ib => Some(Key::Ib),
            _ => None,
        };
        let register = |index: u8| {
            if index == 31 {
                0
            } else {
                x[usize::from(index)]
            }
        };
        let (key, action, destination, modifiers) = match instruction.operation {
            Operation::Sign {
                key: k,
                destination,
                modifier: StackPointer,
            } => (key(k)?, Action::Sign, Some(destination), (sp, pc)),
            Operation::SignIbSp => (Key::Ib, Action::Sign, Some(30), (sp, pc)),
            Operation::Sign1716 { key: k } => (key(k)?, Action::Sign, Some(17), (x[16], x[15])),
            Operation::Authenticate {
                key: k,
                destination,
                modifier: StackPointer,
            } => (
                key(k)?,
                Action::Authenticate,
                Some(destination),
                (sp, x[16]),
            ),
            Operation::AuthenticateIbSp => (Key::Ib, Action::Authenticate, Some(30), (sp, x[16])),
            Operation::Authenticate1716 { key: k } => {
                (key(k)?, Action::Authenticate, Some(17), (x[16], x[15]))
            }
            Operation::ReturnIaSp => (Key::Ia, Action::Return, None, (sp, x[16])),
            Operation::ReturnIbSp => (Key::Ib, Action::Return, None, (sp, x[16])),
            _ => return None,
        };
        let pointer = match destination {
            Some(destination) => register(destination),
            None => x[30],
        };
        Some(pauth::lr_instruction::Operands {
            key,
            action,
            pointer,
            modifier1: modifiers.0,
            modifier2: modifiers.1,
            destination,
            implicit_bti: false,
            instruction_pc: pc,
        })
    }

    /// Arm AddPACIA2, AddPACIB2, AuthIA2 and AuthIB2 with the guest's keys:
    /// with the key's SCTLR enable clear the pointer is unchanged, HCR_EL2.API
    /// clear traps the use, a failed AUT* takes the PAC Fail exception
    /// (FEAT_FPAC) and so does a failed RETA* (FEAT_FPACCOMBINE).
    fn two_modifier_authentication(
        &mut self,
        word: u32,
        instruction: PointerAuthentication,
        operands: pauth::lr_instruction::Operands,
    ) -> Step {
        use pauth::lr_instruction::{Action, Key};
        let pc = self.cpu.pc;
        let (key, runtime_key) = match operands.key {
            Key::Ia => (PointerAuthenticationKey::Ia, pauth::Key::Ia),
            Key::Ib => (PointerAuthenticationKey::Ib, pauth::Key::Ib),
        };
        if !self.key_enabled(key) {
            return self.disabled_pointer_authentication(word, instruction);
        }
        if self.pointer_authentication_trapped() {
            return self.pointer_authentication_trap();
        }
        let context = self.pointer_context()?;
        let refuse = |machine: &Self, detail: String| {
            Err(machine.unsupported(RequirementKind::Instruction { word, detail }))
        };
        let (pointer, m1, m2) = (operands.pointer, operands.modifier1, operands.modifier2);
        let result = match operands.action {
            Action::Sign => match context.sign_two_modifiers(runtime_key, pointer, m1, m2) {
                Ok(signed) => Ok(signed),
                Err(error) => return refuse(self, format!("{error:?}")),
            },
            Action::Authenticate | Action::Return => {
                let combined = operands.action == Action::Return;
                match context.authenticate_two_modifiers(runtime_key, pointer, m1, m2, combined) {
                    Ok(Ok(result)) => Ok(result.pointer),
                    Ok(Err(pauth::AuthenticationError::Failure { code })) => Err(code),
                    Ok(Err(error)) => return refuse(self, format!("{error:?}")),
                    Err(error) => return refuse(self, format!("{error:?}")),
                }
            }
        };
        let value = match result {
            Ok(value) => value,
            Err(code) => {
                self.take(Exception::synchronous(
                    Class::PointerAuthenticationFailure,
                    u32::from(code),
                    pc,
                ));
                return Ok(());
            }
        };
        self.cpu.pstate.btype = 0;
        match operands.destination {
            Some(31) => self.cpu.pc = instruction.next_pc.0,
            Some(destination) => {
                self.cpu.state.x[usize::from(destination)] = value;
                self.cpu.pc = instruction.next_pc.0;
            }
            None => self.cpu.pc = value,
        }
        Ok(())
    }

    /// BTYPE after a completed PAC instruction at `pc`: BRA* and BLRA* set it
    /// as BR and BLR do, every other form clears it.
    fn pointer_branch_type(&mut self, pc: u64, operation: PointerAuthenticationOperation) -> u8 {
        match operation {
            PointerAuthenticationOperation::Branch { target, link, .. } => {
                self.indirect_branch_type(pc, target, link)
            }
            _ => 0,
        }
    }

    /// With the key's SCTLR enable clear, AddPAC and Auth return the pointer
    /// unchanged (Arm ARM `AddPAC`, `Auth`).
    fn disabled_pointer_authentication(
        &mut self,
        word: u32,
        instruction: PointerAuthentication,
    ) -> Step {
        use PointerAuthenticationOperation as Operation;
        let next = instruction.next_pc.0;
        self.cpu.pstate.btype = self.pointer_branch_type(self.cpu.pc, instruction.operation);
        match instruction.operation {
            Operation::Sign1716 { .. }
            | Operation::Authenticate1716 { .. }
            | Operation::SignIbSp
            | Operation::AuthenticateIbSp
            | Operation::Sign { .. }
            | Operation::Authenticate { .. } => self.cpu.pc = next,
            Operation::ReturnIbSp | Operation::ReturnIaSp => self.cpu.pc = self.cpu.state.x[30],
            Operation::LinkRegister(form) if form.is_return() => {
                self.cpu.pc = self.cpu.state.x[30];
            }
            Operation::LinkRegister(_) => self.cpu.pc = next,
            Operation::Branch { target, link, .. } => {
                let destination = if target == 31 {
                    0
                } else {
                    self.cpu.state.x[usize::from(target)]
                };
                if link {
                    self.cpu.state.x[30] = next;
                }
                self.cpu.pc = destination;
            }
            _ => {
                return Err(self.unsupported(RequirementKind::Instruction {
                    word,
                    detail: "PAC load or LR form with its key disabled".into(),
                }));
            }
        }
        Ok(())
    }

    /// LDRAA/LDRAB: authenticate the base, then read through the guest's
    /// translation like any data load.
    fn authenticated_load(
        &mut self,
        word: u32,
        context: &pauth::Context,
        load: stela_compiler::block::pauth_memory::Load,
    ) -> Step {
        let pc = self.cpu.pc;
        let controls = self.cpu.controls(self.cpu.regime());
        let requester = self.cpu.requester();
        let sctlr = controls.sctlr;
        let memory_controls = pauth::memory::Controls {
            check_sp_alignment: if requester.el == 0 {
                sctlr & (1 << 4) != 0
            } else {
                sctlr & (1 << 3) != 0
            },
            privileged: requester.el != 0,
        };
        enum LoadStop {
            Alignment,
            Fault(mmu::Fault),
            Unsupported(mmu::Unsupported),
            Device(u64),
        }
        // A RAM read has no side effects: the load is made, then checked
        // against the watchpoints, and undone if one matches.
        let before = self.cpu.state.clone();
        let loaded = core::cell::Cell::new(None);
        let host = &mut self.host;
        let result = pauth::memory::complete(
            load,
            memory_controls,
            &mut self.cpu.state,
            |key, pointer| {
                let key = match key {
                    stela_compiler::block::pauth_memory::DataKey::A => pauth::Key::Da,
                    stela_compiler::block::pauth_memory::DataKey::B => pauth::Key::Db,
                };
                context
                    .authenticate_operation(key, pointer, 0, true)
                    .map(|result| result.pointer)
            },
            |address| {
                let shape = mmu::alignment::Shape {
                    kind: mmu::alignment::Kind::Plain,
                    bytes: 8,
                    pair: false,
                };
                if mmu::alignment::before_translation(sctlr, address, shape) {
                    return Err(LoadStop::Alignment);
                }
                let translation = match mmu::translate(
                    &controls,
                    address,
                    Access::Read,
                    requester,
                    &mut RamTables(host),
                ) {
                    Translated::Mapped(translation) => translation,
                    Translated::Fault(fault) => return Err(LoadStop::Fault(fault)),
                    Translated::Unsupported(unsupported) => {
                        return Err(LoadStop::Unsupported(unsupported));
                    }
                };
                let mut bytes = [0; 8];
                if (address & (FETCH_PAGE - 1)) > FETCH_PAGE - 8 {
                    return Err(LoadStop::Device(translation.physical));
                }
                loaded.set(Some(address));
                if !host.read_ram(translation.physical, &mut bytes) {
                    return Err(LoadStop::Device(translation.physical));
                }
                Ok(u64::from_le_bytes(bytes))
            },
        );
        match result {
            Ok(_) => {
                let access = loaded.get().map(|address| debug::Access {
                    address,
                    size: 8,
                    read: true,
                    write: false,
                    maintenance: false,
                    el: requester.el,
                });
                if let Some(exception) =
                    access.and_then(|access| self.watchpoint_exception(&access, pc))
                {
                    self.cpu.state = before;
                    self.take(exception);
                    return Ok(());
                }
                self.cpu.pc = pc;
                self.next()
            }
            Err(pauth::memory::Fault::Read {
                address,
                error: LoadStop::Fault(fault),
            }) => self.data_abort(address, fault, false, false),
            Err(pauth::memory::Fault::Read {
                address,
                error: LoadStop::Alignment,
            }) => self.alignment_fault(address, false),
            Err(pauth::memory::Fault::Read {
                error: LoadStop::Unsupported(unsupported),
                ..
            }) => Err(self.unsupported(RequirementKind::Translation(unsupported))),
            Err(pauth::memory::Fault::StackAlignment { .. }) => {
                self.take(Exception::synchronous(Class::SpAlignment, 0, pc));
                Ok(())
            }
            // FEAT_FPACCOMBINE: a failed authentication of the base faults
            // as a standalone AUT does.
            Err(pauth::memory::Fault::Authentication(pauth::AuthenticationError::Failure {
                code,
            })) => {
                self.take(Exception::synchronous(
                    Class::PointerAuthenticationFailure,
                    u32::from(code),
                    pc,
                ));
                Ok(())
            }
            Err(other) => Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: match other {
                    pauth::memory::Fault::Read {
                        error: LoadStop::Device(physical),
                        ..
                    } => format!("LDRA from non-RAM or page-crossing address (PA {physical:#x})"),
                    _ => "LDRA operands or authentication".into(),
                },
            })),
        }
    }

    /// Guest PC of the instruction containing native `offset`.
    fn faulting_pc(&self, index: usize, offset: usize) -> u64 {
        let map = &self.blocks[index].source_map;
        let position = map.partition_point(|(_, start)| *start <= offset);
        map[position.saturating_sub(1)].0
    }

    fn native_fault(&mut self, index: usize, fault: NativeFault) -> Step {
        let pc = self.faulting_pc(index, fault.offset);
        self.retire_before(index, pc);
        self.cpu.pc = pc;
        if pc != self.blocks[index].pc {
            self.cpu.pstate.btype = 0;
        }
        match fault.cause {
            FaultCause::Guest(guest) => self.data_abort(fault.address, guest, fault.write, false),
            FaultCause::Device { physical } => {
                let word = self.word(index, pc)?;
                self.completing(pc, |machine| {
                    machine.device_access(word, fault.address, physical, fault.write)
                })
            }
            FaultCause::Translation(unsupported) => {
                Err(self.unsupported(RequirementKind::Translation(unsupported)))
            }
            FaultCause::NonCanonical => {
                let mut requirement = self.requirement(RequirementKind::Native(
                    "x86 #GP: non-canonical guest address (tagged or outside both ranges)",
                ));
                requirement.address = Some(fault.address);
                Err(Stop::Unsupported(requirement))
            }
            // Native blocks raise #UD for a misaligned SP base when compiled
            // with the check (SCTLR_ELx.SA or SA0 set), which comes first,
            // and for an access that has an Alignment fault: unaligned under
            // SCTLR_ELx.A, or an atomic, or an ordered access with nAA
            // clear, crossing its 16-byte granule.
            FaultCause::Watched => self.watched_access(index, pc),
            FaultCause::InvalidOpcode => {
                let word = self.word(index, pc)?;
                if self.blocks[index].checks.stack_alignment
                    && stack_based(word)
                    && !self.cpu.state.sp.is_multiple_of(16)
                {
                    self.take(Exception::synchronous(Class::SpAlignment, 0, pc));
                    Ok(())
                } else {
                    self.native_alignment_fault(pc, word)
                }
            }
        }
    }

    /// ADDPT, SUBPT, MADDPT and MSUBPT (FEAT_CPA), UNDEFINED on a chip
    /// without it. No Apple chip has FEAT_CPA2, so `EffectiveCPTA` and
    /// `EffectiveCPTM` are 0 and `PointerAddCheck` and
    /// `PointerMultiplyAddCheck` return the plain sum.
    fn checked_pointer(
        &mut self,
        operand: stela_compiler::aarch64::checked_pointer::Operand,
    ) -> Step {
        use stela_compiler::aarch64::checked_pointer::Kind;
        match self.profile.chip.implemented(Feature::FEAT_CPA) {
            Ok(true) => {}
            Ok(false) => return self.undefined(),
            Err(reason) => return Err(self.unsupported(RequirementKind::Native(reason))),
        }
        let (base, change, subtract) = match operand.kind {
            Kind::Offset {
                base,
                offset,
                amount,
                subtract,
            } => (base, self.read_register(offset) << amount, subtract),
            Kind::Product {
                left,
                right,
                base,
                subtract,
            } => (
                base,
                self.read_register(left)
                    .wrapping_mul(self.read_register(right)),
                subtract,
            ),
        };
        let base = self.read_register(base);
        let result = if subtract {
            base.wrapping_sub(change)
        } else {
            base.wrapping_add(change)
        };
        self.write_register(operand.destination, result);
        self.next()
    }

    fn read_register(&self, register: Register) -> u64 {
        match register {
            Register::X(index) => self.cpu.state.x[usize::from(index)],
            Register::Sp => self.cpu.state.sp,
            Register::Zero => 0,
        }
    }

    fn write_register(&mut self, register: Register, value: u64) {
        match register {
            Register::X(index) => self.cpu.state.x[usize::from(index)] = value,
            Register::Sp => self.cpu.state.sp = value,
            Register::Zero => {}
        }
    }

    /// (access address, writeback) for a scalar transfer.
    fn scalar_address(&self, address: ScalarLoadAddress) -> (u64, Option<(Register, u64)>) {
        match address {
            ScalarLoadAddress::Literal { address } => (address, None),
            ScalarLoadAddress::Immediate {
                base,
                displacement,
                mode,
            } => {
                let base_value = self.read_register(base);
                let updated = base_value.wrapping_add(displacement as i64 as u64);
                match mode {
                    AddressMode::Offset => (updated, None),
                    AddressMode::PreIndex => (updated, Some((base, updated))),
                    AddressMode::PostIndex => (base_value, Some((base, updated))),
                }
            }
            ScalarLoadAddress::RegisterOffset {
                base,
                index,
                extend,
                shift,
            } => {
                let raw = self.read_register(index);
                let extended = match extend {
                    IndexExtend::Uxtw => raw & 0xffff_ffff,
                    IndexExtend::Sxtw => raw as u32 as i32 as i64 as u64,
                    IndexExtend::Lsl | IndexExtend::Sxtx => raw,
                };
                (
                    self.read_register(base).wrapping_add(extended << shift),
                    None,
                )
            }
        }
    }

    /// Complete one single-register scalar access to a device.
    fn device_access(&mut self, word: u32, address: u64, physical: u64, write: bool) -> Step {
        let pc = self.cpu.pc;
        let refuse = |machine: &Self, detail: String| {
            let mut requirement = machine.requirement(RequirementKind::Device {
                physical,
                write,
                detail,
            });
            requirement.address = Some(address);
            Stop::Unsupported(requirement)
        };
        let Ok(instruction) = Decoder.lift(GuestAddress(pc), word) else {
            return Err(refuse(
                self,
                "device access by an undecodable instruction".into(),
            ));
        };
        self.statistics.device_accesses += 1;
        if let Some(load) = ScalarLoad::from_instruction(&instruction) {
            let (accessed, writeback) = self.scalar_address(load.address());
            if accessed != address {
                return Err(refuse(
                    self,
                    "device load address differs from the fault".into(),
                ));
            }
            let bytes = load.bytes();
            if !address.is_multiple_of(u64::from(bytes)) {
                return self.alignment_fault(address, false);
            }
            let now = self.host.counter();
            let raw = match self.devices.read(self.current, physical, bytes, now) {
                Ok(value) => value,
                Err(DeviceError::NoDevice) => return Err(refuse(self, "no device model".into())),
                Err(DeviceError::Refused(detail)) => return Err(refuse(self, detail)),
            };
            let bits = u32::from(bytes) * 8;
            let mut value = if bits == 64 {
                raw
            } else {
                raw & ((1u64 << bits) - 1)
            };
            if load.signed() && bits < 64 {
                let shift = 64 - bits;
                value = (((value << shift) as i64) >> shift) as u64;
            }
            if load.result_width() == Width::W32 {
                value &= 0xffff_ffff;
            }
            self.write_register(load.destination(), value);
            if let Some((base, updated)) = writeback {
                self.write_register(base, updated);
            }
        } else if let Some(store) = ScalarStore::from_instruction(&instruction) {
            let (accessed, writeback) = self.scalar_address(store.address());
            if accessed != address {
                return Err(refuse(
                    self,
                    "device store address differs from the fault".into(),
                ));
            }
            let bytes = store.bytes();
            if !address.is_multiple_of(u64::from(bytes)) {
                return self.alignment_fault(address, true);
            }
            let value = self.read_register(store.source_register());
            let now = self.host.counter();
            match self
                .devices
                .write(self.current, physical, bytes, value, now)
            {
                Ok(()) => {}
                Err(DeviceError::NoDevice) => return Err(refuse(self, "no device model".into())),
                Err(DeviceError::Refused(detail)) => return Err(refuse(self, detail)),
            }
            if let Some((base, updated)) = writeback {
                self.write_register(base, updated);
            }
            self.follow_memory_lock();
        } else {
            return Err(refuse(
                self,
                "device access by other than a single-register scalar integer transfer".into(),
            ));
        }
        self.cpu.pc = pc;
        self.next()?;
        match self.devices.take_reset() {
            Some(reason) => Err(Stop::Reset(reason)),
            None => Ok(()),
        }
    }

    /// Give every PE the memory controller's write lock after a device
    /// write changed it.
    fn follow_memory_lock(&mut self) {
        let lock = self.devices.memory_lock();
        if lock == self.cpu.memory_lock {
            return;
        }
        self.cpu.memory_lock = lock;
        for peer in &mut self.peers {
            if let processors::Peer::Parked(parked) = peer {
                parked.cpu_mut().memory_lock = lock;
            }
        }
        self.translations_changed();
    }

    fn alignment_fault(&mut self, address: u64, write: bool) -> Step {
        let class = if self.cpu.route() > self.cpu.pstate.el {
            Class::DataAbortLower
        } else {
            Class::DataAbortSame
        };
        let mut exception =
            Exception::synchronous(class, data_abort_iss(0b10_0001, write), self.cpu.pc);
        exception.fault_address = Some(address);
        self.take(exception);
        Ok(())
    }

    /// Complete the current instruction: the PC advances and BTYPE clears.
    fn next(&mut self) -> Step {
        self.cpu.pc += INSTRUCTION;
        self.cpu.pstate.btype = 0;
        Ok(())
    }

    fn undefined(&mut self) -> Step {
        self.take(Exception::undefined(self.cpu.pc));
        Ok(())
    }

    fn refuse_system(&self, word: u32, detail: &'static str) -> Stop {
        self.unsupported(RequirementKind::SystemInstruction { word, detail })
    }

    fn system_instruction(&mut self, word: u32) -> Step {
        let pc = self.cpu.pc;
        let instruction = match block::decode_system_mode_instruction(GuestAddress(pc), word) {
            Ok(Some(instruction)) => instruction,
            _ => return Err(self.refuse_system(word, "System exit at a word that is not System")),
        };
        match instruction.operation {
            SystemOperation::Exception(operation) => self.exception_instruction(operation),
            SystemOperation::Register(access) => self.register_instruction(word, access),
            SystemOperation::PstateImmediate(encoding) => {
                let outcome = self.cpu.write_pstate_field(encoding);
                self.register_outcome(word, None, outcome)
            }
            SystemOperation::Maintenance(access) => self.maintenance(word, access),
            SystemOperation::InstructionSynchronization { .. } => self.next(),
            SystemOperation::Synchronization(operation) => match operation {
                // DSB nXS waits for a subset of what DSB waits for (accesses
                // to memory with XS 0), and is UNDEFINED without FEAT_XS.
                Synchronization::DataCompletion { nxs: true, .. } => {
                    match self.profile.chip.implemented(Feature::FEAT_XS) {
                        Ok(true) => self.next(),
                        Ok(false) => self.undefined(),
                        Err(reason) => Err(self.unsupported(RequirementKind::Native(reason))),
                    }
                }
                Synchronization::ErrorSynchronization => self.error_synchronization(),
                Synchronization::DataCompletion { .. }
                | Synchronization::StoreBypassBarrier { .. }
                | Synchronization::BranchTarget { .. }
                | Synchronization::TraceSynchronization
                | Synchronization::OtherHint { .. }
                | Synchronization::Yield
                | Synchronization::ConsumptionBarrier
                | Synchronization::SpeculationBarrier => {
                    // One PE runs at a time and its accesses complete in
                    // program order before another runs (`processors`):
                    // completion and hints have no further effect.
                    self.next()
                }
                Synchronization::SendEvent { .. } | Synchronization::Wait { .. } => {
                    Err(self.refuse_system(word, "unexpected synchronization family"))
                }
                Synchronization::InstructionSynchronization { .. } => self.next(),
            },
            SystemOperation::SendEvent { local } => {
                self.send_event(local);
                self.next()
            }
            SystemOperation::Wait {
                kind,
                timeout_register,
            } => self.wait(word, kind, timeout_register),
            // No halting debug: Debug-state-only instructions are UNDEFINED.
            SystemOperation::TagMemory(_) | SystemOperation::DebugStateOnly(_) => self.undefined(),
            SystemOperation::Unprivileged(operand) => self.unprivileged(operand),
            SystemOperation::Exclusive(Ok(operand)) => self.exclusive(operand),
            SystemOperation::Exclusive(Err(_)) => self.undefined(),
            SystemOperation::CheckedPointer(operand) => self.checked_pointer(operand),
            SystemOperation::Guarded(GuardedOperation::Enter) => {
                if self.cpu.guarded_enter().is_err() {
                    return self.undefined();
                }
                self.host.report(&Event::Guarded {
                    enter: true,
                    el: self.cpu.pstate.el,
                    guarded: true,
                    pc: self.cpu.pc,
                });
                self.sync_regime();
                Ok(())
            }
            SystemOperation::Guarded(GuardedOperation::Exit) => match self.cpu.guarded_exit() {
                Err(_) => self.undefined(),
                Ok(Err(reason)) => Err(self.unsupported(RequirementKind::IllegalReturn(reason))),
                Ok(Ok(())) => {
                    self.pacm_written = true;
                    self.host.report(&Event::Guarded {
                        enter: false,
                        el: self.cpu.pstate.el,
                        guarded: self.cpu.pstate.guarded,
                        pc: self.cpu.pc,
                    });
                    self.sync_regime();
                    Ok(())
                }
            },
        }
    }

    fn exception_instruction(&mut self, operation: ExceptionOperation) -> Step {
        let pc = self.cpu.pc;
        match operation {
            // HFGITR_EL2.SVC_EL1 and SVC_EL0 trap SVC from EL1, and from EL0
            // outside the host, to EL2 at the SVC itself (Arm
            // `AArch64_CheckForSVCTrap`).
            ExceptionOperation::SupervisorCall { immediate }
                if self.cpu.pstate.el != 2
                    && self.fine_grained_trap(if self.cpu.pstate.el == 1 {
                        HFGITR_SVC_EL1
                    } else {
                        HFGITR_SVC_EL0
                    }) =>
            {
                self.take(
                    Exception::synchronous(Class::SupervisorCall, u32::from(immediate), pc).to(2),
                );
                Ok(())
            }
            // To EL1, or to EL2 from EL2 and from EL0 in the host.
            ExceptionOperation::SupervisorCall { immediate } => {
                self.advance_step();
                self.take(Exception::synchronous(
                    Class::SupervisorCall,
                    u32::from(immediate),
                    pc + INSTRUCTION,
                ));
                Ok(())
            }
            // BRK: to EL2 from EL2, or under HCR_EL2.TGE or MDCR_EL2.TDE
            // (Arm `AArch64_SoftwareBreakpoint`).
            ExceptionOperation::SoftwareBreakpoint { immediate } => {
                let exception = self.debug_exception(
                    Class::Breakpoint,
                    Class::Breakpoint,
                    u32::from(immediate),
                    pc,
                );
                self.take(exception);
                Ok(())
            }
            ExceptionOperation::ExceptionReturn { key } => self.exception_return(key),
            // HVC from EL1 and EL2 goes to EL2, unless HCR_EL2.HCD disables it.
            ExceptionOperation::HypervisorCall { immediate }
                if self.cpu.pstate.el != 0 && !self.cpu.hcr(HCR_HCD) =>
            {
                self.advance_step();
                self.take(
                    Exception::synchronous(
                        Class::HypervisorCall,
                        u32::from(immediate),
                        pc + INSTRUCTION,
                    )
                    .to(2),
                );
                Ok(())
            }
            // Without EL3, SMC is UNDEFINED, except that HCR_EL2.TSC traps it
            // from EL1 to EL2, returning to the SMC itself (Arm
            // `AArch64_CheckForSMCUndefOrTrap`).
            ExceptionOperation::SecureMonitorCall { immediate }
                if self.cpu.pstate.el == 1 && self.cpu.hcr(HCR_TSC) =>
            {
                self.take(
                    Exception::synchronous(Class::MonitorCall, u32::from(immediate), pc).to(2),
                );
                Ok(())
            }
            // No EL3, debug state or halting, and HVC from EL0 or with HCD:
            // all UNDEFINED.
            ExceptionOperation::HypervisorCall { .. }
            | ExceptionOperation::SecureMonitorCall { .. }
            | ExceptionOperation::Halt { .. }
            | ExceptionOperation::DebugChange { .. }
            | ExceptionOperation::DebugReturn
            | ExceptionOperation::Undefined { .. } => self.undefined(),
        }
    }

    /// Whether HFGITR_EL2 bit `bit` traps an instruction from EL1, or from
    /// EL0 outside the host (FEAT_FGT without EL3, so always enabled).
    fn fine_grained_trap(&self, bit: u32) -> bool {
        let el = self.cpu.pstate.el;
        (el == 1 || (el == 0 && !self.cpu.in_host()))
            && self.cpu.read(SystemRegister::HFGITR_EL2) & (1 << bit) != 0
    }

    /// ERET, ERETAA and ERETAB (Arm `AArch64_CheckForERetTrap`, `AuthIA`,
    /// `AuthIB` and `AArch64_ExceptionReturn`).
    fn exception_return(&mut self, key: Option<AuthenticationKey>) -> Step {
        let pc = self.cpu.pc;
        if self.cpu.pstate.el == 0 {
            return self.undefined();
        }
        // HFGITR_EL2.ERET, or HCR_EL2.NV in effect (no FEAT_NV3), traps an
        // EL1 ERET to EL2 (Arm `AArch64_CheckForERetTrap`).
        if self.fine_grained_trap(HFGITR_ERET)
            || self.cpu.pstate.el == 1 && self.cpu.nested() & 1 != 0
        {
            let iss = match key {
                None => 0,
                Some(AuthenticationKey::A) => 0b10,
                Some(AuthenticationKey::B) => 0b11,
            };
            self.take(Exception::synchronous(Class::ExceptionReturnTrap, iss, pc).to(2));
            return Ok(());
        }
        let mut target = self.cpu.exception_link();
        if let Some(key) = key {
            let key = match key {
                AuthenticationKey::A => PointerAuthenticationKey::Ia,
                AuthenticationKey::B => PointerAuthenticationKey::Ib,
            };
            if self.key_enabled(key) {
                if self.pointer_authentication_trapped() {
                    return self.pointer_authentication_trap();
                }
                let runtime_key = match key {
                    PointerAuthenticationKey::Ia => pauth::Key::Ia,
                    _ => pauth::Key::Ib,
                };
                // A combined authentication: a failure corrupts the pointer,
                // or with FEAT_FPACCOMBINE takes the PAC Fail exception at
                // the ERETA* (Arm `AuthIA`, `Authenticate`).
                match self.pointer_context()?.authenticate_operation(
                    runtime_key,
                    target,
                    self.cpu.state.sp,
                    true,
                ) {
                    Ok(result) => target = result.pointer,
                    Err(pauth::AuthenticationError::Failure { code }) => {
                        self.take(Exception::synchronous(
                            Class::PointerAuthenticationFailure,
                            u32::from(code),
                            pc,
                        ));
                        return Ok(());
                    }
                    Err(_) => {
                        return Err(self.unsupported(RequirementKind::Native(
                            "ERETAA/ERETAB authentication without its key",
                        )));
                    }
                }
            }
        }
        self.cpu.exception_return(target);
        self.pacm_written = true;
        self.host.report(&Event::Return {
            to_el: self.cpu.pstate.el,
            guarded: self.cpu.pstate.guarded,
            pc: self.cpu.pc,
        });
        self.sync_regime();
        Ok(())
    }

    /// ESB: at EL0 or EL1 outside the host with HCR_EL2.AMO set, a virtual
    /// SError pending but masked by PSTATE.A is deferred into VDISR_EL2 (Arm
    /// `AArch64_vESBOperation`). No physical SError is ever pending.
    fn error_synchronization(&mut self) -> Step {
        let hcr = self.cpu.read(SystemRegister::HCR_EL2);
        let guest = self.cpu.pstate.el != 2 && hcr & (1 << HCR_TGE) == 0;
        if guest
            && hcr & (1 << HCR_AMO) != 0
            && hcr & (1 << HCR_VSE) != 0
            && self.cpu.pstate.daif & DAIF_A != 0
        {
            let syndrome = self.cpu.read(SystemRegister::VSESR_EL2) & 0x01ff_ffff;
            self.cpu
                .registers
                .set(SystemRegister::VDISR_EL2, 0, 1 << 31 | syndrome);
            self.cpu
                .registers
                .set(SystemRegister::HCR_EL2, 0, hcr & !(1 << HCR_VSE));
        }
        self.next()
    }

    /// MRS and MSR: the generated accessor of an architectural register, or
    /// Apple's implementation-defined dispatch; any other encoding is
    /// UNDEFINED.
    fn register_instruction(&mut self, word: u32, access: RegisterAccess) -> Step {
        use registers::encodings::{FPCR, FPSR};
        let encoding = access.encoding();
        if matches!(encoding, FPCR | FPSR) && !self.floating_point_enabled() {
            let exception = self.floating_point_exception(self.cpu.pc);
            self.take(exception);
            return Ok(());
        }
        // Apple's vGIC CPU interface answers the ICH_* encodings before the
        // generated accessors, which follow the profile's absent FEAT_GICv3.
        // Under HCR_EL2.NV an EL1 access to an EL2 register traps to EL2.
        let el = self.cpu.pstate.el;
        let vgic = if el == 1 && self.cpu.nested() & 1 != 0 && vgic::owns(encoding) {
            Some(RegisterOutcome::Trapped(Some(2)))
        } else if access.direction() == Direction::Read {
            self.cpu.vgic.read(encoding, el)
        } else {
            let value = match access.rt() {
                31 => 0,
                rt => self.cpu.state.x[usize::from(rt)],
            };
            self.cpu.vgic.write(encoding, el, value)
        };
        if let Some(outcome) = vgic {
            return self.register_outcome(word, Some(access), outcome);
        }
        if let Some(step) = self.system_access(word, access) {
            return step;
        }
        let physical = self.host.counter();
        let outcome = self.cpu.apple_access(access, physical);
        self.derived_changed();
        self.register_outcome(word, Some(access), outcome)
    }

    fn register_outcome(
        &mut self,
        word: u32,
        access: Option<RegisterAccess>,
        outcome: RegisterOutcome,
    ) -> Step {
        match outcome {
            RegisterOutcome::Read(value) => {
                let access = access.expect("reads come from MRS");
                if access.rt() != 31 {
                    self.cpu.state.x[usize::from(access.rt())] = value;
                }
            }
            RegisterOutcome::Written(changes) => {
                // PSTATE.D and Apple registers can change what is derived.
                self.derived_changed();
                if changes.translation {
                    self.translations_changed();
                } else if changes.regime {
                    self.sync_regime();
                }
                if changes.floating_point {
                    // Blocks are keyed by FP enablement; nothing to discard.
                }
            }
            RegisterOutcome::Undefined => return self.undefined(),
            RegisterOutcome::Trapped(el) => {
                let iss = registers::word_trap_iss(word);
                let exception = Exception::synchronous(Class::SystemRegister, iss, self.cpu.pc);
                self.take(match el {
                    Some(el) => exception.to(el),
                    None => exception,
                });
                return Ok(());
            }
            RegisterOutcome::SmeTrapped(el) => {
                let exception = Exception::synchronous(Class::SmeAccess, 0, self.cpu.pc);
                self.take(exception.to(el));
                return Ok(());
            }
            RegisterOutcome::Refused(refusal) => {
                let mut requirement =
                    self.requirement(RequirementKind::SystemRegister { word, refusal });
                requirement.syndrome = Some(super::exception::syndrome(
                    Class::SystemRegister,
                    access.map_or(0, registers::trap_iss),
                ));
                return Err(Stop::Unsupported(requirement));
            }
        }
        self.next()
    }

    /// WFI and WFE (Arm `Hint_WFI`, `Hint_WFE` and `AArch64_CheckForWFxTrap`).
    /// WFE with the event register set clears it and completes, and WFI with
    /// an interrupt pending, masked or not, completes; neither then traps.
    /// WFET and WFIT (FEAT_WFxT) also complete once their local timeout has
    /// expired: the virtual count reaches Xt (Arm `Hint_WFET`, `Hint_WFIT`).
    /// Otherwise SCTLR_ELx.nTWI/nTWE trap them from EL0 to EL1, or to EL2 in
    /// the host, and HCR_EL2.TWI/TWE trap them from EL0 and EL1 outside the
    /// host to EL2, with ISS.TI the form and, for the timeout forms, RV set
    /// and the register in ISS[9:5] (Arm `AArch64_WFxTrap`). On a chip
    /// without FEAT_WFxT the timeout forms are UNDEFINED. An event stream
    /// event wakes WFE and, by this implementation's choice of Arm's
    /// IMPLEMENTATION DEFINED option, clears the event register.
    fn wait(&mut self, _word: u32, kind: WaitKind, register: Option<u8>) -> Step {
        const HCR_TWI: u32 = 13;
        const HCR_TWE: u32 = 14;
        if register.is_some() {
            match self.profile.chip.implemented(Feature::FEAT_WFxT) {
                Ok(true) => {}
                Ok(false) => return self.undefined(),
                Err(reason) => return Err(self.unsupported(RequirementKind::Native(reason))),
            }
        }
        let timeout = register.map(|register| Timeout {
            limit: if register == 31 {
                0
            } else {
                self.cpu.state.x[usize::from(register)]
            },
            offset: if self.cpu.regime() == crate::machine::cpu::TranslationRegime::El20 {
                0
            } else {
                self.cpu.read(SystemRegister::CNTVOFF_EL2)
            },
        });
        let el = self.cpu.pstate.el;
        let sctlr = self.cpu.controls(self.cpu.regime()).sctlr;
        let (enable_bit, hcr_trap, form) = match kind {
            WaitKind::Interrupt => (1u64 << 16, HCR_TWI, 0b00),
            WaitKind::Event => (1u64 << 18, HCR_TWE, 0b01),
        };
        let now = self.host.counter();
        if kind == WaitKind::Event {
            self.sample_events(now);
        }
        match kind {
            WaitKind::Event if self.cpu.event => {
                self.cpu.event = false;
                return self.next();
            }
            WaitKind::Interrupt if self.interrupt_pending() => return self.next(),
            _ => {}
        }
        if timeout.is_some_and(|timeout| timeout.expired(now)) {
            return self.next();
        }
        // ISS.TI: 0b00 WFI, 0b01 WFE, 0b10 WFIT, 0b11 WFET; RV and the
        // register for the timeout forms.
        let iss = TRAPPED_AARCH64
            | form
            | register.map_or(0, |register| 0b10 | 1 << 2 | u32::from(register) << 5);
        if el == 0 && sctlr & enable_bit == 0 {
            self.take(Exception::synchronous(Class::WaitTrap, iss, self.cpu.pc));
            return Ok(());
        }
        if el != 2 && !self.cpu.in_host() && self.cpu.hcr(hcr_trap) {
            self.take(Exception::synchronous(Class::WaitTrap, iss, self.cpu.pc).to(2));
            return Ok(());
        }
        // CYC_OVRD lets WFI power the core down, losing its state until a
        // restart; that lifecycle is not modelled.
        if kind == WaitKind::Interrupt && self.cpu.wfi_mode() == registers::CYC_OVRD_WFI_POWER_DOWN
        {
            return Err(self.unsupported(RequirementKind::Native(
                "WFI with CYC_OVRD's power-down mode (core power-down is not modelled)",
            )));
        }
        // The PE waits until the scheduler finds it woken
        // (`processors::Peer::ready`) and completes the instruction.
        self.waiting = Some(Wait { kind, timeout });
        self.sync_monitor();
        Ok(())
    }

    /// Arm `AArch64_InterruptPending` for the running PE.
    fn interrupt_pending(&mut self) -> bool {
        let lines = self.lines();
        interrupt_pending(&self.cpu, lines)
    }

    /// SYS and SYSL: the generated accessor of an architectural System
    /// instruction. IMPLEMENTATION DEFINED encodings (CRn 11 and 15) stop
    /// with the paused Apple inventory; every other encoding is UNDEFINED.
    fn maintenance(&mut self, word: u32, access: RegisterAccess) -> Step {
        if let Some(step) = self.system_access(word, access) {
            return step;
        }
        if matches!(access.encoding().crn(), 11 | 15) {
            return Err(self.refuse_system(
                word,
                "IMPLEMENTATION DEFINED System instruction (Apple inventory paused)",
            ));
        }
        self.undefined()
    }

    /// Translate a data address for the current EL and regime.
    fn translate_data(&mut self, address: u64, access: Access) -> Translated {
        let controls = self.cpu.controls(self.cpu.regime());
        let requester = self.cpu.requester();
        mmu::translate(
            &controls,
            address,
            access,
            requester,
            &mut RamTables(&mut self.host),
        )
    }

    /// The data abort a stage-1 fault raises at the current EL.
    fn data_abort_exception(
        &mut self,
        address: u64,
        fault: mmu::Fault,
        write: bool,
        cache: bool,
    ) -> Exception {
        self.abort(
            fault,
            [Class::DataAbortLower, Class::DataAbortSame],
            fault.data_syndrome(write, cache),
            address,
            self.cpu.pc,
        )
    }

    /// The abort for a translation fault (Arm `AArch64_Abort` and
    /// `AArch64_ReportException`): a stage-2 fault goes to EL2 whatever the
    /// routing, and records HPFAR_EL2 when its IPA is valid; `classes` are
    /// the lower-EL and same-EL classes, chosen by the target.
    fn abort(
        &mut self,
        fault: mmu::Fault,
        classes: [Class; 2],
        iss: u32,
        address: u64,
        return_address: u64,
    ) -> Exception {
        // A synchronous external abort from EL0 or EL1 goes to EL2 under
        // HCR_EL2.TEA (Arm SyncExternalAbortTarget).
        let external = fault.kind == mmu::FaultKind::ExternalOnWalk;
        let target = if fault.to_el2()
            || external && self.cpu.pstate.el < 2 && self.cpu.hcr(crate::machine::cpu::HCR_TEA)
        {
            2
        } else {
            self.cpu.route()
        };
        let class = if target > self.cpu.pstate.el {
            classes[0]
        } else {
            classes[1]
        };
        if let Some(hpfar) = fault.hpfar() {
            self.cpu
                .registers
                .set_raw(SystemRegister::HPFAR_EL2, 0, hpfar);
        }
        let mut exception = Exception::synchronous(class, iss, return_address).to(target);
        exception.fault_address = Some(address);
        exception
    }

    fn data_abort(&mut self, address: u64, fault: mmu::Fault, write: bool, cache: bool) -> Step {
        let exception = self.data_abort_exception(address, fault, write, cache);
        self.take(exception);
        Ok(())
    }
}

/// Descriptor access through the host's RAM, for the software walker.
struct RamTables<'a, H: Host>(&'a mut H);

impl<H: Host> mmu::TableMemory for RamTables<'_, H> {
    fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
        let mut bytes = [0; 8];
        self.0
            .read_ram(physical, &mut bytes)
            .then(|| u64::from_le_bytes(bytes))
    }

    fn update_descriptor(&mut self, physical: u64, old: u64, new: u64) -> Option<bool> {
        // One PE and no concurrent walker: compare and write in sequence.
        let current = self.read_descriptor(physical)?;
        if current != old {
            return Some(false);
        }
        self.0
            .write_ram(physical, &new.to_le_bytes())
            .then_some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::exception::Pstate;

    pub(super) struct FakeHost {
        pub(super) ram: Vec<u8>,
        base: u64,
        pub(super) now: u64,
        regimes: Vec<Regime>,
        invalidations: usize,
        installed: Vec<Vec<u8>>,
        /// What the next native blocks return, in order: unit tests do not
        /// run native code.
        pub(super) exits: Vec<NativeExit>,
    }

    impl Host for FakeHost {
        fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
            let Some(offset) = physical.checked_sub(self.base) else {
                return false;
            };
            let offset = offset as usize;
            match self.ram.get(offset..offset + buffer.len()) {
                Some(bytes) => {
                    buffer.copy_from_slice(bytes);
                    true
                }
                None => false,
            }
        }
        fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool {
            let Some(offset) = physical.checked_sub(self.base) else {
                return false;
            };
            let offset = offset as usize;
            match self.ram.get_mut(offset..offset + data.len()) {
                Some(bytes) => {
                    bytes.copy_from_slice(data);
                    true
                }
                None => false,
            }
        }
        fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
            self.installed.push(code.to_vec());
            Ok(NativeCode(self.installed.len()))
        }
        fn discard_code(&mut self) {
            self.installed.clear();
        }
        unsafe fn execute(&mut self, _: NativeCode, _: &mut GuestState) -> NativeExit {
            assert!(!self.exits.is_empty(), "unit tests do not run native code");
            self.exits.remove(0)
        }
        fn set_regime(&mut self, regime: &Regime) {
            self.regimes.push(*regime);
        }
        fn invalidate_translations(&mut self) {
            self.invalidations += 1;
        }
        fn counter(&mut self) -> u64 {
            self.now
        }
        fn arm_timer(&mut self, _: Option<u64>) {}
        fn wait_for_interrupt(&mut self) {
            self.now += 1000;
        }
    }

    pub(super) const BASE: u64 = 0x8_0000_0000;

    /// A machine running `words` at BASE on PE 0 at EL1 of the chip the
    /// tests run on ([`crate::machine::test_chip`]).
    pub(super) fn machine(words: &[u32]) -> Machine<FakeHost, NoDevices> {
        board(words, NoDevices, Vec::new())
    }

    /// [`machine`] on `chip`, for a test that fixes its chip.
    pub(super) fn machine_on(
        chip: crate::machine::Chip,
        words: &[u32],
    ) -> Machine<FakeHost, NoDevices> {
        board_on(chip, words, NoDevices, Vec::new())
    }

    /// [`machine`] with `devices` and the PEs of `processors`.
    pub(super) fn board<D: Devices>(
        words: &[u32],
        devices: D,
        processors: Vec<registers::Identity>,
    ) -> Machine<FakeHost, D> {
        board_on(crate::machine::test_chip(), words, devices, processors)
    }

    /// [`board`] on `chip`.
    pub(super) fn board_on<D: Devices>(
        chip: crate::machine::Chip,
        words: &[u32],
        devices: D,
        processors: Vec<registers::Identity>,
    ) -> Machine<FakeHost, D> {
        let mut ram = vec![0u8; 0x10000];
        for (index, word) in words.iter().enumerate() {
            ram[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let host = FakeHost {
            ram,
            base: BASE,
            now: 0,
            regimes: Vec::new(),
            invalidations: 0,
            installed: Vec::new(),
            exits: Vec::new(),
        };
        let profile = CpuProfile {
            name: "test",
            chip,
            counter_frequency: 24_000_000,
            fixed: vec![(registers::encodings::DCZID_EL0, 4)],
            processors,
        };
        Machine::new(
            Cpu::of(chip, BASE, Pstate::reset(1)),
            host,
            devices,
            profile,
            TargetCpu::Baseline,
        )
    }

    #[test]
    fn compiles_blocks_through_the_page_and_reports_unsupported_words() {
        // add x0, x0, #1; svc #0
        let mut machine = machine(&[0x9100_0400, 0xd400_0001]);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("block")
        };
        assert_eq!(machine.blocks[index].source_map.len(), 2);
        assert_eq!(machine.statistics.compiled, 1);
        assert!(matches!(machine.fetch_block(BASE, false), Ok(Fetched::Block(i)) if i == index));
        assert_eq!(machine.statistics.compiled, 1, "cached");
        // An SVE instruction compiles as the UDF it is on a chip without SVE
        // or SME, such as the M2.
        let mut machine = machine_on(crate::machine::Chip::AppleM2, &[0x9100_0400, 0x04a0_0000]);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("block with UDF")
        };
        assert_eq!(machine.blocks[index].source_map.len(), 2);
        // On the M4, whose SME has it in streaming mode, the block ends
        // before it, and the engine applies its access checks on its own.
        let mut machine = machine_on(crate::machine::Chip::AppleM4, &[0x9100_0400, 0x04a0_0000]);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("prefix block")
        };
        assert_eq!(machine.blocks[index].source_map.len(), 1);
        assert!(matches!(
            machine.fetch_block(BASE + 4, false),
            Ok(Fetched::Checked(0x04a0_0000))
        ));
    }

    #[test]
    fn sctlr_sa_selects_blocks_with_or_without_the_sp_alignment_check() {
        const SP_CHECK: [u8; 6] = [0xa8, 15, 0x74, 2, 0x0f, 0x0b];
        // ldr x0, [sp, #8]; svc #0
        let mut machine = machine(&[0xf940_07e0, 0xd400_0001]);
        let has_check = |machine: &Machine<FakeHost, NoDevices>, index: usize| {
            let code = &machine.host.installed[machine.blocks[index].code.0 - 1];
            code.windows(SP_CHECK.len()).any(|bytes| bytes == SP_CHECK)
        };
        let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1) | 1 << 3;
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, sctlr);
        machine.derived_changed();
        let Ok(Fetched::Block(checked)) = machine.fetch_block(BASE, false) else {
            panic!("checked block")
        };
        assert!(machine.blocks[checked].checks.stack_alignment && has_check(&machine, checked));
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, sctlr & !(1 << 3));
        machine.derived_changed();
        let Ok(Fetched::Block(unchecked)) = machine.fetch_block(BASE, false) else {
            panic!("unchecked block")
        };
        assert_ne!(checked, unchecked);
        assert!(
            !machine.blocks[unchecked].checks.stack_alignment && !has_check(&machine, unchecked)
        );
        assert!(stack_based(0xf940_07e0) && !stack_based(0xf940_0020));
        assert!(!stack_based(0x5800_003f), "a literal load has no base");
    }

    #[test]
    fn native_alignment_checks_take_the_alignment_fault_of_the_access() {
        const SCTLR_A: u64 = 1 << 1;
        const SCTLR_NAA: u64 = 1 << 6;
        // ldr x0, [x1]; ldp w2, w3, [x1]; ldadd x4, x5, [x1]; stlr w6, [x1];
        // ld1 {v0.8h}, [x1]
        let words = [
            0xf940_0020,
            0x2940_0c22,
            0xf824_0025,
            0x889f_fc26,
            0x4c40_7420,
        ];
        let mut machine = machine(&words);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        machine
            .cpu
            .registers
            .set(SystemRegister::CPACR_EL1, 0, 0b11 << 20);
        machine
            .cpu
            .registers
            .set(SystemRegister::CPTR_EL2, 0, 0b11 << 20);
        let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1) & !(SCTLR_A | SCTLR_NAA);
        let ud = NativeExit::Fault(NativeFault {
            offset: 0,
            address: 0,
            write: false,
            cause: FaultCause::InvalidOpcode,
        });
        // Run the word at `index` from X1 = `address` under SCTLR_EL1 bits
        // `extra`, its native check failing; ESR_EL1 and FAR_EL1 after it.
        let mut run = |index: u64, address: u64, extra: u64| {
            machine
                .cpu
                .registers
                .set(SystemRegister::SCTLR_EL1, 0, sctlr | extra);
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.derived_changed();
            machine.cpu.pc = BASE + 4 * index;
            machine.cpu.state.x[1] = address;
            machine.host.exits.push(ud);
            let outcome = machine.step();
            (
                outcome.map(|()| {
                    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 4 * index);
                    (
                        machine.cpu.read(SystemRegister::ESR_EL1),
                        machine.cpu.read(SystemRegister::FAR_EL1),
                    )
                }),
                machine.blocks.last().map(|block| block.checks),
            )
        };
        // EC 0x25 with IL and DFSC 0b100001; WnR for a store.
        let load = 0x9600_0021;
        let store = load | 1 << 6;
        // Under SCTLR.A every unaligned access faults at its first element.
        let (outcome, checks) = run(0, BASE + 0x104, SCTLR_A);
        assert_eq!(outcome.unwrap(), (load, BASE + 0x104));
        assert!(checks.unwrap().alignment);
        assert_eq!(
            run(1, BASE + 0x102, SCTLR_A).0.unwrap(),
            (load, BASE + 0x102)
        );
        assert_eq!(
            run(4, BASE + 0x101, SCTLR_A).0.unwrap(),
            (load, BASE + 0x101)
        );
        // An atomic crossing its 16-byte granule faults without SCTLR.A, and
        // its fault is not a write.
        assert_eq!(run(2, BASE + 0x10c, 0).0.unwrap(), (load, BASE + 0x10c));
        // So does an ordered access with nAA clear; a store-release is a write.
        assert_eq!(run(3, BASE + 0x10e, 0).0.unwrap(), (store, BASE + 0x10e));
        // With nAA set the access completes natively; a failed check would
        // have no fault to take, and stops.
        let (outcome, checks) = run(3, BASE + 0x10e, SCTLR_NAA);
        assert!(matches!(outcome, Err(Stop::Unsupported(_))));
        assert!(!checks.unwrap().ordered_granule);
    }

    impl Machine<FakeHost, NoDevices> {
        fn system_instruction_for_test(&mut self, word: u32) {
            self.pointer_authentication(word).unwrap();
        }
    }

    #[test]
    fn svc_eret_and_system_registers_follow_the_architecture() {
        let mut machine = machine(&[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0xffff_0000_0000_0000);
        // msr vbar_el1, x1 then svc #0x42, both at EL1h.
        machine.cpu.state.x[1] = 0x1_0000;
        machine.system_instruction(0xd518_c001).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::VBAR_EL1), 0x1_0000);
        machine.system_instruction(0xd400_0841).unwrap();
        assert_eq!(machine.cpu.pc, 0x1_0200);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 8);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x5600_0042);
        // ERET to EL0t at ELR.
        machine.cpu.registers.set(SystemRegister::SPSR_EL1, 0, 0);
        machine.system_instruction(0xd69f_03e0).unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 8, 0));
        assert_eq!(machine.host.regimes.last().unwrap().requester.el, 0);
        // EL0 cannot read TPIDR_EL1: UNDEFINED to the lower-EL group.
        machine.system_instruction(0xd538_d080).unwrap();
        assert_eq!(machine.cpu.pc, 0x1_0400);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
        // An Apple IMPDEF register is an explicit refusal.
        let Err(Stop::Unsupported(requirement)) = machine.system_instruction(0xd53f_f200) else {
            panic!("refusal")
        };
        assert_eq!(requirement.syndrome, Some(0x6231_fc05));
    }

    #[test]
    fn a_guest_hypervisor_under_nv_traps_eret_sees_el2_and_reaches_vncr_memory() {
        const ERET: u32 = 0xd69f_03e0;
        const SVC: u32 = 0xd400_0001;
        const MRS_X0_HCRX_EL2: u32 = 0xd53c_1240;
        const NV: u64 = 1 << 42;
        const NV2: u64 = 1 << 45;
        let chip = crate::machine::Chip::AppleM3;
        let mut machine = machine_on(chip, &[]);
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
        registers.set(SystemRegister::HCR_EL2, 0, NV | 1 << 43);
        // NV1 is RAZ/WI on the chips with FEAT_NV.
        let nested = NV | 1 << 43 | NV2;
        assert_eq!(machine.cpu.read(SystemRegister::HCR_EL2) & nested, NV);
        // ERET at EL1 traps to EL2: EC 0x1A, ISS 0.
        machine.system_instruction(ERET).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x6a00_0000);
        assert_eq!(machine.cpu.pstate.el, 2);
        // An SVC taken from EL1 to EL1 records EL2h in SPSR_EL1.M.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.system_instruction(SVC).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1) & 0xf, 0b1001);
        // With NV2, MRS HCRX_EL2 at EL1 loads VNCR_EL2 + 0xA0 instead, here
        // through the flat EL2&0 regime.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, NV | NV2);
        machine
            .cpu
            .registers
            .set(SystemRegister::VNCR_EL2, 0, BASE + 0x1000);
        assert!(
            machine
                .host
                .write_ram(BASE + 0x10a0, &0x1234_u64.to_le_bytes())
        );
        machine.system_instruction(MRS_X0_HCRX_EL2).unwrap();
        assert_eq!(machine.cpu.state.x[0], 0x1234);
        // A translation fault on it is an NV2 Data Abort to EL2: EC 0x25 with
        // ISS.VNCR, FAR_EL2 the VNCR address.
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::TCR_EL2, 0, 25);
        registers.set(SystemRegister::TTBR0_EL2, 0, BASE + 0x8000);
        let sctlr = registers.get(SystemRegister::SCTLR_EL2, 0);
        registers.set(SystemRegister::SCTLR_EL2, 0, sctlr | 1);
        machine.derived_changed();
        machine.system_instruction(MRS_X0_HCRX_EL2).unwrap();
        let esr = machine.cpu.read(SystemRegister::ESR_EL2);
        assert_eq!((esr >> 26, esr & 1 << 13 != 0), (0x25, true));
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL2), BASE + 0x10a0);
        assert_eq!(machine.cpu.pstate.el, 2);
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL2, 0, sctlr);
        machine.derived_changed();
        machine.cpu.set_pstate(Pstate::reset(1));
        // Outside RAM the access stops explicitly.
        machine
            .cpu
            .registers
            .set(SystemRegister::VNCR_EL2, 0, 0x4000_0000);
        assert!(matches!(
            machine.system_instruction(MRS_X0_HCRX_EL2),
            Err(Stop::Unsupported(_))
        ));
        // The M2 has no FEAT_NV: the bits are RES0 and ERET returns.
        let mut machine = machine_on(crate::machine::Chip::AppleM2, &[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, NV | NV2);
        assert_eq!(machine.cpu.read(SystemRegister::HCR_EL2) & (NV | NV2), 0);
        machine
            .cpu
            .registers
            .set(SystemRegister::ELR_EL1, 0, BASE + 0x40);
        machine.cpu.registers.set(SystemRegister::SPSR_EL1, 0, 0x5);
        machine.system_instruction(ERET).unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 0x40, 1));
    }

    #[test]
    fn the_m2_performance_monitor_counts_retired_instructions_and_signals_fiq() {
        const MSR_PMCR1_X1: u32 = 0xd519_f101;
        const MSR_PMCR1_COPY_X1: u32 = 0xd519_f741;
        const MSR_PMCR0_X2: u32 = 0xd519_f002;
        const MSR_PMC1_X6: u32 = 0xd51a_f106;
        const MRS_X3_PMC1: u32 = 0xd53a_f103;
        const MRS_X4_HCR_EL2: u32 = 0xd53c_1104;
        const MRS_X5_PMC1: u32 = 0xd53a_f105;
        const MRS_X7_PMCR0: u32 = 0xd539_f007;
        const ADD: u32 = 0x9100_0400;
        const B_NEXT: u32 = 0x1400_0001;
        const SVC: u32 = 0xd400_0001;
        let mut words = vec![
            MSR_PMCR1_X1,
            MSR_PMCR1_COPY_X1,
            MSR_PMCR0_X2,
            ADD,
            ADD,
            B_NEXT,
            MRS_X3_PMC1,
            MRS_X4_HCR_EL2,
        ];
        // The EL1 vectors at BASE + 0x800: current EL, SPx, synchronous.
        words.resize(0xa00 / 4, 0);
        words.extend([MRS_X5_PMC1, SVC]);
        let identity = registers::Identity {
            midr: 0x611f_0330,
            mpidr: 0x8001_0000,
            clock: Some(3_504_000_000),
        };
        let chip = crate::machine::Chip::AppleM2;
        let mut machine = board_on(chip, &words, NoDevices, vec![identity]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, BASE + 0x800);
        // XNU's PMCR1_INIT and PMCR0_INIT: PMC0 and PMC1 with their PMIs.
        machine.cpu.state.x[1] = 0x30300;
        machine.cpu.state.x[2] = 0x3 | 0x3000 | 0x400;
        let run = |machine: &mut Machine<FakeHost, NoDevices>, next_pc, kind: ExitKind| {
            machine.host.exits.push(NativeExit::Exit {
                next_pc,
                kind: kind as u64,
            });
            machine.step().unwrap();
        };
        for pc in [BASE, BASE + 4, BASE + 8] {
            run(&mut machine, pc, ExitKind::System);
        }
        // The two ADDs and the branch, then the MRS, which counts itself.
        run(&mut machine, BASE + 24, ExitKind::Direct);
        run(&mut machine, BASE + 24, ExitKind::System);
        assert_eq!(machine.cpu.state.x[3], 4);
        // An UNDEFINED MRS does not retire; the vector's MRS does.
        run(&mut machine, BASE + 28, ExitKind::System);
        assert_eq!(machine.cpu.pc, BASE + 0xa00);
        run(&mut machine, BASE + 0xa00, ExitKind::System);
        assert_eq!(machine.cpu.state.x[5], 5);
        // SVC retires as it takes its exception.
        run(&mut machine, BASE + 0xa04, ExitKind::System);
        run(&mut machine, BASE + 0xa00, ExitKind::System);
        assert_eq!(machine.cpu.state.x[5], 7);
        // Two instructions short of overflow, the PMI asserts as FIQ once
        // they retire, and PMAI reports it.
        machine.cpu.state.x[6] = (1 << 63) - 2;
        machine.system_instruction(MSR_PMC1_X6).unwrap();
        assert!(!machine.lines().fiq);
        machine.cpu.retired += 2;
        assert!(machine.lines().fiq);
        machine.system_instruction(MRS_X7_PMCR0).unwrap();
        assert_eq!(machine.cpu.state.x[7], 0x3 | 0x3000 | 0x400 | 1 << 11);
    }

    #[test]
    fn tlbi_invalidates_and_wfi_waits_for_the_virtual_timer() {
        let mut machine = machine(&[]);
        machine.system_instruction(0xd508_871f).unwrap(); // tlbi vmalle1
        assert_eq!(machine.host.invalidations, 1);
        // Arm the virtual timer 1500 ticks ahead and wait.
        machine.cpu.state.x[0] = 1500;
        machine.system_instruction(0xd51b_e300).unwrap(); // msr cntv_tval_el0, x0
        machine.cpu.state.x[0] = 1;
        machine.system_instruction(0xd51b_e320).unwrap(); // msr cntv_ctl_el0, x0
        wait(&mut machine, 0xd503_207f).unwrap(); // wfi
        assert_eq!(machine.host.now, 2000);
        // The FIQ is masked by DAIF until it is cleared.
        assert!(!machine.deliver_interrupts());
        machine.cpu.pstate.daif = 0;
        let pc = machine.cpu.pc;
        assert!(machine.deliver_interrupts());
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
        assert_eq!(machine.cpu.pc, 0x300);
        // With no timer armed, WFI is a terminal idle state.
        machine
            .cpu
            .registers
            .set(SystemRegister::CNTV_CTL_EL0, 0, 0);
        machine.derived_changed();
        assert_eq!(wait(&mut machine, 0xd503_207f), Err(Stop::Idle));
    }

    #[test]
    fn wfi_in_cyc_ovrds_power_down_mode_stops() {
        const MSR_CYC_OVRD_X0: u32 = 0xd51d_f500;
        const WFI: u32 = 0xd503_207f;
        let mut machine = machine(&[]);
        // Clock gating only: WFI waits as usual.
        machine.cpu.state.x[0] = 2 << 24;
        machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
        machine.cpu.state.x[1] = 1500;
        machine.system_instruction(0xd51b_e301).unwrap(); // msr cntv_tval_el0, x1
        machine.cpu.state.x[1] = 1;
        machine.system_instruction(0xd51b_e321).unwrap(); // msr cntv_ctl_el0, x1
        wait(&mut machine, WFI).unwrap();
        assert_eq!(machine.host.now, 2000);
        // Power-down mode loses the core's state until a restart.
        machine.cpu.state.x[1] = 0;
        machine.system_instruction(0xd51b_e321).unwrap(); // msr cntv_ctl_el0, x1
        machine.cpu.state.x[0] = 3 << 24 | 1;
        machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
        assert!(matches!(
            machine.system_instruction(WFI),
            Err(Stop::Unsupported(_))
        ));
    }

    #[test]
    fn wfit_and_wfet_wait_until_their_timeout_and_trap_with_the_register() {
        const WFIT_X1: u32 = 0xd503_1021;
        const WFET_X2: u32 = 0xd503_1002;
        const HCR_TWI: u64 = 1 << 13;
        let chip = crate::machine::Chip::AppleM4;
        let mut machine = machine_on(chip, &[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
        // An expired timeout completes at once; WFET also needs no event.
        machine.cpu.state.x[2] = 0;
        machine.system_instruction(WFET_X2).unwrap();
        assert_eq!(machine.cpu.pc, BASE + 4);
        // A later one waits, and the host's next tick (FakeHost adds 1000)
        // passes it: WFIT completes without any timer or interrupt, where a
        // WFI would be idle.
        machine.cpu.state.x[1] = 500;
        wait(&mut machine, WFIT_X1).unwrap();
        assert_eq!((machine.cpu.pc, machine.statistics.waits), (BASE + 8, 1));
        // HCR_EL2.TWI traps it to EL2: ISS.TI 0b10, RV and Rt 1, CV and COND.
        machine.cpu.state.x[1] = u64::MAX;
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, HCR_TWI);
        machine.system_instruction(WFIT_X1).unwrap();
        assert_eq!(
            machine.cpu.read(SystemRegister::ESR_EL2),
            0x0600_0000 | 1 << 24 | 0b1110 << 20 | 1 << 5 | 1 << 2 | 0b10
        );
        // The M2 has no FEAT_WFxT: the timeout forms are UNDEFINED.
        let mut machine = machine_on(crate::machine::Chip::AppleM2, &[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        machine.system_instruction(WFIT_X1).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
    }

    /// Execute WFI or WFE and schedule as `Machine::run` does next.
    fn wait(machine: &mut Machine<FakeHost, NoDevices>, word: u32) -> Step {
        machine.system_instruction(word)?;
        machine.schedule()
    }

    /// Maps VA 0-1 GiB to BASE, EL1-only read/write and executable, with the
    /// stage-1 GP bit when `guarded`.
    fn guarded_machine(guarded: bool) -> Machine<FakeHost, NoDevices> {
        let mut machine = machine(&[]);
        let block = BASE | 1 | 1 << 10 | u64::from(guarded) << 50;
        machine.host.ram[0x4000..0x4008].copy_from_slice(&block.to_le_bytes());
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
        registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
        registers.set(SystemRegister::MAIR_EL1, 0, 0xff);
        registers.set(SystemRegister::SCTLR_EL1, 0, 1);
        registers.set(SystemRegister::VBAR_EL1, 0, 0x2_0000);
        machine.derived_changed();
        machine
    }

    #[test]
    fn branch_target_compatibility_follows_bti_paciasp_brk_and_hlt() {
        const BTI: [u32; 4] = [0xd503_241f, 0xd503_245f, 0xd503_249f, 0xd503_24df];
        const PACIASP: u32 = 0xd503_233f;
        let mut machine = machine(&[]);
        // Rows BTYPE 01, 10, 11; columns BTI, BTI c, BTI j, BTI jc.
        let expected = [
            [false, true, true, true],
            [false, true, false, true],
            [false, false, true, true],
        ];
        for (btype, row) in (1..=3).zip(expected) {
            machine.cpu.pstate.btype = btype;
            for (word, compatible) in BTI.into_iter().zip(row) {
                assert_eq!(
                    machine.branch_target_compatible(word),
                    compatible,
                    "{word:#x} {btype}"
                );
            }
            assert!(machine.branch_target_compatible(PACIASP));
            assert!(machine.branch_target_compatible(0xd420_0000)); // brk #0
            assert!(machine.branch_target_compatible(0xd440_0000)); // hlt #0
            assert!(!machine.branch_target_compatible(0xd503_201f)); // nop
        }
        // SCTLR_EL1.BT1 makes PACIASP incompatible with BTYPE 0b11 at EL1.
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, 1 << 36);
        machine.derived_changed();
        assert!(!machine.branch_target_compatible(PACIASP));
        machine.cpu.pstate.btype = 0b01;
        assert!(machine.branch_target_compatible(PACIASP));
        // At EL0 SCTLR_EL1.BT0 decides instead.
        machine.cpu.pstate.btype = 0b11;
        machine.cpu.pstate.el = 0;
        assert!(machine.branch_target_compatible(PACIASP));
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, 1 << 35);
        machine.derived_changed();
        assert!(!machine.branch_target_compatible(PACIASP));
    }

    #[test]
    fn indirect_branches_set_btype_from_their_page_and_register() {
        let mut guarded = guarded_machine(true);
        assert!(guarded.fetch_guarded(0x1000));
        assert_eq!(guarded.indirect_branch_type(0x1000, 5, false), 0b11);
        assert_eq!(guarded.indirect_branch_type(0x1000, 16, false), 0b01);
        assert_eq!(guarded.indirect_branch_type(0x1000, 17, false), 0b01);
        assert_eq!(guarded.indirect_branch_type(0x1000, 5, true), 0b10);
        let mut unguarded = guarded_machine(false);
        assert!(!unguarded.fetch_guarded(0x1000));
        assert_eq!(unguarded.indirect_branch_type(0x1000, 5, false), 0b01);
    }

    #[test]
    fn native_branch_exits_set_btype_from_the_terminal_branch() {
        const BR_X5: u32 = 0xd61f_00a0;
        const BLR_X5: u32 = 0xd63f_00a0;
        const BL: u32 = 0x9400_0010;
        for (word, kind, btype) in [
            (BR_X5, ExitKind::Indirect, 0b11),
            (BLR_X5, ExitKind::Call, 0b10),
            (BL, ExitKind::Call, 0),
        ] {
            let mut machine = guarded_machine(true);
            machine.host.ram[0x1000..0x1004].copy_from_slice(&word.to_le_bytes());
            let Ok(Fetched::Block(index)) = machine.fetch_block(0x1000, false) else {
                panic!("{word:#x} did not compile");
            };
            machine.cpu.pstate.btype = 0b01;
            machine.exit(index, 0x3000, kind as u64).unwrap();
            assert_eq!(
                (machine.cpu.pc, machine.cpu.pstate.btype),
                (0x3000, btype),
                "{word:#x}"
            );
        }
    }

    #[test]
    fn an_incompatible_guarded_target_takes_the_branch_target_exception() {
        let mut machine = guarded_machine(true);
        machine.host.ram[0x1000..0x1004].copy_from_slice(&0xd503_201fu32.to_le_bytes()); // nop
        machine.cpu.pstate.daif = 0;
        machine.cpu.pstate.btype = 0b11;
        machine.cpu.pc = 0x1000;
        machine.step().unwrap();
        assert_eq!(machine.cpu.pc, 0x2_0200);
        let esr = machine.cpu.read(SystemRegister::ESR_EL1);
        assert_eq!((esr >> 26, esr & 0x1ff_ffff), (0x0d, 0b11));
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), 0x1000);
        assert_eq!((machine.cpu.read(SystemRegister::SPSR_EL1) >> 10) & 3, 0b11);
        assert_eq!(machine.cpu.pstate.btype, 0);
    }

    #[test]
    fn wfe_wakes_on_an_event_stream_edge() {
        const WFE: u32 = 0xd503_205f;
        let mut machine = machine(&[]);
        let start = machine.host.now;
        // CNTHCTL_EL2.EVNTEN with EVNTI 9: rising edges 1024 counts apart.
        machine
            .cpu
            .registers
            .set(SystemRegister::CNTHCTL_EL2, 0, 1 << 2 | 9 << 4);
        wait(&mut machine, WFE).unwrap();
        assert!(machine.host.now > start && !machine.cpu.event);
        // An edge since the last sample sets the event register, so WFE
        // completes without waiting.
        machine.host.now += 1024;
        let now = machine.host.now;
        wait(&mut machine, WFE).unwrap();
        assert_eq!((machine.host.now, machine.cpu.event), (now, false));
        // Without a stream, timer or device, WFE is a terminal idle state.
        machine.cpu.registers.set(SystemRegister::CNTHCTL_EL2, 0, 0);
        assert_eq!(wait(&mut machine, WFE), Err(Stop::Idle));
    }

    #[test]
    fn dc_zva_zeroes_one_profile_block_and_at_reports_par() {
        let mut machine = machine(&[]);
        machine.host.ram[0x100..0x180].fill(0xaa);
        machine.cpu.state.x[2] = BASE + 0x108;
        machine.system_instruction(0xd50b_7422).unwrap(); // dc zva, x2
        assert!(machine.host.ram[0x100..0x140].iter().all(|&b| b == 0));
        assert!(machine.host.ram[0x140..0x180].iter().all(|&b| b == 0xaa));
        machine.system_instruction(0xd508_7802).unwrap(); // at s1e1r, x2
        assert_eq!(
            machine.cpu.read(SystemRegister::PAR_EL1) & 0x0000_ffff_ffff_f000,
            BASE
        );
        assert_eq!(machine.cpu.read(SystemRegister::PAR_EL1) & 1, 0);
    }

    #[test]
    fn epan_makes_pan_cover_el0_execute_only_memory_on_the_chips_with_pan3() {
        const MSR_SCTLR_EL1_X0: u32 = 0xd518_1000;
        const AT_S1E1RP_X2: u32 = 0xd508_7902;
        const EPAN: u64 = 1 << 57;
        for (chip, pan3) in [
            (crate::machine::Chip::AppleM2, false),
            (crate::machine::Chip::AppleM4, true),
        ] {
            let mut machine = machine_on(chip, &[]);
            // A level-1 block maps VA 0-1 GiB at BASE, privileged
            // read/write and EL0 execute-only (AP 0b00, UXN 0).
            let block = BASE | 1 | 1 << 10;
            machine.host.ram[0x4000..0x4008].copy_from_slice(&block.to_le_bytes());
            let registers = &mut machine.cpu.registers;
            registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
            registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
            machine.derived_changed();
            machine.cpu.state.x[0] = 1 | EPAN;
            machine.system_instruction(MSR_SCTLR_EL1_X0).unwrap();
            // EPAN holds only where FEAT_PAN3 is implemented.
            let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
            assert_eq!(sctlr & EPAN != 0, pan3, "{chip:?}");
            machine.cpu.pstate.pan = true;
            machine.cpu.state.x[2] = 0x1000;
            machine.system_instruction(AT_S1E1RP_X2).unwrap();
            let par = machine.cpu.read(SystemRegister::PAR_EL1);
            if pan3 {
                // A level-1 Permission fault.
                assert_eq!(par, 1 << 11 | 0b00_1101 << 1 | 1);
            } else {
                assert_eq!((par & 1, par & 0x0000_ffff_ffff_f000), (0, BASE + 0x1000));
            }
        }
    }

    #[test]
    fn at_s1e1rp_honors_pan_where_s1e1r_ignores_it() {
        let mut machine = machine(&[]);
        // 4 KiB, 39-bit VA from level 1 at BASE + 0x4000, whose first entry
        // maps VA 0-1 GiB at BASE, EL0 read/write (AP 0b01).
        let block = BASE | 1 | 1 << 10 | 1 << 6;
        machine.host.ram[0x4000..0x4008].copy_from_slice(&block.to_le_bytes());
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
        registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
        registers.set(SystemRegister::SCTLR_EL1, 0, 1);
        machine.derived_changed();
        machine.cpu.pstate.pan = true;
        machine.cpu.state.x[2] = 0x1000;
        machine.system_instruction(0xd508_7802).unwrap(); // at s1e1r, x2
        let par = machine.cpu.read(SystemRegister::PAR_EL1);
        assert_eq!((par & 1, par & 0x0000_ffff_ffff_f000), (0, BASE + 0x1000));
        machine.system_instruction(0xd508_7902).unwrap(); // at s1e1rp, x2
        assert_eq!(
            machine.cpu.read(SystemRegister::PAR_EL1),
            1 << 11 | 0b00_1101 << 1 | 1
        );
        machine.cpu.pstate.pan = false;
        machine.system_instruction(0xd508_7902).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::PAR_EL1) & 1, 0);
    }

    #[test]
    fn instruction_and_data_aborts_report_their_origin_el() {
        let mut machine = machine(&[]);
        // 4 KiB, 39-bit VA: VA 0-1 GiB maps BASE (EL0 read/write), and the
        // next GiB is unmapped, a level-1 translation fault.
        let block = BASE | 1 | 1 << 10 | 1 << 6;
        machine.host.ram[0x4000..0x4008].copy_from_slice(&block.to_le_bytes());
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
        registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
        registers.set(SystemRegister::MAIR_EL1, 0, 0xff);
        registers.set(SystemRegister::SCTLR_EL1, 0, 1);
        registers.set(SystemRegister::VBAR_EL1, 0, 0x2_0000);
        machine.derived_changed();
        let unmapped = 0x4000_0000;
        let user = Pstate {
            el: 0,
            sp: false,
            daif: 0,
            ..Pstate::reset(1)
        };
        // Fetches: EC 0x20 from EL0 and 0x21 at EL1, IFSC level-1
        // translation fault, ELR and FAR the fetched address.
        for (pstate, ec, vector) in [(user, 0x20, 0x2_0400), (Pstate::reset(1), 0x21, 0x2_0200)] {
            machine.cpu.set_pstate(pstate);
            machine.cpu.pc = unmapped;
            machine.step().unwrap();
            let esr = machine.cpu.read(SystemRegister::ESR_EL1);
            assert_eq!(
                (machine.cpu.pc, esr >> 26, esr & 0x3f),
                (vector, ec, 0b00_0101)
            );
            assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), unmapped);
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), unmapped);
        }
        // A load from EL0 (LDTR, which the engine performs): EC 0x24 with
        // the faulting address in FAR and the load's address in ELR.
        machine.cpu.set_pstate(user);
        machine.cpu.pc = 0x1000;
        machine.cpu.state.x[2] = unmapped + 8;
        machine.system_instruction(0xf840_0841).unwrap(); // ldtr x1, [x2]
        let esr = machine.cpu.read(SystemRegister::ESR_EL1);
        assert_eq!(
            (machine.cpu.pc, esr >> 26, esr & 0x3f),
            (0x2_0400, 0x24, 0b00_0101)
        );
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), unmapped + 8);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), 0x1000);
        // A level-1 table outside RAM: a synchronous external abort on the
        // walk (DFSC 0b010101), taken at EL1, or at EL2 under HCR_EL2.TEA.
        machine
            .cpu
            .registers
            .set(SystemRegister::TTBR0_EL1, 0, 0x10_0000_0000);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
        machine.derived_changed();
        for (hcr, el, vector, esr) in [
            (0, 1, 0x2_0200, SystemRegister::ESR_EL1),
            (1 << 37, 2, 0x4_0400, SystemRegister::ESR_EL2),
        ] {
            machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, hcr);
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.cpu.state.x[2] = 0x108;
            machine.system_instruction(0xf840_0841).unwrap(); // ldtr x1, [x2]
            let syndrome = machine.cpu.read(esr);
            let ec = if el == 2 { 0x24 } else { 0x25 };
            assert_eq!(
                (
                    machine.cpu.pstate.el,
                    machine.cpu.pc,
                    syndrome >> 26,
                    syndrome & 0x3f
                ),
                (el, vector, ec, 0b01_0101)
            );
        }
    }

    #[test]
    fn stage_two_faults_go_to_el2_with_hpfar_and_at_reports_both_stages() {
        let mut machine = machine(&[]);
        // EL2 host with HCR_EL2.VM: a 40-bit IPA from two concatenated
        // level-1 tables at BASE + 0x4000, whose entry for IPA BASE maps that
        // GiB to itself, Normal Write-Back, read/write.
        let vtcr = 24 | 1 << 6 | 5 << 16 | 1 << 31;
        let tables = BASE + 0x4000;
        let block = BASE | 1 | 1 << 10 | 0b11 << 6 | 0b1111 << 2 | 0b11 << 8;
        let slot = (tables - BASE + (BASE >> 30) * 8) as usize;
        machine.host.ram[slot..slot + 8].copy_from_slice(&block.to_le_bytes());
        machine.cpu.set_pstate(Pstate::reset(2));
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::HCR_EL2, 0, 1 << 34 | 1);
        registers.set(SystemRegister::VTCR_EL2, 0, vtcr);
        registers.set(SystemRegister::VTTBR_EL2, 0, tables);
        registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
        let unmapped = 0x1_0000_0000;
        let hpfar = (unmapped >> 12) << 4;

        // AT S12E1R walks both stages (EL1&0 stage 1 is off); AT S1E1R
        // stops at the IPA; a stage-2 fault reports S=1 in PAR_EL1.
        machine.cpu.state.x[2] = BASE + 0x108;
        // AT S12E1R, S12E1W, S12E0R and S12E0W, x2.
        for word in [0xd50c_7882, 0xd50c_78a2, 0xd50c_78c2, 0xd50c_78e2] {
            machine.cpu.registers.set(SystemRegister::PAR_EL1, 0, 1);
            machine.system_instruction(word).unwrap();
            let par = machine.cpu.read(SystemRegister::PAR_EL1);
            assert_eq!(
                (par & 1, par & 0x0000_ffff_ffff_f000),
                (0, BASE),
                "{word:#x}"
            );
        }
        machine.cpu.state.x[2] = unmapped;
        machine.system_instruction(0xd50c_7882).unwrap();
        let fault = 1 << 11 | 1 << 9 | 0b00_0101 << 1 | 1;
        assert_eq!(machine.cpu.read(SystemRegister::PAR_EL1), fault);
        machine.system_instruction(0xd508_7802).unwrap(); // at s1e1r, x2
        let par = machine.cpu.read(SystemRegister::PAR_EL1);
        assert_eq!((par & 1, par & 0x0000_ffff_ffff_f000), (0, unmapped));

        // At EL1, DC ZVA to an IPA stage 2 does not map is a Data Abort
        // taken to EL2 from the lower EL, with FAR and HPFAR.
        machine.cpu.set_pstate(Pstate::reset(1));
        let pc = machine.cpu.pc;
        machine.system_instruction(0xd50b_7422).unwrap(); // dc zva, x2
        assert_eq!(machine.cpu.pstate.el, 2);
        assert_eq!(machine.cpu.pc, 0x2_0400);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x9200_0045);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL2), pc);
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL2), unmapped);
        assert_eq!(machine.cpu.read(SystemRegister::HPFAR_EL2), hpfar);

        // AT S1E1R at EL1 whose stage-1 table is at an unmapped IPA: the
        // stage-2 fault on the walk is taken to EL2 with S1PTW, CM and WnR.
        machine.cpu.set_pstate(Pstate::reset(1));
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::HPFAR_EL2, 0, 0);
        registers.set(SystemRegister::SCTLR_EL1, 0, 1);
        registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
        registers.set(SystemRegister::TTBR0_EL1, 0, unmapped);
        machine.derived_changed();
        machine.cpu.state.x[2] = 0x1000;
        machine.system_instruction(0xd508_7802).unwrap(); // at s1e1r, x2
        assert_eq!(machine.cpu.pstate.el, 2);
        assert_eq!(
            machine.cpu.read(SystemRegister::ESR_EL2),
            0x9200_0000 | 1 << 8 | 1 << 7 | 1 << 6 | 0b00_0101
        );
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL2), 0x1000);
        assert_eq!(machine.cpu.read(SystemRegister::HPFAR_EL2), hpfar);
    }

    #[test]
    fn debug_state_only_movt_is_undefined() {
        for word in [0xc04c_73e5, 0xc04e_03e0] {
            let mut machine = machine(&[]);
            machine.system_instruction(word).unwrap();
            assert_eq!(
                machine.cpu.read(SystemRegister::ESR_EL1),
                0x0200_0000,
                "{word:#x}"
            );
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
        }
    }

    #[test]
    fn eret_at_gl_enters_gl0_whose_exceptions_return_to_gl() {
        let mut machine = machine(&[]);
        machine.cpu.state.x[0] = 1;
        machine.cpu.state.x[1] = 0x9000;
        machine.cpu.state.x[2] = 0xa000;
        machine.cpu.state.x[3] = 0x3c0;
        machine.cpu.state.x[4] = 0xb000;
        for word in [
            0xd51e_f100, // msr SPRR_CONFIG_EL1, x0
            0xd51e_f140, // msr GXF_CONFIG_EL1, x0
            0xd51e_f821, // msr GXF_ENTER_EL1, x1
            0x0020_1420, // genter
            0xd51e_fa42, // msr VBAR_GL1, x2
            0xd51e_fa63, // msr SPSR_GL1, x3 (EL0t, DAIF masked)
            0xd51e_fac4, // msr ELR_GL1, x4
            0xd69f_03e0, // eret
        ] {
            machine.system_instruction(word).unwrap();
        }
        assert_eq!(
            (machine.cpu.pstate.el, machine.cpu.pstate.guarded),
            (0, true)
        );
        assert_eq!(machine.cpu.pc, 0xb000);
        assert!(machine.host.regimes.last().unwrap().requester.guarded);
        // An SVC at GL0 is taken at VBAR_GL1's lower-EL vector.
        machine.system_instruction(0xd400_0001).unwrap();
        assert_eq!(
            (machine.cpu.pstate.el, machine.cpu.pstate.guarded),
            (1, true)
        );
        assert_eq!(machine.cpu.pc, 0xa400);
        let bank = &machine.cpu.apple.guarded[0];
        assert_eq!((bank.elr, bank.spsr, bank.aspsr), (0xb004, 0x3c0, 1));
        assert_eq!(bank.esr, 0x5600_0000);
        // GEXIT with ASPSR_GL bit 0 set resumes GL0.
        machine.system_instruction(0x0020_1400).unwrap();
        assert_eq!(
            (machine.cpu.pstate.el, machine.cpu.pstate.guarded),
            (0, true)
        );
        assert_eq!(machine.cpu.pc, 0xb004);
        // GL0 has no GEXIT.
        machine.system_instruction(0x0020_1400).unwrap();
        assert_eq!(machine.cpu.pc, 0xa400);
        assert_eq!(machine.cpu.apple.guarded[0].esr, 0x0200_0000);
    }

    #[test]
    fn genter_gexit_and_guarded_exceptions_use_the_gl1_bank() {
        let mut machine = machine(&[]);
        let cpu = &mut machine.cpu;
        cpu.state.x[0] = 1;
        cpu.state.x[1] = 0x9000;
        cpu.state.x[2] = 0xa000;
        cpu.state.sp = 0x7000;
        // GENTER is UNDEFINED until SPRR and GXF are enabled.
        machine.system_instruction(0x0020_1420).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
        machine.cpu.pc = BASE;
        for word in [
            0xd51e_f100, // msr SPRR_CONFIG_EL1, x0
            0xd51e_f140, // msr GXF_CONFIG_EL1, x0
            0xd51e_f821, // msr GXF_ENTER_EL1, x1
        ] {
            machine.system_instruction(word).unwrap();
        }
        // GL1 bank registers are refused outside the guarded level.
        assert!(matches!(
            machine.system_instruction(0xd51e_fa42),
            Err(Stop::Unsupported(_))
        ));
        let genter_pc = machine.cpu.pc;
        machine.system_instruction(0x0020_1420).unwrap();
        assert!(machine.cpu.pstate.guarded);
        assert_eq!(machine.cpu.pc, 0x9000);
        assert_eq!(machine.cpu.apple.guarded[0].elr, genter_pc + 4);
        assert_eq!(machine.cpu.apple.guarded[0].aspsr, 0);
        assert!(machine.host.regimes.last().unwrap().requester.guarded);
        // A fresh GL1 stack; EL1's is banked.
        assert_eq!((machine.cpu.state.sp, machine.cpu.sp(1)), (0, 0x7000));
        machine.cpu.state.sp = 0x8000;
        machine.system_instruction(0xd51e_fa42).unwrap(); // msr VBAR_GL1, x2
        machine.system_instruction(0xd53e_f803).unwrap(); // mrs x3, GXF_STATUS_EL1
        assert_eq!(machine.cpu.state.x[3], 1);
        // An SVC at GL1 is taken at VBAR_GL1 and records a GL return.
        let svc_pc = machine.cpu.pc;
        let el1_elr = machine.cpu.read(SystemRegister::ELR_EL1);
        machine.system_instruction(0xd400_0001).unwrap();
        assert_eq!(machine.cpu.pc, 0xa200);
        assert_eq!(machine.cpu.apple.guarded[0].elr, svc_pc + 4);
        assert_eq!(machine.cpu.apple.guarded[0].esr, 0x5600_0000);
        assert_eq!(machine.cpu.apple.guarded[0].aspsr, 1);
        assert_eq!(
            machine.cpu.read(SystemRegister::ELR_EL1),
            el1_elr,
            "EL1's ELR is untouched"
        );
        // GEXIT returns to GL1, then (with ASPSR clear) to EL1.
        machine.system_instruction(0x0020_1400).unwrap();
        assert!(machine.cpu.pstate.guarded);
        assert_eq!(machine.cpu.pc, svc_pc + 4);
        machine.cpu.apple.guarded[0].aspsr = 0;
        machine.cpu.apple.guarded[0].elr = genter_pc + 4;
        machine.cpu.apple.guarded[0].spsr = 0x3c5;
        machine.system_instruction(0x0020_1400).unwrap();
        assert!(!machine.cpu.pstate.guarded);
        assert_eq!(
            (machine.cpu.pc, machine.cpu.state.sp),
            (genter_pc + 4, 0x7000)
        );
        assert_eq!(machine.cpu.apple.guarded[0].sp, 0x8000);
        // GEXIT outside GL is UNDEFINED; APSTS reports the master key ready.
        machine.system_instruction(0x0020_1400).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
        machine.cpu.pstate = Pstate::reset(1);
        machine.system_instruction(0xd53e_fc85).unwrap(); // mrs x5, APSTS_EL1
        assert_eq!(machine.cpu.state.x[5], 1);
    }

    /// A machine at EL1h with SCTLR_EL1.EnIA and EnIB set, HCR_EL2.API set,
    /// 39-bit TTBR1 addresses without TBI and both instruction keys loaded.
    fn pac_machine() -> Machine<FakeHost, NoDevices> {
        pac_setup(machine(&[]))
    }

    /// [`pac_machine`] on `chip`, running `words` at BASE.
    fn pac_machine_for(chip: crate::machine::Chip, words: &[u32]) -> Machine<FakeHost, NoDevices> {
        pac_setup(machine_on(chip, words))
    }

    fn pac_setup(mut machine: Machine<FakeHost, NoDevices>) -> Machine<FakeHost, NoDevices> {
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::TCR_EL1, 0, 25 << 16 | 25);
        for (register, value) in [
            (SystemRegister::APIAKeyLo_EL1, 0x1111_2222_3333_4444),
            (SystemRegister::APIAKeyHi_EL1, 0x5555_6666_7777_8888),
            (SystemRegister::APIBKeyLo_EL1, 0x0123_4567_89ab_cdef),
            (SystemRegister::APIBKeyHi_EL1, 0xfedc_ba98_7654_3210),
        ] {
            registers.set(register, 0, value);
        }
        let sctlr = registers.get(SystemRegister::SCTLR_EL1, 0) | 1 << 31 | 1 << 30;
        registers.set(SystemRegister::SCTLR_EL1, 0, sctlr);
        registers.set(SystemRegister::HCR_EL2, 0, 1 << HCR_API);
        registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        registers.set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
        machine.derived_changed();
        machine
    }

    const PACM: u32 = 0xd503_24ff;
    /// HCRX_EL2.SCTLR2En and PACMEn, and SCTLR2_EL1.EnPACM.
    fn enable_pacm(machine: &mut Machine<FakeHost, NoDevices>) {
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::HCRX_EL2, 0, 1 << 24 | 1 << 15);
        registers.set(SystemRegister::SCTLR2_EL1, 0, 1 << 7);
    }

    #[test]
    fn pacm_gives_the_next_pac_instruction_a_second_modifier_on_the_m6() {
        const PACIASP: u32 = 0xd503_233f;
        const AUTIASP: u32 = 0xd503_23bf;
        const NOP: u32 = 0xd503_201f;
        let code = [PACM, PACIASP, PACM, AUTIASP, PACM, NOP, PACIASP];
        let mut machine = pac_machine_for(crate::machine::Chip::AppleM6, &code);
        let pointer = 0xffff_ff80_0000_4000_u64;
        let sp = 0xffff_ff80_0001_0000_u64;
        machine.cpu.state.x[30] = pointer;
        machine.cpu.state.sp = sp;
        let pac = |machine: &mut Machine<FakeHost, NoDevices>, at: u64| {
            assert_eq!(machine.cpu.pc, at);
            machine.host.exits.push(NativeExit::Exit {
                next_pc: at,
                kind: ExitKind::PointerAuthentication as u64,
            });
            machine.step().unwrap();
        };
        // HCRX_EL2.PACMEn clear makes PACM leave PSTATE.PACM clear.
        pac(&mut machine, BASE);
        assert!(!machine.cpu.pstate.pacm);
        machine.cpu.pc = BASE;
        enable_pacm(&mut machine);
        pac(&mut machine, BASE);
        assert!(machine.cpu.pstate.pacm);
        // PACIASP signs with SP and its own PC, then PACM lapses.
        pac(&mut machine, BASE + 4);
        let context = machine.pointer_context().unwrap();
        let signed = context
            .sign_two_modifiers(pauth::Key::Ia, pointer, sp, BASE + 4)
            .unwrap();
        assert_eq!(machine.cpu.state.x[30], signed);
        assert!(!machine.cpu.pstate.pacm);
        // AUTIASP takes X16, the signing PACIASP's address, as the second.
        machine.cpu.state.x[16] = BASE + 4;
        pac(&mut machine, BASE + 8);
        pac(&mut machine, BASE + 12);
        assert_eq!(machine.cpu.state.x[30], pointer);
        // Any other instruction lapses PACM: the PACIASP after the NOP signs
        // with SP alone.
        pac(&mut machine, BASE + 16);
        machine.host.exits.push(NativeExit::Exit {
            next_pc: BASE + 24,
            kind: ExitKind::Fallthrough as u64,
        });
        machine.step().unwrap();
        assert!(!machine.cpu.pstate.pacm);
        pac(&mut machine, BASE + 24);
        assert_eq!(
            machine.cpu.state.x[30],
            context.sign(pauth::Key::Ia, pointer, sp).unwrap()
        );
    }

    #[test]
    fn exceptions_save_pacm_in_spsr_and_returns_restore_it_where_enabled() {
        const PACIASP: u32 = 0xd503_233f;
        const ERET: u32 = 0xd69f_03e0;
        const SPSR_PACM: u64 = 1 << 35;
        let mut machine = pac_machine_for(crate::machine::Chip::AppleM6, &[]);
        enable_pacm(&mut machine);
        machine.system_instruction_for_test(PACM);
        assert!(machine.cpu.pstate.pacm);
        // HCR_EL2.API clear traps the PACIASP to EL2, which saves PACM and
        // clears it.
        machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, 0);
        let pc = machine.cpu.pc;
        machine.system_instruction_for_test(PACIASP);
        assert_eq!(machine.cpu.pstate.el, 2);
        assert_ne!(machine.cpu.read(SystemRegister::SPSR_EL2) & SPSR_PACM, 0);
        assert!(!machine.cpu.pstate.pacm);
        // The return restores it for the re-executed PACIASP.
        machine.system_instruction(ERET).unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (pc, 1));
        assert!(machine.cpu.pstate.pacm);
        // Where IsPACMEnabled is false at the EL returned to it reads 0.
        machine.cpu.set_pstate(Pstate::reset(2));
        machine.cpu.registers.set(SystemRegister::SCTLR2_EL1, 0, 0);
        machine.system_instruction(ERET).unwrap();
        assert!(!machine.cpu.pstate.pacm);
    }

    #[test]
    fn pauth_lr_forms_use_two_modifiers_and_fault_when_they_fail() {
        const PACIASPPC: u32 = 0xdac1_a3fe;
        const PACIA171615: u32 = 0xdac1_8bfe;
        const AUTIA171615: u32 = 0xdac1_bbfe;
        // AUTIASPPC and RETAASPPC with imm16 n: the label is PC - 4n.
        let autiasppc = |n: u32| 0xf380_001f | n << 5;
        let retaasppc = |n: u32| 0x5500_001f | n << 5;
        let pointer = 0xffff_ff80_0000_4000_u64;
        let sp = 0xffff_ff80_0001_0000_u64;
        let mut machine = pac_machine_for(crate::machine::Chip::AppleM6, &[]);
        let context = machine.pointer_context().unwrap();
        let at = |machine: &mut Machine<FakeHost, NoDevices>, pc: u64, word: u32| {
            machine.cpu.pc = pc;
            machine.system_instruction_for_test(word);
        };
        machine.cpu.state.sp = sp;
        machine.cpu.state.x[30] = pointer;
        at(&mut machine, BASE, PACIASPPC);
        let signed = context
            .sign_two_modifiers(pauth::Key::Ia, pointer, sp, BASE)
            .unwrap();
        assert_eq!(
            (machine.cpu.state.x[30], machine.cpu.pc),
            (signed, BASE + 4)
        );
        // AUTIASPPC names the PACIASPPC 8 bytes back.
        at(&mut machine, BASE + 8, autiasppc(2));
        assert_eq!(machine.cpu.state.x[30], pointer);
        // RETAASPPC authenticates and returns.
        machine.cpu.state.x[30] = signed;
        at(&mut machine, BASE + 12, retaasppc(3));
        assert_eq!(machine.cpu.pc, pointer);
        // A wrong label fails: EC 0x1C, ISS {instruction key A}. The
        // modifier takes the label's bits 36:5, so this one is 0x40 away.
        machine.cpu.state.x[30] = signed;
        at(&mut machine, BASE + 0x48, autiasppc(2));
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0000);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 0x48);
        // The *171615 forms sign X17 with X16 and X15.
        machine.cpu.set_pstate(Pstate::reset(1));
        let state = &mut machine.cpu.state;
        (state.x[17], state.x[16], state.x[15]) = (pointer, 0x1234, 0x5678);
        at(&mut machine, BASE, PACIA171615);
        assert_eq!(
            machine.cpu.state.x[17],
            context
                .sign_two_modifiers(pauth::Key::Ia, pointer, 0x1234, 0x5678)
                .unwrap()
        );
        at(&mut machine, BASE + 4, AUTIA171615);
        assert_eq!(machine.cpu.state.x[17], pointer);
        // PACIASPPC is a landing pad as PACIASP is; PACNBIASPPC is not.
        machine.cpu.pstate.btype = 0b01;
        assert!(machine.branch_target_compatible(PACIASPPC));
        assert!(!machine.branch_target_compatible(0xdac1_83fe));
        // Without FEAT_PAuth_LR (the M5) they are UNDEFINED.
        let mut machine = pac_machine_for(crate::machine::Chip::AppleM5, &[]);
        at(&mut machine, BASE, PACIASPPC);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
    }

    #[test]
    fn pac_uses_the_guest_keys_regime_layout_and_sctlr_enables() {
        const PACIBSP: u32 = 0xd503_237f;
        const AUTIBSP: u32 = 0xd503_23ff;
        let mut machine = pac_machine();
        let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, sctlr & !(1 << 30));
        let pointer = 0xffff_ff80_0000_4000_u64;
        machine.cpu.state.x[30] = pointer;
        machine.cpu.state.sp = 0xffff_ff80_0001_0000;
        // EnIB clear: PACIBSP leaves LR unchanged.
        machine.system_instruction_for_test(PACIBSP);
        assert_eq!(machine.cpu.state.x[30], pointer);
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, sctlr);
        machine.system_instruction_for_test(PACIBSP);
        let signed = machine.cpu.state.x[30];
        assert_ne!(signed, pointer);
        assert_eq!(
            signed & 0x0000_007f_ffff_ffff,
            pointer & 0x0000_007f_ffff_ffff
        );
        machine.system_instruction_for_test(AUTIBSP);
        assert_eq!(machine.cpu.state.x[30], pointer);
        // PACIA, PACIB, PACDA and PACDB x1, x2 follow EnIA, EnIB, EnDA and
        // EnDB.
        // At EL2 the EL2&0 regime's SCTLR_EL2 and TCR_EL2 govern instead.
        machine
            .cpu
            .registers
            .set(SystemRegister::TCR_EL2, 0, 25 << 16 | 25);
        let sctlr2 = machine.cpu.read(SystemRegister::SCTLR_EL2);
        for (el, register, base) in [
            (1, SystemRegister::SCTLR_EL1, sctlr),
            (2, SystemRegister::SCTLR_EL2, sctlr2),
        ] {
            machine.cpu.set_pstate(Pstate::reset(el));
            for (word, enable) in [
                (0xdac1_0041, 31),
                (0xdac1_0441, 30),
                (0xdac1_0841, 27),
                (0xdac1_0c41, 13),
            ] {
                for enabled in [false, true] {
                    let bit = u64::from(enabled) << enable;
                    machine
                        .cpu
                        .registers
                        .set(register, 0, base & !(1 << enable) | bit);
                    machine.cpu.state.x[1] = pointer;
                    machine.cpu.state.x[2] = 0x55;
                    machine.system_instruction_for_test(word);
                    assert_eq!(
                        machine.cpu.state.x[1] != pointer,
                        enabled,
                        "EL{el} {word:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn pac_follows_the_chips_version() {
        const PACIBSP: u32 = 0xd503_237f;
        const AUTIBSP: u32 = 0xd503_23ff;
        let pointer = 0xffff_ff80_0000_4000_u64;
        let run = |chip| {
            let mut machine = pac_machine_for(chip, &[]);
            machine.cpu.state.x[30] = pointer;
            machine.cpu.state.sp = 0xffff_ff80_0001_0000;
            machine.system_instruction_for_test(PACIBSP);
            let signed = machine.cpu.state.x[30];
            // A different modifier fails the AUT.
            machine.cpu.state.sp += 16;
            let pc = machine.cpu.pc;
            machine.system_instruction_for_test(AUTIBSP);
            (signed, machine.cpu.state.x[30], machine.cpu.pc != pc + 4)
        };
        // The M1 (no PAuth2 or FPAC) replaces the extension bits with the PAC
        // and a failed AUT writes the key B error code without an exception,
        // at bits 62:61 without TBI (Arm `Auth`); the M2 XORs the PAC in and
        // faults.
        let (classic, failed, taken) = run(crate::machine::Chip::AppleM1);
        assert_eq!(
            classic & 0x0000_007f_ffff_ffff,
            pointer & 0x0000_007f_ffff_ffff
        );
        assert!(!taken);
        assert_eq!(failed, pointer & !(0b11 << 61) | 0b10 << 61);
        let (enhanced, _, taken) = run(crate::machine::Chip::AppleM2);
        assert_ne!(enhanced, classic);
        assert!(taken);
    }

    #[test]
    fn cpa_arithmetic_completes_unchecked_on_the_chips_with_feat_cpa() {
        // addpt x0, x1, x2, lsl #3; subpt sp, sp, x2; maddpt x3, x1, x2, x4;
        // msubpt x5, x1, x2, x4.
        const ADDPT: u32 = 0x9a02_2c20;
        const SUBPT_SP: u32 = 0xda02_23ff;
        const MADDPT: u32 = 0x9b62_1023;
        const MSUBPT: u32 = 0x9b62_9025;
        for (chip, cpa) in [
            (crate::machine::Chip::AppleM5, false),
            (crate::machine::Chip::AppleM6, true),
        ] {
            let mut machine = machine_on(chip, &[]);
            machine
                .cpu
                .registers
                .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
            let top = 0xff00_0000_0000_0000_u64;
            machine.cpu.state.x[1] = top | 0x1000;
            machine.cpu.state.x[2] = 0x20;
            machine.cpu.state.x[4] = top | 0x8000;
            machine.cpu.state.sp = 0x9000;
            machine.system_instruction(ADDPT).unwrap();
            if !cpa {
                assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
                continue;
            }
            for word in [SUBPT_SP, MADDPT, MSUBPT] {
                machine.system_instruction(word).unwrap();
            }
            assert_eq!(machine.cpu.pc, BASE + 16);
            // Without FEAT_CPA2 nothing marks a result whose top byte changes.
            assert_eq!(machine.cpu.state.x[0], top | 0x1100);
            assert_eq!(machine.cpu.state.sp, 0x8fe0);
            let product = (top | 0x1000).wrapping_mul(0x20);
            assert_eq!(machine.cpu.state.x[3], (top | 0x8000).wrapping_add(product));
            assert_eq!(machine.cpu.state.x[5], (top | 0x8000).wrapping_sub(product));
        }
    }

    #[test]
    fn combined_pac_instructions_fault_only_with_fpaccombine() {
        const PACIBSP: u32 = 0xd503_237f;
        const RETAB: u32 = 0xd65f_0fff;
        // ldraa x0, [x1]
        const LDRAA_X0_X1: u32 = 0xf820_0420;
        let pointer = 0xffff_ff80_0000_4000_u64;
        for (chip, faults) in [
            (crate::machine::Chip::AppleM2, false),
            (crate::machine::Chip::AppleM6, true),
        ] {
            let mut machine = pac_machine_for(chip, &[]);
            machine.cpu.state.x[30] = pointer;
            machine.cpu.state.sp = 0xffff_ff80_0001_0000;
            machine.system_instruction_for_test(PACIBSP);
            // A different modifier fails the RETAB's authentication.
            machine.cpu.state.sp += 16;
            let pc = machine.cpu.pc;
            machine.system_instruction_for_test(RETAB);
            if faults {
                // EC 0x1C, ISS {data=0, key B=1}, at the RETAB.
                assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0001);
                assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
                assert_eq!(machine.cpu.pc, 0x1_0200);
            } else {
                // FEAT_FPAC alone faults only standalone AUTs: RETAB branches
                // to the pointer with its error code.
                assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0);
                assert_ne!(machine.cpu.pc, pointer);
                assert_eq!(
                    machine.cpu.pc & 0x0000_007f_ffff_ffff,
                    pointer & 0x0000_007f_ffff_ffff
                );
            }
        }
        // LDRAA of an unsigned base faults with the data key A (ISS 0b10).
        let mut machine = pac_machine_for(crate::machine::Chip::AppleM6, &[]);
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::APDAKeyLo_EL1, 0, 0x2468_ace0_1357_9bdf);
        registers.set(SystemRegister::APDAKeyHi_EL1, 0, 0x0f1e_2d3c_4b5a_6978);
        let sctlr = registers.get(SystemRegister::SCTLR_EL1, 0) | 1 << 27;
        registers.set(SystemRegister::SCTLR_EL1, 0, sctlr);
        machine.cpu.state.x[1] = 0xffff_ff80_0000_8000;
        let pc = machine.cpu.pc;
        machine.system_instruction_for_test(LDRAA_X0_X1);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0002);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
    }

    #[test]
    fn pac_use_traps_on_hcr_el2_api_and_failed_aut_takes_ec_0x1c() {
        const PACIBSP: u32 = 0xd503_237f;
        const AUTIBSP: u32 = 0xd503_23ff;
        const XPACLRI: u32 = 0xd503_20ff;
        let mut machine = pac_machine();
        machine.cpu.state.x[30] = 0xffff_ff80_0000_4000;
        machine.cpu.state.sp = 0xffff_ff80_0001_0000;
        machine.system_instruction_for_test(PACIBSP);
        let signed = machine.cpu.state.x[30];
        // A different modifier fails a standalone AUT: under FEAT_FPAC EC
        // 0x1C, ISS {data=0, key B=1}, at the instruction, to the current EL.
        // Without it (the M1) the AUT writes the key B error code at bits
        // 62:61 and completes (Arm `Auth`).
        machine.cpu.state.sp += 16;
        let pc = machine.cpu.pc;
        machine.system_instruction_for_test(AUTIBSP);
        if Feature::FEAT_FPAC.on(machine.profile.chip) {
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0001);
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
            assert_eq!(
                (machine.cpu.pc, machine.cpu.state.x[30]),
                (0x1_0200, signed)
            );
        } else {
            let pointer = 0xffff_ff80_0000_4000_u64;
            assert_eq!(
                (machine.cpu.pc, machine.cpu.state.x[30]),
                (pc + 4, pointer & !(0b11 << 61) | 0b10 << 61)
            );
        }
        // HCR_EL2.API clear traps an enabled key's use from EL1 to EL2
        // (EC 0x09, ISS 0); XPAC uses no key and never traps.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, 0);
        machine.system_instruction_for_test(XPACLRI);
        assert_eq!(machine.cpu.state.x[30], 0xffff_ff80_0000_4000);
        machine.system_instruction_for_test(PACIBSP);
        assert_eq!(machine.cpu.pstate.el, 2);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x2600_0000);
        assert_eq!(machine.cpu.pc, 0x4_0400);
        // A disabled key is not used, so it does not trap.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.registers.set(SystemRegister::SCTLR_EL1, 0, 0);
        machine.system_instruction_for_test(PACIBSP);
        assert_eq!(machine.cpu.pstate.el, 1);
    }

    #[test]
    fn eret_traps_and_eretaa_authenticates_elr_with_sp() {
        const ERETAA: u32 = 0xd69f_0bff;
        const ERETAB: u32 = 0xd69f_0fff;
        let mut machine = pac_machine();
        let target = 0xffff_ff80_0000_8000_u64;
        machine.cpu.state.sp = 0xffff_ff80_0002_0000;
        let signed = machine
            .pointer_context()
            .unwrap()
            .sign(pauth::Key::Ia, target, machine.cpu.state.sp)
            .unwrap();
        machine
            .cpu
            .registers
            .set(SystemRegister::ELR_EL1, 0, signed);
        machine
            .cpu
            .registers
            .set(SystemRegister::SPSR_EL1, 0, 0x3c5);
        // HFGITR_EL2.ERET traps ERETAA from EL1: EC 0x1A, ISS {PAC, key B}.
        machine
            .cpu
            .registers
            .set(SystemRegister::HFGITR_EL2, 0, 1 << HFGITR_ERET);
        machine.system_instruction(ERETAB).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x6a00_0003);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL2), BASE);
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.cpu.registers.set(SystemRegister::HFGITR_EL2, 0, 0);
        machine.system_instruction(ERETAA).unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (target, 1));
        // With another SP the combined check corrupts the target instead of
        // faulting without FEAT_FPACCOMBINE; the M6's fault is below.
        machine.cpu.state.sp += 16;
        if !Feature::FEAT_FPACCOMBINE.on(machine.profile.chip) {
            machine.system_instruction(ERETAA).unwrap();
            assert_ne!(machine.cpu.pc, target);
            assert_eq!(machine.cpu.pc & 0x7f_ffff_ffff, target & 0x7f_ffff_ffff);
        }
        // HCR_EL2.API clear traps the enabled key's use to EL2.
        machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, 0);
        machine.system_instruction(ERETAA).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x2600_0000);
        // With FEAT_FPACCOMBINE (M6) the failed combined check takes EC 0x1C,
        // ISS {data=0, key A=0}, at the ERETAA and the return is not made.
        let mut machine = pac_machine_for(crate::machine::Chip::AppleM6, &[]);
        machine.cpu.state.sp = 0xffff_ff80_0002_0010;
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::ELR_EL1, 0, signed);
        registers.set(SystemRegister::SPSR_EL1, 0, 0x3c4);
        machine.system_instruction(ERETAA).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0000);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (0x1_0200, 1));
    }

    #[test]
    fn illegal_returns_set_il_and_the_next_instruction_takes_ec_0x0e() {
        let mut machine = machine(&[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        machine
            .cpu
            .registers
            .set(SystemRegister::ELR_EL1, 0, BASE + 0x10);
        // ERET from EL1h to EL2h is illegal: EL1h stays, PC is ELR, DAIF and
        // NZCV come from SPSR and IL is set.
        machine
            .cpu
            .registers
            .set(SystemRegister::SPSR_EL1, 0, 0x4000_0000 | 0x9);
        machine.system_instruction(0xd69f_03e0).unwrap();
        let pstate = machine.cpu.pstate;
        assert_eq!((pstate.el, pstate.sp, pstate.il), (1, true, true));
        assert_eq!((pstate.daif, machine.cpu.state.nzcv), (0, 0x4000_0000));
        assert_eq!(machine.cpu.pc, BASE + 0x10);
        machine.step().unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x3a00_0000);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 0x10);
        assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1), 0x4010_0005);
        assert_eq!(machine.cpu.pc, 0x1_0200);
        assert!(!machine.cpu.pstate.il);
        // A legal return restores SPSR.IL. ELR keeps its tag only without TBI.
        machine
            .cpu
            .registers
            .set(SystemRegister::TCR_EL1, 0, 1 << 37);
        machine
            .cpu
            .registers
            .set(SystemRegister::ELR_EL1, 0, 0xab00_0000_0000_1000);
        machine
            .cpu
            .registers
            .set(SystemRegister::SPSR_EL1, 0, 1 << 20 | 0x5);
        machine.system_instruction(0xd69f_03e0).unwrap();
        assert!(machine.cpu.pstate.il);
        assert_eq!(machine.cpu.pc, 0x1000);
        // A PC with bits 1:0 set takes a PC alignment fault with FAR = PC,
        // before the Illegal Execution state.
        machine.cpu.pc = BASE + 2;
        machine.step().unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x8a00_0000);
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), BASE + 2);
        // EL0 ERET is UNDEFINED.
        machine.cpu.pstate = Pstate {
            el: 0,
            sp: false,
            ..Pstate::reset(1)
        };
        machine.system_instruction(0xd69f_03e0).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
    }

    #[test]
    fn svc_traps_esb_fp_and_debug_only_instructions_follow_the_profile() {
        let mut machine = machine(&[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
        machine
            .cpu
            .registers
            .set(SystemRegister::HFGITR_EL2, 0, 1 << HFGITR_SVC_EL1);
        // HFGITR_EL2.SVC_EL1 sends SVC to EL2 with the SVC's own address.
        machine.system_instruction(0xd400_0841).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x5600_0042);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL2), BASE);
        // ESB defers a masked virtual SError into VDISR_EL2.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, 1 << HCR_AMO | 1 << HCR_VSE);
        machine
            .cpu
            .registers
            .set(SystemRegister::VSESR_EL2, 0, 0x0100_1234);
        machine.system_instruction(0xd503_221f).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::VDISR_EL2), 0x8100_1234);
        assert_eq!(machine.cpu.read(SystemRegister::HCR_EL2) & 1 << HCR_VSE, 0);
        // An unmasked one is taken with EC 0x2F and IL set.
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, 1 << HCR_AMO | 1 << HCR_VSE);
        machine.cpu.pstate.daif = 0;
        assert!(machine.deliver_interrupts());
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xbf00_1234);
        // CPACR_EL1.FPEN at reset traps FP/SIMD from EL1: EC 0x07 with CV
        // and COND.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.system_instruction(0xd53b_4401).unwrap(); // mrs x1, fpcr
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x1fe0_0000);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
        // BRK is taken at itself with its immediate; HLT (no halting),
        // DCPS1/2/3 and DRPS (no Debug state) and UDF are UNDEFINED.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.system_instruction(0xd420_00a0).unwrap(); // brk #5
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xf200_0005);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
        for word in [
            0xd440_0000,
            0xd4a0_0001,
            0xd4a0_0002,
            0xd4a0_0003,
            0xd6bf_03e0,
            0,
        ] {
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.system_instruction(word).unwrap();
            assert_eq!(
                machine.cpu.read(SystemRegister::ESR_EL1),
                0x0200_0000,
                "{word:#x}"
            );
        }
        // FPCR's trap enables and fields outside the profile are RAZ/WI.
        machine.cpu.set_pstate(Pstate::reset(1));
        for register in [SystemRegister::CPACR_EL1, SystemRegister::CPTR_EL2] {
            machine.cpu.registers.set(register, 0, 0b11 << 20);
        }
        machine.derived_changed();
        machine.cpu.state.x[0] = u64::MAX;
        machine.system_instruction(0xd51b_4400).unwrap(); // msr fpcr, x0
        machine.system_instruction(0xd53b_4401).unwrap(); // mrs x1, fpcr
        // FEAT_AFP (from the M4) adds FIZ, AH and NEP.
        let afp = if Feature::FEAT_AFP.on(machine.profile.chip) {
            0b111
        } else {
            0
        };
        assert_eq!(machine.cpu.state.x[1], 0x07c8_0000 | afp);
    }

    #[test]
    fn sve_sme_and_streaming_checks_trap_before_the_instruction_runs() {
        const ADD_V: u32 = 0x4ea2_8420; // add v0.4s, v1.4s, v2.4s
        const ADD_Z: u32 = 0x0422_0020; // add z0.b, z1.b, z2.b
        const LDR_ZA: u32 = 0xe100_0000; // ldr za[w12, 0], [x0]
        const FADD_S: u32 = 0x1e22_2820; // fadd s0, s1, s2
        const SME_TRAP: u64 = 0x1d << 26 | 1 << 25;
        let mut machine = machine(&[ADD_V, ADD_Z, LDR_ZA, FADD_S]);
        let chip = machine.profile.chip;
        if machine.cpu.scalable.is_none() {
            // Without SME the SVE and SME forms are UNDEFINED and check
            // nothing.
            for word in [ADD_Z, LDR_ZA] {
                assert_eq!(chip.checks(chip.admit(word)), &[]);
            }
            return;
        }
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        for register in [SystemRegister::CPACR_EL1, SystemRegister::CPTR_EL2] {
            machine
                .cpu
                .registers
                .set(register, 0, 0b11 << 24 | 0b11 << 20);
        }
        machine.derived_changed();
        let run = |machine: &mut Machine<FakeHost, NoDevices>, index: u64| {
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.cpu.pc = BASE + 4 * index;
            let step = machine.step();
            (step, machine.cpu.read(SystemRegister::ESR_EL1))
        };
        let trapped = |index: u64, smtc: u64| (Ok(()), SME_TRAP | smtc, BASE + 4 * index);
        let taken = |machine: &mut Machine<FakeHost, NoDevices>, index| {
            let (step, esr) = run(machine, index);
            (step, esr, machine.cpu.read(SystemRegister::ELR_EL1))
        };
        // Outside streaming mode SVE traps as not streaming and a ZA load
        // as ZA inactive, at the instruction.
        assert_eq!(taken(&mut machine, 1), trapped(1, 2));
        assert_eq!(taken(&mut machine, 2), trapped(2, 3));
        // In streaming mode AdvSIMD traps as streaming; SVE, the ZA load and
        // scalar FP pass their checks and stop explicitly.
        machine.cpu.set_svcr(true, true).unwrap();
        assert_eq!(taken(&mut machine, 0), trapped(0, 1));
        for index in 1..4 {
            assert!(
                matches!(run(&mut machine, index).0, Err(Stop::Unsupported(_))),
                "{index}"
            );
        }
        // CPACR_EL1.SMEN clear traps SVE with SMTC 0 before anything else.
        machine
            .cpu
            .registers
            .set(SystemRegister::CPACR_EL1, 0, 0b11 << 20);
        machine.derived_changed();
        assert_eq!(taken(&mut machine, 1), trapped(1, 0));
    }

    #[test]
    fn fpcr_alternate_controls_hold_on_the_chips_with_afp() {
        const MSR_FPCR_X0: u32 = 0xd51b_4400;
        const MRS_X1_FPCR: u32 = 0xd53b_4401;
        for (chip, afp) in [
            (crate::machine::Chip::AppleM2, false),
            (crate::machine::Chip::AppleM4, true),
        ] {
            let mut machine = machine_on(chip, &[]);
            for register in [SystemRegister::CPACR_EL1, SystemRegister::CPTR_EL2] {
                machine.cpu.registers.set(register, 0, 0b11 << 20);
            }
            machine.derived_changed();
            // FIZ, AH and NEP hold only where FEAT_AFP is implemented; the
            // compiled FP operations take their effects from the stored FPCR.
            machine.cpu.state.x[0] = u64::MAX;
            machine.system_instruction(MSR_FPCR_X0).unwrap();
            machine.system_instruction(MRS_X1_FPCR).unwrap();
            let held = if afp { 0x07c8_0007 } else { 0x07c8_0000 };
            assert_eq!(machine.cpu.state.x[1], held, "{chip:?}");
            assert_eq!(machine.cpu.state.fpcr, held as u32, "{chip:?}");
        }
    }

    #[test]
    fn msr_immediate_waits_and_absent_features_follow_the_profile() {
        let mut machine = machine(&[]);
        let user = Pstate {
            el: 0,
            sp: false,
            daif: 0,
            ..Pstate::reset(1)
        };
        // MSR DAIFSet, #3 at EL0 with SCTLR_EL1.UMA clear traps with the
        // instruction's own Op0/Op2/Op1/CRn/Rt/CRm (Op0 0, Rt 31).
        machine.cpu.set_pstate(user);
        machine.system_instruction(0xd503_43df).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x620c_d3e6);
        // PAN is EL1-only and op1=3 op2=5 is unallocated: UNDEFINED.
        for (pstate, word) in [(user, 0xd500_419f), (Pstate::reset(1), 0xd503_42bf)] {
            machine.cpu.set_pstate(pstate);
            machine.system_instruction(word).unwrap();
            assert_eq!(
                machine.cpu.read(SystemRegister::ESR_EL1),
                0x0200_0000,
                "{word:#x}"
            );
        }
        // With UMA set, EL0 may mask interrupts.
        machine.cpu.set_pstate(Pstate::reset(1));
        let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, sctlr | 1 << 9);
        machine.cpu.set_pstate(user);
        machine.cpu.pc = BASE;
        machine.system_instruction(0xd503_43df).unwrap();
        assert_eq!((machine.cpu.pstate.daif, machine.cpu.pc), (3, BASE + 4));
        // WFE with the event register set completes before the nTWE trap,
        // then traps; WFI with an interrupt pending completes before nTWI.
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, sctlr & !(1 << 16 | 1 << 18));
        machine.cpu.set_pstate(user);
        machine.cpu.pc = BASE;
        machine.cpu.event = true;
        machine.system_instruction(0xd503_205f).unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.event), (BASE + 4, false));
        machine.system_instruction(0xd503_205f).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x07e0_0001);
        machine.cpu.set_pstate(user);
        machine.cpu.pc = BASE;
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, 1 << HCR_IMO | 1 << HCR_VI);
        machine.system_instruction(0xd503_207f).unwrap();
        assert_eq!(machine.cpu.pc, BASE + 4);
        // SEV and SEVL set the event register.
        machine.cpu.set_pstate(Pstate::reset(1));
        for word in [0xd503_209f, 0xd503_20bf] {
            machine.cpu.event = false;
            machine.system_instruction(word).unwrap();
            assert!(machine.cpu.event, "{word:#x}");
        }
        // DSB nXS is UNDEFINED without FEAT_XS (before the M4); PACM
        // completes, a NOP without FEAT_PAuth_LR.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.system_instruction(0xd503_323f).unwrap();
        if Feature::FEAT_XS.on(machine.profile.chip) {
            assert_eq!(machine.cpu.pc, BASE + 4);
        } else {
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
        }
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.system_instruction_for_test(0xd503_24ff);
        assert_eq!(machine.cpu.pc, BASE + 4);
    }

    #[test]
    fn dsb_nxs_tlbi_nxs_and_the_xs_attribute_follow_feat_xs() {
        const DSB_ISHNXS: u32 = 0xd503_3a3f;
        const AT_S1E1R_X2: u32 = 0xd508_7802;
        // SYS (op0 1) with Xt XZR from an accessor's op0:op1:CRn:CRm:op2.
        let sys = |accessor: &crate::machine::system::Accessor| {
            0xd500_001f | u32::from(accessor.value) << 5
        };
        for (chip, xs) in [
            (crate::machine::Chip::AppleM2, false),
            (crate::machine::Chip::AppleM4, true),
        ] {
            let fresh = |el| {
                let mut machine = machine_on(chip, &[]);
                machine.cpu = Cpu::of(chip, BASE, Pstate::reset(el));
                let registers = &mut machine.cpu.registers;
                registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
                registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
                machine
            };
            // DSB nXS completes as DSB does with FEAT_XS, and is UNDEFINED
            // without it.
            let mut machine = fresh(1);
            machine.system_instruction(DSB_ISHNXS).unwrap();
            if xs {
                assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
            } else {
                assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
            }
            // Every TLBI nXS at EL1 and EL2 behaves as its TLBI with FEAT_XS
            // (invalidating XS 1 entries too, which a TLB may always drop),
            // and is UNDEFINED without it.
            let mut count = 0;
            for nxs in crate::machine::system::ACCESSORS
                .iter()
                .filter(|a| a.kind == "TLBI" && a.name.ends_with("NXS"))
            {
                let plain = crate::machine::system::ACCESSORS
                    .iter()
                    .find(|a| a.kind == "TLBI" && a.name == nxs.name.trim_end_matches("NXS"))
                    .unwrap();
                for el in [1, 2] {
                    let mut nxs_machine = fresh(el);
                    nxs_machine.system_instruction(sys(nxs)).unwrap();
                    let outcome = |machine: &Machine<FakeHost, NoDevices>| {
                        (
                            machine.cpu.pc,
                            machine.cpu.pstate.el,
                            machine.cpu.read(SystemRegister::ESR_EL1),
                            machine.cpu.read(SystemRegister::ESR_EL2),
                        )
                    };
                    if xs {
                        let mut plain_machine = fresh(el);
                        plain_machine.system_instruction(sys(plain)).unwrap();
                        assert_eq!(
                            outcome(&nxs_machine),
                            outcome(&plain_machine),
                            "{}",
                            nxs.name
                        );
                    } else {
                        let esr = if el == 1 {
                            SystemRegister::ESR_EL1
                        } else {
                            SystemRegister::ESR_EL2
                        };
                        assert_eq!(nxs_machine.cpu.read(esr), 0x0200_0000, "{} {el}", nxs.name);
                    }
                }
                count += 1;
            }
            assert!(count > 50, "{count}");
            // HCRX_EL2.FnXS makes a TLBI at EL1 behave as its nXS form,
            // which completes as the TLBI does.
            if xs {
                let mut machine = fresh(2);
                machine.cpu.state.x[0] = 1 << 3;
                machine.system_instruction(0xd51c_1240).unwrap(); // msr hcrx_el2, x0
                assert_eq!(machine.cpu.read(SystemRegister::HCRX_EL2) & 1 << 3, 1 << 3);
                machine.cpu.set_pstate(Pstate::reset(1));
                machine.cpu.pc = BASE;
                machine.system_instruction(0xd508_871f).unwrap(); // tlbi vmalle1
                assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
                // HFGITR_EL2.TLBIVMALLE1 traps TLBI VMALLE1NXS from EL1 to
                // EL2 unless HCRX_EL2.FGTnXS exempts the nXS forms.
                const TLBI_VMALLE1NXS: u32 = 0xd508_971f;
                for (hcrx, trapped) in [(0, true), (1 << 4, false)] {
                    let mut machine = fresh(1);
                    let registers = &mut machine.cpu.registers;
                    registers.set(SystemRegister::HFGITR_EL2, 0, 1 << 42);
                    registers.set(SystemRegister::HCRX_EL2, 0, hcrx);
                    machine.system_instruction(TLBI_VMALLE1NXS).unwrap();
                    if trapped {
                        assert_eq!(machine.cpu.pstate.el, 2);
                        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2) >> 26, 0x18);
                    } else {
                        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
                    }
                }
            }
            // MAIR index 0 Device-nGnRE with XS 0, index 1 Normal
            // Write-Back; level-1 blocks map VA 0 and 1 GiB to BASE.
            let mut machine = fresh(1);
            for (entry, index) in [(0x4000, 0u64), (0x4008, 1)] {
                let block = BASE | 1 | 1 << 10 | 1 << 6 | index << 2;
                machine.host.ram[entry..entry + 8].copy_from_slice(&block.to_le_bytes());
            }
            let registers = &mut machine.cpu.registers;
            registers.set(SystemRegister::MAIR_EL1, 0, 0xff_05);
            registers.set(SystemRegister::TCR_EL1, 0, 25 | 1 << 23 | 5 << 32);
            registers.set(SystemRegister::TTBR0_EL1, 0, BASE + 0x4000);
            registers.set(SystemRegister::SCTLR_EL1, 0, 1 | 1 << 2);
            machine.derived_changed();
            let attribute = |machine: &mut Machine<FakeHost, NoDevices>, address: u64| {
                machine.cpu.state.x[2] = address;
                machine.system_instruction(AT_S1E1R_X2).unwrap();
                machine.cpu.read(SystemRegister::PAR_EL1) >> 56
            };
            // With FEAT_XS, PAR_EL1.ATTR reports the Device memory's XS 0;
            // without it the encoding is reserved and reads as nGnRE.
            assert_eq!(
                attribute(&mut machine, 0x1000),
                if xs { 0x05 } else { 0x04 }
            );
            // SCTLR_EL1.C clear makes Write-Back memory Non-cacheable, which
            // keeps its XS 0.
            machine.cpu.registers.set(SystemRegister::SCTLR_EL1, 0, 1);
            machine.derived_changed();
            assert_eq!(
                attribute(&mut machine, 0x4000_1000),
                if xs { 0x40 } else { 0x44 }
            );
        }
    }

    #[test]
    fn prediction_restrictions_complete_on_every_chip() {
        // CFP, DVP and CPP RCTX, X0 (SYS #3, C7, C3, #4, #5 and #7).
        const RCTX_X0: [u32; 3] = [0xd50b_7380, 0xd50b_73a0, 0xd50b_73e0];
        // MSR SCTLR_EL1, X0.
        const MSR_SCTLR_EL1_X0: u32 = 0xd518_1000;
        const SCTLR_ENRCTX: u64 = 1 << 10;
        let fresh = |el| {
            let mut machine = machine(&[]);
            machine.cpu = Cpu::of(machine.profile.chip, BASE, Pstate::reset(el));
            machine
                .cpu
                .registers
                .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
            machine
        };
        for word in RCTX_X0 {
            let mut machine = fresh(1);
            machine.system_instruction(word).unwrap();
            assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
            // EnRCTX clear: EL0 traps to EL1 (EC 0x18).
            let mut machine = fresh(0);
            machine.system_instruction(word).unwrap();
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1) >> 26, 0x18);
        }
        // EnRCTX holds through MSR and then lets EL0 restrict predictions.
        let mut machine = fresh(1);
        let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
        machine.cpu.state.x[0] = sctlr | SCTLR_ENRCTX;
        machine.system_instruction(MSR_SCTLR_EL1_X0).unwrap();
        assert_eq!(
            machine.cpu.read(SystemRegister::SCTLR_EL1) & SCTLR_ENRCTX,
            SCTLR_ENRCTX
        );
        machine.cpu.pstate = Pstate::reset(0);
        machine.cpu.pc = BASE;
        machine.derived_changed();
        machine.system_instruction(RCTX_X0[0]).unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 0));
        // In the host (E2H and TGE) SCTLR_EL2.EnRCTX governs EL0, trapping
        // to EL2.
        const HOST: u64 = 1 << 34 | 1 << 27;
        let host = |enabled: bool| {
            let mut machine = fresh(0);
            let registers = &mut machine.cpu.registers;
            registers.set(SystemRegister::HCR_EL2, 0, HOST);
            registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
            let sctlr = registers.get(SystemRegister::SCTLR_EL2, 0);
            let sctlr = if enabled {
                sctlr | SCTLR_ENRCTX
            } else {
                sctlr & !SCTLR_ENRCTX
            };
            registers.set(SystemRegister::SCTLR_EL2, 0, sctlr);
            registers.set(SystemRegister::SCTLR_EL1, 0, SCTLR_ENRCTX);
            machine.derived_changed();
            machine.system_instruction(RCTX_X0[2]).unwrap();
            machine
        };
        let machine = host(false);
        assert_eq!(machine.cpu.pstate.el, 2);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2) >> 26, 0x18);
        let machine = host(true);
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 0));
    }

    #[test]
    fn cosp_rctx_restricts_nothing_on_the_chips_with_specres2() {
        // COSP RCTX, X0 (SYS #3, C7, C3, #6).
        const COSP_RCTX_X0: u32 = 0xd50b_73c0;
        const SCTLR_ENRCTX: u64 = 1 << 10;
        for (chip, specres2) in [
            (crate::machine::Chip::AppleM4, false),
            (crate::machine::Chip::AppleM5, true),
        ] {
            let fresh = |el| {
                let mut machine = machine_on(chip, &[]);
                machine.cpu = Cpu::of(chip, BASE, Pstate::reset(el));
                machine
                    .cpu
                    .registers
                    .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
                machine
            };
            // At EL1 it completes with no effect, there being no speculation
            // to restrict, or is UNDEFINED without FEAT_SPECRES2.
            let mut machine = fresh(1);
            machine.system_instruction(COSP_RCTX_X0).unwrap();
            if specres2 {
                assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 1));
            } else {
                assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
                continue;
            }
            // At EL0 SCTLR_EL1.EnRCTX clear traps it to EL1 (EC 0x18).
            let mut machine = fresh(0);
            machine.system_instruction(COSP_RCTX_X0).unwrap();
            assert_eq!(machine.cpu.pstate.el, 1);
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1) >> 26, 0x18);
            let mut machine = fresh(0);
            machine
                .cpu
                .registers
                .set(SystemRegister::SCTLR_EL1, 0, SCTLR_ENRCTX);
            machine.derived_changed();
            machine.system_instruction(COSP_RCTX_X0).unwrap();
            assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 4, 0));
        }
    }

    #[test]
    fn sysl_has_no_architectural_accessor_and_refuses_the_implementation_defined_space() {
        let mut machine = machine(&[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        // GCSPOPM (SYSL #0, C7, C7, #1) needs FEAT_GCS, and op1 3 CRn 7 has
        // no SYSL: both are UNDEFINED at EL1 and EL0.
        for (el, word) in [(1, 0xd528_7720), (1, 0xd52b_7000), (0, 0xd528_7720)] {
            machine.cpu.set_pstate(Pstate::reset(el));
            machine.cpu.pc = BASE;
            machine.system_instruction(word).unwrap();
            assert_eq!(machine.cpu.pstate.el, 1, "{word:#x}");
            assert_eq!(
                machine.cpu.read(SystemRegister::ESR_EL1) >> 26,
                0,
                "{word:#x}"
            );
        }
        // CRn 11 and 15 are the IMPLEMENTATION DEFINED space.
        for word in [0xd528_b000, 0xd52f_f3e0] {
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.cpu.pc = BASE;
            assert!(
                matches!(machine.system_instruction(word), Err(Stop::Unsupported(_))),
                "{word:#x}"
            );
        }
    }

    #[test]
    fn completion_barriers_and_unallocated_hints_only_advance_the_pc() {
        let mut machine = machine(&[]);
        for el in [0, 1, 2] {
            // DSB SY, DSB OSHLD, ISB, SSBB, PSSBB, HINT #0x54 and #0x7f.
            for word in [
                0xd503_3f9f,
                0xd503_319f,
                0xd503_3fdf,
                0xd503_309f,
                0xd503_349f,
                0xd503_2a9f,
                0xd503_2fff,
            ] {
                machine.cpu.set_pstate(Pstate::reset(el));
                machine.cpu.pc = BASE;
                let before = machine.cpu.state.clone();
                machine.system_instruction(word).unwrap();
                assert_eq!(machine.cpu.pc, BASE + 4, "{word:#x} at EL{el}");
                assert_eq!(machine.cpu.pstate.el, el);
                assert_eq!(machine.cpu.state, before, "{word:#x} at EL{el}");
            }
        }
    }

    /// A machine with the OS lock clear and MDSCR_EL1 `mdscr`.
    fn debug_machine(mdscr: u64) -> Machine<FakeHost, NoDevices> {
        let mut machine = machine(&[0xd503_201f, 0xd503_201f, 0xd503_201f]);
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::OSLSR_EL1, 0, 0b1000);
        registers.set(SystemRegister::MDSCR_EL1, 0, mdscr);
        registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        registers.set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
        machine.derived_changed();
        machine
    }

    #[test]
    fn breakpoints_and_brk_follow_kde_pstate_d_and_tde() {
        const MDE: u64 = 1 << 15;
        const KDE: u64 = 1 << 13;
        let mut machine = debug_machine(MDE | KDE);
        // Breakpoint 0 at BASE + 4 for EL1 (PMC 0b01).
        machine
            .cpu
            .registers
            .set(SystemRegister::DBGBVR_EL1, 0, BASE + 4);
        machine
            .cpu
            .registers
            .set(SystemRegister::DBGBCR_EL1, 0, 0b1111 << 5 | 0b01 << 1 | 1);
        machine.cpu.set_pstate(Pstate {
            daif: 0,
            ..Pstate::reset(1)
        });
        machine.derived_changed();
        // The instruction at BASE runs as a single-instruction block.
        machine.host.exits.push(NativeExit::Exit {
            next_pc: BASE + 4,
            kind: ExitKind::Fallthrough as u64,
        });
        machine.step().unwrap();
        assert_eq!(machine.cpu.pc, BASE + 4);
        // The breakpoint is taken before BASE + 4 executes: EC 0x31, IFSC
        // 0b100010, FAR not written.
        machine
            .cpu
            .registers
            .set(SystemRegister::FAR_EL1, 0, 0x1234);
        machine.step().unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xc600_0022);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 4);
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), 0x1234);
        assert_eq!(machine.cpu.pc, 0x1_0200);
        // With PSTATE.D set (as on exception entry) the breakpoint is masked.
        machine.cpu.pc = BASE + 4;
        machine.host.exits.push(NativeExit::Exit {
            next_pc: BASE + 8,
            kind: ExitKind::Fallthrough as u64,
        });
        machine.step().unwrap();
        assert_eq!(machine.cpu.pc, BASE + 8);
        // MDCR_EL2.TDCC (bit 27) traps only DCC accesses: BRK stays at EL1.
        machine
            .cpu
            .registers
            .set(SystemRegister::MDCR_EL2, 0, 1 << 27);
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.derived_changed();
        machine.cpu.pc = BASE;
        machine.system_instruction(0xd420_0020).unwrap(); // brk #1
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xf200_0001);
        assert_eq!(machine.cpu.pstate.el, 1);
        // MDCR_EL2.TDE (bit 8) routes debug exceptions, BRK included, to EL2.
        machine
            .cpu
            .registers
            .set(SystemRegister::MDCR_EL2, 0, 1 << 8);
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.derived_changed();
        machine.cpu.pc = BASE;
        machine.system_instruction(0xd420_0020).unwrap(); // brk #1
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0xf200_0001);
        assert_eq!(machine.cpu.pstate.el, 2);
    }

    #[test]
    fn software_step_runs_one_instruction_then_takes_ec_0x32() {
        const SS: u64 = 1;
        let mut machine = debug_machine(SS);
        // ERET from EL1 (debug disabled there: no KDE) to EL0 with SPSR.SS
        // set makes the step active-not-pending at EL0.
        machine.cpu.registers.set(SystemRegister::ELR_EL1, 0, BASE);
        machine
            .cpu
            .registers
            .set(SystemRegister::SPSR_EL1, 0, 1 << 21);
        machine.system_instruction(0xd69f_03e0).unwrap();
        assert!(machine.cpu.pstate.ss && machine.cpu.pstate.el == 0);
        machine.host.exits.push(NativeExit::Exit {
            next_pc: BASE + 4,
            kind: ExitKind::Fallthrough as u64,
        });
        machine.step().unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.ss), (BASE + 4, false));
        // Active-pending: the next instruction takes the step exception to
        // EL1 (EC 0x32, ISS 0x22) with SPSR.SS clear.
        machine.step().unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xca00_0022);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE + 4);
        assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1) & 1 << 21, 0);
        assert_eq!(machine.cpu.pc, 0x1_0400);
        // An SVC stepped from EL0 completes the step: SPSR.SS is 0.
        machine
            .cpu
            .registers
            .set(SystemRegister::SPSR_EL1, 0, 1 << 21);
        machine.cpu.registers.set(SystemRegister::ELR_EL1, 0, BASE);
        machine.system_instruction(0xd69f_03e0).unwrap();
        machine.cpu.step_advance = true;
        machine.system_instruction(0xd400_0001).unwrap(); // svc #0
        assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1) & 1 << 21, 0);
    }

    #[test]
    fn watched_pages_exit_and_matching_accesses_take_ec_0x35() {
        const MDE: u64 = 1 << 15;
        const KDE: u64 = 1 << 13;
        // str x1, [x0]; ldr x2, [x0, #8]
        let mut machine = machine(&[0xf900_0001, 0xf940_0402]);
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::OSLSR_EL1, 0, 0b1000);
        registers.set(SystemRegister::MDSCR_EL1, 0, MDE | KDE);
        registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        // Watchpoint 0: bytes 4..=7 of the doubleword at BASE + 0x100,
        // stores, EL1.
        registers.set(SystemRegister::DBGWVR_EL1, 0, BASE + 0x100);
        registers.set(
            SystemRegister::DBGWCR_EL1,
            0,
            0xf0 << 5 | 0b10 << 3 | 0b01 << 1 | 1,
        );
        machine.cpu.set_pstate(Pstate {
            daif: 0,
            ..Pstate::reset(1)
        });
        machine.sync_regime();
        let watch = machine.host.regimes.last().unwrap().watch;
        assert!(watch.blocks(BASE) && !watch.blocks(BASE + 0x1000));
        machine.cpu.state.x[0] = BASE + 0x100;
        let watched = |address, write| {
            NativeExit::Fault(NativeFault {
                offset: 0,
                address,
                write,
                cause: FaultCause::Watched,
            })
        };
        // The store covers bytes 0..=7: a match at byte 4, EC 0x35 (same
        // EL), WnR, DFSC 0b100010, FAR the first matching byte.
        machine.host.exits.push(watched(BASE + 0x100, true));
        machine.step().unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xd600_0062);
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), BASE + 0x104);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
        // The load at BASE + 4 does not match: it runs once with its page
        // passed, which then leaves the shadow again.
        machine.cpu.set_pstate(Pstate {
            daif: 0,
            ..Pstate::reset(1)
        });
        machine.sync_regime();
        machine.cpu.pc = BASE + 4;
        machine.host.exits.push(watched(BASE + 0x108, false));
        machine.host.exits.push(NativeExit::Exit {
            next_pc: BASE + 8,
            kind: ExitKind::Fallthrough as u64,
        });
        let invalidations = machine.host.invalidations;
        machine.step().unwrap();
        assert_eq!(machine.cpu.pc, BASE + 8);
        assert!(machine.host.invalidations > invalidations);
        assert!(
            machine
                .host
                .regimes
                .iter()
                .any(|regime| regime.watch.pass[0] == Some(BASE))
        );
        assert_eq!(machine.host.regimes.last().unwrap().watch.pass, [None; 2]);
        // DC ZVA writes its whole block: the same watchpoint matches.
        machine.cpu.pc = BASE;
        machine.cpu.state.x[3] = BASE + 0x120;
        machine.system_instruction(0xd50b_7423).unwrap(); // dc zva, x3
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xd600_0062);
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), BASE + 0x104);
    }

    #[test]
    fn exclusives_use_the_monitor_granule_and_lse2_alignment() {
        let mut machine = machine(&[]);
        let data = 0x200;
        machine.host.ram[data..data + 16]
            .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        machine.cpu.state.x[2] = BASE + data as u64;
        // ldxr x1, [x2]; stxr w3, x4, [x2]: passes once.
        machine.system_instruction(0xc85f_7c41).unwrap();
        assert_eq!(machine.cpu.state.x[1], 0x0807_0605_0403_0201);
        assert_eq!(machine.cpu.monitor, Some((BASE + 0x200) & !63));
        machine.cpu.state.x[4] = 0x1111_2222_3333_4444;
        machine.system_instruction(0xc803_7c44).unwrap();
        assert_eq!(machine.cpu.state.x[3], 0);
        assert_eq!(
            &machine.host.ram[data..data + 8],
            &0x1111_2222_3333_4444u64.to_le_bytes()
        );
        machine.cpu.state.x[4] = 0;
        machine.system_instruction(0xc803_7c44).unwrap();
        assert_eq!(machine.cpu.state.x[3], 1, "the monitor was cleared");
        // CLREX clears the monitor between the pair.
        machine.system_instruction(0xc85f_7c41).unwrap();
        machine.system_instruction(0xd503_305f).unwrap();
        machine.system_instruction(0xc803_7c44).unwrap();
        assert_eq!(machine.cpu.state.x[3], 1);
        // ldxp x1, x5, [x2]; stxp w3, x4, x6, [x2].
        machine.system_instruction(0xc87f_1441).unwrap();
        assert_eq!(machine.cpu.state.x[5], 0x100f_0e0d_0c0b_0a09);
        machine.cpu.state.x[6] = 7;
        machine.system_instruction(0xc823_1844).unwrap();
        assert_eq!(machine.cpu.state.x[3], 0);
        assert_eq!(&machine.host.ram[data + 8..data + 16], &7u64.to_le_bytes());
        // With the MMU off data is Device memory, where an unaligned exclusive
        // is an Alignment fault (EC 0x25, DFSC 0b100001) even inside its
        // 16-byte granule.
        machine.cpu.state.x[2] = BASE + data as u64 + 2;
        machine.cpu.pc = BASE;
        machine.system_instruction(0x885f_7c41).unwrap(); // ldxr w1, [x2]
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x9600_0021);
        assert_eq!(
            machine.cpu.read(SystemRegister::FAR_EL1),
            BASE + data as u64 + 2
        );
    }

    #[test]
    fn os_lock_and_the_debug_communications_channel() {
        let mut machine = machine(&[]);
        // The OS lock is set at Cold reset; MSR OSLAR_EL1 clears it.
        assert_eq!(machine.cpu.read(SystemRegister::OSLSR_EL1) & 0b10, 0b10);
        // While it is set, OSECCR_EL1 saves and restores EDECCR (bits 31:0;
        // bits 63:32 are RES0). No external debugger reads it.
        machine.cpu.state.x[0] = 0xffff_ffff_1234_5678;
        machine.system_instruction(0xd510_0640).unwrap(); // msr oseccr_el1, x0
        machine.system_instruction(0xd530_0645).unwrap(); // mrs x5, oseccr_el1
        assert_eq!(machine.cpu.state.x[5], 0x1234_5678);
        machine.cpu.state.x[0] = 0;
        machine.system_instruction(0xd510_1080).unwrap(); // msr oslar_el1, x0
        assert_eq!(machine.cpu.read(SystemRegister::OSLSR_EL1) & 0b10, 0);
        // Unlocked, writes are ignored and reads are UNKNOWN (0 here).
        machine.cpu.state.x[0] = 0x9;
        machine.system_instruction(0xd510_0640).unwrap(); // msr oseccr_el1, x0
        machine.system_instruction(0xd530_0645).unwrap(); // mrs x5, oseccr_el1
        assert_eq!(machine.cpu.state.x[5], 0);
        assert_eq!(machine.cpu.read(SystemRegister::OSECCR_EL1), 0x1234_5678);
        machine.cpu.state.x[0] = 0;
        // A DBGDTRTX_EL0 write latches TXfull; nothing fills DTRRX.
        machine.cpu.state.x[0] = 0x1234_5678;
        machine.system_instruction(0xd513_0500).unwrap(); // msr dbgdtrtx_el0, x0
        machine.system_instruction(0xd533_0101).unwrap(); // mrs x1, mdccsr_el0
        assert_eq!(machine.cpu.state.x[1], 1 << 29);
        machine.cpu.state.x[2] = 7;
        machine.system_instruction(0xd533_0502).unwrap(); // mrs x2, dbgdtrrx_el0
        assert_eq!(machine.cpu.state.x[2], 0);
        assert_eq!(machine.cpu.dcc.tx, 0x1234_5678);
        // Claim tags: SET reads every implemented tag, CLR the claim.
        machine.cpu.state.x[0] = 0b101;
        machine.system_instruction(0xd510_78c0).unwrap(); // msr dbgclaimset_el1, x0
        machine.cpu.state.x[0] = 0b1;
        machine.system_instruction(0xd510_79c0).unwrap(); // msr dbgclaimclr_el1, x0
        machine.system_instruction(0xd530_79c3).unwrap(); // mrs x3, dbgclaimclr_el1
        machine.system_instruction(0xd530_78c4).unwrap(); // mrs x4, dbgclaimset_el1
        assert_eq!(
            (machine.cpu.state.x[3], machine.cpu.state.x[4]),
            (0b100, 0xff)
        );
    }

    #[test]
    fn floating_point_detection_matches_encoding_classes() {
        for word in [
            0x1e60_2820_u32,
            0x4ea1_1c20,
            0x3dc0_0020,
            0xad40_0420,
            0xbd40_0020,
        ] {
            assert!(is_floating_point(word), "{word:#x}");
        }
        for word in [0x9100_0400_u32, 0xf940_0020, 0xa900_0be1, 0xd503_201f] {
            assert!(!is_floating_point(word), "{word:#x}");
        }
    }
}
