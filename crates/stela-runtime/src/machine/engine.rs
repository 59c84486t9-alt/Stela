//! The dispatch loop: fetch translation, block cache, native execution and
//! every exit back from native code.
mod amx;
mod system;

use super::{
    cpu::{
        Cpu, Exception, HCR_AMO, HCR_API, HCR_FMO, HCR_HCD, HCR_IMO, HCR_TGE, HCR_TSC, HCR_VF,
        HCR_VI, HCR_VSE,
    },
    exception::{Class, DAIF_A, DAIF_F, DAIF_I, IllegalReturn, Vector, data_abort_iss},
    mmu::{self, Access, Controls, Outcome as Translated},
    registers::{self, CpuProfile, Lines, Outcome as RegisterOutcome, Refusal},
    system::Register as SystemRegister,
    timer,
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
        PointerAuthenticationKey, PointerAuthenticationOperation,
        el1_platform::{ScalarLoad, ScalarLoadAddress, ScalarStore},
        system::{GuardedOperation, SystemOperation},
    },
};

const PROFILE: BlockProfile = BlockProfile::SystemModeV1;
const INSTRUCTION: u64 = 4;
const FETCH_PAGE: u64 = 4096;
const MAX_BLOCK_BYTES: u64 = block::MAX_BLOCK_INSTRUCTIONS as u64 * INSTRUCTION;
const FETCH_CACHE: usize = 1024;
const JUMP_CACHE: usize = 4096;
/// ISS CV=1 and COND=0b1110, as reported for trapped AArch64 instructions.
const TRAPPED_AARCH64: u32 = (1 << 24) | (0b1110 << 20);
/// HFGITR_EL2 instruction traps (FEAT_FGT).
const HFGITR_ERET: u32 = 51;
const HFGITR_SVC_EL0: u32 = 52;
const HFGITR_SVC_EL1: u32 = 53;

/// The translation regime the host's shadow tables must reflect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Regime {
    pub controls: Controls,
    pub requester: mmu::Requester,
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

/// The board's devices on the guest physical bus. `now` is the system
/// counter value (24 MHz ticks) of the access.
pub trait Devices {
    fn read(&mut self, physical: u64, bytes: u8, now: u64) -> Result<u64, DeviceError>;
    fn write(&mut self, physical: u64, bytes: u8, value: u64, now: u64) -> Result<(), DeviceError>;
    /// Bring time-driven state up to `now` and report the interrupt lines
    /// the devices drive into this PE.
    fn lines(&mut self, now: u64) -> Lines;
    /// The next counter value at which a device changes state by itself.
    fn deadline(&mut self, _now: u64) -> Option<u64> {
        None
    }
    /// A reset or power-off the guest requested from a device, once.
    fn take_reset(&mut self) -> Option<String> {
        None
    }
}

/// A bus with no devices: every access is [`DeviceError::NoDevice`].
pub struct NoDevices;

impl Devices for NoDevices {
    fn read(&mut self, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
        Err(DeviceError::NoDevice)
    }
    fn write(&mut self, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
        Err(DeviceError::NoDevice)
    }
    fn lines(&mut self, _: u64) -> Lines {
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
    Return {
        to_el: u8,
        pc: u64,
    },
    /// GENTER or GEXIT; `entered` tells whether the PE is now guarded.
    Guarded {
        entered: bool,
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
    /// WFI or WFE with no interrupt able to wake the PE.
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
}

struct Block {
    pc: u64,
    physical: u64,
    code: NativeCode,
    /// Guest PC and native offset of every instruction, ascending.
    source_map: Vec<(u64, usize)>,
    /// Compiled with SP alignment checks (SCTLR_ELx.SA or SA0 set).
    stack_check: bool,
}

#[derive(Clone, Copy)]
struct FetchEntry {
    page: u64,
    physical: u64,
    el: u8,
    generation: u64,
}

#[derive(Clone, Copy)]
struct JumpEntry {
    pc: u64,
    physical: u64,
    fp: bool,
    stack_check: bool,
    generation: u64,
    block: usize,
}

/// Floating-point and SIMD instructions, which CPACR_EL1.FPEN can trap:
/// SIMD&FP data processing (op0 x111) and SIMD&FP loads/stores (op0 x1x0, V=1).
/// A load or store addressed through Rn (bits 9:5) that names SP; literal
/// loads have no base register.
fn stack_based(word: u32) -> bool {
    word & 0x0a00_0000 == 0x0800_0000 && word & 0x3b00_0000 != 0x1800_0000 && (word >> 5) & 31 == 31
}

fn is_floating_point(word: u32) -> bool {
    (word >> 25) & 7 == 7 || word & 0x0a00_0000 == 0x0800_0000 && word & (1 << 26) != 0
}

pub struct Machine<H: Host, D: Devices> {
    pub cpu: Cpu,
    pub host: H,
    pub devices: D,
    pub profile: CpuProfile,
    pub statistics: Statistics,
    target: TargetCpu,
    blocks: Vec<Block>,
    /// Blocks by PC, PA, FP enablement and SP alignment checking.
    index: BTreeMap<(u64, u64, bool, bool), usize>,
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
    /// SCTLR_ELx.SA, or SA0 at EL0, of the current regime, while valid.
    stack_check: Option<bool>,
}

enum Fetched {
    Block(usize),
    Exception(Exception),
}

type Step = Result<(), Stop>;

impl<H: Host, D: Devices> Machine<H, D> {
    pub fn new(cpu: Cpu, host: H, devices: D, profile: CpuProfile, target: TargetCpu) -> Self {
        let mut machine = Self {
            cpu,
            host,
            devices,
            profile,
            statistics: Statistics::default(),
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
            stack_check: None,
        };
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
        self.stack_check = None;
    }

    /// Whether loads and stores through SP check its 16-byte alignment (Arm
    /// `CheckSPAlignment`): SCTLR_ELx.SA0 at EL0 and SA otherwise, of the
    /// current translation regime.
    fn stack_alignment_checked(&mut self) -> bool {
        *self.stack_check.get_or_insert_with(|| {
            let sctlr = self.cpu.controls(self.cpu.regime()).sctlr;
            let bit = if self.cpu.pstate.el == 0 { 4 } else { 3 };
            sctlr & (1 << bit) != 0
        })
    }

    fn sync_regime(&mut self) {
        self.derived_changed();
        let regime = Regime {
            controls: self.cpu.controls(self.cpu.regime()),
            requester: self.cpu.requester(),
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
        let device = self.devices.lines(now);
        // A timer signals exactly when the count reaches its deadline, which
        // only System register writes change.
        let deadline = self.timer_deadline();
        Lines {
            irq: device.irq,
            // Apple cores signal the generic timers as FIQ.
            fiq: device.fiq || deadline.is_some_and(|deadline| now >= deadline),
        }
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

    fn timer_deadline(&mut self) -> Option<u64> {
        *self
            .timers
            .get_or_insert_with(|| timer::deadline(&self.cpu))
    }

    /// Run until a stop. `budget` limits executed blocks (0 = unlimited).
    pub fn run(&mut self, budget: u64) -> Stop {
        loop {
            if budget != 0 && self.statistics.blocks >= budget {
                return Stop::Budget;
            }
            if let Err(stop) = self.step() {
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
        if !pc.is_multiple_of(INSTRUCTION) {
            let mut exception = Exception::synchronous(Class::PcAlignment, 0, pc);
            exception.fault_address = Some(pc);
            self.take(exception);
            return Ok(());
        }
        if self.cpu.pstate.il {
            return self.illegal_state(pc);
        }
        let index = match self.fetch_block(pc)? {
            Fetched::Block(index) => index,
            Fetched::Exception(exception) => {
                self.take(exception);
                return Ok(());
            }
        };
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

    /// With PSTATE.IL set, the instruction at `pc` takes the Illegal
    /// Execution state exception after any Instruction Abort its fetch raises
    /// (Arm `AArch64_CheckIllegalState`).
    #[cold]
    fn illegal_state(&mut self, pc: u64) -> Step {
        let exception = match self.fetch_physical(pc) {
            Ok(_) => Exception::synchronous(Class::IllegalExecution, 0, pc),
            Err(Ok(exception)) => exception,
            Err(Err(stop)) => return Err(stop),
        };
        self.take(exception);
        Ok(())
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
            Translated::Fault(fault) => {
                let class = if self.cpu.route() > self.cpu.pstate.el {
                    Class::InstructionAbortLower
                } else {
                    Class::InstructionAbortSame
                };
                let mut exception = Exception::synchronous(class, fault.status_code(), pc);
                exception.fault_address = Some(pc);
                Err(Ok(exception))
            }
            Translated::Unsupported(unsupported) => Err(Err(
                self.unsupported(RequirementKind::Translation(unsupported))
            )),
        }
    }

    /// The EL an FP/SIMD access traps to, if it traps (Arm
    /// `AArch64_CheckFPEnabled`): CPACR_EL1.FPEN at EL0 and EL1 outside the
    /// host, then CPTR_EL2.FPEN, which has the CPACR layout because
    /// HCR_EL2.E2H is RES1.
    fn floating_point_trap(&mut self) -> Option<u8> {
        *self
            .floating_point
            .get_or_insert_with(|| floating_point_trap(&self.cpu))
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

/// The EL an FP/SIMD access traps to, if it traps (Arm
/// `AArch64_CheckFPEnabled`): CPACR_EL1.FPEN at EL0 and EL1 outside the
/// host, then CPTR_EL2.FPEN, which has the CPACR layout because HCR_EL2.E2H
/// is RES1.
fn floating_point_trap(cpu: &Cpu) -> Option<u8> {
    const FPEN: u32 = 20;
    let el = cpu.pstate.el;
    let in_host = el == 2 || (el == 0 && cpu.in_host());
    if el != 2 && !in_host {
        match cpu.field(SystemRegister::CPACR_EL1, FPEN, 2) {
            0b11 => {}
            0b01 if el != 0 => {}
            _ => return Some(1),
        }
    }
    match cpu.field(SystemRegister::CPTR_EL2, FPEN, 2) {
        0b11 => None,
        0b01 if !(el == 0 && cpu.in_host()) => None,
        _ => Some(2),
    }
}

impl<H: Host, D: Devices> Machine<H, D> {
    fn fetch_block(&mut self, pc: u64) -> Result<Fetched, Stop> {
        let physical = match self.fetch_physical(pc) {
            Ok(physical) => physical,
            Err(Ok(exception)) => return Ok(Fetched::Exception(exception)),
            Err(Err(stop)) => return Err(stop),
        };
        let fp = self.floating_point_enabled();
        let stack_check = self.stack_alignment_checked();
        let slot = (pc / INSTRUCTION) as usize % JUMP_CACHE;
        if let Some(entry) = self.jump[slot]
            && entry.pc == pc
            && entry.physical == physical
            && entry.fp == fp
            && entry.stack_check == stack_check
            && entry.generation == self.code_generation
        {
            return Ok(Fetched::Block(entry.block));
        }
        let index = match self.index.get(&(pc, physical, fp, stack_check)) {
            Some(&index) => index,
            None => match self.compile(pc, physical, fp, stack_check)? {
                Some(index) => index,
                None => {
                    // The first instruction is FP/SIMD while CPACR or CPTR
                    // traps it.
                    return Ok(Fetched::Exception(self.floating_point_exception(pc)));
                }
            },
        };
        self.jump[slot] = Some(JumpEntry {
            pc,
            physical,
            fp,
            stack_check,
            generation: self.code_generation,
            block: index,
        });
        Ok(Fetched::Block(index))
    }

    /// Compile the block at `pc`. `None` when its first instruction is a
    /// trapped FP/SIMD instruction.
    fn compile(
        &mut self,
        pc: u64,
        physical: u64,
        fp: bool,
        stack_check: bool,
    ) -> Result<Option<usize>, Stop> {
        let available = (FETCH_PAGE - (pc & (FETCH_PAGE - 1))).min(MAX_BLOCK_BYTES);
        let mut source = vec![0u8; available as usize];
        if !self.host.read_ram(physical, &mut source) {
            return Err(self.unsupported(RequirementKind::Fetch { physical }));
        }
        let mut length = source.len();
        if !fp {
            let first = source
                .as_chunks::<4>()
                .0
                .iter()
                .position(|word| is_floating_point(u32::from_le_bytes(*word)));
            match first {
                Some(0) => return Ok(None),
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
        let compiled = self.compile_prefix(&source[..consumed], pc, stack_check)?;
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
            stack_check,
        });
        let index = self.blocks.len() - 1;
        self.index.insert((pc, physical, fp, stack_check), index);
        Ok(Some(index))
    }

    /// Compile the longest prefix the host target can emit.
    fn compile_prefix(
        &self,
        source: &[u8],
        pc: u64,
        stack_check: bool,
    ) -> Result<stela_compiler::block::CompiledBlock, Stop> {
        let attempt = |bytes: &[u8]| {
            CompilationPlan::new(bytes, GuestAddress(pc), PROFILE, self.target)
                .and_then(|plan| plan.with_stack_alignment_check(stack_check))
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

    /// The original word of an instruction inside a compiled block.
    fn word(&mut self, index: usize, pc: u64) -> Result<u32, Stop> {
        let block = &self.blocks[index];
        let physical = block.physical + (pc - block.pc);
        let mut bytes = [0; 4];
        if !self.host.read_ram(physical, &mut bytes) {
            return Err(self.unsupported(RequirementKind::Fetch { physical }));
        }
        Ok(u32::from_le_bytes(bytes))
    }

    fn exit(&mut self, index: usize, next_pc: u64, kind: u64) -> Step {
        match ExitKind::try_from(kind) {
            Ok(
                ExitKind::Fallthrough
                | ExitKind::Direct
                | ExitKind::Indirect
                | ExitKind::Call
                | ExitKind::Return,
            ) => {
                self.cpu.pc = next_pc;
                Ok(())
            }
            Ok(ExitKind::System) => {
                self.cpu.pc = next_pc;
                self.statistics.system_exits += 1;
                let word = self.word(index, next_pc)?;
                self.system_instruction(word)
            }
            Ok(ExitKind::FloatingPoint) => {
                self.cpu.pc = next_pc;
                let word = self.word(index, next_pc)?;
                let Some(Ok(operation)) = FloatingPointOperation::decode(word) else {
                    return Err(self.unsupported(RequirementKind::Native(
                        "numerical exit at a word that is not numerical FP",
                    )));
                };
                match crate::floating::complete(&mut self.cpu.state, &operation) {
                    Ok(()) => {
                        self.cpu.pc = next_pc + INSTRUCTION;
                        Ok(())
                    }
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
                self.cpu.pc = next_pc;
                let word = self.word(index, next_pc)?;
                self.pointer_authentication(word)
            }
            Ok(ExitKind::Amx) => {
                self.cpu.pc = next_pc;
                let word = self.word(index, next_pc)?;
                self.amx(word)
            }
            _ => Err(self.unsupported(RequirementKind::Native("unknown block exit kind"))),
        }
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

    /// The guest's PAC keys and the current regime's TCR layout, as
    /// FEAT_PAuth2 with FEAT_FPAC.
    fn pointer_context(&self) -> pauth::Context {
        let keys = self.pointer_keys();
        pauth::Context::new_with_version(
            0,
            pauth::Keys::from_words(keys[0], keys[1], keys[2], keys[3]).with_generic_words(keys[4]),
            pauth::Version::Faulting,
        )
        .with_translation_regime(self.cpu.controls(self.cpu.regime()).tcr)
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
        // The profile has no FEAT_PAuth_LR: its hint-space form (PACM) is a
        // NOP and the others are UNDEFINED.
        if let PointerAuthenticationOperation::LinkRegister(_) = instruction.operation {
            return if word & 0xffff_f01f == 0xd503_201f {
                self.next()
            } else {
                self.undefined()
            };
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
        let context = self.pointer_context();
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

    /// With the key's SCTLR enable clear, AddPAC and Auth return the pointer
    /// unchanged (Arm ARM `AddPAC`, `Auth`).
    fn disabled_pointer_authentication(
        &mut self,
        word: u32,
        instruction: PointerAuthentication,
    ) -> Step {
        use PointerAuthenticationOperation as Operation;
        let next = instruction.next_pc.0;
        match instruction.operation {
            Operation::Sign1716 { .. }
            | Operation::Authenticate1716 { .. }
            | Operation::SignIbSp
            | Operation::AuthenticateIbSp
            | Operation::Sign { .. }
            | Operation::Authenticate { .. } => self.cpu.pc = next,
            Operation::ReturnIbSp | Operation::ReturnIaSp => self.cpu.pc = self.cpu.state.x[30],
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
            Fault(mmu::Fault),
            Unsupported(mmu::Unsupported),
            Device(u64),
        }
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
                if !host.read_ram(translation.physical, &mut bytes) {
                    return Err(LoadStop::Device(translation.physical));
                }
                Ok(u64::from_le_bytes(bytes))
            },
        );
        match result {
            Ok(_) => {
                self.cpu.pc = pc + INSTRUCTION;
                Ok(())
            }
            Err(pauth::memory::Fault::Read {
                address,
                error: LoadStop::Fault(fault),
            }) => self.data_abort(address, fault, false, false),
            Err(pauth::memory::Fault::Read {
                error: LoadStop::Unsupported(unsupported),
                ..
            }) => Err(self.unsupported(RequirementKind::Translation(unsupported))),
            Err(pauth::memory::Fault::StackAlignment { .. }) => {
                self.take(Exception::synchronous(Class::SpAlignment, 0, pc));
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
        self.cpu.pc = pc;
        match fault.cause {
            FaultCause::Guest(guest) => {
                let class = if self.cpu.route() > self.cpu.pstate.el {
                    Class::DataAbortLower
                } else {
                    Class::DataAbortSame
                };
                let mut exception = Exception::synchronous(
                    class,
                    data_abort_iss(guest.status_code(), fault.write),
                    pc,
                );
                exception.fault_address = Some(fault.address);
                self.take(exception);
                Ok(())
            }
            FaultCause::Device { physical } => {
                let word = self.word(index, pc)?;
                self.device_access(word, fault.address, physical, fault.write)
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
            // with the check (SCTLR_ELx.SA or SA0 set), and for an LSE2
            // atomic access crossing its 16-byte granule.
            FaultCause::InvalidOpcode => {
                let word = self.word(index, pc)?;
                if self.blocks[index].stack_check
                    && stack_based(word)
                    && !self.cpu.state.sp.is_multiple_of(16)
                {
                    self.take(Exception::synchronous(Class::SpAlignment, 0, pc));
                    Ok(())
                } else {
                    Err(self.unsupported(RequirementKind::Native(
                        "alignment fault of an atomic access crossing its 16-byte granule",
                    )))
                }
            }
        }
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
            let raw = match self.devices.read(physical, bytes, now) {
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
            match self.devices.write(physical, bytes, value, now) {
                Ok(()) => {}
                Err(DeviceError::NoDevice) => return Err(refuse(self, "no device model".into())),
                Err(DeviceError::Refused(detail)) => return Err(refuse(self, detail)),
            }
            if let Some((base, updated)) = writeback {
                self.write_register(base, updated);
            }
        } else {
            return Err(refuse(
                self,
                "device access by other than a single-register scalar integer transfer".into(),
            ));
        }
        self.cpu.pc = pc + INSTRUCTION;
        match self.devices.take_reset() {
            Some(reason) => Err(Stop::Reset(reason)),
            None => Ok(()),
        }
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

    fn next(&mut self) -> Step {
        self.cpu.pc += INSTRUCTION;
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
                // The profile has no FEAT_XS.
                Synchronization::DataCompletion { nxs: true, .. } => self.undefined(),
                Synchronization::ErrorSynchronization => self.error_synchronization(),
                Synchronization::DataCompletion { .. }
                | Synchronization::StoreBypassBarrier { .. }
                | Synchronization::BranchTarget { .. }
                | Synchronization::TraceSynchronization
                | Synchronization::OtherHint { .. }
                | Synchronization::Yield
                | Synchronization::ConsumptionBarrier
                | Synchronization::SpeculationBarrier => {
                    // One coherent PE without external observers: completion
                    // and hints have no further effect.
                    self.next()
                }
                Synchronization::SendEvent { .. } | Synchronization::Wait { .. } => {
                    Err(self.refuse_system(word, "unexpected synchronization family"))
                }
                Synchronization::InstructionSynchronization { .. } => self.next(),
            },
            SystemOperation::SendEvent { .. } => {
                self.cpu.event = true;
                self.next()
            }
            SystemOperation::Wait {
                kind,
                timeout_register,
            } => self.wait(word, kind, timeout_register),
            // No halting debug: Debug-state-only instructions are UNDEFINED.
            SystemOperation::TagMemory(_) | SystemOperation::DebugStateOnly(_) => self.undefined(),
            SystemOperation::Guarded(GuardedOperation::Enter) => {
                if self.cpu.guarded_enter().is_err() {
                    return self.undefined();
                }
                self.host.report(&Event::Guarded {
                    entered: true,
                    pc: self.cpu.pc,
                });
                self.sync_regime();
                Ok(())
            }
            SystemOperation::Guarded(GuardedOperation::Exit) => match self.cpu.guarded_exit() {
                Err(_) => self.undefined(),
                Ok(Err(reason)) => Err(self.unsupported(RequirementKind::IllegalReturn(reason))),
                Ok(Ok(())) => {
                    self.host.report(&Event::Guarded {
                        entered: self.cpu.pstate.guarded,
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
                self.take(Exception::synchronous(
                    Class::SupervisorCall,
                    u32::from(immediate),
                    pc + INSTRUCTION,
                ));
                Ok(())
            }
            ExceptionOperation::SoftwareBreakpoint { immediate } => {
                self.take(Exception::synchronous(
                    Class::Breakpoint,
                    u32::from(immediate),
                    pc,
                ));
                Ok(())
            }
            ExceptionOperation::ExceptionReturn { key } => self.exception_return(key),
            // HVC from EL1 and EL2 goes to EL2, unless HCR_EL2.HCD disables it.
            ExceptionOperation::HypervisorCall { immediate }
                if self.cpu.pstate.el != 0 && !self.cpu.hcr(HCR_HCD) =>
            {
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
        if self.fine_grained_trap(HFGITR_ERET) {
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
                // A combined authentication: a failure corrupts the pointer
                // because the profile has no FEAT_FPACCOMBINE.
                match self.pointer_context().authenticate_operation(
                    runtime_key,
                    target,
                    self.cpu.state.sp,
                    true,
                ) {
                    Ok(result) => target = result.pointer,
                    Err(_) => {
                        return Err(self.unsupported(RequirementKind::Native(
                            "ERETAA/ERETAB authentication without its key",
                        )));
                    }
                }
            }
        }
        self.cpu.exception_return(target);
        self.host.report(&Event::Return {
            to_el: self.cpu.pstate.el,
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
    /// Otherwise SCTLR_ELx.nTWI/nTWE trap them from EL0 to EL1, or to EL2 in
    /// the host, and HCR_EL2.TWI/TWE trap them from EL0 and EL1 outside the
    /// host to EL2. Without FEAT_WFxT the timeout forms are UNDEFINED.
    fn wait(&mut self, _word: u32, kind: WaitKind, timeout: Option<u8>) -> Step {
        const HCR_TWI: u32 = 13;
        const HCR_TWE: u32 = 14;
        if timeout.is_some() {
            return self.undefined();
        }
        let el = self.cpu.pstate.el;
        let sctlr = self.cpu.controls(self.cpu.regime()).sctlr;
        let (enable_bit, hcr_trap, trap_iss) = match kind {
            WaitKind::Interrupt => (1u64 << 16, HCR_TWI, 0),
            WaitKind::Event => (1u64 << 18, HCR_TWE, 1),
        };
        let iss = TRAPPED_AARCH64 | trap_iss;
        match kind {
            WaitKind::Event if self.cpu.event => {
                self.cpu.event = false;
                return self.next();
            }
            WaitKind::Interrupt if self.interrupt_pending() => return self.next(),
            _ => {}
        }
        if el == 0 && sctlr & enable_bit == 0 {
            self.take(Exception::synchronous(Class::WaitTrap, iss, self.cpu.pc));
            return Ok(());
        }
        if el != 2 && !self.cpu.in_host() && self.cpu.hcr(hcr_trap) {
            self.take(Exception::synchronous(Class::WaitTrap, iss, self.cpu.pc).to(2));
            return Ok(());
        }
        while !self.interrupt_pending() {
            let now = self.host.counter();
            let deadline = match (self.timer_deadline(), self.devices.deadline(now)) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            if deadline.is_none() {
                return Err(Stop::Idle);
            }
            self.statistics.waits += 1;
            self.host.arm_timer(deadline);
            self.host.wait_for_interrupt();
        }
        self.host.arm_timer(None);
        self.next()
    }

    /// Arm `AArch64_InterruptPending`: a physical IRQ or FIQ line, or at EL0
    /// and EL1 outside the host a virtual IRQ, FIQ or SError that
    /// HCR_EL2.{IMO,FMO,AMO} route and {VI,VF,VSE} hold, masked or not.
    fn interrupt_pending(&mut self) -> bool {
        let lines = self.lines();
        if lines.irq || lines.fiq {
            return true;
        }
        let hcr = self.cpu.read(SystemRegister::HCR_EL2);
        let routed = |routing: u32, pending: u32| {
            hcr & (1 << routing | 1 << pending) == 1 << routing | 1 << pending
        };
        self.cpu.pstate.el != 2
            && hcr & (1 << HCR_TGE) == 0
            && (routed(HCR_IMO, HCR_VI) || routed(HCR_FMO, HCR_VF) || routed(HCR_AMO, HCR_VSE))
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
        &self,
        address: u64,
        fault: mmu::Fault,
        write: bool,
        cache: bool,
    ) -> Exception {
        let class = if self.cpu.route() > self.cpu.pstate.el {
            Class::DataAbortLower
        } else {
            Class::DataAbortSame
        };
        let iss = data_abort_iss(fault.status_code(), write) | if cache { 1 << 8 } else { 0 };
        let mut exception = Exception::synchronous(class, iss, self.cpu.pc);
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
        ram: Vec<u8>,
        base: u64,
        pub(super) now: u64,
        regimes: Vec<Regime>,
        invalidations: usize,
        installed: Vec<Vec<u8>>,
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
            let offset = (physical - self.base) as usize;
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
            unreachable!("unit tests do not run native code")
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

    pub(super) fn machine(words: &[u32]) -> Machine<FakeHost, NoDevices> {
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
        };
        let profile = CpuProfile {
            name: "test",
            counter_frequency: 24_000_000,
            fixed: vec![(registers::encodings::DCZID_EL0, 4)],
        };
        Machine::new(
            Cpu::new(BASE, Pstate::reset(1)),
            host,
            NoDevices,
            profile,
            TargetCpu::Baseline,
        )
    }

    #[test]
    fn compiles_blocks_through_the_page_and_reports_unsupported_words() {
        // add x0, x0, #1; svc #0
        let mut machine = machine(&[0x9100_0400, 0xd400_0001]);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE) else {
            panic!("block")
        };
        assert_eq!(machine.blocks[index].source_map.len(), 2);
        assert_eq!(machine.statistics.compiled, 1);
        assert!(matches!(machine.fetch_block(BASE), Ok(Fetched::Block(i)) if i == index));
        assert_eq!(machine.statistics.compiled, 1, "cached");
        // An exclusive load is refused at its own PC with its word.
        let mut machine = machine_with(&[0x9100_0400, 0xc85f_7c20]);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE) else {
            panic!("prefix block")
        };
        assert_eq!(machine.blocks[index].source_map.len(), 1);
        let Err(Stop::Unsupported(requirement)) = machine.fetch_block(BASE + 4) else {
            panic!("refusal")
        };
        assert_eq!(requirement.pc, BASE + 4);
        assert!(matches!(
            requirement.kind,
            RequirementKind::Instruction {
                word: 0xc85f_7c20,
                ..
            }
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
        let Ok(Fetched::Block(checked)) = machine.fetch_block(BASE) else {
            panic!("checked block")
        };
        assert!(machine.blocks[checked].stack_check && has_check(&machine, checked));
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, sctlr & !(1 << 3));
        machine.derived_changed();
        let Ok(Fetched::Block(unchecked)) = machine.fetch_block(BASE) else {
            panic!("unchecked block")
        };
        assert_ne!(checked, unchecked);
        assert!(!machine.blocks[unchecked].stack_check && !has_check(&machine, unchecked));
        assert!(stack_based(0xf940_07e0) && !stack_based(0xf940_0020));
        assert!(!stack_based(0x5800_003f), "a literal load has no base");
    }

    impl Machine<FakeHost, NoDevices> {
        fn system_instruction_for_test(&mut self, word: u32) {
            self.pointer_authentication(word).unwrap();
        }
    }

    fn machine_with(words: &[u32]) -> Machine<FakeHost, NoDevices> {
        machine(words)
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
    fn tlbi_invalidates_and_wfi_waits_for_the_virtual_timer() {
        let mut machine = machine(&[]);
        machine.system_instruction(0xd508_871f).unwrap(); // tlbi vmalle1
        assert_eq!(machine.host.invalidations, 1);
        // Arm the virtual timer 1500 ticks ahead and wait.
        machine.cpu.state.x[0] = 1500;
        machine.system_instruction(0xd51b_e300).unwrap(); // msr cntv_tval_el0, x0
        machine.cpu.state.x[0] = 1;
        machine.system_instruction(0xd51b_e320).unwrap(); // msr cntv_ctl_el0, x0
        machine.system_instruction(0xd503_207f).unwrap(); // wfi
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
        assert_eq!(machine.system_instruction(0xd503_207f), Err(Stop::Idle));
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
        let mut machine = machine(&[]);
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
        machine
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
        // A different modifier fails a standalone AUT: EC 0x1C, ISS {data=0,
        // key B=1}, at the instruction, to the current EL.
        machine.cpu.state.sp += 16;
        let pc = machine.cpu.pc;
        machine.system_instruction_for_test(AUTIBSP);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x7200_0001);
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
        assert_eq!(
            (machine.cpu.pc, machine.cpu.state.x[30]),
            (0x1_0200, signed)
        );
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
        // faulting (no FEAT_FPACCOMBINE).
        machine.cpu.state.sp += 16;
        machine.system_instruction(ERETAA).unwrap();
        assert_ne!(machine.cpu.pc, target);
        assert_eq!(machine.cpu.pc & 0x7f_ffff_ffff, target & 0x7f_ffff_ffff);
        // HCR_EL2.API clear traps the enabled key's use to EL2.
        machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, 0);
        machine.system_instruction(ERETAA).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL2), 0x2600_0000);
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
        assert_eq!(machine.cpu.state.x[1], 0x07c8_0000);
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
        // DSB nXS is UNDEFINED without FEAT_XS; PACM (FEAT_PAuth_LR) is a NOP.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.system_instruction(0xd503_323f).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.system_instruction_for_test(0xd503_24ff);
        assert_eq!(machine.cpu.pc, BASE + 4);
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
