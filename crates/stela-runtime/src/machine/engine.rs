//! The dispatch loop: fetch translation, block cache, native execution and
//! every exit back from native code.
use super::{
    cpu::{Cpu, Exception, HCR_FMO, HCR_HCD, HCR_IMO, HCR_TGE},
    exception::{Class, DAIF_F, DAIF_I, IllegalReturn, Vector, data_abort_iss},
    mmu::{self, Access, Controls, Outcome as Translated},
    registers::{self, CpuProfile, Environment, Lines, Outcome as RegisterOutcome, Refusal},
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
            exception::Operation as ExceptionOperation,
            registers::{Direction, Encoding, RegisterAccess},
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
    generation: u64,
    block: usize,
}

/// Floating-point and SIMD instructions, which CPACR_EL1.FPEN can trap:
/// SIMD&FP data processing (op0 x111) and SIMD&FP loads/stores (op0 x1x0, V=1).
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
    index: BTreeMap<(u64, u64, bool), usize>,
    fetch: Vec<Option<FetchEntry>>,
    jump: Vec<Option<JumpEntry>>,
    /// Advances when cached fetch translations become stale.
    translation_generation: u64,
    /// Advances when installed code is discarded.
    code_generation: u64,
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
        };
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

    fn sync_regime(&mut self) {
        let regime = Regime {
            controls: self.cpu.system.translation,
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
        let system = &self.cpu.system;
        let timer = system.virtual_timer.asserted(now) || system.physical_timer.asserted(now);
        let device = self.devices.lines(now);
        Lines {
            irq: device.irq,
            // Apple cores signal the generic timers as FIQ.
            fiq: device.fiq || timer,
        }
    }

    /// Take a pending, unmasked interrupt before the next instruction.
    fn deliver_interrupts(&mut self) -> bool {
        let lines = self.lines();
        let daif = self.cpu.pstate.daif;
        // An EL2 kernel takes physical interrupts only while they route to
        // EL2: with HCR_EL2.TGE, or with FMO/IMO for FIQ/IRQ. Otherwise they
        // route to EL1, which is not entered from EL2 (Arm ARM D1.3.5).
        let hcr = self.cpu.system.hcr;
        let routed = |bit: u64| self.cpu.kernel_el == 1 || hcr & (HCR_TGE | bit) != 0;
        let vector = if lines.fiq && daif & DAIF_F == 0 && routed(HCR_FMO) {
            Vector::Fiq
        } else if lines.irq && daif & DAIF_I == 0 && routed(HCR_IMO) {
            Vector::Irq
        } else {
            return false;
        };
        self.statistics.interrupts += 1;
        self.take(Exception {
            vector,
            syndrome: 0,
            fault_address: None,
            return_address: self.cpu.pc,
        });
        true
    }

    fn timer_deadline(&self) -> Option<u64> {
        let system = &self.cpu.system;
        match (
            system.virtual_timer.deadline(),
            system.physical_timer.deadline(),
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
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
        let controls = self.cpu.system.translation;
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
                let class = if requester.el == 0 {
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

    fn floating_point_enabled(&self) -> bool {
        match (self.cpu.system.cpacr >> 20) & 3 {
            0b11 => true,
            0b01 => self.cpu.pstate.el != 0,
            _ => false,
        }
    }

    fn fetch_block(&mut self, pc: u64) -> Result<Fetched, Stop> {
        let physical = match self.fetch_physical(pc) {
            Ok(physical) => physical,
            Err(Ok(exception)) => return Ok(Fetched::Exception(exception)),
            Err(Err(stop)) => return Err(stop),
        };
        let fp = self.floating_point_enabled();
        let slot = (pc / INSTRUCTION) as usize % JUMP_CACHE;
        if let Some(entry) = self.jump[slot]
            && entry.pc == pc
            && entry.physical == physical
            && entry.fp == fp
            && entry.generation == self.code_generation
        {
            return Ok(Fetched::Block(entry.block));
        }
        let index = match self.index.get(&(pc, physical, fp)) {
            Some(&index) => index,
            None => match self.compile(pc, physical, fp)? {
                Some(index) => index,
                None => {
                    // The first instruction is FP/SIMD while CPACR traps it.
                    return Ok(Fetched::Exception(Exception::synchronous(
                        Class::FloatingPointAccess,
                        TRAPPED_AARCH64,
                        pc,
                    )));
                }
            },
        };
        self.jump[slot] = Some(JumpEntry {
            pc,
            physical,
            fp,
            generation: self.code_generation,
            block: index,
        });
        Ok(Fetched::Block(index))
    }

    /// Compile the block at `pc`. `None` when its first instruction is a
    /// trapped FP/SIMD instruction.
    fn compile(&mut self, pc: u64, physical: u64, fp: bool) -> Result<Option<usize>, Stop> {
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
        let compiled = self.compile_prefix(&source[..consumed], pc)?;
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
        });
        let index = self.blocks.len() - 1;
        self.index.insert((pc, physical, fp), index);
        Ok(Some(index))
    }

    /// Compile the longest prefix the host target can emit.
    fn compile_prefix(
        &self,
        source: &[u8],
        pc: u64,
    ) -> Result<stela_compiler::block::CompiledBlock, Stop> {
        let attempt = |bytes: &[u8]| {
            CompilationPlan::new(bytes, GuestAddress(pc), PROFILE, self.target)
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
            _ => Err(self.unsupported(RequirementKind::Native("unknown block exit kind"))),
        }
    }

    /// Whether SCTLR_EL1 enables a PAC key (EnIA 31, EnIB 30, EnDA 27, EnDB 13).
    fn key_enabled(&self, key: PointerAuthenticationKey) -> bool {
        let bit = match key {
            PointerAuthenticationKey::Ia => 31,
            PointerAuthenticationKey::Ib => 30,
            PointerAuthenticationKey::Da => 27,
            PointerAuthenticationKey::Db => 13,
        };
        self.cpu.system.translation.sctlr & (1 << bit) != 0
    }

    /// Complete one PAC instruction with the guest's own keys, laid out for
    /// the current TCR_EL1. The algorithm is the software QARMA5 service in
    /// its Classic (PAuth1) policy; Apple's hardware algorithm and AppleMode
    /// diversification are not reproduced, so values are self-consistent
    /// rather than equal to hardware's.
    fn pointer_authentication(&mut self, word: u32) -> Step {
        let pc = self.cpu.pc;
        let refuse = |machine: &Self, detail: String| {
            Err(machine.unsupported(RequirementKind::Instruction { word, detail }))
        };
        let instruction = match block::decode_pointer_authentication(GuestAddress(pc), word) {
            Ok(Some(instruction)) => instruction,
            _ => return refuse(self, "PAC exit at a word that is not PAC".into()),
        };
        if let Some(key) = instruction.operation.required_key()
            && !self.key_enabled(key)
        {
            return self.disabled_pointer_authentication(word, instruction);
        }
        let keys = &self.cpu.system.keys;
        let context = pauth::Context::new(
            0,
            pauth::Keys::from_words(keys[0], keys[1], keys[2], keys[3]).with_generic_words(keys[4]),
        )
        .with_translation_regime(self.cpu.system.translation.tcr);
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
            Err(error) => refuse(self, format!("{error:#}")),
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
        let controls = self.cpu.system.translation;
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
                let class = if self.cpu.pstate.el == 0 {
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
            FaultCause::InvalidOpcode => {
                let sctlr = self.cpu.system.translation.sctlr;
                let checked = if self.cpu.pstate.el == 0 {
                    sctlr & (1 << 4) != 0
                } else {
                    sctlr & (1 << 3) != 0
                };
                if checked {
                    self.take(Exception::synchronous(Class::SpAlignment, 0, pc));
                    Ok(())
                } else {
                    Err(self.unsupported(RequirementKind::Native(
                        "misaligned SP with SCTLR_EL1.SA/SA0 clear",
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
        let class = if self.cpu.pstate.el == 0 {
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
            SystemOperation::Exception(operation) => self.exception_instruction(word, operation),
            SystemOperation::Register(access) => self.register_instruction(word, access),
            SystemOperation::PstateImmediate(encoding) => {
                let outcome = self.cpu.write_pstate_field(encoding);
                self.register_outcome(word, None, outcome)
            }
            SystemOperation::Maintenance(access) => self.maintenance(word, access),
            SystemOperation::InstructionSynchronization { .. } => self.next(),
            SystemOperation::Synchronization(operation) => match operation {
                Synchronization::DataCompletion { nxs: true, .. } => {
                    Err(self.refuse_system(word, "DSB nXS needs FEAT_XS in the CPU profile"))
                }
                Synchronization::DataCompletion { .. }
                | Synchronization::StoreBypassBarrier { .. }
                | Synchronization::BranchTarget { .. }
                | Synchronization::ErrorSynchronization
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
                self.cpu.system.event = true;
                self.next()
            }
            SystemOperation::Wait {
                kind,
                timeout_register,
            } => self.wait(word, kind, timeout_register),
            SystemOperation::TagMemory(_) => self.undefined(),
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

    fn exception_instruction(&mut self, word: u32, operation: ExceptionOperation) -> Step {
        let pc = self.cpu.pc;
        match operation {
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
            ExceptionOperation::ExceptionReturn { key: None } => {
                if self.cpu.pstate.el == 0 {
                    return self.undefined();
                }
                if let Err(reason) = self.cpu.exception_return() {
                    return Err(self.unsupported(RequirementKind::IllegalReturn(reason)));
                }
                self.host.report(&Event::Return {
                    to_el: self.cpu.pstate.el,
                    pc: self.cpu.pc,
                });
                self.sync_regime();
                Ok(())
            }
            ExceptionOperation::ExceptionReturn { key: Some(_) } => Err(self.refuse_system(
                word,
                "ERETAA/ERETAB need pointer authentication in the system engine",
            )),
            // HVC at an EL2 kernel, unless HCR_EL2.HCD disables it.
            ExceptionOperation::HypervisorCall { immediate }
                if self.cpu.pstate.el == 2 && self.cpu.system.hcr & HCR_HCD == 0 =>
            {
                self.take(Exception::synchronous(
                    Class::HypervisorCall,
                    u32::from(immediate),
                    pc + INSTRUCTION,
                ));
                Ok(())
            }
            // No EL3, debug state or halting, and HVC elsewhere: all UNDEFINED.
            ExceptionOperation::HypervisorCall { .. }
            | ExceptionOperation::SecureMonitorCall { .. }
            | ExceptionOperation::Halt { .. }
            | ExceptionOperation::DebugChange { .. }
            | ExceptionOperation::DebugReturn
            | ExceptionOperation::Undefined { .. } => self.undefined(),
        }
    }

    fn register_instruction(&mut self, word: u32, access: RegisterAccess) -> Step {
        use registers::encodings::{FPCR, FPSR};
        let encoding = access.encoding();
        if matches!(encoding, FPCR | FPSR) && !self.floating_point_enabled() {
            self.take(Exception::synchronous(
                Class::FloatingPointAccess,
                TRAPPED_AARCH64,
                self.cpu.pc,
            ));
            return Ok(());
        }
        let now = self.host.counter();
        let lines = self.lines();
        let environment = Environment {
            profile: &self.profile,
            now,
            lines,
        };
        let outcome = self.cpu.access_register(access, &environment);
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
            RegisterOutcome::Trapped => {
                let iss = access.map_or(0, registers::trap_iss);
                self.take(Exception::synchronous(
                    Class::SystemRegister,
                    iss,
                    self.cpu.pc,
                ));
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

    fn wait(&mut self, word: u32, kind: WaitKind, timeout: Option<u8>) -> Step {
        if timeout.is_some() {
            return Err(self.refuse_system(word, "WFET/WFIT need FEAT_WFxT in the CPU profile"));
        }
        let sctlr = self.cpu.system.translation.sctlr;
        let (enable_bit, trap_iss) = match kind {
            WaitKind::Interrupt => (1u64 << 16, 0),
            WaitKind::Event => (1u64 << 18, 1),
        };
        if self.cpu.pstate.el == 0 && sctlr & enable_bit == 0 {
            let iss = TRAPPED_AARCH64 | trap_iss;
            self.take(Exception::synchronous(Class::WaitTrap, iss, self.cpu.pc));
            return Ok(());
        }
        if kind == WaitKind::Event && self.cpu.system.event {
            self.cpu.system.event = false;
            return self.next();
        }
        loop {
            let lines = self.lines();
            if lines.irq || lines.fiq {
                break;
            }
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

    fn maintenance(&mut self, word: u32, access: RegisterAccess) -> Step {
        let encoding = access.encoding();
        let el = self.cpu.pstate.el;
        let operand = if access.rt() == 31 {
            0
        } else {
            self.cpu.state.x[usize::from(access.rt())]
        };
        if access.direction() == Direction::Read {
            return Err(self.refuse_system(word, "SYSL has no implemented operation"));
        }
        let sctlr = self.cpu.system.translation.sctlr;
        let uci = sctlr & (1 << 26) != 0;
        match (
            encoding.op1(),
            encoding.crn(),
            encoding.crm(),
            encoding.op2(),
        ) {
            // TLBI at the kernel level (op1=0, CRn=8 or 9), and the EL2 forms
            // (op1=4) at an EL2 kernel. Every form discards all shadow
            // translations, a superset of what it requires. EL3 forms do not
            // exist.
            (0, 8 | 9, _, _) | (4, 8 | 9, _, _) => {
                if el == 0 || encoding.op1() == 4 && el != 2 {
                    return self.undefined();
                }
                self.translations_changed();
                self.next()
            }
            // IC IALLUIS, IC IALLU.
            (0, 7, 1 | 5, 0) => {
                if el == 0 {
                    return self.undefined();
                }
                self.discard_code();
                self.next()
            }
            // IC IVAU.
            (3, 7, 5, 1) => {
                if el == 0 && !uci {
                    return self.trap_system(access);
                }
                self.discard_code();
                self.next()
            }
            // DC ZVA.
            (3, 7, 4, 1) => {
                if !self.cpu.zva_permitted() {
                    return self.trap_system(access);
                }
                self.zero_block(word, operand)
            }
            // DC CVAC, CVAU, CIVAC, CVAP, CVADP: clean by VA; IVAC: invalidate.
            (3, 7, 10..=14, 1) | (0, 7, 6, 1) => {
                if el == 0 && !uci {
                    return self.trap_system(access);
                }
                if el == 0 && encoding.op1() == 0 {
                    return self.undefined();
                }
                let write = encoding.op1() == 0;
                self.cache_maintenance(operand, write)
            }
            // DC ISW, CSW, CISW: set/way at EL1 only.
            (0, 7, 6 | 10 | 14, 2) => {
                if el == 0 {
                    return self.undefined();
                }
                self.next()
            }
            // AT S1E1R/W, S1E0R/W, S1E1RP/WP.
            (0, 7, 8 | 9, 0..=3) => {
                if el == 0 {
                    return self.undefined();
                }
                self.address_translation(encoding, operand)
            }
            // AT S1E2R/W at an EL2 kernel: the EL2&0 regime, like S1E1R/W
            // there under E2H.
            (4, 7, 8, 0 | 1) => {
                if el != 2 {
                    return self.undefined();
                }
                let privileged = Encoding::new(1, 0, 7, 8, encoding.op2());
                self.address_translation(privileged, operand)
            }
            _ => Err(self.refuse_system(word, "SYS operation without a model")),
        }
    }

    fn trap_system(&mut self, access: RegisterAccess) -> Step {
        self.take(Exception::synchronous(
            Class::SystemRegister,
            registers::trap_iss(access),
            self.cpu.pc,
        ));
        Ok(())
    }

    fn translate_data(&mut self, address: u64, access: Access) -> Translated {
        let controls = self.cpu.system.translation;
        let requester = self.cpu.requester();
        mmu::translate(
            &controls,
            address,
            access,
            requester,
            &mut RamTables(&mut self.host),
        )
    }

    fn data_abort(&mut self, address: u64, fault: mmu::Fault, write: bool, cache: bool) -> Step {
        let class = if self.cpu.pstate.el == 0 {
            Class::DataAbortLower
        } else {
            Class::DataAbortSame
        };
        let iss = data_abort_iss(fault.status_code(), write) | if cache { 1 << 8 } else { 0 };
        let mut exception = Exception::synchronous(class, iss, self.cpu.pc);
        exception.fault_address = Some(address);
        self.take(exception);
        Ok(())
    }

    fn cache_maintenance(&mut self, address: u64, write: bool) -> Step {
        let access = if write { Access::Write } else { Access::Read };
        match self.translate_data(address, access) {
            Translated::Mapped(_) => self.next(),
            Translated::Fault(fault) => self.data_abort(address, fault, write, true),
            Translated::Unsupported(unsupported) => {
                Err(self.unsupported(RequirementKind::Translation(unsupported)))
            }
        }
    }

    fn zero_block(&mut self, word: u32, address: u64) -> Step {
        use registers::encodings::DCZID_EL0;
        let Some(dczid) = self
            .profile
            .fixed
            .iter()
            .find(|(e, _)| *e == DCZID_EL0)
            .map(|e| e.1)
        else {
            return Err(self.refuse_system(word, "DC ZVA without a profile DCZID_EL0"));
        };
        if dczid & 0x10 != 0 {
            return self.undefined();
        }
        let bytes = 4u64 << (dczid & 0xf);
        let start = address & !(bytes - 1);
        match self.translate_data(start, Access::Write) {
            Translated::Mapped(translation) => {
                let zero = vec![0u8; bytes as usize];
                if !self.host.write_ram(translation.physical, &zero) {
                    let physical = translation.physical;
                    return Err(self.unsupported(RequirementKind::Device {
                        physical,
                        write: true,
                        detail: "DC ZVA outside RAM".into(),
                    }));
                }
                self.next()
            }
            Translated::Fault(fault) => self.data_abort(address, fault, true, false),
            Translated::Unsupported(unsupported) => {
                Err(self.unsupported(RequirementKind::Translation(unsupported)))
            }
        }
    }

    fn address_translation(&mut self, encoding: Encoding, address: u64) -> Step {
        let op2 = encoding.op2();
        let write = op2 & 1 != 0;
        let mut requester = self.cpu.requester();
        if encoding.crm() == 8 && op2 >= 2 {
            requester.unprivileged = true;
        }
        if encoding.crm() == 8 && op2 < 2 {
            requester.pan = false;
        }
        let controls = self.cpu.system.translation;
        let access = if write { Access::Write } else { Access::Read };
        let outcome = mmu::translate(
            &controls,
            address,
            access,
            requester,
            &mut RamTables(&mut self.host),
        );
        self.cpu.system.par = match outcome {
            Translated::Mapped(translation) => {
                let attribute = match translation.memory {
                    mmu::MemoryType::Device => 0x00,
                    mmu::MemoryType::Normal => 0xff,
                };
                (attribute << 56) | (translation.physical & 0x0000_ffff_ffff_f000) | (0b11 << 7)
            }
            Translated::Fault(fault) => 1 | (u64::from(fault.status_code()) << 1),
            Translated::Unsupported(unsupported) => {
                return Err(self.unsupported(RequirementKind::Translation(unsupported)));
            }
        };
        self.next()
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

    struct FakeHost {
        ram: Vec<u8>,
        base: u64,
        now: u64,
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

    const BASE: u64 = 0x8_0000_0000;

    fn machine(words: &[u32]) -> Machine<FakeHost, NoDevices> {
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
            Cpu::new(BASE, Pstate::RESET_EL1),
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
        machine.cpu.system.vbar = 0xffff_0000_0000_0000;
        // msr vbar_el1, x1 then svc #0x42, both at EL1h.
        machine.cpu.state.x[1] = 0x1_0000;
        machine.system_instruction(0xd518_c001).unwrap();
        assert_eq!(machine.cpu.system.vbar, 0x1_0000);
        machine.system_instruction(0xd400_0841).unwrap();
        assert_eq!(machine.cpu.pc, 0x1_0200);
        assert_eq!(machine.cpu.system.elr, BASE + 8);
        assert_eq!(machine.cpu.system.esr, 0x5600_0042);
        // ERET to EL0t at ELR.
        machine.cpu.system.spsr = 0;
        machine.system_instruction(0xd69f_03e0).unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.pstate.el), (BASE + 8, 0));
        assert_eq!(machine.host.regimes.last().unwrap().requester.el, 0);
        // EL0 cannot read TPIDR_EL1: UNDEFINED to the lower-EL group.
        machine.system_instruction(0xd538_d080).unwrap();
        assert_eq!(machine.cpu.pc, 0x1_0400);
        assert_eq!(machine.cpu.system.esr, 0x0200_0000);
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
        assert_eq!(machine.cpu.system.elr, pc);
        assert_eq!(machine.cpu.pc, 0x300);
        // With no timer armed, WFI is a terminal idle state.
        machine.cpu.system.virtual_timer.write_control(0);
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
        assert_eq!(machine.cpu.system.par & 0x0000_ffff_ffff_f000, BASE);
        assert_eq!(machine.cpu.system.par & 1, 0);
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
        assert_eq!(machine.cpu.system.esr, 0x0200_0000);
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
        assert_eq!(machine.cpu.system.guarded.elr, genter_pc + 4);
        assert_eq!(machine.cpu.system.guarded.aspsr, 0);
        assert!(machine.host.regimes.last().unwrap().requester.guarded);
        // A fresh GL1 stack; EL1's is banked.
        assert_eq!(
            (machine.cpu.state.sp, machine.cpu.system.sp_el1),
            (0, 0x7000)
        );
        machine.cpu.state.sp = 0x8000;
        machine.system_instruction(0xd51e_fa42).unwrap(); // msr VBAR_GL1, x2
        machine.system_instruction(0xd53e_f803).unwrap(); // mrs x3, GXF_STATUS_EL1
        assert_eq!(machine.cpu.state.x[3], 1);
        // An SVC at GL1 is taken at VBAR_GL1 and records a GL return.
        let svc_pc = machine.cpu.pc;
        let el1_elr = machine.cpu.system.elr;
        machine.system_instruction(0xd400_0001).unwrap();
        assert_eq!(machine.cpu.pc, 0xa200);
        assert_eq!(machine.cpu.system.guarded.elr, svc_pc + 4);
        assert_eq!(machine.cpu.system.guarded.esr, 0x5600_0000);
        assert_eq!(machine.cpu.system.guarded.aspsr, 1);
        assert_eq!(machine.cpu.system.elr, el1_elr, "EL1's ELR is untouched");
        // GEXIT returns to GL1, then (with ASPSR clear) to EL1.
        machine.system_instruction(0x0020_1400).unwrap();
        assert!(machine.cpu.pstate.guarded);
        assert_eq!(machine.cpu.pc, svc_pc + 4);
        machine.cpu.system.guarded.aspsr = 0;
        machine.cpu.system.guarded.elr = genter_pc + 4;
        machine.cpu.system.guarded.spsr = 0x3c5;
        machine.system_instruction(0x0020_1400).unwrap();
        assert!(!machine.cpu.pstate.guarded);
        assert_eq!(
            (machine.cpu.pc, machine.cpu.state.sp),
            (genter_pc + 4, 0x7000)
        );
        assert_eq!(machine.cpu.system.guarded.sp, 0x8000);
        // GEXIT outside GL is UNDEFINED; APSTS reports the master key ready.
        machine.system_instruction(0x0020_1400).unwrap();
        assert_eq!(machine.cpu.system.esr, 0x0200_0000);
        machine.cpu.pstate = Pstate::RESET_EL1;
        machine.system_instruction(0xd53e_fc85).unwrap(); // mrs x5, APSTS_EL1
        assert_eq!(machine.cpu.state.x[5], 1);
    }

    #[test]
    fn pac_uses_the_guest_keys_regime_layout_and_sctlr_enables() {
        const PACIBSP: u32 = 0xd503_237f;
        const AUTIBSP: u32 = 0xd503_23ff;
        let mut machine = machine(&[]);
        // 39-bit TTBR1 kernel addresses, no TBI.
        machine.cpu.system.translation.tcr = 25 << 16 | 25;
        machine.cpu.system.keys[1] = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let pointer = 0xffff_ff80_0000_4000_u64;
        machine.cpu.state.x[30] = pointer;
        machine.cpu.state.sp = 0xffff_ff80_0001_0000;
        // EnIB clear: PACIBSP leaves LR unchanged.
        machine.system_instruction_for_test(PACIBSP);
        assert_eq!(machine.cpu.state.x[30], pointer);
        machine.cpu.system.translation.sctlr |= 1 << 30;
        machine.system_instruction_for_test(PACIBSP);
        let signed = machine.cpu.state.x[30];
        assert_ne!(signed, pointer);
        assert_eq!(
            signed & 0x0000_007f_ffff_ffff,
            pointer & 0x0000_007f_ffff_ffff
        );
        machine.system_instruction_for_test(AUTIBSP);
        assert_eq!(machine.cpu.state.x[30], pointer);
        // A different SP modifier poisons bits 62:61 (instruction key B).
        machine.cpu.state.x[30] = signed;
        machine.cpu.state.sp += 16;
        machine.system_instruction_for_test(AUTIBSP);
        assert_eq!(machine.cpu.state.x[30] >> 61 & 3, 2);
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
