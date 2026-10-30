//! The dispatch loop: fetch translation, block cache, native execution and
//! every exit back from native code.
mod boundary;
mod mirrors;
mod reports;
use boundary::*;
pub use boundary::{ConsumedPair, DeviceError, Devices, Host, NoDevices, Start};
use mirrors::*;
use reports::*;
pub use reports::{
    Discard, Event, Occupancy, Requirement, RequirementKind, Reset, Statistics, Stop, Surveyed,
    Suspension, TRACE_HITS, TraceHit, WATCH_HITS, WatchHit,
};
mod amx;
mod apple_maintenance;
mod budget;
mod chain_control;
mod clock;
mod code_cache;
mod compilation;
mod compression;
mod data_access;
mod debugging;
mod degraded;
mod device_access;
mod device_read;
mod device_write;
mod exclusive;
mod fetch;
#[cfg(all(feature = "std", feature = "native-profile"))]
pub mod floating_profile;
mod guarded;
pub mod installed_code;
mod interrupts;
#[cfg(all(feature = "std", feature = "native-profile"))]
pub mod metrics;
mod monitor;
mod native_failure;
mod native_timing;
mod parallel;
mod pointer_authentication;
mod regime_state;
mod scheduler;
mod system_access;
mod timing;
pub use clock::ClockStatus;
pub use monitor::{MonitorEvent, MonitorKind, MonitorLocation};
pub use native_timing::{NativeInstructionSample, NativeTimingPhase, NativeTimingWork};
pub use parallel::{
    BroadcastCounts, BroadcastKind, BroadcastProfile, Call, Counts, Hub, Kick, MaterializedSource,
    ParallelAdmissionError, SharedDevices, SourceObservation, SourcePhase,
};
pub use stela_contracts::dma::{DmaError, TransferFault};
mod pointer;
mod prepare;
pub use device_read::{CanonicalDeviceMemory, ConsumedScalar, DeviceReadRequest, DeviceReadShape};
pub use device_write::{
    CanonicalDeviceWrite, CanonicalWriteMemory, ConsumedWrite, DeviceWriteRequest, DeviceWriteShape,
};
mod processors;
mod recovery;
mod scalable;
mod shared_memory;
pub mod step_timing;
mod stored;
mod system;
mod table;
mod tags;
mod unprivileged;
mod watch;
pub use budget::RunBudget;

use crate::{pauth, scalable::ScalableState};
use alloc::string::ToString;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::fmt;
#[cfg(test)]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use pointer::{PointerInputs, PointerOperation, PointerResult};
#[cfg(test)]
pub(crate) use prepare::test_preparation;
pub use prepare::{Description, Preparation, Prepared, Refused, window};
pub use processors::publication;
pub use processors::{
    PeerState, PreparedProcessorPower, ProcessorBinding, ProcessorChange, ProcessorPowerError,
    ProcessorWrite, Processors, SettledProcessorWrite,
};
pub use recovery::{NativeFailure, NativeFailureReason, SourceRecord, UnsettledChain};
pub use shared_memory::{
    HeldRamService, MAX_NATIVE_EPOCH_BODIES, NativeCohort, NativeEpochDeadline, NativeEpochEnd,
    NativeEpochStatistics, NativeRun, NativeRunIdentity, NativeRunObservation, NativeTransport,
    ReturnedRun, ServiceHost, ServiceTransport, SharedMemory, SharedMemoryFailure,
    SharedMemoryRefusal, dispatch_native_run, recover_native_run,
};
#[cfg(feature = "native-profile")]
pub use shared_memory::{NativeDataTlbStatistics, NativeSourceStatistics};
#[cfg(test)]
use stela_compiler::x86_64::chain::ChainControl;
use stela_compiler::{
    GuestAddress, GuestState, Lifter, TargetCpu,
    aarch64::{
        AddressMode, Decoder, FloatingPointOperation, MemoryTransfer, Operation, Register, Width,
        register_offset::IndexExtend,
        simd::fp8_conversion,
        system::{
            exception::{AuthenticationKey, Operation as ExceptionOperation},
            registers::{Direction, Encoding, RegisterAccess, decode as decode_register},
            synchronization::{Operation as Synchronization, WaitKind},
        },
    },
    block::{
        self, BlockProfile, ExitKind, Features, PointerAuthentication, PointerAuthenticationKey,
        PointerAuthenticationModifier, PointerAuthenticationOperation,
        scalar::{ScalarLoad, ScalarLoadAddress, ScalarStore},
        system::SystemOperation,
    },
    x86_64::{
        MemoryChecks, NativeSystem, cache_clean, chain, pointer as x86_64_pointer, register_read,
        zero_block,
    },
};
pub use stela_contracts::bus::Transition;
pub use stela_contracts::dma::Memory;
pub use stored::{Offer, SharedTranslation, Translations};
pub use system::FP_TRAPS_WRITABLE;
use {
    super::cpu::Cpu, super::cpu::Exception, super::cpu::HCR_AMO, super::cpu::HCR_API,
    super::cpu::HCR_FMO, super::cpu::HCR_HCD, super::cpu::HCR_IMO, super::cpu::HCR_TGE,
    super::cpu::HCR_TSC, super::cpu::HCR_VF, super::cpu::HCR_VI, super::cpu::HCR_VSE, super::ctrr,
    super::debug, super::exception::Class, super::exception::DAIF_A, super::exception::DAIF_D,
    super::exception::DAIF_F, super::exception::DAIF_I, super::exception::IllegalReturn,
    super::exception::Pstate, super::exception::SYNCHRONOUS_EXTERNAL_ABORT,
    super::exception::Vector, super::exception::data_abort_iss, super::hacr, super::identification,
    super::mmu, super::mmu::Access, super::mmu::Controls, super::mmu::Outcome as Translated,
    super::registers, super::registers::CpuProfile, super::registers::HCR_TIDCP,
    super::registers::Lines, super::registers::Outcome as RegisterOutcome,
    super::registers::Refusal, super::streaming, super::streaming::Denial,
    super::system::Register as SystemRegister, super::timer, stela_contracts::Feature,
    stela_contracts::chip::AdmitTable, stela_contracts::chip::Check,
};

const PROFILE: BlockProfile = BlockProfile::new(Features::SYSTEM_MODE);
const INSTRUCTION: u64 = 4;
const FETCH_PAGE: u64 = 4096;
const MAX_BLOCK_BYTES: u64 = block::MAX_BLOCK_INSTRUCTIONS as u64 * INSTRUCTION;
/// The bytes of a block's source window a compile reads and admits first:
/// most blocks end within them, and the rest compile from the whole window.
const FIRST_WINDOW_BYTES: usize = 32 * INSTRUCTION as usize;
const FETCH_CACHE: usize = 1024;
/// The level a fetch the host refuses (`Host::fetch_permitted`) reports its
/// permission fault at: the host refuses whole pages, a level 3 leaf's.
const HOST_REFUSED_FETCH_LEVEL: i8 = 3;
/// ID_AA64PFR0_EL1.CSV3, FEAT_CSV3's field.
const CSV3_SHIFT: u32 = 60;
const JUMP_CACHE: usize = 4096;
/// The most blocks one native run chains into, which bounds how late the
/// engine sees a timer or device deadline pass (tens of microseconds of
/// guest code; every System register write and device access exits
/// anyway). Each run that reaches it costs an exit to the engine, which
/// at 256 caused frequent exits in measured workloads.
const CHAIN_LIMIT: u64 = 4096;
/// The fewest blocks a machine releases for low memory: fewer hold too
/// little metadata to relieve it, and releasing them only compiles them
/// again (`Machine::memory_release_blocks`).
const MEMORY_RELEASE_BLOCKS: usize = 4096;
/// The distinct refusals of one device register and direction reported.
const DEVICE_REFUSALS_REPORTED: usize = 16;
/// ISS CV=1 and COND=0b1110, as reported for trapped AArch64 instructions.
const TRAPPED_AARCH64: u32 = (1 << 24) | (0b1110 << 20);

/// A WFI, WFE, WFIT or WFET a PE waits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Wait {
    kind: WaitKind,
    /// WFIT and WFET only.
    timeout: Option<Timeout>,
    /// A WFI in CYC_OVRD's power-down mode: the core is off, its state
    /// lost, and it wakes by leaving reset (`processors`).
    down: bool,
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
    /// For the lower and upper half, whether the current EL's tag-checked
    /// accesses through untagged pointers are checked (`Cpu::tag_checks`):
    /// the shadow tables then leave that half's Tagged memory
    /// (`mmu::attributes::TAGGED`) unmapped, apart from the `watch.pass`
    /// pages, so that every access to it exits with
    /// [`FaultCause::TagChecked`]. A tagged pointer always fails the native
    /// range check.
    pub tag_checks: [bool; 2],
}

impl Regime {
    /// Whether the 4 KiB page at `page`, whose translation has the memory
    /// `attributes`, must stay unmapped for tag checks.
    pub fn tag_blocks(&self, page: u64, attributes: u8) -> bool {
        self.tag_checks[usize::from(page >> 55 & 1 != 0)]
            && attributes == mmu::attributes::TAGGED
            && !self.watch.pass.contains(&Some(page & !(FETCH_PAGE - 1)))
    }

    /// Whether the regime keeps any Tagged memory out of the shadow.
    pub fn tag_checked(&self) -> bool {
        self.tag_checks.contains(&true)
    }
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

/// The guest context branch predictions must not cross (FEAT_CSV2): the
/// translation regime, its table bases (with the ASID one carries),
/// CONTEXTIDR_ELx and VTTBR_EL2 (the VMID). A change of any of these is a
/// guest context switch, at which the engine has the host isolate its
/// predictions ([`Host::isolate_predictions`]). An exception or return
/// that keeps them, between EL0 and EL1 of one address space, is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredictionContext {
    pub host: bool,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub contextidr: u64,
    pub vttbr: u64,
}

impl PredictionContext {
    fn of(cpu: &Cpu) -> Self {
        use crate::machine::cpu::TranslationRegime;
        let host = cpu.regime() == TranslationRegime::El20;
        let (ttbr0, ttbr1, contextidr) = if host {
            (
                SystemRegister::TTBR0_EL2,
                SystemRegister::TTBR1_EL2,
                SystemRegister::CONTEXTIDR_EL2,
            )
        } else {
            (
                SystemRegister::TTBR0_EL1,
                SystemRegister::TTBR1_EL1,
                SystemRegister::CONTEXTIDR_EL1,
            )
        };
        Self {
            host,
            ttbr0: cpu.read(ttbr0),
            ttbr1: cpu.read(ttbr1),
            contextidr: cpu.read(contextidr),
            vttbr: cpu.read(SystemRegister::VTTBR_EL2),
        }
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
    /// An x86 #UD from a native check: SP alignment, an Alignment fault, or
    /// an address outside the guest's ranges.
    InvalidOpcode,
    /// The access reached a page [`Watch`] keeps unmapped.
    Watched,
    /// The access reached Tagged memory of a half whose accesses are
    /// tag checked ([`Regime::tag_checks`]).
    TagChecked,
}

/// Distinguish an exception image from a deliberate translation-helper
/// return. The helper token cannot invent hardware vector permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFaultOrigin {
    Exception,
    TranslatedHelper,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeFault {
    pub origin: NativeFaultOrigin,
    /// Byte offset of the faulting instruction in the block's native code.
    pub offset: usize,
    pub address: u64,
    pub write: bool,
    pub cause: FaultCause,
    /// X86 exception vector, or zero for a deliberate helper return.
    pub trap: u16,
    /// X86 exception error code; instruction-fetch or host page-table/
    /// protection/stack failures cannot authorize a guest data-abort projection.
    pub error_code: u64,
    /// Initialized words captured from a checked invocation stack, unavailable
    /// until the platform supplies that owned lease and exact plan.
    pub spills: stela_compiler::block::HostSpillSnapshot,
    /// Host GPRs in architectural encoding order at the faulting instruction.
    /// A platform supplies the extended bank only after capturing it
    /// or checking its architectural initialization state. Recovery refuses
    /// a missing bank before publishing any recovered guest register.
    pub registers: stela_compiler::block::HostGprSnapshot,
}

// Keep the complete interrupt capture inline: native fault return must not
// allocate or borrow storage that the next entry can overwrite.
#[allow(
    clippy::large_enum_variant,
    reason = "the owned native interrupt capture is returned without allocation or a borrowed frame lifetime"
)]
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

struct Block {
    pc: u64,
    physical: u64,
    code: NativeCode,
    /// Guest PC and native offset of every instruction, ascending.
    source_map: Vec<(u64, usize)>,
    /// The memory checks it was compiled with.
    checks: MemoryChecks,
    variant: Variant,
    /// Direct exits to static successors not yet chained, its own and its
    /// PAC thunk's.
    successors: Vec<Successor>,
    /// The host address of the exit to the target in RAX that its RET, BR
    /// or BLR form (or that form's PAC thunk) ends with, until a lookup thunk
    /// serves it.
    dynamic_site: Option<u64>,
    /// Its first instruction, for the Branch Target check of a branch to it.
    first: u32,
    /// The PC and word of its last instruction, where it exits to the engine.
    terminal: (u64, u32),
    /// Exits to the engine at `terminal`.
    taken: u64,
    /// The guest bytes it was compiled from, for [`Machine::stale_code`].
    source_bytes: usize,
    source_hash: u64,
}

/// The bytes a block of `variant` at `pc` may be compiled from: one
/// instruction for a single-instruction block, else [`prepare::window`].
fn source_window(pc: u64, variant: Variant) -> usize {
    if variant.single {
        INSTRUCTION as usize
    } else {
        prepare::window(pc)
    }
}

/// The exit kind of a branch to a register's value (RET, BR, BLR and their
/// PAC forms RETA*, BRA*, BLRA*), and the BTYPE it sets whatever page it is
/// in: none for a BR form through other than X16 or X17, which sets 0b11 in
/// a guarded page and 0b01 elsewhere (Arm BTypeNext).
fn dynamic_branch(word: u32) -> Option<(ExitKind, Option<u8>)> {
    // Bits 22:21 select BR, BLR or RET; bit 11 a PAC form, whose bit 24
    // selects the register modifier.
    if word & 0xfe9f_f000 != 0xd61f_0000 {
        return None;
    }
    let register = (word >> 5) & 31;
    Some(match (word >> 21) & 3 {
        0 => (
            ExitKind::Indirect,
            matches!(register, 16 | 17).then_some(0b01),
        ),
        1 => (ExitKind::Call, Some(0b10)),
        2 => (ExitKind::Return, Some(0)),
        _ => return None,
    })
}

/// The compiled blocks one [`Machine::stale_code`] call checks: about a
/// millisecond of hashing.
pub const STALE_CHECKS: usize = 1024;

/// FNV-1a over a block's guest bytes.
fn source_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Compiled blocks whose guest bytes changed without a code invalidation,
/// among those one [`Machine::stale_code`] call checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StaleCode {
    pub blocks: usize,
    pub stale: usize,
    /// The first stale block's PC and physical address.
    pub first: Option<(u64, u64)>,
}

/// A direct exit in native code to a static successor: its host address,
/// the successor's PC and the exit's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Successor {
    site: u64,
    target: GuestAddress,
    kind: ExitKind,
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

/// One lookup context of one half: the EL (with the guarded level) and
/// variant fetches run in, the half's translation inputs
/// ([`Machine::half_inputs`]) and the code generation, under one number.
/// Between changes no control value shows (TLBIs, the host's fetch
/// permissions), translation is a function of these, as a TLB tags its
/// entries, so a return to earlier controls (a TTBR0 or SPRR permission
/// switched back) finds its entries in the lookup table still valid.
#[derive(Debug, Clone, Copy)]
struct Space {
    inputs: (mmu::Controls, u64),
    el: u8,
    variant: Variant,
    code: u64,
    number: u64,
}

/// A half's recent context number, with the EL, variant and translation
/// and code generations it was found for.
#[derive(Debug, Clone, Copy)]
struct Recent {
    el: u8,
    variant: Variant,
    generations: (u64, u64),
    number: u64,
}

/// The contexts one half keeps, least recently used dropped first.
const SPACES: usize = 64;
/// The recent contexts one half finds without comparing controls: enough
/// for the ELs and GXF states a kernel's exceptions alternate between.
const RECENT: usize = 4;

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
    /// The System instructions that complete natively at the end of a
    /// block: DC ZVA while it zeroes without a trap
    /// (`system::native_zero_block`), and the DC clean operations while
    /// they only check the translation of Xt (`system::native_cache_clean`).
    system: NativeSystem,
    /// FEAT_BTI: the block's page is guarded (Arm `InGuardedPage`), which
    /// fixes the BTYPE its BR forms through other than X16 and X17 set.
    /// Contexts leave it out, as it belongs to a page, not to the PE.
    guarded_page: bool,
    /// PSTATE.DIT on a host that gives the timing guarantee: the block is
    /// compiled for the host's data-independent-timing tier
    /// ([`Machine::timing_target`]).
    timing: bool,
    /// The block's page needs the translated variant: every access checks
    /// its address and calls the host's translation helper outside the
    /// native ranges ([`Machine::run_translated`]). Like `guarded_page`, it
    /// belongs to a page, not to the PE.
    translated: bool,
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
    /// `--profile`'s phase timing, while it is on.
    step_timing: Option<step_timing::StepTiming>,
    /// Exits to the engine from compiled code (System, FP, PAC and AMX), by
    /// the instruction word that took them, except those the live blocks
    /// count at their last instructions (see [`Self::exit_words`]).
    exit_words: BTreeMap<u32, u64>,
    #[cfg(all(feature = "std", feature = "native-profile"))]
    floating_profile: Option<alloc::boxed::Box<floating_profile::Sampler>>,
    #[cfg(all(feature = "std", feature = "native-profile"))]
    preparation_metrics: Option<metrics::PreparationMetrics>,
    target: TargetCpu,
    blocks: table::Table<Block>,
    /// Slots of `blocks` whose code was reclaimed, for new blocks.
    free_blocks: Vec<usize>,
    /// The blocks this machine held when it last reclaimed code for memory,
    /// while memory has stayed low since (`reclaim_for_memory`).
    reclaimed_at: Option<usize>,
    /// The fewest live blocks it releases for low memory
    /// ([`MEMORY_RELEASE_BLOCKS`]).
    memory_release_blocks: usize,
    /// The fault recovery tables of the blocks that have entries, by block
    /// index: where their regions keep guest GPRs out of the frame across a
    /// faultable access, which a native fault applies first. Kept apart
    /// from [`Block`], whose fields every exit reads.
    fault_recovery: BTreeMap<usize, recovery::CodeRecovery>,
    native_patches: BTreeMap<usize, recovery::OwnedPatch>,
    native_failure: Option<recovery::CapturedFailure>,
    /// Blocks by PC, PA, FP enablement and SP alignment checking.
    index: BTreeMap<(u64, u64, Variant), usize>,
    /// The `index` keys of the blocks compiled from each physical page.
    code_pages: BTreeMap<u64, Vec<(u64, u64, Variant)>>,
    /// The last block [`Machine::stale_code`] checked, where its sweep goes
    /// on; `None` to start over.
    stale_cursor: Option<(u64, u64, Variant)>,
    /// The fetch pages read for the translation store, by physical page,
    /// until their code is invalidated or they are the least recently used
    /// ([`stored`]), and the count of their uses so far.
    pages: BTreeMap<u64, stored::StoredPage>,
    /// The most `pages` keeps ([`Self::share_kept_pages`]).
    kept_pages: usize,
    page_uses: u64,
    /// Entry contexts by variant and address class.
    stored_contexts: BTreeMap<(Variant, u64), crate::translations::Digest>,
    /// How each variant's blocks are compiled ([`prepare`]).
    preparations: BTreeMap<Variant, Arc<Preparation>>,
    fetch: Vec<Option<FetchEntry>>,
    jump: Vec<Option<JumpEntry>>,
    /// Advances when cached fetch translations become stale.
    translation_generation: u64,
    /// Advances when installed code is discarded.
    code_generation: u64,
    /// The blocks fetches ran, by PC and context, for lookup thunks
    /// (`x86_64::chain`): the table `ChainControl::table` names.
    targets: alloc::boxed::Box<[chain::LookupEntry]>,
    /// Each half's lookup contexts ([`Space`]) since its translations last
    /// changed in a way no control value shows, most recently used last.
    spaces: [Vec<Space>; 2],
    /// Each half's recent contexts, most recent first.
    recent: [[Option<Recent>; RECENT]; 2],
    /// The largest leaf a fetch of each half translated through since its
    /// contexts were last forgotten, 0 for none, and whether one was
    /// non-global: what a TLBI by VA or ASID reaches of its lookup entries.
    fetch_leaves: [u64; 2],
    private_fetches: [bool; 2],
    /// The next context number; numbers are never reused.
    next_context: u64,
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
    /// [`Variant::system`] for the current EL, while valid.
    native_system: Option<NativeSystem>,
    /// The physical count up to which the event streams have set the event
    /// register; `None` before the first sample.
    event_sample: Option<u64>,
    /// What self-hosted debug needs of each instruction, while valid.
    debug: Option<DebugMode>,
    /// The device lines of a PE, the count before which no device changes
    /// state by itself (`Devices::deadline`) and that PE, while valid: a
    /// device or board register access, a System register write and the
    /// host between runs can change them, and clear it; an exception
    /// changes the PE alone, which the devices do not see.
    /// A PE switch keeps it, as it changes no device: another PE's lines,
    /// the running one's or a waiting one's, are then its latched pins
    /// (`Devices::pins`).
    device_lines: Option<(Lines, u64, usize)>,
    /// The PAC context, the memo of results and the key tag words, which
    /// native code reads and completes misses through (`pointer`).
    pointer: alloc::boxed::Box<pointer::PointerService>,
    /// The [`MIRRORED`] registers for native MRS reads
    /// (`x86_64::register_read`): each readable once an MRS exit completes
    /// as a plain read, until derived state may change.
    mirrors: alloc::boxed::Box<Mirrors>,
    /// The chip's `Chip::admit`, indexed.
    admit_table: Arc<AdmitTable>,
    /// The watched pages the host keeps unmapped.
    watch: Watch,
    /// The context the host last isolated predictions for.
    prediction_context: Option<PredictionContext>,
    /// The number of the running PE.
    current: usize,
    /// The WFI, WFE, WFIT or WFET the running PE waits in, until it wakes.
    waiting: Option<Wait>,
    /// Every PE by number; the running one's state is `cpu`.
    peers: Vec<processors::Peer>,
    /// Explicitly checked kept core/cluster clock and quiesce inputs.
    processor_power: Processors,
    /// Native-worker publication inventory; absent in the serial lane.
    native_publication: Option<processors::publication::WorkerPublications>,
    /// Identity of this Machine's persistent checked PE memory/event owners.
    native_memory_identity: Arc<shared_memory::ExecutionDomain>,
    /// Every assigned worker, held while the BSP executes all canonical PEs
    /// in turn through chained native blocks (`run_serialized`).
    serial_hold: Option<processors::publication::StoppedWorkers>,
    /// The other PEs' machines, when each PE runs on its own host core
    /// (`parallel`), and the count of device line changes last seen.
    parallel: Option<Arc<parallel::Hub>>,
    /// The unique admitted hub/PE epoch. The chain owner also keeps this
    /// claim, so field drop order cannot release it before control use ends.
    attached: Option<Arc<parallel::Attached>>,
    /// CPU power changes for the other PEs' machines, not yet sent.
    forwarded_power: Vec<ProcessorChange>,
    /// Instruction-cache maintenance other PEs broadcast while this one
    /// waited mid-instruction, applied at its next mail read.
    deferred_code: Vec<Option<u64>>,
    lines_epoch: u64,
    pending_device_read: Option<device_read::Pending>,
    pending_device_write: Option<device_write::Pending>,
    pending_device_tail: alloc::collections::VecDeque<shared_memory::RecoveredDeviceAccess>,
    /// Host breakpoints, ascending (`set_breakpoints`).
    breakpoints: Vec<u64>,
    /// Host trace points, ascending (`set_traces`), and the hits not yet
    /// taken (`take_trace_hits`).
    traces: Vec<u64>,
    trace_hits: Vec<TraceHit>,
    /// Emit raw guarded boundary events through Host::report, off by default.
    monitor_tracing: bool,
    /// Host watch ranges of physical device addresses, first and last
    /// byte (`set_watches`), and the hits not yet taken (`take_watch_hits`).
    watches: Vec<(u64, u64)>,
    watch_hits: Vec<WatchHit>,
    /// Every degraded operation met so far, each the first time, and those
    /// not yet taken (`take_unmodeled`); device accesses are keyed by
    /// register, direction and refusal in `degraded_devices`.
    unmodeled_met: Vec<RequirementKind>,
    unmodeled: Vec<Requirement>,
    /// The block count at which the running PE's time slice ends.
    slice_end: u64,
    /// The system counter value at which it ends, whichever comes first.
    slice_deadline: u64,
    /// The system counter the PEs observe (`clock`), where native count
    /// reads find it.
    clock: alloc::boxed::Box<clock::Clock>,
    /// End waits of every PE by leaping the counter (`clock::Clock::skip_to`).
    idle_skip: bool,
    /// The longest the waits of every PE in one `run` last in all, in
    /// host counter ticks, before it returns [`Stop::Waiting`]
    /// (`set_wait_limit`).
    wait_limit: Option<u64>,
    /// Host counter ticks the PEs have waited on the host in this `run`.
    waited: u64,
    /// The instruction just completed wrote PSTATE.PACM (PACM, or an
    /// exception return), so it does not lapse.
    pacm_written: bool,
    /// The instruction the engine is completing, already counted as retired
    /// (`Machine::completing`).
    completing: Option<u64>,
    /// The chaining state native code updates (`x86_64::chain`).
    chain: chain_control::Owner,
    /// The block count at which `run` stops.
    block_limit: u64,
    /// Suspended guest threads by thread pointer (see [`Suspension`]).
    suspended: BTreeMap<u64, Suspension>,
    /// The physical fetch pages whose blocks are compiled for the
    /// translated variant ([`Machine::run_translated`]).
    translated_pages: BTreeSet<u64>,
    /// The guest PC and data address that first needed the translated
    /// variant, for a report.
    first_translated: Option<(u64, u64)>,
    /// Device accesses answered without a model ([`Self::begin_survey`]).
    survey: Option<Survey>,
    /// The refusals of each device register and direction whose degraded
    /// answer has been reported (`take_unmodeled`).
    degraded_devices: BTreeMap<(u64, bool), BTreeSet<String>>,
    /// The context leaves SVE and SME instructions run as, by PC, word and
    /// scalable profile ([`scalable`]); discarded with the blocks.
    scalable_leaves:
        BTreeMap<(u64, u32, stela_compiler::scalable_context::ScalableProfile), scalable::Leaf>,
    /// The Allocation Tags of guest memory (FEAT_MTE2).
    tags: crate::machine::tags::Store,
    /// The current [`Regime::tag_checks`].
    tag_checks: [bool; 2],
    /// The PC of an instruction whose Tag Checks are done while it runs
    /// again untagged (`watch::retry_untagged`).
    tags_checked_at: Option<u64>,
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
        Self::new_at(cpu, host, devices, profile, target, 0)
            .expect("PE zero is present in every CPU profile")
    }

    /// Start the supplied architectural state on one existing profile PE.
    /// All other PEs remain held in reset; identities and board resource
    /// indices keep their original order. This selects no native executor.
    pub fn new_at(
        cpu: Cpu,
        host: H,
        devices: D,
        profile: CpuProfile,
        target: TargetCpu,
        boot_processor: usize,
    ) -> Result<Self, &'static str> {
        if boot_processor >= profile.processors.len().max(1) {
            return Err("the boot PE is outside the CPU profile");
        }
        if cpu.registers.chip() != profile.chip {
            return Err("the boot PE is not the profile's chip");
        }
        let admit_table = profile
            .chip
            .admit_table(identification::withheld(profile.chip, &profile.fixed))
            .unwrap_or_else(|reason| panic!("the profile has no admit table: {reason}"));
        let admit_table = Arc::new(admit_table);
        let processor_power = Processors::new(profile.processors.len().max(1))
            .expect("a CPU profile has at least its boot PE");
        let mut machine = Self {
            cpu,
            host,
            devices,
            profile,
            statistics: Statistics::default(),
            step_timing: None,
            exit_words: BTreeMap::new(),
            #[cfg(all(feature = "std", feature = "native-profile"))]
            floating_profile: None,
            #[cfg(all(feature = "std", feature = "native-profile"))]
            preparation_metrics: None,
            target,
            blocks: table::Table::new(),
            free_blocks: Vec::new(),
            reclaimed_at: None,
            memory_release_blocks: MEMORY_RELEASE_BLOCKS,
            fault_recovery: BTreeMap::new(),
            native_patches: BTreeMap::new(),
            native_failure: None,
            index: BTreeMap::new(),
            code_pages: BTreeMap::new(),
            stale_cursor: None,
            pages: BTreeMap::new(),
            kept_pages: stored::KEPT_PAGES,
            page_uses: 0,
            stored_contexts: BTreeMap::new(),
            preparations: BTreeMap::new(),
            fetch: vec![None; FETCH_CACHE],
            jump: vec![None; JUMP_CACHE],
            translation_generation: 1,
            code_generation: 1,
            targets: vec![chain::LookupEntry::default(); chain::LOOKUP_ENTRIES].into_boxed_slice(),
            spaces: [Vec::new(), Vec::new()],
            recent: [[None; RECENT]; 2],
            fetch_leaves: [0; 2],
            private_fetches: [false; 2],
            next_context: 1,
            profile_missing: Vec::new(),
            lookup: super::system::Lookup::new(),
            timers: None,
            floating_point: None,
            memory_checks: None,
            native_system: None,
            event_sample: None,
            debug: None,
            device_lines: None,
            pointer: alloc::boxed::Box::new(pointer::PointerService::new()),
            mirrors: alloc::boxed::Box::default(),
            admit_table,
            watch: Watch::default(),
            prediction_context: None,
            current: boot_processor,
            waiting: None,
            peers: Vec::new(),
            processor_power,
            native_publication: None,
            native_memory_identity: Arc::new(shared_memory::ExecutionDomain::new()),
            serial_hold: None,
            parallel: None,
            attached: None,
            forwarded_power: Vec::new(),
            deferred_code: Vec::new(),
            lines_epoch: 0,
            pending_device_read: None,
            pending_device_write: None,
            pending_device_tail: alloc::collections::VecDeque::new(),
            breakpoints: Vec::new(),
            traces: Vec::new(),
            trace_hits: Vec::new(),
            monitor_tracing: false,
            watches: Vec::new(),
            watch_hits: Vec::new(),
            unmodeled_met: Vec::new(),
            unmodeled: Vec::new(),
            slice_end: processors::QUANTUM,
            slice_deadline: u64::MAX,
            clock: alloc::boxed::Box::default(),
            idle_skip: false,
            wait_limit: None,
            waited: 0,
            pacm_written: false,
            completing: None,
            chain: chain_control::Owner::default(),
            block_limit: u64::MAX,
            suspended: BTreeMap::new(),
            translated_pages: BTreeSet::new(),
            first_translated: None,
            survey: None,
            degraded_devices: BTreeMap::new(),
            scalable_leaves: BTreeMap::new(),
            tags: crate::machine::tags::Store::default(),
            tag_checks: [false; 2],
            tags_checked_at: None,
        };
        machine.chain.set_table(machine.targets.as_ptr() as u64);
        machine.peers = processors::boot(&machine.profile, boot_processor);
        machine.load_profile();
        machine.sync_regime();
        Ok(machine)
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
    let routed = |routing: u32, pending: u32| cpu.hcr(routing) && cpu.virtual_pending(pending);
    cpu.pstate.el != 2
        && !cpu.in_host()
        && (routed(HCR_IMO, HCR_VI) || routed(HCR_FMO, HCR_VF) || routed(HCR_AMO, HCR_VSE))
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
mod tests;
