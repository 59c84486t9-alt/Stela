//! The dispatch loop: fetch translation, block cache, native execution and
//! every exit back from native code.
mod amx;
mod apple_maintenance;
mod clock;
mod compression;
mod device_access;
mod device_read;
mod device_write;
mod exclusive;
#[cfg(all(feature = "std", feature = "native-profile"))]
pub(crate) mod floating_profile;
mod guarded;
mod hosted;
pub mod installed_code;
#[cfg(all(feature = "std", feature = "native-profile"))]
pub(crate) mod metrics;
mod monitor;
mod native_timing;
pub use crate::platform::dma::{DmaError, TransferFault};
pub use monitor::{MonitorEvent, MonitorKind, MonitorLocation};
pub use native_timing::{NativeInstructionSample, NativeTimingPhase, NativeTimingWork};
mod pointer;
mod prepare;
pub use device_read::{CanonicalDeviceMemory, ConsumedScalar, DeviceReadRequest, DeviceReadShape};
pub use device_write::{
    CanonicalDeviceWrite, CanonicalWriteMemory, ConsumedWrite, DeviceWriteRequest, DeviceWriteShape,
};
mod processors;
mod scalable;
mod shared_memory;
mod stored;
mod system;
mod tags;
mod unprivileged;
mod watch;

use super::{
    chip::{AdmitTable, Check},
    cpu::{
        Cpu, Exception, HCR_AMO, HCR_API, HCR_FMO, HCR_HCD, HCR_IMO, HCR_TGE, HCR_TSC, HCR_VF,
        HCR_VI, HCR_VSE,
    },
    ctrr, debug,
    exception::{
        Class, DAIF_A, DAIF_D, DAIF_F, DAIF_I, IllegalReturn, Pstate, SYNCHRONOUS_EXTERNAL_ABORT,
        Vector, data_abort_iss,
    },
    hacr, identification,
    mmu::{self, Access, Controls, Outcome as Translated},
    registers::{self, CpuProfile, HCR_TIDCP, Lines, Outcome as RegisterOutcome, Refusal},
    streaming::{self, Denial},
    system::{Feature, Register as SystemRegister},
    timer,
};
pub use crate::platform::apple::bus::Transition;
pub use crate::platform::dma::Memory;
use crate::{pauth, scalable::ScalableState};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
    vec,
    vec::Vec,
};
use core::fmt;
use pointer::{PointerInputs, PointerOperation, PointerResult};
#[cfg(test)]
pub(crate) use prepare::test_preparation;
pub use prepare::{Description, Preparation, Prepared, Refused, window};
pub use processors::publication;
pub use processors::{
    PeerState, PreparedProcessorPower, ProcessorBinding, ProcessorChange, ProcessorPowerError,
    ProcessorTarget, ProcessorWrite, Processors, SettledProcessorWrite,
};
pub use shared_memory::{
    HeldRamService, MAX_NATIVE_EPOCH_BODIES, NativeCohort, NativeEpochDeadline, NativeEpochEnd,
    NativeEpochStatistics, NativeRun, NativeRunIdentity, NativeRunObservation, NativeTransport,
    ReturnedRun, ServiceHost, ServiceTransport, SharedMemory, SharedMemoryFailure,
    SharedMemoryRefusal, dispatch_native_run, recover_native_run,
};
#[cfg(feature = "native-profile")]
pub use shared_memory::{NativeDataTlbStatistics, NativeSourceStatistics};
use stela_compiler::{
    GuestAddress, GuestState, Lifter, TargetCpu,
    aarch64::{
        AddressMode, Decoder, FloatingPointOperation, MemoryTransfer, Operation, Register, Width,
        register_offset::IndexExtend,
        simd::fp8_conversion,
        system::{
            exception::{AuthenticationKey, Operation as ExceptionOperation},
            registers::{Direction, Encoding, RegisterAccess},
            synchronization::{Operation as Synchronization, WaitKind},
        },
    },
    block::{
        self, BlockProfile, ExitKind, PointerAuthentication, PointerAuthenticationKey,
        PointerAuthenticationModifier, PointerAuthenticationOperation,
        el1_platform::{ScalarLoad, ScalarLoadAddress, ScalarStore},
        system::SystemOperation,
    },
    x86_64::{
        MemoryChecks, NativeSystem, cache_clean,
        chain::{self, ChainControl},
        pointer as x86_64_pointer, register_read, zero_block,
    },
};
pub use stored::{Offer, Translations};
pub use system::FP_TRAPS_WRITABLE;

const PROFILE: BlockProfile = BlockProfile::SystemModeV1;
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
/// at 256 was half of a hosted process's exits.
const CHAIN_LIMIT: u64 = 4096;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeFault {
    /// Byte offset of the faulting instruction in the block's native code.
    pub offset: usize,
    pub address: u64,
    pub write: bool,
    pub cause: FaultCause,
    /// The host GPRs at the faulting instruction, RAX through R15 by x86
    /// register number: guest registers whose frame slots a region has not
    /// yet written back live there, where the block's fault recovery table
    /// (`stela_compiler::block::FaultRecovery`) names them.
    pub registers: [u64; 16],
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
    /// Optional observational timing on the real local owner. Regular builds
    /// contain neither checkpoints nor their counters.
    #[cfg(feature = "native-profile")]
    fn native_timing(&mut self, _phase: NativeTimingPhase) {}
    #[cfg(feature = "native-profile")]
    fn native_instruction_sample(&mut self, _sample: NativeInstructionSample<'_>) {}
    #[cfg(feature = "native-profile")]
    fn native_timing_work_start(&mut self, _work: NativeTimingWork) -> Option<u64> {
        None
    }
    #[cfg(feature = "native-profile")]
    fn native_timing_work_end(&mut self, _work: NativeTimingWork, _started: u64) {}

    /// Select the source PE whose stopped services this Host can settle through
    /// its actual physical owner. Ordinary serial Hosts do not admit this path.
    fn select_native_service(&mut self, _worker: publication::WorkerId) -> bool {
        false
    }

    /// Complete this actual host worker's coherent CPU-memory accesses. This
    /// is not a device/DMA/controller drain or MCC completion authority.
    fn memory_barrier(&mut self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Source-qualified identity retained by this physical worker's local
    /// Host/GS owner. Serial hosts have no native-worker authority.
    fn native_worker(&self) -> Option<publication::WorkerId> {
        None
    }

    /// Optional destination-local stable declaration owner. Absence keeps full
    /// live enumeration at every native boundary. A supplied invalid/revoked
    /// lease refuses; it never falls back to disguise stale ownership.
    fn native_cpu_lease(&self) -> Option<crate::NativeCpuLease> {
        None
    }

    /// Read guest RAM. False when any byte is not RAM.
    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool;
    /// Write guest RAM. False when any byte is not RAM.
    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool;
    /// Descriptor admission needs a real RAM/permission owner. A legacy host
    /// without that service cannot qualify a native coprocessor mapping.
    fn check_ram_range(
        &mut self,
        _physical: u64,
        _bytes: usize,
        _write: bool,
    ) -> Result<(), crate::platform::dma::DmaError> {
        Err(crate::platform::dma::DmaError::Unsupported(
            "host DMA range validation is unavailable",
        ))
    }
    /// Stateful DMA must retain partial effects across later owner failures.
    /// The default is for hosts whose boolean failure commits no bytes.
    fn read_ram_progress(
        &mut self,
        physical: u64,
        buffer: &mut [u8],
    ) -> Result<(), crate::platform::dma::TransferFault> {
        self.read_ram(physical, buffer)
            .then_some(())
            .ok_or(crate::platform::dma::TransferFault {
                error: crate::platform::dma::DmaError::Memory,
                completed: 0,
            })
    }
    fn write_ram_progress(
        &mut self,
        physical: u64,
        data: &[u8],
    ) -> Result<(), crate::platform::dma::TransferFault> {
        self.write_ram(physical, data)
            .then_some(())
            .ok_or(crate::platform::dma::TransferFault {
                error: crate::platform::dma::DmaError::Memory,
                completed: 0,
            })
    }

    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError>;
    /// Install immutable context code, optionally reusing this same live Arc's
    /// installation on this actual Host. Ordinary patchable installs stay
    /// independent. Implementations must invalidate reuse before every arena
    /// patch, discard or reclaim; replacement Hosts start with no entries.
    /// The default preserves the existing one-install-per-call behavior.
    fn install_immutable(&mut self, code: &Arc<Vec<u8>>) -> Result<NativeCode, InstallError> {
        self.install(code.as_slice())
    }
    /// Overwrite installed code at `code` with `bytes`, which the next
    /// native run executes.
    fn patch(&mut self, code: NativeCode, bytes: &[u8]);
    /// Free every installed block.
    fn discard_code(&mut self);
    /// Free the oldest part of the code arena for new code, as a ring
    /// does, and return the host addresses it held: the engine forgets
    /// every block and leaf there before installing more. `None` from a
    /// host whose arena is one part, for which the engine discards every
    /// block instead.
    fn reclaim_code(&mut self) -> Option<core::ops::Range<usize>> {
        None
    }
    /// Whether the memory the engine's own data takes runs low. Installed
    /// blocks' metadata is most of it, so the engine then reclaims code as
    /// when the code arena fills.
    fn memory_low(&self) -> bool {
        false
    }
    /// Run one native block on `state`, and the blocks it chains into. A
    /// fault's offset is from `code`.
    ///
    /// # Safety
    /// `code` was returned by [`Host::install`] since the last discard and
    /// was compiled for the system-mode block ABI.
    unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit;
    /// Run an installed context-ABI block through this physical owner's native
    /// recovery frame. `None` refuses context entry before any native effects.
    ///
    /// # Safety
    /// `code` was installed by this same Host since its last discard, uses the
    /// compiler's context-block ABI and matches the actual source-qualified
    /// target/profile. The caller exclusively retains the real guest frame,
    /// valid context and every reachable service/mapping/code owner through
    /// actual return or fault, complete recovery and source-PC settlement.
    /// The Host stays pinned to its physical owner; callbacks cannot reenter it.
    unsafe fn execute_context(
        &mut self,
        _code: NativeCode,
        _state: &mut GuestState,
        _context: &mut stela_compiler::context::ExecutionContext,
    ) -> Option<NativeExit> {
        None
    }

    /// The address to call installed context-leaf code at, with
    /// `stela_compiler::extended`'s two-argument ABI (the SVE and SME
    /// instructions run so), or `None` on a host that cannot run it. The
    /// engine calls it outside any borrow of the host, whose RAM the leaf's
    /// memory service then reads and writes.
    fn context_entry(&mut self, _code: NativeCode) -> Option<usize> {
        None
    }
    /// Whether the PE may execute the page holding `virtual`, which its
    /// translation lets it execute: false where the host's view of memory
    /// refuses the fetch (an Apple SPRR view in which JIT pages are rw-),
    /// which takes a permission Instruction Abort. Asked when a fetch's
    /// translation is not cached; [`Machine::fetch_permissions_changed`]
    /// makes later fetches ask again.
    fn fetch_permitted(&mut self, _virtual: u64) -> bool {
        true
    }
    /// Where the host places the guest's address space beside its own,
    /// which decides the addresses native code accesses directly
    /// ([`mmu::placement`]).
    fn placement(&self) -> mmu::placement::Placement {
        mmu::placement::Placement::FiveLevel
    }
    /// The address of the 8 bytes that hold the host's translation helper,
    /// which blocks of the translated variant call for each access outside
    /// [`Host::placement`]'s native ranges ([`mmu::translated`]); `None`
    /// on a host without one, which stops explicitly where a guest maps
    /// such an address.
    fn translation_helper(&self) -> Option<u64> {
        None
    }
    /// Make the shadow translation follow `regime`: drop what a change of
    /// its controls translates differently (a TTBR0 write arrives only
    /// here, not through [`Host::invalidate_translations`]).
    fn set_regime(&mut self, regime: &Regime);
    /// Keep the branch predictions trained before this call from steering
    /// speculation after it (FEAT_CSV2): the engine calls it whenever the
    /// guest's context for prediction changes ([`PredictionContext`]). A host
    /// that cannot isolate them leaves this empty and identifies no FEAT_CSV2
    /// (`identification::Speculation::contexts`).
    fn isolate_predictions(&mut self) {}
    /// Keep the reads after this call from executing before the branches
    /// before it resolve (FEAT_CSV3): the engine calls it between its
    /// software translation of an access and the device or tag read it
    /// permits, and [`Host::read_ram`] keeps the same order itself. A host
    /// that cannot order them leaves both empty and identifies no FEAT_CSV3
    /// (`identification::Speculation::faulting_data`).
    fn speculation_barrier(&self) {}
    /// The PE invalidated instruction caches (IC IVAU of `Some(page)`, a
    /// physical page; IC IALLU or IALLUIS for `None`), which this machine
    /// already applied to its own compiled code. A host that runs other
    /// PEs in machines of their own makes them drop theirs before they
    /// next execute: IC IVAU reaches every PE of the shareability domain.
    fn code_invalidated(&mut self, _page: Option<u64>) {}
    /// Drop every cached translation.
    fn invalidate_translations(&mut self);
    /// Drop the cached translations a TLBI reaches in the current context,
    /// as [`Host::set_regime`] last gave it; a superset is always correct.
    fn invalidate_reach(&mut self, reach: mmu::tlbi::Reach) {
        if reach != mmu::tlbi::Reach::Nothing {
            self.invalidate_translations();
        }
    }
    /// The guest's system counter.
    fn counter(&mut self) -> u64;
    /// Interrupt the host at this counter value, or never.
    fn arm_timer(&mut self, deadline: Option<u64>);
    /// Block until a host interrupt arrives.
    fn wait_for_interrupt(&mut self);
    /// Progress events for the diagnostic log.
    fn report(&mut self, _event: &Event) {}
    /// The persistent translation store blocks are taken from and offered
    /// to, if the host keeps one ([`Translations`]).
    fn translations(&mut self) -> Option<&mut dyn Translations> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    /// No device model covers this physical address.
    NoDevice,
    /// The device refused this register, width or state.
    Refused(String),
    /// A DMA service could not execute. Survey mode may substitute unknown
    /// register reads/writes, but cannot invent a completed DMA operation.
    TransferRefused(String),
}

/// A complete device pair read has consumed its input. A subsequent board
/// service failure cannot turn it into a replayable register refusal: the
/// engine retires the returned data and then stops at the retained failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedPair {
    pub values: [u64; 2],
    pub settlement: Result<(), DeviceError>,
}

/// The board's devices on the guest physical bus. `cpu` is the number of the
/// PE making the access, as [`CpuProfile::processors`] numbers it, and `now`
/// is the system counter value (24 MHz ticks) of the access.
pub trait Devices {
    /// The PE a read triggers a debug PC sample of, when this is a sampler.
    fn pc_sample_target(&self, _physical: u64, _bytes: u8) -> Option<usize> {
        None
    }
    /// Supply that PE's execution PC immediately before its sample trigger.
    fn observe_pc_sample(&mut self, _physical: u64, _pc: u64) {}
    fn read(&mut self, cpu: usize, physical: u64, bytes: u8, now: u64) -> Result<u64, DeviceError>;
    /// Effect-free classification only; this grants no memory authority. A
    /// canonical-required read must never execute through the raw/serial hook.
    fn requires_canonical_read(
        &self,
        _cpu: usize,
        _physical: u64,
        _shape: DeviceReadShape,
    ) -> bool {
        false
    }
    /// Refuse before consumption, or return the actual consumed scalar and any
    /// later settlement failure while the same live canonical guard is held.
    fn read_canonical(
        &mut self,
        _cpu: usize,
        _physical: u64,
        _bytes: u8,
        _now: u64,
        _memory: &mut dyn CanonicalDeviceMemory,
    ) -> Result<ConsumedScalar, DeviceError> {
        Err(DeviceError::TransferRefused(
            "canonical device scalar read has no live backend".into(),
        ))
    }
    /// The consuming pair counterpart; no ordinary-read fallback is permitted.
    fn read_pair_canonical(
        &mut self,
        _cpu: usize,
        _physical: u64,
        _bytes: u8,
        _now: u64,
        _memory: &mut dyn CanonicalDeviceMemory,
    ) -> Result<ConsumedPair, DeviceError> {
        Err(DeviceError::TransferRefused(
            "canonical device pair read has no live backend".into(),
        ))
    }
    /// Outer Err is proved effect-free. Partial or unknown effects must be
    /// returned explicitly; no raw write fallback or fabricated ACK is allowed.
    fn write_canonical(
        &mut self,
        _cpu: usize,
        _physical: u64,
        _bytes: u8,
        _value: u64,
        _now: u64,
        _owners: &mut dyn CanonicalDeviceWrite,
    ) -> Result<ConsumedWrite, DeviceError> {
        Err(DeviceError::TransferRefused(
            "canonical device write has no live backend".into(),
        ))
    }
    /// One qualified whole-pair owner; adjacent scalar registers are never
    /// combined by this default boundary.
    fn write_pair_canonical(
        &mut self,
        _cpu: usize,
        _physical: u64,
        _bytes: u8,
        _values: [u64; 2],
        _now: u64,
        _owners: &mut dyn CanonicalDeviceWrite,
    ) -> Result<ConsumedWrite, DeviceError> {
        Err(DeviceError::TransferRefused(
            "canonical device pair write has no live backend".into(),
        ))
    }
    /// Optional whole-pair boundary for a device with a qualified consuming
    /// read protocol. `Ok(None)` has no effects and requests ordinary scalar
    /// reads. `Err` refuses before consumption; `Ok(Some(..))` must retain the
    /// data even if forwarding its resulting board effects later fails.
    fn read_pair(
        &mut self,
        _cpu: usize,
        _physical: u64,
        _bytes: u8,
        _now: u64,
    ) -> Result<Option<ConsumedPair>, DeviceError> {
        Ok(None)
    }
    fn write(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<(), DeviceError>;
    /// Complete a device write with exclusive access to the actual CPU and
    /// native owners. CPU-affecting controllers must preflight every owner,
    /// consume one whole processor batch, then commit infallibly before ACK.
    /// A CPU/lifecycle refusal is a non-substitutable native service failure.
    fn write_with_processors(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        _processors: ProcessorWrite<'_>,
    ) -> Result<(), DeviceError> {
        self.write(cpu, physical, bytes, value, now)
    }
    /// Bring time-driven state up to `now` and report the interrupt lines
    /// the devices drive into PE `cpu`.
    fn lines(&mut self, cpu: usize, now: u64) -> Lines;
    /// The next counter value at which a device changes state by itself.
    fn deadline(&mut self, _now: u64) -> Option<u64> {
        None
    }
    /// An MRS (`write` `None`) or MSR by PE `cpu` of a System register the
    /// board implements for all its PEs rather than one core, such as
    /// Apple's fast-IPI registers: `None` for an encoding it does not
    /// implement, else the value read (0 for a write) or why it is refused.
    fn system_register(
        &mut self,
        _cpu: usize,
        _encoding: Encoding,
        _write: Option<u64>,
        _now: u64,
    ) -> Option<Result<u64, &'static str>> {
        None
    }
    /// A reset or power-off the guest requested from a device, once.
    fn take_reset(&mut self) -> Option<Reset> {
        None
    }
    /// A PE the guest released from reset through a device, once.
    fn take_start(&mut self) -> Option<Start> {
        None
    }
    /// The reset address PE `cpu` leaves reset at, where the board holds it
    /// in a device register (RVBAR_EL2 reads it).
    fn reset_vector(&self, _cpu: usize) -> Option<u64> {
        None
    }
    /// PE `cpu` powered down (`false`: a WFI in CYC_OVRD's power-down
    /// mode) or left reset again (`true`: a start or a wake from power-down).
    fn processor_power(&mut self, _cpu: usize, _on: bool) {}
    /// PE `cpu`'s SIQ_CFG_EL1 now refuses (`true`) or accepts the interrupt
    /// controller's IRQs (`registers::SIQ_CFG_NO_IRQ`).
    fn irq_steering(&mut self, _cpu: usize, _refuses: bool, _now: u64) {}
    /// Whether an input from outside the board, which the host delivers
    /// between runs, can still wake a PE when no device deadline will:
    /// a sleeping SoC's power button. Then a wait of every PE with no
    /// deadline is [`Stop::Waiting`] rather than [`Stop::Idle`].
    fn waits_on_host(&self) -> bool {
        false
    }
    /// The physical regions the memory controllers have locked against writes,
    /// first and last byte, by CTRR lock group.
    fn memory_lock(&self) -> super::mmu::MemoryLocks {
        [None; 4]
    }
    /// A native bus peer's next bounded DMA step. None adds no polling work.
    fn dma_deadline(&self) -> Option<u64> {
        None
    }
    /// Run the DMA a device write by PE `cpu` started, on guest RAM
    /// `memory`, before the next guest access: device DMA completes in the
    /// write's own step.
    fn transfer(
        &mut self,
        _cpu: usize,
        _memory: &mut dyn Memory,
        _now: u64,
    ) -> Result<(), DeviceError> {
        Ok(())
    }
}

/// Guest RAM through the host, as device DMA reaches it.
struct HostMemory<'a, H: Host> {
    host: &'a mut H,
    lock: super::mmu::MemoryLocks,
}

impl<H: Host> Memory for HostMemory<'_, H> {
    fn read(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
        self.read_progress(physical, buffer).is_ok()
    }
    fn write(&mut self, physical: u64, data: &[u8]) -> bool {
        self.write_progress(physical, data).is_ok()
    }
    fn check_range(
        &mut self,
        physical: u64,
        bytes: usize,
        write: bool,
    ) -> Result<(), crate::platform::dma::DmaError> {
        if write && bytes != 0 {
            let last = u64::try_from(bytes - 1)
                .ok()
                .and_then(|n| physical.checked_add(n))
                .ok_or(crate::platform::dma::DmaError::Memory)?;
            if self
                .lock
                .into_iter()
                .flatten()
                .any(|(first, end)| physical <= end && first <= last)
            {
                return Err(crate::platform::dma::DmaError::Memory);
            }
        }
        self.host.check_ram_range(physical, bytes, write)
    }
    fn read_progress(
        &mut self,
        physical: u64,
        buffer: &mut [u8],
    ) -> Result<(), crate::platform::dma::TransferFault> {
        self.host.read_ram_progress(physical, buffer)
    }
    fn write_progress(
        &mut self,
        physical: u64,
        data: &[u8],
    ) -> Result<(), crate::platform::dma::TransferFault> {
        let refused = crate::platform::dma::TransferFault {
            error: crate::platform::dma::DmaError::Memory,
            completed: 0,
        };
        if !data.is_empty() {
            let last = u64::try_from(data.len() - 1)
                .ok()
                .and_then(|bytes| physical.checked_add(bytes))
                .ok_or(refused)?;
            if self
                .lock
                .into_iter()
                .flatten()
                .any(|(first, end)| physical <= end && first <= last)
            {
                return Err(refused);
            }
        }
        self.host.write_ram_progress(physical, data)
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
    /// An exception taken from `from_el`, a guarded level when
    /// `from_guarded`.
    Exception {
        vector: Vector,
        from_el: u8,
        from_guarded: bool,
        syndrome: u64,
        return_address: u64,
        fault_address: Option<u64>,
    },
    /// An exception return, to a guarded level when `guarded`.
    Return { to_el: u8, guarded: bool, pc: u64 },
    /// An opt-in guarded boundary trace, emitted synchronously without a queue.
    Monitor(MonitorEvent),
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
    DeviceAdvance(String),
    IllegalReturn(IllegalReturn),
    /// Entering an EL1&0 guest of the EL2 host while the named Apple VM
    /// register (`impdef::Class::Guest`) holds state the machine does not
    /// apply to a guest.
    VmState(&'static str),
    Native(&'static str),
    /// Detailed refusal before an actual checked native frame was executed.
    NativePreparation(String),
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
            RequirementKind::DeviceAdvance(detail) => write!(f, "device advance: {detail}")?,
            RequirementKind::IllegalReturn(reason) => write!(f, "exception return {reason:?}")?,
            RequirementKind::VmState(register) => write!(
                f,
                "entering an EL1&0 guest with nonzero Apple VM state in {register}"
            )?,
            RequirementKind::Native(detail) => write!(f, "native execution: {detail}")?,
            RequirementKind::NativePreparation(detail) => {
                write!(f, "native preparation: {detail}")?
            }
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

/// Trace hits kept between [`Machine::take_trace_hits`] calls.
pub const TRACE_HITS: usize = 4096;

/// Watch hits kept between [`Machine::take_watch_hits`] calls.
pub const WATCH_HITS: usize = 4096;

/// A device access inside a host watch range (`Machine::set_watches`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchHit {
    pub pc: u64,
    pub pe: usize,
    pub physical: u64,
    pub bytes: u8,
    /// The value read or written; zero for a refused access.
    pub value: u64,
    pub write: bool,
    /// Whether the device completed the access.
    pub completed: bool,
    /// Further hits dropped after this one, beyond [`WATCH_HITS`].
    pub dropped: u64,
}

/// A PE reaching a host trace point (`Machine::set_traces`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceHit {
    pub pc: u64,
    pub pe: usize,
    pub el: u8,
    /// X0 to X3 and the link register.
    pub arguments: [u64; 4],
    pub lr: u64,
    /// Further hits dropped after this one, beyond [`TRACE_HITS`].
    pub dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The block budget ran out.
    Budget,
    /// Every PE is off or waits in WFI or WFE with nothing able to wake it.
    Idle,
    /// Every PE is off or waits, and the wait reached the wait limit
    /// (`Machine::set_wait_limit`), or only something outside the board can
    /// end it (`Devices::waits_on_host`) and no limit is set. The host
    /// takes its inputs and runs the machine again to go on waiting.
    Waiting,
    /// A device carried out the guest's reset or power-off request.
    Reset(Reset),
    Unsupported(Requirement),
    /// An unexecuted device read retained by the actual canonical scheduler.
    DeviceRead(DeviceReadRequest),
    /// An unexecuted write, retained by the same canonical cohort owner.
    DeviceWrite(DeviceWriteRequest),
    /// The running PE reached a host breakpoint (`Machine::set_breakpoints`)
    /// at this PC, before executing its instruction.
    Breakpoint(u64),
}

/// A machine-wide transition a device carried out for the guest: what the
/// host must do next and the device's account of why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reset {
    pub transition: Transition,
    pub reason: String,
}

impl fmt::Display for Reset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.transition, self.reason)
    }
}

/// Where the running regime's TTBR1 tables map ([`Machine::upper_occupancy`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occupancy {
    /// The level-1 table's physical address.
    pub root: u64,
    /// First and last VA of each run of valid level-1 entries.
    pub ranges: Vec<(u64, u64)>,
    /// The first and last byte of the outermost mapped 32 MiB, where the
    /// outermost entries are tables; their whole entry otherwise.
    pub lowest: Option<u64>,
    pub highest: Option<u64>,
}

/// Where a guest thread stopped running: the PE's PC, frame pointer and
/// link register, and the physical count, when software replaced the thread
/// pointer naming it (TPIDR_EL1). While the thread stays suspended its stack
/// still holds the frame records `frame` starts, so diagnostics can walk
/// where it waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suspension {
    pub at: u64,
    pub pc: u64,
    pub frame: u64,
    pub link: u64,
}

/// The suspended threads [`Machine`] remembers at most.
const SUSPENSIONS: usize = 1 << 14;

/// One device register a survey answered in place of its model: where it
/// was first reached, how often, the last value written to it, and the
/// device layer's reason for refusing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surveyed {
    pub physical: u64,
    pub bytes: u8,
    pub write: bool,
    pub pc: u64,
    /// The link register then, which names the caller of an accessor.
    pub link: u64,
    pub count: u64,
    pub value: u64,
    pub detail: String,
}

/// A survey's records by register and direction, and those not yet taken.
#[derive(Default)]
struct Survey {
    records: BTreeMap<(u64, bool), Surveyed>,
    fresh: Vec<(u64, bool)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "std", feature = "native-profile"),
    derive(serde::Serialize)
)]
pub struct Statistics {
    pub blocks: u64,
    /// Retirements from CPU incarnations replaced by a real PE restart.
    /// Add live/parked CPU counters through `retired_instructions`.
    pub replaced_retired: u128,
    /// Blocks entered through a chain from another, without the engine.
    pub chained: u64,
    /// Direct exits redirected into their successors.
    pub links: u64,
    /// Exits redirected through a lookup of their target (returns and
    /// direct exits out of their page), and the transfers those made.
    pub lookups: u64,
    pub lookup_hits: u64,
    /// Native runs that ended in an exit to the engine, by `ExitKind`
    /// (Fallthrough, Direct, Indirect, Call, Return, Trap, PAC, Clock,
    /// ThreadRegister, FloatingPoint, ScalableNumerical, System, AMX).
    pub exit_kinds: [u64; 13],
    pub compiled: u64,
    /// Counter ticks spent analyzing and compiling `compiled`.
    pub compile_ticks: u64,
    /// Blocks taken from the persistent translation store instead of
    /// compiled, and compiled blocks offered to it.
    pub stored: u64,
    pub offered: u64,
    /// Blocks another thread of the process (or its ahead-of-time
    /// translation) had prepared, installed instead of compiled.
    pub shared: u64,
    /// Guest instructions in `compiled`.
    pub compiled_instructions: u64,
    pub exceptions: u64,
    pub interrupts: u64,
    pub system_exits: u64,
    pub device_accesses: u64,
    pub code_discards: u64,
    /// Parts of the code arena reclaimed for new code, oldest first.
    pub code_evictions: u64,
    /// Pages of compiled code an IC IVAU made stale.
    pub code_invalidations: u64,
    pub waits: u64,
    /// Changes of the running PE.
    pub switches: u64,
    /// Translation control writes that dropped every cached translation.
    pub translation_changes: u64,
    /// TLBIs, and those of them whose reach in the shadow was less than
    /// everything.
    pub tlb_maintenance: u64,
    pub scoped_maintenance: u64,
    /// TTBR0 writes, which drop the lower half's.
    pub table_base_changes: u64,
    /// Guest context changes at which the host isolated its branch
    /// predictions ([`PredictionContext`]).
    pub prediction_isolations: u64,
    /// Fetch pages whose blocks run in the translated variant, because one
    /// of their accesses reached a guest address outside the host's native
    /// ranges.
    pub translated_pages: u64,
    /// Operations answered with a degraded response outside strict mode
    /// ([`Machine::set_strict`]); each distinct one is also reported once
    /// ([`Machine::take_unmodeled`]).
    pub degraded: u64,
}

impl core::ops::AddAssign for Statistics {
    fn add_assign(&mut self, other: Self) {
        let Self {
            blocks,
            replaced_retired,
            chained,
            links,
            lookups,
            lookup_hits,
            exit_kinds,
            compiled,
            compile_ticks,
            stored,
            offered,
            shared,
            compiled_instructions,
            exceptions,
            interrupts,
            system_exits,
            device_accesses,
            code_discards,
            code_evictions,
            code_invalidations,
            waits,
            switches,
            translation_changes,
            tlb_maintenance,
            scoped_maintenance,
            table_base_changes,
            prediction_isolations,
            translated_pages,
            degraded,
        } = other;
        self.replaced_retired = self.replaced_retired.saturating_add(replaced_retired);
        for (total, count) in self.exit_kinds.iter_mut().zip(exit_kinds) {
            *total += count;
        }
        for (total, count) in [
            (&mut self.blocks, blocks),
            (&mut self.chained, chained),
            (&mut self.links, links),
            (&mut self.lookups, lookups),
            (&mut self.lookup_hits, lookup_hits),
            (&mut self.compiled, compiled),
            (&mut self.compile_ticks, compile_ticks),
            (&mut self.stored, stored),
            (&mut self.offered, offered),
            (&mut self.shared, shared),
            (&mut self.compiled_instructions, compiled_instructions),
            (&mut self.exceptions, exceptions),
            (&mut self.interrupts, interrupts),
            (&mut self.system_exits, system_exits),
            (&mut self.device_accesses, device_accesses),
            (&mut self.code_discards, code_discards),
            (&mut self.code_evictions, code_evictions),
            (&mut self.code_invalidations, code_invalidations),
            (&mut self.waits, waits),
            (&mut self.switches, switches),
            (&mut self.translation_changes, translation_changes),
            (&mut self.tlb_maintenance, tlb_maintenance),
            (&mut self.scoped_maintenance, scoped_maintenance),
            (&mut self.table_base_changes, table_base_changes),
            (&mut self.prediction_isolations, prediction_isolations),
            (&mut self.translated_pages, translated_pages),
            (&mut self.degraded, degraded),
        ] {
            *total += count;
        }
    }
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

/// FNV-1a over a block's guest bytes.
fn source_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Compiled blocks whose guest bytes changed without a code invalidation.
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

/// The System registers whose MRS native code completes from a mirror
/// cell (`x86_64::register_read`): reads without side effects whose result
/// and plainness follow from System registers and PSTATE alone, so a read
/// the engine found plain stays plain, with the same value, until derived
/// state may change ([`Machine::derived_changed`]). They are the thread
/// pointers, Apple's GL2 thread pointer and GXF status, and DAIF.
const MIRRORED: [Encoding; 7] = {
    use registers::encodings::{
        DAIF, GXF_STATUS_EL1, TPIDR_EL0, TPIDR_EL1, TPIDR_EL2, TPIDR_GL2, TPIDRRO_EL0,
    };
    [
        TPIDR_EL0,
        TPIDRRO_EL0,
        TPIDR_EL1,
        TPIDR_EL2,
        TPIDR_GL2,
        GXF_STATUS_EL1,
        DAIF,
    ]
};

/// Rt 31 in MRS: XZR, which discards the value.
const ZERO_REGISTER: u8 = 31;

/// The cells of the [`MIRRORED`] registers, in its order.
type Mirrors = [register_read::Cell; MIRRORED.len()];

/// The [`MIRRORED`] index of DAIF.
const DAIF_MIRROR: usize = MIRRORED.len() - 1;
const _: () = assert!(matches!(MIRRORED[DAIF_MIRROR], registers::encodings::DAIF));

/// MRS DAIF's value for PSTATE's D, A, I and F masks: bits 9:6.
fn daif_register(daif: u8) -> u64 {
    u64::from(daif) << DAIF_REGISTER_SHIFT
}

const DAIF_REGISTER_SHIFT: u32 = 6;

/// The [`MIRRORED`] index of a read of `access`, other than to XZR.
fn mirrored(access: RegisterAccess) -> Option<usize> {
    if access.direction() != Direction::Read || access.rt() == ZERO_REGISTER {
        return None;
    }
    MIRRORED
        .iter()
        .position(|&encoding| encoding == access.encoding())
}

/// The [`MIRRORED`] index and Xt of `word` at `pc` if it is MRS of a
/// mirrored register to Xt, other than XZR.
fn mirrored_read(pc: u64, word: u32) -> Option<(usize, u8)> {
    let instruction = block::decode_system_mode_instruction(GuestAddress(pc), word).ok()??;
    match instruction.operation {
        SystemOperation::Register(access) => Some((mirrored(access)?, access.rt())),
        _ => None,
    }
}

/// Whether `word` at `pc` is a System instruction blocks compiled for
/// `system` complete natively: DC ZVA or one of its DC clean operations.
fn completes_natively(pc: u64, word: u32, system: NativeSystem) -> bool {
    block::decode_system_mode_instruction(GuestAddress(pc), word)
        .ok()
        .flatten()
        .is_some_and(|instruction| {
            system.zero_block.is_some() && zero_block::operand(&instruction).is_some()
                || cache_clean::operand(&instruction)
                    .is_some_and(|(operation, _)| system.cache_clean.contains(operation))
        })
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

impl<H: Host, D: Devices> Machine<H, D> {
    /// Both FP service boundaries share the same sole semantic completion.
    #[inline]
    fn complete_floating_point(
        &mut self,
        word: u32,
        operation: &FloatingPointOperation,
    ) -> Result<(), stela_compiler::aarch64::floating::UnsupportedControl> {
        #[cfg(all(feature = "std", feature = "native-profile"))]
        if let Some(profile) = &mut self.floating_profile
            && profile.tick()
        {
            return profile.complete_at(&mut self.cpu, word, operation);
        }
        #[cfg(not(all(feature = "std", feature = "native-profile")))]
        let _ = word;
        crate::floating::complete(&mut self.cpu.state, operation)
    }
}

pub struct Machine<H: Host, D: Devices> {
    /// The running PE.
    pub cpu: Cpu,
    pub host: H,
    pub devices: D,
    pub profile: CpuProfile,
    pub statistics: Statistics,
    /// Exits to the engine from compiled code (System, FP, PAC and AMX), by
    /// the instruction word that took them, except those the live blocks
    /// count at their last instructions (see [`Self::exit_words`]).
    exit_words: BTreeMap<u32, u64>,
    #[cfg(all(feature = "std", feature = "native-profile"))]
    floating_profile: Option<alloc::boxed::Box<floating_profile::Sampler>>,
    #[cfg(all(feature = "std", feature = "native-profile"))]
    preparation_metrics: Option<metrics::PreparationMetrics>,
    target: TargetCpu,
    blocks: Vec<Block>,
    /// Slots of `blocks` whose code was reclaimed, for new blocks.
    free_blocks: Vec<usize>,
    /// The fault recovery tables of the blocks that have entries, by block
    /// index: where their regions keep guest GPRs out of the frame across a
    /// faultable access, which a native fault applies first. Kept apart
    /// from [`Block`], whose fields every exit reads.
    fault_recovery: BTreeMap<usize, Vec<stela_compiler::block::FaultRecovery>>,
    /// Blocks by PC, PA, FP enablement and SP alignment checking.
    index: BTreeMap<(u64, u64, Variant), usize>,
    /// The `index` keys of the blocks compiled from each physical page.
    code_pages: BTreeMap<u64, Vec<(u64, u64, Variant)>>,
    /// The fetch pages read for the translation store, by physical page,
    /// until their code is invalidated or they are the least recently used
    /// ([`stored`]), and the count of their uses so far.
    pages: BTreeMap<u64, stored::StoredPage>,
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
    /// The context numbers of the current generations, by EL (with the
    /// guarded level) and variant; numbers are never reused.
    contexts: Vec<(u8, Variant, u64)>,
    /// The translation and code generations `contexts` are for, and the
    /// next number.
    context_generations: (u64, u64),
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
    /// The running PE's device lines and the count before which no device
    /// changes state by itself (`Devices::deadline`), while valid: a device
    /// or board register access, a System register write, an exception and
    /// a PE switch can change them, and clear it.
    device_lines: Option<(Lines, u64)>,
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
    /// Explicitly qualified retained core/cluster clock and quiesce inputs.
    processor_power: Processors,
    /// Actual native-worker publication inventory; absent in the serial lane.
    native_publication: Option<processors::publication::WorkerPublications>,
    /// Identity of this Machine's persistent checked PE memory/event owners.
    native_memory_identity: Arc<()>,
    /// Every assigned worker, held while the BSP executes all canonical PEs
    /// in turn through chained native blocks (`run_serialized`).
    serial_hold: Option<processors::publication::StoppedWorkers>,
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
    /// Stop at the first operation the machine cannot carry out in full
    /// instead of answering it degraded (`set_strict`).
    strict: bool,
    /// Every degraded operation met so far, each the first time, and those
    /// not yet taken (`take_unmodeled`); device accesses are keyed by
    /// register and direction in `degraded_devices`.
    unmodeled_met: Vec<RequirementKind>,
    unmodeled: Vec<Requirement>,
    /// The block count at which the running PE's time slice ends.
    slice_end: u64,
    /// The system counter value at which it ends, whichever comes first.
    slice_deadline: u64,
    /// The system counter the PEs observe (`clock`).
    clock: clock::Clock,
    /// End waits of every PE by leaping the counter (`clock::Clock::skip_to`).
    idle_skip: bool,
    /// The longest one wait of every PE lasts in system counter ticks
    /// before `run` returns [`Stop::Waiting`] (`set_wait_limit`).
    wait_limit: Option<u64>,
    /// The instruction just completed wrote PSTATE.PACM (PACM, or an
    /// exception return), so it does not lapse.
    pacm_written: bool,
    /// The instruction the engine is completing, already counted as retired
    /// (`Machine::completing`).
    completing: Option<u64>,
    /// The chaining state native code updates (`x86_64::chain`).
    chain: alloc::boxed::Box<ChainControl>,
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
    /// The device registers and directions whose degraded answer has been
    /// reported (`take_unmodeled`).
    degraded_devices: BTreeSet<(u64, bool)>,
    /// The context leaves SVE and SME instructions run as, by PC, word and
    /// scalable profile ([`scalable`]); discarded with the blocks.
    scalable_leaves:
        BTreeMap<(u64, u32, stela_compiler::extended::ScalableProfile), scalable::Leaf>,
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
    /// indices retain their original order. This selects no native executor.
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
            exit_words: BTreeMap::new(),
            #[cfg(all(feature = "std", feature = "native-profile"))]
            floating_profile: None,
            #[cfg(all(feature = "std", feature = "native-profile"))]
            preparation_metrics: None,
            target,
            blocks: Vec::new(),
            free_blocks: Vec::new(),
            fault_recovery: BTreeMap::new(),
            index: BTreeMap::new(),
            code_pages: BTreeMap::new(),
            pages: BTreeMap::new(),
            page_uses: 0,
            stored_contexts: BTreeMap::new(),
            preparations: BTreeMap::new(),
            fetch: vec![None; FETCH_CACHE],
            jump: vec![None; JUMP_CACHE],
            translation_generation: 1,
            code_generation: 1,
            targets: vec![chain::LookupEntry::default(); chain::LOOKUP_ENTRIES].into_boxed_slice(),
            contexts: Vec::new(),
            context_generations: (0, 0),
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
            native_memory_identity: Arc::new(()),
            serial_hold: None,
            pending_device_read: None,
            pending_device_write: None,
            pending_device_tail: alloc::collections::VecDeque::new(),
            breakpoints: Vec::new(),
            traces: Vec::new(),
            trace_hits: Vec::new(),
            monitor_tracing: false,
            watches: Vec::new(),
            watch_hits: Vec::new(),
            strict: true,
            unmodeled_met: Vec::new(),
            unmodeled: Vec::new(),
            slice_end: processors::QUANTUM,
            slice_deadline: u64::MAX,
            clock: clock::Clock::default(),
            idle_skip: false,
            wait_limit: None,
            pacm_written: false,
            completing: None,
            chain: alloc::boxed::Box::default(),
            block_limit: u64::MAX,
            suspended: BTreeMap::new(),
            translated_pages: BTreeSet::new(),
            first_translated: None,
            survey: None,
            degraded_devices: BTreeSet::new(),
            scalable_leaves: BTreeMap::new(),
            tags: crate::machine::tags::Store::default(),
            tag_checks: [false; 2],
            tags_checked_at: None,
        };
        machine.chain.table = machine.targets.as_ptr() as u64;
        machine.peers = processors::boot(&machine.profile, boot_processor);
        machine.load_profile();
        machine.sync_regime();
        Ok(machine)
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
        self.native_system = None;
        self.debug = None;
        self.reopen_pointers();
        // A closed cell keeps no value a mispredicted native read could use
        // (FEAT_CSV3's System register rule).
        *self.mirrors = Mirrors::default();
        self.device_lines = None;
    }

    /// The PAC service after a derived-state change: what native code had
    /// open reopens under the new keys, version, layout, enables and traps,
    /// exactly as the PAC exits that opened it would now decide, so the
    /// change costs no exit of its own. PACM changes the next instruction's
    /// operands, which no thunk applies: everything stays closed.
    fn reopen_pointers(&mut self) {
        if !self.pointer.any_open() || self.cpu.pstate.pacm {
            self.pointer.close();
            return;
        }
        let Ok(version) = self.pointer_version() else {
            self.pointer.close();
            return;
        };
        let inputs = PointerInputs {
            keys: self.pointer_keys(),
            version,
            tcr: self.cpu.regime_tcr(),
        };
        let stripping = self.pointer.revalidate(inputs);
        let trapped = self.pointer_authentication_trapped();
        for (key, block) in [
            (pauth::Key::Ia, PointerAuthenticationKey::Ia),
            (pauth::Key::Ib, PointerAuthenticationKey::Ib),
            (pauth::Key::Da, PointerAuthenticationKey::Da),
            (pauth::Key::Db, PointerAuthenticationKey::Db),
        ] {
            let enabled = self.key_enabled(block);
            self.pointer.reopen(key, enabled, trapped);
        }
        for (data, open) in [false, true].into_iter().zip(stripping) {
            if open {
                self.pointer.reopen_stripping(data);
            }
        }
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
    /// alignment, A (Arm `AlignmentEnforced`) and nAA; and, where
    /// ID_AA64PFR0_EL1.CSV3 discloses FEAT_CSV3, the guest range check at
    /// every access (`identification::Speculation::faulting_data`).
    fn memory_checks(&mut self) -> MemoryChecks {
        *self.memory_checks.get_or_insert_with(|| {
            let sctlr = self.cpu.regime_sctlr();
            let bit = if self.cpu.pstate.el == 0 { 4 } else { 3 };
            MemoryChecks::system(
                sctlr & (1 << bit) != 0,
                sctlr & mmu::alignment::SCTLR_A != 0,
                sctlr & mmu::alignment::SCTLR_NAA == 0,
                self.cpu
                    .field(SystemRegister::ID_AA64PFR0_EL1, CSV3_SHIFT, 4)
                    != 0,
            )
            .with_range(self.host.placement().check())
        })
    }

    fn native_system(&mut self) -> NativeSystem {
        *self.native_system.get_or_insert_with(|| NativeSystem {
            zero_block: system::native_zero_block(&self.cpu, &self.profile_missing),
            cache_clean: system::native_cache_clean(&self.cpu),
        })
    }

    fn sync_regime(&mut self) {
        self.derived_changed();
        self.sync_host_regime();
    }

    /// The host's view of the regime (shadow root, requester, watchpoints and
    /// tag checks) and the PMU's and prediction contexts follow the PE, with
    /// state derived from System registers left as it is.
    fn sync_host_regime(&mut self) {
        self.sync_monitor();
        let watch = Watch {
            pass: self.watch.pass,
            ..Watch::from_ranges(&debug::watched(&self.cpu))
        };
        if watch.ranges != self.watch.ranges {
            // Newly watched pages must leave the shadow tables.
            self.advance_translation_generation();
            self.host.invalidate_translations();
        }
        self.watch = watch;
        self.tag_checks = self.cpu.tag_checks();
        let regime = Regime {
            controls: self.cpu.controls(self.cpu.regime()),
            requester: self.cpu.requester(),
            watch,
            tag_checks: self.tag_checks,
        };
        self.host.set_regime(&regime);
        let context = PredictionContext::of(&self.cpu);
        if self.prediction_context != Some(context) {
            self.prediction_context = Some(context);
            self.statistics.prediction_isolations += 1;
            self.host.isolate_predictions();
        }
    }

    /// Stop the run when any PE reaches one of these guest PCs, before its
    /// instruction executes: a diagnostic of the host, invisible to the
    /// guest. Compiled code is discarded so no block runs past one.
    pub fn set_breakpoints(&mut self, pcs: &[u64]) {
        self.breakpoints = pcs.to_vec();
        self.breakpoints.sort_unstable();
        self.breakpoints.dedup();
        self.discard_code();
    }

    /// Run host-side work on the devices, such as an external peer's
    /// computation, between steps: the host time it takes is not guest
    /// time, so the system counter does not advance across it.
    pub fn exclude_host_time<T>(&mut self, work: impl FnOnce(&mut D) -> T) -> T {
        let before = self.host.counter();
        let result = work(&mut self.devices);
        let after = self.host.counter();
        self.clock.exclude(after.saturating_sub(before));
        result
    }

    /// End every wait of all PEs at once by leaping the system counter to
    /// the next deadline instead of waiting on the host: guest sleeps cost no
    /// host time, and time of day runs ahead of the host's (`clock`).
    pub fn set_idle_skip(&mut self, skip: bool) {
        self.idle_skip = skip;
    }

    /// Keep the system counter at the host's: no slow slice holds it back
    /// (`clock::Clock::follow_host`). For a machine that is one thread of a
    /// hosted process, whose threads each run their own machine and must
    /// read one clock.
    pub fn follow_host_counter(&mut self) {
        self.clock.follow_host();
    }

    /// The architectural system count and each generic timer's `(CTL, CVAL)`
    /// in [`timer::CHANNELS`] order, sampled at that count, of the bank that
    /// counts it: the Apple generic timer's from the M3 on, where the kernel
    /// keeps its timer (`timer::agt`). Diagnostics must use this count,
    /// including slice lag and idle leaps, just as guest register reads and
    /// timer delivery do; the host counter can differ.
    pub fn timer_snapshot(&mut self) -> (u64, [(u64, u64); 4]) {
        let now = self.now();
        let bank = timer::system_bank(&self.cpu);
        let timers = timer::CHANNELS.map(|channel| {
            (
                channel.read_control(&self.cpu, bank, now),
                timer::value(&self.cpu, bank, channel.compare),
            )
        });
        (now, timers)
    }

    /// Bound each wait of every PE on the host to `limit` system counter
    /// ticks, after which `run` returns [`Stop::Waiting`] so the host can
    /// take inputs that reach the board from outside it, such as its power
    /// button. The counter keeps following the host's meanwhile; an idle
    /// skip, which leaps to a deadline at once, is not bounded. Without a
    /// limit a wait lasts until a deadline.
    pub fn set_wait_limit(&mut self, limit: Option<u64>) {
        self.wait_limit = limit.map(|limit| limit.max(1));
    }

    /// Record, without stopping, when a PE reaches one of these guest PCs
    /// as a block start through the engine: always its first execution
    /// there, then whenever no chained block enters it directly. Like a
    /// breakpoint, a host diagnostic invisible to the guest.
    pub fn set_traces(&mut self, pcs: &[u64]) {
        self.traces = pcs.to_vec();
        self.traces.sort_unstable();
        self.traces.dedup();
        self.discard_code();
    }

    /// Record, without stopping, every device access whose first byte lies
    /// in one of these physical ranges (base, bytes). A host diagnostic
    /// invisible to the guest.
    pub fn set_watches(&mut self, ranges: &[(u64, u64)]) {
        self.watches = ranges
            .iter()
            .filter(|&&(_, bytes)| bytes != 0)
            .map(|&(base, bytes)| (base, base.saturating_add(bytes - 1)))
            .collect();
    }

    /// The watch hits since the last call, oldest first, at most
    /// [`WATCH_HITS`] of them; later hits are counted in the last one.
    pub fn take_watch_hits(&mut self) -> Vec<WatchHit> {
        core::mem::take(&mut self.watch_hits)
    }

    /// Strict mode, the default (tests, `cargo xtask differential`,
    /// benchmarks): stop at the first operation this machine cannot carry
    /// out in full (`Stop::Unsupported`). Graceful mode (`false`, a user's
    /// boot) answers each with its tier's degraded response, reports it
    /// once and continues ([`Self::degrade`]; docs/design/runtime.md
    /// #unsupported-operations).
    pub fn set_strict(&mut self, strict: bool) {
        self.strict = strict;
    }

    /// What iBoot left in the core lock registers (`machine::ctrr`): every
    /// cluster and PE takes it now, and again when it starts. The boot
    /// mount calls this before the first instruction.
    pub fn hand_off_core_locks(&mut self, handoff: ctrr::Handoff) {
        let handoff = alloc::rc::Rc::new(handoff);
        let parked = self.peers.iter_mut().filter_map(|peer| match peer {
            processors::Peer::Parked(parked) => Some(parked.cpu_mut()),
            _ => None,
        });
        for cpu in core::iter::once(&mut self.cpu).chain(parked) {
            cpu.ctrr.replace(ctrr::Cluster::handed_off(&handoff));
            cpu.ctrr_core = ctrr::Core::handed_off(&handoff);
            cpu.core_locks = handoff.clone();
        }
        self.translations_changed();
    }

    /// The operations since the last call that were answered degraded, each
    /// distinct one reported the first time only, for the boot log.
    pub fn take_unmodeled(&mut self) -> Vec<Requirement> {
        core::mem::take(&mut self.unmodeled)
    }

    /// The policy point for an operation this machine cannot carry out in
    /// full: strict, its stop; graceful, `Ok` after counting it
    /// (`Statistics::degraded`) and reporting it the first time (device
    /// accesses once per register and direction), the caller then giving
    /// the degraded response of its tier.
    fn degrade(&mut self, requirement: Requirement) -> Step {
        if self.strict {
            return Err(Stop::Unsupported(requirement));
        }
        self.statistics.degraded += 1;
        let first = match &requirement.kind {
            RequirementKind::Device {
                physical, write, ..
            } => self.degraded_devices.insert((*physical, *write)),
            kind if self.unmodeled_met.contains(kind) => false,
            kind => {
                self.unmodeled_met.push(kind.clone());
                true
            }
        };
        if first {
            self.unmodeled.push(requirement);
        }
        Ok(())
    }

    /// Graceful mode's answer to an instruction the engine cannot execute,
    /// at the run loop: the UNDEFINED exception at its PC, which an Apple CPU
    /// takes for an encoding it does not implement. Only a stop raised
    /// before the instruction's effects (the PE still at its PC and EL) on a
    /// serially executing PE qualifies; every other stop stands.
    fn undefined_instead(&mut self, stop: Stop) -> Step {
        let Stop::Unsupported(requirement) = stop else {
            return Err(stop);
        };
        let instruction = matches!(
            requirement.kind,
            RequirementKind::Instruction { .. }
                | RequirementKind::SystemInstruction { .. }
                | RequirementKind::SystemRegister { .. }
        );
        if self.strict
            || !instruction
            || requirement.pc != self.cpu.pc
            || requirement.el != self.cpu.pstate.el
            || self.cpu.has_canonical_memory() && self.serial_hold.is_none()
            || self.pending_native_device_access().is_some()
        {
            return Err(Stop::Unsupported(requirement));
        }
        self.degrade(requirement)?;
        self.undefined()
    }

    fn watch(&mut self, physical: u64, bytes: u8, value: Option<u64>, write: bool) {
        if !self
            .watches
            .iter()
            .any(|&(first, last)| (first..=last).contains(&physical))
        {
            return;
        }
        if self.watch_hits.len() == WATCH_HITS {
            if let Some(last) = self.watch_hits.last_mut() {
                last.dropped += 1;
            }
            return;
        }
        self.watch_hits.push(WatchHit {
            pc: self.cpu.pc,
            pe: self.current,
            physical,
            bytes,
            value: value.unwrap_or(0),
            write,
            completed: value.is_some(),
            dropped: 0,
        });
    }

    /// A device read by the running PE, watched.
    fn device_read(&mut self, physical: u64, bytes: u8, now: u64) -> Result<u64, DeviceError> {
        if self.devices.requires_canonical_read(
            self.current,
            physical,
            DeviceReadShape::Scalar { bytes },
        ) {
            self.host.speculation_barrier();
            let consumed =
                self.serial_read_canonical(physical, DeviceReadShape::Scalar { bytes }, now);
            let result = consumed.and_then(|consumed| {
                consumed.settlement?;
                Ok(consumed.values[0])
            });
            self.watch(physical, bytes, result.as_ref().ok().copied(), false);
            return result;
        }
        self.host.speculation_barrier();
        if let Some(cpu) = self.devices.pc_sample_target(physical, bytes) {
            let pc = self.processor_pc(cpu).ok_or_else(|| {
                DeviceError::Refused(format!(
                    "debug PC sample: PE {cpu} has no powered execution state"
                ))
            })?;
            self.devices.observe_pc_sample(physical, pc);
        }
        let result = self.devices.read(self.current, physical, bytes, now);
        self.watch(physical, bytes, result.as_ref().ok().copied(), false);
        result
    }

    /// A device write by the running PE, watched.
    fn device_write(
        &mut self,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<(), DeviceError> {
        let result = if self.serial_hold.is_some() {
            self.serial_write_canonical(physical, bytes, value, now)
        } else {
            let current = self.current;
            let (devices, processors) = self.processor_write_parts();
            devices.write_with_processors(current, physical, bytes, value, now, processors)
        };
        self.watch(physical, bytes, result.is_ok().then_some(value), true);
        result
    }

    /// Native DMA/session service errors cannot become unknown-register
    /// substitutions. Enforce that boundary even
    /// when a provider returns an ordinary register error from its service.
    fn device_transfer(&mut self, now: u64) -> Result<(), DeviceError> {
        // A just-accepted lock write precedes follow_memory_lock(), so query
        // its actual device owner rather than the CPU's previous snapshot.
        let mut memory = HostMemory {
            host: &mut self.host,
            lock: self.devices.memory_lock(),
        };
        match self.devices.transfer(self.current, &mut memory, now) {
            Ok(()) => Ok(()),
            Err(DeviceError::Refused(reason) | DeviceError::TransferRefused(reason)) => {
                Err(DeviceError::TransferRefused(reason))
            }
            Err(DeviceError::NoDevice) => Err(DeviceError::TransferRefused(
                "device DMA has no service model".into(),
            )),
        }
    }

    /// The trace hits since the last call, oldest first, at most
    /// [`TRACE_HITS`] of them; later hits are counted in the last one.
    pub fn take_trace_hits(&mut self) -> Vec<TraceHit> {
        core::mem::take(&mut self.trace_hits)
    }

    /// Check every reachable compiled block against the guest bytes it was
    /// compiled from: a diagnostic of code changed without the IC
    /// maintenance that would discard its blocks.
    pub fn stale_code(&mut self) -> StaleCode {
        let mut report = StaleCode::default();
        let mut bytes = Vec::new();
        for &index in self.index.values() {
            let block = &self.blocks[index];
            bytes.resize(block.source_bytes, 0);
            report.blocks += 1;
            if self.host.read_ram(block.physical, &mut bytes)
                && source_hash(&bytes) != block.source_hash
            {
                report.stale += 1;
                report.first.get_or_insert((block.pc, block.physical));
            }
        }
        report
    }

    /// An architectural cache epoch must never wrap back to an old authority.
    fn advance_translation_generation(&mut self) {
        self.translation_generation = self
            .translation_generation
            .checked_add(1)
            .expect("architectural translation generation exhausted");
    }

    fn translations_changed(&mut self) {
        self.advance_translation_generation();
        self.statistics.translation_changes += 1;
        self.host.invalidate_translations();
        self.sync_regime();
    }

    /// The host's answers to [`Host::fetch_permitted`] changed: every later
    /// fetch translates and asks again, and no cached, looked-up or chained
    /// transfer enters a block of another page before it has.
    pub fn fetch_permissions_changed(&mut self) {
        self.advance_translation_generation();
    }

    /// A TLBI: the fetch translations of every regime go, and the host
    /// drops what `reach` names of its shadow. No control changed, so the
    /// regime and what derives from System registers stay.
    fn tlb_maintained(&mut self, reach: mmu::tlbi::Reach) {
        self.advance_translation_generation();
        self.statistics.tlb_maintenance += 1;
        if reach != mmu::tlbi::Reach::All {
            self.statistics.scoped_maintenance += 1;
        }
        self.host.invalidate_reach(reach);
    }

    /// A TTBR0 write, which changes the translation of the lower half
    /// alone: the regime's new controls tell the host so
    /// ([`Host::set_regime`]), which keeps the upper half's shadow.
    fn table_base_changed(&mut self) {
        self.advance_translation_generation();
        self.statistics.table_base_changes += 1;
        self.sync_regime();
    }

    /// Forget the blocks compiled from the page holding `physical`, which an
    /// IC IVAU made stale: a later fetch compiles the page again. Their code
    /// stays installed until the next full discard.
    fn invalidate_code_page(&mut self, physical: u64) {
        self.pages.remove(&(physical & !(FETCH_PAGE - 1)));
        let Some(keys) = self.code_pages.remove(&(physical & !(FETCH_PAGE - 1))) else {
            return;
        };
        for key in keys {
            self.index.remove(&key);
        }
        // The jump cache holds no generation per page.
        self.code_generation += 1;
        self.statistics.code_invalidations += 1;
    }

    /// Make room in the code arena: reclaim its oldest part, or discard
    /// every block on a host whose arena is one part.
    fn reclaim_code(&mut self) {
        match self.host.reclaim_code() {
            Some(range) => self.evict_code(range),
            None => self.discard_code(),
        }
    }

    /// Forget the blocks and leaves whose code lies in `range`, which the
    /// host reclaimed. A block of the same page may chain into an evicted
    /// one, so an evicted block's page is forgotten whole, as an IC IVAU
    /// forgets it: its other blocks become unreachable and are freed when
    /// their own code is reclaimed. A block no longer indexed has no live
    /// chain into it, as its page was forgotten whole then.
    fn evict_code(&mut self, range: core::ops::Range<usize>) {
        let evicted: Vec<usize> = (0..self.blocks.len())
            .filter(|&slot| range.contains(&self.blocks[slot].code.0))
            .collect();
        for &slot in &evicted {
            let block = &self.blocks[slot];
            if self.index.get(&(block.pc, block.physical, block.variant)) != Some(&slot) {
                continue;
            }
            let page = block.physical & !(FETCH_PAGE - 1);
            for key in self.code_pages.remove(&page).unwrap_or_default() {
                self.index.remove(&key);
            }
        }
        for &slot in &evicted {
            let block = &mut self.blocks[slot];
            if block.taken != 0 {
                *self.exit_words.entry(block.terminal.1).or_default() += block.taken;
            }
            block.code = NativeCode(0);
            block.taken = 0;
            block.dynamic_site = None;
            block.source_map = Vec::new();
            block.successors = Vec::new();
            self.fault_recovery.remove(&slot);
            self.free_blocks.push(slot);
        }
        self.scalable_leaves
            .retain(|_, leaf| !range.contains(&leaf.code.0));
        if !evicted.is_empty() {
            // The jump cache and lookup entries hold no generation per
            // block.
            self.code_generation += 1;
            self.statistics.code_evictions += 1;
        }
    }

    fn discard_code(&mut self) {
        self.exit_words = self.exit_words();
        self.host.discard_code();
        self.blocks.clear();
        self.free_blocks.clear();
        self.fault_recovery.clear();
        self.index.clear();
        self.code_pages.clear();
        self.pages.clear();
        self.scalable_leaves.clear();
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
        let trace = self.monitor_before(MonitorKind::Exception {
            vector: exception.vector,
            syndrome: exception.syndrome,
            return_address: exception.return_address,
            fault_address: exception.fault_address,
        });
        let (from_el, from_guarded) = (self.cpu.pstate.el, self.cpu.pstate.guarded);
        self.cpu.take(exception);
        self.statistics.exceptions += 1;
        self.host.report(&Event::Exception {
            vector: exception.vector,
            from_el,
            from_guarded,
            syndrome: exception.syndrome,
            return_address: exception.return_address,
            fault_address: exception.fault_address,
        });
        self.monitor_after(trace);
        self.sync_regime();
    }

    /// The system counter's count (`clock`).
    pub(super) fn now(&mut self) -> u64 {
        let host = self.host.counter();
        self.clock.read(host)
    }

    fn lines(&mut self) -> Lines {
        // The count is read only when an answer can change with it alone: a
        // device answer with a deadline, a timer's or a PMI's. Every exit
        // asks, and a hosted process's PE has none of them.
        let timed = !matches!(self.device_lines, Some((_, u64::MAX)))
            || self.timer_deadline().is_some()
            || self
                .cpu
                .pmu
                .as_ref()
                .is_some_and(|monitor| monitor.deadline().is_some());
        let now = if timed { self.now() } else { 0 };
        let device = match self.device_lines {
            Some((lines, until)) if now < until => lines,
            _ => {
                #[cfg(feature = "native-profile")]
                let profile_started = self
                    .host
                    .native_timing_work_start(NativeTimingWork::DeviceLines);
                let lines = self.devices.lines(self.current, now);
                let until = self.devices.deadline(now).unwrap_or(u64::MAX);
                #[cfg(feature = "native-profile")]
                if let Some(started) = profile_started {
                    self.host
                        .native_timing_work_end(NativeTimingWork::DeviceLines, started);
                }
                self.device_lines = Some((lines, until));
                lines
            }
        };
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

    /// Bring the running PE's performance monitor and activity monitors up
    /// to now and continue counting in its current EL and wait state. Every
    /// change of either passes here: exception entry and return through
    /// `sync_regime`, and the start and end of a wait.
    pub(super) fn sync_monitor(&mut self) {
        let context = self
            .cpu
            .pmu_context(self.waiting.is_some() || self.processor_paused(self.current));
        let retired = self.cpu.retired;
        let pmu_timed = self.cpu.pmu.as_ref().map(|monitor| monitor.timed());
        let amu_timed = self.cpu.amu.as_ref().map(|monitors| monitors.timed());
        if pmu_timed.is_none() && amu_timed.is_none() {
            return;
        }
        // Without a cycle counter nothing counts time, so the count need not
        // be read.
        let now = if pmu_timed == Some(true) || amu_timed == Some(true) {
            self.now()
        } else {
            0
        };
        if let Some(monitor) = self.cpu.pmu.as_mut() {
            monitor.sync(now, retired, context);
        }
        if let Some(monitors) = self.cpu.amu.as_mut() {
            monitors.sync(now, retired, context.waiting);
        }
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

    /// Whether an interrupt routed to `target` is taken now (Arm ARM D1.3.6;
    /// QEMU `arm_excp_unmasked`): never when it targets a lower EL. Its
    /// PSTATE mask applies at the same EL, to EL1 from EL0, and to EL2 from
    /// EL0 in the host (HCR_EL2.{E2H,TGE} {1,1}; E2H is RES1 on Apple
    /// cores); EL2 from EL0 or EL1 otherwise ignores it.
    fn taken(&self, target: u8, mask: u8) -> bool {
        let el = self.cpu.pstate.el;
        let maskable = target == el || target == 1 || self.cpu.in_host();
        target >= el && (!maskable || self.cpu.pstate.daif & mask == 0)
    }

    /// Take a pending interrupt before the next instruction: the physical
    /// lines routed by HCR_EL2.{TGE,IMO,FMO}, then the virtual IRQ, FIQ and
    /// SError that HCR_EL2.{VI,VF,VSE} hold for EL1 and EL0 outside the host.
    fn deliver_interrupts(&mut self) -> bool {
        let lines = self.lines();
        let virtual_pending = self.cpu.pstate.el != 2
            && [HCR_VI, HCR_VF, HCR_VSE]
                .into_iter()
                .any(|bit| self.cpu.virtual_pending(bit));
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
                    && self.cpu.virtual_pending(virtual_bit)
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
            self.cpu.signal_event();
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

    /// For diagnostics: which parts of the running regime's TTBR1 range
    /// its tables map, read from RAM without changing anything. `None`
    /// unless the regime has two ranges, its MMU is on, TTBR1 walks are
    /// enabled and its walks start at level 1 of a 16 KiB granule (T1SZ
    /// 17 to 27, as 26A434 XNU's T1SZ_BOOT 17), or the root is not RAM.
    pub fn upper_occupancy(&mut self) -> Option<Occupancy> {
        const TG1_16K: u64 = 0b01;
        const LEVEL1_SHIFT: u32 = 36;
        const LEVEL2_SHIFT: u32 = 25;
        const VALID: u64 = 1;
        const TABLE: u64 = 0b11;
        const ADDRESS: u64 = 0x0000_ffff_ffff_c000;
        let controls = self.cpu.controls(self.cpu.regime());
        let tcr = controls.tcr;
        let t1sz = (tcr >> 16 & 0x3f) as u32;
        let epd1 = tcr >> 23 & 1 != 0;
        if controls.regime == mmu::Regime::El2
            || controls.sctlr & 1 == 0
            || epd1
            || tcr >> 30 & 0b11 != TG1_16K
            || !(17..=27).contains(&t1sz)
        {
            return None;
        }
        let entries = 1usize << (64 - t1sz - LEVEL1_SHIFT);
        let root = controls.ttbr1 & ADDRESS & !((entries as u64 * 8).max(64) - 1);
        let mut table = alloc::vec![0u8; entries * 8];
        if !self.host.read_ram(root, &mut table) {
            return None;
        }
        let descriptor = |bytes: &[u8], index: usize| {
            u64::from_le_bytes(bytes[index * 8..][..8].try_into().unwrap())
        };
        let base = u64::MAX << (64 - t1sz);
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut valid = Vec::new();
        for index in 0..entries {
            if descriptor(&table, index) & VALID == 0 {
                continue;
            }
            valid.push(index);
            let first = base + ((index as u64) << LEVEL1_SHIFT);
            let last = first + ((1u64 << LEVEL1_SHIFT) - 1);
            match ranges.last_mut() {
                Some(range) if range.1.wrapping_add(1) == first => range.1 = last,
                _ => ranges.push((first, last)),
            }
        }
        // The lowest and highest mapped 32 MiB, one level below the
        // outermost level-1 entries.
        let mut edge = |index: usize, highest: bool| -> u64 {
            let start = base + ((index as u64) << LEVEL1_SHIFT);
            let entry = descriptor(&table, index);
            let mut next = alloc::vec![0u8; 2048 * 8];
            let table_read =
                entry & TABLE == TABLE && self.host.read_ram(entry & ADDRESS, &mut next);
            let mut slots =
                (0..2048).filter(|&slot| table_read && descriptor(&next, slot) & VALID != 0);
            let slot = if highest {
                slots.next_back()
            } else {
                slots.next()
            };
            let (first, bytes) = match slot {
                Some(slot) => (start + ((slot as u64) << LEVEL2_SHIFT), 1 << LEVEL2_SHIFT),
                None => (start, 1u64 << LEVEL1_SHIFT),
            };
            if highest { first + (bytes - 1) } else { first }
        };
        let lowest = valid.first().map(|&index| edge(index, false));
        let highest = valid.last().map(|&index| edge(index, true));
        Some(Occupancy {
            root,
            ranges,
            lowest,
            highest,
        })
    }

    /// `pointer` without its PAC, laid out as an instruction address in the
    /// current regime (Arm `XPACI`), for diagnostics such as return
    /// addresses in frame records; unchanged without a PAC layout.
    pub fn strip_instruction_pointer(&self, pointer: u64) -> u64 {
        self.pointer_context()
            .ok()
            .and_then(|context| context.strip(pauth::Key::Ia, pointer).ok())
            .unwrap_or(pointer)
    }

    /// Research only: from now on a device access the devices refuse, or
    /// that reaches no device, completes as a zero read or a discarded
    /// write and is recorded instead of stopping the machine. The values
    /// are invented, so a surveyed run proves nothing about the guest; it
    /// lists every register a driver needs in one run.
    pub fn begin_survey(&mut self) {
        self.survey = Some(Survey::default());
    }

    /// The registers the survey answered first since the last call, with
    /// their counts so far.
    pub fn take_survey(&mut self) -> Vec<Surveyed> {
        let Some(survey) = self.survey.as_mut() else {
            return Vec::new();
        };
        let fresh = core::mem::take(&mut survey.fresh);
        fresh
            .into_iter()
            .filter_map(|key| survey.records.get(&key).cloned())
            .collect()
    }

    /// Whether a survey answered the refused access; `value` is a write's.
    fn surveyed(
        &mut self,
        physical: u64,
        bytes: u8,
        write: Option<u64>,
        error: &DeviceError,
    ) -> bool {
        if matches!(error, DeviceError::TransferRefused(_)) {
            return false;
        }
        let pc = self.cpu.pc;
        let link = self.strip_instruction_pointer(self.cpu.state.x[30]);
        let Some(survey) = self.survey.as_mut() else {
            return false;
        };
        let key = (physical, write.is_some());
        let record = survey.records.entry(key).or_insert_with(|| {
            survey.fresh.push(key);
            Surveyed {
                physical,
                bytes,
                write: write.is_some(),
                pc,
                link,
                count: 0,
                value: 0,
                detail: match error {
                    DeviceError::NoDevice => "no device model".into(),
                    DeviceError::Refused(detail) | DeviceError::TransferRefused(detail) => {
                        detail.clone()
                    }
                },
            }
        });
        record.count += 1;
        record.value = write.unwrap_or(0);
        true
    }

    /// Guest threads by thread pointer, with where each stopped running,
    /// while they stay suspended.
    pub fn suspended(&self) -> &BTreeMap<u64, Suspension> {
        &self.suspended
    }

    /// Record that software at `now` replaces the running thread pointer
    /// (TPIDR_EL1) with `next`: the thread it named is suspended where the
    /// PE stands, and `next` runs.
    fn trace(&mut self, pc: u64) {
        if self.trace_hits.len() == TRACE_HITS {
            if let Some(last) = self.trace_hits.last_mut() {
                last.dropped += 1;
            }
            return;
        }
        let x = &self.cpu.state.x;
        self.trace_hits.push(TraceHit {
            pc,
            pe: self.current,
            el: self.cpu.pstate.el,
            arguments: [x[0], x[1], x[2], x[3]],
            lr: x[30],
            dropped: 0,
        });
    }

    fn switch_thread(&mut self, next: u64, now: u64) {
        let previous = self.cpu.read(SystemRegister::TPIDR_EL1);
        if previous == next {
            return;
        }
        self.suspended.remove(&next);
        if previous != 0 && self.suspended.len() < SUSPENSIONS {
            let state = &self.cpu.state;
            let suspension = Suspension {
                at: now,
                pc: self.cpu.pc,
                frame: state.x[29],
                link: state.x[30],
            };
            self.suspended.insert(previous, suspension);
        }
    }

    /// Run until a stop. `budget` limits executed blocks (0 = unlimited).
    pub fn run(&mut self, budget: u64) -> Stop {
        if let Some(pending) = self.pending_native_device_access() {
            return pending;
        }
        if self.cpu.has_canonical_memory() || self.peers.iter().any(|peer|
            matches!(peer, processors::Peer::Parked(parked) if parked.cpu().has_canonical_memory())) {
            return self.unsupported(RequirementKind::Native(
                "converted shared-memory PEs run only through run_serialized or the native scheduler",
            ));
        }
        self.run_blocks(budget)
    }

    /// The serial scheduler and chained native blocks, until a stop.
    pub(super) fn run_blocks(&mut self, budget: u64) -> Stop {
        self.block_limit = if budget == 0 { u64::MAX } else { budget };
        loop {
            if self.statistics.blocks >= self.block_limit {
                return Stop::Budget;
            }
            if let Err(stop) = self
                .schedule()
                .and_then(|()| self.step())
                .or_else(|stop| self.undefined_instead(stop))
            {
                return stop;
            }
        }
    }

    /// The same RAM publication path as MMIO-triggered DMA, reached with no
    /// translated invocation live. Called while running and while all PEs wait.
    fn poll_devices(&mut self, now: u64) -> Step {
        if let Some(deadline) = self.devices.dma_deadline() {
            self.poll_devices_at(now, deadline)?;
        }
        Ok(())
    }

    /// Dispatch need not observe time when no asynchronous DMA is pending.
    /// Scheduler callers already have a timestamp and use `poll_devices`.
    fn poll_due_devices(&mut self) -> Step {
        if let Some(deadline) = self.devices.dma_deadline() {
            let now = self.now();
            self.poll_devices_at(now, deadline)?;
        }
        Ok(())
    }

    fn poll_devices_at(&mut self, now: u64, deadline: u64) -> Step {
        if now >= deadline {
            // A device's asynchronous work it cannot carry out is dropped,
            // reported once, outside strict mode.
            if let Err(error) = self.device_transfer(now) {
                let advance = RequirementKind::DeviceAdvance(format!("{error:?}"));
                self.degrade(self.requirement(advance))?;
            }
            self.device_lines = None;
        }
        Ok(())
    }

    fn step(&mut self) -> Step {
        self.poll_due_devices()?;
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
        if self.breakpoints.binary_search(&pc).is_ok() {
            return Err(Stop::Breakpoint(pc));
        }
        if self.traces.binary_search(&pc).is_ok() {
            self.trace(pc);
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
            Fetched::Checked(word) => {
                let step = self.checked_instruction(pc, word);
                if !core::mem::take(&mut self.pacm_written) && pacm {
                    self.cpu.pstate.pacm = false;
                }
                self.advance_step();
                return step;
            }
        };
        if self.cpu.pstate.btype != 0 && self.fetch_guarded(pc) {
            let word = self.word(index, pc)?;
            if let Some(exception) = self.branch_target_exception(pc, word) {
                self.take(exception);
                return Ok(());
            }
        }
        let step = self.execute(index, if single { 0 } else { self.chain_budget() });
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

    /// An instruction whose FP, SVE, SME and FPMR access checks the engine
    /// applies before it runs: after a Branch Target exception, the first
    /// check that fails traps, or is UNDEFINED (`CheckFPMREnabled`). One
    /// that passes runs on its own: the AdvSIMD FP8 conversions here
    /// ([`Self::fp8_conversion`]), SVE and SME forms through [`scalable`],
    /// and scalar FP in streaming mode as a block that then zeroes the upper
    /// Z bits it wrote.
    #[cold]
    fn checked_instruction(&mut self, pc: u64, word: u32) -> Step {
        if self.cpu.pstate.btype != 0
            && self.fetch_guarded(pc)
            && let Some(exception) = self.branch_target_exception(pc, word)
        {
            self.cpu.step_advance = false;
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
            Err(Denial::Undefined) => return self.undefined(),
            Err(Denial::Unimplemented(feature)) => {
                return Err(self.unsupported(RequirementKind::Instruction {
                    word,
                    detail: format!("its access check needs {feature}, which the engine lacks"),
                }));
            }
            Ok(()) if let Some(operand) = fp8_conversion::decode(word) => {
                return self.fp8_conversion(word, &operand);
            }
            Ok(()) if checks.iter().all(|check| *check == Check::Fp) => {
                return self.streaming_scalar(pc, word);
            }
            Ok(()) => return self.scalable_instruction(pc, word),
        };
        self.cpu.step_advance = false;
        // Arm decodes before it checks access: an SVE or SME word UNDEFINED
        // on this chip takes that instead of the trap.
        if checks.iter().any(|check| *check != Check::Fp) && self.scalable_undefined(pc, word) {
            return self.undefined();
        }
        self.take(exception);
        Ok(())
    }

    /// F1CVTL, F2CVTL, BF1CVTL, BF2CVTL and FCVTN (FP8) and their upper
    /// forms, after their checks passed: the shared FP8 conversion with
    /// FPMR's formats and scales and FPCR, the cumulative exceptions ORed
    /// into FPSR. In streaming mode the V write zeroes the upper Z bits.
    fn fp8_conversion(&mut self, word: u32, operand: &fp8_conversion::Operand) -> Step {
        let Some(fpmr) = self.cpu.scalable.as_ref().map(ScalableState::fpmr) else {
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: "an FP8 conversion on a PE without FPMR".into(),
            }));
        };
        let fpcr = self.cpu.state.fpcr;
        let register = |index: u8| self.cpu.state.v[usize::from(index)];
        let converted = crate::floating::scalable::fixed_fp8_conversion(
            operand,
            register(operand.source),
            register(operand.second_source),
            register(operand.destination),
            fpcr,
            fpmr,
        );
        let Ok((value, exceptions)) = converted else {
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: format!("FPCR {fpcr:#x} enables a trapped FP exception"),
            }));
        };
        let scalable = self.cpu.scalable.as_mut().expect("checked above");
        if let Err(error) = scalable.write_v(&mut self.cpu.state, operand.destination, value) {
            return Err(self.unsupported(RequirementKind::Instruction {
                word,
                detail: format!("its FP8 result cannot be written: {error}"),
            }));
        }
        self.cpu.state.fpsr |= exceptions;
        self.next()
    }

    /// Blocks the next native run may chain into: none past the time slice
    /// or the run's limit.
    fn chain_budget(&self) -> u64 {
        let next = self.statistics.blocks + 1;
        CHAIN_LIMIT
            .min(self.slice_end.saturating_sub(next))
            .min(self.block_limit.saturating_sub(next))
    }

    /// Run compiled block `index` and the blocks it chains into, up to
    /// `budget` of them, and complete the last one's exit or fault.
    fn execute(&mut self, index: usize, budget: u64) -> Step {
        let entry = self.blocks[index].code;
        *self.chain = ChainControl {
            budget,
            retired: 0,
            block: index as u64,
            hits: 0,
            ..*self.chain
        };
        // SAFETY: installed by this machine since the last discard, for the
        // system-mode block ABI; chained blocks and thunks too.
        let exit = unsafe { self.host.execute(entry, &mut self.cpu.state) };
        let control = *self.chain;
        // A thunk that found no transfer left wrapped the budget, after
        // using all of it.
        let chained = budget.checked_sub(control.budget).unwrap_or(budget);
        let last = (control.block & u64::from(u32::MAX)) as usize;
        self.cpu.retired += control.retired;
        self.statistics.blocks += 1 + chained;
        self.statistics.chained += chained;
        self.statistics.lookup_hits += control.hits;
        // A transfer entered the last block, with the BTYPE it names: 0
        // from every thunk but those of BR and BLR forms.
        if chained > 0 {
            self.cpu.pstate.btype = (control.block >> chain::BLOCK_BTYPE_SHIFT) as u8;
        }
        match exit {
            NativeExit::Exit { next_pc, kind } => {
                if let Some(count) = self.statistics.exit_kinds.get_mut(kind as usize) {
                    *count += 1;
                }
                self.exit(last, next_pc, kind)?;
                let btype = self.cpu.pstate.btype;
                match ExitKind::try_from(kind) {
                    Ok(kind @ (ExitKind::Fallthrough | ExitKind::Direct | ExitKind::Call))
                        if btype == 0 =>
                    {
                        self.link(last, next_pc, kind);
                    }
                    Ok(ExitKind::Return | ExitKind::Indirect | ExitKind::Call) => {
                        self.link_dynamic(last, btype);
                    }
                    _ => {}
                }
                Ok(())
            }
            NativeExit::Fault(mut fault) => {
                let at = (entry.0 as u64).wrapping_add(fault.offset as u64);
                fault.offset = at.wrapping_sub(self.blocks[last].code.0 as u64) as usize;
                self.native_fault(last, fault)
            }
        }
    }

    /// Redirect block `index`'s direct exit to `next_pc` into the block a
    /// fetch there would run, once that block exists: one in the same
    /// page, so the same translation and permissions, compiled for the same
    /// variant. Its BTYPE is 0, as no branch that sets it ends in a direct
    /// exit, and every System register write, exception and device access
    /// that changes what the next fetch checks returns to the engine. An
    /// exit out of the page goes through a lookup thunk instead.
    fn link(&mut self, index: usize, next_pc: u64, kind: ExitKind) {
        let block = &self.blocks[index];
        if block.variant.single || self.traces.binary_search(&next_pc).is_ok() {
            return;
        }
        let Some(position) = block
            .successors
            .iter()
            .position(|exit| exit.target.0 == next_pc && exit.kind == kind)
        else {
            return;
        };
        if (next_pc ^ block.pc) & !(FETCH_PAGE - 1) != 0 {
            let exit = block.successors[position];
            let retired = block.source_map.len() as u32;
            if self.redirect_through_lookup(exit.site, retired, Some(exit.target), kind, 0) {
                self.blocks[index].successors.swap_remove(position);
            }
            return;
        }
        let physical = block.physical.wrapping_add(next_pc.wrapping_sub(block.pc));
        let Some(&target) = self.index.get(&(next_pc, physical, block.variant)) else {
            return;
        };
        let exit = block.successors[position];
        let site = exit.site;
        let retired = block.source_map.len() as u32;
        let entry = self.blocks[target].code.0 as u64;
        let control = &*self.chain as *const ChainControl as u64;
        let Ok(thunk) = self.host.install(&[0; chain::THUNK_BYTES]) else {
            return;
        };
        let at = thunk.0 as u64;
        let (Some(code), Some(jump)) = (
            chain::thunk(
                at,
                control,
                retired,
                target as u32,
                entry,
                exit.target,
                exit.kind,
            ),
            chain::jump(site, at),
        ) else {
            return;
        };
        self.host.patch(thunk, &code);
        self.host.patch(NativeCode(site as usize), &jump);
        self.blocks[index].successors.swap_remove(position);
        self.statistics.links += 1;
    }

    /// Redirect block `index`'s exit to the target in RAX, which just left
    /// BTYPE `btype`, through a lookup thunk, whose target any fetch may
    /// have run. The thunk sets the BTYPE the form sets from the block's
    /// page: 0 for RET, 0b10 for BLR forms, 0b01 for BR forms through X16
    /// or X17, and for BR forms through another register 0b11 in a guarded
    /// page and 0b01 elsewhere. Blocks are compiled per guarded page, so
    /// the page's BTYPE is the block's.
    fn link_dynamic(&mut self, index: usize, btype: u8) {
        let block = &self.blocks[index];
        let Some(site) = block.dynamic_site.filter(|_| !block.variant.single) else {
            return;
        };
        let Some((kind, fixed)) = dynamic_branch(block.terminal.1) else {
            return;
        };
        let page = if block.variant.guarded_page {
            0b11
        } else {
            0b01
        };
        if fixed.unwrap_or(page) != btype {
            return;
        }
        let retired = block.source_map.len() as u32;
        if self.redirect_through_lookup(site, retired, None, kind, btype) {
            self.blocks[index].dynamic_site = None;
        }
    }

    /// Install a lookup thunk for the exit of `kind` at host address `site`
    /// (to `target`, or the target in RAX) by a branch that sets `btype`,
    /// and jump there from the exit.
    fn redirect_through_lookup(
        &mut self,
        site: u64,
        retired: u32,
        target: Option<GuestAddress>,
        kind: ExitKind,
        btype: u8,
    ) -> bool {
        let control = &*self.chain as *const ChainControl as u64;
        let Some(code) = chain::lookup_thunk(control, retired, target, kind, btype) else {
            return false;
        };
        let Ok(thunk) = self.host.install(&code) else {
            return false;
        };
        let Some(jump) = chain::jump(site, thunk.0 as u64) else {
            return false;
        };
        self.host.patch(NativeCode(site as usize), &jump);
        self.statistics.lookups += 1;
        true
    }

    /// The number of the context a fetch runs in now: the generations, the
    /// EL with the guarded level, and the variant. Lookup entries name it.
    fn context(&mut self, el: u8, variant: Variant) -> u64 {
        let generations = (self.translation_generation, self.code_generation);
        if self.context_generations != generations {
            self.context_generations = generations;
            self.contexts.clear();
        }
        if let Some(&(_, _, number)) = self
            .contexts
            .iter()
            .find(|(other, kind, _)| *other == el && *kind == variant)
        {
            return number;
        }
        let number = self.next_context;
        self.next_context += 1;
        self.contexts.push((el, variant, number));
        number
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
            Translated::Mapped(_) if !self.host.fetch_permitted(pc) => {
                let fault =
                    mmu::Fault::stage1(mmu::FaultKind::Permission, HOST_REFUSED_FETCH_LEVEL);
                Err(Ok(self.abort(
                    fault,
                    [Class::InstructionAbortLower, Class::InstructionAbortSame],
                    fault.instruction_syndrome(),
                    pc,
                    pc,
                )))
            }
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
        self.branch_target_accepts(word, self.cpu.pstate.btype)
    }

    /// [`Self::branch_target_compatible`] for BTYPE `btype`.
    fn branch_target_accepts(&self, word: u32, btype: u8) -> bool {
        const PACIASP: u32 = 0xd503_233f;
        const PACIBSP: u32 = 0xd503_237f;
        const SCTLR_BT0: u64 = 1 << 35;
        const SCTLR_BT1: u64 = 1 << 36;
        if word & 0xffff_ff3f == 0xd503_241f {
            return match (word >> 6) & 3 {
                0b00 => btype == 0,
                0b01 => btype != 0b11,
                0b10 => btype != 0b10,
                _ => true,
            };
        }
        if word == PACIASP || word == PACIBSP || block::pauth_lr::signs_with_implicit_bti(word) {
            let sctlr = self.cpu.regime_sctlr();
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
    let routed = |routing: u32, pending: u32| cpu.hcr(routing) && cpu.virtual_pending(pending);
    cpu.pstate.el != 2
        && !cpu.in_host()
        && (routed(HCR_IMO, HCR_VI) || routed(HCR_FMO, HCR_VF) || routed(HCR_AMO, HCR_VSE))
}

impl<H: Host, D: Devices> Machine<H, D> {
    fn fetch_block(&mut self, pc: u64, single: bool) -> Result<Fetched, Stop> {
        let physical = match self.fetch_physical(pc) {
            Ok(physical) => physical,
            Err(Ok(exception)) => return Ok(Fetched::Exception(exception)),
            Err(Err(stop)) => return Err(stop),
        };
        let guarded = self.fetch_guarded(pc);
        let current = self.current_variant(single, guarded);
        let variant = self.page_variant(current, physical);
        let el = self.cpu.pstate.el | u8::from(self.cpu.pstate.guarded) << 4;
        let context = Variant {
            guarded_page: false,
            ..current
        };
        self.chain.context = self.context(el, context);
        let slot = (pc / INSTRUCTION) as usize % JUMP_CACHE;
        if let Some(entry) = self.jump[slot]
            && entry.pc == pc
            && entry.physical == physical
            && entry.variant == variant
            && entry.generation == self.code_generation
        {
            self.remember_target(pc, entry.block);
            return Ok(Fetched::Block(entry.block));
        }
        let index = match self.index.get(&(pc, physical, variant)) {
            Some(&index) => index,
            None => {
                let generation = self.code_generation;
                let compiled = self.compile(pc, physical, variant)?;
                // Compiling may have reclaimed code, whose lookup entries
                // the old context still names: the thunks look up in a new
                // one.
                if self.code_generation != generation {
                    self.chain.context = self.context(el, context);
                }
                match compiled {
                    Fetched::Block(index) => index,
                    other => return Ok(other),
                }
            }
        };
        self.jump[slot] = Some(JumpEntry {
            pc,
            physical,
            variant,
            generation: self.code_generation,
            block: index,
        });
        self.remember_target(pc, index);
        Ok(Fetched::Block(index))
    }

    /// Record that a fetch at `pc` runs block `index` in the current
    /// context, for lookup thunks: not single-instruction blocks, which
    /// debug checks precede, nor trace points, which the engine records.
    /// The fetch translated `pc`, so its page's entry is in the fetch cache.
    fn remember_target(&mut self, pc: u64, index: usize) {
        let block = &self.blocks[index];
        if block.variant.single || self.traces.binary_search(&pc).is_ok() {
            return;
        }
        let (entry, first) = (block.code.0 as u64, block.first);
        let page = pc & !(FETCH_PAGE - 1);
        let guarded = self.fetch[(page / FETCH_PAGE) as usize % FETCH_CACHE]
            .is_some_and(|fetched| fetched.page == page && fetched.guarded);
        let targets = (0..4u8)
            .filter(|&btype| !guarded || btype == 0 || self.branch_target_accepts(first, btype))
            .fold(0, |targets, btype| targets | 1 << btype);
        self.targets[chain::lookup_slot(pc)] = chain::LookupEntry {
            pc,
            context: self.chain.context,
            entry,
            block: index as u32,
            targets,
        };
    }

    /// Compile the block at `pc`, unless its first instruction is a
    /// trapped FP/SIMD instruction or one whose access checks the engine
    /// applies.
    fn compile(&mut self, pc: u64, physical: u64, variant: Variant) -> Result<Fetched, Stop> {
        let window = source_window(pc, variant);
        if window > FIRST_WINDOW_BYTES
            && let Some(fetched) = self.compile_window(pc, physical, variant, FIRST_WINDOW_BYTES)?
        {
            return Ok(fetched);
        }
        Ok(self
            .compile_window(pc, physical, variant, window)?
            .expect("a block of the whole window"))
    }

    /// [`Self::compile`] from the first `available` bytes of the block's
    /// source window, or nothing when the block may run past them (it
    /// takes them all, or they are refused) and they are not the whole
    /// window.
    fn compile_window(
        &mut self,
        pc: u64,
        physical: u64,
        variant: Variant,
        available: usize,
    ) -> Result<Option<Fetched>, Stop> {
        let whole = available == source_window(pc, variant);
        let page = pc & !(FETCH_PAGE - 1);
        let offset = (pc - page) as usize;
        let mut source = vec![0u8; available];
        if !self.host.read_ram(physical, &mut source) {
            // Graceful, the fetch takes the external abort the fabric
            // raises outside memory (IFSC 0b010000).
            self.degrade(self.requirement(RequirementKind::Fetch { physical }))?;
            return Ok(Some(Fetched::Exception(self.external_abort_exception(
                [Class::InstructionAbortLower, Class::InstructionAbortSame],
                SYNCHRONOUS_EXTERNAL_ABORT,
                pc,
            ))));
        }
        // A block from elsewhere is used only when its bytes are among
        // those read, and so validated against the stored page.
        let within =
            |compiled: &stela_compiler::block::CompiledBlock| compiled.source_bytes <= available;
        let stored = match variant.single {
            true => None,
            false => self
                .stored_page(pc, physical, &source)
                .map(|stored| (stored.key, stored.record.clone())),
        };
        let preparation = self.preparation(variant);
        preparation.admit(&mut source);
        let context = stored
            .is_some()
            .then(|| self.stored_context(variant, &preparation, page));
        if let (Some((key, record)), Some(context)) = (&stored, &context) {
            let found = record
                .as_ref()
                .and_then(|record| record.find(offset as u16, context))
                .and_then(|entry| entry.rebase(page));
            if let Some(compiled) = found {
                if !within(&compiled) {
                    return Ok(None);
                }
                self.statistics.stored += 1;
                return self
                    .install(pc, physical, variant, &source, compiled)
                    .map(Some);
            }
            if let Some(compiled) = self
                .host
                .translations()
                .and_then(|translations| translations.prepared(key, pc, context))
            {
                if !within(&compiled) {
                    return Ok(None);
                }
                self.statistics.shared += 1;
                return self
                    .install(pc, physical, variant, &source, compiled)
                    .map(Some);
            }
        }
        let started = self.host.counter();
        // No block runs into a host breakpoint or trace point: one ends
        // before it.
        let limit = self
            .breakpoints
            .iter()
            .chain(&self.traces)
            .filter(|&&stop| stop > pc && stop < pc + source.len() as u64)
            .min()
            .map_or(source.len(), |&stop| (stop - pc) as usize);
        let prepared = preparation.prepare(&source, pc, limit);
        let past = match &prepared {
            Ok(Prepared::Block { consumed, .. }) => *consumed == available,
            Ok(Prepared::Checked(_) | Prepared::FloatingPointTrap) => false,
            Err(_) => true,
        };
        #[cfg(all(feature = "std", feature = "native-profile"))]
        if let Some(metrics) = &mut self.preparation_metrics {
            let ticks = self.host.counter().wrapping_sub(started);
            metrics.record(&prepared, ticks, past && !whole);
        }
        if past && !whole {
            return Ok(None);
        }
        let (compiled, input, successors) = match prepared {
            Ok(Prepared::Block {
                compiled,
                input,
                successors,
                ..
            }) => (compiled, input, successors),
            Ok(Prepared::Checked(word)) => return Ok(Some(Fetched::Checked(word))),
            Ok(Prepared::FloatingPointTrap) => {
                return Ok(Some(Fetched::Exception(self.floating_point_exception(pc))));
            }
            Err(refused) => {
                return Err(self.unsupported_word(&source, pc, refused.pc, refused.detail));
            }
        };
        self.statistics.compiled += 1;
        self.statistics.compiled_instructions += (compiled.source_bytes as u64) / INSTRUCTION;
        self.statistics.compile_ticks += self.host.counter().wrapping_sub(started);
        // An offer is kept until the store proves it; with memory low the
        // block is only compiled, as one the store cannot hold.
        if let (Some((key, _)), Some(context)) = (stored, context)
            && !self.host.memory_low()
            && let Some(translations) = self.host.translations()
        {
            translations.offer(Offer {
                key,
                page,
                pc,
                context,
                input: source[..input].to_vec(),
                preparation,
                block: compiled.clone(),
                successors,
            });
            self.statistics.offered += 1;
        }
        self.install(pc, physical, variant, &source, compiled)
            .map(Some)
    }

    /// How the next fetch compiles its block, in the PE's current state:
    /// for preparing blocks elsewhere as this machine would compile them.
    pub fn current_preparation(&mut self) -> Arc<Preparation> {
        let variant = self.current_variant(false, false);
        self.preparation(variant)
    }

    /// The variant a fetch compiles for in the PE's current state.
    fn current_variant(&mut self, single: bool, guarded_page: bool) -> Variant {
        Variant {
            fp: self.floating_point_enabled(),
            checks: self.memory_checks(),
            single,
            scalable: self
                .cpu
                .scalable
                .is_some()
                .then(|| self.cpu.svcr() & 1 != 0),
            system: self.native_system(),
            guarded_page,
            timing: self.cpu.pstate.dit && self.timing_target().is_some(),
            translated: false,
        }
    }

    /// How blocks of `variant` are compiled, made once per variant.
    fn preparation(&mut self, variant: Variant) -> Arc<Preparation> {
        let variant = Variant {
            guarded_page: false,
            ..variant
        };
        if let Some(preparation) = self.preparations.get(&variant) {
            return preparation.clone();
        }
        let target = match variant.timing {
            true => self
                .timing_target()
                .expect("a timing variant has its target"),
            false => self.target,
        };
        let preparation = Arc::new(Preparation::new(
            self.profile.chip,
            self.admit_table.clone(),
            target,
            variant.fp,
            variant.checks,
            variant.scalable,
            variant.system,
        ));
        self.preparations.insert(variant, preparation.clone());
        preparation
    }

    /// Install `compiled`, the block at `pc` of `variant` compiled from the
    /// admitted `source`, and its thunks, and index it.
    fn install(
        &mut self,
        pc: u64,
        physical: u64,
        variant: Variant,
        source: &[u8],
        compiled: stela_compiler::block::CompiledBlock,
    ) -> Result<Fetched, Stop> {
        let Variant { checks, single, .. } = variant;
        let last = compiled.source_bytes - INSTRUCTION as usize;
        let terminal = u32::from_le_bytes(source[last..last + 4].try_into().expect("a word"));
        if !self.blocks.is_empty() && self.host.memory_low() {
            self.reclaim_code();
        }
        let code = match self.host.install(&compiled.native.x86_64_code) {
            Ok(code) => code,
            Err(InstallError::Full) => {
                self.reclaim_code();
                self.host
                    .install(&compiled.native.x86_64_code)
                    .map_err(|_| {
                        self.unsupported(RequirementKind::Native("block exceeds the code arena"))
                    })?
            }
        };
        let terminal_pc = pc + compiled.source_bytes as u64 - INSTRUCTION;
        let mut successors: Vec<Successor> = compiled
            .direct_exits
            .iter()
            .map(|exit| Successor {
                site: code.0 as u64 + exit.offset as u64,
                target: exit.target,
                kind: exit.kind,
            })
            .collect();
        // RET, BR and BLR end the code with their exit to the target in
        // RAX; the PAC thunk of a RETA*, BRA* or BLRA* has one too.
        let code_bytes = &compiled.native.x86_64_code;
        let mut dynamic_site = (!single
            && terminal & 0xff9f_fc1f == 0xd61f_0000
            && dynamic_branch(terminal)
                .is_some_and(|(kind, _)| code_bytes.ends_with(&chain::dynamic_exit(kind))))
        .then(|| (code.0 + code_bytes.len() - chain::DYNAMIC_EXIT_BYTES) as u64);
        let first = self.admit(u32::from_le_bytes(source[..4].try_into().expect("a word")));
        if !single {
            let (successor, dynamic) = self
                .complete_pointer_natively(
                    code,
                    &compiled.native.x86_64_code,
                    terminal_pc,
                    terminal,
                )
                .unwrap_or_default();
            successors.extend(successor);
            dynamic_site = dynamic_site.or(dynamic);
            successors.extend(self.complete_mirrored_read_natively(
                code,
                &compiled.native.x86_64_code,
                terminal_pc,
                terminal,
            ));
        }
        let block = Block {
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
            variant,
            successors,
            dynamic_site,
            first,
            terminal: (terminal_pc, terminal),
            taken: 0,
            source_bytes: compiled.source_bytes,
            source_hash: source_hash(&source[..compiled.source_bytes]),
        };
        let index = match self.free_blocks.pop() {
            Some(slot) => {
                self.blocks[slot] = block;
                slot
            }
            None => {
                self.blocks.push(block);
                self.blocks.len() - 1
            }
        };
        if !compiled.fault_recovery.is_empty() {
            self.fault_recovery.insert(index, compiled.fault_recovery);
        }
        self.index.insert((pc, physical, variant), index);
        self.code_pages
            .entry(physical & !(FETCH_PAGE - 1))
            .or_default()
            .push((pc, physical, variant));
        Ok(Fetched::Block(index))
    }

    /// Redirect the PAC exit ending a block's `native` code, installed at
    /// `code`, through a thunk that completes the PAC instruction `word` at
    /// `pc` from the memo when it can (`x86_64::pointer`); the thunk's
    /// direct exit to the next instruction, if it has one.
    fn complete_pointer_natively(
        &mut self,
        code: NativeCode,
        native: &[u8],
        pc: u64,
        word: u32,
    ) -> Option<(Option<Successor>, Option<u64>)> {
        let exit = chain::direct_exit(GuestAddress(pc), ExitKind::PointerAuthentication);
        let site = native.len().checked_sub(chain::DIRECT_EXIT_BYTES)?;
        if native[site..] != exit {
            return None;
        }
        let instruction = block::decode_pointer_authentication(GuestAddress(pc), word).ok()??;
        let thunk = match instruction.operation {
            PointerAuthenticationOperation::Strip { data, destination } => {
                x86_64_pointer::strip::thunk(
                    GuestAddress(pc),
                    destination,
                    self.pointer.strip_address(data),
                )?
            }
            operation => {
                let form = x86_64_pointer::Form::of(operation)?;
                let (memo, tags, service) = self.pointer.addresses();
                x86_64_pointer::thunk(form, GuestAddress(pc), memo, tags, service)
            }
        };
        let installed = self.host.install(&thunk.code).ok()?;
        let site = code.0 as u64 + site as u64;
        let jump = chain::jump(site, installed.0 as u64)?;
        self.host.patch(NativeCode(site as usize), &jump);
        let successor = thunk.next.map(|next| Successor {
            site: installed.0 as u64 + next as u64,
            target: GuestAddress(pc + INSTRUCTION),
            kind: ExitKind::Fallthrough,
        });
        let dynamic = thunk
            .dynamic
            .map(|dynamic| installed.0 as u64 + dynamic as u64);
        Some((successor, dynamic))
    }

    /// Redirect the System exit ending a block's `native` code, installed at
    /// `code`, through a thunk that completes `word` at `pc`, if it is MRS
    /// of a [`MIRRORED`] register, from its cell in [`Self::mirrors`] while
    /// it is readable (`x86_64::register_read`); the thunk's direct exit to
    /// the next instruction.
    fn complete_mirrored_read_natively(
        &mut self,
        code: NativeCode,
        native: &[u8],
        pc: u64,
        word: u32,
    ) -> Option<Successor> {
        let exit = chain::direct_exit(GuestAddress(pc), ExitKind::System);
        let site = native.len().checked_sub(chain::DIRECT_EXIT_BYTES)?;
        if native[site..] != exit {
            return None;
        }
        let (index, rt) = mirrored_read(pc, word)?;
        let cell = &self.mirrors[index] as *const register_read::Cell as u64;
        let thunk = register_read::thunk(GuestAddress(pc), rt, cell);
        let installed = self.host.install(&thunk.code).ok()?;
        let site = code.0 as u64 + site as u64;
        let jump = chain::jump(site, installed.0 as u64)?;
        self.host.patch(NativeCode(site as usize), &jump);
        thunk.next.map(|next| Successor {
            site: installed.0 as u64 + next as u64,
            target: GuestAddress(pc + INSTRUCTION),
            kind: ExitKind::Fallthrough,
        })
    }

    /// The target PSTATE.DIT code compiles for
    /// (`TargetCpu::data_independent_timing_target`). Without one,
    /// ID_AA64PFR0_EL1.DIT reads 0 (`identification::Basis::Timing`) and
    /// PSTATE.DIT changes no code.
    fn timing_target(&self) -> Option<TargetCpu> {
        self.target.data_independent_timing_target()
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

    /// The word an exit at `pc` executes, counted in [`Self::exit_words`]:
    /// the block's last instruction, as it was compiled, or one it reads.
    fn exit_word(&mut self, index: usize, pc: u64) -> Result<u32, Stop> {
        let block = &mut self.blocks[index];
        if pc == block.terminal.0 {
            block.taken += 1;
            return Ok(block.terminal.1);
        }
        let word = self.word(index, pc)?;
        *self.exit_words.entry(word).or_default() += 1;
        Ok(word)
    }

    /// Discard every installed block, freeing its metadata, as a run that
    /// has ended does before work that needs the memory.
    pub fn discard_blocks(&mut self) {
        self.discard_code();
    }

    /// Exits to the engine from compiled code (System, FP, PAC and AMX), by
    /// the instruction word that took them: which words to compile inline.
    pub fn exit_words(&self) -> BTreeMap<u32, u64> {
        let mut words = self.exit_words.clone();
        for block in self.blocks.iter().filter(|block| block.taken != 0) {
            *words.entry(block.terminal.1).or_default() += block.taken;
        }
        words
    }

    /// The word an instruction inside a compiled block executes as: its
    /// original word, or the UDF or NOP of a form the chip lacks. The
    /// block's last is kept as it was compiled; others are read again.
    fn word(&mut self, index: usize, pc: u64) -> Result<u32, Stop> {
        let block = &self.blocks[index];
        if pc == block.terminal.0 {
            return Ok(block.terminal.1);
        }
        let physical = block.physical + (pc - block.pc);
        let mut bytes = [0; 4];
        if !self.host.read_ram(physical, &mut bytes) {
            return Err(self.unsupported(RequirementKind::Fetch { physical }));
        }
        Ok(self.admit(u32::from_le_bytes(bytes)))
    }

    /// The word the profile's chip executes for `word` (`Chip::admit`).
    fn admit(&self, word: u32) -> u32 {
        self.admit_table.admit(word)
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
                match self.complete_floating_point(word, &operation) {
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
            // BRA* and BLRA* that a PAC thunk completed.
            _ => match block::decode_pointer_authentication(GuestAddress(terminal), word) {
                Ok(Some(instruction)) => self.pointer_branch_type(terminal, instruction.operation),
                _ => 0,
            },
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
        self.cpu.regime_sctlr() & (1 << bit) != 0
    }

    /// The PAC keys as (low, high) words in APIA, APIB, APDA, APDB, APGA order.
    fn pointer_keys(&self) -> [Option<[u64; 2]>; 5] {
        // The original T6000 LLB initializes C13/C14 keys and consumes them
        // at EL2. They are not aliases of the architectural lower bank. EL0
        // in the host shares them, as the architectural keys serve every EL:
        // 26A434 XNU at EL2 loads each thread's B keys there on a context
        // switch (0xfffffe000bb9bd14) for its EL0 to use.
        if self.cpu.pstate.el == 2 || self.cpu.pstate.el == 0 && self.cpu.in_host() {
            return self.cpu.apple.pointer_keys.pairs();
        }
        use SystemRegister as R;
        let pair = |low, high| Some([self.cpu.read(low), self.cpu.read(high)]);
        [
            pair(R::APIAKeyLo_EL1, R::APIAKeyHi_EL1),
            pair(R::APIBKeyLo_EL1, R::APIBKeyHi_EL1),
            pair(R::APDAKeyLo_EL1, R::APDAKeyHi_EL1),
            pair(R::APDBKeyLo_EL1, R::APDBKeyHi_EL1),
            pair(R::APGAKeyLo_EL1, R::APGAKeyHi_EL1),
        ]
    }

    /// The PAC algorithm version of the PE: FEAT_FPACCOMBINE, FEAT_FPAC,
    /// FEAT_PAuth2 or the classic FEAT_PAuth insertion and error code (the
    /// M1). A feature the PE has and the engine does not implement yet stops.
    fn pointer_version(&self) -> Result<pauth::Version, Stop> {
        let has = |feature| {
            self.cpu
                .registers
                .implemented(feature)
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
        let [ia, ib, da, db, generic] = self.pointer_keys();
        let mut keys = pauth::Keys::from_optional_words([ia, ib, da, db]);
        if let Some(generic) = generic {
            keys = keys.with_generic_words(generic);
        }
        Ok(
            pauth::Context::new_with_version(0, keys, self.pointer_version()?)
                .with_translation_regime(self.cpu.regime_tcr()),
        )
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
        if let Some(step) = self.implicit_pointer_authentication(word) {
            return step;
        }
        let pc = self.cpu.pc;
        let refuse = |machine: &Self, detail: String| {
            Err(machine.unsupported(RequirementKind::Instruction { word, detail }))
        };
        let instruction = match block::decode_pointer_authentication(GuestAddress(pc), word) {
            Ok(Some(instruction)) => instruction,
            _ => return refuse(self, "PAC exit at a word that is not PAC".into()),
        };
        let link_register = self
            .cpu
            .registers
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
        if let Some(step) = self.register_pointer_authentication(instruction) {
            return step;
        }
        let context = self.pointer_context()?;
        if let PointerAuthenticationOperation::Strip { data, .. } = instruction.operation {
            self.pointer.open_stripping(&context, data);
        }
        if let PointerAuthenticationOperation::Load(load) = instruction.operation {
            return self.authenticated_load(word, Some(&context), load);
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

    /// PACIASP, PACIBSP, AUTIASP, AUTIBSP, RETAA, RETAB and the HINT-space
    /// *1716 forms, whose operands are implicit (X30 and SP, or X17 and X16):
    /// the kernel's prologues and epilogues. With the key enabled and its use
    /// not trapped, each completes as the general path does (Arm `AddPAC`,
    /// `Auth`; RETA* branches to the authenticated pointer and keeps X30
    /// signed) through [`Self::pointer_result`]. `None` leaves every other
    /// case, and every form under PSTATE.PACM, to the general path.
    fn implicit_pointer_authentication(&mut self, word: u32) -> Option<Step> {
        use PointerAuthenticationKey as Block;
        use pauth::Key;
        #[derive(PartialEq)]
        enum Form {
            Sign,
            Authenticate,
            Return,
        }
        let (form, key, block_key, stack) = match word {
            0xd503_233f => (Form::Sign, Key::Ia, Block::Ia, true),
            0xd503_237f => (Form::Sign, Key::Ib, Block::Ib, true),
            0xd503_23bf => (Form::Authenticate, Key::Ia, Block::Ia, true),
            0xd503_23ff => (Form::Authenticate, Key::Ib, Block::Ib, true),
            0xd65f_0bff => (Form::Return, Key::Ia, Block::Ia, true),
            0xd65f_0fff => (Form::Return, Key::Ib, Block::Ib, true),
            0xd503_211f => (Form::Sign, Key::Ia, Block::Ia, false),
            0xd503_215f => (Form::Sign, Key::Ib, Block::Ib, false),
            0xd503_219f => (Form::Authenticate, Key::Ia, Block::Ia, false),
            0xd503_21df => (Form::Authenticate, Key::Ib, Block::Ib, false),
            _ => return None,
        };
        if self.cpu.pstate.pacm
            || !self.key_enabled(block_key)
            || self.pointer_authentication_trapped()
        {
            return None;
        }
        let (register, modifier) = if stack {
            (30, self.cpu.state.sp)
        } else {
            (17, self.cpu.state.x[16])
        };
        let operation = match form {
            Form::Sign => PointerOperation::Sign,
            Form::Authenticate => PointerOperation::Authenticate { combined: false },
            Form::Return => PointerOperation::Authenticate { combined: true },
        };
        let pointer = self.cpu.state.x[register];
        let result = match self.pointer_result(operation, key, pointer, modifier) {
            Ok(result) => result,
            Err(stop) => return Some(Err(stop)),
        };
        let pc = self.cpu.pc;
        match result {
            Ok((target, _)) if form == Form::Return => {
                self.cpu.pstate.btype = 0;
                self.cpu.pc = target;
            }
            Ok((value, _)) => {
                self.cpu.pstate.btype = 0;
                self.cpu.state.x[register] = value;
                self.cpu.pc = pc + INSTRUCTION;
            }
            Err(code) => self.take(Exception::synchronous(
                Class::PointerAuthenticationFailure,
                u32::from(code),
                pc,
            )),
        }
        Some(Ok(()))
    }

    /// PAC*, AUT*, BRA* and BLRA* with register, SP or zero modifiers, once
    /// their key is known enabled and untrapped: each completes as the
    /// general path does (Arm `AddPAC`, `Auth`; a branch authenticates as a
    /// combined form, then links and branches) through
    /// [`Self::pointer_result`]. `None` leaves forms naming register 31 to
    /// the general path.
    fn register_pointer_authentication(
        &mut self,
        instruction: PointerAuthentication,
    ) -> Option<Step> {
        use PointerAuthenticationModifier as Modifier;
        use PointerAuthenticationOperation as Operation;
        let (operation, key, register, modifier) = match instruction.operation {
            Operation::Sign {
                key,
                destination,
                modifier,
            } => (PointerOperation::Sign, key, destination, modifier),
            Operation::Authenticate {
                key,
                destination,
                modifier,
            } => (
                PointerOperation::Authenticate { combined: false },
                key,
                destination,
                modifier,
            ),
            Operation::Branch {
                key,
                target,
                modifier,
                ..
            } => (
                PointerOperation::Authenticate { combined: true },
                key,
                target,
                modifier,
            ),
            _ => return None,
        };
        let modifier = match modifier {
            Modifier::Register(31) => return None,
            Modifier::Register(register) => self.cpu.state.x[usize::from(register)],
            Modifier::StackPointer => self.cpu.state.sp,
            Modifier::Zero => 0,
        };
        if register == 31 {
            return None;
        }
        let key = match key {
            PointerAuthenticationKey::Ia => pauth::Key::Ia,
            PointerAuthenticationKey::Ib => pauth::Key::Ib,
            PointerAuthenticationKey::Da => pauth::Key::Da,
            PointerAuthenticationKey::Db => pauth::Key::Db,
        };
        let pc = self.cpu.pc;
        let pointer = self.cpu.state.x[usize::from(register)];
        let result = match self.pointer_result(operation, key, pointer, modifier) {
            Ok(result) => result,
            Err(stop) => return Some(Err(stop)),
        };
        match result {
            Ok((value, _)) => {
                self.cpu.pstate.btype = self.pointer_branch_type(pc, instruction.operation);
                if let Operation::Branch { link, .. } = instruction.operation {
                    if link {
                        self.cpu.state.x[30] = instruction.next_pc.0;
                    }
                    self.cpu.pc = value;
                } else {
                    self.cpu.state.x[usize::from(register)] = value;
                    self.cpu.pc = instruction.next_pc.0;
                }
            }
            Err(code) => self.take(Exception::synchronous(
                Class::PointerAuthenticationFailure,
                u32::from(code),
                pc,
            )),
        }
        Some(Ok(()))
    }

    /// One signing or authentication with the current keys, version and
    /// layout (`pointer::PointerService::result`), the key known enabled
    /// and untrapped.
    fn pointer_result(
        &mut self,
        operation: PointerOperation,
        key: pauth::Key,
        pointer: u64,
        modifier: u64,
    ) -> Result<PointerResult, Stop> {
        if !self.pointer.is_open() {
            let inputs = PointerInputs {
                keys: self.pointer_keys(),
                version: self.pointer_version()?,
                tcr: self.cpu.regime_tcr(),
            };
            self.pointer.open(inputs);
        }
        self.pointer
            .result(operation, key, pointer, modifier)
            .ok_or_else(|| {
                self.unsupported(RequirementKind::Native(match operation {
                    PointerOperation::Sign => "PAC key unavailable for signing",
                    PointerOperation::Authenticate { .. } => {
                        "PAC key unavailable for authentication"
                    }
                }))
            })
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
    /// unchanged (Arm ARM `AddPAC`, `Auth`). Until derived state changes,
    /// the key's tag word lets PAC thunks complete its instructions the
    /// same way (`x86_64::pointer::DISABLED`).
    fn disabled_pointer_authentication(
        &mut self,
        word: u32,
        instruction: PointerAuthentication,
    ) -> Step {
        use PointerAuthenticationOperation as Operation;
        if let Some(key) = instruction.operation.required_key() {
            self.pointer.tags[usize::from(x86_64_pointer::key_index(key))] =
                x86_64_pointer::DISABLED;
        }
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
            Operation::Load(load) => return self.authenticated_load(word, None, load),
            Operation::Strip { .. } | Operation::GenericCode(_) => {
                unreachable!("XPAC and PACGA use no key that SCTLR disables")
            }
        }
        Ok(())
    }

    /// LDRAA/LDRAB: authenticate the base, then read through the guest's
    /// translation like any data load. Without a context the key is
    /// disabled, and AuthDA/AuthDB return the base unchanged (Arm `Auth`).
    fn authenticated_load(
        &mut self,
        word: u32,
        context: Option<&pauth::Context>,
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
                match context {
                    Some(context) => context
                        .authenticate_operation(key, pointer, 0, true)
                        .map(|result| result.pointer),
                    None => Ok(pointer),
                }
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
                // Tag checked with writeback or a base other than SP
                // (FEAT_MTE2), after the watchpoint.
                if let Some(access) = access
                    && (load.writeback || load.base != 31)
                    && let tags::TagCheck::Failed(exception) =
                        self.tag_check(&access, requester, None)?
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
        // Guest registers a region kept in host registers across the access.
        if let Some(table) = self.fault_recovery.get(&index) {
            stela_compiler::block::FaultRecovery::apply(
                table,
                fault.offset,
                &fault.registers,
                &mut self.cpu.state,
            );
        }
        let pc = self.faulting_pc(index, fault.offset);
        self.retire_before(index, pc);
        self.cpu.pc = pc;
        if pc != self.blocks[index].pc {
            self.cpu.pstate.btype = 0;
        }
        // A native DC ZVA's first store, or a native DC clean's read of Xt,
        // faulted with nothing written (a DC ZVA block is in one page): the
        // engine completes the instruction, reporting Xt as the fault
        // address with a cache maintenance syndrome and watching the whole
        // DC ZVA block (Arm `AArch64_DataMemZero`), whatever stopped the
        // access.
        let (terminal, word) = self.blocks[index].terminal;
        if pc == terminal && completes_natively(pc, word, self.blocks[index].variant.system) {
            self.statistics.system_exits += 1;
            let word = self.exit_word(index, pc)?;
            return self.completing(pc, |machine| machine.system_instruction(word));
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
            // The access left the native ranges past a check an earlier
            // one through its base stood for: its own check finds which.
            FaultCause::NonCanonical => {
                let word = self.word(index, pc)?;
                self.native_check_fault(index, pc, word, &fault)
            }
            // Native blocks raise #UD for a misaligned SP base when compiled
            // with the check (SCTLR_ELx.SA or SA0 set), which comes first,
            // and for an access that has an Alignment fault: unaligned under
            // SCTLR_ELx.A, or an atomic, or an ordered access with nAA
            // clear, crossing its 16-byte granule; and for an address outside
            // the guest's two ranges.
            FaultCause::Watched | FaultCause::TagChecked => self.watched_access(index, pc),
            FaultCause::InvalidOpcode => {
                let word = self.word(index, pc)?;
                if self.blocks[index].checks.stack_alignment
                    && stack_based(word)
                    && !self.cpu.state.sp.is_multiple_of(16)
                {
                    self.take(Exception::synchronous(Class::SpAlignment, 0, pc));
                    Ok(())
                } else {
                    self.native_check_fault(index, pc, word, &fault)
                }
            }
        }
    }

    /// Run the instruction at `pc` of block `index`, whose access to the
    /// guest's mapped `address` lies outside the host's native ranges
    /// (`docs/design/system.md#host-placement`), again in the translated
    /// variant: its fetch page's blocks are compiled again so that every
    /// access calls the host's translation helper outside those ranges,
    /// which translates it, delivers its fault or completes it. `GuestState`
    /// is the instruction's own (`native_fault`). A translated block that
    /// still leaves the ranges, or a host without the helper, stops
    /// explicitly.
    fn run_translated(&mut self, index: usize, pc: u64, address: u64) -> Step {
        let block = &self.blocks[index];
        if block.variant.translated || self.host.translation_helper().is_none() {
            let mut requirement = self.requirement(RequirementKind::Native(
                "a mapped guest address outside the host's native ranges",
            ));
            requirement.address = Some(address);
            return Err(Stop::Unsupported(requirement));
        }
        let page = block.physical.wrapping_add(pc.wrapping_sub(block.pc)) & !(FETCH_PAGE - 1);
        self.translated_pages.insert(page);
        self.first_translated.get_or_insert((pc, address));
        self.statistics.translated_pages += 1;
        self.invalidate_code_page(page);
        Ok(())
    }

    /// The guest PC and data address that first needed the translated
    /// variant, once one has: a guest that maps an address outside the
    /// host's native ranges, which runs correctly but slower.
    pub fn first_translated(&self) -> Option<(u64, u64)> {
        self.first_translated
    }

    /// `variant` for a block of the fetch page holding `physical`: in the
    /// translated variant when the page needs it, through the host's
    /// translation helper.
    fn page_variant(&self, mut variant: Variant, physical: u64) -> Variant {
        if self.page_translated(physical)
            && let Some(helper) = self.host.translation_helper()
        {
            variant.translated = true;
            variant.checks = variant.checks.with_translation(helper);
        }
        variant
    }

    /// Whether blocks of the fetch page holding `physical` run in the
    /// translated variant.
    fn page_translated(&self, physical: u64) -> bool {
        !self.translated_pages.is_empty()
            && self
                .translated_pages
                .contains(&(physical & !(FETCH_PAGE - 1)))
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
        match self.cpu.registers.implemented(Feature::FEAT_CPA) {
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
        let mut settled_failure = None;
        let refuse = |machine: &mut Self, detail: &str| {
            machine.device_unexecuted(address, physical, write, detail.into())
        };
        let Ok(instruction) = Decoder.lift(GuestAddress(pc), word) else {
            return refuse(self, "device access by an undecodable instruction");
        };
        self.statistics.device_accesses += 1;
        self.device_lines = None;
        if let Some(load) = ScalarLoad::from_instruction(&instruction) {
            let (accessed, writeback) = self.scalar_address(load.address());
            if accessed != address {
                return refuse(self, "device load address differs from the fault");
            }
            let bytes = load.bytes();
            if !address.is_multiple_of(u64::from(bytes)) {
                return self.alignment_fault(address, false);
            }
            let now = self.now();
            let raw = match self.device_read(physical, bytes, now) {
                Ok(value) => value,
                Err(error) => match self.device_refused(error, address, physical, bytes, None) {
                    None => 0,
                    Some(step) => return step,
                },
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
                return refuse(self, "device store address differs from the fault");
            }
            let bytes = store.bytes();
            if !address.is_multiple_of(u64::from(bytes)) {
                return self.alignment_fault(address, true);
            }
            let value = self.read_register(store.source_register());
            let now = self.now();
            let written = self
                .device_write(physical, bytes, value, now)
                .and_then(|()| self.device_transfer(now));
            if let Err(error) = written
                && let Some(step) =
                    self.device_refused(error, address, physical, bytes, Some(value))
            {
                return step;
            }
            if let Some((base, updated)) = writeback {
                self.write_register(base, updated);
            }
            self.follow_memory_lock();
        } else if let Operation::MemoryPair {
            transfer,
            bytes,
            data,
            base,
            displacement,
            mode,
        } = instruction.operation
        {
            // A pair is two accesses of `bytes` each, at ascending addresses
            // and in register order; Device memory faults on either
            // misaligned (Arm DDI 0487 B2.5.2).
            let first = self.immediate_address(base, displacement, mode);
            let bytes_wide = u64::from(bytes);
            if first != address {
                return refuse(self, "device pair address differs from the fault");
            }
            if !address.is_multiple_of(bytes_wide) {
                return self.alignment_fault(address, write);
            }
            // The smallest translation granule: the second element's PA
            // follows the first's only within one.
            const GRANULE: u64 = 0x1000;
            if physical % GRANULE + 2 * bytes_wide > GRANULE {
                return refuse(self, "device pair across a page");
            }
            let writeback = (mode != AddressMode::Offset).then(|| {
                let updated = self
                    .read_register(base)
                    .wrapping_add(displacement as i64 as u64);
                (base, updated)
            });
            let elements = [physical, physical + bytes_wide];
            let now = self.now();
            match transfer {
                MemoryTransfer::Load { signed, width } => {
                    let pair = if self.devices.requires_canonical_read(
                        self.current,
                        physical,
                        DeviceReadShape::Pair { bytes },
                    ) {
                        self.host.speculation_barrier();
                        self.serial_read_canonical(physical, DeviceReadShape::Pair { bytes }, now)
                            .map(Some)
                    } else {
                        self.host.speculation_barrier();
                        self.devices.read_pair(self.current, physical, bytes, now)
                    };
                    let raw_values = match pair {
                        Err(error) => {
                            self.watch(physical, bytes, None, false);
                            match self.device_refused(error, address, physical, bytes, None) {
                                None => [0; 2],
                                Some(step) => return step,
                            }
                        }
                        Ok(Some(pair)) => {
                            for (element, raw) in elements.into_iter().zip(pair.values) {
                                self.watch(element, bytes, Some(raw), false);
                            }
                            if let Err(error) = pair.settlement {
                                // Capture the original access PC before committing
                                // its data, writeback and instruction retirement.
                                let mut requirement = self.requirement(RequirementKind::Device {
                                    physical,
                                    write,
                                    detail: format!(
                                        "consumed device pair: board settlement failed: {error:?}"
                                    ),
                                });
                                requirement.address = Some(address);
                                settled_failure = Some(requirement);
                            }
                            pair.values
                        }
                        Ok(None) => {
                            let mut raw_values = [0; 2];
                            for (raw, element) in raw_values.iter_mut().zip(elements) {
                                *raw = match self.device_read(element, bytes, now) {
                                    Ok(raw) => raw,
                                    Err(error) => {
                                        let at = address + (element - physical);
                                        match self.device_refused(error, at, element, bytes, None) {
                                            None => 0,
                                            Some(step) => return step,
                                        }
                                    }
                                };
                            }
                            raw_values
                        }
                    };
                    let values = raw_values.map(|raw| {
                        let mut value = match (bytes, signed) {
                            (8, _) => raw,
                            (4, true) => raw as u32 as i32 as i64 as u64,
                            _ => raw & 0xffff_ffff,
                        };
                        if width == Width::W32 {
                            value &= 0xffff_ffff;
                        }
                        value
                    });
                    for (register, value) in data.into_iter().zip(values) {
                        self.write_register(register, value);
                    }
                }
                MemoryTransfer::Store => {
                    let values = data.map(|register| self.read_register(register));
                    for (element, value) in elements.into_iter().zip(values) {
                        let written = self
                            .device_write(element, bytes, value, now)
                            .and_then(|()| self.device_transfer(now));
                        if let Err(error) = written {
                            let at = address + (element - physical);
                            if let Some(step) =
                                self.device_refused(error, at, element, bytes, Some(value))
                            {
                                return step;
                            }
                        }
                    }
                    self.follow_memory_lock();
                }
            }
            if let Some((base, updated)) = writeback {
                self.write_register(base, updated);
            }
        } else {
            return refuse(
                self,
                "device access by other than a scalar or pair integer transfer",
            );
        }
        self.cpu.pc = pc;
        self.next()?;
        // The consumed data is retired; a failed board settlement after it
        // stops in strict mode and is reported once otherwise.
        if let Some(requirement) = settled_failure {
            self.degrade(requirement)?;
        }
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

    /// A device access the devices refused or no device answers
    /// (docs/design/runtime.md#unsupported-operations): `None` when it
    /// completes degraded, reading 0 or dropping the write, else the step
    /// the instruction ends with. A survey answers every register access so
    /// and records it ([`Self::begin_survey`]); otherwise [`Self::degrade`]
    /// decides. Graceful, an address no device covers takes the synchronous
    /// external abort the fabric raises there, and a register, setting or
    /// effect a device does not carry out completes degraded: the device
    /// keeps what it accepted and nothing is invented for the rest.
    fn device_refused(
        &mut self,
        error: DeviceError,
        address: u64,
        physical: u64,
        bytes: u8,
        written: Option<u64>,
    ) -> Option<Step> {
        if self.surveyed(physical, bytes, written, &error) {
            return None;
        }
        let write = written.is_some();
        let unmapped = error == DeviceError::NoDevice;
        let detail = match (error, written) {
            (DeviceError::NoDevice, None) => "no device model".into(),
            (DeviceError::NoDevice, Some(value)) => format!("no device model (value {value:#x})"),
            (DeviceError::Refused(detail), Some(value)) => format!("{detail} (value {value:#x})"),
            (DeviceError::Refused(detail) | DeviceError::TransferRefused(detail), _) => detail,
        };
        let mut requirement = self.requirement(RequirementKind::Device {
            physical,
            write,
            detail,
        });
        requirement.address = Some(address);
        if let Err(stop) = self.degrade(requirement) {
            return Some(Err(stop));
        }
        unmapped.then(|| self.external_abort(address, write))
    }

    /// A device access in a form the engine cannot carry out (`detail`):
    /// strict, the stop; graceful, reported once per register and
    /// direction, it takes the synchronous external abort without reaching
    /// the device.
    fn device_unexecuted(
        &mut self,
        address: u64,
        physical: u64,
        write: bool,
        detail: String,
    ) -> Step {
        let mut requirement = self.requirement(RequirementKind::Device {
            physical,
            write,
            detail,
        });
        requirement.address = Some(address);
        self.degrade(requirement)?;
        self.external_abort(address, write)
    }

    /// The synchronous external abort (DFSC 0b010000) a data access takes;
    /// from EL0 or EL1 it goes to EL2 under HCR_EL2.TEA (Arm
    /// SyncExternalAbortTarget).
    fn external_abort(&mut self, address: u64, write: bool) -> Step {
        let iss = data_abort_iss(SYNCHRONOUS_EXTERNAL_ABORT, write);
        let exception = self.external_abort_exception(
            [Class::DataAbortLower, Class::DataAbortSame],
            iss,
            address,
        );
        self.take(exception);
        Ok(())
    }

    /// The synchronous external abort of the access at `address` by the
    /// instruction at the PC, of the lower or same-level `classes`.
    fn external_abort_exception(&self, classes: [Class; 2], iss: u32, address: u64) -> Exception {
        let target = if self.cpu.pstate.el < 2 && self.cpu.hcr(crate::machine::cpu::HCR_TEA) {
            2
        } else {
            self.cpu.route()
        };
        let class = if target > self.cpu.pstate.el {
            classes[0]
        } else {
            classes[1]
        };
        let mut exception = Exception::synchronous(class, iss, self.cpu.pc).to(target);
        exception.fault_address = Some(address);
        exception
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
        // Apple's SDSB (`0x00201460` plus the domain), WKDMC and WKDMD;
        // `guarded` checks the GXF instructions.
        let apple = match instruction.operation {
            SystemOperation::Synchronization(_) if word & !3 == 0x0020_1460 => {
                Some(hacr::Operation::SynchronizationBarrier)
            }
            SystemOperation::Compression(_) => Some(hacr::Operation::Compression),
            _ => None,
        };
        if let Some(operation) = apple
            && let Some(step) = self.hacr_guest(word, operation)
        {
            return step;
        }
        match instruction.operation {
            SystemOperation::Exception(operation) => self.exception_instruction(operation),
            SystemOperation::Register(access) => self.register_instruction(word, access),
            SystemOperation::PstateImmediate(encoding) => {
                let before = self.cpu.pstate;
                let outcome = self.cpu.write_pstate_field(encoding);
                self.pstate_immediate(word, before, outcome)
            }
            SystemOperation::Maintenance(access) => self.maintenance(word, access),
            SystemOperation::InstructionSynchronization { .. } => self.next(),
            SystemOperation::Synchronization(operation) => match operation {
                // DSB nXS waits for a subset of what DSB waits for (accesses
                // to memory with XS 0), and is UNDEFINED without FEAT_XS.
                Synchronization::DataCompletion { nxs: true, .. } => {
                    match self.cpu.registers.implemented(Feature::FEAT_XS) {
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
            SystemOperation::TagMemory(operand) => self.tag_memory(word, operand),
            SystemOperation::TagOffset(operand) => self.tag_offset(word, operand),
            // No halting debug: Debug-state-only instructions are UNDEFINED.
            SystemOperation::DebugStateOnly(_) => self.undefined(),
            SystemOperation::Unprivileged(operand) => self.unprivileged(operand),
            SystemOperation::Exclusive(Ok(operand)) => self.exclusive(operand),
            SystemOperation::Exclusive(Err(_)) => self.undefined(),
            SystemOperation::CheckedPointer(operand) => self.checked_pointer(operand),
            SystemOperation::Compression(instruction) => self.compression(word, instruction),
            SystemOperation::Guarded(operation) => self.guarded(word, operation),
            SystemOperation::AppleMaintenance(operation) => self.apple_maintenance(word, operation),
        }
    }

    /// An ERET or GEXIT to `spsr`, guarded when `guarded`, that enters an
    /// EL1&0 guest of the EL2 host (EL1 or EL0, unguarded, HCR_EL2.TGE
    /// clear) while an Apple VM register holds state this machine does not
    /// apply to a guest (`impdef::Registers::guest_state`): SPTM and the
    /// kernel's hypervisor load a VM's values into them before it runs
    /// (`machine::impdef` `GUEST_EVIDENCE`). Strict, it stops; graceful,
    /// the guest is entered without that state.
    fn guest_entry(&mut self, spsr: u64, guarded: bool) -> Result<(), Stop> {
        let enters_guest = !guarded
            && !self.cpu.in_host()
            && super::exception::spsr_target(spsr).is_ok_and(|(el, _)| el < 2);
        match self.cpu.apple.impdef.guest_state() {
            Some(entry) if enters_guest => {
                self.degrade(self.requirement(RequirementKind::VmState(entry.name)))
            }
            _ => Ok(()),
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
        self.guest_entry(self.cpu.exception_state(), self.cpu.pstate.guarded)?;
        let trace = self.monitor_before(MonitorKind::ExceptionReturn);
        self.cpu.exception_return(target).map_err(|_| {
            self.unsupported(RequirementKind::Native(
                "canonical exclusive/event settlement failed before exception return",
            ))
        })?;
        self.pacm_written = true;
        self.host.report(&Event::Return {
            to_el: self.cpu.pstate.el,
            guarded: self.cpu.pstate.guarded,
            pc: self.cpu.pc,
        });
        self.monitor_after(trace);
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

    /// MRS and MSR (`register_access`); a read of a [`MIRRORED`] register
    /// that completes as a plain read, taking no exception, opens its cell
    /// with the value read.
    fn register_instruction(&mut self, word: u32, access: RegisterAccess) -> Step {
        let Some(index) = mirrored(access) else {
            return self.register_access(word, access);
        };
        let before = (
            self.cpu.pc + INSTRUCTION,
            self.cpu.pstate.el,
            self.cpu.pstate.guarded,
            self.statistics.exceptions,
        );
        let step = self.register_access(word, access);
        let after = (
            self.cpu.pc,
            self.cpu.pstate.el,
            self.cpu.pstate.guarded,
            self.statistics.exceptions,
        );
        if step.is_ok() && after == before {
            self.mirrors[index] = register_read::Cell {
                readable: 1,
                value: self.cpu.state.x[usize::from(access.rt())],
            };
        }
        step
    }

    /// MRS and MSR: the generated accessor of an architectural register, or
    /// Apple's implementation-defined dispatch; any other encoding is
    /// UNDEFINED.
    fn register_access(&mut self, word: u32, access: RegisterAccess) -> Step {
        use registers::encodings::{FPCR, FPSR};
        let encoding = access.encoding();
        if matches!(encoding, FPCR | FPSR) && !self.floating_point_enabled() {
            let exception = self.floating_point_exception(self.cpu.pc);
            self.take(exception);
            return Ok(());
        }
        // Apple's vGIC CPU interface answers the ICH_* and ICC_* encodings
        // before the generated accessors, which follow the profile's absent
        // FEAT_GICv3.
        let write = (access.direction() == Direction::Write).then(|| match access.rt() {
            31 => 0,
            rt => self.cpu.state.x[usize::from(rt)],
        });
        let context = self.cpu.vgic_context(write.is_some());
        if let Some(outcome) = self.cpu.vgic.access(encoding, write, &context) {
            return self.register_outcome(word, Some(access), outcome);
        }
        if self.hacr_reaches(access)
            && let Some(step) = self.hacr_guest(word, hacr::Operation::Register(encoding))
        {
            return step;
        }
        if let Some(step) = self.system_access(word, access) {
            return step;
        }
        if let Some(outcome) = self.board_register(access) {
            return self.register_outcome(word, Some(access), outcome);
        }
        let physical = self.now();
        // A write's outcome forgets derived state, and a trap's exception
        // does; a read changes none of it.
        let outcome = self.cpu.apple_access(access, physical);
        self.register_outcome(word, Some(access), outcome)
    }

    /// Whether HACR_EL2 decides an MRS or MSR of a guest: AIDR_EL1 from EL1,
    /// an op0 3, CRn 11 or 15 encoding from EL1 that HCR_EL2.TIDCP does not
    /// already trap to EL2, and from EL0 the two such encodings EL0 reaches
    /// (SPRR_PERM_EL0, and reads of the counter alias); the others are
    /// UNDEFINED there.
    fn hacr_reaches(&self, access: RegisterAccess) -> bool {
        let encoding = access.encoding();
        if self.cpu.pstate.el == 2 || self.cpu.in_host() {
            return false;
        }
        let apple = encoding.op0() == 3 && matches!(encoding.crn(), 11 | 15);
        match self.cpu.pstate.el {
            1 => encoding == registers::encodings::AIDR_EL1 || (apple && !self.cpu.hcr(HCR_TIDCP)),
            _ => {
                encoding == registers::encodings::SPRR_PERM_EL0
                    || (encoding == registers::encodings::CNTVCT_ALIAS_EL0
                        && access.direction() == Direction::Read)
            }
        }
    }

    /// HACR_EL2 on an Apple-specific operation of an EL1&0 guest
    /// (`machine::hacr`): the step when a set bit traps it to EL2 (EC 0x18,
    /// the instruction's ISS) or refuses it, `None` when it runs.
    fn hacr_guest(&mut self, word: u32, operation: hacr::Operation) -> Option<Step> {
        if self.cpu.pstate.el == 2 || self.cpu.in_host() {
            return None;
        }
        let value = self.cpu.read(SystemRegister::HACR_EL2);
        if value == 0 {
            return None;
        }
        let context = hacr::Context {
            el: self.cpu.pstate.el,
            guarded: self.cpu.pstate.guarded,
        };
        match hacr::guest(value, operation, context) {
            hacr::Outcome::Runs => None,
            hacr::Outcome::Trap => {
                let iss = registers::word_trap_iss(word);
                let exception = Exception::synchronous(Class::SystemRegister, iss, self.cpu.pc);
                self.take(exception.to(2));
                Some(Ok(()))
            }
            hacr::Outcome::Refused(detail) => Some(Err(
                self.unsupported(RequirementKind::Instruction { word, detail })
            )),
        }
    }

    /// An Apple IMPLEMENTATION DEFINED register of the board (`Devices::
    /// system_register`), at EL1 and EL2. EL0 accesses and EL1 accesses that
    /// HCR_EL2.TIDCP traps outside the host are left to `Cpu::apple_access`,
    /// which makes them UNDEFINED or traps them as for the core's own.
    fn board_register(&mut self, access: RegisterAccess) -> Option<RegisterOutcome> {
        let encoding = access.encoding();
        let el = self.cpu.pstate.el;
        if encoding.op0() != 3
            || encoding.crn() != 15
            || el == 0
            || (el == 1 && !self.cpu.in_host() && self.cpu.hcr(HCR_TIDCP))
        {
            return None;
        }
        let write = (access.direction() == Direction::Write).then(|| match access.rt() {
            31 => 0,
            rt => self.cpu.state.x[usize::from(rt)],
        });
        let now = self.now();
        let result = self
            .devices
            .system_register(self.current, encoding, write, now)?;
        self.device_lines = None;
        Some(match (result, write) {
            (Ok(value), None) => RegisterOutcome::Read(value),
            (Ok(_), Some(_)) => RegisterOutcome::Written(registers::Changes::default()),
            (Err(reason), _) => RegisterOutcome::Refused(Refusal::UnsupportedSetting(reason)),
        })
    }

    /// MSR (immediate) after `write_pstate_field` from `before`. A write
    /// that changes only the A, I or F masks, only SPSel or only PAN leaves
    /// System registers and the other PSTATE fields as they were, so state
    /// derived from them stays: the DAIF mirror takes the new masks, PAN
    /// changes the host's requester, and SPSel only which SP `GuestState`
    /// holds. The step re-evaluates interrupt delivery after any of them.
    /// Every other change forgets derived state as an MSR does.
    fn pstate_immediate(&mut self, word: u32, before: Pstate, outcome: RegisterOutcome) -> Step {
        let after = self.cpu.pstate;
        let RegisterOutcome::Written(changes) = outcome else {
            return self.register_outcome(word, None, outcome);
        };
        if changes.unmodeled.is_some() || changes.irq_steering.is_some() {
            return self.register_outcome(word, None, RegisterOutcome::Written(changes));
        }
        let only = |field: Pstate| field == after;
        if only(Pstate {
            daif: after.daif,
            ..before
        }) && (before.daif ^ after.daif) & DAIF_D == 0
        {
            let cell = &mut self.mirrors[DAIF_MIRROR];
            if cell.readable != 0 {
                cell.value = daif_register(after.daif);
            }
        } else if only(Pstate {
            pan: after.pan,
            ..before
        }) {
            if before.pan != after.pan {
                self.sync_host_regime();
            }
        } else if !only(Pstate {
            sp: after.sp,
            ..before
        }) {
            return self.register_outcome(word, None, RegisterOutcome::Written(changes));
        }
        self.next()
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
                let value = self.degraded_read(access, value);
                if access.rt() != 31 {
                    self.cpu.state.x[usize::from(access.rt())] = value;
                }
            }
            RegisterOutcome::Written(changes) => {
                if let Some(access) = access {
                    self.degraded_written(access);
                }
                if let Some(missing) = changes.unmodeled {
                    let refusal = Refusal::UnsupportedSetting(missing);
                    self.degrade(self.register_requirement(word, access, refusal))?;
                }
                if let Some(refuses) = changes.irq_steering {
                    let now = self.now();
                    self.devices.irq_steering(self.current, refuses, now);
                    self.device_lines = None;
                }
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
                return self.register_refused(word, access, refusal);
            }
            RegisterOutcome::View(encoding, bank) => {
                let access = access.expect("views come from MRS and MSR");
                return self
                    .system_access_as(word, access, encoding, bank)
                    .unwrap_or_else(|| {
                        Err(Stop::Unsupported(self.register_requirement(
                            word,
                            Some(access),
                            Refusal::Unimplemented,
                        )))
                    });
            }
        }
        self.next()
    }

    /// A System register access whose model refused it (an encoding the
    /// chip's components use without a model, or a setting or state the
    /// model does not carry out): stop in strict mode; graceful, the
    /// register behaves as storage. A read returns the value last written
    /// to it, 0 before the first write, and a write is held without the
    /// refused effect ([`Cpu::degraded`](crate::machine::cpu::Cpu)).
    pub(super) fn register_refused(
        &mut self,
        word: u32,
        access: Option<RegisterAccess>,
        refusal: Refusal,
    ) -> Step {
        self.degrade(self.register_requirement(word, access, refusal))?;
        if let Some(access) = access {
            let key = access.encoding().selector();
            let rt = usize::from(access.rt());
            if access.direction() == Direction::Read {
                let value = self.cpu.degraded.get(&key).copied().unwrap_or(0);
                if rt != 31 {
                    self.cpu.state.x[rt] = value;
                }
            } else {
                let value = if rt == 31 { 0 } else { self.cpu.state.x[rt] };
                self.cpu.degraded.insert(key, value);
            }
        }
        self.next()
    }

    /// A completed read of `access`: the value a refused write left in
    /// degraded storage, if one did, else the model's `value`.
    pub(super) fn degraded_read(&self, access: RegisterAccess, value: u64) -> u64 {
        if self.cpu.degraded.is_empty() {
            return value;
        }
        let key = access.encoding().selector();
        self.cpu.degraded.get(&key).copied().unwrap_or(value)
    }

    /// A completed write of `access`: its model holds the register again.
    pub(super) fn degraded_written(&mut self, access: RegisterAccess) {
        if !self.cpu.degraded.is_empty() {
            self.cpu.degraded.remove(&access.encoding().selector());
        }
    }

    /// The requirement of a System register access this machine cannot
    /// carry out in full, with the syndrome its trap would report.
    fn register_requirement(
        &self,
        word: u32,
        access: Option<RegisterAccess>,
        refusal: Refusal,
    ) -> Requirement {
        let mut requirement = self.requirement(RequirementKind::SystemRegister { word, refusal });
        requirement.syndrome = Some(super::exception::syndrome(
            Class::SystemRegister,
            access.map_or(0, registers::trap_iss),
        ));
        requirement
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
    /// IMPLEMENTATION DEFINED option, clears the event register. A WFE that
    /// completes at once still yields the rest of the time slice to the
    /// other PEs (`processors`), as a spin-wait that waits for another PE
    /// would on hardware where they run at the same time; only timing
    /// changes.
    fn wait(&mut self, _word: u32, kind: WaitKind, register: Option<u8>) -> Step {
        const HCR_TWI: u32 = 13;
        const HCR_TWE: u32 = 14;
        if register.is_some() {
            match self.cpu.registers.implemented(Feature::FEAT_WFxT) {
                Ok(true) => {}
                Ok(false) => return self.undefined(),
                Err(reason) => return Err(self.unsupported(RequirementKind::Native(reason))),
            }
        }
        let timeout = register.map(|register| {
            let limit = if register == 31 {
                0
            } else {
                self.cpu.state.x[usize::from(register)]
            };
            // The virtual count of the timer bank the regime reads
            // (`timer::agt`); a scaled bank's limit becomes a system count.
            let bank = timer::agt::selected(&self.cpu);
            let offset = if self.cpu.regime() == crate::machine::cpu::TranslationRegime::El20 {
                0
            } else {
                timer::value(&self.cpu, bank, SystemRegister::CNTVOFF_EL2)
            };
            if timer::scaled(&self.cpu, bank) {
                Timeout {
                    limit: timer::system_count(&self.cpu, bank, limit.wrapping_add(offset)),
                    offset: 0,
                }
            } else {
                Timeout { limit, offset }
            }
        });
        let el = self.cpu.pstate.el;
        let sctlr = self.cpu.regime_sctlr();
        let (enable_bit, hcr_trap, form) = match kind {
            WaitKind::Interrupt => (1u64 << 16, HCR_TWI, 0b00),
            WaitKind::Event => (1u64 << 18, HCR_TWE, 0b01),
        };
        let now = self.now();
        if kind == WaitKind::Event {
            self.sample_events(now);
        }
        match kind {
            WaitKind::Event if self.cpu.consume_event() => {
                // The WFE of a spin-wait ends the PE's time slice: the PE
                // it waits for runs next instead of after the slice.
                self.slice_end = self.statistics.blocks;
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
        // CYC_OVRD's power-down mode turns the core off and loses its state
        // (`processors`). A WFIT's local timeout is the core's own, so it
        // could not end that wait.
        let down = kind == WaitKind::Interrupt
            && self.cpu.wfi_mode() == registers::CYC_OVRD_WFI_POWER_DOWN;
        if down && self.cpu.has_canonical_memory() {
            self.require_native_lifecycle_hold().map_err(|_| {
                self.unsupported(RequirementKind::Native(
                    "native power-down requires the actual held physical roster",
                ))
            })?;
        }
        if down && timeout.is_some() {
            return Err(self.unsupported(RequirementKind::Native(
                "WFIT with CYC_OVRD's power-down mode (a powered-down core has no local timeout)",
            )));
        }
        if down && self.cpu.has_canonical_memory() {
            self.cpu.clear_exclusive().map_err(|_| {
                self.unsupported(RequirementKind::Native("native power-down monitor refused"))
            })?;
        }
        // The PE waits until the scheduler finds it woken
        // (`processors::Peer::ready`) and completes the instruction.
        self.waiting = Some(Wait {
            kind,
            timeout,
            down,
        });
        self.sync_monitor();
        if down {
            self.power_down();
        }
        Ok(())
    }

    /// Arm `AArch64_InterruptPending` for the running PE.
    fn interrupt_pending(&mut self) -> bool {
        let lines = self.lines();
        interrupt_pending(&self.cpu, lines)
    }

    /// SYS and SYSL: the generated accessor of an architectural System
    /// instruction; every other encoding is UNDEFINED. In the
    /// IMPLEMENTATION DEFINED space (CRn 11 and 15) HCR_EL2.TIDCP first
    /// traps EL1 outside the host to EL2, as Arm's accessor for that space
    /// does (the profile has no FEAT_TIDCP1, so SCTLR_ELx.TIDCP is RES0).
    /// Its encodings are then UNDEFINED, Arm's behavior for an unallocated
    /// encoding: no 26A434 SPTM, TXM, kernelcache or system kext of any
    /// chip executes one (`isa/apple-soc-facts.json` has no `S1_` row), so
    /// that the chips allocate none is an inference from the census.
    fn maintenance(&mut self, word: u32, access: RegisterAccess) -> Step {
        if let Some(step) = self.system_access(word, access) {
            return step;
        }
        if matches!(access.encoding().crn(), 11 | 15)
            && self.cpu.pstate.el == 1
            && !self.cpu.in_host()
            && self.cpu.hcr(HCR_TIDCP)
        {
            return self.register_outcome(word, Some(access), RegisterOutcome::Trapped(Some(2)));
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

    #[test]
    fn architectural_translation_generation_exhaustion_never_reuses_an_old_epoch() {
        let operations: [fn(&mut Machine<FakeHost, NoDevices>); 5] = [
            Machine::advance_translation_generation,
            Machine::translations_changed,
            Machine::fetch_permissions_changed,
            |machine| machine.tlb_maintained(mmu::tlbi::Reach::All),
            Machine::table_base_changed,
        ];
        for operation in operations {
            let mut machine = board_on(crate::machine::Chip::AppleM1, &[], NoDevices, Vec::new());
            machine.translation_generation = u64::MAX;
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(&mut machine)))
                    .is_err()
            );
            assert_eq!(machine.translation_generation, u64::MAX);
        }
    }

    pub(super) struct FakeHost {
        pub(super) ram: Vec<u8>,
        pub(super) events: Vec<Event>,
        base: u64,
        pub(super) now: u64,
        pub(super) regimes: Vec<Regime>,
        invalidations: usize,
        /// Calls of [`Host::isolate_predictions`].
        pub(super) isolations: usize,
        /// The pages of [`Host::code_invalidated`] calls.
        pub(super) code_invalidations: Vec<Option<u64>>,
        pub(super) reaches: Vec<mmu::tlbi::Reach>,
        pub(super) installed: Vec<Vec<u8>>,
        /// Executable copies of the context leaves the engine called.
        executables: Vec<crate::execution::platform::Mapping>,
        patches: Vec<(usize, Vec<u8>)>,
        /// The chaining state the next native run leaves, as thunks would.
        chained: Option<(*mut ChainControl, ChainControl)>,
        /// What the next native blocks return, in order: unit tests do not
        /// run native code.
        pub(super) exits: Vec<NativeExit>,
        /// A translation store, for the tests that give the host one.
        pub(super) store: Option<stored::tests::MemoryStore>,
        /// Pages whose fetch the host refuses, and its answers.
        refused: Vec<u64>,
        fetch_checks: usize,
        pub(super) counter_reads: usize,
        placement: mmu::placement::Placement,
        translation_helper: Option<u64>,
        /// What [`Host::memory_low`] answers.
        pub(super) memory_low: bool,
        /// Installs per part of a code arena of two parts reclaimed in
        /// turn, and its parts' code addresses, oldest first; `None` for an
        /// arena of one part.
        pub(super) ring: Option<usize>,
        parts: Vec<core::ops::Range<usize>>,
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
            if let Some(installs) = self.ring {
                let next = self.installed.len() + 1;
                let part = match self.parts.last_mut() {
                    Some(part) => part,
                    None => {
                        self.parts.push(next..next);
                        self.parts.last_mut().unwrap()
                    }
                };
                if part.len() == installs {
                    return Err(InstallError::Full);
                }
                part.end += 1;
            }
            self.installed.push(code.to_vec());
            Ok(NativeCode(self.installed.len()))
        }
        fn reclaim_code(&mut self) -> Option<core::ops::Range<usize>> {
            self.ring?;
            let next = self.installed.len() + 1;
            self.parts.push(next..next);
            Some(match self.parts.len() > 2 {
                true => self.parts.remove(0),
                false => 0..0,
            })
        }
        fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
            self.patches.push((code.0, bytes.to_vec()));
        }
        fn discard_code(&mut self) {
            self.installed.clear();
            self.executables.clear();
        }
        fn memory_low(&self) -> bool {
            self.memory_low
        }
        fn context_entry(&mut self, code: NativeCode) -> Option<usize> {
            // Context leaves run: they touch only the state, the context and
            // the memory service.
            let mapping = crate::execution::platform::Mapping::new(&self.installed[code.0 - 1])
                .expect("an executable mapping of the leaf");
            let entry = mapping.entry();
            self.executables.push(mapping);
            Some(entry)
        }
        unsafe fn execute(&mut self, _: NativeCode, _: &mut GuestState) -> NativeExit {
            assert!(!self.exits.is_empty(), "unit tests do not run native code");
            if let Some((control, chained)) = self.chained.take() {
                // SAFETY: the test points at the machine's boxed control.
                unsafe { *control = chained };
            }
            self.exits.remove(0)
        }
        fn set_regime(&mut self, regime: &Regime) {
            self.regimes.push(*regime);
        }
        fn isolate_predictions(&mut self) {
            self.isolations += 1;
        }
        fn code_invalidated(&mut self, page: Option<u64>) {
            self.code_invalidations.push(page);
        }
        fn fetch_permitted(&mut self, virtual_address: u64) -> bool {
            self.fetch_checks += 1;
            !self
                .refused
                .contains(&(virtual_address & !(FETCH_PAGE - 1)))
        }
        fn placement(&self) -> mmu::placement::Placement {
            self.placement
        }
        fn translation_helper(&self) -> Option<u64> {
            self.translation_helper
        }
        fn invalidate_translations(&mut self) {
            self.invalidations += 1;
        }
        fn invalidate_reach(&mut self, reach: mmu::tlbi::Reach) {
            self.reaches.push(reach);
            if reach == mmu::tlbi::Reach::All {
                self.invalidations += 1;
            }
        }
        fn counter(&mut self) -> u64 {
            self.counter_reads += 1;
            self.now
        }
        fn arm_timer(&mut self, _: Option<u64>) {}
        fn wait_for_interrupt(&mut self) {
            self.now += 1000;
        }
        fn report(&mut self, event: &Event) {
            self.events.push(*event);
        }
        fn translations(&mut self) -> Option<&mut dyn Translations> {
            self.store
                .as_mut()
                .map(|store| store as &mut dyn Translations)
        }
    }

    pub(super) const BASE: u64 = 0x8_0000_0000;

    /// A machine running `words` at BASE on PE 0 at EL1 of the chip the
    /// tests run on ([`crate::machine::test_chip`]).
    pub(super) fn machine(words: &[u32]) -> Machine<FakeHost, NoDevices> {
        board(words, NoDevices, Vec::new())
    }

    /// The chip the tests run on, or the M2 where it has the Apple generic
    /// timer's two banks (`timer::agt`): for tests of one bank's
    /// architectural generic timer.
    pub(super) fn one_timer_bank() -> crate::machine::Chip {
        let chip = crate::machine::test_chip();
        if crate::machine::timer::agt::present(chip) {
            crate::machine::Chip::AppleM2
        } else {
            chip
        }
    }

    /// [`machine`] on `chip`, for a test that fixes its chip.
    pub(super) fn machine_on(
        chip: crate::machine::Chip,
        words: &[u32],
    ) -> Machine<FakeHost, NoDevices> {
        board_on(chip, words, NoDevices, Vec::new())
    }

    /// Identity-map the test RAM as Normal Write-Back through stage 1 of
    /// both regimes (4 KiB granule, T0SZ 25, one 1 GiB block, EL0 access
    /// with `el0`, whose writable mapping EL1 cannot execute), for DC ZVA,
    /// which faults on the Device memory of a disabled stage 1.
    pub(super) fn normal_memory(machine: &mut Machine<FakeHost, NoDevices>, el0: bool) {
        const TABLE: usize = 0xf000;
        const TCR: u64 = 25 | 1 << 8 | 1 << 10 | 3 << 12 | 1 << 23 | 5 << 32;
        const SCTLR_M_C: u64 = 1 | 1 << 2;
        let block = BASE | 1 << 10 | 3 << 8 | if el0 { 1 << 6 } else { 0 } | 0b01;
        let entry = TABLE + (BASE >> 30) as usize * 8;
        machine.host.ram[entry..entry + 8].copy_from_slice(&block.to_le_bytes());
        let registers = &mut machine.cpu.registers;
        for (table, control, attributes, sctlr) in [
            (
                SystemRegister::TTBR0_EL1,
                SystemRegister::TCR_EL1,
                SystemRegister::MAIR_EL1,
                SystemRegister::SCTLR_EL1,
            ),
            (
                SystemRegister::TTBR0_EL2,
                SystemRegister::TCR_EL2,
                SystemRegister::MAIR_EL2,
                SystemRegister::SCTLR_EL2,
            ),
        ] {
            registers.set(table, 0, BASE + TABLE as u64);
            registers.set(control, 0, TCR);
            registers.set(attributes, 0, 0xff);
            let value = registers.get(sctlr, 0) | SCTLR_M_C;
            registers.set(sctlr, 0, value);
        }
        machine.translations_changed();
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
            events: Vec::new(),
            base: BASE,
            now: 0,
            regimes: Vec::new(),
            invalidations: 0,
            isolations: 0,
            code_invalidations: Vec::new(),
            reaches: Vec::new(),
            installed: Vec::new(),
            executables: Vec::new(),
            patches: Vec::new(),
            chained: None,
            exits: Vec::new(),
            store: None,
            refused: Vec::new(),
            fetch_checks: 0,
            counter_reads: 0,
            placement: mmu::placement::Placement::FiveLevel,
            translation_helper: None,
            memory_low: false,
            ring: None,
            parts: Vec::new(),
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

    /// Devices whose registers read their own PA's low 32 bits with the
    /// top bit set, recording every access in order.
    #[derive(Default)]
    struct Recorder {
        accesses: Vec<(u64, u8, Option<u64>)>,
    }

    impl Devices for Recorder {
        fn read(&mut self, _: usize, physical: u64, bytes: u8, _: u64) -> Result<u64, DeviceError> {
            self.accesses.push((physical, bytes, None));
            Ok(0x8000_0000 | (physical & 0xffff))
        }
        fn write(
            &mut self,
            _: usize,
            physical: u64,
            bytes: u8,
            value: u64,
            _: u64,
        ) -> Result<(), DeviceError> {
            self.accesses.push((physical, bytes, Some(value)));
            Ok(())
        }
        fn lines(&mut self, _: usize, _: u64) -> Lines {
            Lines::default()
        }
    }

    #[test]
    fn unsupported_instructions_stop_strictly_or_are_undefined_once_reported() {
        let mut machine = machine(&[]);
        let instruction = |machine: &Machine<_, _>| {
            machine.unsupported(RequirementKind::Instruction {
                word: 0xd500_0000,
                detail: "an instruction the engine lacks".into(),
            })
        };
        machine.cpu.pc = BASE;
        let stop = instruction(&machine);
        assert!(matches!(
            machine.undefined_instead(stop),
            Err(Stop::Unsupported(_))
        ));
        assert_eq!(machine.cpu.pc, BASE);
        machine.set_strict(false);
        for _ in 0..2 {
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.cpu.pc = BASE;
            let stop = instruction(&machine);
            machine.undefined_instead(stop).unwrap();
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
        }
        assert_eq!(machine.take_unmodeled().len(), 1);
        assert_eq!(machine.statistics.degraded, 2);
        // A stop raised elsewhere than the PE's instruction, or an engine
        // limit with no architectural answer, still stops.
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        let elsewhere = instruction(&machine);
        machine.cpu.pc = BASE + 4;
        assert!(machine.undefined_instead(elsewhere).is_err());
        let limit = machine.unsupported(RequirementKind::Native("an engine limit"));
        assert!(machine.undefined_instead(limit).is_err());
        assert!(machine.undefined_instead(Stop::Idle).is_err());
    }

    #[test]
    fn fetches_outside_memory_stop_strictly_or_take_an_external_abort() {
        const OUTSIDE: u64 = BASE - 0x1000;
        let mut machine = machine(&[]);
        machine.cpu.pc = OUTSIDE;
        assert!(matches!(
            machine.fetch_block(OUTSIDE, false),
            Err(Stop::Unsupported(Requirement {
                kind: RequirementKind::Fetch { .. },
                ..
            }))
        ));
        machine.set_strict(false);
        let Ok(Fetched::Exception(exception)) = machine.fetch_block(OUTSIDE, false) else {
            panic!("graceful fetches outside memory abort");
        };
        assert_eq!(
            exception.syndrome,
            super::super::exception::syndrome(
                Class::InstructionAbortSame,
                SYNCHRONOUS_EXTERNAL_ABORT
            )
        );
        assert_eq!(exception.fault_address, Some(OUTSIDE));
        assert_eq!(machine.take_unmodeled().len(), 1);
    }

    #[test]
    fn refused_system_registers_stop_strictly_or_act_as_storage_once_reported() {
        // MRS and MSR x0 of S3_4_C15_C13_6, an implementation-defined
        // storage register, and S3_4_C15_C12_0, a control register that
        // takes no set bit (`machine::impdef`).
        const KEY_READ: u32 = 0xd53c_fdc0;
        const CONTROL_READ: u32 = 0xd53c_fc00;
        const CONTROL_WRITE: u32 = 0xd51c_fc00;
        let mut machine = machine_on(crate::machine::Chip::AppleM2, &[]);
        machine.cpu.set_pstate(Pstate::reset(1));
        let run = |machine: &mut Machine<_, _>, word, x0| {
            machine.cpu.pc = BASE;
            machine.cpu.state.x[0] = x0;
            let step = machine.system_instruction(word);
            (step, machine.cpu.state.x[0])
        };
        // Strict: the read before the first write, whose value is unknown,
        // and the setting the model cannot honor stop.
        for (word, x0) in [(KEY_READ, 0xdead), (CONTROL_WRITE, 5)] {
            let (step, _) = run(&mut machine, word, x0);
            assert!(matches!(step, Err(Stop::Unsupported(_))));
            assert_eq!(machine.cpu.pc, BASE);
        }
        machine.set_strict(false);
        // Graceful: the read returns 0, and the control holds the refused
        // setting without its effect.
        assert_eq!(run(&mut machine, KEY_READ, 0xdead), (Ok(()), 0));
        assert_eq!(machine.cpu.pc, BASE + 4);
        for _ in 0..2 {
            assert_eq!(run(&mut machine, CONTROL_WRITE, 5), (Ok(()), 5));
            assert_eq!(run(&mut machine, CONTROL_READ, 0), (Ok(()), 5));
        }
        // A setting the model accepts returns the register to it.
        assert_eq!(run(&mut machine, CONTROL_WRITE, 0), (Ok(()), 0));
        assert_eq!(run(&mut machine, CONTROL_READ, 7), (Ok(()), 0));
        assert_eq!(machine.take_unmodeled().len(), 2);
        assert_eq!(machine.statistics.degraded, 3);
    }

    #[test]
    fn refused_device_registers_stop_strictly_or_read_zero_and_drop_writes() {
        const DEVICE: u64 = 0x2_3b3c_0a00;
        // ldr x2, [x1]; str x2, [x1]
        let (load, store) = (0xf940_0022, 0xf900_0022);
        for strict in [true, false] {
            let mut devices = pair_fault_device();
            devices.refused = Some(DEVICE);
            let mut machine = board(&[], devices, Vec::new());
            machine.set_strict(strict);
            machine.write_register(Register::X(1), DEVICE);
            let esr = machine.cpu.read(SystemRegister::ESR_EL1);
            for (word, write) in [(load, false), (store, true), (load, false)] {
                machine.cpu.pc = BASE;
                machine.write_register(Register::X(2), 0x1234);
                let step = machine.device_access(word, DEVICE, DEVICE, write);
                if strict {
                    assert!(matches!(step, Err(Stop::Unsupported(_))));
                    assert_eq!(machine.cpu.pc, BASE);
                    assert_eq!(machine.read_register(Register::X(2)), 0x1234);
                } else {
                    step.unwrap();
                    assert_eq!(machine.cpu.pc, BASE + 4);
                    let expected = if write { 0x1234 } else { 0 };
                    assert_eq!(machine.read_register(Register::X(2)), expected);
                }
            }
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), esr);
            assert!(machine.devices.stores.is_empty());
            // One report per register and direction.
            assert_eq!(machine.take_unmodeled().len(), if strict { 0 } else { 2 });
        }
    }

    #[test]
    fn survey_substitutes_registers_but_never_dma_service_effects() {
        let mut machine = machine(&[0]);
        machine.begin_survey();
        assert!(!machine.surveyed(
            0x1000,
            4,
            Some(1),
            &DeviceError::TransferRefused("missing DMA/key service".into())
        ));
        assert!(machine.take_survey().is_empty());
        assert!(machine.surveyed(
            0x1000,
            4,
            None,
            &DeviceError::Refused("unknown register".into())
        ));
        assert_eq!(machine.take_survey().len(), 1);
    }

    #[test]
    fn unmapped_device_accesses_stop_strictly_or_take_an_external_abort_once_reported() {
        const DEVICE: u64 = 0x2_3d2b_0010;
        // ldr w0, [x1]; str w0, [x1]
        let (load, store) = (0xb940_0020, 0xb900_0020);
        let mut machine = machine(&[0]);
        machine.write_register(Register::X(1), DEVICE);
        machine.set_strict(true);
        assert!(matches!(
            machine.device_access(load, DEVICE, DEVICE, false),
            Err(Stop::Unsupported(_))
        ));
        machine.set_strict(false);
        for (word, write) in [(load, false), (store, true), (load, false)] {
            machine.cpu.pc = BASE;
            machine.device_access(word, DEVICE, DEVICE, write).unwrap();
            // A data abort at EL1 from EL1: EC 0x25, IL, DFSC 0b010000, WnR.
            let wnr = if write { 1 << 6 } else { 0 };
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x9600_0010 | wnr);
            assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), DEVICE);
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
        }
        // One report per register and direction.
        let reports = machine.take_unmodeled();
        assert_eq!(reports.len(), 2);
        assert!(matches!(
            reports[1].kind,
            RequirementKind::Device { write: true, .. }
        ));
        assert!(machine.take_unmodeled().is_empty());
    }

    #[test]
    fn device_pairs_are_two_ascending_accesses_in_register_order() {
        const DEVICE: u64 = 0x2_3b3c_0a00;
        let mut machine = board(&[], Recorder::default(), Vec::new());
        // ldp x2, x3, [x1, #16]!
        machine.write_register(Register::X(1), DEVICE - 16);
        machine
            .device_access(0xa9c1_0c22, DEVICE, DEVICE, false)
            .unwrap();
        assert_eq!(
            machine.devices.accesses,
            [(DEVICE, 8, None), (DEVICE + 8, 8, None)]
        );
        assert_eq!(machine.read_register(Register::X(2)), 0x8000_0a00);
        assert_eq!(machine.read_register(Register::X(3)), 0x8000_0a08);
        assert_eq!(machine.read_register(Register::X(1)), DEVICE);
        assert_eq!(machine.cpu.pc, BASE + 4);
        // ldpsw x2, x3, [x1] sign-extends each word.
        machine.devices.accesses.clear();
        machine
            .device_access(0x6940_0c22, DEVICE, DEVICE, false)
            .unwrap();
        assert_eq!(
            machine.devices.accesses,
            [(DEVICE, 4, None), (DEVICE + 4, 4, None)]
        );
        assert_eq!(machine.read_register(Register::X(3)), 0xffff_ffff_8000_0a04);
        // stp x2, x3, [x1]
        machine.devices.accesses.clear();
        machine
            .device_access(0xa900_0c22, DEVICE, DEVICE, true)
            .unwrap();
        assert_eq!(
            machine.devices.accesses,
            [
                (DEVICE, 8, Some(0xffff_ffff_8000_0a00)),
                (DEVICE + 8, 8, Some(0xffff_ffff_8000_0a04))
            ]
        );
        // A pair whose second element lies on another page refuses.
        machine.write_register(Register::X(1), DEVICE + 0x5f8);
        assert!(matches!(
            machine.device_access(0xa940_0c22, DEVICE + 0x5f8, DEVICE + 0x5f8, false),
            Err(Stop::Unsupported(_))
        ));
    }

    /// A real register store can start DMA that commits before later failure.
    /// This fixture distinguishes refused register writes from failed service.
    struct PairFaultDevice {
        refused: Option<u64>,
        failed_transfer: Option<usize>,
        reads: Vec<u64>,
        stores: Vec<(u64, u64)>,
        transfers: usize,
        pair: Option<Result<ConsumedPair, DeviceError>>,
        pair_reads: usize,
    }

    impl Devices for PairFaultDevice {
        fn read_pair(
            &mut self,
            _: usize,
            _: u64,
            _: u8,
            _: u64,
        ) -> Result<Option<ConsumedPair>, DeviceError> {
            let Some(pair) = self.pair.clone() else {
                return Ok(None);
            };
            self.pair_reads += 1;
            pair.map(Some)
        }
        fn read(&mut self, _: usize, physical: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
            self.reads.push(physical);
            if self.refused == Some(physical) {
                return Err(DeviceError::Refused("injected register refusal".into()));
            }
            Ok(physical)
        }
        fn write(
            &mut self,
            _: usize,
            physical: u64,
            _: u8,
            value: u64,
            _: u64,
        ) -> Result<(), DeviceError> {
            if self.refused == Some(physical) {
                return Err(DeviceError::Refused("injected register refusal".into()));
            }
            self.stores.push((physical, value));
            Ok(())
        }
        fn transfer(
            &mut self,
            _: usize,
            memory: &mut dyn Memory,
            _: u64,
        ) -> Result<(), DeviceError> {
            let index = self.transfers;
            self.transfers += 1;
            let (_, value) = self.stores[index];
            assert!(memory.write(BASE + 0x800 + index as u64 * 8, &value.to_le_bytes()));
            if self.failed_transfer == Some(index) {
                // Deliberately use an ordinary register error: the engine
                // knows this came from service and must never survey it.
                return Err(DeviceError::Refused("injected later DMA failure".into()));
            }
            Ok(())
        }
        fn lines(&mut self, _: usize, _: u64) -> Lines {
            Lines::default()
        }
    }

    fn pair_fault_device() -> PairFaultDevice {
        PairFaultDevice {
            refused: None,
            failed_transfer: None,
            reads: Vec::new(),
            stores: Vec::new(),
            transfers: 0,
            pair: None,
            pair_reads: 0,
        }
    }

    #[test]
    fn device_dma_preflights_the_actual_memory_lock_before_any_copy() {
        let mut machine = board(&[], pair_fault_device(), Vec::new());
        let first = BASE + 0x808;
        let last = BASE + 0x80f;
        let mut memory = HostMemory {
            host: &mut machine.host,
            lock: [Some((first, last)), None, None, None],
        };
        let mut before = [0u8; 32];
        assert!(memory.read(BASE + 0x800, &mut before));
        for (at, bytes) in [(first, 1), (last, 1), (first - 4, 8), (first - 8, 32)] {
            assert!(!memory.write(at, &vec![0xa5; bytes]));
            let mut observed = [0; 32];
            assert!(memory.read(BASE + 0x800, &mut observed));
            assert_eq!(observed, before);
        }
        assert!(memory.write(first - 8, &[0x12; 8]));
        assert!(memory.write(last + 1, &[0x34; 8]));
        let mut observed = [0; 32];
        assert!(memory.read(BASE + 0x800, &mut observed));
        assert_eq!(&observed[..8], &[0x12; 8]);
        assert_eq!(&observed[8..16], &[0; 8]);
        assert_eq!(&observed[16..24], &[0x34; 8]);
        // Reads of locked RAM remain ordinary RAM reads. Address overflow
        // refuses before calling the native copy provider, even without a lock.
        memory.lock = [None; 4];
        assert!(!memory.write(u64::MAX - 1, &[0x56; 4]));
    }

    #[test]
    fn consumed_device_pair_retires_before_reporting_later_board_failure() {
        const DEVICE: u64 = 0x2_3b3c_0a00;
        for strict in [false, true] {
            for survey in [false, true] {
                for writeback in [false, true] {
                    let mut devices = pair_fault_device();
                    devices.pair = Some(Ok(ConsumedPair {
                        values: [0x1234, 0x5678],
                        settlement: Err(DeviceError::Refused("retained wire failure".into())),
                    }));
                    let mut machine = board(&[], devices, Vec::new());
                    machine.set_strict(strict);
                    if survey {
                        machine.begin_survey();
                    }
                    machine.set_watches(&[(DEVICE, 16)]);
                    machine.cpu.pstate.btype = 1;
                    machine.write_register(Register::X(1), DEVICE - 16);
                    machine.write_register(Register::X(8), DEVICE);
                    machine.write_register(Register::X(9), 0xdead);
                    let esr = machine.cpu.read(SystemRegister::ESR_EL1);
                    let elr = machine.cpu.read(SystemRegister::ELR_EL1);
                    // Original PTD shape: ldp x8, x9, [x8]. Also cover
                    // pre-indexed ldp x2, x3, [x1, #16]! independently.
                    let word = if writeback { 0xa9c1_0c22 } else { 0xa940_2508 };
                    // Strict, the failure stops; graceful, it is reported
                    // once. Neither aborts nor replays the consumed access.
                    let requirement = match machine.device_access(word, DEVICE, DEVICE, false) {
                        Err(Stop::Unsupported(requirement)) if strict => requirement,
                        Ok(()) if !strict => {
                            let mut reports = machine.take_unmodeled();
                            assert_eq!(reports.len(), 1);
                            reports.remove(0)
                        }
                        other => panic!("consumed service failure: {other:?}"),
                    };
                    assert_eq!(requirement.pc, BASE);
                    assert_eq!(requirement.address, Some(DEVICE));
                    assert!(matches!(requirement.kind, RequirementKind::Device {
                        physical: DEVICE, write: false, ref detail
                    } if detail.contains("retained wire failure")));
                    assert_eq!(machine.cpu.pc, BASE + 4);
                    assert_eq!(machine.cpu.pstate.btype, 0);
                    assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), esr);
                    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), elr);
                    let data = if writeback { [2, 3] } else { [8, 9] };
                    assert_eq!(machine.read_register(Register::X(data[0])), 0x1234);
                    assert_eq!(machine.read_register(Register::X(data[1])), 0x5678);
                    assert_eq!(
                        machine.read_register(Register::X(1)),
                        if writeback { DEVICE } else { DEVICE - 16 }
                    );
                    assert_eq!(machine.devices.pair_reads, 1);
                    assert!(machine.devices.reads.is_empty());
                    assert!(machine.devices.stores.is_empty());
                    assert_eq!(machine.devices.transfers, 0);
                    assert!(machine.take_survey().is_empty());
                    let hits = machine.take_watch_hits();
                    assert_eq!(hits.len(), 2);
                    for (index, hit) in hits.iter().enumerate() {
                        assert_eq!(hit.pc, BASE);
                        assert_eq!(hit.physical, DEVICE + index as u64 * 8);
                        assert_eq!(hit.value, [0x1234, 0x5678][index]);
                        assert!(hit.completed && !hit.write);
                    }
                }
            }
        }
    }

    #[test]
    fn whole_device_pair_refusal_precedes_consumption_and_retirement() {
        const DEVICE: u64 = 0x2_3b3c_0a00;
        for strict in [true, false] {
            let mut devices = pair_fault_device();
            devices.pair = Some(Err(DeviceError::Refused("unknown publication".into())));
            let mut machine = board(&[], devices, Vec::new());
            machine.set_strict(strict);
            machine.write_register(Register::X(8), DEVICE);
            machine.write_register(Register::X(9), 0xdead);
            let esr = machine.cpu.read(SystemRegister::ESR_EL1);
            let result = machine.device_access(0xa940_2508, DEVICE, DEVICE, false);
            if strict {
                // Nothing retires before the stop.
                assert!(matches!(result, Err(Stop::Unsupported(_))));
                assert_eq!(machine.cpu.pc, BASE);
                assert_eq!(machine.read_register(Register::X(8)), DEVICE);
                assert_eq!(machine.read_register(Register::X(9)), 0xdead);
            } else {
                // A register the device refuses reads 0, reported once.
                result.unwrap();
                assert_eq!(machine.cpu.pc, BASE + 4);
                assert_eq!(machine.read_register(Register::X(8)), 0);
                assert_eq!(machine.read_register(Register::X(9)), 0);
                assert_eq!(machine.take_unmodeled().len(), 1);
            }
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), esr);
            assert_eq!(machine.devices.pair_reads, 1);
            assert!(machine.devices.reads.is_empty());
        }
    }

    #[test]
    fn device_pair_store_faults_keep_committed_register_and_dma_prefixes_without_writeback() {
        const DEVICE: u64 = 0x2_3b3c_0a00;
        for failed_element in 0..2 {
            for service_failure in [false, true] {
                let mut devices = pair_fault_device();
                if service_failure {
                    devices.failed_transfer = Some(failed_element);
                } else {
                    devices.refused = Some(DEVICE + failed_element as u64 * 8);
                }
                let mut machine = board(&[], devices, Vec::new());
                machine.set_strict(true);
                machine.set_watches(&[(DEVICE, 16)]);
                machine.write_register(Register::X(1), DEVICE - 16);
                machine.write_register(Register::X(2), 0x1234);
                machine.write_register(Register::X(3), 0x5678);
                // stp x2, x3, [x1, #16]!
                let Err(Stop::Unsupported(requirement)) =
                    machine.device_access(0xa981_0c22, DEVICE, DEVICE, true)
                else {
                    panic!("the pair must expose its original failure");
                };
                let failed_address = DEVICE + failed_element as u64 * 8;
                assert_eq!(requirement.address, Some(failed_address));
                assert!(
                    matches!(requirement.kind, RequirementKind::Device { physical, write: true, .. } if physical == failed_address)
                );
                assert_eq!(machine.cpu.pc, BASE);
                assert_eq!(machine.read_register(Register::X(1)), DEVICE - 16);
                let committed = failed_element + usize::from(service_failure);
                assert_eq!(machine.devices.stores.len(), committed);
                assert_eq!(machine.devices.transfers, committed);
                let mut ram = [0; 16];
                assert!(machine.host.read_ram(BASE + 0x800, &mut ram));
                let mut expected = [0; 16];
                for (index, value) in [0x1234u64, 0x5678].into_iter().take(committed).enumerate() {
                    expected[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
                }
                assert_eq!(ram, expected);
                let hits = machine.take_watch_hits();
                assert_eq!(hits.len(), failed_element + 1);
                assert_eq!(hits.iter().filter(|hit| hit.completed).count(), committed);
                assert!(hits.iter().all(|hit| hit.write));
            }
        }
    }

    #[test]
    fn survey_never_substitutes_a_failed_service_after_an_accepted_scalar_or_pair_store() {
        const DEVICE: u64 = 0x2_3b3c_0a00;
        for word in [0xb900_0022, 0xa900_0c22] {
            // str w2 / stp x2, x3, [x1]
            let mut devices = pair_fault_device();
            devices.failed_transfer = Some(0);
            let mut machine = board(&[], devices, Vec::new());
            machine.set_strict(true);
            machine.begin_survey();
            machine.write_register(Register::X(1), DEVICE);
            machine.write_register(Register::X(2), 0x1234);
            machine.write_register(Register::X(3), 0x5678);
            assert!(matches!(
                machine.device_access(word, DEVICE, DEVICE, true),
                Err(Stop::Unsupported(_))
            ));
            assert_eq!(machine.cpu.pc, BASE);
            assert_eq!(machine.devices.stores, [(DEVICE, 0x1234)]);
            assert_eq!(machine.devices.transfers, 1);
            assert!(machine.take_survey().is_empty());
            let mut committed = [0; 8];
            assert!(machine.host.read_ram(BASE + 0x800, &mut committed));
            assert_eq!(u64::from_le_bytes(committed), 0x1234);
        }
    }

    #[test]
    fn device_pair_load_refusal_preserves_both_destinations_and_reports_the_failed_member() {
        const DEVICE: u64 = 0x2_3b3c_0a00;
        for strict in [true, false] {
            for failed_element in 0..2 {
                let failed_address = DEVICE + failed_element as u64 * 8;
                let mut devices = pair_fault_device();
                devices.refused = Some(failed_address);
                let mut machine = board(&[], devices, Vec::new());
                machine.set_strict(strict);
                machine.write_register(Register::X(1), DEVICE - 16);
                machine.write_register(Register::X(2), 0x1234);
                machine.write_register(Register::X(3), 0x5678);
                // ldp x2, x3, [x1, #16]!
                let result = machine.device_access(0xa9c1_0c22, DEVICE, DEVICE, false);
                if strict {
                    let Err(Stop::Unsupported(requirement)) = result else {
                        panic!("strict mode stops");
                    };
                    assert_eq!(requirement.address, Some(failed_address));
                    assert_eq!(machine.read_register(Register::X(1)), DEVICE - 16);
                    assert_eq!(machine.read_register(Register::X(2)), 0x1234);
                    assert_eq!(machine.read_register(Register::X(3)), 0x5678);
                    assert_eq!(machine.devices.reads.len(), failed_element + 1);
                } else {
                    // The refused member reads 0 and the pair completes.
                    result.unwrap();
                    let other = DEVICE + (1 - failed_element) as u64 * 8;
                    let mut values = [other, other];
                    values[failed_element] = 0;
                    assert_eq!(machine.read_register(Register::X(1)), DEVICE);
                    assert_eq!(machine.read_register(Register::X(2)), values[0]);
                    assert_eq!(machine.read_register(Register::X(3)), values[1]);
                    assert_eq!(machine.devices.reads.len(), 2);
                    let reports = machine.take_unmodeled();
                    assert_eq!(reports.len(), 1);
                    assert_eq!(reports[0].address, Some(failed_address));
                }
                assert!(machine.devices.stores.is_empty());
            }
        }
    }

    #[test]
    fn watched_device_ranges_record_each_access_and_its_value() {
        const DEVICE: u64 = 0x3_8228_c80c;
        let mut machine = board(&[], Recorder::default(), Vec::new());
        machine.set_watches(&[(0x3_8228_0000, 0x10_0000)]);
        // ldr w2, [x1]; str w2, [x1]
        machine.write_register(Register::X(1), DEVICE);
        machine
            .device_access(0xb940_0022, DEVICE, DEVICE, false)
            .unwrap();
        machine
            .device_access(0xb900_0022, DEVICE, DEVICE, true)
            .unwrap();
        // An access outside every watch is not recorded.
        machine.write_register(Register::X(1), 0x2_3b3c_0a00);
        machine
            .device_access(0xb940_0022, 0x2_3b3c_0a00, 0x2_3b3c_0a00, false)
            .unwrap();
        let hits = machine.take_watch_hits();
        assert_eq!(
            hits.iter()
                .map(|hit| (hit.physical, hit.bytes, hit.value, hit.write, hit.completed))
                .collect::<Vec<_>>(),
            [
                (DEVICE, 4, 0x8000_c80c, false, true),
                (DEVICE, 4, 0x8000_c80c, true, true)
            ]
        );
        assert!(machine.take_watch_hits().is_empty());
    }

    #[test]
    fn host_breakpoints_end_blocks_and_stop_before_their_instruction() {
        // add x0, x0, #1 (three times); svc #0
        let add = 0x9100_0400;
        let mut machine = machine(&[add, add, add, 0xd400_0001]);
        machine.set_breakpoints(&[BASE + 8]);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("block")
        };
        assert_eq!(machine.blocks[index].source_map.len(), 2);
        machine.cpu.pc = BASE + 8;
        assert!(matches!(machine.step(), Err(Stop::Breakpoint(pc)) if pc == BASE + 8));
        assert_eq!(machine.cpu.state.x[0], 0);
    }

    #[test]
    fn trace_points_end_blocks_and_record_each_entry_without_stopping() {
        // add x0, x0, #1 (twice); fmov d0, d0, which traps with FP access
        // disabled, so the step completes without native code.
        let add = 0x9100_0400;
        let mut machine = machine(&[add, add, 0x1e60_4000]);
        machine.set_traces(&[BASE + 8]);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("block")
        };
        assert_eq!(machine.blocks[index].source_map.len(), 2);
        machine.cpu.pc = BASE + 8;
        machine.cpu.state.x[0] = 7;
        machine.step().unwrap();
        let hits = machine.take_trace_hits();
        assert_eq!(hits.len(), 1);
        assert_eq!((hits[0].pc, hits[0].arguments[0]), (BASE + 8, 7));
        assert_ne!(machine.cpu.pc, BASE + 8, "the step went on, to the FP trap");
        assert!(machine.take_trace_hits().is_empty());
        for _ in 0..TRACE_HITS + 3 {
            machine.trace(BASE);
        }
        let hits = machine.take_trace_hits();
        assert_eq!((hits.len(), hits[TRACE_HITS - 1].dropped), (TRACE_HITS, 3));
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
    fn pstate_dit_selects_blocks_compiled_for_the_data_independent_timing_target() {
        const LDADD_W1_W0_X2: u32 = 0xb821_0040;
        const SVC_0: u32 = 0xd400_0001;
        const LOCK_XADD: [u8; 3] = [0xf0, 0x0f, 0xc1];
        // add r8d,ecx; mov [rdx],r8d: the plain update and store.
        const PLAIN_ADD_STORE: [u8; 6] = [0x41, 0x01, 0xc8, 0x44, 0x89, 0x02];
        let has = |machine: &Machine<FakeHost, NoDevices>, index: usize, bytes: &[u8]| {
            let code = &machine.host.installed[machine.blocks[index].code.0 - 1];
            code.windows(bytes.len()).any(|window| window == bytes)
        };
        let mut machine = machine(&[LDADD_W1_W0_X2, SVC_0]);
        // Without a host that gives the guarantee, PSTATE.DIT changes no code.
        // The engine runs one PE at a time, so its atomics are plain accesses
        // either way, which load first and so report WnR as Arm requires.
        machine.cpu.pstate.dit = true;
        let Ok(Fetched::Block(untimed)) = machine.fetch_block(BASE, false) else {
            panic!("block")
        };
        assert!(!machine.blocks[untimed].variant.timing);
        assert!(has(&machine, untimed, &PLAIN_ADD_STORE) && !has(&machine, untimed, &LOCK_XADD));
        machine.cpu.pstate.dit = false;
        assert!(matches!(machine.fetch_block(BASE, false), Ok(Fetched::Block(i)) if i == untimed));
        // With one, PSTATE.DIT selects a block of its own.
        machine.target = TargetCpu::Sse42Complete.with_doit();
        machine.cpu.pstate.dit = true;
        let Ok(Fetched::Block(timed)) = machine.fetch_block(BASE, false) else {
            panic!("timed block")
        };
        assert_ne!(timed, untimed);
        assert!(machine.blocks[timed].variant.timing);
        assert!(has(&machine, timed, &PLAIN_ADD_STORE) && !has(&machine, timed, &LOCK_XADD));
        machine.cpu.pstate.dit = false;
        assert!(matches!(machine.fetch_block(BASE, false), Ok(Fetched::Block(i)) if i == untimed));
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
            registers: [0; 16],
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
        // An address outside both ranges, such as Stela's window, takes the
        // fault of its translation: with the MMU off, an Address size fault
        // at level 0 (DFSC 0). An Alignment fault still comes first.
        const WINDOW: u64 = 0x0040_0000_0000_0000;
        for index in 0..5 {
            let write = if index == 3 { 1 << 6 } else { 0 };
            assert_eq!(
                run(index, WINDOW, 0).0.unwrap(),
                (0x9600_0000 | write, WINDOW),
                "{index}"
            );
        }
        assert_eq!(run(0, WINDOW + 4, SCTLR_A).0.unwrap(), (load, WINDOW + 4));
    }

    /// On a four-level host, an access to an address the guest maps below
    /// the native upper range, where Stela's window is, runs its page in
    /// the translated variant from the faulting instruction; the same
    /// address is native under LA57, and a host without the translation
    /// helper stops explicitly.
    #[test]
    fn a_mapped_address_outside_the_native_ranges_runs_its_page_translated() {
        // TTBR1_EL1 at 47 bits with a 4 KiB granule: L0 entry 0, then a
        // 1 GiB block of L1 entry 0, maps the upper half's first GiB to RAM.
        const LEVEL0: u64 = 0xd000;
        const LEVEL1: u64 = 0xe000;
        const TCR: u64 = 25
            | 1 << 8
            | 1 << 10
            | 3 << 12
            | 17 << 16
            | 1 << 24
            | 1 << 26
            | 3 << 28
            | 0b10 << 30
            | 5 << 32;
        const ADDRESS: u64 = mmu::placement::UPPER_HALF + 0x100;
        let mut machine = machine(&[0xf940_0020]); // ldr x0, [x1]
        normal_memory(&mut machine, false);
        let table = |machine: &mut Machine<FakeHost, NoDevices>, at: u64, entry: u64| {
            let at = at as usize;
            machine.host.ram[at..at + 8].copy_from_slice(&entry.to_le_bytes());
        };
        table(&mut machine, LEVEL0, (BASE + LEVEL1) | 0b11);
        table(&mut machine, LEVEL1, BASE | 1 << 10 | 3 << 8 | 0b01);
        machine
            .cpu
            .registers
            .set(SystemRegister::TTBR1_EL1, 0, BASE + LEVEL0);
        machine.cpu.registers.set(SystemRegister::TCR_EL1, 0, TCR);
        machine.translations_changed();
        let outside = |cause| {
            NativeExit::Fault(NativeFault {
                registers: [0; 16],
                offset: 0,
                address: 0,
                write: false,
                cause,
            })
        };
        let run = |machine: &mut Machine<FakeHost, NoDevices>, cause| {
            machine.cpu.pc = BASE;
            machine.cpu.state.x[1] = ADDRESS;
            machine.host.exits.push(outside(cause));
            machine.step()
        };
        // Native under LA57: a failed check there has no fault to take.
        assert!(matches!(
            run(&mut machine, FaultCause::InvalidOpcode),
            Err(Stop::Unsupported(_))
        ));
        // Four-level without the helper.
        machine.host.placement = mmu::placement::Placement::four_level(2).unwrap();
        machine.derived_changed();
        let Err(Stop::Unsupported(requirement)) = run(&mut machine, FaultCause::InvalidOpcode)
        else {
            panic!("an explicit stop")
        };
        assert_eq!(requirement.address, Some(ADDRESS));
        assert_eq!(machine.statistics.translated_pages, 0);
        // Four-level blocks check the four-level ranges.
        let check = machine.host.placement.check();
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("block")
        };
        assert_eq!(machine.blocks[index].checks.range, check);
        // With the helper, a range check's #UD and an elided access's #GP
        // alike run the page in the translated variant.
        const HELPER: u64 = 0x1000;
        machine.host.translation_helper = Some(HELPER);
        for cause in [FaultCause::InvalidOpcode, FaultCause::NonCanonical] {
            machine.translated_pages.clear();
            run(&mut machine, cause).unwrap();
            assert_eq!(machine.cpu.pc, BASE, "{cause:?}");
            assert_eq!(machine.first_translated(), Some((BASE, ADDRESS)));
            let current = machine.current_variant(false, false);
            assert!(!machine.page_variant(current, BASE + FETCH_PAGE).translated);
            let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
                panic!("block")
            };
            let block = &machine.blocks[index];
            assert!(block.variant.translated, "{cause:?}");
            assert_eq!(
                block.checks,
                current.checks.with_translation(HELPER),
                "{cause:?}"
            );
            // Its failed check calls the helper through the slot.
            let mut call = vec![0x48, 0xa1]; // movabs rax, [HELPER]
            call.extend(HELPER.to_le_bytes());
            let code = &machine.host.installed[block.code.0 - 1];
            assert!(code.windows(call.len()).any(|bytes| bytes == call));
        }
        assert_eq!(machine.statistics.translated_pages, 2);
        // A translated block that still leaves the ranges stops.
        assert!(matches!(
            run(&mut machine, FaultCause::InvalidOpcode),
            Err(Stop::Unsupported(_))
        ));
    }

    /// System-mode blocks check every access against the guest's ranges,
    /// whatever SCTLR_ELx asks.
    #[test]
    fn system_mode_blocks_check_accesses_against_the_guest_ranges() {
        const CHECK: [u8; 16] = [
            0x48, 0x89, 0xc1, 0x48, 0xc1, 0xf9, 48, 0xff, 0xc1, 0x83, 0xf9, 0x01, 0x76, 0x02, 0x0f,
            0x0b,
        ];
        // ldr x0, [x1]; svc #0
        let mut machine = machine(&[0xf940_0020, 0xd400_0001]);
        let Ok(Fetched::Block(index)) = machine.fetch_block(BASE, false) else {
            panic!("block")
        };
        let code = &machine.host.installed[machine.blocks[index].code.0 - 1];
        assert!(code.windows(CHECK.len()).any(|bytes| bytes == CHECK));
    }

    impl Machine<FakeHost, NoDevices> {
        fn system_instruction_for_test(&mut self, word: u32) {
            self.pointer_authentication(word).unwrap();
        }
    }

    #[test]
    fn untimed_dispatch_skips_dma_clock_but_guest_counter_reads_stay_fresh() {
        let mut machine = machine(&[]);
        machine.lines();
        machine.breakpoints.push(BASE);
        let reads = machine.host.counter_reads;
        for now in [10, 20, 30] {
            machine.host.now = now;
            assert_eq!(machine.step(), Err(Stop::Breakpoint(BASE)));
            assert_eq!(machine.host.counter_reads, reads);
        }
        machine.system_instruction(0xd53b_e041).unwrap(); // mrs x1, cntvct_el0
        assert_eq!(machine.cpu.state.x[1], 30);
        machine.host.now = 40;
        machine.system_instruction(0xd53b_e041).unwrap();
        assert_eq!(machine.cpu.state.x[1], 40);
        assert_eq!(machine.host.counter_reads, reads + 2);
    }

    #[test]
    fn dispatch_still_reads_time_for_timer_lines_without_dma() {
        let mut machine = machine_on(one_timer_bank(), &[]);
        machine.lines();
        machine.breakpoints.push(BASE);
        machine
            .cpu
            .registers
            .set(SystemRegister::CNTV_CVAL_EL0, 0, 10);
        machine
            .cpu
            .registers
            .set(SystemRegister::CNTV_CTL_EL0, 0, 1);
        machine.timers = None;
        let reads = machine.host.counter_reads;
        machine.host.now = 9;
        assert_eq!(machine.step(), Err(Stop::Breakpoint(BASE)));
        assert_eq!(machine.host.counter_reads, reads + 1);
        assert!(!machine.lines().fiq);
        machine.host.now = 10;
        assert_eq!(machine.step(), Err(Stop::Breakpoint(BASE)));
        assert!(machine.lines().fiq); // Apple's generic timer FIQ remains masked.
    }

    #[test]
    fn interrupt_lines_read_the_count_only_when_a_deadline_needs_it() {
        let mut machine = machine(&[]);
        assert_eq!(machine.lines(), Lines::default());
        let reads = machine.host.counter_reads;
        // No device deadline, timer or PMI: the cached answer stands.
        assert_eq!(machine.lines(), Lines::default());
        assert_eq!(machine.host.counter_reads, reads);
        // An enabled, unmasked virtual timer due at count 10.
        machine
            .cpu
            .registers
            .set(SystemRegister::CNTV_CVAL_EL0, 0, 10);
        machine
            .cpu
            .registers
            .set(SystemRegister::CNTV_CTL_EL0, 0, 1);
        machine.timers = None;
        machine.host.now = 0;
        machine.lines();
        assert_eq!(machine.host.counter_reads, reads + 1);
    }

    #[test]
    fn a_fetch_the_host_refuses_takes_a_permission_instruction_abort() {
        // add x0, x0, #1; svc #0
        let mut machine = machine(&[0x9100_0400, 0xd400_0001]);
        assert!(matches!(
            machine.fetch_block(BASE, false),
            Ok(Fetched::Block(_))
        ));
        assert_eq!(machine.host.fetch_checks, 1);
        // The view changes: until the engine hears so, the cached
        // translation stands and the host is not asked.
        machine.host.refused.push(BASE);
        assert!(matches!(
            machine.fetch_block(BASE, false),
            Ok(Fetched::Block(_))
        ));
        assert_eq!(machine.host.fetch_checks, 1);
        machine.fetch_permissions_changed();
        let Ok(Fetched::Exception(exception)) = machine.fetch_block(BASE, false) else {
            panic!("an instruction abort")
        };
        let permission = mmu::Fault::stage1(mmu::FaultKind::Permission, HOST_REFUSED_FETCH_LEVEL);
        assert_eq!(
            exception.syndrome,
            super::super::exception::syndrome(
                Class::InstructionAbortSame,
                permission.instruction_syndrome()
            )
        );
        assert_eq!(exception.fault_address, Some(BASE));
        assert_eq!(machine.host.fetch_checks, 2);
        // Permitted again: the block runs once more.
        machine.host.refused.clear();
        machine.fetch_permissions_changed();
        assert!(matches!(
            machine.fetch_block(BASE, false),
            Ok(Fetched::Block(_))
        ));
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
        // An IMPDEF register no censused component accesses (S3_5_C15_C15_7)
        // is UNDEFINED, as an unallocated encoding.
        let unconsumed = Encoding::new(3, 5, 15, 15, 7);
        assert!(!crate::machine::impdef::consumed(
            unconsumed,
            machine.cpu.registers.chip()
        ));
        machine.system_instruction(0xd53d_ffe0).unwrap();
        assert_eq!(machine.cpu.pc, 0x1_0200);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
        // The M2 kernel's JIT box: its range (S3_4_C15_C15_1) and mode
        // (S3_4_C15_C15_4) are held. A mode that enables the box, whose
        // enforcement is undocumented, is reported once, or stops in strict
        // mode.
        let mut machine = machine_on(crate::machine::Chip::AppleM2, &[]);
        machine.set_strict(false);
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = BASE;
        machine.cpu.state.x[0] = 0x0000_0001_0200_0006;
        machine.system_instruction(0xd51c_ff20).unwrap();
        assert_eq!(machine.cpu.pc, BASE + 4);
        machine.cpu.state.x[0] = 0x061e_0c5b;
        for _ in 0..2 {
            machine.system_instruction(0xd51c_ff80).unwrap();
        }
        assert_eq!(machine.cpu.pc, BASE + 12);
        let reports = machine.take_unmodeled();
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(reports[0].syndrome, Some(0x6239_3c1e));
        assert!(machine.take_unmodeled().is_empty());
        machine.set_strict(true);
        let Err(Stop::Unsupported(requirement)) = machine.system_instruction(0xd51c_ff80) else {
            panic!("strict mode stops")
        };
        assert_eq!(requirement.kind, reports[0].kind);
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
    fn all_chip_performance_monitors_count_retirement_and_signal_their_overflow_fiq() {
        for chip in crate::machine::Chip::ALL {
            let overflow = if chip == crate::machine::Chip::AppleM1 {
                1u64 << 47
            } else {
                1u64 << 63
            };
            const MSR_PMCR1_X1: u32 = 0xd519_f101;
            const MSR_PMCR0_X2: u32 = 0xd519_f002;
            const MSR_PMC1_X6: u32 = 0xd51a_f106;
            const MRS_X3_PMC1: u32 = 0xd53a_f103;
            const MRS_X4_HCR_EL2: u32 = 0xd53c_1104;
            const MRS_X5_PMC1: u32 = 0xd53a_f105;
            const MRS_X7_PMCR0: u32 = 0xd539_f007;
            const MSR_PMESR1_X9: u32 = 0xd519_f609;
            const MRS_X8_PMC7: u32 = 0xd53a_f708;
            const MSR_PMC7_X6: u32 = 0xd51a_f706;
            const MRS_X8_PMSR: u32 = 0xd539_fd08;
            const ADD: u32 = 0x9100_0400;
            const B_NEXT: u32 = 0x1400_0001;
            const SVC: u32 = 0xd400_0001;
            let mut words = vec![
                MSR_PMCR1_X1,
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
                // No hardware identity is claimed by this synthetic PMU fixture.
                midr: 0,
                mpidr: 0x8001_0000,
                // Synthetic fixture clock: no board clock is inferred.
                clock: Some(1_000_000_000),
                caches: None,
            };
            let mut machine = board_on(chip, &words, NoDevices, vec![identity]);
            machine
                .cpu
                .registers
                .set(SystemRegister::VBAR_EL1, 0, BASE + 0x800);
            let programmable = matches!(
                chip,
                crate::machine::Chip::AppleM1 | crate::machine::Chip::AppleM2
            );
            if programmable {
                machine.cpu.state.x[9] = 0x8c00; // INST_ALL on PMC7 only.
                machine.system_instruction(MSR_PMESR1_X9).unwrap();
                // Configuration precedes this scripted retirement trace.
                machine.cpu.pc = BASE;
            }
            // Fixed counters on all chips; the source-qualified M1/M2
            // programmable instruction event counts the same retirements.
            machine.cpu.state.x[1] = 0x30300 | if programmable { 1 << 15 | 1 << 23 } else { 0 };
            let controls = 0x3 | 0x3000 | 0x400 | if programmable { 1 << 7 | 1 << 19 } else { 0 };
            machine.cpu.state.x[2] = controls;
            let run = |machine: &mut Machine<FakeHost, NoDevices>, next_pc, kind: ExitKind| {
                machine.host.exits.push(NativeExit::Exit {
                    next_pc,
                    kind: kind as u64,
                });
                machine.step().unwrap();
            };
            for pc in [BASE, BASE + 4] {
                run(&mut machine, pc, ExitKind::System);
            }
            // The two ADDs and the branch, then the MRS, which counts itself.
            run(&mut machine, BASE + 20, ExitKind::Direct);
            run(&mut machine, BASE + 20, ExitKind::System);
            assert_eq!(machine.cpu.state.x[3], 4);
            // An UNDEFINED MRS does not retire; the vector's MRS does.
            run(&mut machine, BASE + 24, ExitKind::System);
            assert_eq!(machine.cpu.pc, BASE + 0xa00);
            run(&mut machine, BASE + 0xa00, ExitKind::System);
            assert_eq!(machine.cpu.state.x[5], 5);
            // SVC retires as it takes its exception.
            run(&mut machine, BASE + 0xa04, ExitKind::System);
            run(&mut machine, BASE + 0xa00, ExitKind::System);
            assert_eq!(machine.cpu.state.x[5], 7);
            if programmable {
                machine.system_instruction(MRS_X8_PMC7).unwrap();
                assert_eq!(machine.cpu.state.x[8], 7);
            }
            // Two instructions short of overflow, the PMI asserts as FIQ once
            // they retire, and PMAI reports it.
            machine.cpu.state.x[6] = overflow - 2;
            machine.system_instruction(MSR_PMC1_X6).unwrap();
            assert!(!machine.lines().fiq);
            machine.cpu.retired += 2;
            assert!(machine.lines().fiq);
            machine.system_instruction(MRS_X7_PMCR0).unwrap();
            assert_eq!(machine.cpu.state.x[7], controls | 1 << 11);
            if programmable {
                machine.cpu.state.x[6] = 0;
                machine.system_instruction(MSR_PMC1_X6).unwrap();
                machine.cpu.state.x[6] = overflow - 1;
                machine.system_instruction(MSR_PMC7_X6).unwrap();
                assert!(!machine.lines().fiq);
                machine.cpu.retired += 1;
                assert!(machine.lines().fiq);
                machine.system_instruction(MRS_X8_PMSR).unwrap();
                assert_eq!(machine.cpu.state.x[8], 1 << 7);
            }
        }
    }

    #[test]
    fn a_full_arena_reclaims_its_oldest_part_and_forgets_those_pages() {
        const RET: u32 = 0xd65f_03c0;
        let mut machine = machine(&vec![RET; 4 * FETCH_PAGE as usize / 4]);
        machine.host.ring = Some(2);
        let base = machine.cpu.pc;
        let page = |n: u64| base + n * FETCH_PAGE;
        let pcs = [page(0), page(1), page(0) + 4, page(2), page(3), page(1) + 8];
        let mut slots = Vec::new();
        for pc in pcs {
            let Ok(Fetched::Block(slot)) = machine.fetch_block(pc, false) else {
                panic!("a block at {pc:#x}")
            };
            slots.push(slot);
        }
        // The parts held pages 0 and 1, then page 0 again and page 2; page
        // 3 needed the first part back, whose reclaim forgot pages 0 and 1
        // whole, page 0's block in the second part too, and whose slots
        // took the next blocks.
        let left: Vec<u64> = machine.index.keys().map(|&(pc, ..)| pc).collect();
        assert_eq!(left, [page(1) + 8, page(2), page(3)]);
        assert_eq!(machine.statistics.code_evictions, 1);
        assert_eq!(machine.statistics.code_discards, 0);
        assert_eq!(machine.blocks.len(), 4);
        assert_eq!(&slots[4..], [1, 0]);
    }

    #[test]
    fn a_fetch_that_reclaims_code_looks_up_in_a_new_context() {
        const RET: u32 = 0xd65f_03c0;
        let mut machine = machine(&vec![RET; 3 * FETCH_PAGE as usize / 4]);
        machine.host.ring = Some(1);
        let base = machine.cpu.pc;
        assert!(machine.fetch_block(base, false).is_ok());
        let first = machine.chain.context;
        assert!(machine.fetch_block(base + FETCH_PAGE, false).is_ok());
        assert_eq!(machine.chain.context, first);
        // The third part reclaims the first, whose block a lookup entry of
        // the first context names.
        let pc = base + 2 * FETCH_PAGE;
        assert!(machine.fetch_block(pc, false).is_ok());
        assert_eq!(machine.statistics.code_evictions, 1);
        assert_ne!(machine.chain.context, first);
        assert_eq!(
            machine.targets[chain::lookup_slot(pc)].context,
            machine.chain.context
        );
    }

    #[test]
    fn a_block_installed_while_memory_runs_low_discards_the_others_first() {
        const RET: u32 = 0xd65f_03c0;
        let mut machine = machine(&vec![RET; FETCH_PAGE as usize / 4 + 1]);
        let base = machine.cpu.pc;
        assert!(machine.fetch_block(base, false).is_ok());
        machine.host.memory_low = true;
        assert!(machine.fetch_block(base + FETCH_PAGE, false).is_ok());
        let left: Vec<u64> = machine.index.keys().map(|&(pc, ..)| pc).collect();
        assert_eq!(left, [base + FETCH_PAGE]);
        assert_eq!(machine.statistics.code_discards, 1);
    }

    #[test]
    fn ic_ivau_forgets_its_pages_blocks_and_ic_iallu_every_block() {
        const NOP: u32 = 0xd503_201f;
        const RET: u32 = 0xd65f_03c0;
        const IC_IVAU_X0: u32 = 0xd50b_7520;
        const IC_IALLU: u32 = 0xd508_751f;
        let mut words = vec![NOP; 2 * FETCH_PAGE as usize / 4];
        words[0] = RET;
        words[FETCH_PAGE as usize / 4] = RET;
        let mut machine = machine(&words);
        let base = machine.cpu.pc;
        for pc in [base, base + FETCH_PAGE] {
            assert!(matches!(
                machine.fetch_block(pc, false),
                Ok(Fetched::Block(_))
            ));
        }
        assert_eq!(machine.index.len(), 2);
        machine.cpu.state.x[0] = base + 0x40;
        machine.system_instruction(IC_IVAU_X0).unwrap();
        let left: Vec<u64> = machine.index.keys().map(|&(pc, ..)| pc).collect();
        assert_eq!(left, [base + FETCH_PAGE]);
        assert_eq!(machine.statistics.code_invalidations, 1);
        assert_eq!(machine.statistics.code_discards, 0);
        machine.system_instruction(IC_IALLU).unwrap();
        assert!(machine.index.is_empty() && machine.code_pages.is_empty());
        assert_eq!(machine.statistics.code_discards, 1);
    }

    /// Two blocks that branch to each other in one page: each direct exit
    /// is redirected through a thunk once its successor exists, and a run
    /// that chained counts the blocks and instructions it passed through.
    #[test]
    fn direct_exits_chain_into_their_successors_in_the_page() {
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        let mut machine = machine(&[ADD, 0x1400_0002, 0, ADD, 0x17ff_fffc]);
        let base = machine.cpu.pc;
        let direct = |next_pc| NativeExit::Exit {
            next_pc,
            kind: ExitKind::Direct as u64,
        };
        machine.host.exits = vec![direct(base + 12), direct(base), direct(base + 12)];
        machine.step().unwrap();
        assert!(
            machine.host.patches.is_empty(),
            "the successor is not compiled"
        );
        machine.step().unwrap();
        machine.step().unwrap();
        assert_eq!(machine.statistics.links, 2);
        let control = &*machine.chain as *const ChainControl as u64;
        let (first, second) = (&machine.blocks[0], &machine.blocks[1]);
        // The second block's exit to the first, then the first's to it.
        for (patches, from, to, target, index) in [
            (&machine.host.patches[..2], second, first, base, 0),
            (&machine.host.patches[2..], first, second, base + 12, 1),
        ] {
            let (at, thunk) = &patches[0];
            let expected = chain::thunk(
                *at as u64,
                control,
                2,
                index,
                to.code.0 as u64,
                GuestAddress(target),
                ExitKind::Direct,
            );
            assert_eq!(Some(thunk.clone()), expected);
            // The block's one direct exit ends its code.
            let code = &machine.host.installed[from.code.0 - 1];
            let site = from.code.0 + code.len() - chain::DIRECT_EXIT_BYTES;
            let jump = chain::jump(site as u64, *at as u64).unwrap().to_vec();
            assert_eq!(patches[1], (site, jump));
            assert!(from.successors.is_empty());
        }
        // The first block chains into the second, which exits to the first.
        let (blocks, retired) = (machine.statistics.blocks, machine.cpu.retired);
        let current = *machine.chain;
        machine.host.chained = Some((
            &mut *machine.chain,
            ChainControl {
                budget: CHAIN_LIMIT - 1,
                retired: 2,
                block: 1,
                ..current
            },
        ));
        machine.host.exits = vec![direct(base)];
        machine.step().unwrap();
        assert_eq!(machine.statistics.blocks, blocks + 2);
        assert_eq!(machine.statistics.chained, 1);
        assert_eq!(machine.cpu.retired, retired + 4);
        assert_eq!(machine.cpu.pc, base);
        // A run whose last thunk found no transfer left, wrapping the
        // budget, chained the whole budget.
        let budget = machine.chain_budget();
        let (blocks, chained) = (machine.statistics.blocks, machine.statistics.chained);
        let current = *machine.chain;
        machine.host.chained = Some((
            &mut *machine.chain,
            ChainControl {
                budget: u64::MAX,
                retired: 2 * budget,
                block: 0,
                ..current
            },
        ));
        machine.host.exits = vec![direct(base + 12)];
        machine.step().unwrap();
        assert_eq!(machine.statistics.chained, chained + budget);
        assert_eq!(machine.statistics.blocks, blocks + 1 + budget);
        // A run entered with BTYPE 0b01 that chained into a block and
        // faulted at its first instruction saves BTYPE 0, which the
        // transfer left, in SPSR_EL1.
        machine.cpu.pc = base;
        machine.cpu.pstate.btype = 0b01;
        let current = *machine.chain;
        machine.host.chained = Some((
            &mut *machine.chain,
            ChainControl {
                budget: CHAIN_LIMIT - 1,
                retired: 2,
                block: 1,
                ..current
            },
        ));
        let offset = machine.blocks[1]
            .code
            .0
            .wrapping_sub(machine.blocks[0].code.0);
        machine.host.exits = vec![NativeExit::Fault(NativeFault {
            registers: [0; 16],
            offset,
            address: 0x40,
            write: false,
            cause: FaultCause::Guest(mmu::Fault::stage1(mmu::FaultKind::Translation, 3)),
        })];
        machine.step().unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), base + 12);
        assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1) >> 10 & 3, 0);
    }

    /// A direct exit out of its page and a RET are redirected through
    /// lookup thunks at their first exits; every fetch records its block
    /// under the context's number, which changes with the generations and
    /// the EL and returns with neither changed.
    #[test]
    fn returns_and_exits_out_of_the_page_go_through_lookup_thunks() {
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        const RET: u32 = 0xd65f_03c0;
        let mut words = vec![0; 1026];
        words[0] = 0x1400_0400; // b .+0x1000
        words[1024] = ADD;
        words[1025] = RET;
        let mut machine = machine(&words);
        let base = machine.cpu.pc;
        let far = base + 0x1000;
        let exit = |next_pc, kind: ExitKind| NativeExit::Exit {
            next_pc,
            kind: kind as u64,
        };
        machine.host.exits = vec![exit(far, ExitKind::Direct), exit(base, ExitKind::Return)];
        machine.step().unwrap();
        machine.step().unwrap();
        assert_eq!(
            (machine.statistics.lookups, machine.statistics.links),
            (2, 0)
        );
        // The engine counts the exits it completed by kind.
        let mut kinds = [0; 13];
        kinds[ExitKind::Direct as usize] = 1;
        kinds[ExitKind::Return as usize] = 1;
        assert_eq!(machine.statistics.exit_kinds, kinds);
        let control = &*machine.chain as *const ChainControl as u64;
        let (first, second) = (&machine.blocks[0], &machine.blocks[1]);
        assert!(first.successors.is_empty() && first.dynamic_site.is_none());
        assert!(second.dynamic_site.is_none());
        let code = |block: &Block| &machine.host.installed[block.code.0 - 1];
        // The branch's direct exit, then the RET's exit to RAX, ends each
        // block's code.
        let sites = [
            first.code.0 + code(first).len() - chain::DIRECT_EXIT_BYTES,
            second.code.0 + code(second).len() - chain::DYNAMIC_EXIT_BYTES,
        ];
        let thunks = [
            chain::lookup_thunk(control, 1, Some(GuestAddress(far)), ExitKind::Direct, 0),
            chain::lookup_thunk(control, 2, None, ExitKind::Return, 0),
        ];
        for (index, (site, thunk)) in sites.into_iter().zip(thunks).enumerate() {
            let at = machine
                .host
                .installed
                .iter()
                .position(|installed| Some(installed) == thunk.as_ref())
                .expect("the thunk is installed")
                + 1;
            let jump = chain::jump(site as u64, at as u64).unwrap().to_vec();
            assert_eq!(machine.host.patches[index], (site, jump));
        }
        let context = machine.chain.context;
        assert_ne!(context, 0);
        for (pc, block) in [(base, 0), (far, 1)] {
            let entry = machine.targets[chain::lookup_slot(pc)];
            let expected = chain::LookupEntry {
                pc,
                context,
                entry: machine.blocks[block].code.0 as u64,
                block: block as u32,
                targets: 0b1111,
            };
            assert_eq!(entry, expected);
        }
        // Another generation numbers the context anew; another EL too, and
        // the same EL and generation give the same number back.
        machine.translations_changed();
        machine.host.exits = vec![exit(far, ExitKind::Direct)];
        machine.step().unwrap();
        let renewed = machine.chain.context;
        assert!(renewed > context);
        let variant = machine.blocks[0].variant;
        let el = machine.cpu.pstate.el;
        assert_eq!(machine.context(el, variant), renewed);
        assert_ne!(machine.context(el ^ 1, variant), renewed);
        assert_eq!(machine.context(el, variant), renewed);
    }

    #[test]
    fn dynamic_branches_name_their_exit_and_any_page_independent_btype() {
        // BR through other than X16 or X17 sets a BTYPE that depends on
        // its page.
        for (word, expected) in [
            (0xd61f_0000, Some((ExitKind::Indirect, None))), // br x0
            (0xd61f_0200, Some((ExitKind::Indirect, Some(0b01)))), // br x16
            (0xd63f_0100, Some((ExitKind::Call, Some(0b10)))), // blr x8
            (0xd65f_03c0, Some((ExitKind::Return, Some(0)))), // ret
            (0xd71f_0a31, Some((ExitKind::Indirect, Some(0b01)))), // braa x17, x17
            (0xd61f_091f, Some((ExitKind::Indirect, None))), // braaz x8
            (0xd63f_091f, Some((ExitKind::Call, Some(0b10)))), // blraaz x8
            (0xd65f_0fff, Some((ExitKind::Return, Some(0)))), // retab
            (0xd69f_03e0, None),                             // eret
            (0x1400_0000, None),                             // b .
        ] {
            assert_eq!(dynamic_branch(word), expected, "{word:#x}");
        }
    }

    /// BLR and BR exits are redirected through lookup thunks that set their
    /// BTYPE: a BR through other than X16 or X17 sets 0b11 from a guarded
    /// page, whose blocks are compiled apart, and 0b01 elsewhere. A target
    /// in a guarded page accepts the BTYPEs its first instruction is
    /// compatible with.
    #[test]
    fn indirect_branches_go_through_lookups_that_check_the_target() {
        const BLR_X8: u32 = 0xd63f_0100;
        const BR_X16: u32 = 0xd61f_0200;
        const BR_X0: u32 = 0xd61f_0000;
        const BTI_C: u32 = 0xd503_245f;
        let mut words = vec![0; 1025];
        words[0] = BLR_X8;
        words[1] = BR_X16;
        words[2] = BR_X0;
        words[1024] = BTI_C;
        let mut machine = machine(&words);
        let base = machine.cpu.pc;
        let far = base + 0x1000;
        let exit = |kind: ExitKind| NativeExit::Exit {
            next_pc: far,
            kind: kind as u64,
        };
        machine.host.exits = vec![
            exit(ExitKind::Call),
            exit(ExitKind::Indirect),
            exit(ExitKind::Indirect),
            exit(ExitKind::Indirect),
        ];
        for pc in [base, base + 4, base + 8] {
            machine.cpu.pc = pc;
            machine.cpu.pstate.btype = 0;
            machine.step().unwrap();
        }
        // The same BR X0, now in a guarded page.
        let page = (base / FETCH_PAGE) as usize % FETCH_CACHE;
        machine.fetch[page].as_mut().unwrap().guarded = true;
        machine.cpu.pc = base + 8;
        machine.cpu.pstate.btype = 0;
        machine.step().unwrap();
        assert_eq!(machine.blocks.len(), 4);
        assert!(!machine.blocks[2].variant.guarded_page && machine.blocks[3].variant.guarded_page);
        let control = &*machine.chain as *const ChainControl as u64;
        for (index, kind, btype) in [
            (0, ExitKind::Call, 0b10),
            (1, ExitKind::Indirect, 0b01),
            (2, ExitKind::Indirect, 0b01),
            (3, ExitKind::Indirect, 0b11),
        ] {
            let thunk = chain::lookup_thunk(control, 1, None, kind, btype).unwrap();
            assert!(machine.host.installed.contains(&thunk), "{index}");
            assert_eq!(machine.blocks[index].dynamic_site, None, "{index}");
        }
        assert_eq!(machine.statistics.lookups, 4);
        machine.fetch[page].as_mut().unwrap().guarded = false;
        // The target outside a guarded page accepts every BTYPE; in one, the
        // BTYPEs BTI c is compatible with.
        machine.cpu.pc = far;
        machine.host.exits = vec![NativeExit::Exit {
            next_pc: far + 4,
            kind: ExitKind::Fallthrough as u64,
        }];
        machine.step().unwrap();
        let target = machine.blocks.len() - 1;
        assert_eq!(machine.blocks[target].pc, far);
        assert_eq!(machine.targets[chain::lookup_slot(far)].targets, 0b1111);
        let slot = (far / FETCH_PAGE) as usize % FETCH_CACHE;
        machine.fetch[slot].as_mut().unwrap().guarded = true;
        machine.remember_target(far, target);
        assert_eq!(machine.targets[chain::lookup_slot(far)].targets, 0b0111);
        // A run whose last transfer was the BLR's resumes with its BTYPE.
        let current = *machine.chain;
        machine.host.chained = Some((
            &mut *machine.chain,
            ChainControl {
                budget: CHAIN_LIMIT - 1,
                retired: 1,
                block: 0b10 << chain::BLOCK_BTYPE_SHIFT | target as u64,
                ..current
            },
        ));
        let offset = machine.blocks[target]
            .code
            .0
            .wrapping_sub(machine.blocks[0].code.0);
        machine.host.exits = vec![NativeExit::Fault(NativeFault {
            registers: [0; 16],
            offset,
            address: 0x40,
            write: false,
            cause: FaultCause::Guest(mmu::Fault::stage1(mmu::FaultKind::Translation, 3)),
        })];
        machine.cpu.pc = base;
        machine.step().unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), far);
        assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1) >> 10 & 3, 0b10);
    }

    #[test]
    fn apple_sdsb_completes_as_a_barrier() {
        const SDSB_ISH: u32 = 0x0020_1462;
        let mut machine = machine(&[]);
        let pc = machine.cpu.pc;
        machine.system_instruction(SDSB_ISH).unwrap();
        assert_eq!(machine.cpu.pc, pc + 4);
    }

    /// A TTBR0 write reaches the host only as the regime's new controls,
    /// which differ from the old in TTBR0 alone, so the host keeps the upper
    /// half's shadow; any other translation control invalidates everything.
    /// Both make the fetch translations stale.
    #[test]
    fn ttbr0_writes_change_only_the_regime_and_other_controls_invalidate() {
        const MSR_TTBR0_EL1_X0: u32 = 0xd518_2000;
        const MSR_TCR_EL1_X0: u32 = 0xd518_2040;
        let mut machine = machine(&[]);
        let before = *machine.host.regimes.last().unwrap();
        let generation = machine.translation_generation;
        machine.cpu.state.x[0] = 0x1_0000_8000_4000;
        machine.system_instruction(MSR_TTBR0_EL1_X0).unwrap();
        assert_eq!(machine.host.invalidations, 0);
        let after = *machine.host.regimes.last().unwrap();
        assert_ne!(after.controls, before.controls);
        assert_eq!(
            mmu::Controls {
                ttbr0: after.controls.ttbr0,
                ..before.controls
            },
            after.controls
        );
        assert!(machine.translation_generation > generation);
        assert_eq!(
            (
                machine.statistics.table_base_changes,
                machine.statistics.translation_changes
            ),
            (1, 0)
        );
        machine.cpu.state.x[0] = 25 | 25 << 16;
        machine.system_instruction(MSR_TCR_EL1_X0).unwrap();
        assert_eq!(machine.host.invalidations, 1);
        assert_eq!(machine.statistics.translation_changes, 1);
    }

    /// A TLBI hands the host what it reaches of the current context and
    /// makes every fetch translation stale, but changes no control: the
    /// regime is not sent again and what derives from System registers
    /// stays.
    #[test]
    fn tlbis_reach_their_address_range_or_asid_without_a_regime_change() {
        use mmu::tlbi::Reach;
        const TLBI_VAE1_X0: u32 = 0xd508_8720;
        const TLBI_ASIDE1_X0: u32 = 0xd508_8740;
        const TLBI_RVAE1_X0: u32 = 0xd508_8620;
        const TLBI_VMALLE1: u32 = 0xd508_871f;
        let mut machine = machine(&[]);
        let regimes = machine.host.regimes.len();
        machine.native_system();
        let generation = machine.translation_generation;
        let high = 0xffff_fe00_0123_4000_u64;
        machine.cpu.state.x[0] = 3 << 48 | (high & ((1 << 56) - 1)) >> 12;
        machine.system_instruction(TLBI_VAE1_X0).unwrap();
        // ASID 0 is the one TTBR0_EL1 names; 3 is another.
        machine.cpu.state.x[0] = 3 << 48;
        machine.system_instruction(TLBI_ASIDE1_X0).unwrap();
        machine.cpu.state.x[0] = 0;
        machine.system_instruction(TLBI_ASIDE1_X0).unwrap();
        // Four 16 KiB pages from 0x10_0000.
        machine.cpu.state.x[0] = 2 << 46 | 1 << 39 | 0x10_0000 >> 14;
        machine.system_instruction(TLBI_RVAE1_X0).unwrap();
        machine.system_instruction(TLBI_VMALLE1).unwrap();
        assert_eq!(
            machine.host.reaches,
            [
                Reach::Containing(high),
                Reach::Nothing,
                Reach::All,
                Reach::Overlapping {
                    first: 0x10_0000,
                    last: 0x10_ffff
                },
                Reach::All,
            ]
        );
        assert_eq!(machine.translation_generation, generation + 5);
        assert_eq!(machine.host.regimes.len(), regimes);
        assert!(machine.native_system.is_some());
        assert_eq!(
            (
                machine.statistics.tlb_maintenance,
                machine.statistics.scoped_maintenance,
                machine.statistics.translation_changes
            ),
            (5, 3, 0)
        );
    }

    #[test]
    fn tlbi_invalidates_and_wfi_waits_for_the_virtual_timer() {
        let mut machine = machine_on(one_timer_bank(), &[]);
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
    fn timer_snapshot_tracks_guest_reads_and_wfi_when_the_clock_lags() {
        let mut machine = machine_on(one_timer_bank(), &[]);
        // Three slow slices each run ten blocks in 1000 host counts. The
        // initial observed overshoot remains monotonic, but repeated slow
        // work advances it only by ten per slice, not by host duration.
        for slice in 0..3 {
            machine.clock.start_slice(slice * 1000, slice * 10, 1);
            machine.host.now = (slice + 1) * 1000;
            machine.clock.end_slice(machine.host.now, (slice + 1) * 10);
        }
        machine.host.now = 3500;
        machine
            .cpu
            .registers
            .set(SystemRegister::CNTV_CVAL_EL0, 0, 1500);
        machine
            .cpu
            .registers
            .set(SystemRegister::CNTV_CTL_EL0, 0, timer::ENABLE);
        machine.derived_changed();
        assert_eq!(
            timer::CHANNELS[1].read_control(&machine.cpu, timer::agt::Bank::Arm, machine.host.now),
            timer::ENABLE | timer::ISTATUS,
            "the host count would incorrectly report an expired timer"
        );
        let (now, timers) = machine.timer_snapshot();
        assert_eq!((now, timers[1]), (1020, (timer::ENABLE, 1500)));
        machine.system_instruction(0xd53b_e041).unwrap(); // mrs x1, cntvct_el0
        machine.system_instruction(0xd53b_e322).unwrap(); // mrs x2, cntv_ctl_el0
        assert_eq!(
            (machine.cpu.state.x[1], machine.cpu.state.x[2]),
            (now, timers[1].0)
        );

        machine.system_instruction(0xd503_207f).unwrap(); // wfi
        assert!(machine.waiting.is_some());
        assert_eq!(machine.timer_snapshot(), (now, timers));
        machine.schedule().unwrap();
        assert_eq!(machine.host.now, 4500, "WFI waited for guest time");
        let (now, timers) = machine.timer_snapshot();
        assert_eq!(
            (now, timers[1]),
            (1530, (timer::ENABLE | timer::ISTATUS, 1500))
        );
        machine.system_instruction(0xd53b_e041).unwrap();
        machine.system_instruction(0xd53b_e322).unwrap();
        assert_eq!(
            (machine.cpu.state.x[1], machine.cpu.state.x[2]),
            (now, timers[1].0)
        );
        assert!(machine.waiting.is_none());
    }

    #[test]
    fn pstate_masks_interrupts_to_el1_from_el0_and_to_el2_from_the_host() {
        let mut machine = machine(&[]);
        machine.cpu.pstate.daif = DAIF_F;
        let hcr = |machine: &mut Machine<FakeHost, NoDevices>, value: u64| {
            machine
                .cpu
                .registers
                .set_raw(SystemRegister::HCR_EL2, 0, value)
        };
        machine.cpu.pstate.el = 0;
        hcr(&mut machine, 0);
        assert!(!machine.taken(1, DAIF_F));
        assert!(machine.taken(2, DAIF_F));
        hcr(&mut machine, 1 << HCR_TGE);
        assert!(!machine.taken(2, DAIF_F));
        machine.cpu.pstate.el = 1;
        hcr(&mut machine, 0);
        assert!(!machine.taken(1, DAIF_F));
        assert!(machine.taken(2, DAIF_F));
        assert!(!machine.taken(0, 0));
        machine.cpu.pstate.daif = 0;
        assert!(machine.taken(1, DAIF_F));
    }

    #[test]
    fn wfi_in_cyc_ovrds_power_down_mode_turns_the_core_off() {
        const MSR_CYC_OVRD_X0: u32 = 0xd51d_f500;
        const WFI: u32 = 0xd503_207f;
        const WFIT_X1: u32 = 0xd503_1021;
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
        // In power-down mode the core's own timer, armed again, goes down
        // with it: nothing on this board can wake it.
        machine.cpu.state.x[0] = 3 << 24 | 1;
        machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
        machine.cpu.state.x[1] = 1_000_000;
        machine.system_instruction(0xd51b_e301).unwrap(); // msr cntv_tval_el0, x1
        assert_eq!(wait(&mut machine, WFI), Err(Stop::Idle));
        assert!(matches!(machine.peer_states()[0], PeerState::Down));
        assert_eq!(machine.host.now, 2000);
        // A WFIT's local timeout would be the core's too.
        let mut machine = machine_on(crate::machine::Chip::AppleM4, &[]);
        machine.cpu.state.x[0] = 3 << 24;
        machine.system_instruction(MSR_CYC_OVRD_X0).unwrap();
        machine.cpu.state.x[1] = u64::MAX;
        assert!(matches!(
            machine.system_instruction(WFIT_X1),
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

    #[test]
    fn fp8_conversions_take_fpmr_formats_behind_enfpm_and_the_fp_check() {
        const F1CVTL: u32 = 0x2e21_7820; // f1cvtl v0.8h, v1.8b
        const F2CVTL2: u32 = 0x6e61_7820; // f2cvtl2 v0.8h, v1.16b
        const BF1CVTL: u32 = 0x2ea1_7820; // bf1cvtl v0.8h, v1.8b
        const FCVTN_H: u32 = 0x0e42_f420; // fcvtn v0.8b, v1.4h, v2.4h
        const FCVTN2_S: u32 = 0x4e02_f420; // fcvtn2 v0.16b, v1.4s, v2.4s
        const FSCALE: u32 = 0x6ea2_fc20; // fscale v0.4s, v1.4s, v2.4s
        const E4M3: u64 = 1;
        const HCRX_ENFPM: u64 = 1 << 23;
        const SCTLR_ENFPM: u64 = 1 << 34;
        let code = [F1CVTL, F2CVTL2, BF1CVTL, FCVTN_H, FCVTN2_S, FSCALE];
        let mut machine = machine(&code);
        let chip = machine.profile.chip;
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        registers.set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
        registers.set(SystemRegister::CPACR_EL1, 0, 0b11 << 20);
        registers.set(SystemRegister::CPTR_EL2, 0, 0b11 << 20);
        let run = |machine: &mut Machine<FakeHost, NoDevices>, index: u64, el: u8| {
            machine.cpu.set_pstate(Pstate {
                sp: el != 0,
                ..Pstate::reset(el.max(1))
            });
            machine.cpu.pstate.el = el;
            machine.derived_changed();
            machine.cpu.pc = BASE + 4 * index;
            machine.step()
        };
        if !Feature::FEAT_FP8.on(chip) {
            // The chip lacks the forms: they compile as the UDF they are.
            for index in 0..code.len() as u64 {
                assert!(!matches!(
                    machine.fetch_block(BASE + 4 * index, true),
                    Ok(Fetched::Checked(_))
                ));
            }
            return;
        }
        // HCRX_EL2.EnFPM clear makes them UNDEFINED at EL1, even with FP
        // access trapped (CheckFPMREnabled comes first).
        machine.cpu.state.v[1] = [0x3c38, 0];
        run(&mut machine, 0, 1).unwrap();
        assert_eq!(
            (
                machine.cpu.pstate.el,
                machine.cpu.read(SystemRegister::ESR_EL1)
            ),
            (1, 0x0200_0000)
        );
        machine.cpu.registers.set(SystemRegister::CPACR_EL1, 0, 0);
        run(&mut machine, 0, 1).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x0200_0000);
        // With EnFPM set, the FP access check traps (EC 0x07).
        machine
            .cpu
            .registers
            .set(SystemRegister::HCRX_EL2, 0, HCRX_ENFPM);
        run(&mut machine, 0, 1).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x1fe0_0000);
        machine
            .cpu
            .registers
            .set(SystemRegister::CPACR_EL1, 0, 0b11 << 20);
        // EL0 also needs SCTLR_EL1.EnFPM.
        run(&mut machine, 0, 0).unwrap();
        assert_eq!(
            (
                machine.cpu.pstate.el,
                machine.cpu.read(SystemRegister::ESR_EL1)
            ),
            (1, 0x0200_0000)
        );
        let sctlr = machine.cpu.read(SystemRegister::SCTLR_EL1);
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL1, 0, sctlr | SCTLR_ENFPM);
        // FPMR.F8S1 0 is E5M2, whose 0x3c is 1.0 and 0x38 0.5; E4M3 reads
        // 0x38 as 1.0 and 0x3c as 1.5. The widened halves fill V0.
        let fpmr = |machine: &mut Machine<FakeHost, NoDevices>, value: u64| {
            machine.cpu.scalable.as_mut().unwrap().set_fpmr(value);
        };
        fpmr(&mut machine, 0);
        run(&mut machine, 0, 0).unwrap();
        assert_eq!(machine.cpu.state.v[0], [0x3c00_3800, 0]);
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (0, BASE + 4));
        fpmr(&mut machine, E4M3);
        run(&mut machine, 0, 1).unwrap();
        assert_eq!(machine.cpu.state.v[0], [0x3e00_3c00, 0]);
        // F2CVTL2 takes FPMR.F8S2 and the upper half of V1.
        machine.cpu.state.v[1] = [0, 0x38];
        fpmr(&mut machine, E4M3 << 3);
        run(&mut machine, 1, 1).unwrap();
        assert_eq!(machine.cpu.state.v[0], [0x3c00, 0]);
        // BF1CVTL widens to BFloat16: E4M3 1.0 is 0x3f80.
        machine.cpu.state.v[1] = [0x38, 0];
        fpmr(&mut machine, E4M3);
        run(&mut machine, 2, 1).unwrap();
        assert_eq!(machine.cpu.state.v[0], [0x3f80, 0]);
        // FCVTN narrows the halves of V1 then V2 to FPMR.F8D's E4M3, and
        // 1.0 + 2^-10 is inexact.
        fpmr(&mut machine, E4M3 << 6);
        machine.cpu.state.v[1] = [0x3c00, 0];
        machine.cpu.state.v[2] = [0x3c01, 0];
        machine.cpu.state.fpsr = 0;
        run(&mut machine, 3, 1).unwrap();
        assert_eq!(machine.cpu.state.v[0], [0x38 << 32 | 0x38, 0]);
        assert_eq!(machine.cpu.state.fpsr, 1 << 4, "FPSR.IXC");
        // FCVTN2 from singles keeps V0's lower half.
        machine.cpu.state.v[0] = [0x1234, 0];
        machine.cpu.state.v[1] = [0x3f80_0000, 0];
        machine.cpu.state.v[2] = [0, 0];
        run(&mut machine, 4, 1).unwrap();
        assert_eq!(machine.cpu.state.v[0], [0x1234, 0x38]);
        assert_eq!(machine.cpu.pc, BASE + 20);
        // FSCALE, FEAT_FP8 without FPMR, compiles natively.
        assert!(matches!(
            machine.fetch_block(BASE + 20, true),
            Ok(Fetched::Block(_))
        ));
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

    /// SCTLR_EL2 bit 36 is BT with HCR_EL2.TGE clear and BT1 with it set
    /// (E2H is RES1); either way it decides PACIASP at EL2.
    #[test]
    fn sctlr_el2_bt_decides_paciasp_at_el2_with_or_without_tge() {
        const PACIASP: u32 = 0xd503_233f;
        const SCTLR_BT: u64 = 1 << 36;
        const HCR_TGE: u64 = 1 << 27;
        let mut machine = machine(&[]);
        machine.cpu.pstate.el = 2;
        machine.cpu.pstate.btype = 0b11;
        for hcr in [0, HCR_TGE] {
            machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, hcr);
            // SCTLR_EL1.BT1 has no say at EL2.
            machine
                .cpu
                .registers
                .set(SystemRegister::SCTLR_EL1, 0, SCTLR_BT);
            machine.cpu.registers.set(SystemRegister::SCTLR_EL2, 0, 0);
            machine.derived_changed();
            assert!(machine.branch_target_compatible(PACIASP), "{hcr:#x}");
            machine
                .cpu
                .registers
                .set(SystemRegister::SCTLR_EL2, 0, SCTLR_BT);
            machine.derived_changed();
            assert!(!machine.branch_target_compatible(PACIASP), "{hcr:#x}");
            assert!(machine.branch_target_accepts(PACIASP, 0b01));
        }
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
        normal_memory(&mut machine, false);
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

    /// The DC clean operations native code completes are exactly those the
    /// generated accessors complete as a plain translation check: across
    /// ELs, the host, UCI, the HCR_EL2 traps and HFGITR_EL2, an operation in
    /// `native_cache_clean` completes with PC + 4 or takes the Data Abort of
    /// its translation, and one outside it traps.
    #[test]
    fn native_dc_clean_operations_are_the_untrapped_ones() {
        const WORDS: [(cache_clean::Operations, u32); 3] = [
            (cache_clean::Operations::CVAC, 0xd50b_7a22), // dc cvac, x2
            (cache_clean::Operations::CVAU, 0xd50b_7b22), // dc cvau, x2
            (cache_clean::Operations::CIVAC, 0xd50b_7e22), // dc civac, x2
        ];
        const HCR_BITS: [u32; 4] = [23, 24, 52, crate::machine::cpu::HCR_TGE];
        const HFGITR_BITS: [u32; 3] = [54, 10, 7];
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut covered = [[0; 2]; 3];
        for _ in 0..192 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let el = (seed % 3) as u8;
            let bit = |index: u32| seed >> (8 + index) & 1;
            let hcr = HCR_BITS
                .iter()
                .enumerate()
                .fold(1 << 34, |hcr, (index, &field)| {
                    hcr | bit(index as u32) << field
                });
            let hfgitr = HFGITR_BITS
                .iter()
                .enumerate()
                .fold(0, |value, (index, &field)| {
                    value | bit(4 + index as u32) << field
                });
            let uci = (bit(7) << 26, bit(8) << 26);
            for (position, (operation, word)) in WORDS.into_iter().enumerate() {
                let mut machine = machine(&[]);
                normal_memory(&mut machine, true);
                let registers = &mut machine.cpu.registers;
                registers.set(SystemRegister::HCR_EL2, 0, hcr);
                registers.set(SystemRegister::HFGITR_EL2, 0, hfgitr);
                for (sctlr, uci) in [
                    (SystemRegister::SCTLR_EL1, uci.0),
                    (SystemRegister::SCTLR_EL2, uci.1),
                ] {
                    let value = registers.get(sctlr, 0) | uci;
                    registers.set(sctlr, 0, value);
                }
                registers.set(SystemRegister::VBAR_EL1, 0, BASE + 0x8000);
                registers.set(SystemRegister::VBAR_EL2, 0, BASE + 0x8000);
                machine.cpu.pstate.el = el;
                machine.derived_changed();
                let native = machine.native_system().cache_clean.contains(operation);
                machine.cpu.pc = BASE + 0x100;
                machine.cpu.state.x[2] = 0x2040;
                let exceptions = machine.statistics.exceptions;
                machine.system_instruction(word).unwrap();
                // A plain completion, or the Data Abort of the translation
                // check (a cache maintenance syndrome), rather than a trap.
                let target = machine.cpu.pstate.el.max(1);
                let esr = machine.cpu.read(if target == 2 {
                    SystemRegister::ESR_EL2
                } else {
                    SystemRegister::ESR_EL1
                });
                let checked = matches!(esr >> 26, 0x24 | 0x25) && esr & 1 << 8 != 0;
                let plain = machine.statistics.exceptions == exceptions
                    && machine.cpu.pc == BASE + 0x104
                    || machine.statistics.exceptions == exceptions + 1 && checked;
                assert_eq!(
                    native, plain,
                    "{word:#x} EL{el} HCR {hcr:#x} HFGITR {hfgitr:#x}"
                );
                covered[position][usize::from(native)] += 1;
            }
        }
        // Each operation was seen both completed natively and trapped.
        assert!(
            covered.iter().flatten().all(|&count| count > 0),
            "{covered:?}"
        );
    }

    /// A block ending in DC CIVAC checks Xt natively and falls through where
    /// it cannot trap, and exits where HCR_EL2.TPCP traps it; a fault in the
    /// native check completes DC CIVAC in the engine, which takes the Data
    /// Abort with a cache maintenance syndrome.
    #[test]
    fn dc_clean_blocks_follow_the_traps_and_faults_complete_in_the_engine() {
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        const DC_CIVAC: u32 = 0xd50b_7e23; // dc civac, x3
        let mut machine = machine(&[ADD, DC_CIVAC, ADD]);
        normal_memory(&mut machine, false);
        let base = machine.cpu.pc;
        let next = GuestAddress(base + 8);
        let fallthrough = NativeExit::Exit {
            next_pc: next.0,
            kind: ExitKind::Fallthrough as u64,
        };
        machine.host.exits = vec![fallthrough];
        machine.step().unwrap();
        let block = &machine.blocks[0];
        assert_eq!(
            block.variant.system.cache_clean,
            cache_clean::Operations::ALL
        );
        let code = &machine.host.installed[block.code.0 - 1];
        let tail = chain::direct_exit(next, ExitKind::Fallthrough);
        assert_eq!(code[code.len() - chain::DIRECT_EXIT_BYTES..], tail);
        assert_eq!(block.successors.len(), 1);
        // HCR_EL2.TPCP traps DC CIVAC at EL1: the PC gets a block that exits.
        let hcr = machine.cpu.read(SystemRegister::HCR_EL2);
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, hcr | 1 << 23);
        machine.derived_changed();
        machine.cpu.pc = base;
        machine.host.exits = vec![fallthrough];
        machine.step().unwrap();
        let trapped = &machine.blocks[1];
        assert!(
            !trapped
                .variant
                .system
                .cache_clean
                .contains(cache_clean::Operations::CIVAC)
        );
        let code = &machine.host.installed[trapped.code.0 - 1];
        assert_eq!(
            code[code.len() - chain::DIRECT_EXIT_BYTES..],
            chain::direct_exit(GuestAddress(base + 4), ExitKind::System)
        );
        // Without TPCP, an unmapped Xt faults the native read; the engine
        // takes the level-1 translation fault as a cache maintenance one.
        machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, hcr);
        machine.derived_changed();
        machine.cpu.pc = base;
        machine.cpu.state.x[3] = 0x4000_0040;
        let offset = machine.blocks[0].source_map[1].1;
        machine.host.exits = vec![NativeExit::Fault(NativeFault {
            registers: [0; 16],
            offset,
            address: 0x4000_0040,
            write: false,
            cause: FaultCause::Device { physical: 0 },
        })];
        let exits = machine.statistics.system_exits;
        machine.step().unwrap();
        let esr = machine.cpu.read(SystemRegister::ESR_EL1);
        // EC 0x25, CM (bit 8) and WnR (bit 6), a level-1 translation fault.
        assert_eq!(esr >> 26, 0x25, "{esr:#x}");
        assert_eq!(esr & (1 << 8 | 1 << 6 | 0x3f), 1 << 8 | 1 << 6 | 0b000101);
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), 0x4000_0040);
        assert_eq!(machine.statistics.system_exits, exits + 1);
        assert_eq!(machine.exit_words().get(&DC_CIVAC), Some(&1));
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

        // At EL1 with stage 1 off, data is Device-nGnRnE, so DC ZVA takes
        // the stage-1 Alignment fault (DFSC 0b100001, WnR) to EL1 with FAR
        // Xt, before stage 2 sees the IPA (Arm `AArch64_S1DisabledOutput`).
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        machine.cpu.set_pstate(Pstate::reset(1));
        let pc = machine.cpu.pc;
        machine.system_instruction(0xd50b_7422).unwrap(); // dc zva, x2
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (1, 0x1_0200));
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0x9600_0061);
        assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), unmapped);
        // Under HCR_EL2.DC stage 1 output is Normal: DC ZVA to an IPA stage
        // 2 does not map is a Data Abort taken to EL2 from the lower EL,
        // with FAR and HPFAR.
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, 1 << 34 | 1 << 12 | 1);
        machine.cpu.set_pstate(Pstate::reset(1));
        machine.cpu.pc = pc;
        machine.system_instruction(0xd50b_7422).unwrap(); // dc zva, x2
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, 1 << 34 | 1);
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

    #[test]
    fn apple_el2_keys_feed_pac_without_aliasing_lower_keys_or_inventing_unknown_pairs() {
        use crate::machine::system::key;
        use stela_compiler::aarch64::system::registers::Encoding;
        const PACIASP: u32 = 0xd503_233f;
        let mut machine = pac_machine();
        machine.cpu.pstate = Pstate::reset(2);
        machine
            .cpu
            .registers
            .set(SystemRegister::TCR_EL2, 0, 25 | 25 << 16);
        machine.cpu.registers.set(SystemRegister::SCTLR_EL2, 0, 0);
        machine.derived_changed();
        machine.cpu.state.x[30] = 0x4000;
        machine.cpu.state.sp = 0x8000;
        // Disabled PAC is still a NOP with no initialized host keys.
        machine.pointer_authentication(PACIASP).unwrap();
        assert_eq!(machine.cpu.state.x[30], 0x4000);
        machine
            .cpu
            .registers
            .set(SystemRegister::SCTLR_EL2, 0, 1 << 31);
        machine.derived_changed();
        let before = machine.cpu.pc;
        assert!(matches!(
            machine.pointer_authentication(PACIASP),
            Err(Stop::Unsupported(_))
        ));
        assert_eq!((machine.cpu.pc, machine.cpu.state.x[30]), (before, 0x4000));
        // The unknown IA pair never opens; disabled IB completes unchanged.
        let ia = usize::from(x86_64_pointer::key_index(PointerAuthenticationKey::Ia));
        let ib = usize::from(x86_64_pointer::key_index(PointerAuthenticationKey::Ib));
        assert_eq!(machine.pointer.tags[ia], 0);
        assert_eq!(machine.pointer.tags[ib], x86_64_pointer::DISABLED);
        // Actual first LLB MSR encoding; the other half must stay unknown.
        machine.cpu.state.x[1] = 11;
        machine.system_instruction(0xd51e_fd01).unwrap();
        assert_eq!(machine.pointer_keys(), [None; 5]);
        assert!(matches!(
            machine.pointer_authentication(PACIASP),
            Err(Stop::Unsupported(_))
        ));
        machine.cpu.state.x[0] = 21;
        machine.system_instruction(0xd51e_fd20).unwrap();
        assert_eq!(
            machine.pointer_keys(),
            [Some([11, 21]), None, None, None, None]
        );
        let expected = machine
            .pointer_context()
            .unwrap()
            .sign(pauth::Key::Ia, 0x4000, 0x8000)
            .unwrap();
        machine.pointer_authentication(PACIASP).unwrap();
        assert_eq!(machine.cpu.state.x[30], expected);
        let first_generation = machine.pointer.generation;
        assert_ne!(machine.pointer.tags[0], 0);

        // Every source-written pair owns separate halves; a real MSR moves
        // native PAC tags off the cached inputs' generation before any
        // further code can consume them.
        for pair in 0..5 {
            for half in 0..2 {
                let index = pair * 2 + half;
                let encoding = Encoding::new(3, 6, 15, 13 + (index / 8) as u8, (index % 8) as u8);
                machine.cpu.state.x[0] = 100 + index as u64;
                machine
                    .system_instruction(0xd500_0000 | u32::from(key(encoding)) << 5)
                    .unwrap();
                assert!(machine.pointer.tags.iter().all(|&tag| tag == 0
                    || tag == x86_64_pointer::DISABLED
                    || tag >> 8 != first_generation));
            }
        }
        assert_eq!(
            machine.pointer_keys(),
            [
                Some([100, 101]),
                Some([102, 103]),
                Some([104, 105]),
                Some([106, 107]),
                Some([108, 109])
            ]
        );
        machine.cpu.state.x[30] = 0x4000;
        machine.pointer_authentication(PACIASP).unwrap();
        assert_ne!(machine.pointer.generation, first_generation);
        assert_ne!(machine.cpu.state.x[30], expected);
        assert!(
            machine
                .pointer_context()
                .unwrap()
                .generic_code(7, 9)
                .is_ok()
        );
        // Standard EL1 slots are a distinct canonical bank, not C13 storage.
        assert_eq!(
            machine.cpu.read(SystemRegister::APIAKeyLo_EL1),
            0x1111_2222_3333_4444
        );
        machine.cpu.pstate = Pstate::reset(1);
        machine.derived_changed();
        assert_eq!(
            machine.pointer_keys()[0],
            Some([0x1111_2222_3333_4444, 0x5555_6666_7777_8888])
        );
        assert_ne!(
            machine
                .pointer_context()
                .unwrap()
                .sign(pauth::Key::Ia, 0x4000, 0x8000)
                .unwrap(),
            expected
        );
        // A read or a lower-EL access has no source-qualified permissions.
        assert!(matches!(
            machine.system_instruction(0xd51e_fd01),
            Err(Stop::Unsupported(_))
        ));
        machine.cpu.pstate = Pstate::reset(2);
        assert!(matches!(
            machine.system_instruction(0xd53e_fd01),
            Err(Stop::Unsupported(_))
        ));
    }

    #[test]
    fn standard_el2_key_writes_feed_pacga_without_mutating_the_lower_bank() {
        use crate::machine::system::key;
        use stela_compiler::aarch64::system::registers::Encoding;
        // Original SPTM's early canary instruction, used here with authored
        // operands. Its preceding standard-name MSRs must feed actual EL2 PAC.
        const PACGA: u32 = 0x9ac0_33e1;
        let mut machine = pac_machine_for(crate::machine::Chip::AppleM2, &[PACGA]);
        machine
            .cpu
            .registers
            .set(SystemRegister::APGAKeyLo_EL1, 0, 91);
        machine
            .cpu
            .registers
            .set(SystemRegister::APGAKeyHi_EL1, 0, 92);
        machine.cpu.pstate = Pstate::reset(2);
        machine.cpu.state.x[0] = 0x5354_4143_4b47_5244;
        let modifier = machine.cpu.state.x[0];
        let before = machine.cpu.pc;
        assert!(matches!(
            machine.pointer_authentication(PACGA),
            Err(Stop::Unsupported(_))
        ));
        assert_eq!(machine.cpu.pc, before);
        for (half, value) in [11, 21].into_iter().enumerate() {
            machine.cpu.state.x[2] = value;
            let encoding = Encoding::new(3, 0, 2, 3, half as u8);
            machine
                .system_instruction(0xd500_0000 | u32::from(key(encoding)) << 5 | 2)
                .unwrap();
            if half == 0 {
                assert!(!machine.pointer_context().unwrap().has_generic_key());
            }
        }
        machine.cpu.pc = BASE;
        machine.host.exits.push(NativeExit::Exit {
            next_pc: BASE,
            kind: ExitKind::PointerAuthentication as u64,
        });
        machine.step().unwrap();
        let expected = pauth::Context::new_with_version(
            0,
            pauth::Keys::from_optional_words([None; 4]).with_generic_words([11, 21]),
            machine.pointer_version().unwrap(),
        )
        .generic_code(0, modifier)
        .unwrap();
        assert_eq!(
            (machine.cpu.pc, machine.cpu.state.x[1]),
            (BASE + 4, expected)
        );
        assert_eq!(machine.cpu.read(SystemRegister::APGAKeyLo_EL1), 91);
        assert_eq!(machine.cpu.read(SystemRegister::APGAKeyHi_EL1), 92);
        machine.cpu.pstate = Pstate::reset(1);
        machine.derived_changed();
        assert_eq!(machine.pointer_keys()[4], Some([91, 92]));
    }

    #[test]
    fn el0_in_the_host_uses_the_el2_keys() {
        use crate::machine::system::key;
        const HCR_E2H: u64 = 1 << 34;
        use stela_compiler::aarch64::system::registers::Encoding;
        let mut machine = pac_machine();
        machine.cpu.pstate = Pstate::reset(2);
        for (half, value) in [31, 32].into_iter().enumerate() {
            machine.cpu.state.x[2] = value;
            let encoding = Encoding::new(3, 0, 2, 1, 2 + half as u8);
            machine
                .system_instruction(0xd500_0000 | u32::from(key(encoding)) << 5 | 2)
                .unwrap();
        }
        let el2 = machine.pointer_keys();
        assert_eq!(el2[1], Some([31, 32]));
        machine.cpu.pstate = Pstate::reset(0);
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, HCR_E2H | 1 << HCR_TGE);
        machine.derived_changed();
        assert_eq!(machine.pointer_keys(), el2);
        // A guest's EL0 keeps the lower bank.
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
        machine.derived_changed();
        assert_eq!(
            machine.pointer_keys()[1],
            Some([0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210])
        );
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
        // The source-qualified Apple host keys have an independent owner.
        // Give this enable/layout fixture explicit inputs through real MSRs,
        // rather than borrowing the lower bank or assuming reset zeroes.
        machine.cpu.set_pstate(Pstate::reset(2));
        for word in 0..8 {
            machine.cpu.state.x[0] = 11 + word;
            machine
                .system_instruction(0xd51e_fd00 | (word as u32) << 5)
                .unwrap();
        }
        let sctlr2 = machine.cpu.read(SystemRegister::SCTLR_EL2);
        for (el, register, base) in [
            (1, SystemRegister::SCTLR_EL1, sctlr),
            (2, SystemRegister::SCTLR_EL2, sctlr2),
        ] {
            machine.cpu.set_pstate(Pstate::reset(el));
            for (key, (word, enable)) in [
                (0xdac1_0041, 31),
                (0xdac1_0441, 30),
                (0xdac1_0841, 27),
                (0xdac1_0c41, 13),
            ]
            .into_iter()
            .enumerate()
            {
                for enabled in [false, true] {
                    let bit = u64::from(enabled) << enable;
                    machine
                        .cpu
                        .registers
                        .set(register, 0, base & !(1 << enable) | bit);
                    // As an MSR of the register does.
                    machine.derived_changed();
                    machine.cpu.state.x[1] = pointer;
                    machine.cpu.state.x[2] = 0x55;
                    machine.system_instruction_for_test(word);
                    assert_eq!(
                        machine.cpu.state.x[1] != pointer,
                        enabled,
                        "EL{el} {word:#x}"
                    );
                    // A disabled key lets thunks complete with the pointer
                    // until derived state changes.
                    assert_eq!(
                        machine.pointer.tags[key] == x86_64_pointer::DISABLED,
                        !enabled,
                        "EL{el} {word:#x}"
                    );
                    // Unchanged state reopens the same tag words.
                    let tags = machine.pointer.tags;
                    machine.derived_changed();
                    assert_eq!(machine.pointer.tags, tags, "EL{el} {word:#x}");
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
        // With EnDA clear AuthDA returns the unsigned base unchanged:
        // LDRAA reads through it, here an unmapped address, whose data
        // abort (EC 0x25) reports the base itself.
        let mut machine = pac_machine_for(crate::machine::Chip::AppleM6, &[]);
        let registers = &mut machine.cpu.registers;
        let sctlr = registers.get(SystemRegister::SCTLR_EL1, 0) & !(1 << 27);
        registers.set(SystemRegister::SCTLR_EL1, 0, sctlr);
        machine.cpu.state.x[1] = 0xffff_ff80_0000_8000;
        machine.system_instruction_for_test(LDRAA_X0_X1);
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1) >> 26, 0x25);
        assert_eq!(
            machine.cpu.read(SystemRegister::FAR_EL1),
            0xffff_ff80_0000_8000
        );
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
    fn implicit_authentication_fault_saves_incoming_btype_before_completion() {
        let pointer = 0xffff_ff80_0000_4000u64;
        for (sign, authenticate, ret, key) in [
            (0xd503_233f, 0xd503_23bf, 0xd65f_0bff, 0),
            (0xd503_237f, 0xd503_23ff, 0xd65f_0fff, 1),
        ] {
            for chip in [crate::machine::Chip::AppleM2, crate::machine::Chip::AppleM6] {
                for (word, combined) in [(authenticate, false), (ret, true)] {
                    for btype in 1..=3 {
                        let mut machine = pac_machine_for(chip, &[]);
                        machine.cpu.state.x[30] = pointer;
                        machine.cpu.state.sp = 0xffff_ff80_0001_0000;
                        machine.system_instruction_for_test(sign);
                        let signed = machine.cpu.state.x[30];
                        machine.cpu.state.sp += 16;
                        let sp = machine.cpu.state.sp;
                        machine.cpu.state.nzcv = 0xa000_0000;
                        machine.cpu.pstate.btype = btype;
                        let saved = machine.cpu.pstate.to_spsr(machine.cpu.state.nzcv);
                        let pc = machine.cpu.pc;
                        let retired = machine.cpu.retired;
                        // Invoke the actual implicit path after its source-entry
                        // boundary; this fixture does not model a guarded leaf.
                        machine.system_instruction_for_test(word);
                        let faults = !combined || chip == crate::machine::Chip::AppleM6;
                        if faults {
                            assert_eq!(machine.cpu.read(SystemRegister::SPSR_EL1), saved);
                            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), pc);
                            assert_eq!(
                                machine.cpu.read(SystemRegister::ESR_EL1),
                                0x7200_0000 | key
                            );
                            assert_eq!(machine.cpu.state.x[30], signed);
                        } else {
                            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0);
                            assert_ne!(machine.cpu.pc, pointer);
                        }
                        assert_eq!(machine.cpu.pstate.btype, 0);
                        assert_eq!(machine.cpu.state.sp, sp);
                        assert_eq!(machine.cpu.state.nzcv, 0xa000_0000);
                        // This service entry leaves retirement to its scheduler.
                        assert_eq!(machine.cpu.retired, retired);
                    }
                }
            }
        }
    }

    #[test]
    fn implicit_pac_forms_repeat_their_results_until_the_keys_change() {
        const PACIBSP: u32 = 0xd503_237f;
        const AUTIBSP: u32 = 0xd503_23ff;
        const RETAB: u32 = 0xd65f_0fff;
        const PACIA1716: u32 = 0xd503_211f;
        let mut machine = pac_machine();
        let pointer = 0xffff_ff80_0000_4000_u64;
        machine.cpu.state.sp = 0xffff_ff80_0001_0000;
        let sign = |machine: &mut Machine<FakeHost, NoDevices>| {
            machine.cpu.state.x[30] = pointer;
            machine.system_instruction_for_test(PACIBSP);
            machine.cpu.state.x[30]
        };
        let signed = sign(&mut machine);
        let expected = machine
            .pointer_context()
            .unwrap()
            .sign(pauth::Key::Ib, pointer, machine.cpu.state.sp)
            .unwrap();
        assert_eq!(signed, expected);
        assert_eq!(sign(&mut machine), signed, "remembered");
        machine.system_instruction_for_test(AUTIBSP);
        assert_eq!(machine.cpu.state.x[30], pointer);
        // RETAB branches to the authenticated pointer and keeps X30 signed.
        machine.cpu.state.x[30] = signed;
        machine.system_instruction_for_test(RETAB);
        assert_eq!((machine.cpu.pc, machine.cpu.state.x[30]), (pointer, signed));
        // PACIA1716 signs X17 with X16 under key A.
        machine.cpu.state.x[16] = 0x55;
        machine.cpu.state.x[17] = pointer;
        machine.system_instruction_for_test(PACIA1716);
        let context = machine.pointer_context().unwrap();
        assert_eq!(
            machine.cpu.state.x[17],
            context.sign(pauth::Key::Ia, pointer, 0x55).unwrap()
        );
        // A key the guest writes changes every later result.
        machine
            .cpu
            .registers
            .set(SystemRegister::APIBKeyLo_EL1, 0, 0x0bad_cafe);
        machine.derived_changed();
        assert_ne!(sign(&mut machine), signed);
    }

    /// A block ending in a PAC exit has it redirected through a thunk that
    /// completes the instruction from the memo, whose exit onward the block
    /// may chain; a PAC exit opens the key's tag word under the current
    /// memo, and a change of derived state closes it again.
    #[test]
    fn pac_exits_complete_natively_from_the_memo_under_open_tags() {
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        const PACIBSP: u32 = 0xd503_237f;
        let mut machine = machine(&[ADD, PACIBSP, ADD]);
        let base = machine.cpu.pc;
        machine.host.exits = vec![NativeExit::Exit {
            next_pc: base + 8,
            kind: ExitKind::Fallthrough as u64,
        }];
        machine.step().unwrap();
        let block = &machine.blocks[0];
        let code = &machine.host.installed[block.code.0 - 1];
        let (memo, tags, service) = machine.pointer.addresses();
        let thunk = x86_64_pointer::thunk(
            x86_64_pointer::Form::of(block::PointerAuthenticationOperation::SignIbSp).unwrap(),
            GuestAddress(base + 4),
            memo,
            tags,
            service,
        );
        let installed = machine.host.installed.len();
        assert_eq!(machine.host.installed[installed - 1], thunk.code);
        let site = block.code.0 + code.len() - chain::DIRECT_EXIT_BYTES;
        let jump = chain::jump(site as u64, installed as u64).unwrap().to_vec();
        assert_eq!(machine.host.patches, [(site, jump)]);
        assert_eq!(
            block.successors,
            [Successor {
                site: (installed + thunk.next.unwrap()) as u64,
                target: GuestAddress(base + 8),
                kind: ExitKind::Fallthrough,
            }]
        );
        let mut machine = pac_machine();
        assert_eq!(machine.pointer.tags, [0; 4]);
        machine
            .pointer_result(PointerOperation::Sign, pauth::Key::Ib, 0x4000, 0x10)
            .unwrap()
            .unwrap();
        let ib = x86_64_pointer::key_index(PointerAuthenticationKey::Ib);
        let open = x86_64_pointer::tag(machine.pointer.generation, ib, 0);
        assert_eq!(machine.pointer.tags[usize::from(ib)], open);
        // A derived change that keeps the inputs, enable and trap reopens
        // the tag; clearing the key's enable makes it DISABLED.
        machine.derived_changed();
        assert_eq!(machine.pointer.tags[usize::from(ib)], open);
        let sctlr = machine.cpu.regime_sctlr();
        let register = if machine.cpu.pstate.el == 2 {
            SystemRegister::SCTLR_EL2
        } else {
            SystemRegister::SCTLR_EL1
        };
        machine.cpu.registers.set(register, 0, sctlr & !(1 << 30));
        machine.derived_changed();
        assert_eq!(
            machine.pointer.tags[usize::from(ib)],
            x86_64_pointer::DISABLED
        );
    }

    #[test]
    fn xpac_thunks_follow_regime_masks_without_key_enables_and_close_on_changes() {
        const ADD: u32 = 0x9100_0400;
        const XPACD_X17: u32 = 0xdac1_47f1;
        let mut native = machine(&[ADD, XPACD_X17, ADD]);
        let base = native.cpu.pc;
        native.host.exits = vec![NativeExit::Exit {
            next_pc: base + 8,
            kind: ExitKind::Fallthrough as u64,
        }];
        native.step().unwrap();
        let thunk = x86_64_pointer::strip::thunk(
            GuestAddress(base + 4),
            17,
            native.pointer.strip_address(true),
        )
        .unwrap();
        assert_eq!(native.host.installed.last(), Some(&thunk.code));
        let installed = native.host.installed.len();
        assert_eq!(
            native.blocks[0].successors,
            [Successor {
                site: (installed + thunk.next.unwrap()) as u64,
                target: GuestAddress(base + 8),
                kind: ExitKind::Fallthrough,
            }]
        );
        let mut machine = pac_machine();
        machine.cpu.registers.set(SystemRegister::SCTLR_EL1, 0, 0);
        machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, 0);
        for tcr in [25 | 17 << 16, 25 | 17 << 16 | 1 << 37 | 1 << 38 | 1 << 51] {
            machine.cpu.registers.set(SystemRegister::TCR_EL1, 0, tcr);
            machine.derived_changed();
            for (word, data, key) in [
                (0xdac1_43f1, false, pauth::Key::Ia),
                (XPACD_X17, true, pauth::Key::Da),
            ] {
                for pointer in [0xdead_1234_5678_aaaa, 0xdead_9234_5678_aaaa] {
                    machine.cpu.state.x[17] = pointer;
                    let expected = machine
                        .pointer_context()
                        .unwrap()
                        .strip(key, pointer)
                        .unwrap();
                    let el = machine.cpu.pstate.el;
                    machine.system_instruction_for_test(word);
                    assert_eq!(
                        machine.cpu.pstate.el, el,
                        "XPAC neither uses nor traps a key"
                    );
                    assert_eq!(machine.cpu.state.x[17], expected);
                    assert_eq!(machine.pointer.strips[usize::from(data)].enabled, 1);
                    // XPAC opens no key's memo tag; disabled keys stay so.
                    assert!(
                        machine
                            .pointer
                            .tags
                            .iter()
                            .all(|&tag| tag == 0 || tag == x86_64_pointer::DISABLED)
                    );
                }
            }
            // Unchanged state reopens the same masks.
            let strips = machine.pointer.strips;
            machine.derived_changed();
            assert_eq!(machine.pointer.strips, strips);
        }
    }

    /// A RETAB's PAC thunk ends its completion with the exit to the target
    /// in RAX, which the first return through it redirects into a lookup.
    #[test]
    fn pac_returns_go_through_a_lookup_thunk() {
        const RETAB: u32 = 0xd65f_0fff;
        let mut machine = machine(&[RETAB]);
        let base = machine.cpu.pc;
        machine.host.exits = vec![NativeExit::Exit {
            next_pc: base + 0x2000,
            kind: ExitKind::Return as u64,
        }];
        machine.step().unwrap();
        let (memo, tags, service) = machine.pointer.addresses();
        let thunk = x86_64_pointer::thunk(
            x86_64_pointer::Form::of(block::PointerAuthenticationOperation::ReturnIbSp).unwrap(),
            GuestAddress(base),
            memo,
            tags,
            service,
        );
        let at = machine
            .host
            .installed
            .iter()
            .position(|code| *code == thunk.code)
            .unwrap()
            + 1;
        let site = (at + thunk.dynamic.unwrap()) as u64;
        let control = &*machine.chain as *const ChainControl as u64;
        let lookup = chain::lookup_thunk(control, 1, None, ExitKind::Return, 0).unwrap();
        assert_eq!(machine.host.installed.last(), Some(&lookup));
        let jump = chain::jump(site, machine.host.installed.len() as u64).unwrap();
        assert_eq!(
            machine.host.patches.last(),
            Some(&(site as usize, jump.to_vec()))
        );
        assert_eq!(machine.statistics.lookups, 1);
        assert_eq!(machine.blocks[0].dynamic_site, None);
    }

    /// MRS TPIDR_EL1 ends its block in a System exit that a thunk reading
    /// the engine's cell takes over, chaining on to the next instruction;
    /// the cell opens on a plain read and closes on any derived change
    /// other than a PSTATE mask or SPSel write.
    #[test]
    fn mirrored_reads_complete_natively_from_the_open_cell() {
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        const MRS: u32 = 0xd538_d088; // mrs x8, tpidr_el1
        const MSR: u32 = 0xd518_d089; // msr tpidr_el1, x9
        const MRS_DAIF: u32 = 0xd53b_4228; // mrs x8, daif
        const DAIFCLR_I: u32 = 0xd503_42ff; // msr daifclr, #2
        const MRS_GXF_STATUS: u32 = 0xd53e_f808; // mrs x8, gxf_status_el1
        const SPSEL_1: u32 = 0xd500_41bf; // msr spsel, #1
        const DAIFCLR_D: u32 = 0xd503_48ff; // msr daifclr, #8
        let index = |encoding| MIRRORED.iter().position(|&e| e == encoding).unwrap();
        let thread = index(registers::encodings::TPIDR_EL1);
        let daif = index(registers::encodings::DAIF);
        let mut machine = machine(&[ADD, MRS, ADD]);
        let base = machine.cpu.pc;
        machine.host.exits = vec![NativeExit::Exit {
            next_pc: base + 8,
            kind: ExitKind::Fallthrough as u64,
        }];
        machine.step().unwrap();
        let block = &machine.blocks[0];
        let code = &machine.host.installed[block.code.0 - 1];
        let cell = &machine.mirrors[thread] as *const register_read::Cell as u64;
        let thunk = register_read::thunk(GuestAddress(base + 4), 8, cell);
        let installed = machine.host.installed.len();
        assert_eq!(machine.host.installed[installed - 1], thunk.code);
        let site = block.code.0 + code.len() - chain::DIRECT_EXIT_BYTES;
        let jump = chain::jump(site as u64, installed as u64).unwrap().to_vec();
        assert_eq!(machine.host.patches, [(site, jump)]);
        assert_eq!(
            block.successors,
            [Successor {
                site: (installed + thunk.next.unwrap()) as u64,
                target: GuestAddress(base + 8),
                kind: ExitKind::Fallthrough,
            }]
        );
        // Other System reads keep their exit.
        let mut other = super::tests::machine(&[ADD, 0xd538_1008]); // mrs x8, sctlr_el1
        other.host.exits = machine.host.exits.clone();
        other.host.exits.push(NativeExit::Exit {
            next_pc: base + 8,
            kind: ExitKind::Fallthrough as u64,
        });
        other.step().unwrap();
        assert!(other.host.patches.is_empty() && other.blocks[0].successors.is_empty());
        machine
            .cpu
            .registers
            .set(SystemRegister::TPIDR_EL1, 0, 0x5000);
        machine.cpu.pc = base + 4;
        machine.system_instruction(MRS).unwrap();
        assert_eq!(machine.cpu.state.x[8], 0x5000);
        assert_eq!(
            machine.mirrors[thread],
            register_read::Cell {
                readable: 1,
                value: 0x5000
            }
        );
        machine.derived_changed();
        // Closed, the cell keeps no value a mispredicted read could use.
        assert_eq!(*machine.mirrors, Mirrors::default());
        // An Apple register read leaves it open.
        machine.cpu.pc = base + 4;
        machine.system_instruction(MRS).unwrap();
        let exceptions = machine.statistics.exceptions;
        machine.system_instruction(MRS_GXF_STATUS).unwrap();
        assert_eq!(machine.statistics.exceptions, exceptions);
        assert_eq!(machine.mirrors[thread].readable, 1);
        // A write of the register closes it, as does a PSTATE write.
        machine.cpu.pc = base + 4;
        machine.system_instruction(MRS).unwrap();
        machine.system_instruction(MRS_DAIF).unwrap();
        assert_eq!(machine.mirrors[daif].readable, 1);
        machine.cpu.state.x[9] = 0x6000;
        machine.system_instruction(MSR).unwrap();
        assert_eq!(*machine.mirrors, Mirrors::default());
        machine.system_instruction(MRS_DAIF).unwrap();
        let masks = machine.cpu.state.x[8];
        // A mask write keeps the cells, the DAIF one with the new masks.
        machine.system_instruction(MRS).unwrap();
        machine.system_instruction(DAIFCLR_I).unwrap();
        assert_eq!(machine.mirrors[thread].readable, 1);
        let cell = machine.mirrors[daif];
        assert_eq!(cell.readable, 1);
        assert_ne!(cell.value, masks);
        machine.system_instruction(MRS_DAIF).unwrap();
        assert_eq!(
            (machine.mirrors[daif], machine.cpu.state.x[8]),
            (cell, cell.value)
        );
        // So does SPSel; D, like the other fields, forgets them.
        machine.system_instruction(SPSEL_1).unwrap();
        assert_eq!(machine.mirrors[daif], cell);
        assert_eq!(machine.mirrors[thread].readable, 1);
        machine.system_instruction(DAIFCLR_D).unwrap();
        assert_eq!(*machine.mirrors, Mirrors::default());
        // A read to XZR has no cell to open, nor a thunk.
        assert_eq!(mirrored_read(base, 0xd538_d09f), None); // mrs xzr, tpidr_el1
    }

    /// Native accesses check and mask their own addresses at every access
    /// exactly where ID_AA64PFR0_EL1.CSV3 discloses FEAT_CSV3.
    #[test]
    fn every_access_masks_its_address_where_csv3_is_disclosed() {
        let mut machine = machine(&[0xd503_201f]);
        for csv3 in [0, 1] {
            let pfr0 = machine.cpu.read(SystemRegister::ID_AA64PFR0_EL1);
            let pfr0 = pfr0 & !(0xf << CSV3_SHIFT) | csv3 << CSV3_SHIFT;
            machine
                .cpu
                .registers
                .set_raw(SystemRegister::ID_AA64PFR0_EL1, 0, pfr0);
            machine.derived_changed();
            assert_eq!(machine.memory_checks().every_access_masked, csv3 == 1);
        }
    }

    /// Where DC ZVA cannot trap, a block ending in it zeroes natively and
    /// falls through; elsewhere the same PC compiles a block that exits. A
    /// fault in the native zeroing completes DC ZVA in the engine.
    #[test]
    fn dc_zva_blocks_follow_the_permission_and_faults_complete_in_the_engine() {
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        const DC_ZVA: u32 = 0xd50b_7423; // dc zva, x3
        let mut machine = machine(&[ADD, DC_ZVA, ADD]);
        normal_memory(&mut machine, false);
        let base = machine.cpu.pc;
        machine.cpu.state.x[3] = BASE + 0x108;
        machine.host.ram[0x100..0x180].fill(0xaa);
        let next = GuestAddress(base + 8);
        machine.host.exits = vec![NativeExit::Exit {
            next_pc: next.0,
            kind: ExitKind::Fallthrough as u64,
        }];
        machine.step().unwrap();
        let block = &machine.blocks[0];
        assert_eq!(block.variant.system.zero_block, Some(64));
        let code = &machine.host.installed[block.code.0 - 1];
        let tail = chain::direct_exit(next, ExitKind::Fallthrough);
        assert_eq!(code[code.len() - chain::DIRECT_EXIT_BYTES..], tail);
        assert_eq!(block.successors.len(), 1);
        assert_eq!(block.successors[0].target, next);
        // HCR_EL2.TDZ traps DC ZVA at EL1: the PC gets a block that exits.
        let hcr = machine.cpu.read(SystemRegister::HCR_EL2);
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, hcr | 1 << 28);
        machine.derived_changed();
        machine.cpu.pc = base;
        machine.host.exits = vec![NativeExit::Exit {
            next_pc: next.0,
            kind: ExitKind::Fallthrough as u64,
        }];
        machine.step().unwrap();
        let trapped = &machine.blocks[1];
        assert_eq!(trapped.variant.system.zero_block, None);
        let code = &machine.host.installed[trapped.code.0 - 1];
        assert_eq!(
            code[code.len() - chain::DIRECT_EXIT_BYTES..],
            chain::direct_exit(GuestAddress(base + 4), ExitKind::System)
        );
        // Back without TDZ, a store fault in the zeroing hands DC ZVA to the
        // engine, which zeroes the block and continues.
        machine.cpu.registers.set(SystemRegister::HCR_EL2, 0, hcr);
        machine.derived_changed();
        machine.cpu.pc = base;
        let offset = machine.blocks[0].source_map[1].1;
        machine.host.exits = vec![NativeExit::Fault(NativeFault {
            registers: [0; 16],
            offset,
            address: BASE + 0x100,
            write: true,
            cause: FaultCause::Watched,
        })];
        let exits = machine.statistics.system_exits;
        machine.step().unwrap();
        assert_eq!(machine.cpu.pc, next.0);
        assert!(machine.host.ram[0x100..0x140].iter().all(|&byte| byte == 0));
        assert!(
            machine.host.ram[0x140..0x180]
                .iter()
                .all(|&byte| byte == 0xaa)
        );
        assert_eq!(machine.statistics.system_exits, exits + 1);
        assert_eq!(machine.exit_words().get(&DC_ZVA), Some(&1));
    }

    /// A return to earlier keys finds their generation, and its entries,
    /// again; other keys get their own, and beyond the inputs kept a
    /// generation is new.
    #[test]
    fn memo_generations_follow_the_keys() {
        let mut machine = pac_machine();
        let (pointer, modifier) = (0xffff_ff80_0000_4000, 0x10);
        let sign = |machine: &mut Machine<FakeHost, NoDevices>, key| {
            machine
                .cpu
                .registers
                .set(SystemRegister::APIBKeyLo_EL1, 0, key);
            machine.derived_changed();
            let signed = machine
                .pointer_result(PointerOperation::Sign, pauth::Key::Ib, pointer, modifier)
                .unwrap()
                .unwrap();
            (signed, machine.pointer.generation)
        };
        let (first, generation) = sign(&mut machine, 1);
        let (other, other_generation) = sign(&mut machine, 2);
        assert_ne!((other, other_generation), (first, generation));
        assert_eq!(sign(&mut machine, 1), (first, generation));
        let remembered =
            machine
                .pointer
                .remembered(PointerOperation::Sign, pauth::Key::Ib, pointer, modifier);
        assert_eq!(remembered, Some(Ok(first)));
        for key in 0..pointer::POINTER_INPUTS_SEEN as u64 {
            sign(&mut machine, 0x1000 + key);
        }
        let (again, renewed) = sign(&mut machine, 1);
        assert_eq!(again, first);
        assert!(renewed > other_generation);
    }

    /// A signing remembers that its result authenticates back to its
    /// pointer, for the plain and the combined form, unless the pointer was
    /// not canonical, when authentication must be computed (and fails).
    #[test]
    fn signing_remembers_the_authentication_of_its_result() {
        let mut machine = pac_machine();
        let modifier = 0xffff_ff80_0001_0000;
        let sign = PointerOperation::Sign;
        let plain = PointerOperation::Authenticate { combined: false };
        let combined = PointerOperation::Authenticate { combined: true };
        let pointer = 0xffff_ff80_0000_4000;
        let (signed, _) = machine
            .pointer_result(sign, pauth::Key::Ib, pointer, modifier)
            .unwrap()
            .unwrap();
        let remembered = machine
            .pointer
            .remembered(plain, pauth::Key::Ib, signed, modifier);
        assert_eq!(remembered, Some(Ok((pointer, true))));
        let context = machine.pointer_context().unwrap();
        for operation in [plain, combined] {
            let PointerOperation::Authenticate { combined } = operation else {
                unreachable!()
            };
            let computed = context
                .authenticate_operation(pauth::Key::Ib, signed, modifier, combined)
                .unwrap();
            assert_eq!(
                machine.pointer_result(operation, pauth::Key::Ib, signed, modifier),
                Ok(Ok((computed.pointer, computed.authenticated)))
            );
        }
        // A pointer whose extension bits disagree does not strip back.
        let odd = 0x7fff_ff80_0000_4000;
        let (signed, _) = machine
            .pointer_result(sign, pauth::Key::Ib, odd, modifier)
            .unwrap()
            .unwrap();
        assert_eq!(
            machine
                .pointer
                .remembered(plain, pauth::Key::Ib, signed, modifier),
            None
        );
        let computed = context.authenticate_operation(pauth::Key::Ib, signed, modifier, false);
        let result = machine.pointer_result(plain, pauth::Key::Ib, signed, modifier);
        match computed {
            Ok(computed) => assert_eq!(result, Ok(Ok((computed.pointer, computed.authenticated)))),
            Err(pauth::AuthenticationError::Failure { code }) => assert_eq!(result, Ok(Err(code))),
            Err(error) => panic!("{error:?}"),
        }
    }

    #[test]
    fn register_pac_forms_complete_as_the_pac_service_computes() {
        const PACIA_X0_X1: u32 = 0xdac1_0020;
        const AUTIA_X0_X1: u32 = 0xdac1_1020;
        const BLRAA_X2_X3: u32 = 0xd73f_0843;
        const BRAAZ_X2: u32 = 0xd61f_085f;
        let mut machine = pac_machine();
        let pointer = 0xffff_ff80_0000_4000_u64;
        let context = machine.pointer_context().unwrap();
        machine.cpu.state.x[0] = pointer;
        machine.cpu.state.x[1] = 0x1234;
        machine.system_instruction_for_test(PACIA_X0_X1);
        let signed = context.sign(pauth::Key::Ia, pointer, 0x1234).unwrap();
        assert_eq!(machine.cpu.state.x[0], signed);
        machine.system_instruction_for_test(AUTIA_X0_X1);
        assert_eq!(machine.cpu.state.x[0], pointer);
        // BLRAA links after authenticating the target with X3.
        machine.cpu.state.x[2] = context.sign(pauth::Key::Ia, pointer, 0x99).unwrap();
        machine.cpu.state.x[3] = 0x99;
        let pc = machine.cpu.pc;
        machine.system_instruction_for_test(BLRAA_X2_X3);
        assert_eq!((machine.cpu.pc, machine.cpu.state.x[30]), (pointer, pc + 4));
        // BRAAZ authenticates with a zero modifier; a wrong one corrupts
        // the target, as the general path's combined authentication does.
        machine.cpu.state.x[2] = context.sign(pauth::Key::Ia, pointer, 0).unwrap();
        machine.system_instruction_for_test(BRAAZ_X2);
        assert_eq!(machine.cpu.pc, pointer);
        let wrong = context.sign(pauth::Key::Ia, pointer, 1).unwrap();
        machine.cpu.state.x[2] = wrong;
        let fault_pc = machine.cpu.pc;
        machine.system_instruction_for_test(BRAAZ_X2);
        match context.authenticate_operation(pauth::Key::Ia, wrong, 0, true) {
            Ok(result) => assert_eq!(machine.cpu.pc, result.pointer),
            Err(pauth::AuthenticationError::Failure { code }) => {
                // FEAT_FPACCOMBINE (M6) faults the failed branch instead of
                // returning a corrupted target. Its source stays unchanged.
                assert_eq!(
                    machine.cpu.read(SystemRegister::ESR_EL1),
                    0x7200_0000 | u64::from(code)
                );
                assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), fault_pc);
                assert_eq!(machine.cpu.pc, 0x1_0200);
                assert_eq!(machine.cpu.state.x[2], wrong);
            }
            Err(error) => panic!("{error:?}"),
        }
        assert_ne!(machine.cpu.pc, pointer);
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

    /// An ERET or GEXIT into an EL1&0 guest stops while a VM register holds
    /// a nonzero value, and enters it once the value is zero; the host's
    /// own returns are unaffected. Graceful, the guest is entered without
    /// the state, reported once.
    #[test]
    fn entering_a_guest_with_unapplied_vm_state_stops() {
        const ERET: u32 = 0xd69f_03e0;
        const GEXIT: u32 = 0x0020_1400;
        const EL1H: u64 = 0x3c5;
        const EL0T: u64 = 0x3c0;
        const HCR_E2H: u64 = 1 << 34;
        let guest = super::super::impdef::TABLE
            .iter()
            .find(|entry| entry.encoding == super::super::impdef::GUEST_SPRR_C15_4)
            .unwrap();
        let mut machine = machine(&[]);
        let enter = |machine: &mut Machine<_, _>, word, spsr| {
            machine.cpu.set_pstate(Pstate::reset(2));
            machine.cpu.pc = BASE;
            machine.cpu.registers.set(SystemRegister::SPSR_EL2, 0, spsr);
            machine
                .cpu
                .registers
                .set(SystemRegister::ELR_EL2, 0, 0x8000);
            machine.system_instruction(word)
        };
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
        machine.cpu.apple.impdef.write(guest, 0x3b).unwrap();
        match enter(&mut machine, ERET, EL1H) {
            Err(Stop::Unsupported(requirement)) => {
                assert_eq!(requirement.kind, RequirementKind::VmState(guest.name));
                assert_eq!((requirement.pc, requirement.el), (BASE, 2));
            }
            other => panic!("{other:?}"),
        }
        // The host (HCR_EL2.TGE) returning to its EL0 is no guest entry.
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, HCR_E2H | 1 << HCR_TGE);
        enter(&mut machine, ERET, EL0T).unwrap();
        assert_eq!(machine.cpu.pstate.el, 0);
        // GEXIT from GL2 into the guest stops the same way.
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
        machine.cpu.set_pstate(Pstate {
            guarded: true,
            ..Pstate::reset(2)
        });
        machine.cpu.apple.guarded[1].spsr = EL1H;
        machine.cpu.apple.guarded[1].elr = 0x8000;
        machine.cpu.apple.guarded[1].aspsr = 0;
        assert!(matches!(
            machine.system_instruction(GEXIT),
            Err(Stop::Unsupported(_))
        ));
        assert!(machine.cpu.pstate.guarded, "the GEXIT was not made");
        // SPTM's zero loads leave nothing to apply.
        machine.cpu.apple.impdef.write(guest, 0).unwrap();
        machine.system_instruction(GEXIT).unwrap();
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (1, 0x8000));
        enter(&mut machine, ERET, EL1H).unwrap();
        assert_eq!(machine.cpu.pstate.el, 1);
        machine.cpu.apple.impdef.write(guest, 0x3b).unwrap();
        machine.set_strict(false);
        for _ in 0..2 {
            enter(&mut machine, ERET, EL1H).unwrap();
            assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (1, 0x8000));
        }
        let reports = machine.take_unmodeled();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].kind, RequirementKind::VmState(guest.name));
    }

    /// HACR_EL2's SPTM VM entry value traps a guest EL1's HID read to EL2 as
    /// an MRS trap, refuses an encoding no bit names and SDSB by the unnamed
    /// bit, and leaves the host and a guest without set bits alone.
    #[test]
    fn hacr_traps_or_refuses_a_guests_apple_operations() {
        const MRS_HID4: u32 = 0xd538_f402;
        const MRS_C15_C2_5: u32 = 0xd53e_f2a2;
        const MRS_AIDR: u32 = 0xd539_00e2;
        const MRS_SPRR_PERM_EL1: u32 = 0xd53e_f1c2;
        const SDSB_ISH: u32 = 0x0020_1462;
        const HCR_E2H: u64 = 1 << 34;
        const CUSTOMER: u64 = 0x061f_0000_6100_2000;
        let mut machine = machine(&[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL2, 0, 0x4_0000);
        let run = |machine: &mut Machine<_, _>, el, hacr, word| {
            machine.cpu.set_pstate(Pstate::reset(el));
            machine.cpu.pc = BASE;
            machine.cpu.registers.set(SystemRegister::HACR_EL2, 0, hacr);
            machine.system_instruction(word)
        };
        run(&mut machine, 1, CUSTOMER, MRS_HID4).unwrap();
        assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (2, 0x4_0400));
        assert_eq!(
            machine.cpu.read(SystemRegister::ESR_EL2),
            0x18 << 26 | 1 << 25 | u64::from(registers::word_trap_iss(MRS_HID4))
        );
        assert_eq!(machine.cpu.read(SystemRegister::ELR_EL2), BASE);
        for (word, reason) in [
            (
                MRS_C15_C2_5,
                "HACR_EL2 bit 24 on S3_6_C15_C2_5: trapped operation not recovered",
            ),
            (
                SDSB_ISH,
                "HACR_EL2 bit 24 on SDSB: trapped operation not recovered",
            ),
        ] {
            match run(&mut machine, 1, CUSTOMER, word) {
                Err(Stop::Unsupported(requirement)) => assert_eq!(
                    requirement.kind,
                    RequirementKind::Instruction {
                        word,
                        detail: reason.into()
                    }
                ),
                other => panic!("{other:?}"),
            }
        }
        // TRAP_AIDR and TRAP_SPRR trap the guest's AIDR_EL1 and
        // SPRR_PERM_EL1 reads; without set bits the guest's SPRR access and
        // barrier run, and the host's own accesses never consult HACR_EL2.
        for (hacr, word) in [(1 << 4, MRS_AIDR), (1 << 11, MRS_SPRR_PERM_EL1)] {
            run(&mut machine, 1, hacr, word).unwrap();
            assert_eq!((machine.cpu.pstate.el, machine.cpu.pc), (2, 0x4_0400));
        }
        for (el, hacr, word) in [
            (1, 0, MRS_SPRR_PERM_EL1),
            (1, 0, SDSB_ISH),
            (2, CUSTOMER | 1 << 11, MRS_SPRR_PERM_EL1),
        ] {
            // The access completes or takes its own exception at the same
            // EL (SPRR is not enabled here), never HACR_EL2's trap.
            run(&mut machine, el, hacr, word).unwrap();
            assert_eq!(machine.cpu.pstate.el, el);
            assert_ne!(machine.cpu.pc, 0x4_0400);
        }
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
        // scalar FP pass their checks (`engine::scalable` runs them): the SVE
        // addition runs, and the ZA load from address 0, which has no RAM or
        // device, stops explicitly.
        machine.cpu.set_svcr(true, true).unwrap();
        assert_eq!(taken(&mut machine, 0), trapped(0, 1));
        assert_eq!(run(&mut machine, 1).0, Ok(()));
        assert_eq!(machine.cpu.pc, BASE + 8);
        assert!(matches!(run(&mut machine, 2).0, Err(Stop::Unsupported(_))));
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
    fn sysl_has_no_architectural_accessor_and_the_implementation_defined_space_is_undefined() {
        const HCR_E2H: u64 = 1 << 34;
        let mut machine = machine(&[]);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, 0x1_0000);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL2, 0, 0x2_0000);
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
        // CRn 11 and 15 are the IMPLEMENTATION DEFINED space, for SYSL and
        // SYS (sysl x0, #0, C11, C0, #0; sysl x0, #7, C15, C15, #7; sys #0,
        // C11, C0, #0, x0; sys #7, C15, C15, #7). No censused component
        // executes one, so each is UNDEFINED at EL0, EL1 and EL2.
        const SPACE: [u32; 4] = [0xd528_b000, 0xd52f_ffe0, 0xd508_b000, 0xd50f_ffff];
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, HCR_E2H);
        for word in SPACE {
            for el in [0, 1, 2] {
                machine.cpu.set_pstate(Pstate::reset(el));
                machine.cpu.pc = BASE;
                machine.system_instruction(word).unwrap();
                let (target, syndrome) = if el == 2 {
                    (2, SystemRegister::ESR_EL2)
                } else {
                    (1, SystemRegister::ESR_EL1)
                };
                assert_eq!(machine.cpu.pstate.el, target, "{word:#x} at EL{el}");
                assert_eq!(
                    machine.cpu.read(syndrome),
                    0x0200_0000,
                    "{word:#x} at EL{el}"
                );
            }
        }
        // HCR_EL2.TIDCP traps the space from EL1 to EL2 first (EC 0x18).
        machine
            .cpu
            .registers
            .set(SystemRegister::HCR_EL2, 0, HCR_E2H | 1 << 20);
        for word in SPACE {
            machine.cpu.set_pstate(Pstate::reset(1));
            machine.cpu.pc = BASE;
            machine.system_instruction(word).unwrap();
            assert_eq!(machine.cpu.pstate.el, 2, "{word:#x}");
            assert_eq!(
                machine.cpu.read(SystemRegister::ESR_EL2),
                0x6200_0000 | u64::from(registers::word_trap_iss(word)),
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
                registers: [0; 16],
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
        normal_memory(&mut machine, false);
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
        assert_eq!(
            machine.cpu.monitor.map(|reservation| reservation.granule),
            Some((BASE + 0x200) & !63)
        );
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

    /// 26A434 XNU's TTBR1 layout: a 16 KiB granule with T1SZ 17, so 2048
    /// level-1 entries of 64 GiB from 0xffff_8000_0000_0000.
    #[test]
    fn upper_occupancy_lists_the_mapped_level_one_ranges_and_outermost_blocks() {
        const ROOT: u64 = BASE + 0x8000;
        const NEXT: u64 = BASE + 0xc000;
        let mut machine = machine(&[]);
        let mut put = |address: u64, value: u64| {
            let offset = (address - BASE) as usize;
            machine.host.ram[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        };
        put(ROOT + 2016 * 8, NEXT | 0b11);
        put(ROOT + 2017 * 8, 0b01);
        put(ROOT + 2047 * 8, 0b01);
        put(NEXT + 3 * 8, 0b11);
        let registers = &mut machine.cpu.registers;
        registers.set(SystemRegister::TCR_EL1, 0, 17 << 16 | 0b01 << 30);
        registers.set(SystemRegister::TTBR1_EL1, 0, ROOT);
        assert_eq!(machine.upper_occupancy(), None, "the MMU is off");
        machine.cpu.registers.set(SystemRegister::SCTLR_EL1, 0, 1);
        assert_eq!(
            machine.upper_occupancy(),
            Some(Occupancy {
                root: ROOT,
                ranges: vec![
                    (0xffff_fe00_0000_0000, 0xffff_fe1f_ffff_ffff),
                    (0xffff_fff0_0000_0000, u64::MAX),
                ],
                lowest: Some(0xffff_fe00_0600_0000),
                highest: Some(u64::MAX),
            })
        );
        // Another granule is not reported.
        machine
            .cpu
            .registers
            .set(SystemRegister::TCR_EL1, 0, 17 << 16 | 0b10 << 30);
        assert_eq!(machine.upper_occupancy(), None);
    }
}
