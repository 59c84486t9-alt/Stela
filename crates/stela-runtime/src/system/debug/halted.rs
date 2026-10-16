//! The debug registers of a PE and its halted-instruction gate.
use crate::system::{
    access::{ExceptionLevel, SecurityState},
    identification::Register,
    identification_snapshot::{Origin, Snapshot, Unsupported as IdentificationUnsupported},
    state::{PSTATE_SS_MASK, StateError, SystemState},
};
use alloc::sync::Arc;
use stela_compiler::GuestState;

const STATUS_MASK: u32 = 0x3f;
const EDSCR_ERR: u32 = 1 << 6;
const EDSCR_ITE: u32 = 1 << 24;
const EDSCR_ITO: u32 = 1 << 28;
const EDSCR_MA: u32 = 1 << 20;
const EDECR_SS: u32 = 1 << 2;
const EDESR_SS: u8 = 1 << 2;
const MDSCR_SS: u64 = 1;
const EDPRSR_HALTED: u32 = 1 << 4;
const ID_FIELD_MASK: u64 = 0xf;
const PFR0_SEL2_SHIFT: u32 = 36;
const PFR0_RME_SHIFT: u32 = 52;
const ARBITRARY_DEBUG_REGISTER_ZERO: u64 = 0;
const DEBUG_VERSION_V8: u64 = 6;
const DEBUG_VERSION_V8P9: u64 = 11;

/// Named source STATUS values only; reserved encodings cannot enter the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Status {
    Restarting = 0b000001,
    NonDebug = 0b000010,
    Breakpoint = 0b000111,
    ExternalRequest = 0b010011,
    StepNormal = 0b011011,
    StepExclusive = 0b011111,
    OsUnlockCatch = 0b100011,
    ResetCatch = 0b100111,
    Watchpoint = 0b101011,
    HaltInstruction = 0b101111,
    SoftwareAccess = 0b110011,
    ExceptionCatch = 0b110111,
    StepNoSyndrome = 0b111011,
}
impl Status {
    fn from_raw(raw: u32) -> Result<Self, LifecycleError> {
        Ok(match raw {
            1 => Self::Restarting,
            2 => Self::NonDebug,
            7 => Self::Breakpoint,
            19 => Self::ExternalRequest,
            27 => Self::StepNormal,
            31 => Self::StepExclusive,
            35 => Self::OsUnlockCatch,
            39 => Self::ResetCatch,
            43 => Self::Watchpoint,
            47 => Self::HaltInstruction,
            51 => Self::SoftwareAccess,
            55 => Self::ExceptionCatch,
            59 => Self::StepNoSyndrome,
            _ => return Err(LifecycleError::ReservedStatus(raw)),
        })
    }
    pub fn halted(self) -> bool {
        !matches!(self, Self::Restarting | Self::NonDebug)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleError {
    Identification(IdentificationUnsupported),
    ExternalHardwareInitialization,
    ReservedStatus(u32),
    DebugVersion(u64),
    OptionalField {
        register: Register,
        name: &'static str,
        value: u64,
    },
    InitialStatus,
    InitialGate,
    SnapshotMismatch,
    SourceLevel,
    NotHalted,
    Busy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditrDisposition {
    Ignored,
    Overrun,
    Execute,
}

/// The external debug controls of this software PE, owned here with no public
/// setter.
#[derive(Debug)]
pub struct ExternalControls {
    pub powered: bool,
    pub double_locked: bool,
    pub software_locked: bool,
    pub nonsecure_invasive: bool,
    pub secure_invasive: bool,
}

/// EDHSR is declared by the implementation, not inferred absent; accepted only
/// for a new software PE.
#[derive(Debug)]
pub enum ExtendedHaltSyndrome {
    DeclaredAbsent,
}

/// Every initial value is explicit; no reset or Halt() effect is inferred.
/// ResetCatch is an initial status, not a captured reset.
pub struct Initialization {
    pub edscr: u32,
    pub edprsr: u32,
    pub dlr: u64,
    pub dspsr: u64,
    pub edesr: u8,
    pub edecr: u32,
    pub mdscr_el1: u64,
    pub should_advance_ss: bool,
    pub should_advance_hs: bool,
    pub external: ExternalControls,
    pub extended_halt_syndrome: ExtendedHaltSyndrome,
}

#[derive(Debug)]
struct DebugRegisters {
    edscr: u32,
    edprsr: u32,
    dlr: u64,
    dspsr: u64,
    edesr: u8,
    edecr: u32,
    mdscr_el1: u64,
}
/// Instruction fetch and injection state of the PE; the consumer checks it
/// before every entry.
#[derive(Debug)]
struct InstructionGate {
    itr_enabled: bool,
    prefetch_enabled: bool,
    outstanding: bool,
    should_advance_ss: bool,
    should_advance_hs: bool,
}

#[derive(Debug)]
pub(crate) struct DebugMachine {
    snapshot: Arc<Snapshot>,
    registers: DebugRegisters,
    external: ExternalControls,
    gate: InstructionGate,
    extended_halt_syndrome: ExtendedHaltSyndrome,
}

impl DebugMachine {
    pub(crate) fn fresh_declared(
        snapshot: Arc<Snapshot>,
        initial: Initialization,
    ) -> Result<Self, LifecycleError> {
        if snapshot.provenance().origin() != Origin::DeclaredGuest {
            return Err(LifecycleError::ExternalHardwareInitialization);
        }
        snapshot
            .check_base_optional_entry_effects()
            .map_err(LifecycleError::Identification)?;
        let pfr0 = snapshot
            .read(Register::IdAa64Pfr0El1)
            .map_err(LifecycleError::Identification)?;
        for (name, shift) in [("SEL2", PFR0_SEL2_SHIFT), ("RME", PFR0_RME_SHIFT)] {
            let value = (pfr0 >> shift) & ID_FIELD_MASK;
            if value != 0 {
                return Err(LifecycleError::OptionalField {
                    register: Register::IdAa64Pfr0El1,
                    name,
                    value,
                });
            }
        }
        let version = snapshot
            .read(Register::IdAa64Dfr0El1)
            .map_err(LifecycleError::Identification)?
            & ID_FIELD_MASK;
        if !(DEBUG_VERSION_V8..=DEBUG_VERSION_V8P9).contains(&version) {
            return Err(LifecycleError::DebugVersion(version));
        }
        let status = Status::from_raw(initial.edscr & STATUS_MASK)?;
        if status == Status::Restarting || status.halted() != (initial.edprsr & EDPRSR_HALTED != 0)
        {
            return Err(LifecycleError::InitialStatus);
        }
        // A new resource has no outstanding instruction, so if it starts
        // halted, ITE must allow the first injection.
        if status.halted() && initial.edscr & EDSCR_ITE == 0 {
            return Err(LifecycleError::InitialGate);
        }
        Ok(Self {
            snapshot,
            registers: DebugRegisters {
                edscr: initial.edscr,
                edprsr: initial.edprsr,
                dlr: initial.dlr,
                dspsr: initial.dspsr,
                edesr: initial.edesr,
                edecr: initial.edecr,
                mdscr_el1: initial.mdscr_el1,
            },
            external: initial.external,
            extended_halt_syndrome: initial.extended_halt_syndrome,
            gate: InstructionGate {
                itr_enabled: status.halted(),
                prefetch_enabled: !status.halted(),
                outstanding: false,
                should_advance_ss: initial.should_advance_ss,
                should_advance_hs: initial.should_advance_hs,
            },
        })
    }
    pub(crate) fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub(crate) fn status(&self) -> Status {
        Status::from_raw(self.registers.edscr & STATUS_MASK)
            .expect("only checked named STATUS writes")
    }
    pub(crate) fn qualify_initial(&self, system: &SystemState) -> Result<(), LifecycleError> {
        if let Some(higher) = system.higher_el() {
            if !higher.same_snapshot(&self.snapshot) {
                return Err(LifecycleError::SnapshotMismatch);
            }
        } else {
            self.snapshot
                .check_el10_regime()
                .map_err(LifecycleError::Identification)?;
        }
        if self.gate.outstanding
            || self.gate.itr_enabled != self.status().halted()
            || self.gate.prefetch_enabled == self.status().halted()
        {
            return Err(LifecycleError::InitialGate);
        }
        if !matches!(
            system.current_el(),
            ExceptionLevel::El0 | ExceptionLevel::El1
        ) {
            return Err(LifecycleError::SourceLevel);
        }
        Ok(())
    }
    pub(crate) fn qualify_normal_entry(&self) -> Result<(), LifecycleError> {
        if !self.external.powered
            || self.status() != Status::NonDebug
            || self.gate.outstanding
            || self.gate.itr_enabled
            || !self.gate.prefetch_enabled
        {
            return Err(LifecycleError::InitialGate);
        }
        Ok(())
    }
    pub(crate) fn qualify_halted_boundary(&self) -> Result<(), LifecycleError> {
        if !self.external.powered
            || !self.status().halted()
            || self.gate.outstanding
            || !self.gate.itr_enabled
            || self.gate.prefetch_enabled
        {
            return Err(LifecycleError::InitialGate);
        }
        Ok(())
    }
    /// Raw EDITR write priority. No instruction decoding occurs before this.
    pub(crate) fn editr_disposition(&self) -> EditrDisposition {
        if self.registers.edscr & EDSCR_ERR != 0 || !self.status().halted() {
            EditrDisposition::Ignored
        } else if self.registers.edscr & EDSCR_ITE == 0 || self.registers.edscr & EDSCR_MA != 0 {
            EditrDisposition::Overrun
        } else {
            EditrDisposition::Execute
        }
    }
    pub(crate) fn external_access(&self) -> bool {
        self.external.powered && !self.external.double_locked && !self.external.software_locked
    }
    pub(crate) fn halting_allowed(&self, security: SecurityState) -> bool {
        if self.status().halted() || self.external.double_locked {
            return false;
        }
        match security {
            SecurityState::NonSecure => self.external.nonsecure_invasive,
            SecurityState::Secure => self.external.secure_invasive,
            SecurityState::Realm => false,
        }
    }
    pub(crate) fn secure_invasive(&self) -> bool {
        self.external.secure_invasive
    }
    pub(crate) fn nonsecure_invasive(&self) -> bool {
        self.external.nonsecure_invasive
    }
    pub(crate) fn double_locked(&self) -> bool {
        self.external.double_locked
    }
    pub(crate) fn qualifier_step_disabled(&self) -> bool {
        const MDSCR_ACTIVE_DEBUG_MASK: u64 = 1 | (1 << 13) | (1 << 15);
        self.registers.mdscr_el1 & MDSCR_ACTIVE_DEBUG_MASK == 0
            && self.registers.edecr & EDECR_SS == 0
    }

    /// Facts derived once from the snapshot, plus the declared EDHSR absence.
    pub(crate) fn halting_features(&self) -> super::halting::Features {
        let edhsr = match self.extended_halt_syndrome {
            ExtendedHaltSyndrome::DeclaredAbsent => false,
        };
        super::halting::Features {
            pan: false,
            uao: false,
            mte: false,
            bti: false,
            pauth_lr: false,
            gcs: false,
            uinj: false,
            brbe: false,
            edhsr,
            rme: false,
        }
    }

    /// Actual source instruction bookkeeping, in source order. No separate step
    /// bank is synthesized by HVC/SMC selectors; GetPSR is read afterwards.
    pub(crate) fn hs_advance(&mut self, security: SecurityState) {
        if !self.gate.should_advance_hs {
            return;
        }
        let enabled = self.registers.edecr & EDECR_SS != 0 && self.halting_allowed(security);
        if enabled && self.registers.edesr & EDESR_SS == 0 {
            self.registers.edesr |= EDESR_SS;
        }
        self.gate.should_advance_hs = false;
    }
    pub(crate) fn ss_advance(
        &mut self,
        system: &mut SystemState,
        registers: &mut GuestState,
    ) -> Result<(), StateError> {
        if !self.gate.should_advance_ss {
            return Ok(());
        }
        let previous = system.pstate(registers);
        if self.registers.mdscr_el1 & MDSCR_SS != 0 && previous & PSTATE_SS_MASK != 0 {
            // Every EL is AArch64 in this profile, so the debug target cannot
            // be A32.
            system.transition_pstate(registers, previous & !PSTATE_SS_MASK)?;
        }
        self.gate.should_advance_ss = false;
        Ok(())
    }

    pub(crate) fn edscr(&self) -> u32 {
        self.registers.edscr
    }
    pub(crate) fn dlr(&self) -> u64 {
        self.registers.dlr
    }
    pub(crate) fn dspsr(&self) -> u64 {
        self.registers.dspsr
    }
    pub(crate) fn mdscr(&self) -> u64 {
        self.registers.mdscr_el1
    }

    /// State changes made only by the consumer.
    pub(crate) fn save_halt_state(&mut self, restart: u64, saved_psr: u64) {
        self.registers.dlr = restart;
        self.registers.dspsr = saved_psr;
    }
    pub(crate) fn write_edscr_fields(&mut self, value: u32) {
        // STATUS publication stays separate and atomic with EDPRSR.HALTED.
        self.registers.edscr = (value & !STATUS_MASK) | (self.registers.edscr & STATUS_MASK);
    }
    pub(crate) fn stop_prefetch_enable_itr(&mut self) {
        self.gate.prefetch_enabled = false;
        self.gate.itr_enabled = true;
    }
    pub(crate) fn publish_halt_instruction(&mut self) -> Result<(), LifecycleError> {
        if self.gate.prefetch_enabled || !self.gate.itr_enabled || self.gate.outstanding {
            return Err(LifecycleError::InitialGate);
        }
        self.registers.edscr =
            (self.registers.edscr & !STATUS_MASK) | Status::HaltInstruction as u32;
        self.registers.edprsr |= EDPRSR_HALTED;
        Ok(())
    }
    pub(crate) fn write_debug_arbitrary(&mut self) {
        self.registers.dlr = ARBITRARY_DEBUG_REGISTER_ZERO;
        self.registers.dspsr = ARBITRARY_DEBUG_REGISTER_ZERO;
    }
    pub(crate) fn begin_itr(&mut self) -> Result<(), LifecycleError> {
        if !self.status().halted() {
            return Err(LifecycleError::NotHalted);
        }
        if !self.gate.itr_enabled
            || self.gate.prefetch_enabled
            || self.gate.outstanding
            || self.registers.edscr & (EDSCR_ERR | EDSCR_MA) != 0
            || self.registers.edscr & EDSCR_ITE == 0
        {
            return Err(LifecycleError::Busy);
        }
        self.registers.edscr &= !EDSCR_ITE;
        self.gate.outstanding = true;
        Ok(())
    }
    pub(crate) fn complete_itr(&mut self) -> Result<(), LifecycleError> {
        if !self.status().halted()
            || !self.gate.outstanding
            || !self.gate.itr_enabled
            || self.gate.prefetch_enabled
        {
            return Err(LifecycleError::InitialGate);
        }
        self.registers.edscr |= EDSCR_ITE;
        self.gate.outstanding = false;
        Ok(())
    }
    pub(crate) fn set_overrun(&mut self) {
        self.registers.edscr |= EDSCR_ERR | EDSCR_ITO;
    }
    pub(crate) fn clear_should_advance_ss(&mut self) {
        self.gate.should_advance_ss = false;
    }
}

#[cfg(test)]
mod tests;
