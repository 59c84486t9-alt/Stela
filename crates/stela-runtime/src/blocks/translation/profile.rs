//! Which source producers the control-transition entry accepts.

use crate::system::{
    access::ExceptionLevel,
    profile::{EntryProfile, SystemEntryFeature},
    state::{PSTATE_IL_MASK, PSTATE_SS_MASK, SystemState},
    translation::Register,
    translation_controls::{ControlSnapshot, PanFeatures, Presence},
};
use stela_compiler::{
    GuestAddress,
    aarch64::system::{
        registers::Encoding,
        synchronization::{self, Operation},
    },
    block::system::{SystemInstruction, decode_system_instruction},
};

pub(super) fn check_entry(state: &SystemState) -> Result<(), &'static str> {
    state
        .check_lower_el_storage()
        .map_err(|_| "installed lower-EL profile does not own higher-EL storage")?;
    if state.current_el() != ExceptionLevel::El1 {
        return Err("control-only execution requires EL1");
    }
    if state.pstate_misc() & (PSTATE_IL_MASK | PSTATE_SS_MASK) != 0 {
        return Err("illegal or software-step state requires its execution owner");
    }
    if state.mte().is_some() {
        return Err("control-only execution does not own MTE state");
    }
    Ok(())
}

pub(super) fn check_features(
    profile: EntryProfile,
    snapshot: &ControlSnapshot,
) -> Result<(), &'static str> {
    let features = profile.features();
    if features.contains(SystemEntryFeature::Brbe)
        || features.contains(SystemEntryFeature::Bti)
        || features.contains(SystemEntryFeature::SpeExc)
        || features.contains(SystemEntryFeature::TrbeExc)
    {
        return Err("instruction synchronization requires an unavailable observation owner");
    }
    // The consumed base EntryProfile admits no optional entry effects. Require
    // the authoritative control profile to describe those same relevant facts;
    // do not synthesize a second feature registry or ignore present consumers.
    let facts = snapshot.feature_facts();
    if facts.pan != PanFeatures::Absent
        || facts.ssbs != Presence::Absent
        || facts.exs != Presence::Absent
    {
        return Err("control and execution feature witnesses describe different profiles");
    }
    Ok(())
}

/// The compiler has no system-instruction block for the five-register/ISB
/// sequence, so it is refused before fetch.
pub(super) fn require_legacy_carrier() -> Result<(), &'static str> {
    Err("unsupported legacy five-register/ISB carrier in the current compiler")
}

/// Control operations recognized by the dispatcher.
pub(super) enum LegacyControlOperation {
    Read,
    Write,
    Isb,
}

pub(super) fn legacy_control_operation(word: u32) -> Option<LegacyControlOperation> {
    const MRS_BASE: u32 = 0xd520_0000;
    const MSR_BASE: u32 = 0xd500_0000;
    const ENCODING_SHIFT: u32 = 5;
    const RT_MASK: u32 = 31;
    let instruction = word & !RT_MASK;
    for (base, read) in [(MRS_BASE, true), (MSR_BASE, false)] {
        for register in [
            Register::SctlrEl1,
            Register::TcrEl1,
            Register::Ttbr0El1,
            Register::Ttbr1El1,
            Register::MairEl1,
        ] {
            let encoding: Encoding = register.encoding();
            if instruction == base | (u32::from(encoding.selector()) << ENCODING_SHIFT) {
                return Some(if read {
                    LegacyControlOperation::Read
                } else {
                    LegacyControlOperation::Write
                });
            }
        }
    }
    match synchronization::decode(word) {
        Some(Operation::InstructionSynchronization { .. }) => Some(LegacyControlOperation::Isb),
        _ => None,
    }
}

pub(super) fn check_instruction(pc: u64, word: u32) -> Result<SystemInstruction, &'static str> {
    legacy_control_operation(word)
        .ok_or("instruction has no producer in the control-only execution entry")?;
    // Only words the compiler can emit as a system exit get a descriptor.
    let instruction = decode_system_instruction(GuestAddress(pc), word)
        .map_err(|_| "control instruction PC or canonical descriptor is invalid")?
        .ok_or("unsupported legacy five-register/ISB carrier in the current compiler")?;
    require_legacy_carrier()?;
    Ok(instruction)
}

/// Shared unchanged immutable instruction-fetch attributes. Source-class
/// admission remains separate: legacy five controls/ISB versus exact M0 LDR64.
pub(super) fn check_immutable_fetch(
    translation: &crate::memory::stage1::Translation,
    raw_pc: u64,
    state: &SystemState,
) -> Result<(), &'static str> {
    use crate::memory::stage1;
    check_entry(state)?;
    let access = translation.access();
    if access.kind != stage1::AccessKind::Fetch
        || access.raw_virtual_address != raw_pc
        || access.exception_level != stage1::ExceptionLevel::El1
    {
        return Err("canonical result is not this EL1 instruction fetch");
    }
    let attributes = translation.attributes();
    match attributes.memory_type {
        stage1::MemoryType::NormalWriteBackReadWriteAllocate
            if !attributes.tagged && !attributes.guarded_page =>
        {
            Ok(())
        }
        stage1::MemoryType::NormalWriteThroughReadAllocate
        | stage1::MemoryType::NormalNonCacheable
            if attributes.origin == stage1::AttributeOrigin::MmuDisabled
                && attributes.mair.is_none()
                && translation.walk().is_none()
                && translation.permissions().is_none()
                && attributes.shareability == stage1::Shareability::Outer
                && !attributes.tagged
                && attributes.xs
                && !attributes.not_global
                && !attributes.guarded_page =>
        {
            Ok(())
        }
        _ => Err("instruction-fetch attributes are outside the immutable control-only policy"),
    }
}

/// The shared compiler's exact fixed-profile context terminal. Descriptor
/// equality is source validation, not CPU/resource/native admission.
pub(super) fn check_context_instruction(
    pc: u64,
    word: u32,
) -> Result<SystemInstruction, &'static str> {
    let instruction = decode_system_instruction(GuestAddress(pc), word)
        .map_err(|_| "context instruction PC or canonical descriptor is invalid")?
        .ok_or("source has no canonical context terminal")?;
    if !instruction.matches_source(GuestAddress(pc), word)
        || !instruction.is_el1_context_operation()
    {
        return Err("source is outside the exact canonical EL1 context profile");
    }
    Ok(instruction)
}
