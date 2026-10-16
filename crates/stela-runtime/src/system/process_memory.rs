//! Fixed partial authority for checked EL0 GPR process-memory entry.
//!
//! This is the actual immutable declaration for a fresh software machine, not
//! a snapshot that freezes another control owner. Dynamic EL/PSTATE/TCO remain
//! solely in SystemState. MTE-present machines require a separate checked scope.

use super::{
    access::ExceptionLevel,
    events::EventEndpoint,
    execution::EntryBoundary,
    identification::Register,
    identification_snapshot::{Snapshot, Unsupported as IdentificationUnsupported},
    profile::BaseSpeAbsence,
    pstate::{DAIF_MASK, NZCV_MASK},
    state::{PSTATE_EL0T, PSTATE_IL_MASK, PSTATE_MODE_MASK, SystemState},
};
use crate::memory::{
    domain::{DataPolicy, MemoryExecutionLoan, MemoryThread},
    policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
};
use alloc::sync::Arc;
use stela_compiler::{
    GuestState,
    block::ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID,
    context::memory::{
        MemoryContextView, MemoryRequirements, MemoryStatus, flags, profile_requirements,
    },
};

pub mod extended_controls;
#[path = "process_memory/pointer.rs"]
mod pointer;
#[path = "process_memory/pointer_checks.rs"]
mod pointer_checks;
#[path = "process_memory/source.rs"]
mod source;
pub(crate) use pointer::PointerMemoryAuthorization;
pub use pointer_checks::Error as PointerChecksError;
pub(crate) use pointer_checks::ResolvedPointerChecks;
pub use source::SourceNormalWbDomain;
#[path = "process_memory/low128.rs"]
mod low128;
pub(crate) use low128::Low128ProcessMemoryAuthorization;
pub use low128::PreparedLow128ProcessMemory;
#[path = "process_memory/scalable.rs"]
mod scalable;
pub use scalable::ScalableExecutionError;

pub(crate) const SCTLR_ENIA: u64 = 1 << 31;
pub(crate) const SCTLR_ENIB: u64 = 1 << 30;
pub(crate) const SCTLR_ENDA: u64 = 1 << 27;
pub(crate) const SCTLR_ENDB: u64 = 1 << 13;
const SCTLR_MMU_ENABLE: u64 = 1;
const SCTLR_DATA_CACHE_ENABLE: u64 = 1 << 2;
const SCTLR_NATIVE_NORMAL_WB: u64 = SCTLR_MMU_ENABLE | SCTLR_DATA_CACHE_ENABLE;
const TCR_LOWER_SIZE_MASK: u64 = 0x3f;
const TCR_LOWER_SIZE_MIN: u64 = 16;
const TCR_LOWER_SIZE_MAX: u64 = 39;
const TCR_LOWER_WALK_DISABLED: u64 = 1 << 7;
const TCR_LOWER_GRANULE_MASK: u64 = 3 << 14;
const TCR_LOWER_EL0_WALK_DISABLED: u64 = 1 << 55;
const TCR_EXTENDED_SIZE: u64 = 1 << 59;
const TCR_BASE_TRANSLATION_UNSUPPORTED: u64 = TCR_LOWER_WALK_DISABLED
    | TCR_LOWER_GRANULE_MASK
    | TCR_LOWER_EL0_WALK_DISABLED
    | TCR_EXTENDED_SIZE;
const ID_FIELD_MASK: u64 = 0xf;
const MMFR0_TGRAN4_SHIFT: u32 = 28;
const TGRAN4_SUPPORTED: u64 = 0;
const TGRAN4_LPA2: u64 = 1;
const MMFR2_AT_SHIFT: u32 = 32;
const MMFR2_AT_LSE2: u64 = 1;
const ISAR3_CPA_MASK: u64 = ID_FIELD_MASK;
const PFR1_MTE_SHIFT: u32 = 8;
const FEATURE_ABSENT: u64 = 0;
const SCTLR_ALIGNMENT_CHECK: u64 = 1 << 1;
const SCTLR_SP_ALIGNMENT_EL0: u64 = 1 << 4;
const SCTLR_BIG_ENDIAN_EL0: u64 = 1 << 24;
const SCTLR_TAG_FAULT_EL0: u64 = 3 << 38;
const SCTLR_ALLOCATION_TAG_ACCESS_EL0: u64 = 1 << 42;
const SCTLR_UNSUPPORTED: u64 = SCTLR_ALIGNMENT_CHECK
    | SCTLR_BIG_ENDIAN_EL0
    | SCTLR_TAG_FAULT_EL0
    | SCTLR_ALLOCATION_TAG_ACCESS_EL0;
const TCR_TOP_BYTE_IGNORE_LOWER: u64 = 1 << 37;
const TCR_TAG_CHECK_MASK_LOWER: u64 = 1 << 57;
const TCR_EXTENDED_TAG_LOWER: u64 = 1 << 60;
const TCR_UNSUPPORTED: u64 = TCR_TAG_CHECK_MASK_LOWER | TCR_EXTENDED_TAG_LOWER;
const SOURCE_PSTATE_MASK: u64 = NZCV_MASK | DAIF_MASK | PSTATE_MODE_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessMemoryError {
    Identification(IdentificationUnsupported),
    UnsupportedFeature {
        register: &'static str,
        field: &'static str,
        value: u64,
    },
    UnsupportedControl {
        register: &'static str,
        value: u64,
    },
    LowerAddress(MemoryStatus),
    UnsupportedMode(u64),
    IllegalExecutionState,
    UnsupportedPstate(u64),
    MteState,
    WrongAddressSpace,
    WrongMemoryDomain,
    MissingEventEndpoint,
    Memory(MemoryStatus),
    Low128(super::fp_access::Error),
    PointerChecks(PointerChecksError),
}

/// Checked facts for this bounded data contract, not a complete CPU inventory.
/// The shared BaseSpeAbsence is also required because base branch helpers can
/// change profiling history even with profiling disabled. No Default, hardware
/// detection or unknown-value fallback exists.
#[derive(Debug)]
pub struct ProcessMemoryFeatures {
    _base_spe_absence: BaseSpeAbsence,
    cpa: pointer_checks::CpaFeature,
}

impl ProcessMemoryFeatures {
    /// Derive only this bounded memory feature seal from the same named source.
    /// Missing IDs remain unsupported; no exception-feature absence is inferred.
    pub fn from_snapshot(identification: &Snapshot) -> Result<Self, ProcessMemoryError> {
        let read = |register| {
            identification
                .read(register)
                .map_err(ProcessMemoryError::Identification)
        };
        Self::from_id_registers(
            read(Register::IdAa64Mmfr0El1)?,
            read(Register::IdAa64Mmfr2El1)?,
            read(Register::IdAa64Isar3El1)?,
            read(Register::IdAa64Pfr1El1)?,
            identification
                .base_spe_absence()
                .map_err(ProcessMemoryError::Identification)?,
        )
    }

    pub fn from_id_registers(
        id_aa64mmfr0_el1: u64,
        id_aa64mmfr2_el1: u64,
        id_aa64isar3_el1: u64,
        id_aa64pfr1_el1: u64,
        base_spe_absence: BaseSpeAbsence,
    ) -> Result<Self, ProcessMemoryError> {
        let cpa = pointer_checks::CpaFeature::from_raw(id_aa64isar3_el1)
            .map_err(ProcessMemoryError::PointerChecks)?;
        if cpa == pointer_checks::CpaFeature::Checked {
            return Err(ProcessMemoryError::UnsupportedFeature {
                register: "ID_AA64ISAR3_EL1",
                field: "CPA",
                value: id_aa64isar3_el1 & ISAR3_CPA_MASK,
            });
        }
        Self::from_qualified_ids(
            id_aa64mmfr0_el1,
            id_aa64mmfr2_el1,
            id_aa64pfr1_el1,
            base_spe_absence,
            cpa,
        )
    }

    fn from_qualified_ids(
        id_aa64mmfr0_el1: u64,
        id_aa64mmfr2_el1: u64,
        id_aa64pfr1_el1: u64,
        base_spe_absence: BaseSpeAbsence,
        cpa: pointer_checks::CpaFeature,
    ) -> Result<Self, ProcessMemoryError> {
        let granule = (id_aa64mmfr0_el1 >> MMFR0_TGRAN4_SHIFT) & ID_FIELD_MASK;
        if !matches!(granule, TGRAN4_SUPPORTED | TGRAN4_LPA2) {
            return Err(ProcessMemoryError::UnsupportedFeature {
                register: "ID_AA64MMFR0_EL1",
                field: "TGran4",
                value: granule,
            });
        }
        for (register, field, value, expected) in [
            (
                "ID_AA64MMFR2_EL1",
                "AT",
                (id_aa64mmfr2_el1 >> MMFR2_AT_SHIFT) & ID_FIELD_MASK,
                MMFR2_AT_LSE2,
            ),
            (
                "ID_AA64PFR1_EL1",
                "MTE",
                (id_aa64pfr1_el1 >> PFR1_MTE_SHIFT) & ID_FIELD_MASK,
                FEATURE_ABSENT,
            ),
        ] {
            if value != expected {
                return Err(ProcessMemoryError::UnsupportedFeature {
                    register,
                    field,
                    value,
                });
            }
        }
        Ok(Self {
            _base_spe_absence: base_spe_absence,
            cpa,
        })
    }
}

/// Sole immutable owner of these supplied controls in the fresh process scope.
/// The raw controls must select M=1/C=1 and the declared lower namespace must
/// match T0SZ in the bounded 4-KiB/DS=0 translation scope. The retained source
/// witness binds the exact domain and published generation; neither host storage nor M/C alone
/// establish effective ARM attributes. This does not implement a page-table walk.
#[derive(Debug)]
pub struct FixedProcessMemoryControls {
    features: ProcessMemoryFeatures,
    identification: Option<Arc<Snapshot>>,
    sctlr_el1: u64,
    tcr_el1: u64,
    lower_address: LowerAddressProfile,
    source: SourceNormalWbDomain,
    extended: Option<extended_controls::ExtendedControlBank>,
}

impl FixedProcessMemoryControls {
    pub fn new(
        features: ProcessMemoryFeatures,
        sctlr_el1: u64,
        tcr_el1: u64,
        lower_address_bits: u8,
        source: SourceNormalWbDomain,
    ) -> Result<Self, ProcessMemoryError> {
        if sctlr_el1 & SCTLR_NATIVE_NORMAL_WB != SCTLR_NATIVE_NORMAL_WB
            || sctlr_el1 & SCTLR_UNSUPPORTED != 0
        {
            return Err(ProcessMemoryError::UnsupportedControl {
                register: "SCTLR_EL1",
                value: sctlr_el1,
            });
        }
        if tcr_el1 & (TCR_UNSUPPORTED | TCR_BASE_TRANSLATION_UNSUPPORTED) != 0 {
            return Err(ProcessMemoryError::UnsupportedControl {
                register: "TCR_EL1",
                value: tcr_el1,
            });
        }
        let lower_address =
            LowerAddressProfile::new(lower_address_bits, tcr_el1 & TCR_TOP_BYTE_IGNORE_LOWER != 0)
                .map_err(ProcessMemoryError::LowerAddress)?;
        let size = tcr_el1 & TCR_LOWER_SIZE_MASK;
        let declared_size = u64::from(u64::BITS) - u64::from(lower_address_bits);
        if size != declared_size || !(TCR_LOWER_SIZE_MIN..=TCR_LOWER_SIZE_MAX).contains(&size) {
            return Err(ProcessMemoryError::UnsupportedControl {
                register: "TCR_EL1",
                value: tcr_el1,
            });
        }
        Ok(Self {
            features,
            identification: None,
            sctlr_el1,
            tcr_el1,
            lower_address,
            source,
            extended: None,
        })
    }

    /// Construct a fresh scope whose memory features and EL10 regime are
    /// derived from this exact retained identification allocation. Dynamic
    /// CurrentEL/PSTATE and scalable access controls remain separate owners.
    /// This does not qualify PFAR or any other exception-entry optional effect.
    pub fn new_with_identification(
        identification: Arc<Snapshot>,
        sctlr_el1: u64,
        tcr_el1: u64,
        lower_address_bits: u8,
        source: SourceNormalWbDomain,
    ) -> Result<Self, ProcessMemoryError> {
        identification
            .check_el10_regime()
            .map_err(ProcessMemoryError::Identification)?;
        let features = ProcessMemoryFeatures::from_snapshot(&identification)?;
        let mut controls = Self::new(features, sctlr_el1, tcr_el1, lower_address_bits, source)?;
        controls.identification = Some(identification);
        Ok(controls)
    }

    // Only the same-bank extended-control factory may construct CPA2 data
    // authority. Generic/raw-ID constructors continue to reject that feature.
    fn new_with_pointer_identification(
        identification: Arc<Snapshot>,
        sctlr_el1: u64,
        tcr_el1: u64,
        lower_address_bits: u8,
        source: SourceNormalWbDomain,
    ) -> Result<Self, ProcessMemoryError> {
        identification
            .check_el10_regime()
            .map_err(ProcessMemoryError::Identification)?;
        let read = |register| {
            identification
                .read(register)
                .map_err(ProcessMemoryError::Identification)
        };
        let cpa = pointer_checks::CpaFeature::from_snapshot(&identification)
            .map_err(ProcessMemoryError::PointerChecks)?;
        let features = ProcessMemoryFeatures::from_qualified_ids(
            read(Register::IdAa64Mmfr0El1)?,
            read(Register::IdAa64Mmfr2El1)?,
            read(Register::IdAa64Pfr1El1)?,
            identification
                .base_spe_absence()
                .map_err(ProcessMemoryError::Identification)?,
            cpa,
        )?;
        let mut controls = Self::new(features, sctlr_el1, tcr_el1, lower_address_bits, source)?;
        controls.identification = Some(identification);
        Ok(controls)
    }

    /// The same immutable source used at construction, if this scope has one.
    /// Legacy raw-ID construction intentionally supplies no scalable authority.
    pub(crate) fn identification_snapshot_owner(&self) -> Option<&Arc<Snapshot>> {
        self.identification.as_ref()
    }

    pub fn identification_snapshot(&self) -> Option<&Snapshot> {
        self.identification.as_deref()
    }

    pub const fn sctlr_el1(&self) -> u64 {
        self.sctlr_el1
    }

    pub const fn tcr_el1(&self) -> u64 {
        self.tcr_el1
    }

    /// Install a freshly source-resolved witness after a successful mapping
    /// transaction, preserving this actual domain and all fixed controls.
    /// The source owner must resolve the entire resulting mapping set before
    /// minting `fresh`; there is no raw epoch or automatic refresh entry point.
    /// Failed transactions or incompatible effective controls require their
    /// actual owner path, not renewal through this method.
    pub fn renew_source_resolved(
        &mut self,
        fresh: SourceNormalWbDomain,
    ) -> Result<(), ProcessMemoryError> {
        if !self.source.same_domain(&fresh) {
            return Err(ProcessMemoryError::WrongMemoryDomain);
        }
        if !fresh.is_current().map_err(ProcessMemoryError::Memory)? {
            return Err(ProcessMemoryError::WrongMemoryDomain);
        }
        self.source = fresh;
        Ok(())
    }

    /// Existing entry validation separately binds exact source, execution/debug
    /// state and compiler-derived requirements. This does not prewalk accesses.
    /// The backend supplies its live endpoint; an ASID is not PE identity.
    pub fn prepare<'run>(
        &'run self,
        boundary: &EntryBoundary,
        requirements: MemoryRequirements,
        system: &'run SystemState,
        registers: &GuestState,
        thread: &'run mut MemoryThread<MemoryControls>,
        endpoint: Option<&'run EventEndpoint>,
    ) -> Result<PreparedProcessMemory<'run>, ProcessMemoryError> {
        let execution_loan = self.acquire_source_loan(boundary, system, registers, thread)?;
        if self.features.cpa == pointer_checks::CpaFeature::Checked {
            return Err(ProcessMemoryError::PointerChecks(
                PointerChecksError::UnsupportedProfile,
            ));
        }

        // ASIMD/structure/scalable and the other typed memory categories require
        // their own reviewed CPU contracts. Exclusive is not an Atomic alias.
        let unsupported_classes =
            flags::ATOMIC | flags::ORDERED | flags::ASIMD | flags::SME | flags::SVE_PREDICATED;
        if requirements.required_flags & unsupported_classes != 0 {
            return Err(ProcessMemoryError::Memory(MemoryStatus::Unsupported));
        }
        self.finish_prepare(requirements, system, thread, endpoint, execution_loan)
    }

    fn acquire_source_loan(
        &self,
        boundary: &EntryBoundary,
        system: &SystemState,
        registers: &GuestState,
        thread: &MemoryThread<MemoryControls>,
    ) -> Result<MemoryExecutionLoan, ProcessMemoryError> {
        self.validate_source_state(system, registers)?;
        // Capture the actual provider loan before validating source generation.
        // It owns the same domain Arc without borrowing/extracting the policy;
        // failed preparation releases it through Drop before returning.
        let execution_loan = thread
            .execution_loan()
            .map_err(ProcessMemoryError::Memory)?;
        if !self.source.matches(thread) {
            return Err(ProcessMemoryError::WrongMemoryDomain);
        }
        if thread.address_space() != Some(boundary.address_space()) {
            return Err(ProcessMemoryError::WrongAddressSpace);
        }
        Ok(execution_loan)
    }

    fn finish_prepare<'run>(
        &'run self,
        requirements: MemoryRequirements,
        system: &'run SystemState,
        thread: &'run mut MemoryThread<MemoryControls>,
        endpoint: Option<&'run EventEndpoint>,
        execution_loan: MemoryExecutionLoan,
    ) -> Result<PreparedProcessMemory<'run>, ProcessMemoryError> {
        thread
            .validate_execution(0)
            .map_err(ProcessMemoryError::Memory)?;
        let endpoint = if requires_event_endpoint(requirements) {
            let endpoint = endpoint.ok_or(ProcessMemoryError::MissingEventEndpoint)?;
            thread
                .check_event_endpoint(endpoint)
                .map_err(ProcessMemoryError::Memory)?;
            Some(endpoint)
        } else {
            // A CLREX-only body has EXCLUSIVE, no NATIVE_ACCESS and no transfer.
            // It needs the existing reservation owner but no event attachment.
            None
        };
        let authority = if requirements.required_flags & flags::EXCLUSIVE != 0 {
            ProcessMemoryAuthorization::Exclusive(ExclusiveProcessMemoryAuthorization {
                system,
                controls: self,
            })
        } else {
            ProcessMemoryAuthorization::Ordinary {
                system,
                controls: self,
            }
        };
        // No policy installation occurs here. Dropping or forgetting an unused
        // token leaves the baseline category policy unchanged.
        Ok(PreparedProcessMemory {
            execution_loan,
            authority,
            thread,
            endpoint,
            requirements,
            pointer: None,
        })
    }

    fn validate_source_state(
        &self,
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<(), ProcessMemoryError> {
        let pstate = system.pstate(registers);
        if pstate & PSTATE_IL_MASK != 0 {
            return Err(ProcessMemoryError::IllegalExecutionState);
        }
        if system.current_el() != ExceptionLevel::El0 || pstate & PSTATE_MODE_MASK != PSTATE_EL0T {
            return Err(ProcessMemoryError::UnsupportedMode(
                pstate & PSTATE_MODE_MASK,
            ));
        }
        let mut source_mask = SOURCE_PSTATE_MASK;
        if system.pacm_state_feature() == crate::system::state::PacmStateFeature::Full {
            let identification =
                self.identification_snapshot()
                    .ok_or(ProcessMemoryError::UnsupportedPstate(
                        crate::system::state::PSTATE_PACM_MASK,
                    ))?;
            crate::pauth::features::LinkRegisterPauthCapability::from_profile(identification)
                .map_err(|_| {
                    ProcessMemoryError::UnsupportedPstate(crate::system::state::PSTATE_PACM_MASK)
                })?;
            source_mask |= crate::system::state::PSTATE_PACM_MASK;
        }
        let unsupported = pstate & !source_mask;
        if unsupported != 0 {
            return Err(ProcessMemoryError::UnsupportedPstate(unsupported));
        }
        if system.mte().is_some() || system.tag_check_override() {
            return Err(ProcessMemoryError::MteState);
        }
        Ok(())
    }

    fn memory_controls(&self, system: &SystemState) -> MemoryControls {
        MemoryControls::new(
            self.lower_address,
            system.current_el() == ExceptionLevel::El1,
            false, // The actual feature declaration requires MTE absent.
            system.tag_check_override(),
            TagCheckFaultMode::Ignore,
            false, // Constructor rejects TCMA0 in this MTE-absent scope.
        )
        .with_effective_sp_alignment(self.sctlr_el1 & SCTLR_SP_ALIGNMENT_EL0 != 0)
    }
}

const fn requires_event_endpoint(requirements: MemoryRequirements) -> bool {
    requirements.required_flags & flags::EXCLUSIVE != 0
        && requirements.required_profile & profile_requirements::NATIVE_ACCESS != 0
}

/// Checked CPU facts for the fixed EL0/LE/LSE2/A0/CPA-absent/MTE-absent
/// Normal-WB/SCA16 data contract. Source Normal-WB attributes come only from
/// the retained same-domain witness. Native backing, geometry and host capability
/// eligibility remain the existing domain/profile admission; this does not
/// infer source attributes from SCTLR or prewalk permissions.
/// Actual SA0/TBI and dynamic EL/PSTATE/TCO remain in these retained owners.
/// Only the private token may install a temporary typed policy from this proof.
pub(crate) struct ExclusiveProcessMemoryAuthorization<'run> {
    system: &'run SystemState,
    controls: &'run FixedProcessMemoryControls,
}

impl ExclusiveProcessMemoryAuthorization<'_> {
    /// Baseline exact control snapshot: this accessor does not enable a class.
    pub(crate) fn memory_controls(&self) -> MemoryControls {
        self.controls.memory_controls(self.system)
    }
}

enum ProcessMemoryAuthorization<'run> {
    Ordinary {
        system: &'run SystemState,
        controls: &'run FixedProcessMemoryControls,
    },
    Exclusive(ExclusiveProcessMemoryAuthorization<'run>),
}

impl ProcessMemoryAuthorization<'_> {
    fn temporary_policy(&self) -> MemoryControls {
        match self {
            Self::Ordinary { system, controls } => controls.memory_controls(system),
            Self::Exclusive(authority) => MemoryControls::for_exclusive_authority(authority),
        }
    }
}

/// One synchronous checked scope. No GuestState borrow, Clone, thread accessor,
/// policy accessor or caller-selected replacement escapes this token.
pub struct PreparedProcessMemory<'run> {
    execution_loan: MemoryExecutionLoan,
    authority: ProcessMemoryAuthorization<'run>,
    thread: &'run mut MemoryThread<MemoryControls>,
    endpoint: Option<&'run EventEndpoint>,
    requirements: MemoryRequirements,
    pointer: Option<PointerMemoryAuthorization<'run>>,
}

impl PreparedProcessMemory<'_> {
    pub const fn profile_id(&self) -> &'static str {
        if self.pointer.is_some() {
            stela_compiler::block::CHECKED_POINTER_PROCESS_MEMORY_PROFILE_ID
        } else {
            ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID
        }
    }

    /// Exact compiler requirements retained by the typed entry factory.
    pub(crate) const fn requirements(&self) -> MemoryRequirements {
        self.requirements
    }

    /// Install a temporary same-thread policy only for this checked invocation.
    /// All CPU owner borrows survive through the callback. Storage declines and
    /// Rust unwinding restore the previous policy before these borrows expire.
    ///
    /// # Safety
    /// The caller must bind this callback to the sole compiler-derived body and
    /// requirements admitted by the owned runtime. All MemoryThread::with_view
    /// contracts apply: no raw pointer escape, reentry, owner retirement, thread
    /// replacement, policy extraction or asynchronous use is permitted. Rust
    /// borrowing cannot prove the native/raw-pointer portion of this contract.
    pub(crate) unsafe fn with_view<R>(
        self,
        callback: impl FnOnce(&mut MemoryContextView) -> R,
    ) -> Result<R, MemoryStatus> {
        let policy = self.authority.temporary_policy();
        // SAFETY: this base route retains its original checked source/body contract.
        unsafe { self.with_policy(policy, callback) }
    }

    /// Shared invocation mechanics. Only the private typed factories supply a
    /// temporary policy; caller flags cannot select an operation scope.
    unsafe fn with_policy<R>(
        self,
        policy: MemoryControls,
        callback: impl FnOnce(&mut MemoryContextView) -> R,
    ) -> Result<R, MemoryStatus> {
        // This inner guard closes prepare->invoke, body and checked finalization.
        // The actual v2.5 invocation provider must additionally retain an outer
        // same-domain execution loan through once-only PC settlement, then drop
        // that outer guard before entering a Darwin mapping service transaction.
        let _execution_loan = self.execution_loan;
        let policy = if let Some(pointer) = &self.pointer {
            policy.with_pointer_authority(pointer)
        } else {
            policy
        };
        let loan = PolicyLoan::new(self.thread, policy);
        if let Some(endpoint) = self.endpoint {
            // Actual retained same-PE identity, rechecked immediately before
            // native entry; no bind/rebind can be performed by this path.
            loan.thread.check_event_endpoint(endpoint)?;
        }
        // prepare validates the storage/SP/host requirements; typed class
        // admission remains an explicit policy check before any callback.
        loan.thread
            .validate_execution(self.requirements.required_flags)?;
        let checked = loan.thread.prepare(self.requirements)?;
        // SAFETY: the owned runtime binds the exact checked native body and
        // retains its mapping/context plus all native storage contracts.
        unsafe { checked.with_checked_view(callback) }
    }
}

/// Internal same-policy-type loan. This swaps only effective policy, never the
/// actual thread, reservation, domain or PE binding. It exposes nothing publicly.
struct PolicyLoan<'run, P: DataPolicy> {
    thread: &'run mut MemoryThread<P>,
    previous: Option<P>,
}

impl<'run, P: DataPolicy> PolicyLoan<'run, P> {
    fn new(thread: &'run mut MemoryThread<P>, replacement: P) -> Self {
        let previous = core::mem::replace(thread.policy_mut(), replacement);
        Self {
            thread,
            previous: Some(previous),
        }
    }
}

impl<P: DataPolicy> Drop for PolicyLoan<'_, P> {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            let temporary = core::mem::replace(self.thread.policy_mut(), previous);
            // Restore first, even if a future policy's destructor can unwind.
            drop(temporary);
        }
    }
}

#[cfg(test)]
#[path = "process_memory/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "process_memory/identification_tests.rs"]
mod identification_tests;
