//! The fixed controls of checked EL0 memory access.

use super::{
    access::ExceptionLevel,
    identification::Register,
    identification_snapshot::{Snapshot, Unsupported as IdentificationUnsupported},
    profile::BaseSpeAbsence,
    pstate::{DAIF_MASK, NZCV_MASK},
    state::{PSTATE_EL0T, PSTATE_IL_MASK, PSTATE_MODE_MASK, SystemState},
};
#[cfg(feature = "std")]
use super::{events::EventEndpoint, execution::EntryBoundary};
#[cfg(feature = "std")]
use crate::memory::domain::MemoryExecutionLoan;
use crate::memory::{
    domain::{DataPolicy, MemoryThread},
    policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
};
use alloc::sync::Arc;
use stela_compiler::{GuestState, context::memory::MemoryStatus};
#[cfg(feature = "std")]
use stela_compiler::{
    block::ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID,
    context::memory::{MemoryContextView, MemoryRequirements, flags, profile_requirements},
};

pub mod extended_controls;
mod pointer;
mod pointer_checks;
#[cfg(feature = "std")]
mod shared;
mod source;
#[cfg(feature = "std")]
pub(crate) use pointer::PointerMemoryAuthorization;
pub use pointer_checks::Error as PointerChecksError;
pub(crate) use pointer_checks::ResolvedPointerChecks;
#[cfg(feature = "std")]
pub(crate) use shared::SharedProcessMemoryAuthorization;
pub use source::SourceNormalWbDomain;
#[cfg(feature = "std")]
mod low128;
#[cfg(feature = "std")]
pub(crate) use low128::Low128ProcessMemoryAuthorization;
mod scalable;

#[cfg(feature = "std")]
pub(crate) const SCTLR_ENIA: u64 = 1 << 31;
#[cfg(feature = "std")]
pub(crate) const SCTLR_ENIB: u64 = 1 << 30;
#[cfg(feature = "std")]
pub(crate) const SCTLR_ENDA: u64 = 1 << 27;
#[cfg(feature = "std")]
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
    #[cfg(feature = "std")]
    Low128(super::fp_access::Error),
    PointerChecks(PointerChecksError),
}

/// The checked facts this memory contract needs. Base SPE absence is required
/// too, because base branch helpers can change profiling history even with
/// profiling disabled. There is no default or detection.
#[derive(Debug)]
pub struct ProcessMemoryFeatures {
    _base_spe_absence: BaseSpeAbsence,
    cpa: pointer_checks::CpaFeature,
}

impl ProcessMemoryFeatures {
    /// Only source CPA0/CPA1 facts resolve both AddressAdd levels without
    /// extended controls. CPA2 never inherits that unchecked specialization.
    pub(crate) fn unchecked_address_checks(
        &self,
    ) -> Option<stela_compiler::context::memory::address::EffectiveAddressChecks> {
        use stela_compiler::context::memory::address::{AddressAddChecks, EffectiveAddressChecks};
        match self.cpa {
            pointer_checks::CpaFeature::Absent | pointer_checks::CpaFeature::Arithmetic => Some(
                EffectiveAddressChecks::new(AddressAddChecks::Disabled, AddressAddChecks::Disabled),
            ),
            pointer_checks::CpaFeature::Checked => None,
        }
    }

    /// Derive these facts from the snapshot. Missing IDs are unsupported.
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

/// Owner of these controls in the process scope. The controls must set M and C,
/// and the lower namespace must match T0SZ with 4 KiB granules and DS = 0. The
/// source witness binds the domain and its published generation; M and C alone
/// do not establish the effective attributes. No page-table walk is
/// implemented.
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

    // Only the extended-control factory constructs FEAT_CPA2 data access; the
    // other constructors reject it.
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

    /// The source used at construction, if any; raw-ID construction supplies
    /// none.
    #[cfg(feature = "std")]
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

    /// Install a newly resolved source witness after a successful mapping
    /// transaction, keeping the domain and fixed controls. The source owner
    /// resolves the whole resulting mapping set first. Failed transactions or
    /// incompatible controls go through their own owner.
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

    #[cfg(feature = "std")]
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

        // AdvSIMD, structure, scalable and other typed memory categories need
        // their own CPU contracts. Exclusive is not a kind of Atomic.
        let unsupported_classes = flags::ASIMD | flags::SME | flags::SVE_PREDICATED;
        if requirements.required_flags & unsupported_classes != 0 {
            return Err(ProcessMemoryError::Memory(MemoryStatus::Unsupported));
        }
        self.finish_prepare(requirements, system, thread, endpoint, execution_loan)
    }

    #[cfg(feature = "std")]
    fn acquire_source_loan(
        &self,
        boundary: &EntryBoundary,
        system: &SystemState,
        registers: &GuestState,
        thread: &MemoryThread<MemoryControls>,
    ) -> Result<MemoryExecutionLoan, ProcessMemoryError> {
        self.validate_source_state(system, registers)?;
        // Take the provider borrow before validating the source generation. It
        // holds the domain Arc without touching the policy, and a failed
        // preparation releases it on drop.
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

    #[cfg(feature = "std")]
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
        let authority = if requirements.required_flags & (flags::ATOMIC | flags::ORDERED) != 0 {
            ProcessMemoryAuthorization::Shared(self.qualify_shared(requirements, system)?)
        } else if requirements.required_flags & flags::EXCLUSIVE != 0 {
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
        .with_unchecked_address_authority(&self.features)
    }
}

#[cfg(feature = "std")]
const fn requires_event_endpoint(requirements: MemoryRequirements) -> bool {
    requirements.required_flags & (flags::EXCLUSIVE | flags::ATOMIC | flags::ORDERED) != 0
        && requirements.required_profile & profile_requirements::NATIVE_ACCESS != 0
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
impl ExclusiveProcessMemoryAuthorization<'_> {
    /// Baseline exact control snapshot: this accessor does not enable a class.
    pub(crate) fn memory_controls(&self) -> MemoryControls {
        self.controls.memory_controls(self.system)
    }
}

#[cfg(feature = "std")]
enum ProcessMemoryAuthorization<'run> {
    Ordinary {
        system: &'run SystemState,
        controls: &'run FixedProcessMemoryControls,
    },
    Exclusive(ExclusiveProcessMemoryAuthorization<'run>),
    Shared(SharedProcessMemoryAuthorization<'run>),
}

#[cfg(feature = "std")]
impl ProcessMemoryAuthorization<'_> {
    fn temporary_policy(&self) -> MemoryControls {
        match self {
            Self::Ordinary { system, controls } => controls.memory_controls(system),
            Self::Exclusive(authority) => MemoryControls::for_exclusive_authority(authority),
            Self::Shared(authority) => MemoryControls::for_shared_authority(authority),
        }
    }
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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

    /// Install a temporary policy on this thread for one checked call. The CPU
    /// owner's borrows last through the callback, and storage refusals and
    /// unwinding restore the previous policy before they expire.
    ///
    /// # Safety
    /// The callback must run the compiler-derived body and requirements
    /// admitted by the runtime. `MemoryThread::with_view`'s contract applies:
    /// no raw pointer escape, re-entry, owner retirement, thread replacement,
    /// policy extraction or asynchronous use.
    pub(crate) unsafe fn with_view<R>(
        self,
        callback: impl FnOnce(&mut MemoryContextView) -> R,
    ) -> Result<R, MemoryStatus> {
        let policy = self.authority.temporary_policy();
        // SAFETY: this route keeps the checked source and body contract.
        unsafe { self.with_policy(policy, callback) }
    }

    /// Shared invocation mechanics. Only the private typed factories supply a
    /// temporary policy; caller flags cannot select an operation scope.
    unsafe fn with_policy<R>(
        self,
        policy: MemoryControls,
        callback: impl FnOnce(&mut MemoryContextView) -> R,
    ) -> Result<R, MemoryStatus> {
        // This guard covers preparation, the call, the body and finalization.
        // The invocation provider must also hold an outer domain borrow through
        // PC settlement, then drop it before any Darwin mapping service.
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
        // `prepare` validates storage, SP and host requirements; typed class
        // admission is a separate check before any callback.
        loan.thread
            .validate_execution(self.requirements.required_flags)?;
        let checked = loan.thread.prepare(self.requirements)?;
        // SAFETY: the runtime binds the checked native body and keeps its
        // mapping, context and storage contracts.
        unsafe { checked.with_checked_view(callback) }
    }
}

/// Swaps the effective policy only; the thread, reservation, domain and PE
/// binding stay the same.
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
mod tests {
    //! Checked process-memory controls.
    use super::*;
    use crate::memory::domain::{MemoryDomain, MemorySystem};
    use crate::system::state::El1Registers;
    use std::sync::Arc;
    use stela_compiler::{GuestAddress, TargetCpu};

    mod identification {
        //! Identification-dependent process-memory controls.
        use super::*;
        use crate::memory::domain::{MemoryDomain, MemorySystem};
        use stela_compiler::TargetCpu;

        const LOWER_ADDRESS_BITS: u8 = 39;
        const LOWER_SIZE: u64 = u64::BITS as u64 - LOWER_ADDRESS_BITS as u64;
        const EL10_IMPLEMENTED: u64 = 0x11;
        const FEATURE_PRESENT: u64 = 1;
        const CPA_WITH_CHECKING: u64 = 2;
        const EL2_FIELD_SHIFT: u32 = 8;
        const SPE_VERSION_SHIFT: u32 = 32;
        const TEST_ADDRESS_SPACE: u64 = 7;
        const ERG_BYTES: u64 = 16;
        const MONITOR_STRIPES: usize = 4;

        fn ids() -> [(Register, u64); 6] {
            [
                (Register::IdAa64Pfr0El1, EL10_IMPLEMENTED),
                (
                    Register::IdAa64Mmfr0El1,
                    TGRAN4_SUPPORTED << MMFR0_TGRAN4_SHIFT,
                ),
                (Register::IdAa64Mmfr2El1, MMFR2_AT_LSE2 << MMFR2_AT_SHIFT),
                (Register::IdAa64Isar3El1, FEATURE_ABSENT),
                (Register::IdAa64Pfr1El1, FEATURE_ABSENT),
                (Register::IdAa64Dfr0El1, FEATURE_ABSENT),
            ]
        }
        fn snapshot(entries: &[(Register, u64)]) -> Arc<Snapshot> {
            Arc::new(Snapshot::declared("fixed-process-snapshot-component", entries).unwrap())
        }
        fn domain() -> Arc<MemoryDomain> {
            MemoryDomain::new_for_address_space(
                TEST_ADDRESS_SPACE,
                MemorySystem::new(ERG_BYTES, MONITOR_STRIPES).unwrap(),
                Vec::new(),
                TargetCpu::Baseline,
            )
            .unwrap()
        }
        fn source(domain: &Arc<MemoryDomain>) -> SourceNormalWbDomain {
            // SAFETY: this fresh component has no mappings; it tests construction and
            // source identity only, and neither issues memory nor admits a native body.
            unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(domain)) }
                .expect("fresh empty test domain has current source authority")
        }

        #[test]
        fn retains_same_snapshot_and_keeps_legacy_constructor_unqualified() {
            let domain = domain();
            let identification = snapshot(&ids());
            let controls = FixedProcessMemoryControls::new_with_identification(
                Arc::clone(&identification),
                SCTLR_NATIVE_NORMAL_WB,
                LOWER_SIZE,
                LOWER_ADDRESS_BITS,
                source(&domain),
            )
            .unwrap();
            assert!(identification.same_snapshot(controls.identification_snapshot().unwrap()));
            let equal_values = snapshot(&ids());
            assert!(!equal_values.same_snapshot(controls.identification_snapshot().unwrap()));
            let legacy = FixedProcessMemoryControls::new(
                ProcessMemoryFeatures::from_snapshot(&identification).unwrap(),
                SCTLR_NATIVE_NORMAL_WB,
                LOWER_SIZE,
                LOWER_ADDRESS_BITS,
                source(&domain),
            )
            .unwrap();
            assert!(legacy.identification_snapshot().is_none());
        }

        #[test]
        fn every_required_named_id_must_be_supplied() {
            let domain = domain();
            let entries = ids();
            for missing in 0..entries.len() {
                let partial: Vec<_> = entries
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != missing)
                    .map(|(_, entry)| *entry)
                    .collect();
                let error = FixedProcessMemoryControls::new_with_identification(
                    snapshot(&partial),
                    SCTLR_NATIVE_NORMAL_WB,
                    LOWER_SIZE,
                    LOWER_ADDRESS_BITS,
                    source(&domain),
                )
                .unwrap_err();
                assert_eq!(
                    error,
                    ProcessMemoryError::Identification(IdentificationUnsupported::MissingRegister(
                        entries[missing].0
                    ))
                );
            }
        }

        #[test]
        fn same_source_feature_and_regime_failures_are_not_normalized() {
            let domain = domain();
            for (register, value) in [
                (
                    Register::IdAa64Pfr0El1,
                    EL10_IMPLEMENTED | FEATURE_PRESENT << EL2_FIELD_SHIFT,
                ),
                (
                    Register::IdAa64Mmfr0El1,
                    ID_FIELD_MASK << MMFR0_TGRAN4_SHIFT,
                ),
                (Register::IdAa64Mmfr2El1, FEATURE_ABSENT),
                (Register::IdAa64Isar3El1, CPA_WITH_CHECKING),
                (Register::IdAa64Pfr1El1, FEATURE_PRESENT << PFR1_MTE_SHIFT),
                (
                    Register::IdAa64Dfr0El1,
                    FEATURE_PRESENT << SPE_VERSION_SHIFT,
                ),
            ] {
                let mut entries = ids();
                entries
                    .iter_mut()
                    .find(|entry| entry.0 == register)
                    .unwrap()
                    .1 = value;
                assert!(
                    FixedProcessMemoryControls::new_with_identification(
                        snapshot(&entries),
                        SCTLR_NATIVE_NORMAL_WB,
                        LOWER_SIZE,
                        LOWER_ADDRESS_BITS,
                        source(&domain),
                    )
                    .is_err()
                );
            }
            let identification = snapshot(&ids());
            for (sctlr, tcr) in [
                (SCTLR_MMU_ENABLE, LOWER_SIZE),
                (SCTLR_NATIVE_NORMAL_WB, LOWER_SIZE + 1),
            ] {
                assert!(
                    FixedProcessMemoryControls::new_with_identification(
                        Arc::clone(&identification),
                        sctlr,
                        tcr,
                        LOWER_ADDRESS_BITS,
                        source(&domain),
                    )
                    .is_err()
                );
            }
        }

        #[test]
        fn arithmetic_only_cpa_preserves_unchecked_data_constructor_without_extended_bank() {
            let domain = domain();
            let mut entries = ids();
            entries
                .iter_mut()
                .find(|entry| entry.0 == Register::IdAa64Isar3El1)
                .unwrap()
                .1 = FEATURE_PRESENT;
            let identification = snapshot(&entries);
            let controls = FixedProcessMemoryControls::new_with_identification(
                Arc::clone(&identification),
                SCTLR_NATIVE_NORMAL_WB,
                LOWER_SIZE,
                LOWER_ADDRESS_BITS,
                source(&domain),
            )
            .unwrap();
            assert!(controls.extended.is_none());
            assert_eq!(
                controls.features.cpa,
                pointer_checks::CpaFeature::Arithmetic
            );
        }
    }

    const ADDRESS_SPACE: u64 = 7;
    const SOURCE_PC: GuestAddress = GuestAddress(0x1000);
    const SOURCE_WORD: u32 = 0xd503_3f5f;
    const LOWER_BITS: u8 = 39;
    const LOWER_SIZE: u64 = 64 - LOWER_BITS as u64;
    const ERG_BYTES: u64 = 16;
    const MONITOR_STRIPES: usize = 4;
    const UNKNOWN_PROFILE_REQUIREMENT: u32 = 1 << (u32::BITS - 1);

    fn features() -> ProcessMemoryFeatures {
        ProcessMemoryFeatures::from_id_registers(
            0,
            MMFR2_AT_LSE2 << MMFR2_AT_SHIFT,
            0,
            0,
            BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
        )
        .unwrap()
    }
    fn domain() -> Arc<MemoryDomain> {
        MemoryDomain::new_for_address_space(
            ADDRESS_SPACE,
            MemorySystem::new(ERG_BYTES, MONITOR_STRIPES).unwrap(),
            Vec::new(),
            TargetCpu::Baseline,
        )
        .unwrap()
    }
    fn source(domain: &Arc<MemoryDomain>) -> SourceNormalWbDomain {
        // SAFETY: the fixtures declare their source mappings Normal write-back with
        // matching rights, tag and shareability attributes, and offsets.
        unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(domain)) }.unwrap()
    }
    fn controls(domain: &Arc<MemoryDomain>) -> FixedProcessMemoryControls {
        FixedProcessMemoryControls::new(
            features(),
            SCTLR_NATIVE_NORMAL_WB,
            LOWER_SIZE,
            LOWER_BITS,
            source(domain),
        )
        .unwrap()
    }
    fn memory(domain: &Arc<MemoryDomain>) -> MemoryThread<MemoryControls> {
        domain.thread(MemoryControls::new(
            LowerAddressProfile::new(LOWER_BITS, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        ))
    }
    fn boundary() -> EntryBoundary {
        EntryBoundary::new(ADDRESS_SPACE, 1, SOURCE_PC, SOURCE_PC, 4, SOURCE_WORD)
    }
    fn state() -> SystemState {
        SystemState::new(PSTATE_EL0T, 0x3000, El1Registers::new(0, 0, 0, 0, 0)).unwrap()
    }
    fn requirements() -> MemoryRequirements {
        MemoryRequirements {
            required_flags: flags::EXCLUSIVE,
            ..MemoryRequirements::default()
        }
    }

    #[test]
    fn exact_control_and_geometry_inputs_are_required() {
        let domain = domain();
        for sctlr in [
            0,
            SCTLR_MMU_ENABLE,
            SCTLR_DATA_CACHE_ENABLE,
            SCTLR_NATIVE_NORMAL_WB | SCTLR_ALIGNMENT_CHECK,
            SCTLR_NATIVE_NORMAL_WB | SCTLR_BIG_ENDIAN_EL0,
        ] {
            assert!(
                FixedProcessMemoryControls::new(
                    features(),
                    sctlr,
                    LOWER_SIZE,
                    LOWER_BITS,
                    source(&domain)
                )
                .is_err()
            );
        }
        for bad in [
            TCR_LOWER_WALK_DISABLED,
            TCR_LOWER_EL0_WALK_DISABLED,
            TCR_EXTENDED_SIZE,
            1 << 14,
            1 << 15,
            TCR_EXTENDED_TAG_LOWER,
            TCR_TAG_CHECK_MASK_LOWER,
        ] {
            assert!(
                FixedProcessMemoryControls::new(
                    features(),
                    SCTLR_NATIVE_NORMAL_WB,
                    LOWER_SIZE | bad,
                    LOWER_BITS,
                    source(&domain)
                )
                .is_err()
            );
        }
        for (size, bits, accepted) in [
            (16, 48, true),
            (39, 25, true),
            (15, 49, false),
            (40, 24, false),
            (25, 48, false),
        ] {
            assert_eq!(
                FixedProcessMemoryControls::new(
                    features(),
                    SCTLR_NATIVE_NORMAL_WB,
                    size,
                    bits,
                    source(&domain)
                )
                .is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn granule_witness_accepts_only_known_supported_encodings() {
        for granule in 0..=ID_FIELD_MASK {
            assert_eq!(
                ProcessMemoryFeatures::from_id_registers(
                    granule << MMFR0_TGRAN4_SHIFT,
                    MMFR2_AT_LSE2 << MMFR2_AT_SHIFT,
                    0,
                    0,
                    BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap()
                )
                .is_ok(),
                granule <= 1
            );
        }
    }

    #[test]
    fn distinct_snapshot_with_same_asid_is_rejected_before_policy_installation() {
        let actual = domain();
        let other = domain();
        let controls = controls(&actual);
        let system = state();
        let registers = GuestState::default();
        let mut thread = memory(&other);
        let before = *thread.policy_mut();
        assert!(matches!(
            controls.prepare(
                &boundary(),
                requirements(),
                &system,
                &registers,
                &mut thread,
                None
            ),
            Err(ProcessMemoryError::WrongMemoryDomain)
        ));
        assert_eq!(*thread.policy_mut(), before);
        assert_eq!(
            thread.validate_execution(flags::EXCLUSIVE),
            Err(MemoryStatus::Unsupported)
        );
    }

    #[test]
    fn same_snapshot_arc_clone_matches_without_new_reservation_owner() {
        let actual = domain();
        let controls = controls(&Arc::clone(&actual));
        let mut thread = memory(&actual);
        let previous = *thread.policy_mut();
        let system = state();
        let mut registers = GuestState::default();
        let entry = controls
            .prepare(
                &boundary(),
                requirements(),
                &system,
                &registers,
                &mut thread,
                None,
            )
            .unwrap();
        registers.x[0] = 0x53c7;
        // SAFETY: synchronous component callback neither keeps raw pointers nor reenters.
        assert_eq!(
            unsafe { entry.with_view(|view| view.has_supported_header()) },
            Ok(true)
        );
        assert_eq!(registers.x[0], 0x53c7);
        assert_eq!(*thread.policy_mut(), previous);
    }

    #[test]
    // Intentionally exercise both ways an unused opaque token can end. Neither
    // may install the capability, even when no destructor runs.
    #[allow(clippy::forget_non_drop, clippy::drop_non_drop)]
    fn unused_and_forgotten_tokens_never_install_authorization() {
        let actual = domain();
        let controls = controls(&actual);
        let mut thread = memory(&actual);
        let previous = *thread.policy_mut();
        let system = state();
        let registers = GuestState::default();
        for forget in [false, true] {
            let entry = controls
                .prepare(
                    &boundary(),
                    requirements(),
                    &system,
                    &registers,
                    &mut thread,
                    None,
                )
                .unwrap();
            if forget {
                std::mem::forget(entry)
            } else {
                drop(entry)
            };
            assert_eq!(*thread.policy_mut(), previous);
            assert_eq!(
                thread.validate_execution(flags::EXCLUSIVE),
                Err(MemoryStatus::Unsupported)
            );
        }
    }

    #[test]
    fn callback_error_prepare_decline_and_unwind_restore_exact_baseline() {
        let actual = domain();
        let controls = controls(&actual);
        let mut thread = memory(&actual);
        let previous = *thread.policy_mut();
        let system = state();
        let registers = GuestState::default();
        let entry = controls
            .prepare(
                &boundary(),
                requirements(),
                &system,
                &registers,
                &mut thread,
                None,
            )
            .unwrap();
        assert_eq!(
            unsafe { entry.with_view(|_| Err::<(), _>("callback")) },
            Ok(Err("callback"))
        );
        assert_eq!(*thread.policy_mut(), previous);
        let mut unsupported = requirements();
        assert_eq!(UNKNOWN_PROFILE_REQUIREMENT & profile_requirements::KNOWN, 0);
        unsupported.required_profile = UNKNOWN_PROFILE_REQUIREMENT;
        let entry = controls
            .prepare(
                &boundary(),
                unsupported,
                &system,
                &registers,
                &mut thread,
                None,
            )
            .unwrap();
        assert!(
            unsafe { entry.with_view::<()>(|_| panic!("declined body must not run")) }.is_err()
        );
        assert_eq!(*thread.policy_mut(), previous);
        let entry = controls
            .prepare(
                &boundary(),
                requirements(),
                &system,
                &registers,
                &mut thread,
                None,
            )
            .unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                entry.with_view(|_| panic!("fixture unwind"))
            }))
            .is_err()
        );
        assert_eq!(*thread.policy_mut(), previous);
    }

    mod reservation {
        //! Exclusive reservations through the memory-service callback.
        use super::*;
        use crate::memory::{
            backing::{AccessPermissions, MemoryBacking, MemoryView},
            domain::MappingAttributes,
        };
        use crate::system::events::EventDomain;
        use std::{
            alloc::{Layout, alloc_zeroed, dealloc},
            ptr::NonNull,
            sync::Arc,
        };
        use stela_compiler::context::memory::{
            MemoryOrder, MemoryRequest,
            exclusive::{
                EXCLUSIVE_FAILED, EXCLUSIVE_STORED, ExclusiveData, ExclusiveOperation,
                ExclusiveShape,
            },
        };

        const STORAGE_BYTES: usize = 64;
        const SCA_BYTES: usize = 16;
        const DATA_BASE: u64 = 0x4000;
        const WORD_BYTES: u32 = 4;
        const STORED_VALUE: u64 = 0x53c7_1a09;
        const RIGHTS: AccessPermissions = AccessPermissions {
            readable: true,
            writable: true,
            executable: false,
        };

        struct Storage {
            pointer: NonNull<u8>,
            layout: Layout,
        }
        // SAFETY: raw allocation owner lends no Rust references to the bytes.
        unsafe impl Send for Storage {}
        // SAFETY: every byte access in this fixture goes through the same coherent
        // domain.
        unsafe impl Sync for Storage {}
        impl Drop for Storage {
            fn drop(&mut self) {
                // SAFETY: this owner keeps its allocation and layout.
                unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
            }
        }

        fn reserved_memory() -> (Arc<MemoryDomain>, MemoryThread<MemoryControls>) {
            let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
            // SAFETY: nonempty valid layout retained by the matching storage owner.
            let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            let storage = Arc::new(Storage { pointer, layout });
            // SAFETY: stable raw storage, coherent single domain, no byte references.
            let backing =
                unsafe { MemoryBacking::new(pointer, STORAGE_BYTES, RIGHTS, storage) }.unwrap();
            let view = MemoryView::new(backing, DATA_BASE, 0, STORAGE_BYTES, RIGHTS).unwrap();
            let policy = *memory(&domain()).policy_mut();
            let domain = MemoryDomain::new_for_address_space(
                ADDRESS_SPACE,
                MemorySystem::new(ERG_BYTES, MONITOR_STRIPES).unwrap(),
                vec![(
                    view,
                    MappingAttributes {
                        tagged: false,
                        shareable: true,
                    },
                )],
                TargetCpu::Baseline,
            )
            .unwrap();
            let thread = domain.thread(policy);
            (domain, thread)
        }

        fn transfer_requirements() -> MemoryRequirements {
            MemoryRequirements {
                required_profile: profile_requirements::NATIVE_ACCESS,
                ..requirements()
            }
        }

        fn transfer(view: &mut MemoryContextView, operation: ExclusiveOperation) -> ExclusiveData {
            let write = operation == ExclusiveOperation::Store;
            let mut data = ExclusiveData {
                operation: operation as u32,
                order: MemoryOrder::Relaxed as u32,
                shape: ExclusiveShape::Scalar as u32,
                status: EXCLUSIVE_STORED,
                value: [if write { STORED_VALUE } else { 0 }, 0],
            };
            let request = MemoryRequest {
                address: DATA_BASE,
                data: std::ptr::from_mut(&mut data).cast(),
                bytes: WORD_BYTES,
                flags: flags::EXCLUSIVE | if write { flags::WRITE } else { 0 },
                pc: SOURCE_PC.0,
            };
            // SAFETY: complete initialized aligned ExclusiveData and valid request/view;
            // all staging is private and disjoint from retained native backing.
            let status = unsafe { (view.callback)(view, &request) };
            assert_eq!(MemoryStatus::from_code(status), Some(MemoryStatus::Success));
            data
        }

        enum Completion {
            Return,
            CallbackError,
            PreflightDecline,
            Unwind,
        }

        #[test]
        fn reservation_survives_scoped_policy_return_error_decline_and_unwind() {
            let system = state();
            let registers = GuestState::default();
            let before = registers.clone();
            for completion in [
                Completion::Return,
                Completion::CallbackError,
                Completion::PreflightDecline,
                Completion::Unwind,
            ] {
                let events = EventDomain::new();
                let endpoint = events.register(false, None).unwrap();
                let (domain, mut thread) = reserved_memory();
                // This private component declares the retained source RAM mapping as
                // effective NormalWB, EL0 RW and InnerShareable; host WB is not proof.
                let controls = controls(&domain);
                thread.bind_events(&endpoint.producer()).unwrap();
                let baseline = *thread.policy_mut();
                let entry = controls
                    .prepare(
                        &boundary(),
                        transfer_requirements(),
                        &system,
                        &registers,
                        &mut thread,
                        Some(&endpoint),
                    )
                    .unwrap();
                // SAFETY: a checked service call over stable RAM.
                let loaded =
                    unsafe { entry.with_view(|view| transfer(view, ExclusiveOperation::Load)) }
                        .unwrap();
                assert_eq!(loaded.value, [0; 2]);
                assert_eq!(*thread.policy_mut(), baseline);

                match completion {
                    Completion::Return => {
                        let entry = controls
                            .prepare(
                                &boundary(),
                                requirements(),
                                &system,
                                &registers,
                                &mut thread,
                                None,
                            )
                            .unwrap();
                        assert_eq!(unsafe { entry.with_view(|_| ()) }, Ok(()));
                    }
                    Completion::CallbackError => {
                        let entry = controls
                            .prepare(
                                &boundary(),
                                requirements(),
                                &system,
                                &registers,
                                &mut thread,
                                None,
                            )
                            .unwrap();
                        assert_eq!(
                            unsafe { entry.with_view(|_| Err::<(), _>("callback")) },
                            Ok(Err("callback"))
                        );
                    }
                    Completion::PreflightDecline => {
                        let requirements = MemoryRequirements {
                            required_host_caps: u32::MAX,
                            ..super::requirements()
                        };
                        let entry = controls
                            .prepare(
                                &boundary(),
                                requirements,
                                &system,
                                &registers,
                                &mut thread,
                                None,
                            )
                            .unwrap();
                        assert_eq!(
                            unsafe { entry.with_view::<()>(|_| panic!("preflight must decline")) },
                            Err(MemoryStatus::InvalidRequest)
                        );
                    }
                    Completion::Unwind => {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let entry = controls
                                .prepare(
                                    &boundary(),
                                    requirements(),
                                    &system,
                                    &registers,
                                    &mut thread,
                                    None,
                                )
                                .unwrap();
                            let _ = unsafe { entry.with_view(|_| panic!("outer callback unwind")) };
                        }));
                        assert!(result.is_err());
                    }
                }
                assert_eq!(*thread.policy_mut(), baseline);
                assert_eq!(registers, before);
                let store_requirements = MemoryRequirements {
                    required_flags: flags::EXCLUSIVE | flags::WRITE,
                    ..transfer_requirements()
                };
                for expected_status in [EXCLUSIVE_STORED, EXCLUSIVE_FAILED] {
                    let entry = controls
                        .prepare(
                            &boundary(),
                            store_requirements,
                            &system,
                            &registers,
                            &mut thread,
                            Some(&endpoint),
                        )
                        .unwrap();
                    let stored = unsafe {
                        entry.with_view(|view| transfer(view, ExclusiveOperation::Store))
                    }
                    .unwrap();
                    assert_eq!(stored.status, expected_status);
                    assert_eq!(*thread.policy_mut(), baseline);
                }
            }
        }
    }

    #[test]
    fn source_generation_capture_and_same_domain_renewal_are_explicit() {
        let domain = domain();
        assert_eq!(domain.generation().unwrap(), 0);
        let mut controls = controls(&domain);
        let thread = memory(&domain);
        assert!(controls.source.matches(&thread));
        controls.renew_source_resolved(source(&domain)).unwrap();
        assert!(controls.source.matches(&thread));
        assert_eq!(controls.sctlr_el1(), SCTLR_NATIVE_NORMAL_WB);
        assert_eq!(controls.tcr_el1(), LOWER_SIZE);
    }

    #[test]
    fn source_renewal_rejects_equal_looking_other_domain_without_replacing_old_witness() {
        let original = domain();
        let other = domain();
        let mut controls = controls(&original);
        assert_eq!(original.generation().unwrap(), other.generation().unwrap());
        assert_eq!(
            controls.renew_source_resolved(source(&other)),
            Err(ProcessMemoryError::WrongMemoryDomain)
        );
        assert!(controls.source.matches(&memory(&original)));
        assert!(!controls.source.matches(&memory(&other)));
    }

    #[test]
    fn actual_mapping_publication_invalidates_same_domain_source_until_explicit_renewal() {
        use crate::memory::domain::MappingAttributes;
        use crate::memory::{
            AllocateDataRequest, DataInheritance, DataPermissions, DataPlacement, OwnedMemory,
            SharedMemoryConfig,
        };
        let page = crate::memory::host_page_size().unwrap() as u64;
        let rights = DataPermissions {
            readable: true,
            writable: true,
            executable: false,
        };
        let request = AllocateDataRequest {
            placement: DataPlacement::Anywhere { hint: 0 },
            bytes: page,
            alignment_mask: 0,
            current: rights,
            maximum: rights,
            alias_tag: 0,
            inheritance: DataInheritance::Copy,
        };
        let mut owner = OwnedMemory::map(Vec::new()).unwrap();
        let allocation = owner.allocate_data(request).unwrap();
        // SAFETY: the fixture owns the anonymous RAM; every untagged, shareable
        // write-back view and host writer belongs to this domain, and no native
        // code is running.
        let domain = unsafe {
            owner.bind_shared_memory(
                SharedMemoryConfig {
                    address_space: ADDRESS_SPACE,
                    system: MemorySystem::new(ERG_BYTES, MONITOR_STRIPES).unwrap(),
                    target: TargetCpu::Baseline,
                    attributes: MappingAttributes {
                        tagged: false,
                        shareable: true,
                    },
                },
                &mut [],
            )
        }
        .unwrap();
        let lower_bits = 47;
        let mut authority = FixedProcessMemoryControls::new(
            features(),
            SCTLR_NATIVE_NORMAL_WB,
            u64::from(64 - lower_bits),
            lower_bits,
            source(&domain),
        )
        .unwrap();
        let thread = domain.thread(MemoryControls::new(
            LowerAddressProfile::new(lower_bits, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        ));
        let old = source(&domain);
        assert!(authority.source.matches(&thread));
        owner
            .protect_data(allocation.guest_address, page, true, false)
            .unwrap();
        assert_eq!(domain.generation().unwrap(), 1);
        assert!(!authority.source.matches(&thread));
        assert_eq!(
            authority.renew_source_resolved(old),
            Err(ProcessMemoryError::WrongMemoryDomain)
        );
        // The fixture resolves the entire resulting view set under serialization; a
        // host mprotect alone does not produce the witness.
        authority.renew_source_resolved(source(&domain)).unwrap();
        assert!(authority.source.matches(&thread));
        owner.allocate_data(request).unwrap();
        assert_eq!(domain.generation().unwrap(), 2);
        assert!(!authority.source.matches(&thread));
        authority.renew_source_resolved(source(&domain)).unwrap();
        assert!(authority.source.matches(&thread));
    }
}
