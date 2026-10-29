//! Optional SCTLR2 and TCR2 storage.

use super::{
    FixedProcessMemoryControls, MemoryStatus, ProcessMemoryError, Register, Snapshot,
    SourceNormalWbDomain,
};
#[cfg(feature = "std")]
use super::{MemoryControls, MemoryExecutionLoan, MemoryThread};
use crate::{
    pauth::features::{LinkRegisterPauthCapability, UnsupportedInstructionProfile},
    system::identification_snapshot::{Origin, Unsupported},
};
use alloc::sync::Arc;

const FIELD_MASK: u64 = 0xf;
const MMFR3_SCTLRX_SHIFT: u32 = 4;
const MMFR3_TCRX_SHIFT: u32 = 0;
const MMFR4_SRMASK_SHIFT: u32 = 44;
const PFR1_MTE_SHIFT: u32 = 8;
const EXTENSION_PRESENT: u8 = 1;
const FEATURE_ABSENT: u8 = 0;
pub(crate) const SCTLR2_ENPACM: u64 = 1 << 7;
pub(crate) const SCTLR2_ENPACM0: u64 = 1 << 8;
pub(crate) const SCTLR2_CPTA: u64 = 1 << 9;
pub(crate) const SCTLR2_CPTA0: u64 = 1 << 10;
pub(crate) const SCTLR2_CPTM: u64 = 1 << 11;
pub(crate) const SCTLR2_CPTM0: u64 = 1 << 12;
const SCTLR2_CPA_FIELDS: u64 = SCTLR2_CPTA | SCTLR2_CPTA0 | SCTLR2_CPTM | SCTLR2_CPTM0;
const SCTLR2_PACM_FIELDS: u64 = SCTLR2_ENPACM | SCTLR2_ENPACM0;
const SCTLR2_REVIEWED: u64 = SCTLR2_PACM_FIELDS | SCTLR2_CPA_FIELDS;
const ISAR3_CPA_SHIFT: u32 = 0;
const CPA_WITH_CHECKING: u8 = 2;

/// Stored once inside FixedProcessMemoryControls; no SCTLR/TCR copies.
/// The constructor rejects nonzero TCR2 and all unimplemented SCTLR2 bits.
/// Future EnFPM or mutation belongs to this same owner.
#[derive(Debug)]
#[cfg_attr(
    not(feature = "std"),
    expect(
        dead_code,
        reason = "only the host checked-memory borrow reads the control bank"
    )
)]
pub(super) struct ExtendedControlBank {
    sctlr2_el1: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Process(ProcessMemoryError),
    Identification(Unsupported),
    PauthProfile(UnsupportedInstructionProfile),
    CapturedSourceRequiresActualTransfer,
    MissingIdentification,
    DifferentSnapshot,
    ExtendedControlsUnavailable,
    MissingAddressSpace,
    SourceDomain(MemoryStatus),
    UnsupportedControl { register: &'static str, value: u64 },
}

fn field(snapshot: &Snapshot, register: Register, shift: u32) -> Result<u8, Error> {
    Ok(((snapshot.read(register).map_err(Error::Identification)? >> shift) & FIELD_MASK) as u8)
}

fn require(
    snapshot: &Snapshot,
    register: Register,
    name: &'static str,
    shift: u32,
    expected: u8,
) -> Result<(), Error> {
    let value = field(snapshot, register, shift)?;
    if value != expected {
        return Err(Error::Identification(Unsupported::Field {
            register,
            field: name,
            value,
        }));
    }
    Ok(())
}

impl FixedProcessMemoryControls {
    /// Build a new software control bank from explicit source facts; not for
    /// upgrading an existing bank. No reset value is guessed.
    pub fn new_source_resolved_with_extended_controls(
        identification: Arc<Snapshot>,
        sctlr_el1: u64,
        tcr_el1: u64,
        lower_address_bits: u8,
        source: SourceNormalWbDomain,
        sctlr2_el1: u64,
        tcr2_el1: u64,
    ) -> Result<Self, Error> {
        if identification.provenance().origin() != Origin::DeclaredGuest {
            return Err(Error::CapturedSourceRequiresActualTransfer);
        }
        require(
            &identification,
            Register::IdAa64Mmfr3El1,
            "SCTLRX",
            MMFR3_SCTLRX_SHIFT,
            EXTENSION_PRESENT,
        )?;
        require(
            &identification,
            Register::IdAa64Mmfr3El1,
            "TCRX",
            MMFR3_TCRX_SHIFT,
            EXTENSION_PRESENT,
        )?;
        require(
            &identification,
            Register::IdAa64Mmfr4El1,
            "SRMASK",
            MMFR4_SRMASK_SHIFT,
            FEATURE_ABSENT,
        )?;
        if sctlr2_el1 & !SCTLR2_REVIEWED != 0 {
            return Err(Error::UnsupportedControl {
                register: "SCTLR2_EL1",
                value: sctlr2_el1,
            });
        }
        // Nonzero feature-dependent fields cannot be stored when FEAT_PAuth_LR
        // is absent, reserved or unsupported.
        if sctlr2_el1 & SCTLR2_PACM_FIELDS != 0 {
            LinkRegisterPauthCapability::from_profile(&identification)
                .map_err(Error::PauthProfile)?;
        }
        if sctlr2_el1 & SCTLR2_CPA_FIELDS != 0 {
            require(
                &identification,
                Register::IdAa64Isar3El1,
                "CPA",
                ISAR3_CPA_SHIFT,
                CPA_WITH_CHECKING,
            )?;
        }
        if tcr2_el1 != 0 {
            return Err(Error::UnsupportedControl {
                register: "TCR2_EL1",
                value: tcr2_el1,
            });
        }
        if !source.is_current().map_err(Error::SourceDomain)? {
            return Err(Error::SourceDomain(MemoryStatus::Domain));
        }
        require(
            &identification,
            Register::IdAa64Pfr1El1,
            "MTE",
            PFR1_MTE_SHIFT,
            FEATURE_ABSENT,
        )?;
        let mut bank = Self::new_with_pointer_identification(
            identification,
            sctlr_el1,
            tcr_el1,
            lower_address_bits,
            source,
        )
        .map_err(Error::Process)?;
        // This new value has not escaped yet; there is no setter on an existing
        // bank.
        bank.extended = Some(ExtendedControlBank { sctlr2_el1 });
        Ok(bank)
    }

    /// Validate the thread with a short borrow, then keep only the bank,
    /// snapshot and outer references; the consumer keeps the mutable thread and
    /// PE through its memory and native stages. The borrow validates the
    /// current source and outer domain; it does not extend MTE support or prove
    /// PE identity.
    #[cfg(feature = "std")]
    pub(crate) fn extended_controls<'run>(
        &'run self,
        expected_snapshot: &Snapshot,
        thread: &MemoryThread<MemoryControls>,
        execution: &'run MemoryExecutionLoan,
    ) -> Result<ExtendedControlLoan<'run>, Error> {
        let snapshot = self
            .identification_snapshot()
            .ok_or(Error::MissingIdentification)?;
        if !snapshot.same_snapshot(expected_snapshot) {
            return Err(Error::DifferentSnapshot);
        }
        let extended = self
            .extended
            .as_ref()
            .ok_or(Error::ExtendedControlsUnavailable)?;
        self.source
            .check_current_execution(thread, execution)
            .map_err(Error::SourceDomain)?;
        let address_space = thread.address_space().ok_or(Error::MissingAddressSpace)?;
        Ok(ExtendedControlLoan {
            _bank: self,
            extended,
            snapshot,
            _execution: execution,
            address_space,
        })
    }
}

/// While borrowed, the bank cannot be renewed or changed and the outer pin
/// cannot be released.
#[cfg(feature = "std")]
pub(crate) struct ExtendedControlLoan<'run> {
    _bank: &'run FixedProcessMemoryControls,
    extended: &'run ExtendedControlBank,
    snapshot: &'run Snapshot,
    _execution: &'run MemoryExecutionLoan,
    address_space: u64,
}

#[cfg(feature = "std")]
impl<'run> ExtendedControlLoan<'run> {
    pub(crate) fn snapshot(&self) -> &'run Snapshot {
        self.snapshot
    }
    pub(crate) fn address_space(&self) -> u64 {
        self.address_space
    }
    pub(crate) fn sctlr2_el1(&self) -> u64 {
        self.extended.sctlr2_el1
    }
}

#[cfg(test)]
mod tests {
    //! SCTLR2 and TCR2 storage.
    use super::*;
    use crate::memory::{
        domain::{MemoryDomain, MemorySystem},
        policy::{LowerAddressProfile, TagCheckFaultMode},
    };
    use stela_compiler::TargetCpu;

    const ADDRESS_SPACE: u64 = 7;
    const ADDRESS_BITS: u8 = 47;
    const TCR: u64 = 17 | (17 << 16) | (2 << 30);
    const SCTLR: u64 = 1 | (1 << 2) | (1 << 31);

    fn entries(mte: u64) -> Vec<(Register, u64)> {
        vec![
            (Register::IdAa64Pfr0El1, 0x11),
            (Register::IdAa64Pfr1El1, mte << PFR1_MTE_SHIFT),
            (Register::IdAa64Mmfr0El1, 0),
            (Register::IdAa64Mmfr2El1, 1 << 32),
            (Register::IdAa64Mmfr3El1, 0x11),
            (Register::IdAa64Mmfr4El1, 0),
            (Register::IdAa64Isar1El1, 6 << 4),
            (Register::IdAa64Isar2El1, 0),
            (Register::IdAa64Isar3El1, 2 << 12),
            (Register::IdAa64Dfr0El1, 0),
        ]
    }
    fn snapshot(mte: u64) -> Arc<Snapshot> {
        Arc::new(Snapshot::declared("LR-sole-bank-declared-component", &entries(mte)).unwrap())
    }
    fn new_domain() -> Arc<MemoryDomain> {
        MemoryDomain::new_for_address_space(
            ADDRESS_SPACE,
            MemorySystem::new(16, 4).unwrap(),
            Vec::new(),
            TargetCpu::Baseline,
        )
        .unwrap()
    }
    fn source(domain: &Arc<MemoryDomain>) -> SourceNormalWbDomain {
        // SAFETY: this fresh empty domain declares no mappings or native invocation.
        // No copied hardware PE or inferred effective ARM memory attributes are used.
        unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(domain)) }.unwrap()
    }
    fn memory(domain: &Arc<MemoryDomain>) -> MemoryThread<MemoryControls> {
        domain.thread(MemoryControls::new(
            LowerAddressProfile::new(ADDRESS_BITS, false).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        ))
    }
    fn bank(
        ids: Arc<Snapshot>,
        domain: &Arc<MemoryDomain>,
        sctlr2: u64,
    ) -> FixedProcessMemoryControls {
        FixedProcessMemoryControls::new_source_resolved_with_extended_controls(
            ids,
            SCTLR,
            TCR,
            ADDRESS_BITS,
            source(domain),
            sctlr2,
            0,
        )
        .unwrap()
    }

    #[test]
    fn old_named_scopes_have_unavailable_extended_storage() {
        let mte = FEATURE_ABSENT as u64;
        let ids = snapshot(mte);
        let domain = new_domain();
        let bank = FixedProcessMemoryControls::new_with_identification(
            Arc::clone(&ids),
            SCTLR,
            TCR,
            ADDRESS_BITS,
            source(&domain),
        )
        .unwrap();
        let thread = memory(&domain);
        let outer = thread.execution_loan().unwrap();
        assert!(bank.extended.is_none());
        assert!(matches!(
            bank.extended_controls(&ids, &thread, &outer),
            Err(Error::ExtendedControlsUnavailable)
        ));
    }

    #[test]
    fn fresh_scopes_preserve_original_ids_and_all_four_control_values() {
        let mte = FEATURE_ABSENT as u64;
        let ids = snapshot(mte);
        let domain = new_domain();
        for sctlr2 in [
            0,
            SCTLR2_ENPACM,
            SCTLR2_ENPACM0,
            SCTLR2_ENPACM | SCTLR2_ENPACM0,
        ] {
            let bank = bank(Arc::clone(&ids), &domain, sctlr2);
            let thread = memory(&domain);
            let outer = thread.execution_loan().unwrap();
            let loan = bank.extended_controls(&ids, &thread, &outer).unwrap();
            assert!(loan.snapshot().same_snapshot(&ids));
            assert_eq!(loan.address_space(), ADDRESS_SPACE);
            assert_eq!(
                (
                    loan._bank.sctlr_el1(),
                    loan._bank.tcr_el1(),
                    loan.sctlr2_el1(),
                    0
                ),
                (SCTLR, TCR, sctlr2, 0)
            );
            assert_eq!(
                (loan.snapshot().read(Register::IdAa64Pfr1El1).unwrap() >> PFR1_MTE_SHIFT)
                    & FIELD_MASK,
                mte
            );
        }
    }

    #[test]
    fn different_snapshot_thread_domain_and_outer_pin_decline() {
        let ids = snapshot(0);
        let equal_values = snapshot(0);
        let domain = new_domain();
        let other = new_domain();
        let bank = bank(Arc::clone(&ids), &domain, 0);
        let thread = memory(&domain);
        let different_thread = memory(&other);
        let outer = thread.execution_loan().unwrap();
        let different_outer = different_thread.execution_loan().unwrap();
        assert!(matches!(
            bank.extended_controls(&equal_values, &thread, &outer),
            Err(Error::DifferentSnapshot)
        ));
        assert!(matches!(
            bank.extended_controls(&ids, &different_thread, &outer),
            Err(Error::SourceDomain(_))
        ));
        assert!(matches!(
            bank.extended_controls(&ids, &thread, &different_outer),
            Err(Error::SourceDomain(_))
        ));
    }

    #[test]
    fn domain_read_loan_intentionally_does_not_identify_a_pe_or_thread() {
        let ids = snapshot(0);
        let domain = new_domain();
        let bank = bank(Arc::clone(&ids), &domain, 0);
        let first = memory(&domain);
        let second = memory(&domain);
        let outer = first.execution_loan().unwrap();
        // Both are admitted as domain reads; the consumer must still hold its own
        // frame, system, PE and outer object.
        assert!(bank.extended_controls(&ids, &first, &outer).is_ok());
        assert!(bank.extended_controls(&ids, &second, &outer).is_ok());
    }

    #[test]
    fn missing_features_and_unimplemented_extended_bits_never_default() {
        let domain = new_domain();
        for (register, bad) in [
            (Register::IdAa64Mmfr3El1, 0),
            (Register::IdAa64Mmfr4El1, 1 << MMFR4_SRMASK_SHIFT),
            (Register::IdAa64Pfr1El1, 2 << PFR1_MTE_SHIFT),
        ] {
            let mut values = entries(0);
            values.iter_mut().find(|(r, _)| *r == register).unwrap().1 = bad;
            let ids = Arc::new(Snapshot::declared("LR-bank-invalid-declaration", &values).unwrap());
            assert!(
                FixedProcessMemoryControls::new_source_resolved_with_extended_controls(
                    ids,
                    SCTLR,
                    TCR,
                    ADDRESS_BITS,
                    source(&domain),
                    0,
                    0,
                )
                .is_err()
            );
        }
        let values: Vec<_> = entries(0)
            .into_iter()
            .filter(|(r, _)| *r != Register::IdAa64Mmfr4El1)
            .collect();
        let partial = Arc::new(Snapshot::declared("LR-bank-missing-field", &values).unwrap());
        assert!(matches!(
            FixedProcessMemoryControls::new_source_resolved_with_extended_controls(
                partial,
                SCTLR,
                TCR,
                ADDRESS_BITS,
                source(&domain),
                0,
                0,
            ),
            Err(Error::Identification(_))
        ));
        for (sctlr2, tcr2) in [(1, 0), (1 << 63, 0), (0, 1)] {
            assert!(matches!(
                FixedProcessMemoryControls::new_source_resolved_with_extended_controls(
                    snapshot(0),
                    SCTLR,
                    TCR,
                    ADDRESS_BITS,
                    source(&domain),
                    sctlr2,
                    tcr2,
                ),
                Err(Error::UnsupportedControl { .. })
            ));
        }
    }

    #[test]
    fn cpt_fields_require_cpa2_and_the_qualified_same_bank_constructor() {
        let domain = new_domain();
        for cpa in [0, 1, 2, FIELD_MASK] {
            let mut values = entries(0);
            values
                .iter_mut()
                .find(|(register, _)| *register == Register::IdAa64Isar3El1)
                .unwrap()
                .1 |= cpa;
            let ids = Arc::new(
                Snapshot::declared("shared-bank-cpt-feature-declaration", &values).unwrap(),
            );
            let result = FixedProcessMemoryControls::new_source_resolved_with_extended_controls(
                ids,
                SCTLR,
                TCR,
                ADDRESS_BITS,
                source(&domain),
                SCTLR2_CPTA,
                0,
            );
            if cpa == u64::from(CPA_WITH_CHECKING) {
                // The same-bank constructor keeps FEAT_CPA2; entry still needs its
                // source, profile and owner token.
                let bank = result.expect("qualified CPA2 same-bank declaration");
                assert_eq!(bank.extended.as_ref().unwrap().sctlr2_el1, SCTLR2_CPTA);
                assert_eq!(
                    bank.features.cpa,
                    super::super::pointer_checks::CpaFeature::Checked
                );
            } else {
                assert!(matches!(result, Err(Error::Identification(_))));
            }
        }
    }

    #[test]
    fn nonzero_pacm_fields_require_same_snapshot_reviewed_lr_profile() {
        let domain = new_domain();
        for apa in [0, 1, 5, 7] {
            let mut values = entries(0);
            values
                .iter_mut()
                .find(|(register, _)| *register == Register::IdAa64Isar1El1)
                .unwrap()
                .1 = apa << 4;
            let ids = Arc::new(Snapshot::declared("bank-PACM-applicability", &values).unwrap());
            for bits in [SCTLR2_ENPACM, SCTLR2_ENPACM0, SCTLR2_PACM_FIELDS] {
                assert!(matches!(
                    FixedProcessMemoryControls::new_source_resolved_with_extended_controls(
                        Arc::clone(&ids),
                        SCTLR,
                        TCR,
                        ADDRESS_BITS,
                        source(&domain),
                        bits,
                        0,
                    ),
                    Err(Error::PauthProfile(_))
                ));
            }
            // Explicit zero fields require no LR algorithm/PACM capability.
            assert!(
                FixedProcessMemoryControls::new_source_resolved_with_extended_controls(
                    ids,
                    SCTLR,
                    TCR,
                    ADDRESS_BITS,
                    source(&domain),
                    0,
                    0,
                )
                .is_ok()
            );
        }
        for pacm in [0, 1, 3] {
            let mut values = entries(0);
            values
                .iter_mut()
                .find(|(register, _)| *register == Register::IdAa64Isar3El1)
                .unwrap()
                .1 = pacm << 12;
            let ids = Arc::new(Snapshot::declared("bank-PACM-implementation", &values).unwrap());
            assert!(matches!(
                FixedProcessMemoryControls::new_source_resolved_with_extended_controls(
                    ids,
                    SCTLR,
                    TCR,
                    ADDRESS_BITS,
                    source(&domain),
                    SCTLR2_ENPACM0,
                    0,
                ),
                Err(Error::PauthProfile(_))
            ));
        }
    }
}
