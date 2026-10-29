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
fn bank(ids: Arc<Snapshot>, domain: &Arc<MemoryDomain>, sctlr2: u64) -> FixedProcessMemoryControls {
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
            (loan.snapshot().read(Register::IdAa64Pfr1El1).unwrap() >> PFR1_MTE_SHIFT) & FIELD_MASK,
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
        let ids =
            Arc::new(Snapshot::declared("shared-bank-cpt-feature-declaration", &values).unwrap());
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
