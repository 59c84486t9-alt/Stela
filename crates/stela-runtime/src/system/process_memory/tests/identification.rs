//! Declared-source component tests; no captured-hardware or native admission.
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
