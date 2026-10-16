use super::*;
use crate::memory::source_ram::{
    InitializedRamRegion, PhysicalRamRange, SourceRamDeclaration, SourceRamPermissions,
    SourceRamSystemConfig, materialize_source_ram_regions,
};
const BASE: u64 = 0x1000;
const WORD: u32 = 0xd503_207f;
fn actual_pin() -> (
    PhysicalAddressSpace,
    MemoryExecutionLoan,
    BoundPhysicalInstruction,
) {
    let prefix = WORD.to_le_bytes().to_vec();
    let materialized = materialize_source_ram_regions(
        SourceRamDeclaration {
            address_space: 713,
            target: stela_compiler::TargetCpu::Baseline,
            declared_capacity: vec![PhysicalRamRange {
                source_pa: BASE,
                bytes: 64,
            }],
            initialized: Vec::new(),
        },
        Vec::new(),
        vec![InitializedRamRegion {
            range: PhysicalRamRange {
                source_pa: BASE,
                bytes: 64,
            },
            file_sha256: crate::sha256(&prefix),
            file_prefix: prefix,
            permissions: SourceRamPermissions {
                readable: true,
                writable: true,
                executable: true,
            },
        }],
        SourceRamSystemConfig {
            reservation_granule_bytes: 16,
            reservation_stripe_count: 8,
        },
    )
    .unwrap();
    let (binding, immutable) = materialized.into_parts();
    assert!(immutable.is_empty());
    let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
    let outer = physical.initial_source_execution_loan().unwrap();
    let config = stage1::Config::from_controls_for_cpu(
        stage1::Controls {
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            tcr_el1: 0,
            sctlr_el1: 0,
            mair_el1: 0,
        },
        stage1::CpuProfile {
            pa_max: stage1::PaBits::Bits40,
            asid_bits: stage1::AsidBits::Bits8,
            granules: stage1::GranuleSupport {
                kib4: true,
                kib16: true,
                kib64: false,
                lower_fallback: stage1::Granule::KiB4,
                upper_fallback: stage1::Granule::KiB4,
            },
            pauth: false,
            pan: false,
            pan3: false,
        },
    )
    .unwrap();
    let translation = stage1::translate(
        &config,
        &physical,
        stage1::Access {
            kind: stage1::AccessKind::Fetch,
            exception_level: stage1::ExceptionLevel::El1,
            raw_virtual_address: BASE,
            source_pc: BASE,
            pan: false,
            uao: false,
            aligned: true,
        },
    )
    .unwrap();
    let pin = physical
        .read_instruction(&outer, &translation, BASE, &[], 0)
        .unwrap();
    (physical, outer, pin)
}
#[test]
fn retained_pin_rejects_foreign_owner_and_unaccounted_identical_write() {
    let (physical, outer, pin) = actual_pin();
    physical.validate_retired_instruction(&outer, &pin).unwrap();
    let (foreign, foreign_outer, _) = actual_pin();
    assert!(
        foreign
            .validate_retired_instruction(&foreign_outer, &pin)
            .is_err()
    );
    drop(outer);
    {
        let _service = physical.domain().service_loan().unwrap();
        // SAFETY: a writer of the same memory system under a quiescent
        // service loan; identical bytes still advance the mutation history.
        unsafe {
            physical.memory_system().publish(
                pin.backing(),
                pin.backing_offset(),
                &WORD.to_le_bytes(),
            )
        }
        .unwrap();
    }
    let outer = physical.initial_source_execution_loan().unwrap();
    assert_eq!(pin.word(), WORD);
    assert!(pin.is_current());
    assert!(!pin.bytes_are_current());
    assert!(physical.validate_retired_instruction(&outer, &pin).is_err());
}
#[test]
fn unknown_writer_poison_precedes_retained_pin_release() {
    let (physical, outer, pin) = actual_pin();
    drop(outer);
    {
        let _service = physical.domain().service_loan().unwrap();
        let mut attempted = physical
            .memory_system()
            .prepare_source_write(pin.backing(), pin.backing_offset(), size_of::<u32>())
            .unwrap();
        attempted.attempting();
        drop(attempted); // actual writer lost its host-effect outcome
        assert!(physical.check_fetch_execution().is_err());
        assert!(pin.is_current()); // pin remains owned until after poison
    }
    assert!(physical.initial_source_execution_loan().is_err());
}
