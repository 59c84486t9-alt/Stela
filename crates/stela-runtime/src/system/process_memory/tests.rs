//! Declared fresh-machine component fixtures, not original/native observations.
use super::*;
use crate::memory::domain::{MemoryDomain, MemorySystem};
use crate::system::state::El1Registers;
use std::sync::Arc;
use stela_compiler::{GuestAddress, TargetCpu};

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
    // SAFETY: these fixtures explicitly declare retained source mappings
    // NormalWB with matching rights, tag/shareability attributes and offsets.
    // This is a fresh software component declaration, not a hardware observation.
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
    assert!(unsafe { entry.with_view::<()>(|_| panic!("declined body must not run")) }.is_err());
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

mod reservation;

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
    // SAFETY: fixture is the sole source/creation owner of actual anonymous
    // software-machine RAM. All current untagged/shareable Normal-WB views
    // and host writers participate in this same domain; no native run is active.
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
    // This explicit fixture source owner resolves the entire resulting view set
    // under serialization; host mprotect alone does not mint this witness.
    authority.renew_source_resolved(source(&domain)).unwrap();
    assert!(authority.source.matches(&thread));
    owner.allocate_data(request).unwrap();
    assert_eq!(domain.generation().unwrap(), 2);
    assert!(!authority.source.matches(&thread));
    authority.renew_source_resolved(source(&domain)).unwrap();
    assert!(authority.source.matches(&thread));
}
