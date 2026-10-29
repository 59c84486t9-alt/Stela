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
    assert_eq!(
        // SAFETY: synchronous component callback neither keeps raw pointers nor reenters.
        unsafe { entry.with_view(|view| view.has_supported_header()) },
        Ok(true)
    );
    assert_eq!(registers.x[0], 0x53c7);
    assert_eq!(*thread.policy_mut(), previous);
}

#[test]
// Both ways an unused token can end leave the capability uninstalled.
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
        // SAFETY: the entry was prepared for this body, which touches only the view.
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
        // SAFETY: the entry was prepared for this body, which touches only the view.
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
        // SAFETY: the entry was prepared for this body, which touches only the view.
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
            EXCLUSIVE_FAILED, EXCLUSIVE_STORED, ExclusiveData, ExclusiveOperation, ExclusiveShape,
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
        // SAFETY: nonempty valid layout kept by the matching storage owner.
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
        // all staging is private and disjoint from kept native backing.
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
            // This private component declares the source RAM mapping as
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
                    // SAFETY: the entry was prepared for this body, which touches only the
                    // view.
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
                        // SAFETY: the entry was prepared for this body, which touches only the
                        // view.
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
                        // SAFETY: the entry was prepared for this body, which touches only the
                        // view.
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
                        // SAFETY: the entry was prepared for this body, which touches only the
                        // view.
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
                // SAFETY: the entry was prepared for this body, which touches only the view.
                let stored =
                    unsafe { entry.with_view(|view| transfer(view, ExclusiveOperation::Store)) }
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
