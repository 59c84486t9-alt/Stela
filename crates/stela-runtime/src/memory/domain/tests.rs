use super::super::backing::AccessPermissions;
use super::*;
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;

const GUEST_BASE: u64 = 0x1000;
const STORAGE_BYTES: usize = 64;
const TEST_PC: u64 = 0x1234;
const TEST_ERG_BYTES: u64 = 16;
const TEST_STRIPES: usize = 4;
const RIGHTS: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};
const ATTRIBUTES: MappingAttributes = MappingAttributes {
    tagged: false,
    shareable: true,
};

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}

// SAFETY: this owner retains raw storage without lending Rust references.
unsafe impl Send for Storage {}
// SAFETY: actual byte accesses use the tested native execution domain.
unsafe impl Sync for Storage {}

impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: the original raw allocation and layout remain owned here.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn backing() -> Arc<MemoryBacking> {
    let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
    // SAFETY: valid nonempty layout retained for its matching deallocation.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let storage = Arc::new(Storage { pointer, layout });
    // SAFETY: storage owns stable raw bytes and rights; no Rust references
    // alias them and tests access only through the native access boundary.
    unsafe { MemoryBacking::new(pointer, STORAGE_BYTES, RIGHTS, storage) }.unwrap()
}

fn view(
    backing: &Arc<MemoryBacking>,
    offset: usize,
    bytes: usize,
    rights: AccessPermissions,
) -> Arc<MemoryView> {
    MemoryView::new(
        Arc::clone(backing),
        GUEST_BASE + offset as u64,
        offset,
        bytes,
        rights,
    )
    .unwrap()
}

fn domain(views: Vec<Arc<MemoryView>>) -> Arc<MemoryDomain> {
    MemoryDomain::new(
        MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
        views.into_iter().map(|view| (view, ATTRIBUTES)).collect(),
        TargetCpu::detect(),
    )
    .unwrap()
}

#[derive(Default)]
struct Policy {
    unavailable: bool,
    reject: Option<u64>,
    checked: Vec<(u64, usize)>,
    checked_flags: Vec<u32>,
}

impl DataPolicy for Policy {
    fn validate_execution(&self, _required_flags: u32) -> Result<(), MemoryStatus> {
        if self.unavailable {
            Err(MemoryStatus::Unsupported)
        } else {
            Ok(())
        }
    }
    fn translate(&self, raw_address: u64) -> Result<u64, MemoryStatus> {
        Ok(raw_address)
    }

    fn check(&mut self, access: DataAccess<'_>) -> Result<(), MemoryStatus> {
        self.checked.push((access.raw_address, access.bytes));
        self.checked_flags.push(access.flags);
        if self.reject == Some(access.raw_address) {
            Err(MemoryStatus::TagCheck)
        } else {
            Ok(())
        }
    }
}

#[test]
fn unqualified_policy_refuses_both_checked_and_disabled_cpa_specializations_before_entry() {
    use stela_compiler::context::memory::address::{
        AccessEl, AddressAddChecks, AddressCheckRequirements, IncrementChoice,
    };
    let domain = domain(Vec::new());
    let mut thread = domain.thread(Policy::default());
    assert!(thread.prepare(MemoryRequirements::default()).is_ok());
    for access_el in [AccessEl::El0, AccessEl::El1] {
        for checks in [AddressAddChecks::Disabled, AddressAddChecks::Enabled] {
            let required = MemoryRequirements {
                required_address_checks: AddressCheckRequirements::for_access(access_el, checks)
                    .with_increment_choice(IncrementChoice::Unchecked),
                ..Default::default()
            };
            assert_eq!(
                thread.prepare(required).err(),
                Some(MemoryStatus::Unsupported)
            );
            assert!(thread.policy.checked.is_empty());
        }
    }
}

#[derive(Debug)]
struct Outcome {
    status: u32,
    fault_kind: u32,
    fault_address: u64,
    fault_pc: u64,
    completed: u64,
}

fn invoke(
    thread: &mut MemoryThread<Policy>,
    address: u64,
    bytes: &mut [u8],
    flags: u32,
) -> Outcome {
    let request = MemoryRequest {
        address,
        data: bytes.as_mut_ptr(),
        bytes: bytes.len() as u32,
        flags,
        pc: TEST_PC,
    };
    // SAFETY: the synchronous callback receives valid ABI objects and private
    // staging disjoint from raw guest storage, with no retained pointers.
    unsafe {
        thread.with_view(|context| {
            let status = (context.callback)(context, &request);
            Outcome {
                status,
                fault_kind: context.fault_kind,
                fault_address: context.fault_address,
                fault_pc: context.fault_pc,
                completed: context.completed_bytes,
            }
        })
    }
}

fn snapshot(backing: &MemoryBacking, bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|offset| {
            let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
            // SAFETY: tests inspect after synchronous execution; no byte access
            // overlaps this exact live one-byte native read.
            unsafe { access::read_part(pointer.as_ptr(), 1, TargetCpu::Baseline) }.unwrap() as u8
        })
        .collect()
}

fn reservation_access(
    domain: &MemoryDomain,
    offset: u64,
) -> monitor::Access<MemoryBacking, MemoryView, MappingAttributes> {
    let registered = &domain.registered_views()[0];
    monitor::Access::new(
        Arc::clone(registered.view.backing()),
        Arc::clone(&registered.monitor),
        offset,
        1,
        monitor::Shape::Scalar,
    )
    .unwrap()
}

#[test]
fn access_parts_match_all_sca_residues_and_architectural_widths() {
    for residue in 0..SCA_BYTES {
        for bytes in [1, 2, 4, 8, SCA_BYTES] {
            let actual: Vec<_> =
                AccessParts::new(GUEST_BASE + residue as u64, bytes, flags::SVE_PREDICATED)
                    .collect();
            let expected_widths = if residue + bytes <= SCA_BYTES {
                vec![bytes]
            } else if bytes == SCA_BYTES && residue == HALF_SCA_BYTES {
                vec![HALF_SCA_BYTES; 2]
            } else {
                vec![1; bytes]
            };
            assert_eq!(
                actual.iter().map(|part| part.bytes).collect::<Vec<_>>(),
                expected_widths,
                "residue={residue} width={bytes}"
            );
            let mut offset = 0;
            for part in actual {
                assert_eq!(part.offset, offset);
                assert_eq!(part.address, GUEST_BASE + residue as u64 + offset as u64);
                assert!((part.address as usize & (SCA_BYTES - 1)) + part.bytes <= SCA_BYTES);
                offset += part.bytes;
            }
            assert_eq!(offset, bytes);
        }
    }
}

#[test]
fn synchronous_callbacks_write_read_and_preserve_neighbors() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut thread = domain.thread(Policy::default());
    for bytes in [1, 2, 4, 8, SCA_BYTES] {
        if bytes == SCA_BYTES && !TargetCpu::detect().supports(TargetCpu::Cx16) {
            continue;
        }
        let mut expected = (1..=bytes).map(|byte| byte as u8).collect::<Vec<_>>();
        let written = invoke(
            &mut thread,
            GUEST_BASE + SCA_BYTES as u64,
            &mut expected,
            flags::WRITE,
        );
        assert_eq!(written.status, MemoryStatus::Success as u32);
        assert_eq!(written.completed, bytes as u64);
        let mut actual = vec![0xa5; bytes];
        let read = invoke(&mut thread, GUEST_BASE + SCA_BYTES as u64, &mut actual, 0);
        if bytes == SCA_BYTES && !TargetCpu::detect().supports(TargetCpu::AtomicLoad16) {
            assert_eq!(read.status, MemoryStatus::Unsupported as u32);
            assert_eq!(actual, vec![0xa5; bytes]);
            continue;
        }
        assert_eq!(read.status, MemoryStatus::Success as u32);
        assert_eq!(actual, expected);
        assert!(snapshot(&backing, SCA_BYTES).iter().all(|byte| *byte == 0));
    }
}

#[test]
fn actual_native_callbacks_cover_every_admitted_residue_and_width() {
    let target = TargetCpu::detect();
    let mut admitted = 0;
    let mut capability_declined = 0;
    for residue in 0..SCA_BYTES {
        for bytes in [1, 2, 4, 8, SCA_BYTES] {
            let address = GUEST_BASE + SCA_BYTES as u64 + residue as u64;
            let physical = backing();
            let pointer = physical
                .host_pointer(SCA_BYTES + residue, bytes, AccessKind::Read)
                .unwrap();
            let supported = AccessParts::new(address, bytes, 0).all(|part| {
                (part.bytes != SCA_BYTES || target.supports(TargetCpu::Cx16))
                    && access::read_footprint(
                        pointer.as_ptr() as usize + part.offset,
                        part.bytes,
                        target,
                    )
                    .is_ok()
            });
            if !supported {
                capability_declined += 1;
                continue;
            }
            admitted += 1;
            let domain = domain(vec![view(&physical, 0, STORAGE_BYTES, RIGHTS)]);
            let mut thread = domain.thread(Policy::default());
            let mut expected = (1..=bytes).map(|byte| byte as u8).collect::<Vec<_>>();
            let written = invoke(&mut thread, address, &mut expected, flags::WRITE);
            assert_eq!(
                written.status,
                MemoryStatus::Success as u32,
                "residue={residue} width={bytes}"
            );
            assert_eq!(written.completed, bytes as u64);
            let mut actual = vec![0xa5; bytes];
            assert_eq!(
                invoke(&mut thread, address, &mut actual, 0).status,
                MemoryStatus::Success as u32
            );
            assert_eq!(actual, expected);
            let mut full_expected = vec![0; STORAGE_BYTES];
            full_expected[SCA_BYTES + residue..SCA_BYTES + residue + bytes]
                .copy_from_slice(&expected);
            assert_eq!(snapshot(&physical, STORAGE_BYTES), full_expected);
        }
    }
    assert_eq!(admitted + capability_declined, SCA_BYTES * 5);
    eprintln!(
        "native callback matrix: {admitted} admitted, {capability_declined} capability-declined"
    );
}

#[test]
fn wide_read_and_write_host_capabilities_are_independent() {
    for target in [
        TargetCpu::Baseline,
        TargetCpu::Cx16,
        TargetCpu::AtomicLoad16,
    ] {
        if !target.supported() {
            continue;
        }
        let physical = backing();
        let domain = MemoryDomain::new(
            MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
            vec![(view(&physical, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
            target,
        )
        .unwrap();
        let mut thread = domain.thread(Policy::default());
        let mut expected = [0x5a; SCA_BYTES];
        let written = invoke(&mut thread, GUEST_BASE, &mut expected, flags::WRITE);
        let expected_write = if target.supports(TargetCpu::Cx16) {
            MemoryStatus::Success
        } else {
            MemoryStatus::Unsupported
        };
        assert_eq!(written.status, expected_write as u32);
        let mut actual = [0xa5; SCA_BYTES];
        let read = invoke(&mut thread, GUEST_BASE, &mut actual, 0);
        if target.supports(TargetCpu::AtomicLoad16) {
            assert_eq!(read.status, MemoryStatus::Success as u32);
            assert_eq!(actual, [0; SCA_BYTES]);
        } else {
            assert_eq!(read.status, MemoryStatus::Unsupported as u32);
            assert_eq!(actual, [0xa5; SCA_BYTES]);
        }
    }
}

#[test]
fn adjacent_views_resolve_one_atomic_quantity_before_writing() {
    let backing = backing();
    let readonly = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let domain = domain(vec![
        view(&backing, 0, 4, RIGHTS),
        view(&backing, 4, 12, readonly),
    ]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [0x5a; 8];
    let denied = invoke(&mut thread, GUEST_BASE, &mut bytes, flags::WRITE);
    assert_eq!(denied.status, MemoryStatus::Permission as u32);
    assert_eq!(denied.completed, 0);
    assert_eq!(snapshot(&backing, 8), [0; 8]);
    assert!(thread.policy.checked.is_empty());
    let mut read = [0xff; 8];
    assert_eq!(
        invoke(&mut thread, GUEST_BASE, &mut read, 0).status,
        MemoryStatus::Success as u32
    );
    assert_eq!(read, [0; 8]);
}

#[test]
fn contiguous_alias_views_share_one_native_atomic_quantity() {
    let backing = backing();
    let domain = domain(vec![
        view(&backing, 0, 4, RIGHTS),
        view(&backing, 4, 12, RIGHTS),
    ]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(
        invoke(&mut thread, GUEST_BASE, &mut bytes, flags::WRITE).status,
        MemoryStatus::Success as u32
    );
    assert_eq!(thread.policy.checked, [(GUEST_BASE, 8)]);
    assert_eq!(snapshot(&backing, 8), bytes);
}

#[test]
fn later_byte_permission_failure_preserves_completed_store_prefix() {
    let backing = backing();
    let readonly = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let domain = domain(vec![
        view(&backing, 0, SCA_BYTES, RIGHTS),
        view(&backing, SCA_BYTES, SCA_BYTES, readonly),
    ]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [0x36, 0x79];
    let result = invoke(
        &mut thread,
        GUEST_BASE + (SCA_BYTES - 1) as u64,
        &mut bytes,
        flags::WRITE,
    );
    assert_eq!(result.status, MemoryStatus::Permission as u32);
    assert_eq!(result.fault_kind, result.status);
    assert_eq!(result.fault_address, GUEST_BASE + SCA_BYTES as u64);
    assert_eq!(result.fault_pc, TEST_PC);
    assert_eq!(result.completed, 1);
    let actual = snapshot(&backing, SCA_BYTES + 1);
    assert_eq!(actual[SCA_BYTES - 1], 0x36);
    assert_eq!(actual[SCA_BYTES], 0);
    assert_eq!(
        thread.policy.checked,
        [(GUEST_BASE + (SCA_BYTES - 1) as u64, 1)]
    );
}

#[test]
fn denied_later_read_only_changes_private_staging_prefix() {
    let backing = backing();
    let noaccess = AccessPermissions {
        readable: false,
        writable: false,
        executable: false,
    };
    let domain = domain(vec![
        view(&backing, 0, SCA_BYTES, RIGHTS),
        view(&backing, SCA_BYTES, SCA_BYTES, noaccess),
    ]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [0xa5; 2];
    let result = invoke(
        &mut thread,
        GUEST_BASE + (SCA_BYTES - 1) as u64,
        &mut bytes,
        0,
    );
    assert_eq!(result.status, MemoryStatus::Permission as u32);
    assert_eq!(result.completed, 1);
    assert_eq!(bytes, [0, 0xa5]);
}

#[test]
fn controlled_tag_fault_clears_other_reservation_and_releases_writer_gate() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut observer = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    domain
        .system
        .reservations
        .load(&mut observer.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    let mut writer = domain.thread(Policy {
        reject: Some(GUEST_BASE),
        ..Policy::default()
    });
    let mut bytes = [0x6b];
    let fault = invoke(
        &mut writer,
        GUEST_BASE,
        &mut bytes,
        flags::WRITE | flags::TAG_CHECKED,
    );
    assert_eq!(fault.status, MemoryStatus::TagCheck as u32);
    assert_eq!(fault.completed, 0);
    assert_eq!(snapshot(&backing, 1), [0]);
    let conditional = domain
        .system
        .reservations
        .store(&mut observer.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    assert_eq!(conditional, monitor::ConditionalWrite::Failed);
    writer.policy_mut().reject = None;
    assert_eq!(
        invoke(&mut writer, GUEST_BASE, &mut bytes, flags::WRITE).status,
        MemoryStatus::Success as u32
    );
    assert_eq!(snapshot(&backing, 1), bytes);
    assert!(domain.check_execution().is_ok());
}

#[test]
fn retirement_rejects_access_and_invalidates_reserved_mapping() {
    let backing = backing();
    let mapping = view(&backing, 0, STORAGE_BYTES, RIGHTS);
    let domain = domain(vec![Arc::clone(&mapping)]);
    let mut thread = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    domain
        .system
        .reservations
        .load(&mut thread.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    domain.retire(&mapping).unwrap();
    assert!(!mapping.is_current());
    assert!(matches!(
        domain.system.reservations.store(
            &mut thread.reservation,
            &access,
            || Ok::<_, MemoryStatus>(())
        ),
        Err(monitor::AccessError::Monitor(
            monitor::MonitorError::DeadMapping
        ))
    ));
    let mut bytes = [0];
    assert_eq!(
        invoke(&mut thread, GUEST_BASE, &mut bytes, 0).status,
        MemoryStatus::Translation as u32
    );
}

#[test]
fn discontiguous_physical_views_and_overlapping_guest_views_decline() {
    let backing = backing();
    let first = view(&backing, 0, 4, RIGHTS);
    let discontiguous =
        MemoryView::new(Arc::clone(&backing), GUEST_BASE + 4, 16, 12, RIGHTS).unwrap();
    let domain = domain(vec![Arc::clone(&first), discontiguous]);
    let mut thread = domain.thread(Policy::default());
    let mut bytes = [0x3d; 8];
    assert_eq!(
        invoke(&mut thread, GUEST_BASE, &mut bytes, flags::WRITE).status,
        MemoryStatus::Unsupported as u32
    );
    assert_eq!(snapshot(&backing, 8), [0; 8]);
    assert!(
        MemoryDomain::new(
            MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
            vec![
                (first, ATTRIBUTES),
                (view(&backing, 2, 4, RIGHTS), ATTRIBUTES)
            ],
            TargetCpu::Baseline,
        )
        .is_err()
    );
}

fn in_system(system: &Arc<MemorySystem>, views: Vec<Arc<MemoryView>>) -> Arc<MemoryDomain> {
    MemoryDomain::new(
        Arc::clone(system),
        views.into_iter().map(|view| (view, ATTRIBUTES)).collect(),
        TargetCpu::detect(),
    )
    .unwrap()
}

#[test]
fn shared_backing_writer_invalidates_reservations_across_address_spaces() {
    let physical = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let first = in_system(&system, vec![view(&physical, 0, STORAGE_BYTES, RIGHTS)]);
    let alias_base = GUEST_BASE * 2;
    let alias =
        MemoryView::new(Arc::clone(&physical), alias_base, 0, STORAGE_BYTES, RIGHTS).unwrap();
    let second = in_system(&system, vec![alias]);
    let mut observer = first.thread(Policy::default());
    let access = reservation_access(&first, 0);
    system
        .reservations
        .load(&mut observer.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    let mut writer = second.thread(Policy::default());
    let mut bytes = [0x43];
    assert_eq!(
        invoke(&mut writer, alias_base, &mut bytes, flags::WRITE).status,
        MemoryStatus::Success as u32
    );
    assert_eq!(
        system
            .reservations
            .store(
                &mut observer.reservation,
                &access,
                || Ok::<_, MemoryStatus>(())
            )
            .unwrap(),
        monitor::ConditionalWrite::Failed
    );
    assert_eq!(snapshot(&physical, 1), bytes);
}

#[test]
fn conflicting_system_cannot_register_a_live_physical_backing() {
    let physical = backing();
    let first_system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let second_system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    let first = in_system(&first_system, vec![Arc::clone(&mapping)]);
    let same_system_snapshot = in_system(&first_system, vec![Arc::clone(&mapping)]);
    assert!(matches!(
        MemoryDomain::new(
            Arc::clone(&second_system),
            vec![(Arc::clone(&mapping), ATTRIBUTES)],
            TargetCpu::Baseline
        ),
        Err(MemoryStatus::Domain)
    ));
    drop(first_system);
    drop(first);
    assert!(matches!(
        MemoryDomain::new(
            Arc::clone(&second_system),
            vec![(Arc::clone(&mapping), ATTRIBUTES)],
            TargetCpu::Baseline
        ),
        Err(MemoryStatus::Domain)
    ));
    drop(same_system_snapshot);
    assert!(
        MemoryDomain::new(
            second_system,
            vec![(mapping, ATTRIBUTES)],
            TargetCpu::Baseline
        )
        .is_ok()
    );
}

#[test]
fn retirement_reaches_reservations_from_every_snapshot_of_the_same_view() {
    let physical = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    let first = in_system(&system, vec![Arc::clone(&mapping)]);
    let second = in_system(&system, vec![Arc::clone(&mapping)]);
    let alias = in_system(&system, vec![view(&physical, 0, STORAGE_BYTES, RIGHTS)]);
    let mut observer = second.thread(Policy::default());
    let original = reservation_access(&second, 0);
    system
        .reservations
        .load(&mut observer.reservation, &original, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    first.retire(&mapping).unwrap();
    let alias_access = reservation_access(&alias, 0);
    let result = system
        .reservations
        .store(&mut observer.reservation, &alias_access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    assert_eq!(result, monitor::ConditionalWrite::Failed);
}

#[test]
fn one_view_generation_cannot_change_attributes_between_live_snapshots() {
    let physical = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    let original = in_system(&system, vec![Arc::clone(&mapping)]);
    let changed = MappingAttributes {
        tagged: !ATTRIBUTES.tagged,
        ..ATTRIBUTES
    };
    assert!(matches!(
        MemoryDomain::new(
            Arc::clone(&system),
            vec![(Arc::clone(&mapping), changed)],
            TargetCpu::Baseline
        ),
        Err(MemoryStatus::InvalidRequest)
    ));
    let unchanged = in_system(&system, vec![mapping]);
    assert!(Arc::ptr_eq(
        &original.registered_views()[0].monitor,
        &unchanged.registered_views()[0].monitor
    ));
}

#[test]
fn retiring_an_unregistered_view_declines_without_mutation() {
    let physical = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let mapping = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    let original = in_system(&system, vec![mapping]);
    let unregistered = view(&physical, 0, STORAGE_BYTES, RIGHTS);
    assert_eq!(
        original.retire(&unregistered),
        Err(MemoryStatus::InvalidRequest)
    );
    assert!(unregistered.is_current());
    assert!(original.registered_views()[0].view.is_current());
}

#[test]
fn platform_and_abi_declines_preserve_existing_local_reservation() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut thread = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    for unavailable in [true, false] {
        domain
            .system
            .reservations
            .load(&mut thread.reservation, &access, || {
                Ok::<_, MemoryStatus>(())
            })
            .unwrap();
        thread.policy_mut().unavailable = unavailable;
        let mut staging = [0x7b; 3];
        let result = invoke(&mut thread, GUEST_BASE, &mut staging, flags::WRITE);
        assert_eq!(
            result.status,
            if unavailable {
                MemoryStatus::Unsupported
            } else {
                MemoryStatus::InvalidRequest
            } as u32
        );
        assert_eq!(result.completed, 0);
        assert_eq!(snapshot(&backing, 3), [0; 3]);
        thread.policy_mut().unavailable = false;
        assert_eq!(
            domain
                .system
                .reservations
                .store(&mut thread.reservation, &access, || Ok::<_, MemoryStatus>(
                    ()
                )),
            Ok(monitor::ConditionalWrite::Stored(()))
        );
    }
}

#[test]
fn local_native_fault_record_clears_reservation_at_invocation_return() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut thread = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    domain
        .system
        .reservations
        .load(&mut thread.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    // SAFETY: the callback only records a local fault, retaining no pointers.
    unsafe {
        thread.with_view(|context| {
            context.record(MemoryStatus::Alignment, GUEST_BASE + 1, TEST_PC, 0)
        });
    }
    assert_eq!(
        domain.system.reservations.store(
            &mut thread.reservation,
            &access,
            || Ok::<_, MemoryStatus>(())
        ),
        Ok(monitor::ConditionalWrite::Failed)
    );
    assert_eq!(snapshot(&backing, 1), [0]);
}

#[test]
fn crossing_quadword_split_requires_explicit_predicated_sve_or_asimd() {
    for descriptor in [
        0,
        flags::SME,
        flags::SME | flags::SVE_PREDICATED,
        flags::SVE_PREDICATED,
        flags::ASIMD,
    ] {
        let backing = backing();
        let readonly = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let domain = domain(vec![
            view(&backing, 0, 11, RIGHTS),
            view(&backing, 11, 21, readonly),
        ]);
        let mut thread = domain.thread(Policy::default());
        let mut bytes = [0x63; 16];
        let result = invoke(
            &mut thread,
            GUEST_BASE + 8,
            &mut bytes,
            flags::WRITE | descriptor,
        );
        let special = descriptor & flags::SME == 0
            && descriptor & (flags::SVE_PREDICATED | flags::ASIMD) != 0;
        assert_eq!(result.status, MemoryStatus::Permission as u32);
        assert_eq!(result.completed, if special { 0 } else { 3 });
        assert_eq!(
            result.fault_address,
            GUEST_BASE + if special { 8 } else { 11 }
        );
        assert_eq!(
            &snapshot(&backing, 16)[8..11],
            if special { &[0; 3] } else { &[0x63; 3] }
        );
    }
}

#[test]
fn raw_reached_part_translation_precedes_permissions_and_retains_prefix() {
    use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
    for tbi in [false, true] {
        let backing = backing();
        let denied = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let views = vec![
            MemoryView::new(backing.clone(), 0xfff0, 0, 16, RIGHTS).unwrap(),
            MemoryView::new(backing.clone(), 0x10000, 16, 16, denied).unwrap(),
        ];
        let domain = domain(views);
        let controls = MemoryControls::new(
            LowerAddressProfile::new(16, tbi).unwrap(),
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        );
        let mut thread = domain.thread(controls);
        let mut staging = [0x7c; 2];
        let raw = 0xffff | if tbi { 0xa500_0000_0000_0000 } else { 0 };
        let request = MemoryRequest {
            address: raw,
            data: staging.as_mut_ptr(),
            bytes: 2,
            flags: flags::WRITE,
            pc: TEST_PC,
        };
        unsafe {
            thread.with_view(|context| {
                assert_eq!(
                    (context.callback)(context, &request),
                    MemoryStatus::Translation as u32
                );
                assert_eq!(context.completed_bytes, 1);
                assert_eq!(context.fault_address, raw + 1);
                assert_eq!(context.fault_pc, TEST_PC);
            });
        }
        assert_eq!(snapshot(&backing, 17)[15..17], [0x7c, 0]);
    }
}

#[test]
fn fault_settlement_preserves_declines_and_clears_selected_architectural_faults() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut thread = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    for status in [
        MemoryStatus::Translation,
        MemoryStatus::Permission,
        MemoryStatus::Alignment,
        MemoryStatus::StackAlignment,
        MemoryStatus::TagCheck,
        MemoryStatus::Unsupported,
        MemoryStatus::InvalidRequest,
    ] {
        domain
            .system
            .reservations
            .load(&mut thread.reservation, &access, || {
                Ok::<_, MemoryStatus>(())
            })
            .unwrap();
        thread.settle_fault(status).unwrap();
        let outcome = domain
            .system
            .reservations
            .store(&mut thread.reservation, &access, || {
                Ok::<_, MemoryStatus>(())
            })
            .unwrap();
        assert_eq!(
            outcome,
            if is_guest_fault(status as u32) {
                monitor::ConditionalWrite::Failed
            } else {
                monitor::ConditionalWrite::Stored(())
            }
        );
    }
}

#[test]
fn sme_crossing_prefix_invalidates_only_bytes_actually_written() {
    let backing = backing();
    let readonly = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let domain = MemoryDomain::new(
        system.clone(),
        vec![
            (view(&backing, 0, 11, RIGHTS), ATTRIBUTES),
            (view(&backing, 11, 21, readonly), ATTRIBUTES),
        ],
        TargetCpu::detect(),
    )
    .unwrap();
    let mut writer = domain.thread(Policy::default());
    let mut touched = domain.thread(Policy::default());
    let mut untouched = domain.thread(Policy::default());
    let touched_access = reservation_access(&domain, 10);
    let untouched_access = monitor::Access::new(
        backing.clone(),
        domain.registered_views()[1].monitor.clone(),
        16,
        1,
        monitor::Shape::Scalar,
    )
    .unwrap();
    system
        .reservations
        .load(&mut touched.reservation, &touched_access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    system
        .reservations
        .load(&mut untouched.reservation, &untouched_access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    let mut bytes = [0x5e; 16];
    let result = invoke(
        &mut writer,
        GUEST_BASE + 8,
        &mut bytes,
        flags::WRITE | flags::SME,
    );
    assert_eq!(result.completed, 3);
    assert_eq!(
        system
            .reservations
            .store(&mut touched.reservation, &touched_access, || Ok::<
                _,
                MemoryStatus,
            >(
                ()
            ))
            .unwrap(),
        monitor::ConditionalWrite::Failed
    );
    assert_eq!(
        system
            .reservations
            .store(&mut untouched.reservation, &untouched_access, || Ok::<
                _,
                MemoryStatus,
            >(
                ()
            ))
            .unwrap(),
        monitor::ConditionalWrite::Stored(())
    );
}

#[test]
fn each_wrapping_raw_part_is_translated_in_its_own_regime() {
    struct WrappingPolicy;
    impl DataPolicy for WrappingPolicy {
        fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
            Ok(())
        }
        fn translate(&self, address: u64) -> Result<u64, MemoryStatus> {
            Ok(address & 0xffff)
        }
        fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
            Ok(())
        }
    }
    let backing = backing();
    let domain = domain(vec![
        MemoryView::new(backing.clone(), 0xfff0, 0, 16, RIGHTS).unwrap(),
        MemoryView::new(backing.clone(), 0, 16, 16, RIGHTS).unwrap(),
    ]);
    let mut thread = domain.thread(WrappingPolicy);
    let mut staging = [0x2d, 0x7b];
    let request = MemoryRequest {
        address: u64::MAX,
        data: staging.as_mut_ptr(),
        bytes: 2,
        flags: flags::WRITE,
        pc: TEST_PC,
    };
    unsafe {
        thread.with_view(|context| {
            assert_eq!(
                (context.callback)(context, &request),
                MemoryStatus::Success as u32
            );
            assert_eq!(context.completed_bytes, 2);
        });
    }
    assert_eq!(snapshot(&backing, 17)[15..17], staging);
}

#[test]
fn local_stack_fault_keeps_named_provenance_and_clears_selected_reservation() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let mut thread = domain.thread(Policy::default());
    let access = reservation_access(&domain, 0);
    domain
        .system
        .reservations
        .load(&mut thread.reservation, &access, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    unsafe {
        thread.with_view(|context| {
            context.record(MemoryStatus::StackAlignment, GUEST_BASE + 1, TEST_PC, 0);
            assert_eq!(context.fault_kind, 8);
            assert_eq!(context.fault_address, GUEST_BASE + 1);
            assert_eq!(context.fault_pc, TEST_PC);
            assert_eq!(context.completed_bytes, 0);
        });
    }
    assert_eq!(
        domain.system.reservations.store(
            &mut thread.reservation,
            &access,
            || Ok::<_, MemoryStatus>(())
        ),
        Ok(monitor::ConditionalWrite::Failed)
    );
    assert_eq!(snapshot(&backing, 1), [0]);
}

#[test]
fn exact_pair_and_asimd_quantity_table_preserves_mem_branch_order() {
    let cases: &[(usize, usize, u32, &[usize], bool)] = &[
        (0, 16, flags::ASIMD, &[8, 8], false),
        (8, 16, flags::ASIMD, &[8, 8], false),
        (0, 16, flags::ASIMD | flags::PAIR, &[8, 8], true),
        (8, 16, flags::ASIMD | flags::PAIR, &[8, 8], true),
        (0, 32, flags::ASIMD | flags::PAIR, &[8, 8, 8, 8], false),
        (8, 32, flags::ASIMD | flags::PAIR, &[8, 8, 8, 8], false),
        (4, 8, flags::PAIR, &[8], true),
        (12, 8, flags::PAIR, &[4, 4], false),
        (0, 16, flags::PAIR, &[16], true),
        (8, 16, flags::PAIR, &[8, 8], false),
        (0, 16, flags::SVE_PREDICATED, &[16], false),
        (8, 16, flags::SVE_PREDICATED, &[8, 8], false),
        (8, 16, flags::SME, &[1; 16], false),
    ];
    for (residue, bytes, descriptor, widths, retains_pair) in cases {
        let parts =
            AccessParts::new(GUEST_BASE + *residue as u64, *bytes, *descriptor).collect::<Vec<_>>();
        assert_eq!(parts.iter().map(|p| p.bytes).collect::<Vec<_>>(), *widths);
        assert!(
            parts
                .iter()
                .all(|p| (p.flags & flags::PAIR != 0) == *retains_pair)
        );
        assert!(
            parts
                .iter()
                .all(|p| (p.address as usize & 15) + p.bytes <= 16)
        );
    }
    for (bytes, descriptor) in [
        (16, flags::ASIMD),
        (16, flags::ASIMD | flags::PAIR),
        (32, flags::ASIMD | flags::PAIR),
        (16, flags::PAIR),
    ] {
        for residue in [1, 3, 5, 7, 9, 11, 13, 15] {
            let parts =
                AccessParts::new(GUEST_BASE + residue, bytes, descriptor).collect::<Vec<_>>();
            assert_eq!(parts.len(), bytes);
            assert!(parts.iter().all(|p| p.bytes == 1 && p.flags == descriptor));
        }
    }
}

#[test]
fn aligned_asimd_first_split_preserves_store_prefix_while_sve_lse2_combines() {
    for descriptor in [
        flags::ASIMD,
        flags::ASIMD | flags::PAIR,
        flags::SVE_PREDICATED,
        flags::PAIR,
    ] {
        let physical = backing();
        let readonly = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let domain = domain(vec![
            view(&physical, 0, 8, RIGHTS),
            view(&physical, 8, 24, readonly),
        ]);
        let mut thread = domain.thread(Policy::default());
        let mut data = [0x57; 16];
        let outcome = invoke(
            &mut thread,
            GUEST_BASE,
            &mut data,
            flags::WRITE | descriptor,
        );
        let prefix = if descriptor & flags::ASIMD != 0 { 8 } else { 0 };
        assert_eq!(outcome.status, MemoryStatus::Permission as u32);
        assert_eq!(outcome.completed, prefix);
        assert_eq!(outcome.fault_address, GUEST_BASE + prefix);
        assert_eq!(outcome.fault_pc, TEST_PC);
        assert_eq!(
            &snapshot(&physical, 16)[..8],
            if prefix == 8 { &[0x57; 8] } else { &[0; 8] }
        );
        if prefix == 8 {
            assert_eq!(thread.policy.checked_flags, [flags::WRITE | descriptor]);
        }
    }
}

#[test]
fn pair_half_quantity_is_checked_before_any_byte_and_not_family_split() {
    for (address, width, prefix_boundary) in [(GUEST_BASE + 8, 16, 11), (GUEST_BASE + 12, 8, 14)] {
        let physical = backing();
        let readonly = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let domain = domain(vec![
            view(&physical, 0, prefix_boundary, RIGHTS),
            view(&physical, prefix_boundary, 32 - prefix_boundary, readonly),
        ]);
        let mut thread = domain.thread(Policy::default());
        let mut data = vec![0x38; width];
        let result = invoke(&mut thread, address, &mut data, flags::WRITE | flags::PAIR);
        assert_eq!(result.status, MemoryStatus::Permission as u32);
        assert_eq!(result.completed, 0);
        assert_eq!(result.fault_address, address);
        assert!(snapshot(&physical, 32).iter().all(|b| *b == 0));
    }
}

#[test]
fn every_wide_asimd_residue_executes_on_declared_baseline_without_wide_host_caps() {
    for bytes in [16, 32] {
        for residue in 0..16 {
            let physical = backing();
            let domain = MemoryDomain::new(
                MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
                vec![(view(&physical, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
                TargetCpu::Baseline,
            )
            .unwrap();
            let mut thread = domain.thread(Policy::default());
            let descriptor = flags::ASIMD | if bytes == 32 { flags::PAIR } else { 0 };
            let address = GUEST_BASE + 16 + residue as u64;
            let mut expected = (0..bytes).map(|i| (i + 1) as u8).collect::<Vec<_>>();
            let written = invoke(
                &mut thread,
                address,
                &mut expected,
                descriptor | flags::WRITE,
            );
            assert_eq!(written.status, MemoryStatus::Success as u32);
            assert_eq!(written.completed, bytes as u64);
            let mut actual = vec![0xa5; bytes];
            assert_eq!(
                invoke(&mut thread, address, &mut actual, descriptor).status,
                MemoryStatus::Success as u32
            );
            assert_eq!(actual, expected);
            let mut full = vec![0; STORAGE_BYTES];
            full[16 + residue..16 + residue + bytes].copy_from_slice(&expected);
            assert_eq!(snapshot(&physical, STORAGE_BYTES), full);
        }
    }
}

#[test]
fn asimd32_prefix_and_descriptor_clear_do_not_touch_later_reservation_granules() {
    let physical = backing();
    let readonly = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let domain = MemoryDomain::new(
        system.clone(),
        vec![
            (view(&physical, 0, 8, RIGHTS), ATTRIBUTES),
            (view(&physical, 8, STORAGE_BYTES - 8, readonly), ATTRIBUTES),
        ],
        TargetCpu::Baseline,
    )
    .unwrap();
    let mut writer = domain.thread(Policy::default());
    let mut touched = domain.thread(Policy::default());
    let mut later = domain.thread(Policy::default());
    let first = reservation_access(&domain, 0);
    let future = monitor::Access::new(
        physical.clone(),
        domain.registered_views()[1].monitor.clone(),
        16,
        1,
        monitor::Shape::Scalar,
    )
    .unwrap();
    system
        .reservations
        .load(&mut touched.reservation, &first, || {
            Ok::<_, MemoryStatus>(())
        })
        .unwrap();
    system
        .reservations
        .load(
            &mut later.reservation,
            &future,
            || Ok::<_, MemoryStatus>(()),
        )
        .unwrap();
    let mut data = [0x75; 32];
    let result = invoke(
        &mut writer,
        GUEST_BASE,
        &mut data,
        flags::ASIMD | flags::PAIR | flags::WRITE,
    );
    assert_eq!(result.status, MemoryStatus::Permission as u32);
    assert_eq!(result.completed, 8);
    assert_eq!(result.fault_address, GUEST_BASE + 8);
    assert_eq!(writer.policy.checked_flags, [flags::ASIMD | flags::WRITE]);
    assert_eq!(
        system
            .reservations
            .store(&mut touched.reservation, &first, || Ok::<_, MemoryStatus>(
                ()
            ))
            .unwrap(),
        monitor::ConditionalWrite::Failed
    );
    assert_eq!(
        system
            .reservations
            .store(
                &mut later.reservation,
                &future,
                || Ok::<_, MemoryStatus>(())
            )
            .unwrap(),
        monitor::ConditionalWrite::Stored(())
    );
    assert!(
        snapshot(&physical, STORAGE_BYTES)[8..]
            .iter()
            .all(|b| *b == 0)
    );
}

#[test]
fn small_combined_pair_read_still_requires_atomic16_when_it_crosses_host8() {
    let physical = backing();
    let domain = MemoryDomain::new(
        MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap(),
        vec![(view(&physical, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
        TargetCpu::Baseline,
    )
    .unwrap();
    let mut thread = domain.thread(Policy::default());
    let mut data = [0xa5; 8];
    let result = invoke(&mut thread, GUEST_BASE + 4, &mut data, flags::PAIR);
    assert_eq!(result.status, MemoryStatus::Unsupported as u32);
    assert_eq!(result.completed, 0);
    assert_eq!(data, [0xa5; 8]);
}

// Exclusive service descendant proofs use the existing family storage/monitor fixture.
use stela_compiler::context::memory::{
    MemoryOperationClass, MemoryOrder,
    exclusive::{EXCLUSIVE_FAILED, ExclusiveData, ExclusiveOperation, ExclusiveShape},
};

#[derive(Default)]
struct ExclusivePolicy {
    unavailable: bool,
    reject_tag: bool,
    checked: usize,
    validated: Option<std::sync::mpsc::Sender<()>>,
    block: Option<(std::sync::mpsc::Sender<()>, Arc<std::sync::Barrier>)>,
}

impl DataPolicy for ExclusivePolicy {
    fn validate_operation_execution(
        &self,
        class: MemoryOperationClass,
    ) -> Result<(), MemoryStatus> {
        if !self.unavailable && class == MemoryOperationClass::Exclusive {
            Ok(())
        } else {
            Err(MemoryStatus::Unsupported)
        }
    }
    fn validate_execution(&self, required: u32) -> Result<(), MemoryStatus> {
        if let Some(validated) = &self.validated {
            validated.send(()).unwrap();
        }
        if required & !flags::KNOWN == 0 {
            Ok(())
        } else {
            Err(MemoryStatus::InvalidRequest)
        }
    }
    fn translate(&self, raw: u64) -> Result<u64, MemoryStatus> {
        Ok(raw)
    }
    fn check(&mut self, _access: DataAccess<'_>) -> Result<(), MemoryStatus> {
        self.checked += 1;
        if let Some((entered, release)) = self.block.take() {
            entered.send(()).unwrap();
            release.wait();
        }
        if self.reject_tag {
            Err(MemoryStatus::TagCheck)
        } else {
            Ok(())
        }
    }
}

fn exclusive_bound(
    domain: &Arc<MemoryDomain>,
) -> (
    MemoryThread<ExclusivePolicy>,
    crate::system::events::EventEndpoint,
    crate::system::events::EventDomain,
) {
    let events = crate::system::events::EventDomain::new();
    let endpoint = events.register(false, None).unwrap();
    let mut thread = domain.thread(ExclusivePolicy::default());
    thread.bind_events(&endpoint.producer()).unwrap();
    thread.check_event_endpoint(&endpoint).unwrap();
    (thread, endpoint, events)
}

fn exclusive_data(op: ExclusiveOperation, shape: ExclusiveShape, value: u128) -> ExclusiveData {
    ExclusiveData {
        operation: op as u32,
        order: MemoryOrder::Relaxed as u32,
        shape: shape as u32,
        status: 0,
        value: [value as u64, (value >> u64::BITS) as u64],
    }
}

fn exclusive_invoke(
    thread: &mut MemoryThread<ExclusivePolicy>,
    address: u64,
    bytes: u32,
    data: &mut ExclusiveData,
    extra: u32,
) -> (MemoryStatus, u64, u64, u64) {
    let request = MemoryRequest {
        address,
        data: std::ptr::from_mut(data).cast(),
        bytes,
        flags: flags::EXCLUSIVE | extra,
        pc: TEST_PC,
    };
    let mut observed = (MemoryStatus::Success, 0, address, TEST_PC);
    // SAFETY: actual private aligned payload and disjoint valid ABI objects;
    // the fixture retains stable coherent native storage and the bound PE owner.
    let finalized = unsafe {
        thread.with_checked_view(|view| {
            let status = (view.callback)(view, &request);
            observed = (
                MemoryStatus::from_code(status).unwrap(),
                view.completed_bytes,
                view.fault_address,
                view.fault_pc,
            );
            observed
        })
    };
    match finalized {
        Ok(result) => result,
        Err(status) => (status, observed.1, observed.2, observed.3),
    }
}

fn exclusive_wait(
    endpoint: &mut crate::system::events::EventEndpoint,
    events: &crate::system::events::EventDomain,
) -> bool {
    use crate::system::access::{ExceptionLevel, Profile, SecurityState};
    use crate::system::events::{Context, EventInstruction, Outcome, RetireReason};
    let context = Context::new(
        Profile {
            current_el: ExceptionLevel::El0,
            security: SecurityState::NonSecure,
            el2_enabled: false,
            el3_present: false,
        },
        true,  // wfxt
        false, // twed
        false, // halted
        false, // n_twe
        false, // n_twi
    )
    .unwrap();
    let instruction =
        EventInstruction::decode(0xd503_205f, TEST_PC, &stela_compiler::GuestState::default())
            .unwrap();
    match endpoint
        .complete(
            events,
            instruction,
            context,
            false,
            || -> Result<u64, ()> { panic!("untimed WFE") },
        )
        .unwrap()
    {
        Outcome::Retired {
            reason: RetireReason::EventConsumed,
            ..
        } => true,
        Outcome::Trap(_) => false,
        other => panic!("unexpected WFE {other:?}"),
    }
}

#[test]
fn exclusive_service_layout_and_complete_25_matrix_reject_malformed_payloads() {
    use std::mem::{align_of, offset_of, size_of};
    use stela_compiler::context::memory::exclusive::*;
    assert_eq!(size_of::<ExclusiveData>(), EXCLUSIVE_DATA_BYTES);
    assert_eq!(align_of::<ExclusiveData>(), EXCLUSIVE_DATA_ALIGNMENT);
    assert_eq!(
        [
            offset_of!(ExclusiveData, operation),
            offset_of!(ExclusiveData, order),
            offset_of!(ExclusiveData, shape),
            offset_of!(ExclusiveData, status),
            offset_of!(ExclusiveData, value)
        ],
        [0, 4, 8, 12, 16]
    );
    let mut count = 0;
    for op in [
        ExclusiveOperation::Load,
        ExclusiveOperation::Store,
        ExclusiveOperation::Clear,
    ] {
        for shape in [ExclusiveShape::Scalar, ExclusiveShape::Pair] {
            for bytes in [0, 1, 2, 4, 8, 16, 32] {
                for order in [
                    MemoryOrder::Relaxed,
                    MemoryOrder::AcquireRcpc,
                    MemoryOrder::AcquireRcsc,
                    MemoryOrder::Release,
                    MemoryOrder::AcquireRelease,
                ] {
                    let mut data = exclusive_data(op, shape, 0);
                    data.order = order as u32;
                    let expected = if op == ExclusiveOperation::Clear {
                        bytes == 0
                            && shape == ExclusiveShape::Scalar
                            && order == MemoryOrder::Relaxed
                    } else {
                        shape.supports_width(bytes)
                            && match op {
                                ExclusiveOperation::Load => {
                                    matches!(order, MemoryOrder::Relaxed | MemoryOrder::AcquireRcsc)
                                }
                                ExclusiveOperation::Store => {
                                    matches!(order, MemoryOrder::Relaxed | MemoryOrder::Release)
                                }
                                _ => false,
                            }
                    };
                    assert_eq!(data.validate(bytes).is_some(), expected);
                    count += usize::from(expected);
                }
            }
        }
    }
    assert_eq!(count, 25);
    for field in 0..6 {
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        match field {
            0 => data.operation = u32::MAX,
            1 => data.order = u32::MAX,
            2 => data.shape = u32::MAX,
            3 => data.status = 1,
            4 => data.value[0] = 1,
            _ => data.value[1] = 1,
        }
        assert!(data.validate(4).is_none());
    }
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        1_u128 << 32,
    );
    assert!(store.validate(4).is_none());
    store.value = [0, 1];
    assert!(store.validate(8).is_none());
}

#[test]
fn exclusive_service_width4_load_store_clear_and_failed_store_are_real() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let (mut thread, mut endpoint, events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        0xaabbccdd,
    );
    store.order = MemoryOrder::Release as u32;
    let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
    assert_eq!(
        (result.0, result.1, store.status),
        (MemoryStatus::Success, 4, 0)
    );
    assert_eq!(&snapshot(&backing, 4), &0xaabbccdd_u32.to_le_bytes());
    assert!(exclusive_wait(&mut endpoint, &events));
    assert!(!exclusive_wait(&mut endpoint, &events));
    load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    load.order = MemoryOrder::AcquireRcsc as u32;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert_eq!(load.value, [0xaabbccdd, 0]);
    let mut clear = exclusive_data(ExclusiveOperation::Clear, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, 0, 0, &mut clear, 0).0,
        MemoryStatus::Success
    );
    assert!(!endpoint.is_set()); // local-only clear preserves the independent global mark.
    let checks = thread.policy.checked;
    store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        0x12345678,
    );
    let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
    assert_eq!(
        (result.0, result.1, store.status),
        (MemoryStatus::Success, 0, EXCLUSIVE_FAILED)
    );
    assert_eq!(thread.policy.checked, checks);
    assert!(endpoint.is_set());
    assert_eq!(&snapshot(&backing, 4), &0xaabbccdd_u32.to_le_bytes());
}

#[test]
fn exclusive_service_shared_same_value_aba_publication_invalidates_without_extra_owner() {
    let backing = backing();
    let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
    let first = MemoryDomain::new(
        system.clone(),
        vec![(view(&backing, 0, STORAGE_BYTES, RIGHTS), ATTRIBUTES)],
        TargetCpu::detect(),
    )
    .unwrap();
    let alias = MemoryView::new(
        backing.clone(),
        GUEST_BASE + 0x1000,
        0,
        STORAGE_BYTES,
        RIGHTS,
    )
    .unwrap();
    let second = MemoryDomain::new(
        system.clone(),
        vec![(alias, ATTRIBUTES)],
        TargetCpu::detect(),
    )
    .unwrap();
    let (mut thread, mut endpoint, events) = exclusive_bound(&first);
    for values in [&[0_u8; 4][..], &[1_u8; 4][..], &[0_u8; 4][..]] {
        let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        assert_eq!(
            exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
            MemoryStatus::Success
        );
        // SAFETY: source is disjoint private bytes and the shared system owns the retained raw backing.
        unsafe { system.publish(&backing, 0, values) }.unwrap();
        assert!(exclusive_wait(&mut endpoint, &events));
        let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 9);
        let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
        assert_eq!(
            (result.0, result.1, store.status),
            (MemoryStatus::Success, 0, 1)
        );
    }
    let mut ordinary = second.thread(Policy::default());
    let mut data = [0x73; 4];
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert_eq!(
        invoke(&mut ordinary, GUEST_BASE + 0x1000, &mut data, flags::WRITE).status,
        MemoryStatus::Success as u32
    );
    let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE).0,
        MemoryStatus::Success
    );
    assert_eq!(store.status, 1);
}

#[test]
fn exclusive_service_pair8_packed_and_store_guest_write_only_are_supported() {
    let backing = backing();
    let alias = MemoryView::new(
        backing.clone(),
        GUEST_BASE + 0x1000,
        0,
        STORAGE_BYTES,
        AccessPermissions {
            readable: false,
            ..RIGHTS
        },
    )
    .unwrap();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS), alias]);
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Pair, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 8, &mut load, 0).0,
        MemoryStatus::Success
    );
    let value = 0x89abcdef01234567_u64;
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Pair,
        u128::from(value),
    );
    assert_eq!(
        exclusive_invoke(
            &mut thread,
            GUEST_BASE + 0x1000,
            8,
            &mut store,
            flags::WRITE
        )
        .0,
        MemoryStatus::Success
    );
    assert_eq!(store.status, 0);
    assert_eq!(&snapshot(&backing, 8), &value.to_le_bytes());
    load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Pair, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 8, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert_eq!(load.value, [value, 0]);
}

#[test]
fn exclusive_service_faults_and_declines_preserve_all_payload_bytes() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    for (address, flags, expected) in [
        (GUEST_BASE + 15, 0, MemoryStatus::Alignment),
        (GUEST_BASE + 0x4000, 0, MemoryStatus::Translation),
        (GUEST_BASE, flags::PAIR, MemoryStatus::InvalidRequest),
        (GUEST_BASE, flags::ATOMIC, MemoryStatus::InvalidRequest),
        (GUEST_BASE, flags::ORDERED, MemoryStatus::InvalidRequest),
    ] {
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        let before = data;
        let result = exclusive_invoke(&mut thread, address, 4, &mut data, flags);
        assert_eq!(
            (result.0, result.1, result.2, result.3),
            (expected, 0, address, TEST_PC)
        );
        assert_eq!(data, before);
    }
    thread.policy.unavailable = true;
    let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    let before = data;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0).0,
        MemoryStatus::Unsupported
    );
    assert_eq!(data, before);
    let req = MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_flags: flags::EXCLUSIVE,
        required_host_caps: 0,
        required_profile: stela_compiler::context::memory::profile_requirements::NATIVE_ACCESS,
        required_sp_alignment: SpAlignmentRequirement::Any,
    };
    assert!(thread.prepare(req).is_err());
    thread.policy.unavailable = false;
    thread.policy.reject_tag = true;
    let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    let before = data;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, flags::TAG_CHECKED).0,
        MemoryStatus::TagCheck
    );
    assert_eq!(data, before);
    thread.policy.reject_tag = false;
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    thread.policy.reject_tag = true;
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        0xdeadbeef,
    );
    let before = store;
    assert_eq!(
        exclusive_invoke(
            &mut thread,
            GUEST_BASE,
            4,
            &mut store,
            flags::WRITE | flags::TAG_CHECKED
        )
        .0,
        MemoryStatus::TagCheck
    );
    assert_eq!(store, before);
    assert_eq!(snapshot(&backing, 4), [0; 4]);
    thread.policy.reject_tag = false;
    let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 9);
    let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
    assert_eq!(
        (result.0, result.1, store.status),
        (MemoryStatus::Success, 0, 1)
    );
    domain.system.failed.store(true, Ordering::Release);
    let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    let before = data;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0).0,
        MemoryStatus::Domain
    );
    assert_eq!(data, before);
}

fn exclusive_joined() -> (Arc<MemoryBacking>, Arc<MemoryDomain>, Arc<MemoryView>) {
    let backing = backing();
    let second = view(&backing, 2, STORAGE_BYTES - 2, RIGHTS);
    let alias = MemoryView::new(
        backing.clone(),
        GUEST_BASE + 0x1000,
        0,
        STORAGE_BYTES,
        RIGHTS,
    )
    .unwrap();
    let domain = domain(vec![view(&backing, 0, 2, RIGHTS), second.clone(), alias]);
    (backing, domain, second)
}

#[test]
fn exclusive_service_second_view_retirement_and_mapdead_gap_clear_actual_global_mark() {
    let (backing, domain, second) = exclusive_joined();
    let (mut thread, mut endpoint, events) = exclusive_bound(&domain);
    // Directed map-dead/view-live gap: actual first generation remains live,
    // so load must be caught by the final physical retirement invalidation.
    domain
        .system
        .reservations
        .revoke_mapping(&domain.registered_views()[1].monitor)
        .unwrap();
    assert!(second.is_current());
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert!(!endpoint.is_set());
    domain.retire(&second).unwrap();
    assert!(exclusive_wait(&mut endpoint, &events));
    let mut store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 7);
    assert_eq!(
        exclusive_invoke(
            &mut thread,
            GUEST_BASE + 0x1000,
            4,
            &mut store,
            flags::WRITE
        )
        .0,
        MemoryStatus::Success
    );
    assert_eq!(store.status, 1);
    assert_eq!(snapshot(&backing, 4), [0; 4]);
    load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE + 0x1000, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert_eq!(domain.retire(&second), Err(MemoryStatus::InvalidRequest));
    assert!(!endpoint.is_set());
    store = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 7);
    assert_eq!(
        exclusive_invoke(
            &mut thread,
            GUEST_BASE + 0x1000,
            4,
            &mut store,
            flags::WRITE
        )
        .0,
        MemoryStatus::Success
    );
    assert_eq!(store.status, 0);
    assert_eq!(&snapshot(&backing, 4), &7_u32.to_le_bytes());
}

#[test]
fn exclusive_service_stale_second_view_is_rechecked_inside_gate() {
    let (backing, domain, second) = exclusive_joined();
    let physical = domain.resolve(GUEST_BASE, 4, AccessKind::Read).unwrap();
    let access = monitor::Access::new(
        backing,
        domain.registered_views()[0].monitor.clone(),
        0,
        4,
        monitor::Shape::Scalar,
    )
    .unwrap();
    domain.retire(&second).unwrap();
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    let mut native = false;
    let result = domain.system.reservations.load_with_scope(
        &mut thread.reservation,
        &access,
        monitor::ReservationScope::Global,
        || {
            physical.check_current()?;
            native = true;
            Ok::<_, MemoryStatus>(())
        },
    );
    assert_eq!(
        result,
        Err(monitor::AccessError::Memory(MemoryStatus::Domain))
    );
    assert!(!native);
}

#[test]
fn exclusive_service_inflight_load_refuses_retirement_until_original_finalization() {
    let (backing, domain, second) = exclusive_joined();
    let monitor = domain
        .registered_views()
        .into_iter()
        .find(|registered| Arc::ptr_eq(&registered.view, &second))
        .unwrap()
        .monitor;
    let generation = domain.generation().unwrap();
    let (mut thread, endpoint, events) = exclusive_bound(&domain);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let release = Arc::new(std::sync::Barrier::new(2));
    thread.policy.block = Some((entered_tx, release.clone()));
    let load = std::thread::spawn(move || {
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0);
        (thread, endpoint, events, result)
    });
    entered_rx.recv().unwrap();
    let d = domain.clone();
    let retiring = second.clone();
    let (refusal_tx, refusal_rx) = std::sync::mpsc::channel();
    let retire = std::thread::spawn(move || {
        refusal_tx.send(d.retire(&retiring)).unwrap();
    });
    // The actual native loan remains live inside the blocked original callback.
    // Service admission must refuse before waiting on the callback's monitor gate.
    let refusal = refusal_rx.recv_timeout(std::time::Duration::from_secs(2));
    // Always release and join the actual load before asserting, even if a broken
    // retirement path waited on its monitor gate instead of refusing admission.
    release.wait();
    let (mut thread, mut endpoint, events, result) = load.join().unwrap();
    retire.join().unwrap();
    assert_eq!(result.0, MemoryStatus::Success);
    assert_eq!(refusal.unwrap(), Err(MemoryStatus::Domain));
    assert!(second.is_current());
    assert!(monitor.is_live());
    assert_eq!(domain.generation().unwrap(), generation);
    assert!(!endpoint.is_set());
    // Original checked finalization released its actual loan. The same domain
    // may now retire the same view and invalidate the real alias reservation.
    domain.retire(&second).unwrap();
    assert!(!second.is_current());
    assert!(!monitor.is_live());
    assert_eq!(domain.generation().unwrap(), generation + 1);
    assert!(exclusive_wait(&mut endpoint, &events));
    assert!(!exclusive_wait(&mut endpoint, &events));
    let mut data = exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, 1);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE + 0x1000, 4, &mut data, flags::WRITE).0,
        MemoryStatus::Success
    );
    assert_eq!(data.status, 1);
    assert_eq!(snapshot(&backing, 4), [0; 4]);
}

#[test]
fn exclusive_service_contended_width4_has_one_actual_native_winner() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut joins = Vec::new();
    for value in [0x12345678_u128, 0x87654321] {
        let (mut thread, endpoint, events) = exclusive_bound(&domain);
        let barrier = barrier.clone();
        joins.push(std::thread::spawn(move || {
            let _owners = (endpoint, events);
            let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
            assert_eq!(
                exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
                MemoryStatus::Success
            );
            barrier.wait();
            let mut store =
                exclusive_data(ExclusiveOperation::Store, ExclusiveShape::Scalar, value);
            let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
            assert_eq!(result.0, MemoryStatus::Success);
            store.status
        }));
    }
    let statuses = joins
        .into_iter()
        .map(|j| j.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(statuses.iter().filter(|&&s| s == 0).count(), 1);
    let value = u32::from_le_bytes(snapshot(&backing, 4).try_into().unwrap());
    assert!([0x12345678, 0x87654321].contains(&value));
}

#[test]
fn exclusive_service_permission_and_raw_payload_fail_before_any_effect() {
    let backing = backing();
    let denied = AccessPermissions {
        writable: false,
        ..RIGHTS
    };
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, denied)]);
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    let mut store = exclusive_data(
        ExclusiveOperation::Store,
        ExclusiveShape::Scalar,
        0xfeedbeef,
    );
    let before = store;
    let result = exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut store, flags::WRITE);
    assert_eq!((result.0, result.1), (MemoryStatus::Permission, 0));
    assert_eq!(store, before);
    assert_eq!(thread.policy.checked, 0);
    for index in 0..6 {
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        match index {
            0 => data.operation = u32::MAX,
            1 => data.order = u32::MAX,
            2 => data.shape = u32::MAX,
            3 => data.status = 1,
            4 => data.value[0] = 1,
            _ => data.value[1] = 1,
        }
        let before = data;
        assert_eq!(
            exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut data, 0).0,
            MemoryStatus::InvalidRequest
        );
        assert_eq!(data, before);
    }
    let mut clear = exclusive_data(ExclusiveOperation::Clear, ExclusiveShape::Scalar, 0);
    let before = clear;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 0, &mut clear, 0).0,
        MemoryStatus::InvalidRequest
    );
    assert_eq!(clear, before);
    assert_eq!(snapshot(&backing, STORAGE_BYTES), vec![0; STORAGE_BYTES]);
}

#[test]
fn exclusive_service_poisoned_domain_refuses_retirement_before_mapping_effects() {
    let (backing, domain, second) = exclusive_joined();
    let monitor = domain
        .registered_views()
        .into_iter()
        .find(|registered| Arc::ptr_eq(&registered.view, &second))
        .unwrap()
        .monitor;
    let generation = domain.generation().unwrap();
    let (mut thread, endpoint, _events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    assert!(!endpoint.is_set());
    let before = snapshot(&backing, 4);
    domain.system.failed.store(true, Ordering::Release);
    assert_eq!(domain.retire(&second), Err(MemoryStatus::Domain));
    assert!(second.is_current());
    assert!(monitor.is_live());
    assert_eq!(domain.state.lock().unwrap().snapshot.generation, generation);
    assert!(!endpoint.is_set());
    assert_eq!(domain.retire(&second), Err(MemoryStatus::Domain));
    // Liveness is diagnostic only: the poisoned actual domain admits neither
    // native execution nor service mutation, and retains the original storage.
    assert!(domain.check_execution().is_err());
    assert!(domain.execution_loan().is_err());
    let mut declined = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    let untouched = declined;
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut declined, 0).0,
        MemoryStatus::Domain
    );
    assert_eq!(declined, untouched);
    assert_eq!(snapshot(&backing, 4), before);
    assert!(!endpoint.is_set());
}

#[test]
fn exclusive_service_shifted_relative_erg_geometry_declines_before_prefix_only_for_transfers() {
    let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
    // SAFETY: actual owner retains the complete allocation, including prefix.
    let raw = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let owner = Arc::new(Storage {
        pointer: raw,
        layout,
    });
    // SAFETY: shifted extent is live inside the real allocation and lifetime owner.
    let physical = unsafe {
        MemoryBacking::new(
            NonNull::new(raw.as_ptr().add(8)).unwrap(),
            STORAGE_BYTES - 8,
            RIGHTS,
            owner,
        )
    }
    .unwrap();
    let mapping = MemoryView::new(physical, GUEST_BASE + 8, 0, STORAGE_BYTES - 8, RIGHTS).unwrap();
    let domain = domain(vec![mapping]);
    let mut thread = domain.thread(ExclusivePolicy::default());
    let req = MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_flags: flags::EXCLUSIVE,
        required_host_caps: 0,
        required_profile: stela_compiler::context::memory::profile_requirements::NATIVE_ACCESS,
        required_sp_alignment: SpAlignmentRequirement::Any,
    };
    assert!(matches!(
        thread.prepare(req),
        Err(MemoryStatus::Unsupported)
    ));
    let ordinary = MemoryRequirements {
        required_flags: 0,
        ..req
    };
    assert!(thread.prepare(ordinary).is_ok());
    let clear = MemoryRequirements {
        required_profile: 0,
        ..req
    };
    assert!(thread.prepare(clear).is_ok());
    assert_eq!(thread.policy.checked, 0);
}

#[test]
fn exclusive_service_callback_fault_late_failure_cannot_escape_checked_finalization() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let (mut thread, endpoint, events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let release = Arc::new(std::sync::Barrier::new(2));
    let d = domain.clone();
    let release_writer = release.clone();
    let b = backing.clone();
    let writer = std::thread::spawn(move || {
        let range = monitor::WriteRange::new(b, 0, 4).unwrap();
        d.system
            .reservations
            .with_writer(&range, monitor::Invalidation::OnCommit, || {
                held_tx.send(()).unwrap();
                release_writer.wait();
                Ok::<_, MemoryStatus>(())
            })
            .unwrap();
    });
    held_rx.recv().unwrap();
    let (validated_tx, validated_rx) = std::sync::mpsc::channel();
    thread.policy.validated = Some(validated_tx);
    let fault = std::thread::spawn(move || {
        let _owners = (endpoint, events);
        let mut data = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
        let before = data;
        let result = exclusive_invoke(&mut thread, GUEST_BASE + 15, 4, &mut data, 0);
        (result, data, before)
    });
    // Failure becomes visible after the callback's initial owner health check,
    // while the old reservation's cleanup is behind the real writer gate.
    validated_rx.recv().unwrap();
    domain.system.failed.store(true, Ordering::Release);
    release.wait();
    writer.join().unwrap();
    let (result, data, before) = fault.join().unwrap();
    assert_eq!(
        (result.0, result.1, result.2, result.3),
        (MemoryStatus::Domain, 0, GUEST_BASE + 15, TEST_PC)
    );
    assert_eq!(data, before);
    assert_eq!(snapshot(&backing, 4), [0; 4]);
}

#[test]
fn exclusive_service_local_sp_fault_finalization_failure_discards_callback_result() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let (mut thread, _endpoint, _events) = exclusive_bound(&domain);
    let mut load = exclusive_data(ExclusiveOperation::Load, ExclusiveShape::Scalar, 0);
    assert_eq!(
        exclusive_invoke(&mut thread, GUEST_BASE, 4, &mut load, 0).0,
        MemoryStatus::Success
    );
    let mut original = None;
    // SAFETY: this source-bound local-emitter analogue writes only diagnostic
    // fields; it does not invoke native code or lend guest RAM references.
    let result = unsafe {
        thread.with_checked_view(|view| {
            view.record(MemoryStatus::StackAlignment, GUEST_BASE + 1, TEST_PC, 0);
            original = Some((
                view.fault_kind,
                view.fault_address,
                view.fault_pc,
                view.completed_bytes,
            ));
            domain.system.failed.store(true, Ordering::Release);
            42_u32
        })
    };
    assert_eq!(result, Err(MemoryStatus::Domain));
    assert_eq!(
        original,
        Some((
            MemoryStatus::StackAlignment as u32,
            GUEST_BASE + 1,
            TEST_PC,
            0
        ))
    );
    assert_eq!(snapshot(&backing, 4), [0; 4]);
}

#[test]
fn exclusive_service_dedicated_tag_entry_cannot_bypass_typed_class_preflight() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let controls = crate::memory::policy::MemoryControls::new(
        crate::memory::policy::LowerAddressProfile::new(48, false).unwrap(),
        false,
        false,
        false,
        crate::memory::policy::TagCheckFaultMode::Ignore,
        false,
    );
    let mut thread = domain.thread(controls);
    for class in [
        flags::ATOMIC,
        flags::ORDERED,
        flags::EXCLUSIVE,
        flags::ATOMIC | flags::ORDERED | flags::EXCLUSIVE,
    ] {
        let req = MemoryRequirements {
            required_pointer_arithmetic: None,
            required_address_checks: Default::default(),
            required_flags: class,
            required_host_caps: 0,
            required_profile: 0,
            required_sp_alignment: SpAlignmentRequirement::Any,
        };
        assert!(matches!(
            thread.prepare_tag(req, false),
            Err(MemoryStatus::InvalidRequest)
        ));
    }
}

mod checked_finalization;

#[test]
fn generic_data_and_tag_entries_refuse_every_separately_owned_m0_identity() {
    let backing = backing();
    let domain = domain(vec![view(&backing, 0, STORAGE_BYTES, RIGHTS)]);
    let controls = crate::memory::policy::MemoryControls::new(
        crate::memory::policy::LowerAddressProfile::new(48, false).unwrap(),
        false,
        false,
        false,
        crate::memory::policy::TagCheckFaultMode::Ignore,
        false,
    );
    let mut thread = domain.thread(controls);
    let ordinary = MemoryRequirements {
        required_profile: profile_requirements::NATIVE_ACCESS,
        ..Default::default()
    };
    assert!(thread.prepare(ordinary).is_ok());
    assert!(thread.prepare_tag(ordinary, false).is_ok());
    let before = snapshot(&backing, STORAGE_BYTES);
    for dedicated in [
        profile_requirements::M0_DEVICE_RAM_READ64,
        profile_requirements::M0_DEVICE_RAM_WRITE8_OR_PAIR,
        profile_requirements::M0_DEVICE_RAM_READ64_PAIR_NO_LSE2,
        profile_requirements::M0_DEVICE_RAM_SCALAR_LOAD,
    ] {
        for generic in [0, profile_requirements::NATIVE_ACCESS] {
            let requirements = MemoryRequirements {
                required_profile: dedicated | generic,
                ..Default::default()
            };
            assert_eq!(
                thread.prepare(requirements).err(),
                Some(MemoryStatus::Unsupported)
            );
            assert_eq!(
                thread.prepare_tag(requirements, false).err(),
                Some(MemoryStatus::Unsupported)
            );
        }
    }
    assert_eq!(snapshot(&backing, STORAGE_BYTES), before);
    assert!(thread.prepare(ordinary).is_ok());
    assert!(thread.prepare_tag(ordinary, false).is_ok());
}
