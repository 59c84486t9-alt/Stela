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
        if self.reject == Some(access.raw_address) {
            Err(MemoryStatus::TagCheck)
        } else {
            Ok(())
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
    let registered = &domain.views[0];
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
        &original.views[0].monitor,
        &unchanged.views[0].monitor
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
    assert!(original.views[0].view.is_current());
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
        domain.views[1].monitor.clone(),
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
