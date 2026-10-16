use super::super::{
    Arc, DataAccess, MappingAttributes, MemoryDomain, MemorySystem, access, monitor,
};
use super::*;
use crate::memory::backing::{AccessKind, AccessPermissions, MemoryBacking, MemoryView};
use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
use crate::memory::tags::{AllocationTag, TAG_GRANULE_BYTES};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;
use stela_compiler::TargetCpu;

const STORAGE_BYTES: usize = 64;
const GUEST_BASE: u64 = 0x4000;
const GUEST_PC: u64 = 0x1234_5678;
const ADDRESS_SPACE: u64 = 42;
const TAG: u8 = 7;
const RIGHTS: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};
const READONLY: AccessPermissions = AccessPermissions {
    writable: false,
    ..RIGHTS
};
const ATTRIBUTES: MappingAttributes = MappingAttributes {
    tagged: true,
    shareable: true,
};

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}

// SAFETY: owner retains raw storage and lends no byte references.
unsafe impl Send for Storage {}
// SAFETY: native memory accesses use one physical execution domain.
unsafe impl Sync for Storage {}

impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: this value owns its allocation and layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn controls(mode: TagCheckFaultMode) -> MemoryControls {
    MemoryControls::new(
        LowerAddressProfile::new(48, true).unwrap(),
        false,
        true,
        false,
        mode,
        false,
    )
}

fn tagged(address: u64, tag: u8) -> u64 {
    AllocationTag::new(tag).unwrap().apply_to_address(address)
}

fn backing(system: &MemorySystem) -> Arc<MemoryBacking> {
    let layout = Layout::from_size_align(STORAGE_BYTES, SCA_BYTES).unwrap();
    // SAFETY: valid nonempty layout retained by the raw lifetime owner.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let owner = Arc::new(Storage { pointer, layout });
    // SAFETY: owner pins coherent readable/writable RAM, without byte references.
    let backing = unsafe { MemoryBacking::new(pointer, STORAGE_BYTES, RIGHTS, owner) }.unwrap();
    let initial: Vec<_> = (0..STORAGE_BYTES).map(|index| index as u8 * 3).collect();
    // SAFETY: the private source is disjoint from the owned RAM, and all writes
    // go through `system`.
    unsafe { system.publish(&backing, 0, &initial) }.unwrap();
    for offset in (0..STORAGE_BYTES).step_by(TAG_GRANULE_BYTES) {
        backing
            .allocation_tags()
            .write(offset, AllocationTag::new(TAG).unwrap())
            .unwrap();
    }
    backing
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

fn domain(
    system: &Arc<MemorySystem>,
    views: Vec<Arc<MemoryView>>,
    target: TargetCpu,
) -> Arc<MemoryDomain> {
    MemoryDomain::new(
        Arc::clone(system),
        views.into_iter().map(|view| (view, ATTRIBUTES)).collect(),
        target,
    )
    .unwrap()
}

fn setup() -> (Arc<MemorySystem>, Arc<MemoryBacking>, Arc<MemoryDomain>) {
    let system = MemorySystem::new(16, 4).unwrap();
    let backing = backing(&system);
    let domain = domain(
        &system,
        vec![view(&backing, 0, STORAGE_BYTES, READONLY)],
        TargetCpu::Baseline,
    );
    (system, backing, domain)
}

fn snapshot(backing: &MemoryBacking) -> Vec<u8> {
    (0..STORAGE_BYTES)
        .map(|offset| {
            let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
            // SAFETY: exact synchronous raw reads have pinned host rights/lifetime.
            unsafe { access::read_part(pointer.as_ptr(), 1, TargetCpu::Baseline) }.unwrap() as u8
        })
        .collect()
}

type ReservationAccess = monitor::Access<MemoryBacking, MemoryView, MappingAttributes>;

fn reserve<P: DataPolicy>(thread: &mut MemoryThread<P>) -> ReservationAccess {
    let registered = &thread.domain.registered_views()[0];
    let access = monitor::Access::new(
        Arc::clone(registered.view.backing()),
        Arc::clone(&registered.monitor),
        0,
        1,
        monitor::Shape::Scalar,
    )
    .unwrap();
    thread
        .domain
        .system
        .reservations
        .load(&mut thread.reservation, &access, || Ok::<(), ()>(()))
        .unwrap();
    access
}

fn marked<P: DataPolicy>(thread: &mut MemoryThread<P>, access: &ReservationAccess) -> bool {
    matches!(
        thread
            .domain
            .system
            .reservations
            .store(&mut thread.reservation, access, || Ok::<(), ()>(()))
            .unwrap(),
        monitor::ConditionalWrite::Stored(())
    )
}

#[test]
fn actual_native_scalar_reads_zero_extend_and_preserve_ram_and_tags() {
    let (_, backing, domain) = setup();
    let original = snapshot(&backing);
    let mut thread = domain.thread(controls(TagCheckFaultMode::Synchronous));
    for bytes in [1, 2, 4, 8] {
        let mut expected = [0; SCA_BYTES];
        expected[..bytes as usize].copy_from_slice(&original[..bytes as usize]);
        assert_eq!(
            thread.read_scalar(tagged(GUEST_BASE, TAG), bytes, flags::TAG_CHECKED, GUEST_PC),
            Ok(u128::from_le_bytes(expected))
        );
    }
    let reader: &mut dyn MemoryReader = &mut thread;
    assert_eq!(reader.address_space(), None);
    assert_eq!(reader.validate_privilege(false), Ok(()));
    assert_eq!(
        reader.validate_privilege(true),
        Err(MemoryStatus::Unsupported)
    );
    assert_eq!(
        reader.read_scalar(tagged(GUEST_BASE, TAG), 8, flags::TAG_CHECKED, GUEST_PC),
        Ok(u64::from_le_bytes(original[..8].try_into().unwrap()).into())
    );
    assert_eq!(snapshot(&backing), original);
    for offset in (0..STORAGE_BYTES).step_by(TAG_GRANULE_BYTES) {
        assert_eq!(
            backing.allocation_tags().read(offset).unwrap(),
            AllocationTag::new(TAG).unwrap()
        );
    }
}

#[test]
fn policy_erased_reader_retains_explicit_address_space_binding() {
    let (system, backing, _) = setup();
    let domain = MemoryDomain::new_for_address_space(
        ADDRESS_SPACE,
        system,
        vec![(view(&backing, 0, STORAGE_BYTES, READONLY), ATTRIBUTES)],
        TargetCpu::Baseline,
    )
    .unwrap();
    let mut thread = domain.thread(controls(TagCheckFaultMode::Synchronous));
    let reader: &mut dyn MemoryReader = &mut thread;
    assert_eq!(reader.address_space(), Some(ADDRESS_SPACE));
    assert_eq!(reader.validate_privilege(false), Ok(()));
    assert_eq!(
        reader.validate_privilege(true),
        Err(MemoryStatus::Unsupported)
    );
    assert!(
        reader
            .read_scalar(tagged(GUEST_BASE, TAG), 8, flags::TAG_CHECKED, GUEST_PC)
            .is_ok()
    );
}

#[test]
fn incongruent_native_profile_declines_before_reading_and_preserves_reservation() {
    let (system, backing, _) = setup();
    let view = MemoryView::new(
        Arc::clone(&backing),
        GUEST_BASE + 1,
        0,
        STORAGE_BYTES,
        READONLY,
    )
    .unwrap();
    let domain = domain(&system, vec![view], TargetCpu::Baseline);
    let original = snapshot(&backing);
    let mut thread = domain.thread(controls(TagCheckFaultMode::Synchronous));
    let access = reserve(&mut thread);
    let address = tagged(GUEST_BASE + 1, TAG);
    assert_eq!(
        thread.read_scalar(address, 8, 0, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::Unsupported,
            address,
            pc: GUEST_PC,
            completed_bytes: 0,
        })
    );
    assert!(marked(&mut thread, &access));
    assert_eq!(snapshot(&backing), original);
}

#[test]
fn raw_logical_tag_reaches_real_memory_controls() {
    let (_, backing, domain) = setup();
    let mut thread = domain.thread(controls(TagCheckFaultMode::Synchronous));
    let address = tagged(GUEST_BASE, TAG - 1);
    assert_eq!(
        thread.read_scalar(address, 8, flags::TAG_CHECKED, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::TagCheck,
            address,
            pc: GUEST_PC,
            completed_bytes: 0,
        })
    );
    let original = snapshot(&backing);
    assert_eq!(
        thread.read_scalar(address, 8, 0, GUEST_PC),
        Ok(u64::from_le_bytes(original[..8].try_into().unwrap()).into())
    );
    assert_eq!(snapshot(&backing), original);
}

#[test]
fn contiguous_views_and_cross_sca_reads_use_existing_native_service() {
    let (system, backing, _) = setup();
    let domain = domain(
        &system,
        vec![
            view(&backing, 0, 4, READONLY),
            view(&backing, 4, STORAGE_BYTES - 4, READONLY),
        ],
        TargetCpu::Baseline,
    );
    let mut thread = domain.thread(controls(TagCheckFaultMode::Synchronous));
    let original = snapshot(&backing);
    for offset in [0, SCA_BYTES - 3] {
        assert_eq!(
            thread.read_scalar(
                tagged(GUEST_BASE + offset as u64, TAG),
                8,
                flags::TAG_CHECKED,
                GUEST_PC
            ),
            Ok(u64::from_le_bytes(original[offset..offset + 8].try_into().unwrap()).into())
        );
    }
    assert_eq!(snapshot(&backing), original);
}

#[test]
fn permission_and_translation_faults_retain_guest_source_and_private_prefix() {
    let (system, backing, _) = setup();
    let no_read = AccessPermissions {
        readable: false,
        ..READONLY
    };
    let domain = domain(
        &system,
        vec![
            view(&backing, 0, SCA_BYTES, READONLY),
            view(&backing, SCA_BYTES, STORAGE_BYTES - SCA_BYTES, no_read),
        ],
        TargetCpu::Baseline,
    );
    let original = snapshot(&backing);
    let mut thread = domain.thread(controls(TagCheckFaultMode::Synchronous));
    assert_eq!(
        thread.read_scalar(
            tagged(GUEST_BASE + (SCA_BYTES - 1) as u64, TAG),
            8,
            flags::TAG_CHECKED,
            GUEST_PC
        ),
        Err(MemoryFault {
            status: MemoryStatus::Permission,
            address: tagged(GUEST_BASE + SCA_BYTES as u64, TAG),
            pc: GUEST_PC,
            completed_bytes: 1,
        })
    );
    let unmapped = tagged(GUEST_BASE + STORAGE_BYTES as u64, TAG);
    assert_eq!(
        thread.read_scalar(unmapped, 8, flags::TAG_CHECKED, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::Translation,
            address: unmapped,
            pc: GUEST_PC,
            completed_bytes: 0,
        })
    );
    assert_eq!(snapshot(&backing), original);
}

#[test]
fn later_tag_fault_reports_completed_prefix_without_returning_partial_value() {
    let (_, backing, domain) = setup();
    backing
        .allocation_tags()
        .write(SCA_BYTES, AllocationTag::ZERO)
        .unwrap();
    let original = snapshot(&backing);
    let mut thread = domain.thread(controls(TagCheckFaultMode::Synchronous));
    assert_eq!(
        thread.read_scalar(
            tagged(GUEST_BASE + (SCA_BYTES - 1) as u64, TAG),
            8,
            flags::TAG_CHECKED,
            GUEST_PC
        ),
        Err(MemoryFault {
            status: MemoryStatus::TagCheck,
            address: tagged(GUEST_BASE + SCA_BYTES as u64, TAG),
            pc: GUEST_PC,
            completed_bytes: 1,
        })
    );
    assert_eq!(snapshot(&backing), original);
}

#[test]
fn invalid_scalar_requests_preserve_reservation_and_do_not_enter_policy() {
    let (_, backing, domain) = setup();
    let original = snapshot(&backing);
    let mut thread = domain.thread(controls(TagCheckFaultMode::Asynchronous));
    for (bytes, required_flags) in [
        (0, 0),
        (3, 0),
        (17, 0),
        (8, flags::WRITE),
        (8, flags::KNOWN + 1),
        (8, flags::TAG_CHECKED | flags::WRITE),
    ] {
        let access = reserve(&mut thread);
        let address = tagged(GUEST_BASE, TAG);
        assert_eq!(
            thread.read_scalar(address, bytes, required_flags, GUEST_PC),
            Err(MemoryFault {
                status: MemoryStatus::InvalidRequest,
                address,
                pc: GUEST_PC,
                completed_bytes: 0,
            })
        );
        assert!(marked(&mut thread, &access));
    }
    assert_eq!(snapshot(&backing), original);
}

#[test]
fn success_and_platform_declines_preserve_marks_but_guest_faults_clear_them() {
    let (_, _, domain) = setup();
    let mut thread = domain.thread(controls(TagCheckFaultMode::Asynchronous));
    let address = tagged(GUEST_BASE, TAG);
    let access = reserve(&mut thread);
    assert_eq!(
        thread.read_scalar(address, 8, flags::TAG_CHECKED, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::Unsupported,
            address,
            pc: GUEST_PC,
            completed_bytes: 0,
        })
    );
    assert!(marked(&mut thread, &access));
    let access = reserve(&mut thread);
    thread.read_scalar(address, 8, 0, GUEST_PC).unwrap();
    assert!(marked(&mut thread, &access));
    *thread.policy_mut() = controls(TagCheckFaultMode::Synchronous);
    let access = reserve(&mut thread);
    assert_eq!(
        thread
            .read_scalar(tagged(GUEST_BASE, TAG - 1), 8, flags::TAG_CHECKED, GUEST_PC)
            .unwrap_err()
            .status,
        MemoryStatus::TagCheck
    );
    assert!(!marked(&mut thread, &access));
}

#[test]
fn wide_native_recipe_declines_explicitly_without_capability_and_preserves_mark() {
    let (_, physical, initial_domain) = setup();
    let original = snapshot(&physical);
    let mut thread = initial_domain.thread(controls(TagCheckFaultMode::Synchronous));
    let access = reserve(&mut thread);
    let address = tagged(GUEST_BASE, TAG);
    assert_eq!(
        thread.read_scalar(address, SCA_BYTES as u8, flags::TAG_CHECKED, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::Unsupported,
            address,
            pc: GUEST_PC,
            completed_bytes: 0
        })
    );
    assert!(marked(&mut thread, &access));
    if TargetCpu::AtomicLoad16.supported() {
        let system = MemorySystem::new(16, 4).unwrap();
        let backing = backing(&system);
        let domain = domain(
            &system,
            vec![view(&backing, 0, STORAGE_BYTES, READONLY)],
            TargetCpu::AtomicLoad16,
        );
        let expected: [u8; SCA_BYTES] = snapshot(&backing)[..SCA_BYTES].try_into().unwrap();
        let mut thread = domain.thread(controls(TagCheckFaultMode::Synchronous));
        assert_eq!(
            thread.read_scalar(address, SCA_BYTES as u8, flags::TAG_CHECKED, GUEST_PC),
            Ok(u128::from_le_bytes(expected))
        );
    }
    assert_eq!(snapshot(&physical), original);
}

#[test]
fn faults_serialize_with_typed_status_as_stable_abi_code() {
    let fault = MemoryFault {
        status: MemoryStatus::TagCheck,
        address: tagged(GUEST_BASE, TAG),
        pc: GUEST_PC,
        completed_bytes: 1,
    };
    let json = serde_json::to_value(fault).unwrap();
    assert_eq!(json["status"], MemoryStatus::TagCheck as u32);
    assert_eq!(json["address"], fault.address);
    assert_eq!(json["pc"], GUEST_PC);
    assert_eq!(json["completed_bytes"], 1);
}

struct PanicPolicy(MemoryControls);

impl DataPolicy for PanicPolicy {
    fn validate_execution(&self, required_flags: u32) -> Result<(), MemoryStatus> {
        self.0.validate_execution(required_flags)
    }

    fn translate(&self, raw_address: u64) -> Result<u64, MemoryStatus> {
        self.0.translate(raw_address)
    }

    fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
        panic!("scalar read policy failure")
    }
}

#[test]
fn policy_panic_uses_existing_fail_stop_cleanup_and_retains_source_location() {
    let (_, backing, domain) = setup();
    let original = snapshot(&backing);
    let mut thread = domain.thread(PanicPolicy(controls(TagCheckFaultMode::Synchronous)));
    let access = reserve(&mut thread);
    let address = tagged(GUEST_BASE, TAG);
    let expected = MemoryFault {
        status: MemoryStatus::Domain,
        address,
        pc: GUEST_PC,
        completed_bytes: 0,
    };
    assert_eq!(
        thread.read_scalar(address, 8, flags::TAG_CHECKED, GUEST_PC),
        Err(expected)
    );
    assert!(!marked(&mut thread, &access));
    assert_eq!(thread.read_scalar(address, 8, 0, GUEST_PC), Err(expected));
    assert_eq!(snapshot(&backing), original);
}

struct PreflightPanicPolicy;

impl DataPolicy for PreflightPanicPolicy {
    fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
        panic!("scalar preflight policy failure")
    }

    fn translate(&self, _: u64) -> Result<u64, MemoryStatus> {
        unreachable!("failed preflight must not reach translation")
    }

    fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
        unreachable!("failed preflight must not reach a data check")
    }
}

#[test]
fn preflight_policy_panic_uses_shared_fail_stop_boundary() {
    let (_, backing, domain) = setup();
    let original = snapshot(&backing);
    let mut thread = domain.thread(PreflightPanicPolicy);
    let access = reserve(&mut thread);
    let address = tagged(GUEST_BASE, TAG);
    assert_eq!(
        thread.read_scalar(address, 8, 0, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::Domain,
            address,
            pc: GUEST_PC,
            completed_bytes: 0,
        })
    );
    assert!(!marked(&mut thread, &access));
    assert_eq!(snapshot(&backing), original);
}

#[derive(Default)]
struct CheckedCalls {
    validate: std::cell::Cell<usize>,
    translate: std::cell::Cell<usize>,
    check: std::cell::Cell<usize>,
}

struct CheckedPolicy {
    system: Arc<MemorySystem>,
    calls: std::rc::Rc<CheckedCalls>,
    fail_after_check: bool,
}

impl DataPolicy for CheckedPolicy {
    fn validate_execution(&self, _: u32) -> Result<(), MemoryStatus> {
        self.calls.validate.set(self.calls.validate.get() + 1);
        Ok(())
    }
    fn translate(&self, address: u64) -> Result<u64, MemoryStatus> {
        self.calls.translate.set(self.calls.translate.get() + 1);
        Ok(address & 0x00ff_ffff_ffff_ffff)
    }
    fn check(&mut self, access: DataAccess<'_>) -> Result<(), MemoryStatus> {
        self.calls.check.set(self.calls.check.get() + 1);
        if self.fail_after_check {
            self.system
                .failed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        controls(TagCheckFaultMode::Synchronous).check(access)
    }
}

fn checked_policy(
    system: &Arc<MemorySystem>,
    fail_after_check: bool,
) -> (CheckedPolicy, std::rc::Rc<CheckedCalls>) {
    let calls = std::rc::Rc::new(CheckedCalls::default());
    (
        CheckedPolicy {
            system: Arc::clone(system),
            calls: std::rc::Rc::clone(&calls),
            fail_after_check,
        },
        calls,
    )
}

#[test]
fn checked_scalar_typed_categories_decline_before_prepare_or_callback() {
    let (system, backing, domain) = setup();
    let (policy, calls) = checked_policy(&system, false);
    let mut thread = domain.thread(policy);
    let before = snapshot(&backing);
    let mut rejected: Vec<_> = (0..u32::BITS)
        .map(|bit| 1u32 << bit)
        .filter(|descriptor| descriptor & SCALAR_READ_FLAGS == 0)
        .collect();
    // All combinations of currently known non-read classes, including future
    // typed operation categories, must decline without relying on KNOWN width.
    let known_blocked = flags::KNOWN & !SCALAR_READ_FLAGS;
    let mut combination = known_blocked;
    while combination != 0 {
        rejected.push(combination);
        combination = (combination - 1) & known_blocked;
    }
    for descriptor in rejected {
        for ordinary in [0, flags::TAG_CHECKED] {
            let access = reserve(&mut thread);
            assert_eq!(
                thread.read_scalar(tagged(GUEST_BASE, TAG), 8, descriptor | ordinary, GUEST_PC),
                Err(MemoryFault {
                    status: MemoryStatus::InvalidRequest,
                    address: tagged(GUEST_BASE, TAG),
                    pc: GUEST_PC,
                    completed_bytes: 0,
                })
            );
            assert!(marked(&mut thread, &access));
        }
    }
    assert_eq!(
        (
            calls.validate.get(),
            calls.translate.get(),
            calls.check.get()
        ),
        (0, 0, 0)
    );
    assert_eq!(snapshot(&backing), before);
}

#[test]
fn checked_scalar_late_success_is_terminal_with_full_read_prefix() {
    let (system, backing, domain) = setup();
    let (policy, calls) = checked_policy(&system, true);
    let mut thread = domain.thread(policy);
    let before = snapshot(&backing);
    assert_eq!(
        thread.read_scalar(tagged(GUEST_BASE, TAG), 8, 0, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::Domain,
            address: tagged(GUEST_BASE, TAG),
            pc: GUEST_PC,
            completed_bytes: 8,
        })
    );
    // One check and a complete prefix mean the native read returned;
    // finalization still withholds the staged value.
    assert_eq!(calls.check.get(), 1);
    assert_eq!(domain.check_execution(), Err(MemoryStatus::Domain));
    assert_eq!(snapshot(&backing), before);
}

#[test]
fn checked_scalar_mid_transfer_health_failure_stops_before_next_fragment() {
    let (system, backing, domain) = setup();
    let (policy, calls) = checked_policy(&system, true);
    let mut thread = domain.thread(policy);
    let access = reserve(&mut thread);
    let before = snapshot(&backing);
    let raw = tagged(GUEST_BASE + 14, TAG);
    assert_eq!(
        thread.read_scalar(raw, 4, 0, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::Domain,
            address: raw + 1,
            pc: GUEST_PC,
            completed_bytes: 1,
        })
    );
    // The first byte's policy check marks the system failed. That read
    // completes, but the next byte's resolve refuses before another check or
    // access. No permission or tag fault occurred, so fault cleanup must not
    // clear the local reservation.
    assert_eq!(calls.check.get(), 1);
    assert!(marked(&mut thread, &access));
    assert_eq!(domain.check_execution(), Err(MemoryStatus::Domain));
    assert!(domain.execution_loan().is_err());
    assert_eq!(
        thread.prepare(MemoryRequirements::default()).err(),
        Some(MemoryStatus::Domain)
    );
    assert_eq!(snapshot(&backing), before);
}

#[test]
fn checked_scalar_terminal_preentry_is_distinct_from_executed_read() {
    let (system, _, domain) = setup();
    let (policy, calls) = checked_policy(&system, false);
    let mut thread = domain.thread(policy);
    system
        .failed
        .store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(
        thread.read_scalar(tagged(GUEST_BASE, TAG), 8, 0, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::Domain,
            address: tagged(GUEST_BASE, TAG),
            pc: GUEST_PC,
            completed_bytes: 0,
        })
    );
    assert_eq!(
        (
            calls.validate.get(),
            calls.translate.get(),
            calls.check.get()
        ),
        (0, 0, 0)
    );
}

#[test]
fn checked_scalar_healthy_finalization_returns_exact_native_read() {
    let (system, backing, domain) = setup();
    let (policy, calls) = checked_policy(&system, false);
    let mut thread = domain.thread(policy);
    let expected = u64::from_le_bytes(snapshot(&backing)[..8].try_into().unwrap());
    assert_eq!(
        thread.read_scalar(tagged(GUEST_BASE, TAG), 8, 0, GUEST_PC),
        Ok(u128::from(expected))
    );
    assert_eq!(calls.check.get(), 1);
    assert_eq!(domain.check_execution(), Ok(()));
}

#[test]
fn checked_scalar_late_zero_prefix_fault_observes_reached_callback() {
    let (system, backing, domain) = setup();
    let (policy, calls) = checked_policy(&system, true);
    let mut thread = domain.thread(policy);
    let access = reserve(&mut thread);
    let before = snapshot(&backing);
    let raw = tagged(GUEST_BASE, TAG ^ 1);
    assert_eq!(
        thread.read_scalar(raw, 8, flags::TAG_CHECKED, GUEST_PC),
        Err(MemoryFault {
            status: MemoryStatus::Domain,
            address: raw,
            pc: GUEST_PC,
            completed_bytes: 0,
        })
    );
    // A synchronous tag fault reached the callback before any native read. The
    // later terminal health failure takes precedence without losing the fault's
    // source location; a zero prefix alone does not mean the access never
    // started.
    assert_eq!(calls.check.get(), 1);
    assert!(!marked(&mut thread, &access));
    assert_eq!(domain.check_execution(), Err(MemoryStatus::Domain));
    assert_eq!(snapshot(&backing), before);
}
