use super::super::{DataAccess, DataPolicy, MappingAttributes, MemoryDomain};
use super::*;
use crate::memory::backing::{AccessPermissions, MemoryView};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;
use stela_compiler::context::memory::{MemoryContextView, MemoryRequest};

const STORAGE_BYTES: usize = 64;
const GUEST_BASE: u64 = 0x1000;
const ALIAS_BASE: u64 = 0x2000;
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
    tagged: false,
    shareable: false,
};

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}

// SAFETY: storage only owns raw allocation; byte access uses native helpers.
unsafe impl Send for Storage {}
// SAFETY: storage lends no Rust references and accesses use one writer domain.
unsafe impl Sync for Storage {}

impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: this owner keeps its allocation and layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn backing(rights: AccessPermissions) -> Arc<MemoryBacking> {
    let layout = Layout::from_size_align(STORAGE_BYTES, HOST_QUANTITY_BYTES).unwrap();
    // SAFETY: nonempty valid layout retained by Storage for deallocation.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let storage = Arc::new(Storage { pointer, layout });
    // SAFETY: owner pins raw coherent RAM, with no aliasing Rust references.
    unsafe { MemoryBacking::new(pointer, STORAGE_BYTES, rights, storage) }.unwrap()
}

fn system() -> Arc<MemorySystem> {
    MemorySystem::new(16, 4).unwrap()
}

fn domain(
    system: &Arc<MemorySystem>,
    backing: &Arc<MemoryBacking>,
    base: u64,
) -> Arc<MemoryDomain> {
    let view = MemoryView::new(Arc::clone(backing), base, 0, STORAGE_BYTES, READONLY).unwrap();
    MemoryDomain::new(
        Arc::clone(system),
        vec![(view, ATTRIBUTES)],
        TargetCpu::Baseline,
    )
    .unwrap()
}

fn publish(
    system: &MemorySystem,
    backing: &Arc<MemoryBacking>,
    offset: usize,
    bytes: &[u8],
) -> Result<(), PublicationFault> {
    // SAFETY: the test may publish; inputs are private, host storage is pinned
    // and disjoint, and every write uses this domain.
    unsafe { system.publish(backing, offset, bytes) }
}

fn snapshot(backing: &MemoryBacking) -> Vec<u8> {
    (0..STORAGE_BYTES)
        .map(|offset| {
            let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
            // SAFETY: synchronous exact raw reads have pinned rights/lifetime.
            unsafe { access::read_part(pointer.as_ptr(), 1, TargetCpu::Baseline) }.unwrap() as u8
        })
        .collect()
}

struct Policy;

impl DataPolicy for Policy {
    fn validate_execution(&self, _required_flags: u32) -> Result<(), MemoryStatus> {
        Ok(())
    }

    fn translate(&self, raw_address: u64) -> Result<u64, MemoryStatus> {
        Ok(raw_address)
    }
    fn check(&mut self, _: DataAccess<'_>) -> Result<(), MemoryStatus> {
        Ok(())
    }
}

fn native_read(domain: &Arc<MemoryDomain>, address: u64, bytes: &mut [u8]) -> u32 {
    let mut thread = domain.thread(Policy);
    let request = MemoryRequest {
        address,
        data: bytes.as_mut_ptr(),
        bytes: bytes.len() as u32,
        flags: 0,
        pc: 0x1234,
    };
    // SAFETY: raw native call uses the C ABI, synchronous valid context/request,
    // and private staging disjoint from guest RAM; no pointers escape.
    unsafe {
        thread.with_view(|context: &mut MemoryContextView| {
            let status: u32;
            std::arch::asm!(
                "call {callback}",
                callback = in(reg) context.callback,
                in("rdi") std::ptr::from_mut(context),
                in("rsi") std::ptr::from_ref(&request),
                lateout("eax") status,
                clobber_abi("C"),
            );
            status
        })
    }
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
fn fragments_fit_host_quantities_and_choose_largest_exact_scalar() {
    for residue in 0..HOST_QUANTITY_BYTES {
        for length in 0..=STORAGE_BYTES {
            let mut completed = 0;
            for part in PublicationParts::new(residue, length) {
                assert_eq!(part.offset, completed);
                assert_eq!(part.address, residue + completed);
                assert!(matches!(part.bytes, 1 | 2 | 4 | 8));
                let available = HOST_QUANTITY_BYTES - (part.address & (HOST_QUANTITY_BYTES - 1));
                assert!(part.bytes <= available);
                assert!(part.bytes * 2 > available.min(length - completed));
                assert_eq!(
                    access::read_footprint(part.address, part.bytes, TargetCpu::Baseline),
                    Ok((part.address, part.bytes))
                );
                completed += part.bytes;
            }
            assert_eq!(completed, length);
        }
    }
}

#[test]
fn native_publications_preserve_all_neighbors_for_every_residue_and_length() {
    for residue in 0..HOST_QUANTITY_BYTES {
        for length in 0..=32 {
            let system = system();
            let backing = backing(RIGHTS);
            let mut expected = vec![0xa5; STORAGE_BYTES];
            publish(&system, &backing, 0, &expected).unwrap();
            let bytes: Vec<_> = (0..length).map(|index| index as u8).collect();
            let offset = HOST_QUANTITY_BYTES + residue;
            publish(&system, &backing, offset, &bytes).unwrap();
            expected[offset..offset + length].copy_from_slice(&bytes);
            assert_eq!(
                snapshot(&backing),
                expected,
                "residue={residue}, length={length}"
            );
        }
    }
}

#[test]
fn guest_readonly_alias_reads_host_publication_through_native_callback() {
    let system = system();
    let backing = backing(RIGHTS);
    let domain = domain(&system, &backing, GUEST_BASE);
    let expected = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
    publish(&system, &backing, 0, &expected).unwrap();
    let mut actual = [0; 8];
    assert_eq!(
        native_read(&domain, GUEST_BASE, &mut actual),
        MemoryStatus::Success as u32
    );
    assert_eq!(actual, expected);
}

#[test]
fn publication_invalidates_cross_address_space_alias_reservations_including_aba() {
    let system = system();
    let backing = backing(RIGHTS);
    let first = domain(&system, &backing, GUEST_BASE);
    let alias = domain(&system, &backing, ALIAS_BASE);
    let mut reservation = system.reservations.thread();
    let first_access = reservation_access(&first, 0);
    let alias_access = reservation_access(&alias, 0);
    for values in [&[0][..], &[0x5a, 0][..]] {
        system
            .reservations
            .load(&mut reservation, &first_access, || {
                let pointer = backing.host_pointer(0, 1, AccessKind::Read).unwrap();
                // SAFETY: reservation gate protects this exact live raw read.
                unsafe { access::read_part(pointer.as_ptr(), 1, TargetCpu::Baseline) }
            })
            .unwrap();
        for value in values {
            publish(&system, &backing, 0, &[*value]).unwrap();
        }
        let stored = system
            .reservations
            .store(&mut reservation, &alias_access, || -> Result<(), ()> {
                panic!("host publication must invalidate the alias reservation")
            })
            .unwrap();
        assert_eq!(stored, monitor::ConditionalWrite::Failed);
        assert_eq!(snapshot(&backing)[0], 0);
    }
}

#[test]
fn wrong_coherence_owner_and_invalid_bounds_have_no_byte_effects() {
    let system = system();
    let backing = backing(RIGHTS);
    publish(&system, &backing, 0, &[0x5a; STORAGE_BYTES]).unwrap();
    let other = MemorySystem::new(16, 4).unwrap();
    assert_eq!(
        publish(&other, &backing, 0, &[0xff]),
        Err(PublicationFault {
            status: MemoryStatus::Domain,
            completed: 0,
        })
    );
    for (offset, bytes) in [
        (STORAGE_BYTES - 1, &[1, 2][..]),
        (usize::MAX, &[1][..]),
        (STORAGE_BYTES + 1, &[][..]),
    ] {
        assert_eq!(
            publish(&system, &backing, offset, bytes),
            Err(PublicationFault {
                status: MemoryStatus::Translation,
                completed: 0,
            })
        );
    }
    assert_eq!(snapshot(&backing), [0x5a; STORAGE_BYTES]);
}

#[test]
fn preflight_failures_and_empty_publications_preserve_reservations() {
    let system = system();
    let backing = backing(RIGHTS);
    let domain = domain(&system, &backing, GUEST_BASE);
    let access = reservation_access(&domain, 0);
    let mut reservation = system.reservations.thread();
    system
        .reservations
        .load(&mut reservation, &access, || Ok::<(), ()>(()))
        .unwrap();
    assert!(publish(&system, &backing, STORAGE_BYTES - 1, &[1, 2]).is_err());
    let other = MemorySystem::new(16, 4).unwrap();
    assert!(publish(&other, &backing, 0, &[1]).is_err());
    publish(&system, &backing, 0, &[]).unwrap();
    let stored = system
        .reservations
        .store(&mut reservation, &access, || Ok::<(), ()>(()))
        .unwrap();
    assert_eq!(stored, monitor::ConditionalWrite::Stored(()));
    assert_eq!(snapshot(&backing), [0; STORAGE_BYTES]);
}

#[test]
fn complete_host_read_and_write_rights_are_required_before_any_write() {
    for rights in [
        READONLY,
        AccessPermissions {
            readable: false,
            ..RIGHTS
        },
    ] {
        let system = system();
        let backing = backing(rights);
        assert_eq!(
            publish(&system, &backing, 0, &[0x5a; STORAGE_BYTES]),
            Err(PublicationFault {
                status: MemoryStatus::Permission,
                completed: 0,
            })
        );
        // The allocation is readable natively even when backing metadata denies
        // reads; its owner pins those rights for this post-failure observation.
        let pointer = backing
            .host_pointer(
                0,
                1,
                if rights.readable {
                    AccessKind::Read
                } else {
                    AccessKind::Write
                },
            )
            .unwrap();
        for offset in 0..STORAGE_BYTES {
            // SAFETY: allocation remains live readable coherent raw RAM.
            assert_eq!(
                unsafe { access::read_part(pointer.as_ptr().add(offset), 1, TargetCpu::Baseline) }
                    .unwrap(),
                0
            );
        }
    }
}

#[test]
fn empty_publication_is_noop_but_terminal_system_still_declines() {
    let system = system();
    let backing = backing(RIGHTS);
    publish(&system, &backing, 0, &[]).unwrap();
    publish(&system, &backing, STORAGE_BYTES, &[]).unwrap();
    assert_eq!(snapshot(&backing), [0; STORAGE_BYTES]);
    system.failed.store(true, Ordering::Release);
    for bytes in [&[][..], &[0x5a][..]] {
        assert_eq!(
            publish(&system, &backing, 0, bytes),
            Err(PublicationFault {
                status: MemoryStatus::Domain,
                completed: 0,
            })
        );
    }
    assert_eq!(snapshot(&backing), [0; STORAGE_BYTES]);
}

#[test]
fn poisoned_monitor_declines_before_publication() {
    let system = system();
    let backing = backing(RIGHTS);
    let range = monitor::WriteRange::new(Arc::clone(&backing), 0, 1).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = system.reservations.with_writer(
            &range,
            monitor::Invalidation::BeforeAttempt,
            || -> Result<(), ()> { panic!("poison the existing physical writer monitor") },
        );
    }));
    assert!(result.is_err());
    for bytes in [&[][..], &[0x5a][..]] {
        assert_eq!(
            publish(&system, &backing, 0, bytes),
            Err(PublicationFault {
                status: MemoryStatus::Domain,
                completed: 0,
            })
        );
    }
    assert_eq!(snapshot(&backing), [0; STORAGE_BYTES]);
}

mod binding_reservation;
