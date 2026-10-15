use super::*;
use crate::memory::{
    backing::{AccessPermissions, MemoryBacking},
    domain::{MemoryDomain, MemorySystem},
    policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
};
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    ptr::NonNull,
};

const RIGHTS: AccessPermissions = AccessPermissions {
    readable: true,
    writable: true,
    executable: false,
};
const ATTRIBUTES: MappingAttributes = MappingAttributes {
    tagged: true,
    shareable: true,
};
struct Storage(NonNull<u8>, Layout);
// SAFETY: ownership grants no references or unsynchronized data accesses.
unsafe impl Send for Storage {}
// SAFETY: ownership grants no references or unsynchronized data accesses.
unsafe impl Sync for Storage {}
impl Drop for Storage {
    fn drop(&mut self) {
        unsafe { dealloc(self.0.as_ptr(), self.1) }
    }
}
fn domain(host_residue: usize, backing_offset: usize, tagged: bool) -> Arc<MemoryDomain> {
    let layout = Layout::from_size_align(80, 16).unwrap();
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let owner = Arc::new(Storage(pointer, layout));
    let backing =
        unsafe { MemoryBacking::new(pointer.add(host_residue), 64, RIGHTS, owner) }.unwrap();
    let view = MemoryView::new(backing, 0x1000, backing_offset, 16, RIGHTS).unwrap();
    MemoryDomain::new_for_address_space(
        42,
        MemorySystem::new(16, 4).unwrap(),
        vec![(
            view,
            MappingAttributes {
                tagged,
                ..ATTRIBUTES
            },
        )],
        TargetCpu::detect(),
    )
    .unwrap()
}
fn policy(ata: bool) -> MemoryControls {
    MemoryControls::new(
        LowerAddressProfile::new(48, true).unwrap(),
        true,
        ata,
        false,
        TagCheckFaultMode::Synchronous,
        false,
    )
}
fn requirements(profile: u32, caps: u32, flags: u32) -> MemoryRequirements {
    MemoryRequirements {
        required_flags: flags,
        required_host_caps: caps,
        required_profile: profile,
        ..MemoryRequirements::default()
    }
}
#[test]
fn checked_entry_rejects_incongruent_native_before_callback() {
    let domain = domain(1, 0, true);
    let mut thread = domain.thread(policy(true));
    assert!(matches!(
        thread.prepare(requirements(profile_requirements::NATIVE_ACCESS, 0, 0)),
        Err(MemoryStatus::Unsupported)
    ));
    assert_eq!(thread.address_space(), Some(42));
    assert_eq!(domain.address_space(), Some(42));
}
#[test]
fn tag_plane_is_independent_of_native_alignment_and_authoritative_enable() {
    // The host pointer is aligned, but the physical tag offset is not.
    for (ata, tagged, expected) in [
        (true, true, false),
        (false, true, true),
        (true, false, true),
    ] {
        let domain = domain(1, 15, tagged);
        let mut thread = domain.thread(policy(ata));
        assert_eq!(
            thread
                .prepare_tag(requirements(profile_requirements::TAG_GRANULES, 0, 0), true)
                .is_ok(),
            expected
        );
        assert!(
            thread
                .prepare(requirements(profile_requirements::NATIVE_ACCESS, 0, 0))
                .is_ok()
        );
    }
}
#[test]
fn data16_declines_bad_native_layout_even_when_tags_disabled() {
    let domain = domain(1, 0, true);
    let mut thread = domain.thread(policy(false));
    assert!(matches!(
        thread.prepare_tag(
            requirements(
                profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES,
                host_caps::CX16,
                flags::WRITE
            ),
            true
        ),
        Err(MemoryStatus::Unsupported)
    ));
}
#[test]
fn checked_entry_validates_declared_caps_unknown_requirements_and_policy() {
    let domain = domain(0, 0, true);
    let mut thread = domain.thread(policy(true));
    assert!(
        thread
            .prepare(requirements(profile_requirements::NATIVE_ACCESS, 0, 0))
            .is_ok()
    );
    assert!(matches!(
        thread.prepare(requirements(1 << 31, 0, 0)),
        Err(MemoryStatus::InvalidRequest)
    ));
    assert!(matches!(
        thread.prepare_tag(
            requirements(profile_requirements::TAG_GRANULES, 0, 0),
            false
        ),
        Err(MemoryStatus::Unsupported)
    ));
    let physical = domain.views[0].view.clone();
    let baseline = MemoryDomain::new(
        domain.system.clone(),
        vec![(physical, ATTRIBUTES)],
        TargetCpu::Baseline,
    )
    .unwrap();
    let mut thread = baseline.thread(policy(true));
    for cap in [host_caps::ATOMIC_LOAD16, host_caps::CX16] {
        assert!(matches!(
            thread.prepare(requirements(profile_requirements::NATIVE_ACCESS, cap, 0)),
            Err(MemoryStatus::Unsupported)
        ));
    }
    assert_eq!(baseline.address_space(), None);
}

#[test]
fn host_recipe_and_complete_granule_requirements_decline_before_entry() {
    for (bytes, rights, required_profile, caps, flags) in [
        (
            64,
            AccessPermissions {
                readable: false,
                ..RIGHTS
            },
            profile_requirements::NATIVE_ACCESS,
            0,
            flags::WRITE,
        ),
        (
            31,
            RIGHTS,
            profile_requirements::NATIVE_ACCESS,
            host_caps::ATOMIC_LOAD16,
            0,
        ),
        (31, RIGHTS, profile_requirements::TAG_GRANULES, 0, 0),
    ] {
        let layout = Layout::from_size_align(64, 16).unwrap();
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let owner = Arc::new(Storage(pointer, layout));
        let backing = unsafe { MemoryBacking::new(pointer, bytes, rights, owner) }.unwrap();
        let view = MemoryView::new(backing, 0x1000, 0, bytes, rights).unwrap();
        let domain = MemoryDomain::new(
            MemorySystem::new(16, 4).unwrap(),
            vec![(view, ATTRIBUTES)],
            TargetCpu::detect(),
        )
        .unwrap();
        let mut thread = domain.thread(policy(true));
        assert!(matches!(
            thread.prepare(requirements(required_profile, caps, flags)),
            Err(MemoryStatus::Unsupported)
        ));
    }
}

#[test]
fn partial_quantity_boundaries_cache_physical_layout_without_permission_prevalidation() {
    fn physical() -> Arc<MemoryBacking> {
        let layout = Layout::from_size_align(64, 16).unwrap();
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let owner = Arc::new(Storage(pointer, layout));
        unsafe { MemoryBacking::new(pointer, 64, RIGHTS, owner) }.unwrap()
    }
    for (same_backing, boundary, gap, same_attributes, expected) in [
        (false, 24, 0, true, false),
        (true, 24, 0, true, true),
        (true, 24, 0, false, false),
        (false, 32, 0, true, true),
        (false, 24, 8, true, true),
    ] {
        let first = physical();
        let second = if same_backing {
            first.clone()
        } else {
            physical()
        };
        let readonly = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let first_view = MemoryView::new(first.clone(), 0x1000, 0, boundary, RIGHTS).unwrap();
        let second_view = MemoryView::new(
            second,
            0x1000 + (boundary + gap) as u64,
            boundary + gap,
            16,
            readonly,
        )
        .unwrap();
        let second_attributes = MappingAttributes {
            shareable: same_attributes,
            ..ATTRIBUTES
        };
        let domain = MemoryDomain::new(
            MemorySystem::new(16, 4).unwrap(),
            vec![(first_view, ATTRIBUTES), (second_view, second_attributes)],
            TargetCpu::detect(),
        )
        .unwrap();
        for ata in [true, false] {
            let mut thread = domain.thread(policy(ata));
            assert_eq!(
                thread
                    .prepare_tag(requirements(profile_requirements::TAG_GRANULES, 0, 0), true)
                    .is_ok(),
                expected
            );
            assert_eq!(
                thread
                    .prepare(requirements(
                        profile_requirements::NATIVE_ACCESS,
                        0,
                        flags::WRITE
                    ))
                    .is_ok(),
                expected
            );
        }
        // Preparing a whole instruction never commits an earlier granule.
        assert_eq!(
            first.allocation_tags().read(0).unwrap(),
            crate::memory::tags::AllocationTag::ZERO
        );
    }
}
