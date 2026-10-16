use super::*;
use crate::memory::backing::{AccessPermissions, MemoryBacking};
use crate::memory::domain::MappingAttributes;
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;
use std::sync::Arc;

const STORAGE_BYTES: usize = TAG_GRANULE_BYTES * 4;
const ADDRESS_BITS: u8 = 48;
const GUEST_ADDRESS: u64 = 0x4000;
const TEST_TAG: u8 = 7;

struct Storage {
    pointer: NonNull<u8>,
    layout: Layout,
}

// SAFETY: ownership exposes no references/accesses to the raw allocation.
unsafe impl Send for Storage {}
// SAFETY: shared ownership only retains the allocation's lifetime.
unsafe impl Sync for Storage {}

impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: this owner keeps its allocation and layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

fn backing(bytes: usize) -> Arc<MemoryBacking> {
    let layout = Layout::from_size_align(bytes, TAG_GRANULE_BYTES).unwrap();
    // SAFETY: the valid nonzero layout is retained for matching deallocation.
    let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
    let owner = Arc::new(Storage { pointer, layout });
    // SAFETY: the owner retains raw storage with no Rust byte references;
    // these tests only access the separate allocation-tag plane.
    unsafe {
        MemoryBacking::new(
            pointer,
            bytes,
            AccessPermissions {
                readable: true,
                writable: true,
                executable: false,
            },
            owner,
        )
    }
    .unwrap()
}

fn controls(mode: TagCheckFaultMode) -> MemoryControls {
    MemoryControls::new(
        LowerAddressProfile::new(ADDRESS_BITS, true).unwrap(),
        false,
        true,
        false,
        mode,
        false,
    )
}

fn request(backing: &MemoryBacking, offset: usize, bytes: usize, tag: u8) -> DataAccess<'_> {
    DataAccess {
        raw_address: AllocationTag::new(tag)
            .unwrap()
            .apply_to_address(GUEST_ADDRESS),
        translated_address: GUEST_ADDRESS,
        backing,
        backing_offset: offset,
        bytes,
        attributes: MappingAttributes {
            tagged: true,
            shareable: true,
        },
        flags: flags::TAG_CHECKED,
    }
}

#[test]
fn lower_profiles_strip_only_the_enabled_top_byte() {
    for bits in [16, 32, 39, 47, 48, 52] {
        let address = (1u64 << bits) - 1;
        for ignored in [false, true] {
            let profile = LowerAddressProfile::new(bits, ignored).unwrap();
            for top in 0..=u8::MAX {
                let raw = (u64::from(top) << TOP_BYTE_SHIFT) | address;
                assert_eq!(
                    profile.translate(raw),
                    if ignored || top == 0 {
                        Ok(address)
                    } else {
                        Err(MemoryStatus::Translation)
                    }
                );
            }
            for high_bit in bits..TOP_BYTE_SHIFT as u8 {
                assert_eq!(
                    profile.translate(address | (1u64 << high_bit)),
                    Err(MemoryStatus::Translation)
                );
            }
        }
    }
    for bits in [0, 15, 53, 55, 64, u8::MAX] {
        assert_eq!(
            LowerAddressProfile::new(bits, true),
            Err(MemoryStatus::InvalidRequest)
        );
    }
}

#[test]
fn every_intersecting_granule_is_checked_without_mutating_tags() {
    let backing = backing(STORAGE_BYTES);
    let tag = AllocationTag::new(TEST_TAG).unwrap();
    for offset in (0..STORAGE_BYTES).step_by(TAG_GRANULE_BYTES) {
        backing.allocation_tags().write(offset, tag).unwrap();
    }
    let mut policy = controls(TagCheckFaultMode::Synchronous);
    for offset in 0..STORAGE_BYTES {
        for bytes in 1..=STORAGE_BYTES - offset {
            assert_eq!(
                policy.check(request(&backing, offset, bytes, TEST_TAG)),
                Ok(())
            );
        }
    }
    backing
        .allocation_tags()
        .write(TAG_GRANULE_BYTES, AllocationTag::ZERO)
        .unwrap();
    assert_eq!(
        policy.check(request(&backing, 0, TAG_GRANULE_BYTES, TEST_TAG)),
        Ok(())
    );
    assert_eq!(
        policy.check(request(&backing, TAG_GRANULE_BYTES - 1, 2, TEST_TAG)),
        Err(MemoryStatus::TagCheck)
    );
    assert_eq!(
        backing.allocation_tags().read(TAG_GRANULE_BYTES),
        Ok(AllocationTag::ZERO)
    );
}

#[test]
fn effective_controls_bypass_checks_independently() {
    let backing = backing(STORAGE_BYTES);
    for gate in 0..6 {
        let mut policy = controls(TagCheckFaultMode::Synchronous);
        let mut access = request(&backing, 0, 1, TEST_TAG);
        match gate {
            0 => access.flags &= !flags::TAG_CHECKED,
            1 => access.attributes.tagged = false,
            2 => policy.allocation_tags_enabled = false,
            3 => policy.tag_check_override = true,
            4 => {
                policy.lower_address = LowerAddressProfile::new(ADDRESS_BITS, false).unwrap();
                access.raw_address = GUEST_ADDRESS;
                backing
                    .allocation_tags()
                    .write(0, AllocationTag::new(TEST_TAG).unwrap())
                    .unwrap();
            }
            5 => {
                policy.tag_check_mask = true;
                access.raw_address = GUEST_ADDRESS;
                backing
                    .allocation_tags()
                    .write(0, AllocationTag::new(TEST_TAG).unwrap())
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(policy.check(access), Ok(()), "gate {gate}");
    }
    let mut policy = controls(TagCheckFaultMode::Synchronous);
    policy.tag_check_mask = true;
    assert_eq!(
        policy.check(request(&backing, TAG_GRANULE_BYTES, 1, TEST_TAG)),
        Err(MemoryStatus::TagCheck)
    );
}

#[test]
fn ignored_mismatches_and_unsupported_async_are_distinct() {
    let backing = backing(STORAGE_BYTES);
    assert_eq!(
        controls(TagCheckFaultMode::Ignore).check(request(&backing, 0, 1, TEST_TAG)),
        Ok(())
    );
    for mode in [
        TagCheckFaultMode::Asynchronous,
        TagCheckFaultMode::Asymmetric,
    ] {
        for write in [false, true] {
            let mut access = request(&backing, 0, 1, 0);
            if write {
                access.flags |= flags::WRITE;
            }
            assert_eq!(controls(mode).check(access), Err(MemoryStatus::Unsupported));
            let mut policy = controls(mode);
            policy.tag_check_override = true;
            assert_eq!(policy.check(request(&backing, 0, 1, TEST_TAG)), Ok(()));
        }
    }
}

#[test]
fn malformed_accesses_and_incomplete_tag_storage_decline_explicitly() {
    let backing = backing(STORAGE_BYTES - 1);
    let mut policy = controls(TagCheckFaultMode::Synchronous);
    for (offset, bytes) in [(0, 0), (usize::MAX, 2), (backing.bytes(), 1)] {
        assert_eq!(
            policy.check(request(&backing, offset, bytes, 0)),
            Err(MemoryStatus::InvalidRequest)
        );
    }
    let mut access = request(&backing, 0, 1, 0);
    access.flags |= !flags::KNOWN;
    assert_eq!(policy.check(access), Err(MemoryStatus::InvalidRequest));
    let mut access = request(&backing, 0, 1, 0);
    access.translated_address += 1;
    assert_eq!(policy.check(access), Err(MemoryStatus::InvalidRequest));
    assert_eq!(
        policy.check(request(&backing, backing.bytes() - 1, 1, 0)),
        Err(MemoryStatus::Unsupported)
    );
}

#[test]
fn dedicated_tag_access_uses_the_selected_privilege_and_mapping_controls() {
    let mut policy = controls(TagCheckFaultMode::Asynchronous);
    for privileged in [false, true] {
        policy.privileged = privileged;
        for enabled in [false, true] {
            policy.allocation_tags_enabled = enabled;
            for tagged in [false, true] {
                let attributes = MappingAttributes {
                    tagged,
                    shareable: true,
                };
                assert_eq!(policy.validate_privilege(privileged), Ok(()));
                assert_eq!(
                    policy.validate_privilege(!privileged),
                    Err(MemoryStatus::Unsupported)
                );
                assert_eq!(
                    policy.allocation_tag_access(attributes, privileged),
                    Ok(tagged && enabled)
                );
                assert_eq!(
                    policy.allocation_tag_access(attributes, !privileged),
                    Err(MemoryStatus::Unsupported)
                );
            }
        }
    }
}

#[test]
fn execution_preflight_checks_only_required_tag_effects() {
    for mode in [
        TagCheckFaultMode::Ignore,
        TagCheckFaultMode::Synchronous,
        TagCheckFaultMode::Asynchronous,
        TagCheckFaultMode::Asymmetric,
    ] {
        for enabled in [false, true] {
            for override_checks in [false, true] {
                for top_byte_ignore in [false, true] {
                    for mask_checks in [false, true] {
                        let policy = MemoryControls::new(
                            LowerAddressProfile::new(ADDRESS_BITS, top_byte_ignore).unwrap(),
                            false,
                            enabled,
                            override_checks,
                            mode,
                            mask_checks,
                        );
                        let before = policy;
                        for required_flags in [
                            0,
                            flags::WRITE,
                            flags::TAG_CHECKED,
                            flags::WRITE | flags::TAG_CHECKED,
                        ] {
                            let unavailable = required_flags & flags::TAG_CHECKED != 0
                                && enabled
                                && !override_checks
                                && top_byte_ignore
                                && matches!(
                                    mode,
                                    TagCheckFaultMode::Asynchronous | TagCheckFaultMode::Asymmetric
                                );
                            assert_eq!(
                                policy.validate_execution(required_flags),
                                if unavailable {
                                    Err(MemoryStatus::Unsupported)
                                } else {
                                    Ok(())
                                }
                            );
                        }
                        assert_eq!(policy, before);
                    }
                }
            }
        }
    }
}

#[test]
fn preflight_rejects_unknown_effects_before_checking_controls() {
    for mode in [
        TagCheckFaultMode::Ignore,
        TagCheckFaultMode::Synchronous,
        TagCheckFaultMode::Asynchronous,
        TagCheckFaultMode::Asymmetric,
    ] {
        for enabled in [false, true] {
            for override_checks in [false, true] {
                for top_byte_ignore in [false, true] {
                    let policy = MemoryControls::new(
                        LowerAddressProfile::new(ADDRESS_BITS, top_byte_ignore).unwrap(),
                        false,
                        enabled,
                        override_checks,
                        mode,
                        false,
                    );
                    assert_eq!(
                        policy.validate_execution(flags::TAG_CHECKED | !flags::KNOWN),
                        Err(MemoryStatus::InvalidRequest)
                    );
                }
            }
        }
    }
}

#[test]
fn async_preflight_rejects_checked_writes_and_permits_unchecked_writes() {
    use crate::memory::backing::{AccessKind, MemoryView};
    use crate::memory::domain::{MemoryDomain, MemorySystem};
    use stela_compiler::TargetCpu;
    use stela_compiler::context::memory::MemoryRequest;

    for mode in [
        TagCheckFaultMode::Asynchronous,
        TagCheckFaultMode::Asymmetric,
    ] {
        let backing = backing(STORAGE_BYTES);
        let tag = AllocationTag::new(TEST_TAG).unwrap();
        backing
            .allocation_tags()
            .write(TAG_GRANULE_BYTES, tag)
            .unwrap();
        let permissions = AccessPermissions {
            readable: true,
            writable: true,
            executable: false,
        };
        let mut views = Vec::new();
        for (index, tagged) in [false, true].into_iter().enumerate() {
            let offset = index * TAG_GRANULE_BYTES;
            views.push((
                MemoryView::new(
                    Arc::clone(&backing),
                    GUEST_ADDRESS + offset as u64,
                    offset,
                    TAG_GRANULE_BYTES,
                    permissions,
                )
                .unwrap(),
                MappingAttributes {
                    tagged,
                    shareable: true,
                },
            ));
        }
        let system = MemorySystem::new(TAG_GRANULE_BYTES as u64, 1).unwrap();
        let domain = MemoryDomain::new(system, views, TargetCpu::Baseline).unwrap();
        let mut thread = domain.thread(controls(mode));
        assert_eq!(
            thread.validate_execution(flags::WRITE | flags::TAG_CHECKED),
            Err(MemoryStatus::Unsupported)
        );
        let mut data = [0x41, 0x42];
        let mut request = MemoryRequest {
            address: GUEST_ADDRESS + TAG_GRANULE_BYTES as u64 - 1,
            data: data.as_mut_ptr(),
            bytes: data.len() as u32,
            flags: flags::WRITE | flags::TAG_CHECKED,
            pc: 0,
        };
        // SAFETY: synchronous valid ABI objects and disjoint private staging;
        // the callback must independently reject the unavailable profile.
        unsafe {
            thread.with_view(|view| {
                assert_eq!(
                    (view.callback)(view, &request),
                    MemoryStatus::Unsupported as u32
                );
                assert_eq!(view.completed_bytes, 0);
            });
        }
        for offset in 0..STORAGE_BYTES {
            let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
            // SAFETY: the callback returned, no other executor accesses this
            // private raw storage, and this copies one byte without a reference.
            assert_eq!(unsafe { pointer.as_ptr().read() }, 0);
        }
        for offset in (0..STORAGE_BYTES).step_by(TAG_GRANULE_BYTES) {
            assert_eq!(
                backing.allocation_tags().read(offset),
                Ok(if offset == TAG_GRANULE_BYTES {
                    tag
                } else {
                    AllocationTag::ZERO
                })
            );
        }
        request.flags = flags::WRITE;
        assert_eq!(thread.validate_execution(request.flags), Ok(()));
        // SAFETY: the same valid staging/request remain live; unchecked
        // writes do not require asynchronous tag-fault accumulation.
        unsafe {
            thread.with_view(|view| {
                assert_eq!(
                    (view.callback)(view, &request),
                    MemoryStatus::Success as u32
                );
                assert_eq!(view.completed_bytes, data.len() as u64);
            });
        }
        for offset in 0..STORAGE_BYTES {
            let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
            let expected = if offset == TAG_GRANULE_BYTES - 1 {
                data[0]
            } else if offset == TAG_GRANULE_BYTES {
                data[1]
            } else {
                0
            };
            // SAFETY: no executor remains active and the live raw backing
            // provides this byte; no Rust reference to guest RAM is created.
            assert_eq!(unsafe { pointer.as_ptr().read() }, expected);
        }
        assert_eq!(backing.allocation_tags().read(TAG_GRANULE_BYTES), Ok(tag));
    }
}

#[test]
fn accepted_preflight_preserves_ignore_tag_storage_checks() {
    let backing = backing(STORAGE_BYTES - 1);
    let mut policy = controls(TagCheckFaultMode::Ignore);
    assert_eq!(policy.validate_execution(flags::TAG_CHECKED), Ok(()));
    assert_eq!(
        policy.check(request(&backing, backing.bytes() - 1, 1, 0)),
        Err(MemoryStatus::Unsupported)
    );
}

#[test]
fn sp_alignment_requirements_match_only_resolved_effective_controls() {
    for privileged in [false, true] {
        for effective in [None, Some(false), Some(true)] {
            let mut policy = MemoryControls::new(
                LowerAddressProfile::new(ADDRESS_BITS, true).unwrap(),
                privileged,
                true,
                false,
                TagCheckFaultMode::Synchronous,
                false,
            );
            if let Some(enabled) = effective {
                policy = policy.with_effective_sp_alignment(enabled);
            }
            for required in [
                SpAlignmentRequirement::Any,
                SpAlignmentRequirement::Enabled,
                SpAlignmentRequirement::Disabled,
            ] {
                let expected = match required {
                    SpAlignmentRequirement::Any => Ok(()),
                    SpAlignmentRequirement::Enabled if effective == Some(true) => Ok(()),
                    SpAlignmentRequirement::Disabled if effective == Some(false) => Ok(()),
                    _ => Err(MemoryStatus::Unsupported),
                };
                assert_eq!(policy.validate_sp_alignment(required), expected);
            }
        }
    }
}

#[test]
fn effective_sp_control_refresh_replaces_the_previous_snapshot() {
    let original = controls(TagCheckFaultMode::Synchronous);
    let enabled = original.with_effective_sp_alignment(true);
    let disabled = enabled.with_effective_sp_alignment(false);
    assert_eq!(
        original.validate_sp_alignment(SpAlignmentRequirement::Any),
        Ok(())
    );
    assert_eq!(
        original.validate_sp_alignment(SpAlignmentRequirement::Enabled),
        Err(MemoryStatus::Unsupported)
    );
    assert_eq!(
        enabled.validate_sp_alignment(SpAlignmentRequirement::Enabled),
        Ok(())
    );
    assert_eq!(
        enabled.validate_sp_alignment(SpAlignmentRequirement::Disabled),
        Err(MemoryStatus::Unsupported)
    );
    assert_eq!(
        disabled.validate_sp_alignment(SpAlignmentRequirement::Disabled),
        Ok(())
    );
    assert_eq!(
        disabled.validate_sp_alignment(SpAlignmentRequirement::Enabled),
        Err(MemoryStatus::Unsupported)
    );
    assert_eq!(
        original.translate_address(GUEST_ADDRESS),
        disabled.translate_address(GUEST_ADDRESS)
    );
}

#[test]
fn scalable_contract_requires_the_known_supported_implementation() {
    for actual in [
        None,
        Some(MemoryImplementationProfile::ScalableTagChecks),
        Some(MemoryImplementationProfile::StreamingSveTagSuppression),
        Some(MemoryImplementationProfile::SmeTagSuppression),
    ] {
        let mut policy = controls(TagCheckFaultMode::Synchronous);
        if let Some(profile) = actual {
            policy = policy.with_implementation_profile(profile);
        }
        let expected = if actual == Some(MemoryImplementationProfile::ScalableTagChecks) {
            Ok(())
        } else {
            Err(MemoryStatus::Unsupported)
        };
        assert_eq!(
            policy.validate_implementation_profile(MemoryImplementationProfile::ScalableTagChecks),
            expected
        );
        assert_eq!(
            policy.validate_implementation_profile(
                MemoryImplementationProfile::StreamingSveTagSuppression
            ),
            Err(MemoryStatus::Unsupported)
        );
        assert_eq!(
            policy.validate_implementation_profile(MemoryImplementationProfile::SmeTagSuppression),
            Err(MemoryStatus::Unsupported)
        );
        assert_eq!(
            policy.validate_sp_alignment(SpAlignmentRequirement::Any),
            Ok(())
        );
    }
}

#[test]
fn implementation_profile_refresh_replaces_the_previous_named_choice() {
    let original = controls(TagCheckFaultMode::Synchronous).with_effective_sp_alignment(true);
    let checks =
        original.with_implementation_profile(MemoryImplementationProfile::ScalableTagChecks);
    let suppression =
        checks.with_implementation_profile(MemoryImplementationProfile::StreamingSveTagSuppression);
    assert_eq!(
        checks.validate_implementation_profile(MemoryImplementationProfile::ScalableTagChecks),
        Ok(())
    );
    assert_eq!(
        suppression.validate_implementation_profile(MemoryImplementationProfile::ScalableTagChecks),
        Err(MemoryStatus::Unsupported)
    );
    assert_eq!(
        suppression.validate_sp_alignment(SpAlignmentRequirement::Enabled),
        Ok(())
    );
    assert_eq!(
        original.translate_address(GUEST_ADDRESS),
        suppression.translate_address(GUEST_ADDRESS)
    );
}

#[test]
fn ordinary_cpu_snapshots_never_authorize_typed_operations() {
    for mode in [
        TagCheckFaultMode::Ignore,
        TagCheckFaultMode::Synchronous,
        TagCheckFaultMode::Asynchronous,
        TagCheckFaultMode::Asymmetric,
    ] {
        for policy in [
            controls(mode),
            controls(mode).with_effective_sp_alignment(true),
            controls(mode)
                .with_implementation_profile(MemoryImplementationProfile::ScalableTagChecks),
        ] {
            for class in [
                MemoryOperationClass::Atomic,
                MemoryOperationClass::Ordered,
                MemoryOperationClass::Exclusive,
            ] {
                assert_eq!(
                    policy.validate_operation_execution(class),
                    Err(MemoryStatus::Unsupported)
                );
            }
        }
    }
}
