//! Which native storage a memory profile may use.

use super::{
    AllocationTagPolicy, DataPolicy, MappingAttributes, MemoryThread, MemoryView, SCA_BYTES,
};
use crate::memory::{backing::AccessKind, tag_store::TAG_GRANULE_BYTES};
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use stela_compiler::{
    TargetCpu,
    context::memory::{
        MemoryContextView, MemoryImplementationProfile, MemoryRequirements, MemoryStatus, flags,
        host_caps, profile_requirements,
    },
};

/// Cached properties of the host storage (not guest permissions or tags),
/// pinned for the domain's lifetime. Native data access supports coherent
/// write-back RAM with FEAT_LSE2 16-byte atomicity, unenforced alignment and
/// FEAT_CPA2 off; emitters still check SP.
#[derive(Clone)]
pub struct MemoryProfile {
    native_congruent: bool,
    reservation_congruent: bool,
    native_fragments: bool,
    tag_fragments: bool,
    writable_host_readable: bool,
    read_envelopes: bool,
    read_write_envelopes: bool,
    tag_ineligible: Vec<MappingAttributes>,
}

// Profiles that need their own physical, source and control owners; the generic
// entry points never accept them.
const SEPARATELY_OWNED_M0_PROFILES: u32 = profile_requirements::M0_DEVICE_RAM_READ64
    | profile_requirements::M0_DEVICE_RAM_WRITE8_OR_PAIR
    | profile_requirements::M0_DEVICE_RAM_READ64_PAIR_NO_LSE2
    | profile_requirements::M0_DEVICE_RAM_SCALAR_LOAD
    | profile_requirements::M0_DEVICE_RAM_SCALAR_STORE;

impl MemoryProfile {
    pub(super) fn inspect(views: &[(Arc<MemoryView>, MappingAttributes)]) -> Self {
        let mut profile = Self {
            native_congruent: cfg!(target_arch = "x86_64"),
            reservation_congruent: true,
            native_fragments: fragments_compatible(views, SCA_BYTES),
            tag_fragments: fragments_compatible(views, TAG_GRANULE_BYTES),
            writable_host_readable: true,
            read_envelopes: true,
            read_write_envelopes: true,
            tag_ineligible: Vec::new(),
        };
        for (view, attributes) in views {
            let backing = view.backing();
            // The extent is already checked; taking its address reads nothing.
            let pointer = backing.host_pointer(
                view.backing_offset(),
                view.bytes(),
                if backing.maximum_permissions().readable {
                    AccessKind::Read
                } else {
                    AccessKind::Write
                },
            );
            if view.permissions().readable || view.permissions().writable {
                // Monitor ERGs are backing-relative and at least 16 bytes.
                // Source SCA16 containment must imply one relative granule.
                profile.reservation_congruent &= view.guest_base() as usize & (SCA_BYTES - 1)
                    == view.backing_offset() & (SCA_BYTES - 1);
                profile.native_congruent &= pointer.is_ok_and(|pointer| {
                    pointer.as_ptr() as usize & (SCA_BYTES - 1)
                        == view.guest_base() as usize & (SCA_BYTES - 1)
                });
            }
            if view.permissions().writable {
                profile.writable_host_readable &= backing.maximum_permissions().readable;
            }
            if view.permissions().readable {
                let host = pointer
                    .expect("readable backing extent checked by view construction")
                    .as_ptr() as usize;
                let prefix = host & (SCA_BYTES - 1);
                let envelope_start = view.backing_offset().checked_sub(prefix);
                let envelope_bytes = prefix
                    .checked_add(view.bytes())
                    .and_then(|bytes| bytes.checked_add(SCA_BYTES - 1))
                    .map(|bytes| bytes & !(SCA_BYTES - 1));
                profile.read_write_envelopes &=
                    envelope_start
                        .zip(envelope_bytes)
                        .is_some_and(|(offset, bytes)| {
                            backing
                                .host_pointer(offset, bytes, AccessKind::Write)
                                .is_ok()
                        });
                profile.read_envelopes &=
                    envelope_start
                        .zip(envelope_bytes)
                        .is_some_and(|(offset, bytes)| {
                            backing
                                .host_pointer(offset, bytes, AccessKind::Read)
                                .is_ok()
                        });
            }
            // Physical tags are indexed relative to the backing, not the
            // native pointer. Include complete granules covering the view.
            let congruent = view.guest_base() as usize & (TAG_GRANULE_BYTES - 1)
                == view.backing_offset() & (TAG_GRANULE_BYTES - 1);
            let end = view.backing_offset() + view.bytes();
            let complete = end
                .checked_add(TAG_GRANULE_BYTES - 1)
                .is_some_and(|end| (end & !(TAG_GRANULE_BYTES - 1)) <= backing.bytes());
            if (!congruent || !complete) && !profile.tag_ineligible.contains(attributes) {
                profile.tag_ineligible.push(*attributes);
            }
        }
        profile
    }

    pub(super) fn validate(
        &self,
        requirements: MemoryRequirements,
        target: TargetCpu,
    ) -> Result<(), MemoryStatus> {
        if requirements.context_version != stela_compiler::context::memory::MEMORY_CONTEXT_VERSION {
            return Err(MemoryStatus::Unsupported);
        }
        if !requirements.required_instructions.valid() {
            return Err(MemoryStatus::InvalidRequest);
        }
        if requirements.required_flags & !flags::KNOWN != 0
            || requirements.required_host_caps & !host_caps::KNOWN != 0
            || requirements.required_profile & !profile_requirements::KNOWN != 0
        {
            return Err(MemoryStatus::InvalidRequest);
        }
        // The staged M0 profiles are not generic memory permission; their own
        // owner must admit them.
        if requirements.required_profile & SEPARATELY_OWNED_M0_PROFILES != 0 {
            return Err(MemoryStatus::Unsupported);
        }
        // Actual host admission belongs to the domain/prepared entry. This
        // profile checks storage geometry and the retained target's recipes.
        if requirements.required_host_caps & host_caps::ATOMIC_LOAD16 != 0
            && !target.supports(TargetCpu::AtomicLoad16)
            || requirements.required_host_caps & host_caps::CX16 != 0
                && !target.supports(TargetCpu::Cx16)
        {
            return Err(MemoryStatus::Unsupported);
        }
        if requirements.required_profile & profile_requirements::SYSTEM_ATOMIC_READ_WRITEBACK != 0
            && (!self.read_envelopes
                || !self.read_write_envelopes
                || !target.supports(TargetCpu::Cx16))
        {
            return Err(MemoryStatus::Unsupported);
        }
        if requirements.required_profile & profile_requirements::NATIVE_ACCESS != 0
            && (!self.native_congruent
                || !self.native_fragments
                || requirements.required_flags & flags::WRITE != 0 && !self.writable_host_readable
                || requirements.required_host_caps & host_caps::ATOMIC_LOAD16 != 0
                    && !self.read_envelopes)
        {
            return Err(MemoryStatus::Unsupported);
        }
        if requirements.required_flags & (flags::EXCLUSIVE | flags::ATOMIC) != 0
            && requirements.required_profile & profile_requirements::NATIVE_ACCESS != 0
            && !self.reservation_congruent
        {
            return Err(MemoryStatus::Unsupported);
        }
        if requirements.required_profile & profile_requirements::TAG_GRANULES != 0
            && (!self.tag_fragments
                || self
                    .tag_ineligible
                    .iter()
                    .any(|attributes| attributes.tagged))
        {
            return Err(MemoryStatus::Unsupported);
        }
        Ok(())
    }
}

/// The resolver joins adjacent fragments of one atomic quantity only when
/// physical storage and attributes agree. Guest permissions remain checked
/// separately, in reached order. Gaps retain their architectural translation
/// fault and are not replaced by a platform-layout decline.
fn fragments_compatible(views: &[(Arc<MemoryView>, MappingAttributes)], quantity: usize) -> bool {
    views.windows(2).all(|pair| {
        let (first, first_attributes) = &pair[0];
        let (next, next_attributes) = &pair[1];
        let boundary = first.guest_base() + first.bytes() as u64;
        boundary != next.guest_base()
            || boundary.is_multiple_of(quantity as u64)
            || Arc::ptr_eq(first.backing(), next.backing())
                && first.backing_offset() + first.bytes() == next.backing_offset()
                && first_attributes == next_attributes
    })
}

/// One checked synchronous entry. A mutable borrow prevents replacing the
/// thread's effective policy until consumption. A dedicated adapter consuming
/// `thread_mut` then owns the contract to keep those controls stable.
pub struct CheckedMemoryEntry<'a, P> {
    thread: &'a mut MemoryThread<P>,
    pub(super) native_system: Option<&'a crate::platform::cpu::system::NativeSystemTarget>,
}

impl<'a, P: DataPolicy> CheckedMemoryEntry<'a, P> {
    pub(super) fn new(thread: &'a mut MemoryThread<P>) -> Self {
        Self {
            thread,
            native_system: None,
        }
    }

    /// Consume this entry when binding the checked native body's service view.
    ///
    /// # Safety
    /// The callback must obey `MemoryThread::with_view`'s invocation contract,
    /// and its body must be bound to the requirements used to prepare this entry.
    pub unsafe fn with_view<R>(self, callback: impl FnOnce(&mut MemoryContextView) -> R) -> R {
        assert!(
            self.native_system.is_none(),
            "native system entry requires checked finalization"
        );
        // SAFETY: the caller binds the checked body's exact requirements and
        // inherits the low-level callback's staging and lifetime contract.
        unsafe { self.thread.with_view(callback) }
    }

    /// Consume this entry and observe finalization before returning the body result.
    /// Fault provenance needed on failure must be copied during the callback.
    ///
    /// # Safety
    /// The callback must obey `MemoryThread::with_checked_view`'s invocation
    /// contract and bind the requirements used to prepare this entry.
    pub unsafe fn with_checked_view<R>(
        self,
        callback: impl FnOnce(&mut MemoryContextView) -> R,
    ) -> Result<R, MemoryStatus> {
        if let Some(authority) = self.native_system {
            authority
                .revalidate()
                .map_err(|_| MemoryStatus::Unsupported)?;
        }
        // SAFETY: the caller binds the checked body's exact requirements and
        // inherits the low-level callback's staging and lifetime contract. The
        // actual current-owner proof remains borrowed through finalization.
        let result = unsafe { self.thread.with_checked_view(callback) };
        if let Some(authority) = self.native_system {
            authority
                .revalidate()
                .map_err(|_| MemoryStatus::Unsupported)?;
        }
        result
    }

    /// Consume entry for a dedicated service whose typed adapter owns the
    /// complete checked operation and does not mutate effective controls.
    pub fn thread_mut(self) -> &'a mut MemoryThread<P> {
        assert!(
            self.native_system.is_none(),
            "native system target loan cannot escape"
        );
        self.thread
    }
}

impl<P: AllocationTagPolicy> MemoryThread<P> {
    /// Preflight for a dedicated tag access, from the effective privilege and
    /// the mapping attributes. Untagged storage, or ATA disabled, needs no tag
    /// plane.
    pub fn prepare_tag(
        &mut self,
        requirements: MemoryRequirements,
        privileged: bool,
    ) -> Result<CheckedMemoryEntry<'_, P>, MemoryStatus> {
        if self.domain.role == super::DomainRole::NativeSystemRam {
            return Err(MemoryStatus::Unsupported);
        }
        self.prepare_with(|owner| {
            // Dedicated allocation-tag admission cannot authorize another
            // typed service through its tag-storage-specific preflight rules.
            if requirements.required_flags & (flags::ATOMIC | flags::ORDERED | flags::EXCLUSIVE)
                != 0
            {
                return Err(MemoryStatus::InvalidRequest);
            }
            owner.domain.check_execution()?;
            owner.policy.validate_privilege(privileged)?;
            let mut data_requirements = requirements;
            data_requirements.required_profile &= !profile_requirements::TAG_GRANULES;
            owner
                .domain
                .profile()?
                .validate(data_requirements, owner.domain.target)?;
            owner
                .policy
                .validate_execution(requirements.required_flags)?;
            owner
                .policy
                .validate_sp_alignment(requirements.required_sp_alignment)?;
            if requirements.required_profile & profile_requirements::SCALABLE_TAG_CHECKS != 0 {
                owner.policy.validate_implementation_profile(
                    MemoryImplementationProfile::ScalableTagChecks,
                )?;
            }
            if requirements.required_profile & profile_requirements::TAG_GRANULES != 0 {
                // Even suppressed tag storage still performs exact granule
                // translation/rights resolution through this representation.
                if !owner.domain.profile()?.tag_fragments {
                    return Err(MemoryStatus::Unsupported);
                }
                for attributes in &owner.domain.profile()?.tag_ineligible {
                    if attributes.tagged
                        && owner
                            .policy
                            .allocation_tag_access(*attributes, privileged)?
                    {
                        return Err(MemoryStatus::Unsupported);
                    }
                }
            }
            Ok(())
        })
    }
}

impl<P: DataPolicy> MemoryThread<P> {
    pub(super) fn prepare_with(
        &mut self,
        validate: impl FnOnce(&Self) -> Result<(), MemoryStatus>,
    ) -> Result<CheckedMemoryEntry<'_, P>, MemoryStatus> {
        match crate::platform::unwind::invoke(core::panic::AssertUnwindSafe(|| validate(self))) {
            Ok(Ok(())) => Ok(CheckedMemoryEntry::new(self)),
            Ok(Err(status)) => {
                self.settle_fault(status)?;
                Err(status)
            }
            Err(_) => {
                self.domain
                    .system
                    .failed
                    .store(true, core::sync::atomic::Ordering::Release);
                let _ = self.domain.system.reservations.clear(&mut self.reservation);
                Err(MemoryStatus::Domain)
            }
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
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
    // SAFETY: ownership hands out no references or unsynchronized accesses.
    unsafe impl Send for Storage {}
    // SAFETY: ownership hands out no references or unsynchronized accesses.
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
        let physical = domain.registered_views()[0].view.clone();
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
}
