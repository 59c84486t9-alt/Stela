//! Immutable native-storage eligibility, separate from scalable CPU state.

use super::{
    AllocationTagPolicy, DataPolicy, MappingAttributes, MemoryThread, MemoryView, SCA_BYTES,
};
use crate::memory::{backing::AccessKind, tag_store::TAG_GRANULE_BYTES};
use std::sync::Arc;
use stela_compiler::{
    TargetCpu,
    context::memory::{
        MemoryContextView, MemoryImplementationProfile, MemoryRequirements, MemoryStatus, flags,
        host_caps, profile_requirements,
    },
};

/// Cached properties of host storage, never a prewalk of guest permissions or
/// logical tags. The backing constructor pins these rights and extents for the
/// immutable domain's lifetime. The supported native data profile is coherent
/// Normal-WB, LSE2/SCA16, AlignmentEnforced=false and CPA2 disabled; emitters
/// retain original-SP checks independently.
pub struct MemoryProfile {
    native_congruent: bool,
    reservation_congruent: bool,
    native_fragments: bool,
    tag_fragments: bool,
    writable_host_readable: bool,
    read_envelopes: bool,
    tag_ineligible: Vec<MappingAttributes>,
}

impl MemoryProfile {
    pub(super) fn inspect(views: &[(Arc<MemoryView>, MappingAttributes)]) -> Self {
        let mut profile = Self {
            native_congruent: cfg!(target_arch = "x86_64"),
            reservation_congruent: true,
            native_fragments: fragments_compatible(views, SCA_BYTES),
            tag_fragments: fragments_compatible(views, TAG_GRANULE_BYTES),
            writable_host_readable: true,
            read_envelopes: true,
            tag_ineligible: Vec::new(),
        };
        for (view, attributes) in views {
            let backing = view.backing();
            // Construction has already checked this physical extent. Taking
            // its address grants no guest permission and reads no guest byte.
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
        if requirements.required_flags & !flags::KNOWN != 0
            || requirements.required_host_caps & !host_caps::KNOWN != 0
            || requirements.required_profile & !profile_requirements::KNOWN != 0
        {
            return Err(MemoryStatus::InvalidRequest);
        }
        if !target.supported()
            || requirements.required_host_caps & host_caps::ATOMIC_LOAD16 != 0
                && !target.supports(TargetCpu::AtomicLoad16)
            || requirements.required_host_caps & host_caps::CX16 != 0
                && !target.supports(TargetCpu::Cx16)
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
        if requirements.required_flags & flags::EXCLUSIVE != 0
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
}

impl<'a, P: DataPolicy> CheckedMemoryEntry<'a, P> {
    pub(super) fn new(thread: &'a mut MemoryThread<P>) -> Self {
        Self { thread }
    }

    /// Consume this entry when binding the checked native body's service view.
    ///
    /// # Safety
    /// The callback must obey `MemoryThread::with_view`'s invocation contract,
    /// and its body must be bound to the requirements used to prepare this entry.
    pub unsafe fn with_view<R>(self, callback: impl FnOnce(&mut MemoryContextView) -> R) -> R {
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
        // SAFETY: the caller binds the checked body's exact requirements and
        // inherits the low-level callback's staging and lifetime contract.
        unsafe { self.thread.with_checked_view(callback) }
    }

    /// Consume entry for a dedicated service whose typed adapter owns the
    /// complete checked operation and does not mutate effective controls.
    pub fn thread_mut(self) -> &'a mut MemoryThread<P> {
        self.thread
    }
}

impl<P: AllocationTagPolicy> MemoryThread<P> {
    /// Dedicated tag access preflight uses authoritative privilege and actual
    /// cached mapping attributes. Disabled ATA/untagged storage does not use the
    /// physical tag plane and therefore needs no unused tag-plane requirements.
    pub fn prepare_tag(
        &mut self,
        requirements: MemoryRequirements,
        privileged: bool,
    ) -> Result<CheckedMemoryEntry<'_, P>, MemoryStatus> {
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
                .profile
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
                if !owner.domain.profile.tag_fragments {
                    return Err(MemoryStatus::Unsupported);
                }
                for attributes in &owner.domain.profile.tag_ineligible {
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
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| validate(self))) {
            Ok(Ok(())) => Ok(CheckedMemoryEntry::new(self)),
            Ok(Err(status)) => {
                self.settle_fault(status)?;
                Err(status)
            }
            Err(_) => {
                self.domain
                    .system
                    .failed
                    .store(true, std::sync::atomic::Ordering::Release);
                let _ = self.domain.system.reservations.clear(&mut self.reservation);
                Err(MemoryStatus::Domain)
            }
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "profile/tests.rs"]
mod tests;
