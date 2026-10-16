//! Address translation and allocation-tag checks for data accesses, from
//! resolved controls. The profile has MTX and store-only tag checking off.

use super::domain::{AllocationTagPolicy, DataAccess, DataPolicy, MappingAttributes};
use super::tag_store::TagStoreError;
use super::tags::{AllocationTag, TAG_GRANULE_BYTES};
use stela_compiler::context::memory::{
    MemoryImplementationProfile, MemoryOperationClass, MemoryStatus, SpAlignmentRequirement, flags,
};

const MIN_ADDRESS_BITS: u8 = 16;
const MAX_ADDRESS_BITS: u8 = 52;
const TOP_BYTE_SHIFT: u32 = 56;
const TOP_BYTE_MASK: u64 = u64::MAX << TOP_BYTE_SHIFT;
const TCMA_FIELD_SHIFT: u32 = 55;
const TCMA_FIELD_BITS: u32 = 5;
const TCMA_FIELD_MASK: u64 = ((1 << TCMA_FIELD_BITS) - 1) << TCMA_FIELD_SHIFT;
const TAG_GRANULE_MASK: usize = TAG_GRANULE_BYTES - 1;

/// One supported lower translation region with upper translation disabled.
/// Larger address profiles require their own validated platform configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowerAddressProfile {
    address_mask: u64,
    top_byte_ignore: bool,
}

impl LowerAddressProfile {
    pub const fn new(address_bits: u8, top_byte_ignore: bool) -> Result<Self, MemoryStatus> {
        if address_bits < MIN_ADDRESS_BITS || address_bits > MAX_ADDRESS_BITS {
            return Err(MemoryStatus::InvalidRequest);
        }
        Ok(Self {
            address_mask: (1 << address_bits) - 1,
            top_byte_ignore,
        })
    }

    pub const fn top_byte_ignore(self) -> bool {
        self.top_byte_ignore
    }

    fn translate(self, raw_address: u64) -> Result<u64, MemoryStatus> {
        let ignored = if self.top_byte_ignore {
            TOP_BYTE_MASK
        } else {
            0
        };
        if raw_address & !(self.address_mask | ignored) != 0 {
            return Err(MemoryStatus::Translation);
        }
        Ok(raw_address & self.address_mask)
    }
}

/// Effective TCF behavior, after architectural feature-dependent selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagCheckFaultMode {
    /// Mismatches have no architectural effect; tag-storage failures still fail.
    Ignore,
    Synchronous,
    Asynchronous,
    Asymmetric,
}

/// Typed operations admitted by the checked process policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationScope {
    Unbound,
    FixedEl0ProcessExclusive,
    FixedEl0ProcessLow128,
}

/// A per-thread snapshot of effective controls, supplied by the common CPU owner.
/// `allocation_tags_enabled` is IsMTEEnabled(el), including effective ATA and
/// higher-level controls. TCO and the selected region's TCMA remain independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryControls {
    lower_address: LowerAddressProfile,
    privileged: bool,
    allocation_tags_enabled: bool,
    tag_check_override: bool,
    tag_check_fault_mode: TagCheckFaultMode,
    tag_check_mask: bool,
    effective_sp_alignment: Option<bool>,
    pointer_checks: Option<crate::system::process_memory::ResolvedPointerChecks>,
    memory_implementation_profile: Option<MemoryImplementationProfile>,
    operation_scope: OperationScope,
}

impl MemoryControls {
    pub const fn new(
        lower_address: LowerAddressProfile,
        privileged: bool,
        allocation_tags_enabled: bool,
        tag_check_override: bool,
        tag_check_fault_mode: TagCheckFaultMode,
        tag_check_mask: bool,
    ) -> Self {
        Self {
            lower_address,
            privileged,
            allocation_tags_enabled,
            tag_check_override,
            tag_check_fault_mode,
            tag_check_mask,
            effective_sp_alignment: None,
            pointer_checks: None,
            memory_implementation_profile: None,
            operation_scope: OperationScope::Unbound,
        }
    }

    /// Build the temporary snapshot from the checked CPU authority. Only the
    /// process owner's same-thread borrow may install it; its native scope
    /// holds the controls, system state and event endpoint and restores the
    /// previous policy on every return, refusal or unwind.
    pub(crate) fn for_exclusive_authority(
        authority: &crate::system::process_memory::ExclusiveProcessMemoryAuthorization<'_>,
    ) -> Self {
        let mut controls = authority.memory_controls();
        controls.operation_scope = OperationScope::FixedEl0ProcessExclusive;
        controls
    }

    /// Admit ordinary ASIMD only while the same installed FP context and process
    /// memory owners remain borrowed by the opaque prepared invocation token.
    /// This snapshot has no raw flag/boolean constructor for the Low128 scope.
    #[cfg(feature = "std")]
    pub(crate) fn for_low128_authority(
        authority: &crate::system::process_memory::Low128ProcessMemoryAuthorization<'_, '_, '_>,
    ) -> Self {
        let mut controls = authority.memory_controls();
        controls.operation_scope = OperationScope::FixedEl0ProcessLow128;
        controls
    }

    pub(crate) fn with_pointer_authority(
        mut self,
        authority: &crate::system::process_memory::PointerMemoryAuthorization<'_>,
    ) -> Self {
        self.pointer_checks = Some(authority.checks());
        self
    }

    /// Set the effective SA0/SA for the current EL, as resolved by the CPU
    /// owner.
    pub const fn with_effective_sp_alignment(mut self, enabled: bool) -> Self {
        self.effective_sp_alignment = Some(enabled);
        self
    }

    /// Bind the CPU owner's combined SVE/SME memory implementation choice.
    /// An unknown or different choice cannot authorize the compiled contract.
    pub const fn with_implementation_profile(
        mut self,
        profile: MemoryImplementationProfile,
    ) -> Self {
        self.memory_implementation_profile = Some(profile);
        self
    }

    pub fn translate_address(&self, raw_address: u64) -> Result<u64, MemoryStatus> {
        self.lower_address.translate(raw_address)
    }

    fn check_data_tags(&self, access: DataAccess<'_>) -> Result<(), MemoryStatus> {
        if access.flags & !flags::KNOWN != 0 || access.bytes == 0 {
            return Err(MemoryStatus::InvalidRequest);
        }
        if self.translate_address(access.raw_address)? != access.translated_address {
            return Err(MemoryStatus::InvalidRequest);
        }
        let end = access
            .backing_offset
            .checked_add(access.bytes)
            .filter(|end| *end <= access.backing.bytes())
            .ok_or(MemoryStatus::InvalidRequest)?;
        if access.flags & flags::TAG_CHECKED == 0
            || !access.attributes.tagged
            || !self.allocation_tags_enabled
            || self.tag_check_override
            || !self.lower_address.top_byte_ignore
            || (self.tag_check_mask && access.raw_address & TCMA_FIELD_MASK == 0)
        {
            return Ok(());
        }
        if matches!(
            self.tag_check_fault_mode,
            TagCheckFaultMode::Asynchronous | TagCheckFaultMode::Asymmetric
        ) {
            // TFSR accumulation and asymmetric read/write checking need the
            // CPU's fault state; synchronous faults are never substituted.
            return Err(MemoryStatus::Unsupported);
        }
        let logical_tag = AllocationTag::from_address(access.raw_address);
        let first_granule = access.backing_offset & !TAG_GRANULE_MASK;
        let last_granule = (end - 1) & !TAG_GRANULE_MASK;
        for offset in (first_granule..=last_granule).step_by(TAG_GRANULE_BYTES) {
            let allocation_tag =
                access
                    .backing
                    .allocation_tags()
                    .read(offset)
                    .map_err(|error| match error {
                        // A partial physical granule needs a backing representation
                        // that can retain its complete tag; it is not a guest fault.
                        TagStoreError::OutOfBounds => MemoryStatus::Unsupported,
                        _ => MemoryStatus::Domain,
                    })?;
            if allocation_tag != logical_tag
                && self.tag_check_fault_mode == TagCheckFaultMode::Synchronous
            {
                return Err(MemoryStatus::TagCheck);
            }
        }
        Ok(())
    }
}

impl DataPolicy for MemoryControls {
    fn validate_operation_execution(
        &self,
        class: MemoryOperationClass,
    ) -> Result<(), MemoryStatus> {
        match (class, self.operation_scope) {
            (MemoryOperationClass::Exclusive, OperationScope::FixedEl0ProcessExclusive) => Ok(()),
            _ => Err(MemoryStatus::Unsupported),
        }
    }

    fn validate_implementation_profile(
        &self,
        required: MemoryImplementationProfile,
    ) -> Result<(), MemoryStatus> {
        match (required, self.memory_implementation_profile) {
            (
                MemoryImplementationProfile::ScalableTagChecks,
                Some(MemoryImplementationProfile::ScalableTagChecks),
            ) => Ok(()),
            // The compiler implements tag checking only; an implementation that
            // suppresses checks is incompatible.
            _ => Err(MemoryStatus::Unsupported),
        }
    }

    fn validate_address_checks(
        &self,
        required: stela_compiler::context::memory::address::AddressCheckRequirements,
    ) -> Result<(), MemoryStatus> {
        if required.is_empty() {
            return Ok(());
        }
        match self.pointer_checks {
            Some(checks)
                if required.matches(
                    checks.address_checks(),
                    stela_compiler::context::memory::address::IncrementChoice::Unchecked,
                ) =>
            {
                Ok(())
            }
            _ => Err(MemoryStatus::Unsupported),
        }
    }
    fn validate_pointer_arithmetic(
        &self,
        required: Option<stela_compiler::context::pointer::PointerArithmeticRequirement>,
    ) -> Result<(), MemoryStatus> {
        let Some(required) = required else {
            return Ok(());
        };
        match self.pointer_checks {
            Some(checks)
                if checks.feature().has_arithmetic()
                    && required.access_el() == stela_compiler::context::pointer::AccessEl::El0
                    && checks.arithmetic_at(required.access_el()) == required.checks() =>
            {
                Ok(())
            }
            _ => Err(MemoryStatus::Unsupported),
        }
    }

    fn validate_sp_alignment(&self, required: SpAlignmentRequirement) -> Result<(), MemoryStatus> {
        match (required, self.effective_sp_alignment) {
            (SpAlignmentRequirement::Any, _)
            | (SpAlignmentRequirement::Enabled, Some(true))
            | (SpAlignmentRequirement::Disabled, Some(false)) => Ok(()),
            _ => Err(MemoryStatus::Unsupported),
        }
    }

    fn validate_execution(&self, required_flags: u32) -> Result<(), MemoryStatus> {
        if required_flags & !flags::KNOWN != 0 {
            return Err(MemoryStatus::InvalidRequest);
        }
        // The ASIMD requirement also applies to register-only SIMD bodies that
        // request no native RAM access. Preserve it through every admission gate.
        if required_flags & flags::ASIMD != 0
            && self.operation_scope != OperationScope::FixedEl0ProcessLow128
        {
            return Err(MemoryStatus::Unsupported);
        }
        if self.operation_scope == OperationScope::FixedEl0ProcessLow128
            && required_flags
                & (flags::ATOMIC
                    | flags::ORDERED
                    | flags::EXCLUSIVE
                    | flags::SME
                    | flags::SVE_PREDICATED)
                != 0
        {
            return Err(MemoryStatus::Unsupported);
        }
        if required_flags & flags::TAG_CHECKED != 0
            && self.allocation_tags_enabled
            && !self.tag_check_override
            && self.lower_address.top_byte_ignore
            && matches!(
                self.tag_check_fault_mode,
                TagCheckFaultMode::Asynchronous | TagCheckFaultMode::Asymmetric
            )
        {
            // TCMA only exempts particular addresses. A checked instruction
            // must decline before an earlier unchecked fragment can write RAM.
            return Err(MemoryStatus::Unsupported);
        }
        Ok(())
    }

    fn translate(&self, raw_address: u64) -> Result<u64, MemoryStatus> {
        self.translate_address(raw_address)
    }

    fn check(&mut self, access: DataAccess<'_>) -> Result<(), MemoryStatus> {
        self.check_data_tags(access)
    }
}

impl AllocationTagPolicy for MemoryControls {
    fn validate_privilege(&self, privileged: bool) -> Result<(), MemoryStatus> {
        if privileged != self.privileged {
            return Err(MemoryStatus::Unsupported);
        }
        Ok(())
    }

    fn allocation_tag_access(
        &self,
        attributes: MappingAttributes,
        privileged: bool,
    ) -> Result<bool, MemoryStatus> {
        self.validate_privilege(privileged)?;
        Ok(attributes.tagged && self.allocation_tags_enabled)
    }
}

#[cfg(test)]
mod tests {
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
                                        TagCheckFaultMode::Asynchronous
                                            | TagCheckFaultMode::Asymmetric
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
                policy.validate_implementation_profile(
                    MemoryImplementationProfile::ScalableTagChecks
                ),
                expected
            );
            assert_eq!(
                policy.validate_implementation_profile(
                    MemoryImplementationProfile::StreamingSveTagSuppression
                ),
                Err(MemoryStatus::Unsupported)
            );
            assert_eq!(
                policy.validate_implementation_profile(
                    MemoryImplementationProfile::SmeTagSuppression
                ),
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
        let suppression = checks
            .with_implementation_profile(MemoryImplementationProfile::StreamingSveTagSuppression);
        assert_eq!(
            checks.validate_implementation_profile(MemoryImplementationProfile::ScalableTagChecks),
            Ok(())
        );
        assert_eq!(
            suppression
                .validate_implementation_profile(MemoryImplementationProfile::ScalableTagChecks),
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
}
