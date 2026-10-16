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
mod tests;
