//! Allocation-tag accesses through the physical memory domain.
use super::{
    AllocationTagPolicy, DataOperation, DataPart, DataRequest, MemoryThread, PhysicalAccess,
};
use crate::memory::{
    access,
    backing::AccessKind,
    monitor,
    tag_store::{TAG_GRANULE_BYTES, TagStoreError},
    tag_transfer::{self, Access, AccessKind as TransferAccessKind},
    tags::AllocationTag,
};
use alloc::sync::Arc;
use stela_compiler::{
    GuestState, TargetCpu,
    aarch64::tag_memory::{BulkKind, Operand, StoreKind},
    context::memory::{MemoryRequirements, MemoryStatus, flags, host_caps, profile_requirements},
};

const TAG_ALIGNMENT: u8 = TAG_GRANULE_BYTES as u8;
const TAG_GRANULE_MASK: u64 = (TAG_GRANULE_BYTES - 1) as u64;

impl<P: AllocationTagPolicy> MemoryThread<P> {
    /// Execute through the checked platform entry before any guest effects.
    /// EL0 bulk instructions keep their architectural Undefined outcome even
    /// when the host lacks the capability required by privileged data writes.
    pub fn complete_tag_memory(
        &mut self,
        operand: Operand,
        registers: &mut GuestState,
        profile: tag_transfer::Profile,
    ) -> Result<tag_transfer::Completion, tag_transfer::Fault<MemoryStatus>> {
        if !operand.is_valid() {
            return Err(tag_transfer::Fault {
                cause: tag_transfer::Cause::InvalidOperands,
                completed: tag_transfer::Progress::default(),
            });
        }
        let platform_fault = |status| tag_transfer::Fault {
            cause: tag_transfer::Cause::Platform(status),
            completed: tag_transfer::Progress::default(),
        };
        let _loan = self.execution_loan().map_err(platform_fault)?;
        self.policy
            .validate_privilege(profile.privileged())
            .map_err(platform_fault)?;
        if operand.requires_privilege() && !profile.privileged() {
            return tag_transfer::complete(operand, registers, profile, self);
        }
        let mut requirements = MemoryRequirements {
            required_profile: profile_requirements::TAG_GRANULES,
            ..MemoryRequirements::default()
        };
        if writes_data_granules(operand) {
            requirements.required_flags = flags::WRITE;
            requirements.required_profile |= profile_requirements::NATIVE_ACCESS;
            requirements.required_host_caps = host_caps::CX16;
        }
        // The cached profile rejects unsupported physical representations before
        // any tag/data effects. Disabled allocation access needs no tag plane.
        let entry = self
            .prepare_tag(requirements, profile.privileged())
            .map_err(platform_fault)?;
        tag_transfer::complete(operand, registers, profile, entry.thread_mut())
    }

    fn resolve_tag_transfer(
        &mut self,
        descriptor: Access,
        expected: TransferAccessKind,
        kind: AccessKind,
    ) -> Result<PhysicalAccess, MemoryStatus> {
        if descriptor.kind != expected
            || descriptor.tag_checked
            || descriptor.required_alignment != TAG_ALIGNMENT
        {
            return Err(MemoryStatus::InvalidRequest);
        }
        // Dedicated tag stores enforce alignment even with ATA disabled or an
        // untagged mapping. The helper has already rounded down LDG addresses.
        if descriptor.address & TAG_GRANULE_MASK != 0 {
            return Err(MemoryStatus::Alignment);
        }
        self.policy.validate_privilege(descriptor.privileged)?;
        self.domain.check_execution()?;
        let intent = DataRequest {
            address: descriptor.address,
            bytes: TAG_GRANULE_BYTES,
            flags: if kind == AccessKind::Write {
                flags::WRITE
            } else {
                0
            },
            pc: None,
            operation: DataOperation::AllocationTag,
        };
        self.policy.validate_data_request(intent)?;
        let translated = self
            .policy
            .translate_part(
                intent,
                DataPart {
                    address: descriptor.address,
                    bytes: TAG_GRANULE_BYTES,
                    kind,
                },
            )
            .map_err(|(status, _)| status)?;
        self.domain.resolve(translated, TAG_GRANULE_BYTES, kind)
    }

    fn allocation_access_enabled(
        &self,
        descriptor: Access,
        physical: &PhysicalAccess,
    ) -> Result<bool, MemoryStatus> {
        let enabled = self
            .policy
            .allocation_tag_access(physical.attributes, descriptor.privileged)?;
        Ok(enabled && physical.attributes.tagged)
    }
}

impl<P: AllocationTagPolicy> tag_transfer::Memory for MemoryThread<P> {
    type Error = MemoryStatus;

    fn read_tag(&mut self, descriptor: Access) -> Result<AllocationTag, Self::Error> {
        let _loan = self.execution_loan()?;
        let physical =
            self.resolve_tag_transfer(descriptor, TransferAccessKind::TagRead, AccessKind::Read)?;
        if !self.allocation_access_enabled(descriptor, &physical)? {
            return Ok(AllocationTag::ZERO);
        }
        let first = physical.first();
        first
            .view()
            .backing()
            .allocation_tags()
            .read(first.backing_offset())
            .map_err(tag_store_status)
    }

    fn write_tag(&mut self, descriptor: Access, tag: AllocationTag) -> Result<(), Self::Error> {
        let _loan = self.execution_loan()?;
        let physical =
            self.resolve_tag_transfer(descriptor, TransferAccessKind::TagWrite, AccessKind::Write)?;
        if !self.allocation_access_enabled(descriptor, &physical)? {
            return Ok(());
        }
        let first = physical.first();
        // Allocation tags are independent of the data bytes and exclusive data
        // reservations. The backing store publishes one tag atomically.
        first
            .view()
            .backing()
            .allocation_tags()
            .write(first.backing_offset(), tag)
            .map_err(tag_store_status)
    }

    fn write_data16(
        &mut self,
        descriptor: Access,
        data: [u8; TAG_GRANULE_BYTES],
    ) -> Result<(), Self::Error> {
        let _loan = self.execution_loan()?;
        let physical = self.resolve_tag_transfer(
            descriptor,
            TransferAccessKind::DataWrite,
            AccessKind::Write,
        )?;
        let target = self.domain.target;
        let first = physical.first();
        let pointer = first.host_ptr().as_ptr();
        if !cfg!(target_arch = "x86_64")
            || !target.supports(TargetCpu::Cx16)
            || pointer as usize & (TAG_GRANULE_BYTES - 1) != 0
        {
            return Err(MemoryStatus::Unsupported);
        }
        // CMPXCHG16B reads its exact host quantity. This recipe requirement is
        // distinct from the guest write permission checked by resolve above.
        first
            .view()
            .backing()
            .host_pointer(first.backing_offset(), TAG_GRANULE_BYTES, AccessKind::Read)
            .map_err(|_| MemoryStatus::Unsupported)?;
        let range = monitor::WriteRange::new(
            Arc::clone(first.view().backing()),
            first.backing_offset() as u64,
            TAG_GRANULE_BYTES as u64,
        )
        .map_err(|_| MemoryStatus::Domain)?;
        let invalidation = if physical.attributes.shareable {
            monitor::Invalidation::BeforeAttempt
        } else {
            monitor::Invalidation::OnCommit
        };
        let mut mutation = self.domain.system.prepare_source_write(
            first.view().backing(),
            first.backing_offset(),
            TAG_GRANULE_BYTES,
        )?;
        self.domain
            .system
            .reservations
            .with_writer(&range, invalidation, || {
                self.policy.check(physical.data(
                    descriptor.address,
                    TAG_GRANULE_BYTES,
                    flags::WRITE,
                ))?;
                mutation.attempting();
                // SAFETY: Resolution pins this whole aligned writable host quantity and checks
                // the target. The writer gate is held, and private staging is disjoint.
                unsafe {
                    access::write_part(
                        pointer,
                        TAG_GRANULE_BYTES,
                        u128::from_le_bytes(data),
                        target,
                    )
                }
                .map_err(|_| MemoryStatus::Unsupported)?;
                let _receipt = mutation.complete();
                Ok::<_, MemoryStatus>(())
            })
            .map_err(|error| match error {
                monitor::AccessError::Monitor(_) => MemoryStatus::Domain,
                monitor::AccessError::Memory(status) => status,
            })
    }
}

fn writes_data_granules(operand: Operand) -> bool {
    matches!(
        operand,
        Operand::StoreTags {
            kind: StoreKind::ZeroTag | StoreKind::ZeroTagPair,
            ..
        } | Operand::StorePair { .. }
            | Operand::BulkTags {
                kind: BulkKind::StoreZero,
                ..
            }
    )
}

fn tag_store_status(error: TagStoreError) -> MemoryStatus {
    match error {
        TagStoreError::UnalignedOffset | TagStoreError::OutOfBounds => MemoryStatus::Unsupported,
        TagStoreError::EmptyBacking
        | TagStoreError::LockPoisoned
        | TagStoreError::AllocationFailed => MemoryStatus::Domain,
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
