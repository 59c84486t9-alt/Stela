//! Allocation-tag accesses through the physical memory domain.
use super::{AllocationTagPolicy, MemoryThread, PhysicalAccess};
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
    /// EL0 bulk instructions retain their architectural Undefined outcome even
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
        &self,
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
        let translated = self.policy.translate(descriptor.address)?;
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
                // SAFETY: resolution pins all exact contiguous spans and their
                // rights; the host quantity is aligned/readable/writable, the
                // target was checked, and private staging cannot alias RAM.
                mutation.attempting();
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
mod tests {
    use super::*;
    use crate::memory::backing::{AccessPermissions, MemoryBacking, MemoryView};
    use crate::memory::domain::{
        DataAccess, DataPolicy, MappingAttributes, MemoryDomain, MemorySystem,
    };
    use crate::memory::tag_transfer::Memory;
    use std::cell::UnsafeCell;
    use std::ptr::NonNull;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_ADDRESS_BITS: u8 = 48;
    const STORAGE_BYTES: usize = TAG_GRANULE_BYTES * 4;
    const GUEST_BASE: u64 = 0x1000;
    const ALIAS_BASE: u64 = 0x2000;
    const LOGICAL_TAG: u64 = 7 << 56;
    const ADDRESS_MASK: u64 = (1 << 56) - 1;
    const TEST_ERG_BYTES: u64 = TAG_GRANULE_BYTES as u64;
    const TEST_STRIPES: usize = 4;
    const RIGHTS: AccessPermissions = AccessPermissions {
        readable: true,
        writable: true,
        executable: false,
    };
    const TAGGED: MappingAttributes = MappingAttributes {
        tagged: true,
        shareable: true,
    };

    #[repr(align(16))]
    struct Storage(UnsafeCell<[u8; STORAGE_BYTES]>);

    // SAFETY: tests expose only raw pointers; all byte accesses use the domain.
    unsafe impl Sync for Storage {}

    fn backing() -> Arc<MemoryBacking> {
        backing_with_residue(0)
    }

    fn backing_with_residue(residue: usize) -> Arc<MemoryBacking> {
        assert!(residue < TAG_GRANULE_BYTES);
        let storage = Arc::new(Storage(UnsafeCell::new([0; STORAGE_BYTES])));
        // The optional residue models a valid raw backing with no native alignment.
        let pointer = NonNull::new(storage.0.get().cast::<u8>().wrapping_add(residue)).unwrap();
        // SAFETY: the retained owner supplies aligned stable raw storage; tests
        // never create references to its bytes or change its native rights.
        unsafe { MemoryBacking::new(pointer, STORAGE_BYTES - residue, RIGHTS, storage) }.unwrap()
    }

    fn view(
        backing: &Arc<MemoryBacking>,
        address: u64,
        rights: AccessPermissions,
    ) -> Arc<MemoryView> {
        MemoryView::new(Arc::clone(backing), address, 0, STORAGE_BYTES, rights).unwrap()
    }

    fn domain(
        system: &Arc<MemorySystem>,
        views: Vec<(Arc<MemoryView>, MappingAttributes)>,
        target: TargetCpu,
    ) -> Arc<MemoryDomain> {
        MemoryDomain::new(Arc::clone(system), views, target).unwrap()
    }

    #[derive(Default)]
    struct Policy {
        enabled: bool,
        privileged: bool,
        reject_data: bool,
        reject_execution: bool,
        reject_privileged: bool,
        translations: Arc<AtomicUsize>,
        data_flags: Vec<u32>,
    }

    impl DataPolicy for Policy {
        fn validate_execution(&self, required_flags: u32) -> Result<(), MemoryStatus> {
            if self.reject_execution && required_flags & flags::TAG_CHECKED != 0 {
                Err(MemoryStatus::Unsupported)
            } else {
                Ok(())
            }
        }

        fn translate(&self, address: u64) -> Result<u64, MemoryStatus> {
            self.translations.fetch_add(1, Ordering::Relaxed);
            Ok(address & ADDRESS_MASK)
        }

        fn check(&mut self, access: DataAccess<'_>) -> Result<(), MemoryStatus> {
            self.data_flags.push(access.flags);
            if self.reject_data {
                Err(MemoryStatus::Permission)
            } else {
                Ok(())
            }
        }
    }

    impl AllocationTagPolicy for Policy {
        fn validate_privilege(&self, privileged: bool) -> Result<(), MemoryStatus> {
            if privileged != self.privileged {
                Err(MemoryStatus::Unsupported)
            } else {
                Ok(())
            }
        }

        fn allocation_tag_access(
            &self,
            attributes: MappingAttributes,
            privileged: bool,
        ) -> Result<bool, MemoryStatus> {
            if privileged && self.reject_privileged {
                return Err(MemoryStatus::Unsupported);
            }
            Ok(self.enabled && attributes.tagged)
        }
    }

    fn descriptor(address: u64, kind: TransferAccessKind) -> Access {
        Access {
            address,
            kind,
            privileged: false,
            required_alignment: TAG_ALIGNMENT,
            pair: false,
            zero_bulk: false,
            data_registers: [Some(0), None],
            tag_checked: false,
        }
    }

    fn tag(value: u8) -> AllocationTag {
        AllocationTag::new(value).unwrap()
    }

    fn mark<P: DataPolicy>(
        thread: &mut MemoryThread<P>,
    ) -> monitor::Access<MemoryBacking, MemoryView, MappingAttributes> {
        let domain = &thread.domain;
        let registered = &domain.registered_views()[0];
        let access = monitor::Access::new(
            Arc::clone(registered.view.backing()),
            Arc::clone(&registered.monitor),
            0,
            TAG_ALIGNMENT,
            monitor::Shape::Pair,
        )
        .unwrap();
        domain
            .system
            .reservations
            .load(&mut thread.reservation, &access, || Ok::<_, ()>(()))
            .unwrap();
        access
    }

    fn consumes_mark<P: DataPolicy>(
        thread: &mut MemoryThread<P>,
        access: &monitor::Access<MemoryBacking, MemoryView, MappingAttributes>,
    ) -> bool {
        matches!(
            thread
                .domain
                .system
                .reservations
                .store(&mut thread.reservation, access, || Ok::<_, ()>(()))
                .unwrap(),
            monitor::ConditionalWrite::Stored(())
        )
    }

    #[test]
    fn aliases_share_one_tag_plane_and_untagged_views_keep_it_hidden() {
        let backing = backing();
        let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
        let first = domain(
            &system,
            vec![(view(&backing, GUEST_BASE, RIGHTS), TAGGED)],
            TargetCpu::Baseline,
        );
        let aliases = domain(
            &system,
            vec![
                (view(&backing, ALIAS_BASE, RIGHTS), TAGGED),
                (
                    view(&backing, ALIAS_BASE + STORAGE_BYTES as u64, RIGHTS),
                    MappingAttributes {
                        tagged: false,
                        ..TAGGED
                    },
                ),
            ],
            TargetCpu::Baseline,
        );
        let mut writer = first.thread(Policy {
            enabled: true,
            ..Policy::default()
        });
        let mut reader = aliases.thread(Policy {
            enabled: true,
            ..Policy::default()
        });
        writer
            .write_tag(
                descriptor(GUEST_BASE | LOGICAL_TAG, TransferAccessKind::TagWrite),
                tag(11),
            )
            .unwrap();
        assert_eq!(
            reader.read_tag(descriptor(
                ALIAS_BASE | LOGICAL_TAG,
                TransferAccessKind::TagRead
            )),
            Ok(tag(11))
        );
        let hidden = ALIAS_BASE + STORAGE_BYTES as u64;
        assert_eq!(
            reader.read_tag(descriptor(hidden, TransferAccessKind::TagRead)),
            Ok(AllocationTag::ZERO)
        );
        reader
            .write_tag(descriptor(hidden, TransferAccessKind::TagWrite), tag(15))
            .unwrap();
        assert_eq!(backing.allocation_tags().read(0), Ok(tag(11)));
        assert!(writer.policy.data_flags.is_empty() && reader.policy.data_flags.is_empty());
        let pointer = backing
            .host_pointer(0, TAG_GRANULE_BYTES, AccessKind::Read)
            .unwrap();
        // SAFETY: live raw backing, single-thread test and exact scalar footprint.
        assert_eq!(
            unsafe { access::read_part(pointer.as_ptr(), 8, TargetCpu::Baseline) },
            Ok(0)
        );
    }

    #[test]
    fn disabled_tag_access_still_checks_alignment_translation_and_rights() {
        let backing = backing();
        backing.allocation_tags().write(0, tag(9)).unwrap();
        let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
        let readonly = AccessPermissions {
            writable: false,
            ..RIGHTS
        };
        let domain = domain(
            &system,
            vec![(view(&backing, GUEST_BASE, readonly), TAGGED)],
            TargetCpu::Baseline,
        );
        let mut thread = domain.thread(Policy::default());
        assert_eq!(
            thread.write_tag(
                descriptor(GUEST_BASE + 1, TransferAccessKind::TagWrite),
                tag(1)
            ),
            Err(MemoryStatus::Alignment)
        );
        assert_eq!(thread.policy.translations.load(Ordering::Relaxed), 0);
        assert_eq!(
            thread.write_tag(descriptor(GUEST_BASE, TransferAccessKind::TagWrite), tag(1)),
            Err(MemoryStatus::Permission)
        );
        assert_eq!(
            thread.read_tag(descriptor(ALIAS_BASE, TransferAccessKind::TagRead)),
            Err(MemoryStatus::Translation)
        );
        assert_eq!(
            thread.read_tag(descriptor(GUEST_BASE, TransferAccessKind::TagRead)),
            Ok(AllocationTag::ZERO)
        );
        assert_eq!(backing.allocation_tags().read(0), Ok(tag(9)));
        assert!(thread.policy.data_flags.is_empty());
        let mut malformed = descriptor(GUEST_BASE, TransferAccessKind::TagRead);
        malformed.tag_checked = true;
        assert_eq!(
            thread.read_tag(malformed),
            Err(MemoryStatus::InvalidRequest)
        );
        malformed.tag_checked = false;
        malformed.required_alignment /= 2;
        assert_eq!(
            thread.read_tag(malformed),
            Err(MemoryStatus::InvalidRequest)
        );
        assert_eq!(
            thread.read_tag(descriptor(GUEST_BASE, TransferAccessKind::TagWrite)),
            Err(MemoryStatus::InvalidRequest)
        );
    }

    #[test]
    fn tag_publication_preserves_data_reservations_and_capability_declines_do_not_consume_them() {
        let backing = backing();
        let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
        let domain = domain(
            &system,
            vec![(view(&backing, GUEST_BASE, RIGHTS), TAGGED)],
            TargetCpu::Baseline,
        );
        let mut thread = domain.thread(Policy {
            enabled: true,
            ..Policy::default()
        });
        let marked = mark(&mut thread);
        thread
            .write_tag(descriptor(GUEST_BASE, TransferAccessKind::TagWrite), tag(3))
            .unwrap();
        assert!(consumes_mark(&mut thread, &marked));
        let marked = mark(&mut thread);
        assert_eq!(
            thread.write_data16(
                descriptor(GUEST_BASE, TransferAccessKind::DataWrite),
                [7; TAG_GRANULE_BYTES]
            ),
            Err(MemoryStatus::Unsupported)
        );
        assert!(consumes_mark(&mut thread, &marked));
        assert!(thread.policy.data_flags.is_empty());
        assert_eq!(backing.allocation_tags().read(0), Ok(tag(3)));
    }

    #[test]
    fn data_granules_use_writer_invalidation_and_never_request_logical_tag_checks() {
        let target = TargetCpu::detect();
        if !target.supports(TargetCpu::Cx16) {
            return;
        }
        for shareable in [false, true] {
            let backing = backing();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let attrs = MappingAttributes {
                shareable,
                ..TAGGED
            };
            let write_only = AccessPermissions {
                readable: false,
                ..RIGHTS
            };
            let domain = domain(
                &system,
                vec![(view(&backing, GUEST_BASE, write_only), attrs)],
                target,
            );
            let mut thread = domain.thread(Policy {
                reject_data: true,
                ..Policy::default()
            });
            let marked = mark(&mut thread);
            assert_eq!(
                thread.write_data16(
                    descriptor(GUEST_BASE | LOGICAL_TAG, TransferAccessKind::DataWrite),
                    [7; TAG_GRANULE_BYTES]
                ),
                Err(MemoryStatus::Permission)
            );
            assert_eq!(consumes_mark(&mut thread, &marked), !shareable);
            let marked = mark(&mut thread);
            thread.policy.reject_data = false;
            thread
                .write_data16(
                    descriptor(GUEST_BASE | LOGICAL_TAG, TransferAccessKind::DataWrite),
                    [7; TAG_GRANULE_BYTES],
                )
                .unwrap();
            assert!(!consumes_mark(&mut thread, &marked));
            assert_eq!(thread.policy.data_flags, vec![flags::WRITE, flags::WRITE]);
            let pointer = backing
                .host_pointer(0, TAG_GRANULE_BYTES, AccessKind::Read)
                .unwrap();
            // SAFETY: exact stable raw parts with no concurrent byte observers.
            let low =
                unsafe { access::read_part(pointer.as_ptr(), 8, TargetCpu::Baseline) }.unwrap();
            // SAFETY: the second scalar part stays inside the retained backing.
            let high =
                unsafe { access::read_part(pointer.as_ptr().add(8), 8, TargetCpu::Baseline) }
                    .unwrap();
            assert_eq!(
                low | (high << u64::BITS),
                u128::from_le_bytes([7; TAG_GRANULE_BYTES])
            );
            assert_eq!(backing.allocation_tags().read(0), Ok(AllocationTag::ZERO));
        }
    }

    #[test]
    fn untagged_policy_errors_and_retired_views_are_not_suppressed() {
        let backing = backing();
        let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
        let mapping = view(&backing, GUEST_BASE, RIGHTS);
        let domain = domain(
            &system,
            vec![(
                Arc::clone(&mapping),
                MappingAttributes {
                    tagged: false,
                    ..TAGGED
                },
            )],
            TargetCpu::Baseline,
        );
        let mut thread = domain.thread(Policy {
            reject_privileged: true,
            ..Policy::default()
        });
        let mut request = descriptor(GUEST_BASE, TransferAccessKind::TagRead);
        request.privileged = true;
        assert_eq!(thread.read_tag(request), Err(MemoryStatus::Unsupported));
        domain.retire(&mapping).unwrap();
        request.privileged = false;
        assert_eq!(thread.read_tag(request), Err(MemoryStatus::Translation));
        assert_eq!(
            tag_store_status(TagStoreError::UnalignedOffset),
            MemoryStatus::Unsupported
        );
        assert_eq!(
            tag_store_status(TagStoreError::OutOfBounds),
            MemoryStatus::Unsupported
        );
        assert_eq!(
            tag_store_status(TagStoreError::LockPoisoned),
            MemoryStatus::Domain
        );
        assert_eq!(
            tag_store_status(TagStoreError::AllocationFailed),
            MemoryStatus::Domain
        );
    }

    #[test]
    fn checked_entry_declines_all_data_kinds_before_tag_ram_or_reservation_effects() {
        use stela_compiler::aarch64::{AddressMode, Register};
        let operands = [
            Operand::StoreTags {
                kind: StoreKind::ZeroTag,
                source: Register::X(0),
                base: Register::X(1),
                displacement: 0,
                mode: AddressMode::Offset,
            },
            Operand::StoreTags {
                kind: StoreKind::ZeroTagPair,
                source: Register::X(0),
                base: Register::X(1),
                displacement: 0,
                mode: AddressMode::PreIndex,
            },
            Operand::StorePair {
                data: [Register::X(0), Register::X(2)],
                base: Register::X(1),
                displacement: 0,
                mode: AddressMode::PostIndex,
            },
            Operand::BulkTags {
                kind: BulkKind::StoreZero,
                data: Register::X(0),
                base: Register::X(1),
            },
        ];
        for operand in operands {
            let backing = backing();
            backing.allocation_tags().write(0, tag(9)).unwrap();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let domain = domain(
                &system,
                vec![(view(&backing, GUEST_BASE, RIGHTS), TAGGED)],
                TargetCpu::Baseline,
            );
            let mut thread = domain.thread(Policy {
                enabled: true,
                privileged: true,
                ..Policy::default()
            });
            let marked = mark(&mut thread);
            let mut registers = GuestState::default();
            registers.x[0] = (11 << 56) | 5;
            registers.x[1] = GUEST_BASE;
            registers.x[2] = u64::MAX;
            let before = registers.clone();
            let profile =
                tag_transfer::Profile::new(true, true, STORAGE_BYTES as u32, STORAGE_BYTES as u32)
                    .unwrap();
            let error = thread
                .complete_tag_memory(operand, &mut registers, profile)
                .unwrap_err();
            assert_eq!(
                error.cause,
                tag_transfer::Cause::Platform(MemoryStatus::Unsupported)
            );
            assert_eq!(error.completed, tag_transfer::Progress::default());
            assert_eq!(registers, before);
            assert_eq!(backing.allocation_tags().read(0), Ok(tag(9)));
            assert!(consumes_mark(&mut thread, &marked));
            assert_eq!(thread.policy.translations.load(Ordering::Relaxed), 0);
            assert!(thread.policy.data_flags.is_empty());
        }
    }

    #[test]
    fn checked_entry_preserves_el0_bulk_undefined_before_capability_or_sp_fault() {
        use stela_compiler::aarch64::Register;
        let backing = backing();
        let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
        let domain = domain(
            &system,
            vec![(view(&backing, GUEST_BASE, RIGHTS), TAGGED)],
            TargetCpu::Baseline,
        );
        let mut thread = domain.thread(Policy {
            enabled: true,
            reject_execution: true,
            ..Policy::default()
        });
        let mut registers = GuestState {
            sp: GUEST_BASE + 1,
            ..GuestState::default()
        };
        let before = registers.clone();
        let profile =
            tag_transfer::Profile::new(false, true, STORAGE_BYTES as u32, STORAGE_BYTES as u32)
                .unwrap();
        let operand = Operand::BulkTags {
            kind: BulkKind::StoreZero,
            data: Register::X(0),
            base: Register::Sp,
        };
        let error = thread
            .complete_tag_memory(operand, &mut registers, profile)
            .unwrap_err();
        assert_eq!(error.cause, tag_transfer::Cause::UndefinedPrivilege);
        assert_eq!(error.completed, tag_transfer::Progress::default());
        assert_eq!(registers, before);
        assert_eq!(backing.allocation_tags().read(0), Ok(AllocationTag::ZERO));
        assert_eq!(thread.policy.translations.load(Ordering::Relaxed), 0);
        assert!(thread.policy.data_flags.is_empty());
    }

    #[test]
    fn checked_entry_keeps_unchecked_tag_operations_available_in_async_data_modes() {
        use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
        use stela_compiler::aarch64::{AddressMode, Register};
        use stela_compiler::context::memory::MemoryRequest;

        let target = TargetCpu::detect();
        if !target.supports(TargetCpu::Cx16) {
            return;
        }
        for mode in [
            TagCheckFaultMode::Asynchronous,
            TagCheckFaultMode::Asymmetric,
        ] {
            for bulk in [false, true] {
                let backing = backing();
                for offset in 0..STORAGE_BYTES {
                    let pointer = backing.host_pointer(offset, 1, AccessKind::Write).unwrap();
                    // SAFETY: private live raw storage with no concurrent byte accesses.
                    unsafe { pointer.as_ptr().write(0xa5) };
                }
                for offset in (0..STORAGE_BYTES).step_by(TAG_GRANULE_BYTES) {
                    backing.allocation_tags().write(offset, tag(9)).unwrap();
                }
                let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
                let domain = domain(
                    &system,
                    vec![(view(&backing, GUEST_BASE, RIGHTS), TAGGED)],
                    target,
                );
                let controls = MemoryControls::new(
                    LowerAddressProfile::new(TEST_ADDRESS_BITS, true).unwrap(),
                    bulk,
                    true,
                    false,
                    mode,
                    false,
                );
                let mut thread = domain.thread(controls);
                let mut registers = GuestState::default();
                registers.x[0] = if bulk { 7 } else { LOGICAL_TAG };
                registers.x[1] = GUEST_BASE | LOGICAL_TAG;
                let before = registers.clone();
                let mut data = [0x41; TAG_GRANULE_BYTES];
                let request = MemoryRequest {
                    address: GUEST_BASE | LOGICAL_TAG,
                    data: data.as_mut_ptr(),
                    bytes: data.len() as u32,
                    flags: flags::WRITE | flags::TAG_CHECKED,
                    pc: 0,
                };
                // SAFETY: valid synchronous ABI objects with disjoint private staging.
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
                    // SAFETY: previous callback returned; one exact private raw byte.
                    assert_eq!(unsafe { pointer.as_ptr().read() }, 0xa5);
                }
                for offset in (0..STORAGE_BYTES).step_by(TAG_GRANULE_BYTES) {
                    assert_eq!(backing.allocation_tags().read(offset), Ok(tag(9)));
                }
                let operand = if bulk {
                    Operand::BulkTags {
                        kind: BulkKind::StoreZero,
                        data: Register::X(0),
                        base: Register::X(1),
                    }
                } else {
                    Operand::StoreTags {
                        kind: StoreKind::Tag,
                        source: Register::X(0),
                        base: Register::X(1),
                        displacement: 0,
                        mode: AddressMode::Offset,
                    }
                };
                let profile = tag_transfer::Profile::new(
                    bulk,
                    true,
                    STORAGE_BYTES as u32,
                    STORAGE_BYTES as u32,
                )
                .unwrap();
                let completion = thread
                    .complete_tag_memory(operand, &mut registers, profile)
                    .unwrap();
                let granules = if bulk {
                    STORAGE_BYTES / TAG_GRANULE_BYTES
                } else {
                    1
                };
                assert_eq!(completion.completed.tag_reads, 0);
                assert_eq!(completion.completed.tag_writes, granules as u32);
                assert_eq!(
                    completion.completed.data_granules,
                    if bulk { granules as u32 } else { 0 }
                );
                assert_eq!(registers, before);
                for offset in (0..STORAGE_BYTES).step_by(TAG_GRANULE_BYTES) {
                    let expected = if bulk || offset == 0 { tag(7) } else { tag(9) };
                    assert_eq!(backing.allocation_tags().read(offset), Ok(expected));
                }
                for offset in 0..STORAGE_BYTES {
                    let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
                    // SAFETY: completed instruction, one exact retained raw byte.
                    assert_eq!(
                        unsafe { pointer.as_ptr().read() },
                        if bulk { 0 } else { 0xa5 }
                    );
                }
            }
        }
    }

    #[test]
    fn checked_entry_rejects_forged_privilege_before_undefined_or_memory_effects() {
        use stela_compiler::aarch64::Register;
        for privileged in [false, true] {
            let backing = backing();
            backing.allocation_tags().write(0, tag(9)).unwrap();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let domain = domain(
                &system,
                vec![(view(&backing, GUEST_BASE, RIGHTS), TAGGED)],
                TargetCpu::detect(),
            );
            let mut thread = domain.thread(Policy {
                enabled: true,
                privileged,
                ..Policy::default()
            });
            let mut registers = GuestState::default();
            registers.x[0] = 5;
            registers.x[1] = GUEST_BASE;
            let before = registers.clone();
            let operand = Operand::BulkTags {
                kind: BulkKind::StoreZero,
                data: Register::X(0),
                base: Register::X(1),
            };
            let profile = tag_transfer::Profile::new(
                !privileged,
                true,
                STORAGE_BYTES as u32,
                STORAGE_BYTES as u32,
            )
            .unwrap();
            let error = thread
                .complete_tag_memory(operand, &mut registers, profile)
                .unwrap_err();
            assert_eq!(
                error.cause,
                tag_transfer::Cause::Platform(MemoryStatus::Unsupported)
            );
            assert_eq!(error.completed, tag_transfer::Progress::default());
            assert_eq!(registers, before);
            assert_eq!(backing.allocation_tags().read(0), Ok(tag(9)));
            assert_eq!(thread.policy.translations.load(Ordering::Relaxed), 0);
            assert!(thread.policy.data_flags.is_empty());
        }
    }

    #[test]
    fn checked_entry_rejects_invalid_registers_before_privilege_or_platform_checks() {
        use stela_compiler::aarch64::{AddressMode, Register};
        let backing = backing();
        let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
        let domain = domain(
            &system,
            vec![(view(&backing, GUEST_BASE, RIGHTS), TAGGED)],
            TargetCpu::Baseline,
        );
        let mut thread = domain.thread(Policy::default());
        let mut registers = GuestState::default();
        registers.x[1] = GUEST_BASE;
        let before = registers.clone();
        let operand = Operand::StorePair {
            data: [Register::X(u8::MAX), Register::Zero],
            base: Register::X(1),
            displacement: 0,
            mode: AddressMode::Offset,
        };
        let profile =
            tag_transfer::Profile::new(true, true, STORAGE_BYTES as u32, STORAGE_BYTES as u32)
                .unwrap();
        let error = thread
            .complete_tag_memory(operand, &mut registers, profile)
            .unwrap_err();
        assert_eq!(error.cause, tag_transfer::Cause::InvalidOperands);
        assert_eq!(error.completed, tag_transfer::Progress::default());
        assert_eq!(registers, before);
        assert_eq!(thread.policy.translations.load(Ordering::Relaxed), 0);
        assert!(thread.policy.data_flags.is_empty());
    }

    #[test]
    fn public_adapter_rejects_forged_privilege_before_pair_data_effects() {
        use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
        use stela_compiler::aarch64::{AddressMode, Register};
        for privileged in [false, true] {
            let backing = backing();
            backing.allocation_tags().write(0, tag(9)).unwrap();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let domain = domain(
                &system,
                vec![(view(&backing, GUEST_BASE, RIGHTS), TAGGED)],
                TargetCpu::detect(),
            );
            let controls = MemoryControls::new(
                LowerAddressProfile::new(TEST_ADDRESS_BITS, true).unwrap(),
                privileged,
                true,
                false,
                TagCheckFaultMode::Synchronous,
                false,
            );
            let mut thread = domain.thread(controls);
            let marked = mark(&mut thread);
            let mut registers = GuestState::default();
            registers.x[0] = u64::MAX;
            registers.x[1] = GUEST_BASE | LOGICAL_TAG;
            registers.x[2] = 0xa5a5_a5a5_a5a5_a5a5;
            let before = registers.clone();
            let operand = Operand::StorePair {
                data: [Register::X(0), Register::X(2)],
                base: Register::X(1),
                displacement: 0,
                mode: AddressMode::PostIndex,
            };
            let profile = tag_transfer::Profile::new(
                !privileged,
                true,
                STORAGE_BYTES as u32,
                STORAGE_BYTES as u32,
            )
            .unwrap();
            let error =
                tag_transfer::complete(operand, &mut registers, profile, &mut thread).unwrap_err();
            assert!(matches!(
                error.cause,
                tag_transfer::Cause::Access {
                    error: MemoryStatus::Unsupported,
                    ..
                }
            ));
            assert_eq!(error.completed, tag_transfer::Progress::default());
            assert_eq!(registers, before);
            let mut forged = descriptor(GUEST_BASE, TransferAccessKind::DataWrite);
            forged.privileged = !privileged;
            assert_eq!(
                thread.write_data16(forged, [0x41; TAG_GRANULE_BYTES]),
                Err(MemoryStatus::Unsupported)
            );
            assert!(consumes_mark(&mut thread, &marked));
            assert_eq!(backing.allocation_tags().read(0), Ok(tag(9)));
            for offset in 0..STORAGE_BYTES {
                let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
                // SAFETY: both rejected calls returned; private exact raw byte.
                assert_eq!(unsafe { pointer.as_ptr().read() }, 0);
            }
        }
    }

    #[test]
    fn cached_profile_declines_native_or_tag_plane_misalignment_before_first_effect() {
        use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
        use stela_compiler::aarch64::Register;
        for tag_only in [false, true] {
            let first = if tag_only {
                backing()
            } else {
                backing_with_residue(1)
            };
            let second = backing_with_residue(1);
            first.allocation_tags().write(0, tag(9)).unwrap();
            second.allocation_tags().write(0, tag(3)).unwrap();
            second
                .allocation_tags()
                .write(TAG_GRANULE_BYTES, tag(3))
                .unwrap();
            let views = if tag_only {
                vec![
                    (
                        MemoryView::new(
                            Arc::clone(&first),
                            GUEST_BASE,
                            0,
                            TAG_GRANULE_BYTES,
                            RIGHTS,
                        )
                        .unwrap(),
                        TAGGED,
                    ),
                    (
                        MemoryView::new(
                            Arc::clone(&second),
                            GUEST_BASE + TAG_GRANULE_BYTES as u64,
                            TAG_GRANULE_BYTES - 1,
                            TAG_GRANULE_BYTES,
                            RIGHTS,
                        )
                        .unwrap(),
                        TAGGED,
                    ),
                ]
            } else {
                vec![(
                    MemoryView::new(
                        Arc::clone(&first),
                        GUEST_BASE,
                        0,
                        TAG_GRANULE_BYTES * 2,
                        RIGHTS,
                    )
                    .unwrap(),
                    TAGGED,
                )]
            };
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let domain = domain(&system, views, TargetCpu::detect());
            let controls = MemoryControls::new(
                LowerAddressProfile::new(TEST_ADDRESS_BITS, true).unwrap(),
                true,
                true,
                false,
                TagCheckFaultMode::Synchronous,
                false,
            );
            let mut thread = domain.thread(controls);
            let marked = mark(&mut thread);
            let mut registers = GuestState::default();
            registers.x[0] = (8 << 56) | 8;
            registers.x[1] = GUEST_BASE;
            let before = registers.clone();
            let operand = if tag_only {
                Operand::StoreTags {
                    kind: StoreKind::TagPair,
                    source: Register::X(0),
                    base: Register::X(1),
                    displacement: 0,
                    mode: stela_compiler::aarch64::AddressMode::Offset,
                }
            } else {
                Operand::BulkTags {
                    kind: BulkKind::StoreZero,
                    data: Register::X(0),
                    base: Register::X(1),
                }
            };
            let block_bytes = (TAG_GRANULE_BYTES * 2) as u32;
            let profile = tag_transfer::Profile::new(true, true, block_bytes, block_bytes).unwrap();
            let error = thread
                .complete_tag_memory(operand, &mut registers, profile)
                .unwrap_err();
            assert_eq!(
                error.cause,
                tag_transfer::Cause::Platform(MemoryStatus::Unsupported)
            );
            assert_eq!(error.completed, tag_transfer::Progress::default());
            assert_eq!(registers, before);
            assert!(consumes_mark(&mut thread, &marked));
            assert_eq!(first.allocation_tags().read(0), Ok(tag(9)));
            for offset in [0, TAG_GRANULE_BYTES] {
                assert_eq!(second.allocation_tags().read(offset), Ok(tag(3)));
            }
            for backing in [&first, &second] {
                for offset in 0..backing.bytes() {
                    let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
                    // SAFETY: declined execution, retained private raw backing byte.
                    assert_eq!(unsafe { pointer.as_ptr().read() }, 0);
                }
            }
        }
    }

    #[test]
    fn unused_tag_plane_does_not_restrict_disabled_or_untagged_stores() {
        use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
        use stela_compiler::aarch64::{AddressMode, Register};
        for (tagged, enabled) in [(true, false), (false, true), (true, true)] {
            let backing = backing_with_residue(1);
            backing.allocation_tags().write(0, tag(9)).unwrap();
            backing
                .allocation_tags()
                .write(TAG_GRANULE_BYTES, tag(9))
                .unwrap();
            let mapping = MemoryView::new(
                Arc::clone(&backing),
                GUEST_BASE,
                TAG_GRANULE_BYTES - 1,
                TAG_GRANULE_BYTES,
                RIGHTS,
            )
            .unwrap();
            let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
            let domain = domain(
                &system,
                vec![(mapping, MappingAttributes { tagged, ..TAGGED })],
                TargetCpu::Baseline,
            );
            let controls = MemoryControls::new(
                LowerAddressProfile::new(TEST_ADDRESS_BITS, true).unwrap(),
                false,
                enabled,
                false,
                TagCheckFaultMode::Synchronous,
                false,
            );
            let mut thread = domain.thread(controls);
            let mut registers = GuestState::default();
            registers.x[0] = LOGICAL_TAG;
            registers.x[1] = GUEST_BASE;
            let before = registers.clone();
            let operand = Operand::StoreTags {
                kind: StoreKind::Tag,
                source: Register::X(0),
                base: Register::X(1),
                displacement: 0,
                mode: AddressMode::Offset,
            };
            let profile =
                tag_transfer::Profile::new(false, true, STORAGE_BYTES as u32, STORAGE_BYTES as u32)
                    .unwrap();
            let result = thread.complete_tag_memory(operand, &mut registers, profile);
            if tagged && enabled {
                let error = result.unwrap_err();
                assert_eq!(
                    error.cause,
                    tag_transfer::Cause::Platform(MemoryStatus::Unsupported)
                );
                assert_eq!(error.completed, tag_transfer::Progress::default());
            } else {
                assert_eq!(
                    result.unwrap().completed,
                    tag_transfer::Progress {
                        tag_reads: 0,
                        tag_writes: 1,
                        data_granules: 0,
                    }
                );
            }
            assert_eq!(registers, before);
            for offset in [0, TAG_GRANULE_BYTES] {
                assert_eq!(backing.allocation_tags().read(offset), Ok(tag(9)));
            }
        }
    }

    #[test]
    fn incompatible_physical_fragments_decline_before_an_earlier_granule_changes() {
        use crate::memory::policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode};
        use stela_compiler::aarch64::{AddressMode, Register};
        const HALF_GRANULE_BYTES: usize = TAG_GRANULE_BYTES / 2;
        for tag_only in [false, true] {
            for enabled in [false, true] {
                let backings = [backing(), backing(), backing()];
                for backing in &backings {
                    backing.allocation_tags().write(0, tag(9)).unwrap();
                    for offset in 0..backing.bytes() {
                        let pointer = backing.host_pointer(offset, 1, AccessKind::Write).unwrap();
                        // SAFETY: private retained raw storage before execution.
                        unsafe { pointer.as_ptr().write(0xa5) };
                    }
                }
                let views = vec![
                    (
                        MemoryView::new(
                            Arc::clone(&backings[0]),
                            GUEST_BASE,
                            0,
                            TAG_GRANULE_BYTES,
                            RIGHTS,
                        )
                        .unwrap(),
                        TAGGED,
                    ),
                    (
                        MemoryView::new(
                            Arc::clone(&backings[1]),
                            GUEST_BASE + TAG_GRANULE_BYTES as u64,
                            0,
                            HALF_GRANULE_BYTES,
                            RIGHTS,
                        )
                        .unwrap(),
                        TAGGED,
                    ),
                    (
                        MemoryView::new(
                            Arc::clone(&backings[2]),
                            GUEST_BASE + (TAG_GRANULE_BYTES + HALF_GRANULE_BYTES) as u64,
                            HALF_GRANULE_BYTES,
                            HALF_GRANULE_BYTES,
                            RIGHTS,
                        )
                        .unwrap(),
                        TAGGED,
                    ),
                ];
                let system = MemorySystem::new(TEST_ERG_BYTES, TEST_STRIPES).unwrap();
                let domain = domain(&system, views, TargetCpu::detect());
                let controls = MemoryControls::new(
                    LowerAddressProfile::new(TEST_ADDRESS_BITS, true).unwrap(),
                    true,
                    enabled,
                    false,
                    TagCheckFaultMode::Synchronous,
                    false,
                );
                let mut thread = domain.thread(controls);
                let marked = mark(&mut thread);
                let mut registers = GuestState::default();
                registers.x[0] = (8 << 56) | 8;
                registers.x[1] = GUEST_BASE;
                let before = registers.clone();
                let operand = if tag_only {
                    Operand::StoreTags {
                        kind: StoreKind::TagPair,
                        source: Register::X(0),
                        base: Register::X(1),
                        displacement: 0,
                        mode: AddressMode::Offset,
                    }
                } else {
                    Operand::BulkTags {
                        kind: BulkKind::StoreZero,
                        data: Register::X(0),
                        base: Register::X(1),
                    }
                };
                let block_bytes = (TAG_GRANULE_BYTES * 2) as u32;
                let profile =
                    tag_transfer::Profile::new(true, true, block_bytes, block_bytes).unwrap();
                let error = thread
                    .complete_tag_memory(operand, &mut registers, profile)
                    .unwrap_err();
                assert_eq!(
                    error.cause,
                    tag_transfer::Cause::Platform(MemoryStatus::Unsupported)
                );
                assert_eq!(error.completed, tag_transfer::Progress::default());
                assert_eq!(registers, before);
                assert!(consumes_mark(&mut thread, &marked));
                for backing in &backings {
                    assert_eq!(backing.allocation_tags().read(0), Ok(tag(9)));
                    for offset in 0..backing.bytes() {
                        let pointer = backing.host_pointer(offset, 1, AccessKind::Read).unwrap();
                        // SAFETY: preflight returned without executing, exact raw byte.
                        assert_eq!(unsafe { pointer.as_ptr().read() }, 0xa5);
                    }
                }
            }
        }
    }
}
