//! One authoritative ARM walk for each reached physical atomic quantity.
use super::*;
use crate::memory::{
    backing::AccessKind,
    domain::{DataAccess, DataOperation, DataPart, DataPolicy, DataRequest},
};
use stela_compiler::context::memory::{
    InstructionRequirements, MemoryOperationClass, SpAlignmentRequirement, flags,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// A reached, aligned Device read translated successfully but has no RAM
    /// backing. No device callback/effect has run; only a true recovered frame
    /// may turn this diagnostic into a stopped consuming continuation.
    DeviceRead {
        request: DataRequest,
        address: u64,
        physical: u64,
        bytes: usize,
    },
    Fault {
        request: DataRequest,
        address: u64,
        access: AccessKind,
        fault: mmu::Fault,
    },
    Unsupported {
        request: DataRequest,
        address: u64,
        reason: Refusal,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    UnalignedQuantity,
    Translation(mmu::Unsupported),
    MemoryAttributes,
    PhysicalGeometry,
}

pub(super) struct Policy {
    pub(super) controls: Controls,
    ram: Arc<RegisteredSystemRam>,
    pub(super) failure: Option<Failure>,
}
impl Policy {
    pub(super) fn new(controls: Controls, ram: Arc<RegisteredSystemRam>) -> Self {
        Self {
            controls,
            ram,
            failure: None,
        }
    }
    fn unsupported(&mut self, request: DataRequest, address: u64, reason: Refusal) -> MemoryStatus {
        self.failure.get_or_insert(Failure::Unsupported {
            request,
            address,
            reason,
        });
        MemoryStatus::Unsupported
    }
    fn fault(
        &mut self,
        request: DataRequest,
        address: u64,
        access: AccessKind,
        fault: mmu::Fault,
    ) -> MemoryStatus {
        self.failure.get_or_insert(Failure::Fault {
            request,
            address,
            access,
            fault,
        });
        match fault.kind {
            mmu::FaultKind::Permission => MemoryStatus::Permission,
            mmu::FaultKind::Alignment => MemoryStatus::Alignment,
            mmu::FaultKind::TagCheck => MemoryStatus::TagCheck,
            _ => MemoryStatus::Translation,
        }
    }
}
fn shape(request: DataRequest) -> mmu::alignment::Shape {
    use mmu::alignment::Kind;
    mmu::alignment::Shape {
        bytes: request.bytes as u64,
        pair: request.flags & flags::PAIR != 0,
        kind: match request.operation {
            DataOperation::Ordinary => Kind::Plain,
            DataOperation::Exclusive => Kind::Exclusive,
            DataOperation::Atomic => Kind::Atomic,
            DataOperation::Ordered => Kind::Ordered,
            DataOperation::AllocationTag => Kind::Plain,
        },
    }
}
impl DataPolicy for Policy {
    fn device_ram_ordering(&self) -> bool {
        self.controls.cold_m0()
    }
    fn validate_instructions(&self, required: InstructionRequirements) -> Result<(), MemoryStatus> {
        self.controls.instructions(required)
    }
    fn validate_execution(&self, required: u32) -> Result<(), MemoryStatus> {
        if required & !flags::KNOWN != 0 {
            return Err(MemoryStatus::InvalidRequest);
        }
        if required & (flags::SME | flags::SVE_PREDICATED | flags::ASIMD) != 0 {
            return Err(MemoryStatus::Unsupported);
        }
        Ok(())
    }
    fn validate_operation_execution(
        &self,
        _class: MemoryOperationClass,
    ) -> Result<(), MemoryStatus> {
        // Cold Device-nGnRnE ordinary RAM is qualified separately. Do not
        // infer LSE/LLSC/ordered Device behavior from the normal-WB lane.
        if self.controls.cold_m0() && _class != MemoryOperationClass::Exclusive {
            Err(MemoryStatus::Unsupported)
        } else {
            // CLREX has no data-memory type. Exclusive transfers still refuse
            // in validate_data_request before any Device-RAM access.
            Ok(())
        }
    }
    fn validate_sp_alignment(&self, required: SpAlignmentRequirement) -> Result<(), MemoryStatus> {
        if required == SpAlignmentRequirement::Any || required == self.controls.sp.sp_requirement()
        {
            Ok(())
        } else {
            Err(MemoryStatus::Unsupported)
        }
    }
    fn translate(&self, address: u64) -> Result<u64, MemoryStatus> {
        // TBI/address-size decisions belong to the source walker. Its low four
        // address bits are unchanged, so decomposition needs no early walk.
        Ok(address)
    }
    fn validate_data_request(&mut self, request: DataRequest) -> Result<(), MemoryStatus> {
        self.validate_execution(request.flags)?;
        if request.bytes == 0
            || request.bytes > 16
            || request.operation == DataOperation::AllocationTag
        {
            return Err(MemoryStatus::Unsupported);
        }
        if self.controls.cold_m0() && request.operation != DataOperation::Ordinary {
            return Err(MemoryStatus::Unsupported);
        }
        let shape = shape(request);
        if mmu::alignment::before_translation(
            self.controls.translation.sctlr,
            request.address,
            shape,
        ) {
            let access = if request.flags & flags::WRITE != 0 {
                AccessKind::Write
            } else {
                AccessKind::Read
            };
            return Err(self.fault(
                request,
                request.address,
                access,
                mmu::Fault {
                    kind: mmu::FaultKind::Alignment,
                    level: 0,
                    second_stage: None,
                },
            ));
        }
        // The initial system cohort admits naturally aligned quantities. This
        // refuses before any walk/effect: a split part must not replace the
        // original address in Device alignment-fault prioritization. It is an
        // implementation boundary, never a fabricated guest alignment abort.
        if !shape.aligned(request.address) {
            return Err(self.unsupported(request, request.address, Refusal::UnalignedQuantity));
        }
        Ok(())
    }
    fn translate_part(
        &mut self,
        request: DataRequest,
        part: DataPart,
    ) -> Result<u64, (MemoryStatus, u64)> {
        let access = match part.kind {
            AccessKind::Read => mmu::Access::Read,
            AccessKind::Write => mmu::Access::Write,
            AccessKind::Execute => return Err((MemoryStatus::Unsupported, part.address)),
        };
        let mut tables = Tables {
            ram: &self.ram,
            failure: None,
        };
        let outcome = mmu::translate_checked(
            &self.controls.translation,
            part.address,
            access,
            self.controls.requester,
            shape(request),
            &mut tables,
        );
        if let Some(status) = tables.failure {
            return Err((status, part.address));
        }
        let translated = match outcome {
            mmu::Outcome::Mapped(mapped) => mapped,
            mmu::Outcome::Fault(fault) => {
                return Err((
                    self.fault(request, part.address, part.kind, fault),
                    part.address,
                ));
            }
            mmu::Outcome::Unsupported(reason) => {
                return Err((
                    self.unsupported(request, part.address, Refusal::Translation(reason)),
                    part.address,
                ));
            }
        };
        let remaining = translated.size - (translated.physical & (translated.size - 1));
        if part.bytes == 0 || part.bytes as u64 > remaining {
            return Err((
                self.unsupported(request, part.address, Refusal::PhysicalGeometry),
                part.address,
            ));
        }
        if translated.memory == mmu::MemoryType::Device
            && request.operation == DataOperation::Ordinary
            && request.flags & flags::WRITE == 0
            && self.ram.check_physical(translated.physical, part.bytes)
                == Err(MemoryStatus::Translation)
        {
            self.failure.get_or_insert(Failure::DeviceRead {
                request,
                address: part.address,
                physical: translated.physical,
                bytes: part.bytes,
            });
            return Err((MemoryStatus::Unsupported, part.address));
        }
        let cold_device = self.controls.cold_m0()
            && request.operation == DataOperation::Ordinary
            && translated.memory == mmu::MemoryType::Device
            && translated.attributes == mmu::attributes::DEVICE_NGNRNE;
        if !cold_device
            && (translated.memory != mmu::MemoryType::Normal
                || translated.attributes == mmu::attributes::TAGGED
                || !mmu::attributes::write_back(translated.attributes))
            || !matches!(
                translated.shareability,
                mmu::attributes::INNER_SHAREABLE | mmu::attributes::OUTER_SHAREABLE
            )
        {
            return Err((
                self.unsupported(request, part.address, Refusal::MemoryAttributes),
                part.address,
            ));
        }
        // Mapping the data quantity to an unowned device/aperture cannot acquire
        // canonical-RAM authority just because its ARM descriptor was Normal.
        if let Err(status) = self.ram.check_physical(translated.physical, part.bytes) {
            return Err((
                if status == MemoryStatus::Domain {
                    status
                } else {
                    self.unsupported(request, part.address, Refusal::PhysicalGeometry)
                },
                part.address,
            ));
        }
        Ok(translated.physical)
    }
    fn check(&mut self, access: DataAccess<'_>) -> Result<(), MemoryStatus> {
        if access.attributes.tagged || !access.attributes.shareable {
            Err(MemoryStatus::Unsupported)
        } else {
            Ok(())
        }
    }
}
pub(super) struct Tables<'a> {
    ram: &'a RegisteredSystemRam,
    pub(super) failure: Option<MemoryStatus>,
}
impl<'a> Tables<'a> {
    pub(super) fn new(ram: &'a RegisteredSystemRam) -> Self {
        Self { ram, failure: None }
    }
}
impl mmu::TableMemory for Tables<'_> {
    fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
        match self.ram.read_descriptor(physical) {
            Ok(value) => Some(value),
            Err(MemoryStatus::Translation) => None,
            Err(status) => {
                self.failure = Some(status);
                None
            }
        }
    }
    fn update_descriptor(&mut self, physical: u64, old: u64, new: u64) -> Option<bool> {
        match self.ram.update_descriptor(physical, old, new) {
            Ok(changed) => Some(changed),
            Err(MemoryStatus::Translation) => None,
            Err(status) => {
                self.failure = Some(status);
                None
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::{
        machine::system::Register,
        memory::{ReservedSystemRamRange, source_ram::system::fixture as ram_fixture},
    };
    use core::{cell::UnsafeCell, ptr::NonNull};
    const BASE: u64 = 0x10000;
    const PAGE: usize = 4096;
    const DATA: u64 = BASE + 4 * PAGE as u64;
    const LEAF: u64 = BASE + 3 * PAGE as u64 + 4 * 8;
    const DESCRIPTOR: u64 = DATA | 3 | (1 << 10) | (3 << 8);
    #[repr(align(4096))]
    struct Storage(UnsafeCell<[u8; 6 * PAGE]>);
    // SAFETY: tests never create racing Rust references; the canonical owner
    // retains these exact bytes and every writer uses its physical system.
    unsafe impl Send for Storage {}
    unsafe impl Sync for Storage {}
    pub(in crate::machine::engine::shared_memory) fn fixture() -> (
        crate::machine::Cpu,
        crate::machine::CpuProfile,
        Vec<Register>,
        Arc<RegisteredSystemRam>,
    ) {
        let storage = Arc::new(Storage(UnsafeCell::new([0; 6 * PAGE])));
        let range = ReservedSystemRamRange {
            source_pa: BASE,
            host_pa: 0x800000,
            host_base: NonNull::new(storage.0.get().cast()).unwrap(),
            bytes: 6 * PAGE,
        };
        // SAFETY: test-only actual byte owner, no production CPL0 claim.
        let ram = Arc::new(unsafe { ram_fixture(&[range], storage) });
        for (address, descriptor) in [
            (BASE, (BASE + PAGE as u64) | 3),
            (BASE + PAGE as u64, (BASE + 2 * PAGE as u64) | 3),
            (BASE + 2 * PAGE as u64, (BASE + 3 * PAGE as u64) | 3),
            (LEAF, DESCRIPTOR),
        ] {
            unsafe { ram.publish_physical(address, &descriptor.to_le_bytes()) }.unwrap();
        }
        let (mut cpu, profile, missing) = super::super::controls::tests::captured();
        cpu.registers.set_raw(
            Register::TCR_EL1,
            0,
            16 | (16 << 16) | (1 << 23) | (5 << 32),
        );
        cpu.registers.set_raw(Register::TTBR0_EL1, 0, BASE);
        cpu.registers.set_raw(Register::MAIR_EL1, 0, 0xff);
        (cpu, profile, missing, ram)
    }
    fn cold_policy() -> Policy {
        let (mut cpu, profile, missing, ram) = fixture();
        cpu.pstate = crate::machine::exception::Pstate::reset(2);
        cpu.registers.set_raw(Register::SCTLR_EL2, 0, 0);
        Policy::new(
            Controls::capture(&cpu, profile.name, &missing).unwrap(),
            ram,
        )
    }
    #[test]
    fn cold_el2_m0_uses_real_device_attributes_and_checked_native_ram_parts() {
        use stela_compiler::context::memory::{MemoryRequest, MemoryRequirements};
        let policy = cold_policy();
        assert!(policy.controls.cold_m0());
        let ram = Arc::clone(&policy.ram);
        let mut thread = ram.domain().thread(policy);
        for (index, bytes) in [1usize, 2, 4, 8].into_iter().enumerate() {
            let address = DATA + index as u64 * 16;
            let expected = 0x8967452301efcdabu64.to_le_bytes();
            let mut staging = expected;
            let request = MemoryRequest {
                address,
                data: staging.as_mut_ptr(),
                bytes: bytes as u32,
                flags: flags::WRITE,
                pc: 0x18000,
            };
            let entry = thread.prepare(MemoryRequirements::default()).unwrap();
            let result =
                unsafe { entry.with_checked_view(|view| (view.callback)(view, &request)) }.unwrap();
            assert_eq!(result, MemoryStatus::Success as u32);
            staging.fill(0xa5);
            let request = MemoryRequest {
                flags: 0,
                ..request
            };
            let entry = thread.prepare(MemoryRequirements::default()).unwrap();
            let result =
                unsafe { entry.with_checked_view(|view| (view.callback)(view, &request)) }.unwrap();
            assert_eq!(result, MemoryStatus::Success as u32);
            assert_eq!(&staging[..bytes], &expected[..bytes]);
            assert!(staging[bytes..].iter().all(|byte| *byte == 0xa5));
            let mut around = [0xa5; 16];
            unsafe { ram.read_physical(address, &mut around) }.unwrap();
            assert_eq!(&around[..bytes], &expected[..bytes]);
            assert!(around[bytes..].iter().all(|byte| *byte == 0));
        }
        for class in [MemoryOperationClass::Atomic, MemoryOperationClass::Ordered] {
            assert_eq!(
                thread.policy_mut().validate_operation_execution(class),
                Err(MemoryStatus::Unsupported)
            );
        }
        let unaligned = request(DATA + 1, 0);
        assert_eq!(
            thread.policy_mut().validate_data_request(unaligned),
            Err(MemoryStatus::Unsupported)
        );
        assert!(matches!(
            thread
                .policy_mut()
                .translate_part(request(DATA + 1, 0), part(DATA + 1, AccessKind::Read)),
            Err((MemoryStatus::Alignment, _))
        ));
    }
    #[test]
    fn cold_device_window_records_unexecuted_read_without_staging_or_ram_effect() {
        use stela_compiler::context::memory::{MemoryRequest, MemoryRequirements};
        let policy = cold_policy();
        let ram = Arc::clone(&policy.ram);
        let mut thread = ram.domain().thread(policy);
        let mut staging = [0xa5; 8];
        let request = MemoryRequest {
            address: 0x90000,
            data: staging.as_mut_ptr(),
            bytes: 4,
            flags: 0,
            pc: 0x18000,
        };
        let entry = thread.prepare(MemoryRequirements::default()).unwrap();
        let (status, completed, pc) = unsafe {
            entry.with_checked_view(|view| {
                let status = (view.callback)(view, &request);
                (status, view.completed_bytes, view.fault_pc)
            })
        }
        .unwrap();
        assert_eq!(
            (status, completed, pc),
            (MemoryStatus::Unsupported as u32, 0, request.pc)
        );
        assert_eq!(staging, [0xa5; 8]);
        assert!(matches!(
            thread.policy_mut().failure,
            Some(Failure::DeviceRead {
                address: 0x90000,
                physical: 0x90000,
                bytes: 4,
                ..
            })
        ));
    }

    fn policy() -> Policy {
        let (cpu, profile, missing, ram) = fixture();
        Policy::new(
            Controls::capture(&cpu, profile.name, &missing).unwrap(),
            ram,
        )
    }
    fn request(address: u64, flags: u32) -> DataRequest {
        DataRequest {
            address,
            bytes: 8,
            flags,
            pc: Some(0x8000),
            operation: DataOperation::Ordinary,
        }
    }
    fn part(address: u64, kind: AccessKind) -> DataPart {
        DataPart {
            address,
            bytes: 8,
            kind,
        }
    }
    #[test]
    fn real_tables_keep_read_write_permissions_and_typed_source_fault() {
        let mut policy = policy();
        let request = request(0x4000, flags::WRITE);
        policy.validate_data_request(request).unwrap();
        assert_eq!(
            policy.translate_part(request, part(0x4000, AccessKind::Read)),
            Ok(DATA)
        );
        assert_eq!(
            policy.translate_part(request, part(0x4000, AccessKind::Write)),
            Ok(DATA)
        );
        unsafe {
            policy
                .ram
                .publish_physical(LEAF, &(DESCRIPTOR | (2 << 6)).to_le_bytes())
        }
        .unwrap();
        assert_eq!(
            policy.translate_part(request, part(0x4000, AccessKind::Read)),
            Ok(DATA)
        );
        assert_eq!(
            policy.translate_part(request, part(0x4000, AccessKind::Write)),
            Err((MemoryStatus::Permission, 0x4000))
        );
        assert!(matches!(policy.failure, Some(Failure::Fault {
            request: original, address: 0x4000, access: AccessKind::Write,
            fault: mmu::Fault { kind: mmu::FaultKind::Permission, level: 3, second_stage: None },
        }) if original == request));
    }
    #[test]
    fn alignment_precedes_walk_and_unqualified_geometry_never_becomes_guest_success() {
        let mut policy = policy();
        let unaligned = request(0x4001, 0);
        policy.controls.translation.ttbr0 = 0x999000;
        policy.controls.translation.sctlr |= mmu::alignment::SCTLR_A;
        assert_eq!(
            policy.validate_data_request(unaligned),
            Err(MemoryStatus::Alignment)
        );
        assert!(matches!(
            policy.failure,
            Some(Failure::Fault {
                fault: mmu::Fault {
                    kind: mmu::FaultKind::Alignment,
                    ..
                },
                ..
            })
        ));
        policy.failure = None;
        policy.controls.translation.sctlr &= !mmu::alignment::SCTLR_A;
        assert_eq!(
            policy.validate_data_request(unaligned),
            Err(MemoryStatus::Unsupported)
        );
        assert!(matches!(
            policy.failure,
            Some(Failure::Unsupported {
                reason: Refusal::UnalignedQuantity,
                ..
            })
        ));
        policy.failure = None;
        let request = request(0x4000, 0);
        assert_eq!(
            policy.translate_part(request, part(0x4000, AccessKind::Read)),
            Err((MemoryStatus::Translation, 0x4000))
        );
        assert!(matches!(
            policy.failure,
            Some(Failure::Fault {
                fault: mmu::Fault {
                    kind: mmu::FaultKind::ExternalOnWalk,
                    ..
                },
                ..
            })
        ));
    }
    #[test]
    fn device_nonshareable_and_unowned_physical_memory_remain_explicit_boundaries() {
        let mut policy = policy();
        let request = request(0x4000, 0);
        for (descriptor, reason) in [
            (DESCRIPTOR & !(3 << 8), Refusal::MemoryAttributes),
            (
                (DESCRIPTOR & !0x0000_ffff_ffff_f000) | 0x999000,
                Refusal::PhysicalGeometry,
            ),
        ] {
            policy.failure = None;
            unsafe { policy.ram.publish_physical(LEAF, &descriptor.to_le_bytes()) }.unwrap();
            assert_eq!(
                policy.translate_part(request, part(0x4000, AccessKind::Read)),
                Err((MemoryStatus::Unsupported, 0x4000))
            );
            assert!(
                matches!(policy.failure, Some(Failure::Unsupported { reason: found, .. }) if found == reason)
            );
        }
        unsafe { policy.ram.publish_physical(LEAF, &DESCRIPTOR.to_le_bytes()) }.unwrap();
        policy.controls.translation.mair = 0;
        policy.failure = None;
        assert_eq!(
            policy.translate_part(request, part(0x4000, AccessKind::Read)),
            Err((MemoryStatus::Unsupported, 0x4000))
        );
        assert!(matches!(
            policy.failure,
            Some(Failure::Unsupported {
                reason: Refusal::MemoryAttributes,
                ..
            })
        ));
    }
}
