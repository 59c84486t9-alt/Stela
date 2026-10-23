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
    DeviceWrite {
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
    /// Exact effective output of the reached walk, retained only on refusal.
    /// The diagnostic must not require another walk after the source stopped.
    MemoryAttributes {
        physical: u64,
        memory: mmu::MemoryType,
        attributes: u8,
        shareability: u8,
    },
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
        if required & (flags::SME | flags::SVE_PREDICATED) != 0
            || required & flags::ASIMD != 0 && !self.controls.asimd
        {
            return Err(MemoryStatus::Unsupported);
        }
        Ok(())
    }
    fn validate_operation_execution(
        &self,
        class: MemoryOperationClass,
    ) -> Result<(), MemoryStatus> {
        // Ordered scalar transfers use the same checked physical RAM path as
        // ordinary quantities. The cold callback retains the machine's Device
        // serializer and MFENCE pair; typed ordered staging adds acquire/release
        // semantics. Arm 2026-06 LDAPRB/LDAR/STLR use Mem with acquire/release
        // descriptors; aligned Device memory is not an instruction refusal.
        // This does not qualify LSE or exclusive Device transfers.
        if self.controls.cold_m0() && class == MemoryOperationClass::Atomic {
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
                && !(request.bytes == 32
                    && request.operation == DataOperation::Ordinary
                    && request.flags & (flags::ASIMD | flags::PAIR) == (flags::ASIMD | flags::PAIR))
            || request.operation == DataOperation::AllocationTag
        {
            return Err(MemoryStatus::Unsupported);
        }
        if self.controls.cold_m0()
            && (!matches!(
                request.operation,
                DataOperation::Ordinary | DataOperation::Ordered
            ) || request.operation == DataOperation::Ordered
                && !matches!(request.bytes, 1 | 2 | 4 | 8))
        {
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
        // Ordinary Normal transfers use Mem's exact SCA/byte decomposition.
        // Keep the separate cold Device and nonordinary alignment cohorts
        // explicit; their admission is not inferred from ordinary RAM support.
        if !shape.aligned(request.address)
            && (request.operation != DataOperation::Ordinary || self.controls.cold_m0())
        {
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
        // Match Arm Mem, including its ASIMD-pair alignment override. All
        // other pieces retain the original instruction's alignment result;
        // DEVPAGE2 takes FAULT when a later byte reaches Device memory.
        let alignment = if request.operation == DataOperation::Ordinary
            && request.bytes == 32
            && request.flags & (flags::ASIMD | flags::PAIR) == (flags::ASIMD | flags::PAIR)
            && request.address.is_multiple_of(8)
        {
            mmu::alignment::MemoryCheck::aligned()
        } else {
            mmu::alignment::MemoryCheck::new(shape(request), request.address)
        };
        let outcome = mmu::translate_checked_part(
            &self.controls.translation,
            part.address,
            access,
            self.controls.requester,
            alignment,
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
            && self.ram.check_physical(translated.physical, part.bytes)
                == Err(MemoryStatus::Translation)
        {
            let reached = if request.flags & flags::WRITE == 0 {
                Failure::DeviceRead {
                    request,
                    address: part.address,
                    physical: translated.physical,
                    bytes: part.bytes,
                }
            } else {
                Failure::DeviceWrite {
                    request,
                    address: part.address,
                    physical: translated.physical,
                    bytes: part.bytes,
                }
            };
            self.failure.get_or_insert(reached);
            return Err((MemoryStatus::Unsupported, part.address));
        }
        let cold_device = self.controls.cold_m0()
            && matches!(
                request.operation,
                DataOperation::Ordinary | DataOperation::Ordered
            )
            && translated.memory == mmu::MemoryType::Device
            && translated.attributes == mmu::attributes::DEVICE_NGNRNE;
        if !cold_device
            && (translated.memory != mmu::MemoryType::Normal
                || translated.attributes == mmu::attributes::TAGGED)
            || !matches!(
                translated.shareability,
                mmu::attributes::INNER_SHAREABLE | mmu::attributes::OUTER_SHAREABLE
            )
        {
            return Err((
                self.unsupported(
                    request,
                    part.address,
                    Refusal::MemoryAttributes {
                        physical: translated.physical,
                        memory: translated.memory,
                        attributes: translated.attributes,
                        shareability: translated.shareability,
                    },
                ),
                part.address,
            ));
        }
        // Normal cacheability, allocation and transience describe the guest
        // translation, not a new host mapping. Every observer still reaches
        // the same qualified coherent WB reservation below. Existing SCA,
        // monitor, publication and barrier services supply its memory effects;
        // Normal Non-cacheable is not Device memory and needs no Device lock.
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
    fn actual_asimd_pair_store_copies_both_q_members_through_canonical_parts() {
        use stela_compiler::context::memory::{MemoryRequest, MemoryRequirements};
        let (mut cpu, profile, missing, ram) = fixture();
        cpu.registers.set_raw(Register::CPACR_EL1, 0, 3 << 20);
        cpu.registers.set_raw(Register::CPTR_EL2, 0, 3 << 20);
        let policy = Policy::new(
            Controls::capture(&cpu, profile.name, &missing).unwrap(),
            alloc::sync::Arc::clone(&ram),
        );
        let mut thread = ram.domain().thread(policy);
        let mut bytes = core::array::from_fn::<_, 32, _>(|index| index as u8 + 1);
        let request = MemoryRequest {
            address: 0x4000,
            data: bytes.as_mut_ptr(),
            bytes: 32,
            flags: flags::WRITE | flags::ASIMD | flags::PAIR,
            pc: 0x8000,
        };
        let entry = thread.prepare(MemoryRequirements::default()).unwrap();
        let (status, completed) = unsafe {
            entry.with_checked_view(|view| {
                let status = (view.callback)(view, &request);
                (status, view.completed_bytes)
            })
        }
        .unwrap();
        assert_eq!((status, completed), (MemoryStatus::Success as u32, 32));
        let mut actual = [0; 32];
        unsafe { ram.read_physical(DATA, &mut actual) }.unwrap();
        assert_eq!(actual, bytes);
    }

    fn ordinary_policy() -> Policy {
        let (mut cpu, profile, missing, ram) = fixture();
        cpu.registers.set_raw(Register::CPACR_EL1, 0, 3 << 20);
        cpu.registers.set_raw(Register::CPTR_EL2, 0, 3 << 20);
        Policy::new(
            Controls::capture(&cpu, profile.name, &missing).unwrap(),
            ram,
        )
    }
    fn ordinary_transfer(
        thread: &mut crate::memory::domain::MemoryThread<Policy>,
        address: u64,
        bytes: &mut [u8],
        flags: u32,
    ) -> (MemoryStatus, u64, u64) {
        use stela_compiler::context::memory::{MemoryRequest, MemoryRequirements};
        let request = MemoryRequest {
            address,
            data: bytes.as_mut_ptr(),
            bytes: bytes.len() as u32,
            flags,
            pc: 0x18000,
        };
        let entry = thread.prepare(MemoryRequirements::default()).unwrap();
        unsafe {
            entry.with_checked_view(|view| {
                let code = (view.callback)(view, &request);
                (
                    MemoryStatus::from_code(code).unwrap(),
                    view.completed_bytes,
                    view.fault_address,
                )
            })
        }
        .unwrap()
    }

    #[test]
    fn normal_cacheability_hints_use_the_same_canonical_ram_without_device_ordering() {
        // Allocated Normal MAIR nibbles: transient/non-transient WT and WB
        // with their allocation hints, plus NC. Cross inner and outer levels.
        const NORMAL_NIBBLES: [u8; 13] = [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 13, 14, 15];
        for inner in NORMAL_NIBBLES {
            for outer in NORMAL_NIBBLES {
                for shareability in [
                    mmu::attributes::INNER_SHAREABLE,
                    mmu::attributes::OUTER_SHAREABLE,
                ] {
                    let mut policy = ordinary_policy();
                    let attribute = outer << 4 | inner;
                    policy.controls.translation.mair = u64::from(attribute);
                    let descriptor = (DESCRIPTOR & !(3 << 8)) | u64::from(shareability) << 8;
                    let ram = Arc::clone(&policy.ram);
                    unsafe { ram.publish_physical(LEAF, &descriptor.to_le_bytes()) }.unwrap();
                    let mut thread = ram.domain().thread(policy);
                    let expected = [attribute, shareability, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86];
                    let mut data = expected;
                    assert_eq!(
                        ordinary_transfer(&mut thread, 0x4000, &mut data, flags::WRITE),
                        (MemoryStatus::Success, 8, 0),
                        "MAIR={attribute:#x} SH={shareability}"
                    );
                    data.fill(0);
                    assert_eq!(
                        ordinary_transfer(&mut thread, 0x4000, &mut data, 0),
                        (MemoryStatus::Success, 8, 0)
                    );
                    assert_eq!(data, expected);
                    let mut physical = [0; 8];
                    unsafe { ram.read_physical(DATA, &mut physical) }.unwrap();
                    assert_eq!(physical, expected);
                    assert!(!thread.policy_mut().device_ram_ordering());
                    assert_eq!(thread.policy_mut().failure, None);
                }
            }
        }
    }

    #[test]
    fn non_writeback_normal_ram_retains_page_fault_prefix_and_physical_ownership() {
        for attribute in [0x44, 0xbb, 0x4f, 0xf4] {
            for descriptor in [0, (DESCRIPTOR + PAGE as u64) | (2 << 6)] {
                let mut policy = ordinary_policy();
                policy.controls.translation.mair = attribute;
                let ram = Arc::clone(&policy.ram);
                unsafe { ram.publish_physical(LEAF + 8, &descriptor.to_le_bytes()) }.unwrap();
                let mut thread = ram.domain().thread(policy);
                assert_eq!(
                    ordinary_transfer(&mut thread, 0x4ffd, &mut [0x39; 8], flags::WRITE),
                    (
                        if descriptor == 0 {
                            MemoryStatus::Translation
                        } else {
                            MemoryStatus::Permission
                        },
                        3,
                        0x5000
                    )
                );
                let mut physical = [0; 8];
                unsafe { ram.read_physical(DATA + PAGE as u64 - 3, &mut physical) }.unwrap();
                assert_eq!(physical, [0x39, 0x39, 0x39, 0, 0, 0, 0, 0]);
            }
            let mut policy = ordinary_policy();
            policy.controls.translation.mair = attribute;
            let ram = Arc::clone(&policy.ram);
            let unowned = (DESCRIPTOR & !0x0000_ffff_ffff_f000) | 0x999000;
            unsafe { ram.publish_physical(LEAF, &unowned.to_le_bytes()) }.unwrap();
            let mut thread = ram.domain().thread(policy);
            assert_eq!(
                ordinary_transfer(&mut thread, 0x4000, &mut [0x39; 8], flags::WRITE),
                (MemoryStatus::Unsupported, 0, 0x4000)
            );
            assert!(matches!(
                thread.policy_mut().failure,
                Some(Failure::Unsupported {
                    reason: Refusal::PhysicalGeometry,
                    ..
                })
            ));
            let mut physical = [0; 8];
            unsafe { ram.read_physical(DATA, &mut physical) }.unwrap();
            assert_eq!(physical, [0; 8]);
        }
    }

    #[test]
    fn non_writeback_normal_ram_keeps_global_exclusives_ordered_and_atomic_effects() {
        use stela_compiler::context::memory::{
            MemoryOrder, MemoryRequest, MemoryRequirements,
            atomic::{AtomicData, AtomicOperation},
            exclusive::{EXCLUSIVE_FAILED, EXCLUSIVE_STORED, ExclusiveData, ExclusiveOperation},
            ordered::{OrderedData, OrderedOperation},
        };
        unsafe fn transfer<T>(
            thread: &mut crate::memory::domain::MemoryThread<Policy>,
            data: &mut T,
            flags: u32,
        ) -> (u32, u64) {
            let request = MemoryRequest {
                address: 0x4000,
                bytes: 8,
                flags,
                pc: 0x8000,
                data: core::ptr::from_mut(data).cast(),
            };
            let entry = thread
                .prepare(MemoryRequirements {
                    required_flags: flags,
                    ..Default::default()
                })
                .unwrap();
            // SAFETY: each caller supplies its complete initialized typed
            // exclusive, ordered or atomic payload in private test storage.
            unsafe {
                entry.with_checked_view(|view| {
                    let status = (view.callback)(view, &request);
                    (status, view.completed_bytes)
                })
            }
            .unwrap()
        }
        // SAFETY: all calls below use the complete initialized typed staging
        // selected by the exact request category, disjoint from canonical RAM.
        for attribute in [0x44, 0xbb, 0x4f, 0xf4] {
            let mut first_policy = ordinary_policy();
            first_policy.controls.translation.mair = attribute;
            let ram = Arc::clone(&first_policy.ram);
            let second_policy = Policy::new(first_policy.controls.clone(), Arc::clone(&ram));
            let mut first = ram.domain().thread(first_policy);
            let mut second = ram.domain().thread(second_policy);
            unsafe { ram.publish_physical(DATA, &5u64.to_le_bytes()) }.unwrap();
            let mut load = ExclusiveData::default();
            assert_eq!(
                unsafe { transfer(&mut first, &mut load, flags::EXCLUSIVE) },
                (0, 8)
            );
            assert_eq!(load.value, [5, 0]);
            let mut ordered = OrderedData {
                operation: OrderedOperation::Store as u32,
                order: MemoryOrder::Release as u32,
                value: [9, 0],
                ..Default::default()
            };
            assert_eq!(
                unsafe { transfer(&mut second, &mut ordered, flags::ORDERED | flags::WRITE) },
                (0, 8)
            );
            let mut store = ExclusiveData {
                operation: ExclusiveOperation::Store as u32,
                value: [7, 0],
                ..Default::default()
            };
            assert_eq!(
                unsafe { transfer(&mut first, &mut store, flags::EXCLUSIVE | flags::WRITE) },
                (0, 0)
            );
            assert_eq!(store.status, EXCLUSIVE_FAILED);
            load = ExclusiveData::default();
            assert_eq!(
                unsafe { transfer(&mut first, &mut load, flags::EXCLUSIVE) },
                (0, 8)
            );
            assert_eq!(load.value, [9, 0]);
            store.status = EXCLUSIVE_STORED;
            assert_eq!(
                unsafe { transfer(&mut first, &mut store, flags::EXCLUSIVE | flags::WRITE) },
                (0, 8)
            );
            assert_eq!(store.status, EXCLUSIVE_STORED);
            let mut atomic = AtomicData {
                operation: AtomicOperation::Add as u32,
                order: MemoryOrder::AcquireRelease as u32,
                operand: [3, 0],
                ..Default::default()
            };
            assert_eq!(
                unsafe { transfer(&mut first, &mut atomic, flags::ATOMIC | flags::WRITE) },
                (0, 8)
            );
            assert_eq!(atomic.result, [7, 0]);
            let mut physical = [0; 8];
            unsafe { ram.read_physical(DATA, &mut physical) }.unwrap();
            assert_eq!(u64::from_le_bytes(physical), 10);
        }
    }
    #[test]
    fn ordinary_unaligned_scalar_and_simd_parts_preserve_exact_registered_ram_bytes() {
        for (bytes, flags) in [
            (1, 0),
            (2, 0),
            (4, 0),
            (8, 0),
            (16, flags::ASIMD),
            (32, flags::ASIMD | flags::PAIR),
        ] {
            for residue in 0..16 {
                let policy = ordinary_policy();
                let ram = Arc::clone(&policy.ram);
                unsafe { ram.publish_physical(DATA, &[0x5a; 64]) }.unwrap();
                let mut thread = ram.domain().thread(policy);
                let address = 0x4010 + residue;
                let mut expected: Vec<_> = (0..bytes).map(|i| i as u8 + 1).collect();
                assert_eq!(
                    ordinary_transfer(&mut thread, address, &mut expected, flags | flags::WRITE).0,
                    MemoryStatus::Success,
                    "width={bytes} residue={residue}"
                );
                let mut actual = [0; 64];
                unsafe { ram.read_physical(DATA, &mut actual) }.unwrap();
                assert_eq!(
                    &actual[16 + residue as usize..16 + residue as usize + bytes],
                    &expected
                );
                assert!(actual[..16 + residue as usize].iter().all(|b| *b == 0x5a));
                assert!(
                    actual[16 + residue as usize + bytes..]
                        .iter()
                        .all(|b| *b == 0x5a)
                );
                let mut read = alloc::vec![0xa5; bytes];
                let result = ordinary_transfer(&mut thread, address, &mut read, flags);
                // Baseline deliberately lacks AtomicLoad16. A scalar quantity
                // spanning host8 within source SCA16 must not silently tear.
                let needs_atomic16 = bytes <= 8
                    && residue as usize + bytes <= 16
                    && residue as usize % 8 + bytes > 8;
                if needs_atomic16 {
                    assert_eq!((result.0, result.1), (MemoryStatus::Unsupported, 0));
                    assert!(read.iter().all(|b| *b == 0xa5));
                } else {
                    assert_eq!((result.0, result.1), (MemoryStatus::Success, bytes as u64));
                    assert_eq!(read, expected);
                }
            }
        }
    }
    #[test]
    fn unaligned_page_faults_preserve_only_the_architectural_mem_prefix() {
        for (address, bytes, flags, prefix) in [
            (0x4ffd, 8, 0, 3),
            (0x4ff8, 32, flags::ASIMD | flags::PAIR, 8),
        ] {
            for descriptor in [0, (DESCRIPTOR + PAGE as u64) | (2 << 6)] {
                let policy = ordinary_policy();
                let ram = Arc::clone(&policy.ram);
                unsafe { ram.publish_physical(LEAF + 8, &descriptor.to_le_bytes()) }.unwrap();
                let mut thread = ram.domain().thread(policy);
                let mut data = alloc::vec![0x39; bytes];
                let result =
                    ordinary_transfer(&mut thread, address, &mut data, flags | flags::WRITE);
                let status = if descriptor == 0 {
                    MemoryStatus::Translation
                } else {
                    MemoryStatus::Permission
                };
                assert_eq!(result, (status, prefix, 0x5000));
                let mut actual = [0; 32];
                unsafe { ram.read_physical(DATA + PAGE as u64 - prefix, &mut actual) }.unwrap();
                assert!(actual[..prefix as usize].iter().all(|b| *b == 0x39));
                assert!(actual[prefix as usize..].iter().all(|b| *b == 0));
            }
        }
    }
    #[test]
    fn original_alignment_is_checked_once_and_retained_before_device_permissions() {
        let mut policy = ordinary_policy();
        let ram = Arc::clone(&policy.ram);
        policy.controls.translation.sctlr |= mmu::alignment::SCTLR_A;
        policy.controls.translation.ttbr0 = 0x999000;
        let pair = DataRequest {
            bytes: 32,
            flags: flags::ASIMD | flags::PAIR,
            ..request(0x4008, 0)
        };
        assert_eq!(
            policy.validate_data_request(pair),
            Err(MemoryStatus::Alignment)
        );
        // Restoring a valid walk leaves a genuinely aligned pair legal even
        // when its later eight-byte pieces are not whole-Q aligned.
        policy.failure = None;
        policy.controls.translation.ttbr0 = BASE;
        let mut thread = ram.domain().thread(policy);
        assert_eq!(
            ordinary_transfer(
                &mut thread,
                0x4000,
                &mut [0x79; 32],
                flags::WRITE | flags::ASIMD | flags::PAIR
            )
            .0,
            MemoryStatus::Success
        );

        let mut policy = ordinary_policy();
        let ram = Arc::clone(&policy.ram);
        // AttrIndx1 remains Device-nGnRnE; AP is read-only. A later page's
        // Device alignment must win before that permission fault, even though
        // its individual reached byte at 0x5000 is naturally aligned.
        let device_readonly = (DESCRIPTOR + PAGE as u64) | (1 << 2) | (2 << 6);
        unsafe { ram.publish_physical(LEAF + 8, &device_readonly.to_le_bytes()) }.unwrap();
        policy.controls.translation.mair = 0xff;
        let mut thread = ram.domain().thread(policy);
        assert_eq!(
            ordinary_transfer(&mut thread, 0x4ffd, &mut [0x51; 8], flags::WRITE),
            (MemoryStatus::Alignment, 3, 0x5000)
        );
        assert!(matches!(
            thread.policy_mut().failure,
            Some(Failure::Fault {
                request: DataRequest {
                    address: 0x4ffd,
                    bytes: 8,
                    ..
                },
                address: 0x5000,
                fault: mmu::Fault {
                    kind: mmu::FaultKind::Alignment,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn asimd_requests_require_actual_source_permission_and_preserve_scalable_refusals() {
        let (mut cpu, profile, missing, ram) = fixture();
        let denied = Policy::new(
            Controls::capture(&cpu, profile.name, &missing).unwrap(),
            alloc::sync::Arc::clone(&ram),
        );
        assert_eq!(
            denied.validate_execution(flags::ASIMD),
            Err(MemoryStatus::Unsupported)
        );
        cpu.registers.set_raw(Register::CPACR_EL1, 0, 3 << 20);
        cpu.registers.set_raw(Register::CPTR_EL2, 0, 3 << 20);
        let enabled = Policy::new(
            Controls::capture(&cpu, profile.name, &missing).unwrap(),
            ram,
        );
        assert_eq!(enabled.validate_execution(flags::ASIMD), Ok(()));
        assert_eq!(
            enabled.validate_execution(flags::ASIMD | flags::SME),
            Err(MemoryStatus::Unsupported)
        );
        assert_eq!(
            enabled.validate_execution(flags::SVE_PREDICATED),
            Err(MemoryStatus::Unsupported)
        );
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
        assert_eq!(
            thread
                .policy_mut()
                .validate_operation_execution(MemoryOperationClass::Atomic),
            Err(MemoryStatus::Unsupported)
        );
        assert_eq!(
            thread
                .policy_mut()
                .validate_operation_execution(MemoryOperationClass::Ordered),
            Ok(())
        );
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
    fn cold_ordered_ram_uses_typed_acquire_release_and_preserves_exact_widths() {
        use stela_compiler::context::memory::{
            MemoryOrder, MemoryRequest, MemoryRequirements,
            ordered::{OrderedData, OrderedFeature, OrderedOperation},
        };
        let policy = cold_policy();
        let ram = Arc::clone(&policy.ram);
        let mut thread = ram.domain().thread(policy);
        let requirements = MemoryRequirements {
            required_flags: flags::ORDERED,
            ..Default::default()
        };
        for (index, bytes) in [1u32, 2, 4, 8].into_iter().enumerate() {
            let address = DATA + index as u64 * 16;
            let value = 0x8967452301efcdabu64 & (u64::MAX >> ((8 - bytes) * 8));
            let mut data = OrderedData {
                operation: OrderedOperation::Store as u32,
                order: MemoryOrder::Release as u32,
                value: [value, 0],
                ..Default::default()
            };
            let request = MemoryRequest {
                address,
                data: core::ptr::from_mut(&mut data).cast(),
                bytes,
                flags: flags::ORDERED | flags::WRITE,
                pc: 0x18000,
            };
            let entry = thread.prepare(requirements).unwrap();
            let (status, completed) = unsafe {
                entry.with_checked_view(|view| {
                    let status = (view.callback)(view, &request);
                    (status, view.completed_bytes)
                })
            }
            .unwrap();
            assert_eq!(
                (status, completed),
                (MemoryStatus::Success as u32, u64::from(bytes))
            );
            // Both the RCsc and RCpc load categories must return actual bytes;
            // RCpc retains its real captured source-feature admission.
            for (order, feature) in [
                (MemoryOrder::AcquireRcsc, OrderedFeature::Base),
                (MemoryOrder::AcquireRcpc, OrderedFeature::Rcpc),
            ] {
                data = OrderedData {
                    order: order as u32,
                    feature: feature as u32,
                    ..Default::default()
                };
                let request = MemoryRequest {
                    data: core::ptr::from_mut(&mut data).cast(),
                    flags: flags::ORDERED,
                    ..request
                };
                let entry = thread.prepare(requirements).unwrap();
                let (status, completed) = unsafe {
                    entry.with_checked_view(|view| {
                        let status = (view.callback)(view, &request);
                        (status, view.completed_bytes)
                    })
                }
                .unwrap();
                assert_eq!(
                    (status, completed),
                    (MemoryStatus::Success as u32, u64::from(bytes))
                );
                assert_eq!(data.value, [value, 0]);
            }
            let mut actual = [0; 16];
            unsafe { ram.read_physical(address, &mut actual) }.unwrap();
            assert_eq!(
                &actual[..bytes as usize],
                &value.to_le_bytes()[..bytes as usize]
            );
            assert!(actual[bytes as usize..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn cold_ordered_requests_cannot_acquire_device_or_unaligned_ram_authority() {
        use stela_compiler::context::memory::{
            MemoryOrder, MemoryRequest, MemoryRequirements, ordered::OrderedData,
        };
        let policy = cold_policy();
        let ram = Arc::clone(&policy.ram);
        let mut thread = ram.domain().thread(policy);
        for address in [0x90000, DATA + 1] {
            let mut data = OrderedData {
                order: MemoryOrder::AcquireRcsc as u32,
                ..Default::default()
            };
            let request = MemoryRequest {
                address,
                data: core::ptr::from_mut(&mut data).cast(),
                bytes: 8,
                flags: flags::ORDERED,
                pc: 0x18000,
            };
            let entry = thread
                .prepare(MemoryRequirements {
                    required_flags: flags::ORDERED,
                    ..Default::default()
                })
                .unwrap();
            let (status, completed) = unsafe {
                entry.with_checked_view(|view| {
                    let status = (view.callback)(view, &request);
                    (status, view.completed_bytes)
                })
            }
            .unwrap();
            assert_eq!((status, completed), (MemoryStatus::Unsupported as u32, 0));
            assert_eq!(data.value, [0; 2]);
            assert!(matches!(
                thread.policy_mut().failure,
                Some(Failure::Unsupported { .. })
            ));
            thread.policy_mut().failure = None;
        }
        assert_eq!(
            thread.policy_mut().validate_data_request(DataRequest {
                operation: DataOperation::Ordered,
                bytes: 16,
                ..request(DATA, 0)
            }),
            Err(MemoryStatus::Unsupported)
        );
        for operation in [DataOperation::Atomic, DataOperation::Exclusive] {
            assert_eq!(
                thread.policy_mut().validate_data_request(DataRequest {
                    operation,
                    ..request(DATA, 0)
                }),
                Err(MemoryStatus::Unsupported)
            );
        }
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
        assert_eq!(policy.validate_data_request(unaligned), Ok(()));
        assert_eq!(policy.failure, None);
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
            (
                DESCRIPTOR & !(3 << 8),
                Refusal::MemoryAttributes {
                    physical: DATA,
                    memory: mmu::MemoryType::Normal,
                    attributes: mmu::attributes::NORMAL_WRITE_BACK,
                    shareability: mmu::attributes::NON_SHAREABLE,
                },
            ),
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
                reason: Refusal::MemoryAttributes {
                    physical: DATA,
                    memory: mmu::MemoryType::Device,
                    attributes: mmu::attributes::DEVICE_NGNRNE,
                    shareability: mmu::attributes::OUTER_SHAREABLE,
                },
                ..
            })
        ));
    }
}
