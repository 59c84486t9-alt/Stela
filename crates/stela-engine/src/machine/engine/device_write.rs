//! Consuming canonical stores from recovered native frames.
mod owners;
use super::*;
use owners::WriteOwners;
pub use owners::{CanonicalDeviceWrite, CanonicalWriteMemory};
use shared_memory::RecoveredWrite;
use stela_contracts::refuse;

pub type DeviceWriteShape = DeviceReadShape;
/// Diagnostics omit stored values; they grant no execution or replay permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceWriteRequest {
    pub pe: usize,
    pub pc: u64,
    pub word: u32,
    pub address: u64,
    pub physical: u64,
    pub shape: DeviceWriteShape,
}
/// Outer backend Err means no effects. An incomplete/unknown effect is instead
/// explicitly, with no invented byte prefix or source retirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumedWrite {
    Complete { settlement: Result<(), DeviceError> },
    Prefix { bytes: u8, error: DeviceError },
    Unknown { error: DeviceError },
}

pub(super) enum Pending {
    Queued(alloc::boxed::Box<Queued>),
    Terminal(Stop),
}
impl Pending {
    pub(super) fn stop(&self) -> Stop {
        match self {
            Self::Queued(write) => Stop::DeviceWrite(write.request),
            Self::Terminal(stop) => stop.clone(),
        }
    }
}
pub(super) struct Queued {
    recovered: RecoveredWrite,
    held: publication::StoppedWorkers,
    request: DeviceWriteRequest,
    plan: Plan,
    state: GuestState,
    pstate: crate::machine::exception::Pstate,
}
#[derive(Debug, Clone, Copy)]
struct Plan {
    values: [u64; 2],
    count: usize,
    bytes: u8,
    writeback: Option<(Register, u64)>,
}
impl<H: Host, D: Devices> Machine<H, D> {
    fn device_write_plan(&self, word: u32, address: u64) -> Option<Plan> {
        let instruction = Decoder.lift(GuestAddress(self.cpu.pc), word).ok()?;
        let (data, count, bytes, accessed, writeback) = if let Some(store) =
            ScalarStore::from_instruction(&instruction)
        {
            let (accessed, writeback) = self.scalar_address(store.address());
            (
                [store.source_register(), Register::Zero],
                1,
                store.bytes(),
                accessed,
                writeback,
            )
        } else {
            let (data, count, bytes, base, displacement, mode) = match instruction.operation {
                Operation::MemoryPair {
                    transfer: MemoryTransfer::Store,
                    bytes,
                    data,
                    base,
                    displacement,
                    mode,
                } => (data, 2, bytes, base, displacement, mode),
                Operation::MemoryNonTemporal(operand) if !operand.load => {
                    let stela_compiler::aarch64::non_temporal::Data::Integer(data) = operand.data
                    else {
                        return None;
                    };
                    (
                        data,
                        2,
                        operand.bytes,
                        operand.base,
                        operand.displacement,
                        AddressMode::Offset,
                    )
                }
                Operation::MemoryUnprivileged(operand)
                    if operand.transfer == MemoryTransfer::Store =>
                {
                    (
                        [operand.data, Register::Zero],
                        1,
                        operand.bytes,
                        operand.base,
                        operand.displacement,
                        AddressMode::Offset,
                    )
                }
                _ => return None,
            };
            let (accessed, writeback) = self.scalar_address(ScalarLoadAddress::Immediate {
                base,
                displacement,
                mode,
            });
            (data, count, bytes, accessed, writeback)
        };
        if accessed != address
            || !matches!(bytes, 1 | 2 | 4 | 8)
            || count == 2 && !matches!(bytes, 4 | 8)
            || !address.is_multiple_of(u64::from(bytes))
            || writeback
                .is_some_and(|(base, _)| base != Register::Sp && data[..count].contains(&base))
        {
            return None;
        }
        let mask = if bytes == 8 {
            u64::MAX
        } else {
            (1u64 << (u32::from(bytes) * 8)) - 1
        };
        Some(Plan {
            values: data.map(|register| self.read_register(register) & mask),
            count,
            bytes,
            writeback,
        })
    }
}
impl<H: Host, D: Devices> Machine<H, D> {
    /// A device write by a serialized PE, consumed through the same canonical
    /// RAM and processor owners as a recovered native write. The held
    /// workers stay held; a prefix or unknown effect is an error.
    pub(super) fn serial_write_canonical(
        &mut self,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<(), DeviceError> {
        self.serial_write_canonical_as(self.current, physical, bytes, value, now)
    }

    /// [`Self::serial_write_canonical`] for PE `cpu`, which may run on a
    /// machine of its own and forwarded the write here.
    pub(super) fn serial_write_canonical_as(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<(), DeviceError> {
        let Some(held) = self.serial_hold.take() else {
            return Err(DeviceError::TransferRefused(refuse!(
                "canonical device write requires the serialized worker hold"
            )));
        };
        let consumed = self.serial_write_held(&held, cpu, physical, bytes, value, now);
        self.serial_hold = Some(held);
        match consumed? {
            ConsumedWrite::Complete { settlement } => settlement,
            ConsumedWrite::Prefix { error, .. } | ConsumedWrite::Unknown { error } => Err(error),
        }
    }

    fn serial_write_held(
        &mut self,
        held: &publication::StoppedWorkers,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<ConsumedWrite, DeviceError> {
        self.device_transfer(now)?;
        let ram = Arc::clone(
            self.cpu
                .canonical_memory
                .as_ref()
                .ok_or_else(|| {
                    DeviceError::TransferRefused(refuse!(
                        "serialized PE has no canonical RAM owner"
                    ))
                })?
                .ram_owner(),
        );
        let (devices, processors) = self.processor_write_parts();
        let mut owners = WriteOwners::new(&ram, held, processors);
        devices.write_canonical(cpu, physical, bytes, value, now, &mut owners)
    }
}
impl<H: Host, T: NativeTransport, D: Devices> Machine<ServiceHost<H, T>, D> {
    pub(super) fn queue_device_write(
        &mut self,
        recovered: RecoveredWrite,
        held: publication::StoppedWorkers,
    ) -> Stop {
        let (word, fault) = recovered.diagnostic();
        let refuse = self.unsupported(RequirementKind::Instruction {
            word,
            detail: alloc::format!(
                "native device write lacks a complete original scalar/pair continuation: {fault:?}"
            ),
        });
        self.pending_device_write = Some(Pending::Terminal(refuse.clone()));
        let (binding, _, pc, retired) = recovered.source();
        if self.native_source_pe(binding).is_err()
            || self.cpu.pc != pc
            || self.cpu.retired != retired
        {
            return refuse;
        }
        let Some((word, access, address, physical, first_bytes)) = recovered.access() else {
            return refuse;
        };
        let Some(plan) = self.device_write_plan(word, address) else {
            return refuse;
        };
        let bytes = usize::from(plan.bytes) * plan.count;
        if access.bytes != bytes
            || !(first_bytes == usize::from(plan.bytes) || plan.count == 2 && first_bytes == bytes)
            || address.checked_add(bytes as u64).is_none()
            || physical.checked_add(bytes as u64).is_none()
            || address % FETCH_PAGE + bytes as u64 > FETCH_PAGE
            || physical % FETCH_PAGE + bytes as u64 > FETCH_PAGE
        {
            return refuse;
        }
        let shape = if plan.count == 1 {
            DeviceWriteShape::Scalar { bytes: plan.bytes }
        } else {
            DeviceWriteShape::Pair { bytes: plan.bytes }
        };
        let request = DeviceWriteRequest {
            pe: binding.pe,
            pc,
            word,
            address,
            physical,
            shape,
        };
        self.pending_device_write = Some(Pending::Queued(alloc::boxed::Box::new(Queued {
            recovered,
            held,
            request,
            plan,
            state: self.cpu.state.clone(),
            pstate: self.cpu.pstate,
        })));
        Stop::DeviceWrite(request)
    }

    /// Consume one original write, keeping its real worker hold and exact
    /// source prefix through controller effects, native CPU settlement and ACK.
    ///
    /// # Safety
    /// The complete closed synchronous producer-set contract of the native
    /// RAM service holds throughout. No independently advancing queued job,
    /// async/direct writer or device reentrancy is admitted between sequential
    /// memory/processor borrows. Synchronous device requests may stay queued
    /// only under the same exclusive owner which prevents their advancement.
    pub unsafe fn complete_device_write(&mut self) -> Step {
        if let Some(Pending::Terminal(stop)) = &self.pending_device_write {
            return Err(stop.clone());
        }
        let terminal = self.unsupported(RequirementKind::Native(
            "canonical device write is terminal or already consumed",
        ));
        let pending = self
            .pending_device_write
            .replace(Pending::Terminal(terminal.clone()));
        let Some(Pending::Queued(write)) = pending else {
            return Err(terminal);
        };
        let (binding, generation, pc, retired) = write.recovered.source();
        let valid = self.current == binding.pe
            && self.cpu.pc == pc
            && self.cpu.retired == retired
            && self.cpu.state == write.state
            && self.cpu.pstate == write.pstate
            && write
                .recovered
                .machine_matches(&self.native_memory_identity)
            && self.native_publication.as_ref().is_some_and(|inventory| {
                inventory.require_recovered(binding, generation).is_ok()
                    && inventory.require_all_held(&write.held).is_ok()
            });
        if !valid {
            return Err(terminal);
        }
        let now = self.now();
        self.device_transfer(now).map_err(|error| {
            self.unsupported(RequirementKind::DeviceAdvance(alloc::format!("{error:?}")))
        })?;
        let Some((_, access, _, _, _)) = write.recovered.access() else {
            return Err(terminal);
        };
        let service = self
            .host
            .borrow_ram_service(
                self.native_publication
                    .as_mut()
                    .expect("validated inventory"),
                write.held,
            )
            .map_err(|_| terminal.clone())?;
        let memory = self
            .cpu
            .canonical_memory
            .as_ref()
            .expect("actual recovered canonical owner");
        if memory
            .current_access_source(
                &self.cpu,
                &self.profile,
                &self.profile_missing,
                &write.recovered,
                service.memory(),
            )
            .is_err()
            || memory
                .current_device_access(
                    &self.cpu,
                    &self.profile,
                    &self.profile_missing,
                    access,
                    write.plan.bytes,
                    write.request.physical,
                )
                .is_err()
        {
            return Err(terminal);
        }
        let held = service.finish_memory();
        let ram = Arc::clone(
            self.cpu
                .canonical_memory
                .as_ref()
                .expect("actual source owner")
                .ram_owner(),
        );
        let consumed = {
            let (devices, processors) = self.processor_write_parts();
            let mut owners = WriteOwners::new(&ram, &held, processors);
            match write.request.shape {
                DeviceWriteShape::Scalar { bytes } => devices.write_canonical(
                    binding.pe,
                    write.request.physical,
                    bytes,
                    write.plan.values[0],
                    now,
                    &mut owners,
                ),
                DeviceWriteShape::Pair { bytes } => devices.write_pair_canonical(
                    binding.pe,
                    write.request.physical,
                    bytes,
                    write.plan.values,
                    now,
                    &mut owners,
                ),
            }
        };
        let settlement = match consumed {
            Ok(ConsumedWrite::Complete { settlement }) => settlement,
            result => {
                // Keep any peripheral prefix in its owner; neither a
                // backend error nor a numeric byte count permits source replay.
                if let Ok(Some(memory)) = ram.try_service() {
                    memory.fail();
                }
                let valid_prefix = !matches!(
                    &result,
                    Ok(ConsumedWrite::Prefix { bytes, .. })
                        if *bytes == 0 || usize::from(*bytes) >= write.plan.count * usize::from(write.plan.bytes)
                );
                let stop = self.unsupported(RequirementKind::Device {
                    physical: write.request.physical,
                    write: true,
                    detail: alloc::format!(
                        "canonical write incomplete/unconsumed (prefix_report_valid={valid_prefix}): {result:?}"
                    ),
                });
                self.pending_device_write = Some(Pending::Terminal(stop.clone()));
                return Err(stop);
            }
        };
        if self.cpu.pc != pc || self.cpu.retired != retired {
            if let Ok(Some(memory)) = ram.try_service() {
                memory.fail();
            }
            return Err(terminal);
        }
        if let Some((base, value)) = write.plan.writeback {
            self.write_register(base, value);
        }
        self.cpu.pc = pc.wrapping_add(INSTRUCTION);
        self.cpu.retired = retired.wrapping_add(1);
        self.cpu.pstate.btype = 0;
        self.device_lines = None;
        self.statistics.device_accesses += 1;
        if let Err(error) = settlement {
            if let Ok(Some(memory)) = ram.try_service() {
                memory.fail();
            }
            let stop = self.unsupported(RequirementKind::Device {
                physical: write.request.physical,
                write: true,
                detail: alloc::format!(
                    "consumed canonical write: board settlement failed: {error:?}"
                ),
            });
            self.pending_device_write = Some(Pending::Terminal(stop.clone()));
            return Err(stop);
        }
        self.follow_memory_lock();
        self.pending_device_write = None;
        self.finish_device_access(held)
    }
}
