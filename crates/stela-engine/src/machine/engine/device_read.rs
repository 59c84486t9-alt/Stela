//! Typed canonical-memory device reads. Public request fields are diagnostic;
//! only the engine's live recovered-frame and held-memory owners may consume.
use super::DeviceError;
use crate::memory::CanonicalRamService;

pub(in crate::machine::engine) mod sealed {
    pub trait Sealed {}
}

/// Actual live canonical RAM/worker borrow, never a stored readiness grant.
/// Only engine-held services implement this interface.
pub trait CanonicalDeviceMemory: sealed::Sealed {
    fn memory(&self) -> &CanonicalRamService<'_>;
    /// CPU and synchronous registered-copyout visibility only. This does not
    /// retire a source DSB or certify DMA/Apple DRAM/cache-power completion.
    fn fence_cpu_memory(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceReadShape {
    Scalar {
        bytes: u8,
    },
    /// Two consecutive quantities, each `bytes` wide.
    Pair {
        bytes: u8,
    },
}

/// An actual scalar read consumed its input. Preserve data and retire once
/// even when forwarding its resulting board effects fails afterward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedScalar {
    pub value: u64,
    pub settlement: Result<(), DeviceError>,
}

/// Diagnostic only. The private pending owner retains the actual recovered
/// native frame and same-generation worker hold; copying this grants nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceReadRequest {
    pub pe: usize,
    pub pc: u64,
    pub word: u32,
    pub address: u64,
    pub physical: u64,
    pub shape: DeviceReadShape,
}

use super::*;
use shared_memory::RecoveredRead;

pub(super) enum Pending {
    Queued(alloc::boxed::Box<Queued>),
    Terminal(Stop),
}
impl Pending {
    pub(super) fn stop(&self) -> Stop {
        match self {
            Self::Queued(read) => Stop::DeviceRead(read.request),
            Self::Terminal(stop) => stop.clone(),
        }
    }
}
pub(super) struct Queued {
    recovered: RecoveredRead,
    held: publication::StoppedWorkers,
    request: DeviceReadRequest,
    plan: Plan,
    state: GuestState,
    pstate: crate::machine::exception::Pstate,
}
#[derive(Debug, Clone, Copy)]
struct Plan {
    data: [Register; 2],
    count: usize,
    bytes: u8,
    signed: bool,
    width: Width,
    writeback: Option<(Register, u64)>,
}
impl Plan {
    fn values(self, raw: [u64; 2]) -> [u64; 2] {
        raw.map(|value| {
            let bits = u32::from(self.bytes) * 8;
            let mut value = if bits == 64 {
                value
            } else {
                value & ((1u64 << bits) - 1)
            };
            if self.signed && bits < 64 {
                value = ((value << (64 - bits)) as i64 >> (64 - bits)) as u64;
            }
            if self.width == Width::W32 {
                value &= 0xffff_ffff;
            }
            value
        })
    }
}
impl<H: Host, D: Devices> Machine<H, D> {
    fn device_read_plan(&self, word: u32, address: u64) -> Option<Plan> {
        let instruction = Decoder.lift(GuestAddress(self.cpu.pc), word).ok()?;
        let plan = if let Some(load) = ScalarLoad::from_instruction(&instruction) {
            let (accessed, writeback) = self.scalar_address(load.address());
            if accessed != address {
                return None;
            }
            Plan {
                data: [load.destination(), Register::Zero],
                count: 1,
                bytes: load.bytes(),
                signed: load.signed(),
                width: load.result_width(),
                writeback,
            }
        } else if let Operation::MemoryPair {
            transfer: MemoryTransfer::Load { signed, width },
            bytes,
            data,
            base,
            displacement,
            mode,
        } = instruction.operation
        {
            if self.immediate_address(base, displacement, mode) != address || data[0] == data[1] {
                return None;
            }
            let writeback = (mode != AddressMode::Offset).then(|| {
                (
                    base,
                    self.read_register(base)
                        .wrapping_add(displacement as i64 as u64),
                )
            });
            Plan {
                data,
                count: 2,
                bytes,
                signed,
                width,
                writeback,
            }
        } else {
            return None;
        };
        // Constrained writeback overlap must never select an arbitrary result.
        if plan.writeback.is_some_and(|(base, _)| {
            base != Register::Sp && plan.data[..plan.count].contains(&base)
        }) {
            return None;
        }
        (matches!(plan.bytes, 1 | 2 | 4 | 8) && address.is_multiple_of(u64::from(plan.bytes)))
            .then_some(plan)
    }
}
impl<H: Host, D: Devices> Machine<H, D> {
    /// A RAM-consuming device read by a serialized PE, through the same
    /// canonical owner as a recovered native read. Synchronous copyout
    /// completes before the RAM service is borrowed.
    pub(super) fn serial_read_canonical(
        &mut self,
        physical: u64,
        shape: DeviceReadShape,
        now: u64,
    ) -> Result<ConsumedPair, DeviceError> {
        if self.serial_hold.is_none() && self.parallel.is_some() {
            return self.forward_read(physical, shape);
        }
        self.serial_read_canonical_as(self.current, physical, shape, now)
    }

    /// [`Self::serial_read_canonical`] for PE `cpu`, which may run on a
    /// machine of its own and forwarded the read here.
    pub(super) fn serial_read_canonical_as(
        &mut self,
        cpu: usize,
        physical: u64,
        shape: DeviceReadShape,
        now: u64,
    ) -> Result<ConsumedPair, DeviceError> {
        let refused = |reason: &str| DeviceError::TransferRefused(reason.into());
        if self.serial_hold.is_none() {
            return Err(refused(
                "canonical device read requires its actual recovered-frame memory continuation",
            ));
        }
        self.device_transfer(now)?;
        let ram = Arc::clone(
            self.cpu
                .canonical_memory
                .as_ref()
                .ok_or_else(|| refused("serialized PE has no canonical RAM owner"))?
                .ram_owner(),
        );
        let memory = ram
            .try_service()
            .map_err(|_| refused("canonical read RAM owner failed"))?
            .ok_or_else(|| refused("canonical read RAM gates unavailable"))?;
        let mut memory = device_write::CanonicalWriteMemory::serial(memory, &mut self.host);
        match shape {
            DeviceReadShape::Scalar { bytes } => self
                .devices
                .read_canonical(cpu, physical, bytes, now, &mut memory)
                .map(|scalar| ConsumedPair {
                    values: [scalar.value, 0],
                    settlement: scalar.settlement,
                }),
            DeviceReadShape::Pair { bytes } => {
                self.devices
                    .read_pair_canonical(cpu, physical, bytes, now, &mut memory)
            }
        }
    }
}
impl<H: Host, T: NativeTransport, D: Devices> Machine<ServiceHost<H, T>, D> {
    pub(super) fn queue_device_read(
        &mut self,
        recovered: RecoveredRead,
        held: publication::StoppedWorkers,
    ) -> Stop {
        let (word, fault) = recovered.diagnostic();
        let refuse = self.unsupported(RequirementKind::Instruction {
            word,
            detail: alloc::format!(
                "native device read lacks a complete original scalar/pair continuation: {fault:?}"
            ),
        });
        // An error cannot discard the held generation and become replayable.
        self.pending_device_read = Some(Pending::Terminal(refuse.clone()));
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
        let Some(plan) = self.device_read_plan(word, address) else {
            return refuse;
        };
        let bytes = usize::from(plan.bytes) * plan.count;
        // No cross-page or mixed RAM/device footprint is authorized by the
        // reached first part. A Normal/SCA callback may have reached the
        // unconsumed WHOLE pair snapshot; this is not a widened MMIO read.
        // Every original quantity is rewalked under the live guard.
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
            DeviceReadShape::Scalar { bytes: plan.bytes }
        } else {
            DeviceReadShape::Pair { bytes: plan.bytes }
        };
        let request = DeviceReadRequest {
            pe: binding.pe,
            pc,
            word,
            address,
            physical,
            shape,
        };
        self.pending_device_read = Some(Pending::Queued(alloc::boxed::Box::new(Queued {
            recovered,
            held,
            request,
            plan,
            state: self.cpu.state.clone(),
            pstate: self.cpu.pstate,
        })));
        Stop::DeviceRead(request)
    }

    /// Consume the actual stopped native read exactly once. Public diagnostics
    /// cannot select a PE, address, instruction or worker generation here.
    ///
    /// # Safety
    /// The closed synchronous producer-set contract of
    /// `prepare_native_ram_service_parts` remains valid across the pending stop
    /// and this call. No independently advancing queued/background producer,
    /// direct DMA, firmware/SMI, external writer or reentrant device submission
    /// is admitted. Synchronous requests may remain queued only under the
    /// actual exclusive Devices owner preventing their advancement. The same
    /// controller/request owner must settle its actual effect before returning.
    pub unsafe fn complete_device_read(&mut self) -> Step {
        if let Some(Pending::Terminal(stop)) = &self.pending_device_read {
            return Err(stop.clone());
        }
        let terminal = self.unsupported(RequirementKind::Native(
            "canonical device read is terminal or already consumed",
        ));
        let pending = self
            .pending_device_read
            .replace(Pending::Terminal(terminal.clone()));
        let Some(Pending::Queued(read)) = pending else {
            return Err(terminal);
        };
        let (binding, generation, pc, retired) = read.recovered.source();
        let valid = self.current == binding.pe
            && self.cpu.pc == pc
            && self.cpu.retired == retired
            && self.cpu.state == read.state
            && self.cpu.pstate == read.pstate
            && read.recovered.machine_matches(&self.native_memory_identity)
            && self.native_publication.as_ref().is_some_and(|inventory| {
                inventory.require_recovered(binding, generation).is_ok()
                    && inventory.require_all_held(&read.held).is_ok()
            });
        if !valid {
            return Err(terminal);
        }
        // All synchronous modeled copyout completes BEFORE freezing RAM. No
        // callback may start another RAM transfer while this guard exists.
        let now = self.now();
        self.device_transfer(now).map_err(|error| {
            self.unsupported(RequirementKind::DeviceAdvance(alloc::format!("{error:?}")))
        })?;
        let Some((_, access, _, _, _)) = read.recovered.access() else {
            return Err(terminal);
        };
        let mut service = self
            .host
            .borrow_ram_service(
                self.native_publication
                    .as_mut()
                    .expect("validated actual inventory"),
                read.held,
            )
            .map_err(|_| terminal.clone())?;
        let memory = self
            .cpu
            .canonical_memory
            .as_ref()
            .expect("recovered actual memory");
        if memory
            .current_access_source(
                &self.cpu,
                &self.profile,
                &self.profile_missing,
                &read.recovered,
                service.memory(),
            )
            .is_err()
            || memory
                .current_device_access(
                    &self.cpu,
                    &self.profile,
                    &self.profile_missing,
                    access,
                    read.plan.bytes,
                    read.request.physical,
                )
                .is_err()
        {
            // No device effect; closing the failed continuation is safe. The
            // private terminal marker still prevents replay or native resume.
            return Err(terminal);
        }
        let consumed = match read.request.shape {
            DeviceReadShape::Scalar { bytes } => self
                .devices
                .read_canonical(binding.pe, read.request.physical, bytes, now, &mut service)
                .map(|value| ([value.value, 0], value.settlement)),
            DeviceReadShape::Pair { bytes } => self
                .devices
                .read_pair_canonical(binding.pe, read.request.physical, bytes, now, &mut service)
                .map(|value| (value.values, value.settlement)),
        };
        let (raw, settlement) = match consumed {
            Ok(consumed) => consumed,
            Err(error) => {
                // Err is contractually effect-free. It may not be retried as
                // another source read; retain the terminal pending marker.
                drop(service);
                let stop = self.unsupported(RequirementKind::Device {
                    physical: read.request.physical,
                    write: false,
                    detail: alloc::format!("canonical read refused before consumption: {error:?}"),
                });
                self.pending_device_read = Some(Pending::Terminal(stop.clone()));
                return Err(stop);
            }
        };
        // Consumption is irrevocable: settle architectural data/writeback/PC
        // even if forwarding board effects then fails. No re-decode/replay.
        let values = read.plan.values(raw);
        for (register, value) in read.plan.data.into_iter().zip(values).take(read.plan.count) {
            match register {
                Register::X(index) => self.cpu.state.x[usize::from(index)] = value,
                Register::Sp => self.cpu.state.sp = value,
                Register::Zero => {}
            }
        }
        if let Some((base, value)) = read.plan.writeback {
            match base {
                Register::X(index) => self.cpu.state.x[usize::from(index)] = value,
                Register::Sp => self.cpu.state.sp = value,
                Register::Zero => unreachable!("validated base"),
            }
        }
        self.cpu.pc = pc.wrapping_add(INSTRUCTION);
        self.cpu.retired = retired.wrapping_add(1);
        self.cpu.pstate.btype = 0;
        self.device_lines = None;
        self.statistics.device_accesses += 1;
        if let Err(error) = settlement {
            // Unknown board settlement poisons RAM/monitor and leaves actual
            // worker sessions held. Returned load data is nevertheless final.
            drop(service);
            let stop = self.unsupported(RequirementKind::Device {
                physical: read.request.physical,
                write: false,
                detail: alloc::format!(
                    "consumed canonical read: board settlement failed: {error:?}"
                ),
            });
            self.pending_device_read = Some(Pending::Terminal(stop.clone()));
            return Err(stop);
        }
        let held = service.finish_memory();
        self.pending_device_read = None;
        self.finish_device_access(held)
    }
}
