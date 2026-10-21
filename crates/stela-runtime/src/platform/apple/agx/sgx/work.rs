//! Fixed-family CL native programming in the actual SGX owner.
//!
//! Original G14G setup 0x160ac..0x17020 and G13G 0x129bc..0x12a3c
//! program these type-17 registers before the finalize record. G13X's
//! 0x13380..0x13508 path omits parameter +0x38 and adds a context mirror.
//! Native configuration and backend outcome survive retained gates and
//! firmware DMA faults. No command stamps or resource releases occur here.

use super::FirmwarePower;
use crate::platform::apple::agx::{
    channel::Kind as CommandKind,
    exec::WorkError,
    pio::{Kind, Region},
    work::{Execution, ResultKind},
    work_decode::{
        Submission,
        resources::{Lease, Policy},
    },
};
use crate::platform::apple::amcc::firmware::FirmwareCache;
use crate::platform::dma::{DmaError, Port};
use alloc::vec::Vec;
use core::fmt;

pub mod render;

const PARAMETER_REGISTERS: [u32; 13] = [
    0x10080, 0x1a420, 0x1a4d0, 0x1a4d8, 0x1a4e0, 0x1a4e8, 0x10070, 0x1a458, 0x11840, 0x11848,
    0x11f80, 0x1a440, 0x12090,
];
const CONTROL: u32 = 0x10190;
const CONTEXT: u32 = 0x10200;
const CONTEXT_MASK: u32 = 0x17610;
const LEGACY_MASK: u32 = 0x7610;
const LEGACY_SETUP: u32 = 0x17000;
const SETUP: u32 = 0x11000;
const RESOURCE: u32 = 0x118e0;
const SUBMIT: u32 = 0x10180;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Control,
    Context,
    ContextMask,
    LegacyMask,
    LegacySetup,
    Parameter(u8),
    Setup,
    Resource,
    Submit,
}
impl Register {
    fn word(self, policy: Policy) -> Result<(u32, u32), &'static str> {
        Ok(match self {
            Self::Control => (CONTROL, 8),
            Self::Context => (CONTEXT, 4),
            Self::ContextMask => (CONTEXT_MASK, 8),
            Self::LegacyMask if policy == Policy::G13X => (LEGACY_MASK, 8),
            Self::LegacySetup if policy == Policy::G13X => (LEGACY_SETUP, 8),
            Self::Parameter(index) => {
                if index == 7 && policy == Policy::G13X {
                    return Err("GFX G13X does not program the CL +0x38 parameter register");
                }
                (
                    *PARAMETER_REGISTERS
                        .get(usize::from(index))
                        .ok_or("GFX CL parameter index is outside its original native block")?,
                    8,
                )
            }
            Self::Setup => (SETUP, 8),
            Self::Resource => (RESOURCE, 8),
            Self::Submit => (SUBMIT, 4),
            _ => return Err("GFX CL native register is not present on this family"),
        })
    }
}

struct Run {
    submission: Submission,
    lease: Lease,
    parameter_mask: u16,
    programmed: u8,
    backend: Option<Execution>,
}

#[derive(Default)]
pub(super) struct Registers {
    // No original reset/capture authority currently defines these words.
    // Unknown is distinct from a readable hardware zero. The other arrays
    // are storage only: phase masks require source writes before use.
    control: Option<u64>,
    context_mask: Option<u64>,
    legacy_mask: Option<u64>,
    legacy_setup: Option<u64>,
    context: u32,
    setup: u64,
    resource: u64,
    parameters: [u64; 13],
    run: Option<Run>,
    render: render::Registers,
}
impl fmt::Debug for Registers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClRegisters")
            .field("control", &self.control)
            .field("context_mask", &self.context_mask)
            .field(
                "command",
                &self.run.as_ref().map(|run| run.submission.command.va),
            )
            .finish()
    }
}
impl Registers {
    pub(super) fn active(&self) -> bool {
        self.run.is_some() || self.render.active()
    }

    fn begin(&mut self, submission: &Submission, lease: Lease) -> Result<(), &'static str> {
        if self.render.active() {
            return Err("GFX native parameter bank still belongs to accepted render work");
        }
        if submission.command.kind != CommandKind::Cl || lease.pipe != 2 || lease.slot >= 6 {
            return Err("GFX CL native ownership requires its compute lease");
        }
        if submission.context >= 64 {
            return Err("GFX fixed CL native context is outside its 64-bit context mask");
        }
        if let Some(run) = &self.run {
            return if run.submission == *submission && run.lease == lease {
                Ok(())
            } else {
                Err("GFX CL native registers still belong to another accepted command")
            };
        }
        self.run = Some(Run {
            submission: submission.clone(),
            lease,
            parameter_mask: 0,
            programmed: 0,
            backend: None,
        });
        Ok(())
    }

    fn read(&self, register: Register) -> Result<u64, &'static str> {
        match register {
            Register::Control => self
                .control
                .ok_or("GFX CL native control initial value is not qualified"),
            Register::ContextMask => self
                .context_mask
                .ok_or("GFX CL native context-mask initial value is not qualified"),
            _ => Err("GFX CL native readback is not an original modeled operation"),
        }
    }

    fn write(
        &mut self,
        policy: Policy,
        register: Register,
        value: u64,
    ) -> Result<(), &'static str> {
        register.word(policy)?;
        let run = self
            .run
            .as_mut()
            .ok_or("GFX CL native write has no accepted owner")?;
        if run.backend.is_some() {
            return Err("GFX CL native configuration changed after submission");
        }
        match register {
            Register::Control if self.control.is_some_and(|old| value == old | 1) => {
                self.control = Some(value);
                run.programmed |= 1;
            }
            Register::Context
                if value >> 8 == u64::from(run.submission.context) && value & 0xc0 == 0 =>
            {
                self.context = value as u32;
                run.programmed |= 2;
            }
            Register::ContextMask
                if self
                    .context_mask
                    .is_some_and(|old| (value ^ old) & !(1u64 << run.submission.context) == 0) =>
            {
                self.context_mask = Some(value);
                run.programmed |= 4;
            }
            Register::LegacyMask if policy == Policy::G13X && Some(value) == self.context_mask => {
                self.legacy_mask = Some(value);
                run.programmed |= 0x20;
            }
            Register::LegacySetup if policy == Policy::G13X && value == 0x100 => {
                self.legacy_setup = Some(value);
                run.programmed |= 0x40;
            }
            Register::Setup if value == 0x100 => {
                self.setup = value;
                run.programmed |= 8;
            }
            Register::Resource => {
                self.resource = value;
                run.programmed |= 0x10;
            }
            Register::Parameter(index) => {
                let at = usize::from(index);
                let field = self
                    .parameters
                    .get_mut(at)
                    .ok_or("GFX CL native parameter index is outside its block")?;
                *field = value;
                run.parameter_mask |= 1u16 << at;
            }
            _ => {
                return Err(
                    "GFX CL native register value is outside its source programming contract",
                );
            }
        }
        Ok(())
    }

    fn prepare_submit(&mut self, policy: Policy) -> Result<(), &'static str> {
        let run = self
            .run
            .as_mut()
            .ok_or("GFX CL submission has no accepted owner")?;
        if run.backend.is_some() {
            return Ok(());
        }
        let parameters = ((1u16 << 13) - 1)
            & if policy == Policy::G13X {
                !(1 << 7)
            } else {
                u16::MAX
            };
        let controls = if policy == Policy::G13X { 0x7f } else { 0x1f };
        if run.parameter_mask != parameters || run.programmed != controls {
            return Err("GFX CL submit precedes complete native parameter/context programming");
        }
        if self.control != Some(1) {
            return Err("GFX CL captured native control mode is not qualified");
        }
        if self.resource != 0 {
            return Err("GFX CL native buffer-cache resource configuration is not qualified");
        }
        if self.parameters[8] & 1 != 0 {
            return Err("GFX CL enabled helper program execution is not qualified");
        }
        if policy != Policy::G13X && self.parameters[7] != 0x8c60 {
            return Err("GFX CL native scheduling mode is not qualified");
        }
        if self.parameters[10] != 0 || self.parameters[11] != 1 || self.parameters[12] != 0 {
            return Err("GFX CL secondary native controls are not qualified");
        }
        // The deflake addresses are retained configuration. This serial
        // backend never preempts or restores a partially executing job.
        let job = crate::platform::apple::agx::exec::compute::Job {
            stream: self.parameters[1],
            usc_base: self.parameters[6],
            vm_slot: run.submission.context,
        };
        run.backend = Some(
            Execution::compute(run.submission.clone(), job)
                .map_err(|_| "GFX CL source context cannot construct its backend")?,
        );
        Ok(())
    }
}

/// The actual SGX native state, sharing power and retained execution with
/// the AP aperture. Every operation qualifies its full firmware PIO target.
#[derive(Clone)]
pub struct FirmwareWork {
    power: FirmwarePower,
    region: Region,
    policy: Policy,
    cache: FirmwareCache,
}
impl FirmwarePower {
    pub fn native_work_targets(&self) -> Result<Vec<(u64, u32)>, &'static str> {
        let policy = Policy::for_family(self.family)?;
        let mut registers = alloc::vec![
            Register::Control,
            Register::Context,
            Register::ContextMask,
            Register::Setup,
            Register::Resource,
            Register::Submit
        ];
        if policy == Policy::G13X {
            registers.extend([Register::LegacySetup, Register::LegacyMask]);
        }
        for index in 0..13 {
            if policy != Policy::G13X || index != 7 {
                registers.push(Register::Parameter(index));
            }
        }
        let mut words = Vec::new();
        for register in registers {
            words.push(register.word(policy)?);
        }
        words.extend(
            crate::platform::apple::agx::work_decode::ta::words(policy)
                .into_iter()
                .map(|word| word.range()),
        );
        words.extend(
            crate::platform::apple::agx::work_decode::three_d::words(policy)
                .into_iter()
                .map(|word| word.range()),
        );
        let mut targets = Vec::new();
        for (offset, width) in words {
            let physical = self
                .banks
                .iter()
                .find_map(|&(base, bytes, start)| {
                    let at = u64::from(offset).checked_sub(start)?;
                    if at.checked_add(u64::from(width))? > bytes {
                        return None;
                    }
                    let physical = base.checked_add(at)?;
                    physical.checked_add(u64::from(width) - 1)?;
                    Some(physical)
                })
                .ok_or("GFX native work target is not wholly inside an actual SGX bank")?;
            if !targets.contains(&(physical, width)) {
                targets.push((physical, width));
            }
        }
        Ok(targets)
    }
    pub fn firmware_work(
        &self,
        region: Region,
        cache: FirmwareCache,
    ) -> Result<FirmwareWork, &'static str> {
        let policy = Policy::for_family(self.family)?;
        self.native_work_targets()?;
        if region.kind != Kind::ResourceWindows || region.relative != 0 {
            return Err("GFX CL native programming requires original type-17 PIO");
        }
        for (physical, width) in self.native_work_targets()? {
            let logical = self.logical_range(physical, u64::from(width))?;
            let (_, target) = region.range(logical as u32, width, true)?;
            if target != physical {
                return Err("GFX CL PIO does not target its actual SGX owner");
            }
        }
        Ok(FirmwareWork {
            power: self.clone(),
            region,
            policy,
            cache,
        })
    }
}
impl FirmwareWork {
    pub fn begin(&self, submission: &Submission, lease: Lease) -> Result<(), &'static str> {
        self.available()?;
        self.power.native.borrow_mut().work.begin(submission, lease)
    }
    fn available(&self) -> Result<(), &'static str> {
        let native = self.power.native.borrow();
        if !native.available || !native.gpu_awake.get() {
            return Err("GFX CL native operation while SGX execution is inhibited");
        }
        self.cache.check_ram_access()?;
        Ok(())
    }
    fn target(
        &self,
        port: &mut Port<'_, '_>,
        register: Register,
        write: bool,
    ) -> Result<(), &'static str> {
        let (offset, width) = register.word(self.policy)?;
        self.target_word(port, offset, width, write)
    }
    fn target_word(
        &self,
        port: &mut Port<'_, '_>,
        offset: u32,
        width: u32,
        write: bool,
    ) -> Result<(), &'static str> {
        self.available()?;
        let (va, expected) = self.region.range(offset, width, write)?;
        let physical = port
            .iommu
            .translate(
                port.memory,
                port.stream,
                va,
                va + u64::from(width) - 1,
                write,
                port.access,
            )
            .map_err(|error| match error {
                DmaError::Fault(_) => "GFX CL PIO faults in the UAT",
                DmaError::Memory => "GFX CL PIO page table is not RAM",
                DmaError::Unsupported(reason) => reason,
            })?;
        if physical != expected
            || self.power.logical_range(physical, u64::from(width))? != u64::from(offset)
        {
            return Err("GFX CL PIO translation disagrees with its actual SGX bank");
        }
        Ok(())
    }
    pub fn read(&self, port: &mut Port<'_, '_>, register: Register) -> Result<u64, &'static str> {
        self.target(port, register, false)?;
        self.power.native.borrow().work.read(register)
    }
    pub fn write(
        &self,
        port: &mut Port<'_, '_>,
        register: Register,
        value: u64,
    ) -> Result<(), &'static str> {
        self.target(port, register, true)?;
        if register == Register::Submit {
            if value != 1 {
                return Err("GFX CL native submit value is not one");
            }
            let mut native = self.power.native.borrow_mut();
            native.work.prepare_submit(self.policy)?;
            // The register trigger is committed even when GPU execution
            // faults. Its outcome is a separate retained hardware result.
            let run = native.work.run.as_mut().unwrap();
            let _ = run.backend.as_mut().unwrap().run(port);
            return Ok(());
        }
        self.power
            .native
            .borrow_mut()
            .work
            .write(self.policy, register, value)
    }
    fn check_setup_owner(
        &self,
        submission: &Submission,
        lease: Lease,
        policy: Policy,
    ) -> Result<(), &'static str> {
        self.available()?;
        let native = self.power.native.borrow();
        let run = native
            .work
            .run
            .as_ref()
            .ok_or("GFX CL attachment phase has no accepted native owner")?;
        let parameters = ((1u16 << 13) - 1)
            & if policy == Policy::G13X {
                !(1 << 7)
            } else {
                u16::MAX
            };
        let controls = if policy == Policy::G13X { 0x6f } else { 0x0f };
        if self.policy != policy
            || run.submission != *submission
            || run.lease != lease
            || run.backend.is_some()
            || run.parameter_mask != parameters
            || run.programmed != controls
        {
            return Err(
                "GFX CL attachment phase does not own complete pre-trigger native parameters",
            );
        }
        Ok(())
    }
    /// A canceled setup never started a GPU unit. Settle its actual resource
    /// release before forgetting command ownership; native configuration stays.
    pub fn cancel_setup(
        &self,
        submission: &Submission,
        lease: Lease,
        outcome: &crate::platform::apple::agx::work_decode::resources::Outcome,
    ) -> Result<(), &'static str> {
        self.available()?;
        let mut native = self.power.native.borrow_mut();
        let run = native
            .work
            .run
            .as_ref()
            .ok_or("GFX CL setup cancellation has no native owner")?;
        if run.submission != *submission
            || run.lease != lease
            || run.backend.is_some()
            || !matches!(
                outcome,
                crate::platform::apple::agx::work_decode::resources::Outcome::Aborted
            )
        {
            return Err(
                "GFX CL setup cancellation requires its settled pre-trigger resource abort",
            );
        }
        native.work.run = None;
        Ok(())
    }
    pub fn check_submitted(
        &self,
        submission: &Submission,
        lease: Lease,
    ) -> Result<(), &'static str> {
        self.available()?;
        let native = self.power.native.borrow();
        let run = native
            .work
            .run
            .as_ref()
            .ok_or("GFX CL post-trigger phase has no native owner")?;
        if run.submission != *submission
            || run.lease != lease
            || run.backend.as_ref().and_then(Execution::outcome).is_none()
        {
            return Err("GFX CL post-trigger phase does not own its accepted native trigger");
        }
        Ok(())
    }
    pub fn outcome(&self) -> Result<Option<ResultKind>, WorkError> {
        let native = self.power.native.borrow();
        let run = native.work.run.as_ref().ok_or(WorkError::Refused(
            "GFX CL outcome has no accepted native owner",
        ))?;
        match &run.backend {
            Some(backend) => backend.outcome().transpose(),
            None => Ok(None),
        }
    }

    /// The stock finalize owner calls this only after its actual resource
    /// release and shared-memory phases have committed. A terminal GPU error
    /// requires the separately qualified abort/recovery path, not success.
    pub fn complete(
        &self,
        submission: &Submission,
        lease: Lease,
        released: &crate::platform::apple::agx::work_decode::resources::Outcome,
    ) -> Result<(), &'static str> {
        self.available()?;
        let mut native = self.power.native.borrow_mut();
        let run = native
            .work
            .run
            .as_ref()
            .ok_or("GFX CL completion has no native owner")?;
        if run.submission != *submission || run.lease != lease {
            return Err("GFX CL completion does not own its original submission and lease");
        }
        if !matches!(
            released,
            crate::platform::apple::agx::work_decode::resources::Outcome::Released
        ) || !matches!(
            run.backend.as_ref().and_then(Execution::outcome),
            Some(Ok(ResultKind::Compute(_)))
        ) {
            return Err("GFX CL completion precedes actual GPU success or resource release");
        }
        native.work.run = None;
        Ok(())
    }
}

/// Original setup parameter phase over the actual firmware DMA port.
/// Shared memory remains RAM-only; native operations use the SGX owner.
pub struct ParameterAccess<'a, 'b, 'c> {
    owner: &'a FirmwareWork,
    port: &'a mut Port<'b, 'c>,
}
impl FirmwareWork {
    pub fn parameter_access<'a, 'b, 'c>(
        &'a self,
        port: &'a mut Port<'b, 'c>,
    ) -> ParameterAccess<'a, 'b, 'c> {
        ParameterAccess { owner: self, port }
    }
}
impl crate::platform::apple::agx::work_decode::cl::Access for ParameterAccess<'_, '_, '_> {
    fn policy(&self) -> Policy {
        self.owner.policy
    }
    fn memory(&mut self) -> &mut dyn crate::platform::apple::agx::ring::Shared {
        self.port
    }
    fn check_available(&self) -> Result<(), &'static str> {
        self.owner.available()
    }
    fn begin(&mut self, submission: &Submission, lease: Lease) -> Result<(), &'static str> {
        self.owner.begin(submission, lease)
    }
    fn check_submitted(&self, submission: &Submission, lease: Lease) -> Result<(), &'static str> {
        self.owner.check_submitted(submission, lease)
    }
    fn read_native(&mut self, register: Register) -> Result<u64, &'static str> {
        self.owner.read(self.port, register)
    }
    fn write_native(&mut self, register: Register, value: u64) -> Result<(), &'static str> {
        self.owner.write(self.port, register, value)
    }
}

/// A resource phase must use the same concrete SGX and MCC objects as its
/// native parameters, not merely equal register addresses or geometry.
pub struct AttachmentAccess<'a, 'b, 'c> {
    owner: &'a FirmwareWork,
    resources: &'a super::resources::FirmwareResources,
    port: &'a mut Port<'b, 'c>,
}
impl FirmwareWork {
    pub fn attachment_access<'a, 'b, 'c>(
        &'a self,
        resources: &'a super::resources::FirmwareResources,
        port: &'a mut Port<'b, 'c>,
    ) -> Result<AttachmentAccess<'a, 'b, 'c>, &'static str> {
        resources.check_compute_owner(&self.power, &self.cache)?;
        Ok(AttachmentAccess {
            owner: self,
            resources,
            port,
        })
    }
}
impl crate::platform::apple::agx::work_decode::resources::Access for AttachmentAccess<'_, '_, '_> {
    fn memory(&mut self) -> &mut dyn crate::platform::apple::agx::ring::Shared {
        self.port
    }
    fn check_available(&self) -> Result<(), &'static str> {
        self.owner.available()
    }
    fn check_native(
        &self,
        write: crate::platform::apple::agx::work_decode::resources::NativeWrite,
    ) -> Result<(), &'static str> {
        self.resources.check_native(write)
    }
    fn write_native(
        &mut self,
        write: crate::platform::apple::agx::work_decode::resources::NativeWrite,
    ) -> Result<(), &'static str> {
        self.owner.available()?;
        self.resources.access(self.port).write_native(write)
    }
}
impl crate::platform::apple::agx::work_decode::cl::attachments::Access
    for AttachmentAccess<'_, '_, '_>
{
    fn check_owner(
        &self,
        parameters: &crate::platform::apple::agx::work_decode::cl::Parameters,
    ) -> Result<(), &'static str> {
        let (submission, lease, policy) = parameters.identity();
        self.owner.check_setup_owner(submission, lease, policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::{
        agx::{
            channel::{Command, Stamp},
            generation::{self, GPUS},
            ring::tests::Flat,
            sgx::Sgx,
            uat,
            work_decode::Encoding,
        },
        amcc::{Amcc, Cache, Layout, LockGroup, Register as MccRegister},
        bus::{Access, Lifecycle, LifecycleState, MmioDevice, Width},
        interrupt::InterruptLatch,
    };
    use crate::platform::dma::{Memory, tests::Ram};

    const RAM: u64 = 0x800000000;
    const SGX: u64 = 0x204000000;
    const VA: u64 = 0x100000;
    const DATA: u64 = RAM + 0x10000;

    fn cache() -> Amcc {
        cache_for(1)
    }
    fn cache_for(apertures: usize) -> Amcc {
        let bit = |offset| MccRegister {
            offset,
            mask: 1,
            value: 1,
        };
        let limit = |offset| MccRegister {
            offset,
            mask: u32::MAX,
            value: 0,
        };
        Amcc::new(
            Layout {
                aperture_bytes: 0xf40000,
                planes: 4,
                stride: 0x40000,
                cache_status: Some(bit(0x424)),
                group: LockGroup {
                    page_size_shift: 14,
                    lower_limit: limit(0x680),
                    upper_limit: limit(0x684),
                    enable: Some(bit(0x688)),
                    write_disable: Some(bit(0x7f0)),
                    lock: Some(bit(0x68c)),
                },
                dram_base: RAM,
            },
            apertures,
            None,
            Some(Cache {
                shared: (0x100000, 0x80000),
                broadcast: 0xf00000,
                bytes: 8 << 20,
                ways: 16,
            }),
        )
        .unwrap()
    }
    fn region() -> Region {
        let mut memory = Flat::new(0x1000, 0x4000);
        let descriptor = 0x1000 + 0x640 + 17 * 0x28;
        memory.put_u64(descriptor, SGX);
        memory.put_u64(descriptor + 8, VA);
        memory.put_u32(descriptor + 0x10, 0x20000);
        memory.put_u32(descriptor + 0x14, 0x20000);
        memory.put_u32(descriptor + 0x20, 2);
        Region::read(&mut memory, 0x1000, Kind::ResourceWindows).unwrap()
    }
    fn gpu(family: &'static generation::Family) -> Sgx {
        let gpu = GPUS
            .iter()
            .find(|gpu| gpu.family == family && gpu.admitted().is_ok())
            .unwrap();
        Sgx::handed_off(gpu, RAM, RAM + 0x8000).unwrap()
    }
    fn submission() -> Submission {
        Submission {
            command: Command {
                va: 0x3000,
                kind: CommandKind::Cl,
            },
            encoding: Encoding::Fixed,
            counter: 0x9876,
            context: 5,
            stamp: Stamp {
                driver: 0x3040,
                firmware: 0x3044,
                value: 0x100,
                index: 1,
            },
            stream: 0x3400,
            stream_bytes: 0x400,
        }
    }
    const LEASE: Lease = Lease { pipe: 2, slot: 0 };
    fn mapping(memory: &mut Ram, va: u64, physical: u64, device: bool) {
        let flags = uat::Flags {
            access: uat::Access::FirmwareGpu,
            memory: if device {
                uat::MemoryAttr::Device
            } else {
                uat::MemoryAttr::Cached
            },
            global: true,
            pxn: true,
            uxn: true,
            gpu_access: true,
        };
        memory.put_u64(
            RAM + 0xc000 + ((va >> 14) & 0x7ff) * 8,
            uat::encode_pte(physical, &flags),
        );
    }
    struct TraceRam {
        ram: Ram,
        reads: usize,
        writes: usize,
        fail_write: Option<usize>,
    }
    impl Memory for TraceRam {
        fn read(&mut self, pa: u64, out: &mut [u8]) -> bool {
            if (DATA..DATA + 0x8000).contains(&pa) {
                self.reads += 1;
            }
            self.ram.read(pa, out)
        }
        fn write(&mut self, pa: u64, data: &[u8]) -> bool {
            if (DATA..DATA + 0x8000).contains(&pa) {
                let at = self.writes;
                self.writes += 1;
                if self.fail_write == Some(at) {
                    self.fail_write = None;
                    return false;
                }
            }
            self.ram.write(pa, data)
        }
    }
    fn ram() -> TraceRam {
        let mut memory = Ram::new(RAM, 0x18000);
        for context in [0, 5] {
            let [ttbr0, ttbr1] = uat::encode_gptbat(context, RAM + 0x4000, 0);
            memory.put_u64(RAM + u64::from(context) * 16, ttbr0);
            memory.put_u64(RAM + u64::from(context) * 16 + 8, ttbr1);
        }
        memory.put_u64(RAM + 0x4000, uat::encode_table(RAM + 0x8000));
        memory.put_u64(RAM + 0x8000, uat::encode_table(RAM + 0xc000));
        mapping(&mut memory, 0, DATA, false);
        mapping(&mut memory, 0x4000, DATA + 0x4000, false);
        for page in [0x4000, 0x10000, 0x14000, 0x18000] {
            mapping(&mut memory, VA + page, SGX + page, true);
        }
        // One real four-thread CDM launch; USC and shader stay in context 5.
        let mut usc = Vec::new();
        usc.extend_from_slice(&(0x8d_u32 | 8 << 8).to_le_bytes());
        usc.extend_from_slice(&(0x1d_u64 | 4 << 20 | (0x800_u64 >> 2) << 26).to_le_bytes());
        usc.extend_from_slice(&[0x0d, 0]);
        usc.extend_from_slice(&0x200u32.to_le_bytes());
        usc.extend_from_slice(&[0x88, 0]);
        assert!(memory.write(DATA + 0x100, &usc));
        assert!(memory.write(
            DATA + 0x200,
            &crate::platform::apple::agx::isa::assemble::program(
                "mov r2, thread_in_grid_x\nstore r2, du0, r2, i32, x, a\nstop"
            )
        ));
        memory.put_u64(DATA + 0x800, 0x1000);
        for (index, word) in [1u32 << 1, 0x100, 4, 1, 1, 4, 1, 1, 2 << 29]
            .iter()
            .enumerate()
        {
            assert!(memory.write(DATA + 0x2000 + index as u64 * 4, &word.to_le_bytes()));
        }
        TraceRam {
            ram: memory,
            reads: 0,
            writes: 0,
            fail_write: None,
        }
    }
    fn io<R>(sgx: &mut Sgx, memory: &mut TraceRam, f: impl FnOnce(&mut Port<'_, '_>) -> R) -> R {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut iommu = sgx.uat().agent(uat::Agent::Firmware);
        f(&mut Port {
            iommu: &mut iommu,
            stream: 0,
            memory,
            access: &mut access,
        })
    }
    fn captured_rmw(owner: &FirmwareWork) {
        let mut native = owner.power.native.borrow_mut();
        native.work.control = Some(0);
        native.work.context_mask = Some(1 << 9);
    }
    #[test]
    fn actual_3d_parameter_owner_retains_scene_store_then_ram_fault_and_excludes_ta() {
        use crate::platform::apple::agx::work_decode::three_d;
        for family in [&generation::G13G, &generation::G13X, &generation::G14G] {
            let mut sgx = gpu(family);
            let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
            let mcc = cache();
            let owner = power
                .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
                .unwrap();
            let mut input = submission();
            input.command.kind = CommandKind::ThreeD;
            let lease = Lease { pipe: 1, slot: 2 };
            let mut memory = ram();
            let frame = io(&mut sgx, &mut memory, |port| {
                port.write(input.stream, &7u32.to_le_bytes()).unwrap();
                port.write(input.stream + 4, &0x3ffcu64.to_le_bytes())
                    .unwrap();
                port.write(input.stream + 0xc, &0x5000u64.to_le_bytes())
                    .unwrap();
                port.write(input.stream + 0x14, &0x2500u64.to_le_bytes())
                    .unwrap();
                port.write(input.stream + 0x54, &input.context.to_le_bytes())
                    .unwrap();
                port.write(0x2518, &0x131fu64.to_le_bytes()).unwrap();
                for index in 0..18 {
                    port.write(0x3ffc + index * 4, &(0x100 + index as u32).to_le_bytes())
                        .unwrap();
                }
                for index in 0..51 {
                    port.write(0x5000 + index * 8, &(0x8000 + index).to_le_bytes())
                        .unwrap();
                }
                input.cursor().next(port).unwrap().unwrap()
            });
            let mut parameters =
                three_d::Parameters::new(&input, &frame, lease, owner.policy).unwrap();
            mapping(&mut memory.ram, VA + 0x14000, 0, true);
            assert!(
                io(&mut sgx, &mut memory, |port| parameters
                    .advance(&mut owner.three_d_parameter_access(port)))
                .is_err()
            );
            assert_eq!(power.native.borrow().work.render.writes, 0);
            memory.ram.put_u64(DATA + 0x2518, 0x999f);
            mapping(&mut memory.ram, VA + 0x14000, SGX + 0x14000, true);
            mapping(&mut memory.ram, 0x4000, 0, false);
            assert!(
                io(&mut sgx, &mut memory, |port| parameters
                    .advance(&mut owner.three_d_parameter_access(port)))
                .is_err()
            );
            assert_eq!(power.native.borrow().work.render.writes, 2);
            assert_eq!(
                power
                    .native
                    .borrow()
                    .work
                    .render
                    .value(three_d::words(owner.policy)[0]),
                Some(0x1310)
            );
            assert!(power.check_reset().is_err());
            assert!(owner.begin(&submission(), LEASE).is_err());
            let mut other = input.clone();
            other.command.kind = CommandKind::Ta;
            use crate::platform::apple::agx::work_decode::ta::Access as _;
            assert!(
                io(&mut sgx, &mut memory, |port| owner
                    .ta_parameter_access(port)
                    .write_native(three_d::words(owner.policy)[2], 0x101))
                .is_err()
            );
            assert_eq!(power.native.borrow().work.render.writes, 2);
            assert!(
                io(&mut sgx, &mut memory, |port| owner
                    .ta_parameter_access(port)
                    .begin(&other, Lease { pipe: 0, slot: 1 }))
                .is_err()
            );
            mapping(&mut memory.ram, 0x4000, DATA + 0x4000, false);
            io(&mut sgx, &mut memory, |port| {
                parameters.advance(&mut owner.three_d_parameter_access(port))
            })
            .unwrap();
            assert!(parameters.completed());
            let expected = match owner.policy {
                Policy::G13G => 61,
                Policy::G13X => 60,
                Policy::G14G => 67,
            };
            assert_eq!(power.native.borrow().work.render.writes, expected);
            let counts = (memory.reads, memory.writes);
            io(&mut sgx, &mut memory, |port| {
                parameters.advance(&mut owner.three_d_parameter_access(port))
            })
            .unwrap();
            assert_eq!((memory.reads, memory.writes), counts);
            assert_eq!(power.native.borrow().work.control, None);
            assert!(
                owner
                    .cancel_ta_parameters(
                        &input,
                        lease,
                        &crate::platform::apple::agx::work_decode::resources::Outcome::Aborted
                    )
                    .is_err()
            );
            owner
                .cancel_three_d_parameters(
                    &input,
                    lease,
                    &crate::platform::apple::agx::work_decode::resources::Outcome::Aborted,
                )
                .unwrap();
            assert!(!power.native.borrow().work.active());
            assert_eq!(
                power
                    .native
                    .borrow()
                    .work
                    .render
                    .value(three_d::words(owner.policy)[0]),
                Some(0x1310)
            );
        }
    }
    #[test]
    fn ta_native_parameters_retain_captured_store_and_committed_prefix_across_real_uat_faults() {
        use crate::platform::apple::agx::work_decode::ta;
        for family in [&generation::G13G, &generation::G13X, &generation::G14G] {
            let mut sgx = gpu(family);
            let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
            let mcc = cache();
            let owner = power
                .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
                .unwrap();
            let mut input = submission();
            input.command.kind = CommandKind::Ta;
            let lease = Lease { pipe: 0, slot: 1 };
            let mut memory = ram();
            mapping(&mut memory.ram, VA + 0x1c000, SGX + 0x1c000, true);
            let frame = io(&mut sgx, &mut memory, |port| {
                port.write(input.stream, &5u32.to_le_bytes()).unwrap();
                port.write(input.stream + 4, &0x2200u64.to_le_bytes())
                    .unwrap();
                port.write(input.stream + 0xc, &0x3ff8u64.to_le_bytes())
                    .unwrap();
                port.write(input.stream + 0x1c, &0x2500u64.to_le_bytes())
                    .unwrap();
                port.write(input.stream + 0x3c, &input.context.to_le_bytes())
                    .unwrap();
                for index in 0..13 {
                    port.write(0x2200 + index * 4, &(0x100 + index as u32).to_le_bytes())
                        .unwrap();
                }
                for index in 0..36 {
                    port.write(0x3ff8 + index * 8, &(0x4000 + index).to_le_bytes())
                        .unwrap();
                }
                port.write(0x2208, &0x200u32.to_le_bytes()).unwrap();
                port.write(0x220c, &0x000f000fu32.to_le_bytes()).unwrap();
                let (vdm, usc) = if owner.policy == Policy::G14G {
                    (0x70, 0xa8)
                } else {
                    (0x90, 0xe0)
                };
                port.write(0x3ff8 + vdm, &0x2000u64.to_le_bytes()).unwrap();
                port.write(0x3ff8 + usc, &0x1100000000u64.to_le_bytes())
                    .unwrap();
                input.cursor().next(port).unwrap().unwrap()
            });
            let mut parameters = ta::Parameters::new(&input, &frame, lease, owner.policy).unwrap();
            assert_eq!(
                power
                    .native
                    .borrow()
                    .work
                    .render
                    .value(ta::words(owner.policy)[0]),
                None
            );
            // The thirteenth tiling read succeeds, but its actual native PIO
            // store faults. Earlier native words remain committed.
            mapping(&mut memory.ram, VA + 0x14000, 0, true);
            assert!(
                io(&mut sgx, &mut memory, |port| parameters
                    .advance(&mut owner.ta_parameter_access(port)))
                .is_err()
            );
            assert_eq!(power.native.borrow().work.render.writes, 12);
            assert!(owner.ta_geometry_inputs(&input, lease, None).is_err());
            assert!(power.check_reset().is_err());
            assert!(owner.begin(&submission(), LEASE).is_err());
            let mut other = input.clone();
            other.counter += 1;
            let mut foreign = ta::Parameters::new(&other, &frame, lease, owner.policy).unwrap();
            let counts = (memory.reads, memory.writes);
            assert!(
                io(&mut sgx, &mut memory, |port| foreign
                    .advance(&mut owner.ta_parameter_access(port)))
                .is_err()
            );
            assert_eq!((memory.reads, memory.writes), counts);
            let active = LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            };
            let gated = LifecycleState {
                clocked: false,
                ..active
            };
            let mut latch = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut latch);
            sgx.check_lifecycle(gated).unwrap();
            sgx.set_lifecycle(gated, &mut access);
            let counts = (memory.reads, memory.writes);
            assert!(
                io(&mut sgx, &mut memory, |port| parameters
                    .advance(&mut owner.ta_parameter_access(port)))
                .is_err()
            );
            assert_eq!((memory.reads, memory.writes), counts);
            assert_eq!(power.native.borrow().work.render.writes, 12);
            sgx.check_lifecycle(active).unwrap();
            sgx.set_lifecycle(active, &mut access);
            memory.ram.put_u64(DATA + 0x2230, 0xdeadbeef);
            mapping(&mut memory.ram, VA + 0x14000, SGX + 0x14000, true);
            // A later parameter read faults across a different RAM page;
            // retry must first store the retained tiling word, not reread it.
            mapping(&mut memory.ram, 0x4000, 0, false);
            assert!(
                io(&mut sgx, &mut memory, |port| parameters
                    .advance(&mut owner.ta_parameter_access(port)))
                .is_err()
            );
            assert_eq!(power.native.borrow().work.render.writes, 14);
            assert_eq!(
                power
                    .native
                    .borrow()
                    .work
                    .render
                    .value(ta::words(owner.policy)[12]),
                Some(0x10c)
            );
            mapping(&mut memory.ram, 0x4000, DATA + 0x4000, false);
            io(&mut sgx, &mut memory, |port| {
                parameters.advance(&mut owner.ta_parameter_access(port))
            })
            .unwrap();
            assert!(parameters.completed());
            assert_eq!(
                owner.ta_geometry_inputs(&input, lease, None).unwrap(),
                crate::platform::apple::agx::exec::render::GeometryInputs {
                    vdm_stream: 0x2000,
                    usc_base: 0x1100000000,
                    vm_slot: input.context,
                    ppp_control: 0x200,
                    width: 16,
                    height: 16,
                    sampler_heap: None,
                }
            );
            assert!(owner.ta_geometry_inputs(&other, lease, None).is_err());
            let expected = if owner.policy == Policy::G13X { 49 } else { 41 };
            assert_eq!(power.native.borrow().work.render.writes, expected);
            let counts = (memory.reads, memory.writes);
            io(&mut sgx, &mut memory, |port| {
                parameters.advance(&mut owner.ta_parameter_access(port))
            })
            .unwrap();
            assert_eq!((memory.reads, memory.writes), counts);
            assert_eq!(power.native.borrow().work.render.writes, expected);
            // No common control/mask initialization, GPU execution or command
            // completion authority is manufactured by parameter storage.
            assert_eq!(power.native.borrow().work.control, None);
            assert_eq!(power.native.borrow().work.context_mask, None);
            assert_eq!(
                power
                    .native
                    .borrow()
                    .work
                    .render
                    .value(ta::words(owner.policy)[14]),
                Some(0x4001)
            );
            assert!(
                owner
                    .cancel_ta_parameters(
                        &input,
                        Lease { slot: 2, ..lease },
                        &crate::platform::apple::agx::work_decode::resources::Outcome::Aborted
                    )
                    .is_err()
            );
            owner
                .cancel_ta_parameters(
                    &input,
                    lease,
                    &crate::platform::apple::agx::work_decode::resources::Outcome::Aborted,
                )
                .unwrap();
            assert!(!power.native.borrow().work.active());
            assert!(owner.ta_geometry_inputs(&input, lease, None).is_err());
            assert_eq!(
                power
                    .native
                    .borrow()
                    .work
                    .render
                    .value(ta::words(owner.policy)[12]),
                Some(0x10c)
            );
            let mut stamp = [0; 4];
            assert!(memory.ram.read(DATA + input.stamp.firmware, &mut stamp));
            assert_eq!(stamp, [0; 4]);
        }
    }
    fn program(owner: &FirmwareWork, sgx: &mut Sgx, memory: &mut TraceRam) {
        captured_rmw(owner);
        let mut words = alloc::vec![(Register::Control, 1), (Register::Context, (5 << 8) | 3)];
        if owner.policy == Policy::G13X {
            words.push((Register::LegacySetup, 0x100));
        }
        words.push((Register::ContextMask, 1 << 9 | 1 << 5));
        if owner.policy == Policy::G13X {
            words.push((Register::LegacyMask, 1 << 9 | 1 << 5));
        }
        for (index, value) in [0, 0x2000, 0, 0, 0, 0, 0, 0x8c60, 0, 0, 0, 1, 0]
            .into_iter()
            .enumerate()
        {
            if index == 7 && owner.policy == Policy::G13X {
                continue;
            }
            words.push((Register::Parameter(index as u8), value));
            if index == if owner.policy == Policy::G13X { 6 } else { 7 } {
                words.push((Register::Setup, 0x100));
            }
        }
        words.push((Register::Resource, 0));
        for (register, value) in words {
            io(sgx, memory, |port| owner.write(port, register, value)).unwrap();
        }
    }

    #[test]
    fn actual_native_submit_runs_once_retains_parameters_and_preserves_terminal_faults() {
        for family in [&generation::G13G, &generation::G13X, &generation::G14G] {
            for fail in [false, true] {
                let mut sgx = gpu(family);
                let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
                let mcc = cache();
                let owner = power
                    .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
                    .unwrap();
                let input = submission();
                owner.begin(&input, LEASE).unwrap();
                let mut memory = ram();
                assert!(power.check_reset().is_err());
                assert!(
                    io(&mut sgx, &mut memory, |port| owner.write(
                        port,
                        Register::Submit,
                        1
                    ))
                    .is_err()
                );
                program(&owner, &mut sgx, &mut memory);
                if fail {
                    memory.fail_write = Some(2);
                }
                io(&mut sgx, &mut memory, |port| {
                    owner.write(port, Register::Submit, 1)
                })
                .unwrap();
                owner.check_submitted(&input, LEASE).unwrap();
                let mut other = input.clone();
                other.counter += 1;
                assert!(owner.check_submitted(&other, LEASE).is_err());
                assert!(
                    owner
                        .check_submitted(&input, Lease { slot: 1, ..LEASE })
                        .is_err()
                );
                assert!(
                    owner
                        .cancel_setup(
                            &input,
                            LEASE,
                            &crate::platform::apple::agx::work_decode::resources::Outcome::Aborted
                        )
                        .is_err()
                );
                let outcome = owner.outcome();
                assert_eq!(outcome.is_err(), fail);
                if !fail {
                    assert!(matches!(outcome, Ok(Some(ResultKind::Compute(_)))));
                }
                let counts = (memory.reads, memory.writes);
                assert_eq!(counts.1, if fail { 3 } else { 4 });
                assert!(memory.ram.write(DATA + 0x1000, &777u32.to_le_bytes()));
                assert!(memory.ram.write(DATA + 0x2000, &u32::MAX.to_le_bytes()));
                owner.begin(&input, LEASE).unwrap();
                io(&mut sgx, &mut memory, |port| {
                    owner.write(port, Register::Submit, 1)
                })
                .unwrap();
                assert_eq!(owner.outcome(), outcome);
                assert_eq!((memory.reads, memory.writes), counts);
                let mut value = [0; 4];
                assert!(memory.ram.read(DATA + 0x1000, &mut value));
                assert_eq!(u32::from_le_bytes(value), 777);
                assert_eq!(owner.power.native.borrow().work.parameters[1], 0x2000);
                assert!(
                    owner
                        .complete(
                            &input,
                            LEASE,
                            &crate::platform::apple::agx::work_decode::resources::Outcome::Aborted
                        )
                        .is_err()
                );
                if fail {
                    assert!(owner.complete(&input, LEASE,
                        &crate::platform::apple::agx::work_decode::resources::Outcome::Released).is_err());
                } else {
                    owner
                        .complete(
                            &input,
                            LEASE,
                            &crate::platform::apple::agx::work_decode::resources::Outcome::Released,
                        )
                        .unwrap();
                    assert!(!owner.power.native.borrow().work.active());
                    assert_eq!(owner.power.native.borrow().work.parameters[1], 0x2000);
                    power.check_reset().unwrap();
                }
            }
        }
    }

    #[test]
    fn native_pio_faults_and_retained_power_or_dram_gates_preserve_owned_configuration() {
        for dram in [false, true] {
            let mut sgx = gpu(&generation::G14G);
            let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
            let mut mcc = cache();
            let owner = power
                .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
                .unwrap();
            owner.begin(&submission(), LEASE).unwrap();
            let mut memory = ram();
            // A translated foreign bank cannot alter the shared SGX state.
            mapping(&mut memory.ram, VA + 0x18000, SGX + 0x28000, true);
            assert_eq!(
                io(&mut sgx, &mut memory, |port| owner.write(
                    port,
                    Register::Parameter(1),
                    0x2000
                )),
                Err("GFX CL PIO translation disagrees with its actual SGX bank")
            );
            assert_eq!(
                power
                    .native
                    .borrow()
                    .work
                    .run
                    .as_ref()
                    .unwrap()
                    .parameter_mask,
                0
            );
            mapping(&mut memory.ram, VA + 0x18000, SGX + 0x18000, true);
            program(&owner, &mut sgx, &mut memory);
            let mut latch = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut latch);
            assert!(
                sgx.write(super::super::FENDER_SLEEP, Width::Word, 1, &mut access)
                    .is_err()
            );
            assert_eq!(power.native.borrow().sleep_request, 0);
            if dram {
                mcc.write(0xf00410, Width::Word, 0, &mut access).unwrap();
                assert_eq!(
                    io(&mut sgx, &mut memory, |port| owner.write(
                        port,
                        Register::Submit,
                        1
                    )),
                    Err("MCC resource RAM after DRAM access disable")
                );
                assert_eq!(owner.outcome(), Ok(None));
            } else {
                let active = LifecycleState {
                    powered: true,
                    clocked: true,
                    quiesced: false,
                    reset: false,
                    retention: false,
                };
                let gated = LifecycleState {
                    clocked: false,
                    ..active
                };
                sgx.check_lifecycle(gated).unwrap();
                sgx.set_lifecycle(gated, &mut access);
                assert_eq!(
                    io(&mut sgx, &mut memory, |port| owner.write(
                        port,
                        Register::Submit,
                        1
                    )),
                    Err("GFX CL native operation while SGX execution is inhibited")
                );
                assert_eq!(owner.outcome(), Ok(None));
                assert_eq!((memory.reads, memory.writes), (0, 0));
                sgx.check_lifecycle(active).unwrap();
                sgx.set_lifecycle(active, &mut access);
                io(&mut sgx, &mut memory, |port| {
                    owner.write(port, Register::Submit, 1)
                })
                .unwrap();
                assert!(matches!(owner.outcome(), Ok(Some(ResultKind::Compute(_)))));
            }
            assert_eq!(power.native.borrow().work.parameters[1], 0x2000);
        }
    }

    #[test]
    fn original_parameter_phase_reaches_real_native_trigger_after_a_retained_uat_fault() {
        use crate::platform::apple::agx::work_decode::cl::Parameters;
        for family in [&generation::G13G, &generation::G13X, &generation::G14G] {
            let mut sgx = gpu(family);
            let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
            let mcc = cache();
            let owner = power
                .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
                .unwrap();
            let input = submission();
            let mut memory = ram();
            let mut setup = alloc::vec![0; 0x16c];
            setup[..4].copy_from_slice(&11u32.to_le_bytes());
            setup[0xc..0x14].copy_from_slice(&0x3000u64.to_le_bytes());
            setup[0x14..0x1c].copy_from_slice(&0x3800u64.to_le_bytes());
            setup[0x1c..0x24].copy_from_slice(&0x3900u64.to_le_bytes());
            setup[0x24..0x28].copy_from_slice(&5u32.to_le_bytes());
            setup[0x28..0x2c].copy_from_slice(&1u32.to_le_bytes());
            setup[0x2c..0x30].copy_from_slice(&3u32.to_le_bytes());
            assert!(memory.ram.write(DATA + input.stream, &setup));
            for (index, value) in [0u64, 0x2000, 0, 0, 0, 0, 0, 0x8c60, 0, 0, 0, 1, 0]
                .into_iter()
                .enumerate()
            {
                memory.ram.put_u64(DATA + 0x3000 + index as u64 * 8, value);
            }
            let frame = io(&mut sgx, &mut memory, |port| input.cursor().next(port))
                .unwrap()
                .unwrap();
            captured_rmw(&owner);
            let mut program = Parameters::new(&input, &frame, LEASE, owner.policy).unwrap();
            mapping(&mut memory.ram, VA + 0x14000, SGX + 0x24000, true);
            assert_eq!(
                io(&mut sgx, &mut memory, |port| program
                    .advance(&mut owner.parameter_access(port))),
                Err("GFX CL PIO translation disagrees with its actual SGX bank")
            );
            assert_eq!(power.native.borrow().work.control, Some(1));
            assert_eq!(power.native.borrow().work.context, 0x503);
            assert_eq!(
                power
                    .native
                    .borrow()
                    .work
                    .run
                    .as_ref()
                    .unwrap()
                    .parameter_mask,
                0
            );
            assert_eq!(memory.writes, 0);
            assert!(power.check_reset().is_err());
            mapping(&mut memory.ram, VA + 0x14000, SGX + 0x14000, true);
            // A retry owns the accepted SKU fields, even if AP memory changes.
            assert!(
                memory
                    .ram
                    .write(DATA + input.stream + 0x24, &9u32.to_le_bytes())
            );
            io(&mut sgx, &mut memory, |port| {
                program.advance(&mut owner.parameter_access(port))
            })
            .unwrap();
            assert!(program.completed());
            assert_eq!(owner.outcome(), Ok(None));
            io(&mut sgx, &mut memory, |port| {
                owner.write(port, Register::Resource, 0)
            })
            .unwrap();
            let before = memory.writes;
            io(&mut sgx, &mut memory, |port| {
                owner.write(port, Register::Submit, 1)
            })
            .unwrap();
            assert!(matches!(owner.outcome(), Ok(Some(ResultKind::Compute(_)))));
            assert_eq!(memory.writes - before, 4);
            for index in 0..4 {
                let mut word = [0; 4];
                assert!(memory.ram.read(DATA + 0x1000 + index * 4, &mut word));
                assert_eq!(u32::from_le_bytes(word), index as u32);
            }
            let counts = (memory.reads, memory.writes);
            io(&mut sgx, &mut memory, |port| {
                program.advance(&mut owner.parameter_access(port))
            })
            .unwrap();
            io(&mut sgx, &mut memory, |port| {
                owner.write(port, Register::Submit, 1)
            })
            .unwrap();
            assert_eq!((memory.reads, memory.writes), counts);
            // The post-trigger source slot publication owns each RAM write
            // independently of both the native trigger and its prior stores.
            let mut tail = crate::platform::apple::agx::work_decode::cl::slot::SetupTail::new(
                &input, &frame, LEASE,
            )
            .unwrap();
            memory.fail_write = Some(memory.writes + 1);
            assert!(
                io(&mut sgx, &mut memory, |port| tail
                    .advance(&mut owner.parameter_access(port)))
                .is_err()
            );
            let mut queue = [0; 8];
            assert!(memory.ram.read(DATA + 0x3810, &mut queue));
            assert_eq!(u64::from_le_bytes(queue), 0x3900);
            let reads = memory.reads;
            assert!(memory.ram.write(DATA + 0x2000, &u32::MAX.to_le_bytes()));
            io(&mut sgx, &mut memory, |port| {
                tail.advance(&mut owner.parameter_access(port))
            })
            .unwrap();
            assert!(tail.completed());
            assert_eq!(memory.reads, reads);
            let mut flag = [0; 4];
            assert!(memory.ram.read(DATA + 0x380c, &mut flag));
            assert_eq!(u32::from_le_bytes(flag), 1);
            let writes = memory.writes;
            io(&mut sgx, &mut memory, |port| {
                tail.advance(&mut owner.parameter_access(port))
            })
            .unwrap();
            assert_eq!(memory.writes, writes);
            // Neither source phase completes the original AP command.
            assert!(power.native.borrow().work.active());
        }
    }

    fn cache_region(policy: Policy) -> Region {
        let mut source = Flat::new(0x1000, 0x4000);
        let at = 0x1000 + 0x640 + 3 * 0x28;
        let (physical, bytes, range) = match policy {
            Policy::G14G => (0x200f04000u64, 0x18000u32, 0x18000u32),
            Policy::G13G => (0x200004000, 4 * 0x14000, 0x14000),
            Policy::G13X => (0x200004000, 8 * 0x14000, 0x14000),
        };
        source.put_u64(at, physical);
        source.put_u64(at + 8, 0x180000);
        source.put_u32(at + 0x10, bytes);
        source.put_u32(at + 0x14, range);
        source.put_u32(at + 0x20, 2);
        Region::read(&mut source, 0x1000, Kind::MCache).unwrap()
    }
    fn resource_root(memory: &mut TraceRam) -> crate::platform::apple::agx::initdata::Root {
        use crate::platform::apple::agx::initdata::{CONFIG_BYTES, Root};
        memory.ram.put_u64(DATA + 0x4000 + 0x2c8, 0x4800);
        memory.ram.put_u64(DATA + 0x4000 + 0x2d0, 0x6000);
        memory.ram.put_u64(DATA + 0x4000 + 0x2d8, 0x6400);
        Root {
            page_1660: 1,
            rings: 0x4000,
            object_358: 1,
            object_848: 1,
            object_928: 1,
            object_930: 1,
            object_368: 1,
            config: [0; CONFIG_BYTES],
        }
    }
    fn setup_with_attachment(
        input: &Submission,
        sgx: &mut Sgx,
        memory: &mut TraceRam,
    ) -> crate::platform::apple::agx::work_decode::Frame {
        let mut setup = alloc::vec![0;0x16c];
        setup[..4].copy_from_slice(&11u32.to_le_bytes());
        setup[0xc..0x14].copy_from_slice(&0x3000u64.to_le_bytes());
        setup[0x14..0x1c].copy_from_slice(&0x3800u64.to_le_bytes());
        setup[0x1c..0x24].copy_from_slice(&0x3900u64.to_le_bytes());
        setup[0x24..0x28].copy_from_slice(&input.context.to_le_bytes());
        setup[0x28..0x2c].copy_from_slice(&1u32.to_le_bytes());
        setup[0x50..0x58].copy_from_slice(&0x60000000u64.to_le_bytes());
        setup[0x58..0x5c].copy_from_slice(&8u32.to_le_bytes());
        setup[0x5c] = 5;
        setup[0x5e..0x60].copy_from_slice(&7u16.to_le_bytes());
        setup[0x150..0x154].copy_from_slice(&1u32.to_le_bytes());
        assert!(memory.ram.write(DATA + input.stream, &setup));
        for (index, value) in [0u64, 0x2000, 0, 0, 0, 0, 0, 0x8c60, 0, 0, 0, 1, 0]
            .into_iter()
            .enumerate()
        {
            memory.ram.put_u64(DATA + 0x3000 + index as u64 * 8, value);
        }
        io(sgx, memory, |port| input.cursor().next(port))
            .unwrap()
            .unwrap()
    }
    #[test]
    fn source_attachment_ownership_settles_real_native_and_ram_faults_before_canceling_setup() {
        use crate::platform::apple::agx::{
            sgx::resources::FirmwareResources,
            work_decode::{
                cl::{Parameters, attachments::Attachments},
                resources::{AttachmentResult, Outcome, Pool},
            },
        };
        for family in [&generation::G13G, &generation::G13X, &generation::G14G] {
            for cancel_early in [false, true] {
                let policy = Policy::for_family(family).unwrap();
                let mut sgx = gpu(family);
                let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
                let apertures = if policy == Policy::G13X {
                    alloc::vec![0x200000000, 0x201000000]
                } else {
                    alloc::vec![0x200000000]
                };
                let mcc = cache_for(apertures.len());
                let cache = mcc.firmware_cache(&apertures).unwrap();
                let owner = power.firmware_work(region(), cache.clone()).unwrap();
                let resources = FirmwareResources::new(power.clone(), region())
                    .unwrap()
                    .with_cache(cache_region(policy), cache)
                    .unwrap();
                let input = submission();
                let mut memory = ram();
                let root = resource_root(&mut memory);
                let frame = setup_with_attachment(&input, &mut sgx, &mut memory);
                let pool = io(&mut sgx, &mut memory, |port| {
                    Pool::bind(port, &root, family, 1)
                })
                .unwrap();
                let mut parameters = Parameters::new(&input, &frame, LEASE, policy).unwrap();
                captured_rmw(&owner);
                io(&mut sgx, &mut memory, |port| {
                    parameters.advance(&mut owner.parameter_access(port))
                })
                .unwrap();
                let mut phase = Attachments::new(parameters, pool).unwrap();
                // AP mutation after the accepted setup cannot redirect a row.
                memory.ram.put_u64(DATA + input.stream + 0x50, 0x70000000);
                if cancel_early {
                    phase.abort().unwrap();
                } else {
                    // All three native stores commit before the first shared
                    // row store faults; retries retain that native prefix.
                    memory.fail_write = Some(memory.writes);
                    assert!(
                        io(&mut sgx, &mut memory, |port| phase.advance(
                            &mut owner.attachment_access(&resources, port).unwrap()
                        ))
                        .is_err()
                    );
                    assert_ne!(resources.window(0).unwrap().control, 0);
                    assert_eq!(power.native.borrow().resources.committed_writes, 3);
                    // A refused transfer returns the same live owner, with
                    // the pool's committed native prefix still retained.
                    phase = phase.finish().unwrap_err().0;
                    assert_eq!(power.native.borrow().resources.committed_writes, 3);
                    let active = LifecycleState {
                        powered: true,
                        clocked: true,
                        quiesced: false,
                        reset: false,
                        retention: false,
                    };
                    let gated = LifecycleState {
                        clocked: false,
                        ..active
                    };
                    let mut latch = InterruptLatch::new();
                    let mut access = Access::new(0, 0, &mut latch);
                    sgx.check_lifecycle(gated).unwrap();
                    sgx.set_lifecycle(gated, &mut access);
                    let counts = (memory.reads, memory.writes);
                    assert!(
                        io(&mut sgx, &mut memory, |port| phase.advance(
                            &mut owner.attachment_access(&resources, port).unwrap()
                        ))
                        .is_err()
                    );
                    assert_eq!((memory.reads, memory.writes), counts);
                    sgx.check_lifecycle(active).unwrap();
                    sgx.set_lifecycle(active, &mut access);
                }
                io(&mut sgx, &mut memory, |port| {
                    phase.advance(&mut owner.attachment_access(&resources, port).unwrap())
                })
                .unwrap();
                if !cancel_early {
                    assert_eq!(
                        phase.result(),
                        Some(&Outcome::Acquired(alloc::vec![
                            AttachmentResult::Allocated(0)
                        ]))
                    );
                    assert_eq!(
                        resources.window(0).unwrap().address,
                        (0x60000000 >> 7) | (5 << 33) | (5 << 39) | (1 << 47)
                    );
                    assert!(
                        owner
                            .cancel_setup(&input, LEASE, &Outcome::Acquired(Vec::new()))
                            .is_err()
                    );
                    assert_eq!(power.native.borrow().resources.committed_writes, 3);
                    phase.abort().unwrap();
                    phase.abort().unwrap();
                    assert!(phase.result().is_none());
                    memory.fail_write = Some(memory.writes + 1);
                    assert!(
                        io(&mut sgx, &mut memory, |port| phase.advance(
                            &mut owner.attachment_access(&resources, port).unwrap()
                        ))
                        .is_err()
                    );
                    assert_eq!(resources.window(0).unwrap().control, 0);
                    assert_eq!(power.native.borrow().resources.committed_writes, 4);
                    assert!(phase.result().is_none());
                    io(&mut sgx, &mut memory, |port| {
                        phase.advance(&mut owner.attachment_access(&resources, port).unwrap())
                    })
                    .unwrap();
                }
                assert_eq!(phase.result(), Some(&Outcome::Aborted));
                assert_eq!(
                    power.native.borrow().resources.committed_writes,
                    if cancel_early { 0 } else { 4 }
                );
                assert_eq!(owner.outcome(), Ok(None));
                let (_, pool, outcome) = phase.finish().unwrap();
                io(&mut sgx, &mut memory, |port| pool.check_reset(port)).unwrap();
                assert!(power.check_reset().is_err());
                owner.cancel_setup(&input, LEASE, &outcome).unwrap();
                power.check_reset().unwrap();
                assert_eq!(power.native.borrow().work.parameters[1], 0x2000);
            }
        }
    }
    #[test]
    fn attachment_transfer_refusals_return_the_live_program_and_pool_owners() {
        use crate::platform::apple::agx::work_decode::{
            cl::{Parameters, attachments::Attachments},
            resources::Pool,
        };
        let mut sgx = gpu(&generation::G14G);
        let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
        let mcc = cache();
        let owner = power
            .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
            .unwrap();
        let input = submission();
        let mut memory = ram();
        let root = resource_root(&mut memory);
        let frame = setup_with_attachment(&input, &mut sgx, &mut memory);
        let pool = io(&mut sgx, &mut memory, |port| {
            Pool::bind(port, &root, &generation::G14G, 1)
        })
        .unwrap();
        let parameters = Parameters::new(&input, &frame, LEASE, Policy::G14G).unwrap();
        let (mut parameters, pool, reason) = Attachments::new(parameters, pool).unwrap_err();
        assert!(reason.contains("precedes complete"));
        assert!(!power.native.borrow().work.active());
        assert_eq!(power.native.borrow().resources.committed_writes, 0);
        captured_rmw(&owner);
        io(&mut sgx, &mut memory, |port| {
            parameters.advance(&mut owner.parameter_access(port))
        })
        .unwrap();
        let foreign = io(&mut sgx, &mut memory, |port| {
            Pool::bind(port, &root, &generation::G13G, 1)
        })
        .unwrap();
        let (parameters, foreign, reason) = Attachments::new(*parameters, foreign).unwrap_err();
        assert!(reason.contains("another fixed family"));
        assert!(!foreign.pending());
        assert!(power.native.borrow().work.active());
        assert_eq!(power.native.borrow().resources.committed_writes, 0);
        let phase = Attachments::new(*parameters, *pool).unwrap();
        assert!(phase.result().is_none());
        assert_eq!(owner.outcome(), Ok(None));
    }

    #[test]
    fn attachment_composition_rejects_equal_geometry_with_foreign_concrete_owners() {
        use crate::platform::apple::agx::sgx::resources::FirmwareResources;
        let mut sgx = gpu(&generation::G14G);
        let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
        let mcc = cache();
        let actual = mcc.firmware_cache(&[0x200000000]).unwrap();
        let owner = power.firmware_work(region(), actual.clone()).unwrap();
        let foreign = gpu(&generation::G14G);
        let foreign_power = foreign.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
        let mut memory = ram();
        for resources in [
            FirmwareResources::new(foreign_power, region())
                .unwrap()
                .with_cache(cache_region(Policy::G14G), actual)
                .unwrap(),
            FirmwareResources::new(power.clone(), region())
                .unwrap()
                .with_cache(
                    cache_region(Policy::G14G),
                    cache().firmware_cache(&[0x200000000]).unwrap(),
                )
                .unwrap(),
            FirmwareResources::new(power.clone(), region()).unwrap(),
        ] {
            assert!(
                io(&mut sgx, &mut memory, |port| owner
                    .attachment_access(&resources, port)
                    .map(|_| ()))
                .is_err()
            );
            assert_eq!((memory.reads, memory.writes), (0, 0));
        }
        assert!(!power.native.borrow().work.active());
    }

    #[test]
    fn unknown_native_rmw_words_never_manufacture_reset_readbacks_or_erase_independent_writes() {
        for family in [&generation::G13G, &generation::G13X, &generation::G14G] {
            let mut sgx = gpu(family);
            let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
            let mcc = cache();
            let owner = power
                .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
                .unwrap();
            let mut memory = ram();
            owner.begin(&submission(), LEASE).unwrap();
            for (register, reason) in [
                (Register::Control, "control initial value"),
                (Register::ContextMask, "context-mask initial value"),
            ] {
                assert!(
                    io(&mut sgx, &mut memory, |port| owner.read(port, register))
                        .unwrap_err()
                        .contains(reason)
                );
            }
            assert!(
                io(&mut sgx, &mut memory, |port| owner.write(
                    port,
                    Register::Control,
                    1
                ))
                .is_err()
            );
            assert!(
                io(&mut sgx, &mut memory, |port| owner.write(
                    port,
                    Register::ContextMask,
                    1 << 5
                ))
                .is_err()
            );
            // Complete independent native stores retain their values and
            // phase even though the earlier RMW source remains unqualified.
            io(&mut sgx, &mut memory, |port| {
                owner.write(port, Register::Context, 0x503)
            })
            .unwrap();
            io(&mut sgx, &mut memory, |port| {
                owner.write(port, Register::Parameter(1), 0x2000)
            })
            .unwrap();
            assert!(
                io(&mut sgx, &mut memory, |port| owner
                    .read(port, Register::Control))
                .is_err()
            );
            let input = submission();
            let mut source = Flat::new(0x1000, 0x4000);
            source.put_u32(input.stream, 11);
            source.put_u64(input.stream + 0xc, 0x2000);
            source.put_u32(input.stream + 0x24, input.context);
            let frame = input.cursor().next(&mut source).unwrap().unwrap();
            let mut program = crate::platform::apple::agx::work_decode::cl::Parameters::new(
                &input,
                &frame,
                LEASE,
                owner.policy,
            )
            .unwrap();
            assert!(
                io(&mut sgx, &mut memory, |port| program
                    .advance(&mut owner.parameter_access(port)))
                .unwrap_err()
                .contains("control initial value")
            );
            let native = power.native.borrow();
            assert_eq!(native.work.control, None);
            assert_eq!(native.work.context_mask, None);
            assert_eq!(native.work.legacy_mask, None);
            assert_eq!(native.work.legacy_setup, None);
            assert_eq!(native.work.context, 0x503);
            assert_eq!(native.work.parameters[1], 0x2000);
            let run = native.work.run.as_ref().unwrap();
            assert_eq!(run.programmed, 2);
            assert_eq!(run.parameter_mask, 1 << 1);
            assert_eq!((memory.reads, memory.writes), (0, 0));
            assert!(run.backend.is_none());
        }
    }

    #[test]
    fn captured_unqualified_control_flags_are_preserved_but_never_executed() {
        let mut sgx = gpu(&generation::G14G);
        let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
        let mcc = cache();
        let owner = power
            .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
            .unwrap();
        owner.begin(&submission(), LEASE).unwrap();
        let mut memory = ram();
        program(&owner, &mut sgx, &mut memory);
        // A capture can establish bits without establishing their effect.
        power.native.borrow_mut().work.control = Some(0x41);
        assert_eq!(
            io(&mut sgx, &mut memory, |port| owner.write(
                port,
                Register::Submit,
                1
            )),
            Err("GFX CL captured native control mode is not qualified")
        );
        assert_eq!(power.native.borrow().work.control, Some(0x41));
        assert_eq!(owner.outcome(), Ok(None));
        assert_eq!((memory.reads, memory.writes), (0, 0));
    }

    #[test]
    fn unknown_later_mask_preserves_the_committed_source_control_phase() {
        let mut sgx = gpu(&generation::G14G);
        let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
        let mcc = cache();
        let owner = power
            .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
            .unwrap();
        let input = submission();
        let mut source = Flat::new(0x1000, 0x4000);
        source.put_u32(input.stream, 11);
        source.put_u64(input.stream + 0xc, 0x2000);
        source.put_u32(input.stream + 0x24, input.context);
        let frame = input.cursor().next(&mut source).unwrap().unwrap();
        let mut program = crate::platform::apple::agx::work_decode::cl::Parameters::new(
            &input,
            &frame,
            LEASE,
            owner.policy,
        )
        .unwrap();
        // Only this captured word is known. There is no mask capture.
        power.native.borrow_mut().work.control = Some(0x40);
        let mut memory = ram();
        assert!(
            io(&mut sgx, &mut memory, |port| program
                .advance(&mut owner.parameter_access(port)))
            .unwrap_err()
            .contains("context-mask initial value")
        );
        assert_eq!(power.native.borrow().work.control, Some(0x41));
        assert_eq!(power.native.borrow().work.context, 0x500);
        assert_eq!(
            power.native.borrow().work.run.as_ref().unwrap().programmed,
            3
        );
        // Losing later capture authority cannot replay the already committed
        // control phase. Retry still reaches only the unknown mask read.
        power.native.borrow_mut().work.control = None;
        assert!(
            io(&mut sgx, &mut memory, |port| program
                .advance(&mut owner.parameter_access(port)))
            .unwrap_err()
            .contains("context-mask initial value")
        );
        assert_eq!(power.native.borrow().work.control, None);
        assert_eq!(
            power.native.borrow().work.run.as_ref().unwrap().programmed,
            3
        );
        assert_eq!((memory.reads, memory.writes), (0, 0));
    }

    #[test]
    fn native_target_extent_and_parameter_family_are_checked_before_effects() {
        let sgx = gpu(&generation::G14G);
        let mut power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
        // Deliberately corrupt only the copied descriptor to exercise the
        // final checked extent independently of constructor qualification.
        power.banks = alloc::vec![(u64::MAX - 0x10180, 0x4000000, 0)];
        assert!(power.native_work_targets().is_err());
        let mut registers = Registers::default();
        registers.begin(&submission(), LEASE).unwrap();
        assert!(
            registers
                .write(Policy::G13X, Register::Parameter(7), 1)
                .is_err()
        );
        assert_eq!(registers.parameters[7], 0);
        assert_eq!(registers.run.as_ref().unwrap().parameter_mask, 0);
    }

    #[test]
    fn unqualified_helper_resource_and_native_modes_never_start_the_backend() {
        for (register, value, reason) in [
            (Register::Parameter(8), 1, "enabled helper"),
            (Register::Parameter(7), 0x8ee0, "scheduling mode"),
            (Register::Parameter(10), 1, "secondary native controls"),
            (Register::Parameter(11), 0, "secondary native controls"),
            (Register::Parameter(12), 1, "secondary native controls"),
            (Register::Resource, 1, "buffer-cache resource"),
        ] {
            let mut sgx = gpu(&generation::G14G);
            let power = sgx.firmware_power(&[(SGX, 0x4000000, 0)]).unwrap();
            let mcc = cache();
            let owner = power
                .firmware_work(region(), mcc.firmware_cache(&[0x200000000]).unwrap())
                .unwrap();
            owner.begin(&submission(), LEASE).unwrap();
            let mut memory = ram();
            program(&owner, &mut sgx, &mut memory);
            io(&mut sgx, &mut memory, |port| {
                owner.write(port, register, value)
            })
            .unwrap();
            assert!(
                io(&mut sgx, &mut memory, |port| owner.write(
                    port,
                    Register::Submit,
                    1
                ))
                .unwrap_err()
                .contains(reason)
            );
            assert_eq!((memory.reads, memory.writes), (0, 0));
            assert_eq!(owner.outcome(), Ok(None));
            assert!(power.check_reset().is_err());
        }
        assert!(Register::Parameter(7).word(Policy::G13X).is_err());
        assert!(Register::Parameter(13).word(Policy::G14G).is_err());
        assert!(Register::LegacyMask.word(Policy::G14G).is_err());
        assert!(Policy::for_family(&generation::G14X).is_err());
        assert!(Policy::for_family(&generation::G15G).is_err());
    }
}
