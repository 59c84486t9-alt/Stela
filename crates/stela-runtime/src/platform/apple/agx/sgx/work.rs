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
    control: u64,
    context_mask: u64,
    legacy_mask: u64,
    legacy_setup: u64,
    context: u32,
    setup: u64,
    resource: u64,
    parameters: [u64; 13],
    run: Option<Run>,
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
        self.run.is_some()
    }

    fn begin(&mut self, submission: &Submission, lease: Lease) -> Result<(), &'static str> {
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
            Register::Control => Ok(self.control),
            Register::ContextMask => Ok(self.context_mask),
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
            Register::Control if value == self.control | 1 => {
                self.control = value;
                run.programmed |= 1;
            }
            Register::Context
                if value >> 8 == u64::from(run.submission.context) && value & 0xc0 == 0 =>
            {
                self.context = value as u32;
                run.programmed |= 2;
            }
            Register::ContextMask
                if (value ^ self.context_mask) & !(1u64 << run.submission.context) == 0 =>
            {
                self.context_mask = value;
                run.programmed |= 4;
            }
            Register::LegacyMask if policy == Policy::G13X && value == self.context_mask => {
                self.legacy_mask = value;
                run.programmed |= 0x20;
            }
            Register::LegacySetup if policy == Policy::G13X && value == 0x100 => {
                self.legacy_setup = value;
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
        let mut targets = Vec::new();
        for register in registers {
            let (offset, width) = register.word(policy)?;
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
                .ok_or("GFX CL native target is not wholly inside an actual SGX bank")?;
            targets.push((physical, width));
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
        self.available()?;
        let (offset, width) = register.word(self.policy)?;
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
    fn read_native(&mut self, register: Register) -> Result<u64, &'static str> {
        self.owner.read(self.port, register)
    }
    fn write_native(&mut self, register: Register, value: u64) -> Result<(), &'static str> {
        self.owner.write(self.port, register, value)
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
                cache_status: bit(0x424),
                group: LockGroup {
                    page_size_shift: 14,
                    lower_limit: limit(0x680),
                    upper_limit: limit(0x684),
                    enable: bit(0x688),
                    write_disable: bit(0x7f0),
                    lock: bit(0x68c),
                },
                dram_base: RAM,
            },
            1,
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
            if (DATA..DATA + 0x4000).contains(&pa) {
                self.reads += 1;
            }
            self.ram.read(pa, out)
        }
        fn write(&mut self, pa: u64, data: &[u8]) -> bool {
            if (DATA..DATA + 0x4000).contains(&pa) {
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
        let mut memory = Ram::new(RAM, 0x14000);
        for context in [0, 5] {
            let [ttbr0, ttbr1] = uat::encode_gptbat(context, RAM + 0x4000, 0);
            memory.put_u64(RAM + u64::from(context) * 16, ttbr0);
            memory.put_u64(RAM + u64::from(context) * 16 + 8, ttbr1);
        }
        memory.put_u64(RAM + 0x4000, uat::encode_table(RAM + 0x8000));
        memory.put_u64(RAM + 0x8000, uat::encode_table(RAM + 0xc000));
        mapping(&mut memory, 0, DATA, false);
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
    fn program(owner: &FirmwareWork, sgx: &mut Sgx, memory: &mut TraceRam) {
        let mut words = alloc::vec![(Register::Control, 1), (Register::Context, (5 << 8) | 3)];
        if owner.policy == Policy::G13X {
            words.push((Register::LegacySetup, 0x100));
        }
        words.push((Register::ContextMask, 1 << 5));
        if owner.policy == Policy::G13X {
            words.push((Register::LegacyMask, 1 << 5));
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
            let mut program = Parameters::new(&input, &frame, LEASE, owner.policy).unwrap();
            mapping(&mut memory.ram, VA + 0x14000, SGX + 0x24000, true);
            assert_eq!(
                io(&mut sgx, &mut memory, |port| program
                    .advance(&mut owner.parameter_access(port))),
                Err("GFX CL PIO translation disagrees with its actual SGX bank")
            );
            assert_eq!(power.native.borrow().work.control, 1);
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
            // This parameter phase does not complete the original AP command.
            assert!(power.native.borrow().work.active());
        }
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
