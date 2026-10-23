// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Owned standalone AX200/AX210 ROM publication and polling RX-to-ALIVE.
//! Adapted from pcie/{ctxt-info.c,gen1_2/{trans-gen2.c,rx.c}} and mvm/ops.c.
//! ALIVE is firmware boot metadata, not NVM/calibration/PNVM/radio readiness.
use super::{
    calibration,
    context::{self, Ax200Context, Queues},
    context_v2::{self, Ax210Context},
    dma::{self, Chunk, MappedFirmware},
    firmware::{self, Family, Firmware},
    identity::{Profile, Staged},
    platform::{Observations, StepConfiguration},
    pnvm_dma::{self, MappedTable},
    power::{self, Csr, Power},
    receive::{self, Alive, FreeDescriptor, Imr, Lmac, Packets, Umac},
};
use crate::{
    Clock,
    bus::{
        dma::{
            mapping::{Direction, DmaDomain},
            memory::PageSource,
        },
        mmio::Mmio,
    },
    firmware as resources,
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    any::Any,
    ptr::NonNull,
    sync::atomic::{Ordering, fence},
};
mod ax200;
mod hcmd;
pub use ax200::{
    Ax200Mcc, Ax200MccError, Ax200MccPhase, Ax200ScanConfiguration, Ax200ScanConfigurationError,
    Ax200ScanConfigurationPhase, Ax200Setup, Ax200SetupError, Ax200SetupOptions, Ax200SetupPhase,
    SetupDecisions,
};
mod lari;
pub use lari::{LariError, LariPhase, LariRadio};
mod radio;
mod recycle;
mod rx;
pub use radio::{ColdRadio, ColdRadioPhase};
pub use recycle::Replenished;
pub use rx::{MpduProgress, NormalizedMpdu, ObservedMpdu, RejectedMpdu};
mod unified;
pub use hcmd::{CommandProgress, CommandResponse, CommandTicket, FirmwareNotification};
pub use unified::{InitializationPhase, InitializationProgress, InitializedNvm, UnifiedNvm};
const RECEIVE_BUFFER_BYTES: usize = 4096;

/// Declared platform integration mode, never inferred from an SB flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductResetPolicy {
    NoIwlmei,
    ManagedSap,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductResetCoordination {
    NotPerformedNoIwlmei,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductResetObservation {
    pub sb_configuration: u32,
    pub coordination: ProductResetCoordination,
}

/// Exclusive actual requester/BAR owner plus ordered CSR writes.
/// # Safety
/// Implementors retain the actual exclusive PCI function and uncached BAR
/// reservation through final Drop, excluding other firmware/OS/reset/IRQ users.
/// This is an owned reservation, never a borrowed token. Accesses must use the
/// actual device and complete ordered MMIO stores; errors may be uncertain.
/// Uncertain transport Drop deliberately retains this entire object.
pub unsafe trait BootIo: Csr + 'static {
    fn write8(&mut self, register: u32, value: u8) -> Result<(), power::AccessError>;
}
pub struct NativeBootIo {
    registers: Mmio,
    clock: Clock,
    _owner: Arc<dyn Any>,
}
impl NativeBootIo {
    /// # Safety
    /// `window` is the actual claimed AX200/AX210 function's aligned uncached BAR
    /// mapping covering all8192 bytes. `owner` retains that real exclusive PCI
    /// claim and BAR reservation, with all old DMA/IRQs stopped and drained and
    /// PCI interrupt routes disabled; no unrelated/dummy owner qualifies.
    /// The clock is calibrated and advancing. The window stays mapped through
    /// the owner's final Drop, including deliberate quarantine on failure.
    pub unsafe fn from_window(
        window: NonNull<[u8; 8192]>,
        owner: Arc<dyn Any>,
        clock: Clock,
    ) -> Result<Self, Error> {
        if clock.ticks_per_microsecond == 0 || !(window.as_ptr() as usize).is_multiple_of(4096) {
            return Err(Error::Access(power::AccessError::Mapping));
        }
        Ok(Self {
            // SAFETY: covered by this function's own safety contract.
            registers: unsafe { Mmio::new(window.as_ptr().cast::<u8>() as u64) },
            clock,
            _owner: owner,
        })
    }
}
impl Csr for NativeBootIo {
    fn read32(&mut self, register: u32) -> Result<u32, power::AccessError> {
        if !register.is_multiple_of(4) || register > 8188 {
            return Err(power::AccessError::Bounds);
        }
        Ok(self.registers.read32(register as usize))
    }
    fn write32(&mut self, register: u32, value: u32) -> Result<(), power::AccessError> {
        if !register.is_multiple_of(4) || register > 8188 {
            return Err(power::AccessError::Bounds);
        }
        self.registers.write32(register as usize, value);
        Ok(())
    }
    fn delay_us(&mut self, microseconds: u32) -> Result<(), power::AccessError> {
        self.clock.delay(u64::from(microseconds));
        Ok(())
    }
}
// SAFETY: construction requires the actual owned exclusive requester/BAR.
unsafe impl BootIo for NativeBootIo {
    fn write8(&mut self, register: u32, value: u8) -> Result<(), power::AccessError> {
        if register >= 8192 {
            return Err(power::AccessError::Bounds);
        }
        self.registers.write8(register as usize, value);
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Access(power::AccessError),
    Power(power::Error),
    Dma(dma::Error),
    Context(context::Error),
    ContextV2(context_v2::Error),
    Calibration(calibration::Error),
    PnvmDma(pnvm_dma::Error),
    PnvmNotification,
    Command(super::command::Error),
    CommandReclaim(dma::Error),
    CommandTicket,
    CommandPending,
    CommandSequence(u16),
    NotificationLimit,
    ReceiveEpoch,
    Nvm(super::nvm::Error),
    Radio(super::radio::Error),
    InitializationResponse { command: u8, group: u8 },
    ManagedSapUnsupported,
    Firmware(firmware::Error),
    Receive(receive::Error),
    Family,
    FirmwareBinding,
    PhyConfiguration,
    QueueSize,
    State,
    IdentityChanged,
    FailedRead { register: u32, value: u32 },
    Rejected { register: u32 },
    Timeout { register: u32 },
    RfKilled,
    DeviceError(u32),
    CompletionId(u16),
    CompletionCredit,
    Fragmented,
}
impl From<crate::bus::dma::mapping::DmaError> for Error {
    fn from(e: crate::bus::dma::mapping::DmaError) -> Self {
        Self::Dma(dma::Error::Dma(e))
    }
}
impl From<power::AccessError> for Error {
    fn from(e: power::AccessError) -> Self {
        Self::Access(e)
    }
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Power(e)
    }
}
impl From<dma::Error> for Error {
    fn from(e: dma::Error) -> Self {
        Self::Dma(e)
    }
}
impl From<context::Error> for Error {
    fn from(e: context::Error) -> Self {
        Self::Context(e)
    }
}
impl From<context_v2::Error> for Error {
    fn from(e: context_v2::Error) -> Self {
        Self::ContextV2(e)
    }
}
impl From<calibration::Error> for Error {
    fn from(value: calibration::Error) -> Self {
        Self::Calibration(value)
    }
}
impl From<pnvm_dma::Error> for Error {
    fn from(value: pnvm_dma::Error) -> Self {
        Self::PnvmDma(value)
    }
}
impl From<super::nvm::Error> for Error {
    fn from(value: super::nvm::Error) -> Self {
        Self::Nvm(value)
    }
}
impl From<super::radio::Error> for Error {
    fn from(value: super::radio::Error) -> Self {
        Self::Radio(value)
    }
}
impl From<super::command::Error> for Error {
    fn from(value: super::command::Error) -> Self {
        Self::Command(value)
    }
}
impl From<firmware::Error> for Error {
    fn from(e: firmware::Error) -> Self {
        Self::Firmware(e)
    }
}
impl From<receive::Error> for Error {
    fn from(e: receive::Error) -> Self {
        Self::Receive(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Prepared,
    Published,
    Restocked,
    Alive,
    PnvmWaiting,
    PnvmObserved,
    Poisoned,
    Quiescent,
    Stopped,
}
#[derive(Clone, Debug)]
pub struct AliveReport {
    pub notification_version: u8,
    pub flags: u16,
    pub lmac: [Lmac; 2],
    pub umac: Umac,
    pub sku: [u32; 3],
    pub imr: Imr,
    pub platform_id: Option<u64>,
    pub raw: Vec<u8>,
}
/// Raw notification status, deliberately not a radio/calibration success enum.
/// Linux's helper logs this word without defining a success-value contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PnvmNotification {
    pub status: u32,
    pub raw: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PnvmProgress {
    Skipped,
    Waiting,
    Observed,
}
struct PlatformPhase<'a> {
    receipts: calibration::Receipts<'a>,
    tables: Vec<MappedTable>,
    notification: Option<PnvmNotification>,
    released_tables: usize,
}
struct Buffer {
    allocation: Chunk,
    device_owned: bool,
}
/// One firmware/reset epoch, retaining actual CSR owner, native pins, CPU views
/// and isolated device DMA mappings. Polling mode never unmasks IRQ sources.
/// Dropping an active/uncertain epoch quarantines the actual BAR/requester too.
pub struct RomBoot<'a, Q: BootIo> {
    io: Option<Q>,
    profile: Profile,
    firmware: Firmware<'a>,
    image: resources::Image<'a>,
    images: MappedFirmware,
    images_stopped: bool,
    domain: Arc<dyn DmaDomain>,
    platform: Option<PlatformPhase<'a>>,
    alive_sku: Option<[u32; 3]>,
    sb_configuration: Option<u32>,
    product_reset_policy: Option<ProductResetPolicy>,
    context: Chunk,
    ax210: Option<Ax210Memory<'a>>,
    free: Chunk,
    used: Chunk,
    status: Chunk,
    command: Chunk,
    hcmd: hcmd::Queue,
    receive_ring: recycle::Ring,
    buffers: Vec<Buffer>,
    entries: u16,
    read: u16,
    credits: u16,
    state: State,
}
struct Ax210Memory<'a> {
    scratch: Chunk,
    info: Chunk,
    iml: Chunk,
    step: StepConfiguration<'a>,
}
/// Compatibility name for the original AX200 `start` constructor. New family
/// consumers can name `RomBoot` and choose its explicit family constructor.
pub type Ax200Boot<'a, Q> = RomBoot<'a, Q>;
impl<'a, Q: BootIo> RomBoot<'a, Q> {
    /// Start the standalone AX200 context protocol.
    /// # Safety
    /// PCI Memory Space is enabled and bus mastering has been enabled only
    /// after actual isolated domain attachment by the qualified platform owner.
    /// Source allocations are fresh/exclusive and domain is actually attached
    /// to this exact requester. Actual platform/requester WB DMA is coherent,
    /// PCIe NoSnoop, ATS and relaxed ordering are disabled, and aligned16/32-bit
    /// volatile completion observations plus acquire ordering see prior device
    /// payload writes. A WB attribute/compiler fence alone proves none of this.
    /// Qualification remains true through every quarantined lease. No IRQ route
    /// or competing submission/reset worker can run during this polling epoch.
    /// General production PCI/IOMMU/coherency attachment is not supplied here.
    pub unsafe fn start(
        power: Power<Q>,
        staged: Staged<'a>,
        source: &dyn PageSource,
        domain: Option<Arc<dyn DmaDomain>>,
        entries: u16,
    ) -> Result<Self, Error> {
        // SAFETY: the caller supplies the complete documented qualification.
        unsafe { Self::start_inner(power, staged, None, source, domain, entries, None) }
    }
    /// Start the distinct AX210 IML/context-v2 protocol, preserving the actual
    /// checked STEP resource receipt through this epoch. No absent default is
    /// manufactured; actual EFI_NOT_FOUND must have been recorded by its loader.
    /// # Safety
    /// The same requester/domain/coherency/exclusive polling obligations as
    /// `start` apply, for the actual standalone AX210 function. NoIwlmei is
    /// an explicit unmanaged platform mode: the caller retains genuine
    /// exclusive controller/reset ownership and no retained active SAP owner.
    /// It does not assert AMT is disabled or fabricate a PLDR acknowledgement.
    /// ManagedSap requires a real session/PLDR/END provider and is refused.
    pub unsafe fn start_ax210(
        power: Power<Q>,
        staged: Staged<'a>,
        step: StepConfiguration<'a>,
        source: &dyn PageSource,
        domain: Option<Arc<dyn DmaDomain>>,
        entries: u16,
        product_reset_policy: ProductResetPolicy,
    ) -> Result<Self, Error> {
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            Self::start_inner(
                power,
                staged,
                Some(step),
                source,
                domain,
                entries,
                Some(product_reset_policy),
            )
        }
    }
    unsafe fn start_inner(
        power: Power<Q>,
        staged: Staged<'a>,
        step: Option<StepConfiguration<'a>>,
        source: &dyn PageSource,
        domain: Option<Arc<dyn DmaDomain>>,
        entries: u16,
        product_reset_policy: Option<ProductResetPolicy>,
    ) -> Result<Self, Error> {
        let (io, profile, awake) = power.into_awake()?;
        let (firmware, image) = staged.into_parts();
        let request = profile.firmware_request();
        if image.name() != request.name || image.target() != request.requirement().target {
            return Err(Error::FirmwareBinding);
        }
        let family = profile.family();
        if (family == Family::Ax210) != step.is_some() {
            return Err(Error::Family);
        }
        if product_reset_policy == Some(ProductResetPolicy::ManagedSap) {
            return Err(Error::ManagedSapUnsupported);
        }
        if awake.rf_killed {
            return Err(Error::RfKilled);
        }
        let maximum = if family == Family::Ax210 { 1024 } else { 2048 };
        if !(16..=maximum).contains(&entries) || !entries.is_power_of_two() {
            return Err(Error::QueueSize);
        }
        firmware.require_family(family)?;
        if firmware.phy_sku().is_none() {
            return Err(Error::PhyConfiguration);
        }
        if firmware
            .command_version(0, 1)
            .is_none_or(|v| !matches!(v.notification_version, 6..=8))
        {
            return Err(Error::Receive(receive::Error::AliveVersion(
                firmware
                    .command_version(0, 1)
                    .map(|v| v.notification_version),
            )));
        }
        if family == Family::Ax210 {
            let iml = firmware
                .iml()
                .ok_or(firmware::Error::Missing("AX210 IML"))?;
            if iml.len() > 32768 {
                return Err(Error::Dma(dma::Error::PayloadSize));
            }
        }
        let domain = domain.ok_or(Error::Dma(dma::Error::Dma(
            crate::bus::dma::mapping::DmaError::IommuUnavailable,
        )))?;
        let plan = firmware.self_load_plan()?;
        // SAFETY: covered by this function's own safety contract.
        let images = unsafe { MappedFirmware::prepare(&plan, source, Some(domain.clone()))? };
        let allocate = |bytes: usize, direction| {
            Chunk::allocate(source, domain.clone(), &alloc::vec![0;bytes], direction)
        };
        let (free_stride, used_stride, status_bytes, command_entries) = match family {
            Family::Ax200 => (8, 4, 12, 32),
            Family::Ax210 => (16, 32, 2, 128),
        };
        let free = allocate(usize::from(entries) * free_stride, Direction::Bidirectional)?;
        let used = allocate(usize::from(entries) * used_stride, Direction::Bidirectional)?;
        let status = allocate(status_bytes, Direction::Bidirectional)?;
        let command = allocate(command_entries * 256, Direction::Bidirectional)?;
        // SAFETY: covered by this function's own safety contract.
        let hcmd = unsafe { hcmd::Queue::prepare(&command, &profile, source, domain.clone())? };
        let mut buffers = Vec::new();
        for _ in 0..entries - 1 {
            buffers.push(Buffer {
                allocation: allocate(RECEIVE_BUFFER_BYTES, Direction::FromDevice)?,
                device_owned: false,
            });
        }
        let (context, ax210) = if let Some(step) = step {
            let context = allocate(context_v2::CONTEXT_BYTES, Direction::Bidirectional)?;
            let scratch = allocate(context_v2::SCRATCH_BYTES, Direction::Bidirectional)?;
            let info = allocate(context_v2::INFO_BYTES, Direction::Bidirectional)?;
            // Keep donor dma_alloc_coherent permissions; IML remains pinned
            // until actual current-epoch ALIVE or acknowledged device stop.
            let iml = Chunk::allocate(
                source,
                domain.clone(),
                firmware.iml().unwrap(),
                Direction::Bidirectional,
            )?;
            let encoded = Ax210Context::encode(
                &profile,
                &firmware,
                context_v2::Queues {
                    free: free.region(),
                    used: used.region(),
                    status: status.region(),
                    command: command.region(),
                    receive_entries: entries,
                },
                images.prepared_regions()?,
                context_v2::Memory {
                    info: info.region(),
                    scratch: scratch.region(),
                    context: context.region(),
                    iml: iml.region(),
                },
                &step,
            )?;
            // SAFETY: every allocation remains exclusively CPU owned before
            // the first context pointer publication below.
            unsafe {
                context.write_owned(0, encoded.context())?;
                scratch.write_owned(0, encoded.scratch())?;
            }
            (
                context,
                Some(Ax210Memory {
                    scratch,
                    info,
                    iml,
                    step,
                }),
            )
        } else {
            let encoded = Ax200Context::encode(
                &profile,
                &plan,
                Queues {
                    free: free.region(),
                    used: used.region(),
                    status: status.region(),
                    command: command.region(),
                    receive_entries: entries,
                },
                images.prepared_regions()?,
            )?;
            (
                Chunk::allocate(
                    source,
                    domain.clone(),
                    encoded.bytes(),
                    Direction::Bidirectional,
                )?,
                None,
            )
        };
        let mut boot = Self {
            io: Some(io),
            profile,
            firmware,
            image,
            images,
            images_stopped: false,
            domain,
            platform: None,
            alive_sku: None,
            sb_configuration: None,
            product_reset_policy,
            context,
            ax210,
            free,
            used,
            status,
            command,
            hcmd,
            receive_ring: recycle::Ring::new(entries),
            buffers,
            entries,
            read: 0,
            credits: 0,
            state: State::Prepared,
        };
        boot.publish()?;
        Ok(boot)
    }
    /// Exact canonical image identity, integrity and provenance retained across
    /// publication/completion; no parsed-input or diagnostic-image substitution.
    pub fn firmware_source(&self) -> resources::Image<'a> {
        self.image
    }
    pub fn product_reset_observation(&self) -> Option<ProductResetObservation> {
        self.sb_configuration
            .map(|sb_configuration| ProductResetObservation {
                sb_configuration,
                coordination: ProductResetCoordination::NotPerformedNoIwlmei,
            })
    }
    /// Actual observed STEP receipt used by AX210 scratch, retained without
    /// copying its original resource bytes. AX200 has no context-v2 input.
    pub fn step_configuration(&self) -> Option<&StepConfiguration<'a>> {
        self.ax210.as_ref().map(|memory| &memory.step)
    }
    fn io(&mut self) -> &mut Q {
        self.io.as_mut().expect("retained owner")
    }
    fn read_register(&mut self, register: u32) -> Result<u32, Error> {
        let value = self.io().read32(register)?;
        if value == u32::MAX || matches!(value & !0xf, 0xa5a5a5a0 | 0x5a5a5a50) {
            return Err(Error::FailedRead { register, value });
        }
        Ok(value)
    }
    fn write(&mut self, register: u32, value: u32) -> Result<(), Error> {
        self.io().write32(register, value)?;
        Ok(())
    }
    fn set(&mut self, register: u32, value: u32) -> Result<(), Error> {
        let old = self.read_register(register)?;
        self.write(register, old | value)
    }
    fn poll_register(
        &mut self,
        register: u32,
        mask: u32,
        value: u32,
        microseconds: u32,
    ) -> Result<(), Error> {
        for _ in 0..microseconds.div_ceil(10) {
            if self.read_register(register)? & mask == value {
                return Ok(());
            }
            self.io().delay_us(10)?;
        }
        Err(Error::Timeout { register })
    }
    fn prph_write(&mut self, address: u32, value: u32) -> Result<(), Error> {
        self.set(0x24, 8)?;
        self.io().delay_us(2)?;
        self.poll_register(0x24, 0x11, 1, 15000)?;
        let mask = if self.profile.family() == Family::Ax210 {
            0xffffff
        } else {
            0xfffff
        };
        self.write(0x444, (address & mask) | (3 << 24))?;
        self.write(0x44c, value)?;
        let gp = self.read_register(0x24)?;
        self.write(0x24, gp & !8)
    }
    fn prph_read(&mut self, address: u32) -> Result<u32, Error> {
        self.set(0x24, 8)?;
        self.io().delay_us(2)?;
        self.poll_register(0x24, 0x11, 1, 15000)?;
        let mask = if self.profile.family() == Family::Ax210 {
            0xffffff
        } else {
            0xfffff
        };
        self.write(0x440, (address & mask) | (3 << 24))?;
        let value = self.read_register(0x448)?;
        let gp = self.read_register(0x24)?;
        self.write(0x24, gp & !8)?;
        Ok(value)
    }
    fn publish(&mut self) -> Result<(), Error> {
        let observed = self.profile.observed();
        if self.read_register(0x28)? != observed.hardware_revision
            || self.read_register(0x9c)? != observed.radio_id
        {
            return Err(Error::IdentityChanged);
        }
        if self.read_register(0x24)? & 0x08000000 == 0 {
            return Err(Error::RfKilled);
        }
        // CONFIG_IWLMEI-disabled Linux performs no PLDR coordination. Retain
        // the actual SB value even when0x80, under this explicit unmanaged
        // ownership mode. Never infer mode or a fictional ACK from that flag.
        if self.profile.family() == Family::Ax210 {
            if self.product_reset_policy != Some(ProductResetPolicy::NoIwlmei) {
                return Err(Error::ManagedSapUnsupported);
            }
            self.sb_configuration = Some(self.prph_read(0xa03088 + 0x300000)?);
        }
        self.write(12, 0)?;
        if self.read_register(12)? != 0 {
            return Err(Error::Rejected { register: 12 });
        }
        self.write(0x5c, 2)?;
        self.write(0x5c, 4)?;
        self.write(8, u32::MAX)?;
        // iwl_mvm_nic_config returns immediately on AX210: CSR0 becomes the
        // context-v2 boot control, never the old PHY configuration fields.
        if self.profile.family() == Family::Ax200 {
            let phy = self.firmware.phy_sku().ok_or(Error::PhyConfiguration)?;
            let config = (observed.hardware_revision & 0xf)
                | ((phy & 3) << 10)
                | (((phy >> 2) & 3) << 14)
                | (((phy >> 4) & 3) << 12);
            let hw = self.read_register(0)?;
            self.write(0, (hw & !0xff0f) | config)?;
            if self.read_register(0)? & 0xff0f != config {
                return Err(Error::Rejected { register: 0 });
            }
        }
        self.io().write8(4, 0x40)?;
        self.set(0xa8, 0x800fffff)?;
        // Retain the complete guard before the FIRST context pointer write;
        // even its low half/error can be an uncertain DMA publication.
        self.images.expose_for_context()?;
        self.context.expose();
        self.free.expose();
        self.used.expose();
        self.status.expose();
        self.command.expose();
        self.hcmd.expose();
        if let Some(memory) = self.ax210.as_mut() {
            memory.scratch.expose();
            memory.info.expose();
            memory.iml.expose();
        }
        self.state = State::Published;
        fence(Ordering::Release);
        let address = self.context.region().address;
        let register = if self.profile.family() == Family::Ax210 {
            0x118
        } else {
            0x40
        };
        self.write(register, address as u32)?;
        self.write(register + 4, (address >> 32) as u32)?;
        if let Some(memory) = &self.ax210 {
            let iml = memory.iml.region();
            self.write(0x120, iml.address as u32)?;
            self.write(0x124, (iml.address >> 32) as u32)?;
            self.write(0x128, iml.bytes as u32)?;
            self.set(0, 2)?; // CSR_AUTO_FUNC_BOOT_ENA
        }
        self.write(0xd4, 0x88fa88fa)?;
        let offset = if self.profile.family() == Family::Ax210 {
            0x300000
        } else {
            0
        };
        self.prph_write(0xa05c44 + offset, 1)
    }
    fn restock(&mut self) -> Result<(), Error> {
        for (index, buffer) in self.buffers.iter_mut().enumerate() {
            let descriptor = receive::free_descriptor(
                self.profile.family(),
                buffer.allocation.region().address,
                index as u16 + 1,
            )?;
            let descriptor = match &descriptor {
                FreeDescriptor::Ax200(bytes) => bytes.as_slice(),
                FreeDescriptor::Ax210(bytes) => bytes.as_slice(),
            };
            buffer.allocation.expose();
            // SAFETY: the initial free descriptors are still CPU-owned; ROM
            // configured RFH, but no free-ring producer doorbell has advanced.
            unsafe {
                self.free
                    .write_owned(index * descriptor.len(), descriptor)?;
            }
        }
        let published = (self.entries - 1) & !7;
        // Mark exact eligible payloads before the potentially uncertain store.
        for buffer in &mut self.buffers[..usize::from(published)] {
            buffer.device_owned = true;
        }
        self.credits = published;
        self.receive_ring.initial(self.entries, published);
        self.state = State::Restocked;
        fence(Ordering::Release);
        self.write(0x1c80, u32::from(published))
    }
    fn completed_buffer(&mut self) -> Result<Option<Vec<u8>>, Error> {
        // SAFETY: start qualified shared coherent producer polling, retained
        // pins/domain/CPU view, aligned width; this is NOT streaming sync_cpu.
        let family = self.profile.family();
        let mask = if family == Family::Ax200 {
            0xfff
        } else {
            u16::MAX
        };
        // SAFETY: the status page is pinned, coherent and device-written; this reads a
        // complete aligned u16 without claiming CPU ownership.
        let closed = unsafe { self.status.read16_coherent(0)? } & mask & (self.entries - 1);
        fence(Ordering::Acquire);
        let count = closed.wrapping_sub(self.read) & (self.entries - 1);
        if count > self.credits {
            return Err(Error::CompletionCredit);
        }
        if self.read == closed {
            return Ok(None);
        }
        let stride = if family == Family::Ax200 { 4 } else { 32 };
        let mut descriptor = [0; 32];
        for offset in (0..stride).step_by(4) {
            descriptor[offset..offset + 4].copy_from_slice(
                // SAFETY: the used ring is pinned and coherent, and `closed` says the device
                // finished writing this entry.
                &unsafe {
                    self.used
                        .read32_coherent(usize::from(self.read) * stride + offset)?
                }
                .to_le_bytes(),
            );
        }
        let used = receive::used_descriptor(family, &descriptor[..stride])?;
        if used.fragmented {
            return Err(Error::Fragmented);
        }
        let buffer = self
            .buffers
            .get_mut(usize::from(used.id - 1))
            .ok_or(Error::CompletionId(used.id))?;
        if !buffer.device_owned {
            return Err(Error::CompletionId(used.id));
        }
        buffer.device_owned = false;
        self.credits -= 1;
        self.read = (self.read + 1) & (self.entries - 1);
        // SAFETY: the actual closed producer and unique submitted VID
        // transfer this complete RB to CPU ownership. Explicit rearm is only
        // allowed after this visibility/copy completes successfully.
        let bytes = unsafe { buffer.allocation.snapshot_completed()? };
        self.receive_ring.complete(used.id)?;
        Ok(Some(bytes))
    }
    fn receive(&mut self) -> Result<Option<AliveReport>, Error> {
        let family = self.profile.family();
        while let Some(bytes) = self.completed_buffer()? {
            let mut observed = None;
            for packet in Packets::new(family, 0, &bytes)? {
                let packet = packet?;
                if packet.command != 1 || packet.group != 0 {
                    self.hcmd.retain_notification(&packet)?;
                    continue;
                }
                if observed.is_some() {
                    return Err(Error::State);
                }
                let alive = Alive::decode(&packet, &self.firmware)?;
                let report = AliveReport {
                    notification_version: alive.notification_version,
                    flags: alive.flags,
                    lmac: alive.lmac,
                    umac: alive.umac,
                    sku: alive.sku,
                    imr: alive.imr,
                    platform_id: alive.platform_id,
                    raw: alive.raw().to_vec(),
                };
                // SAFETY: actual valid ALIVE was decoded only from completed
                // DMA in this exclusively retained context/firmware/reset epoch.
                unsafe {
                    self.images.release_after_alive()?;
                    if let Some(memory) = self.ax210.as_mut() {
                        memory.iml.release()?;
                    } else {
                        self.context.release()?;
                    }
                }
                self.alive_sku = Some(report.sku);
                self.state = State::Alive;
                observed = Some(report);
            }
            if observed.is_some() {
                return Ok(observed);
            }
        }
        Ok(None)
    }
    /// Derive conditional resource requirements only from this transport's
    /// actual completed ALIVE; caller-mutated report metadata cannot choose
    /// another board/default. Acquisition/upload/status remain a later phase.
    pub fn post_alive_plan(&self) -> Result<super::platform::PostAlivePlan, Error> {
        if !matches!(
            self.state,
            State::Alive | State::PnvmWaiting | State::PnvmObserved
        ) {
            return Err(Error::State);
        }
        Ok(super::platform::post_alive_plan(
            &self.profile,
            self.alive_sku.ok_or(Error::State)?,
        ))
    }
    /// Acquire exactly the current ALIVE SKU's canonical resources, prepare
    /// DMA, then publish scratch and the source PNVM doorbell once. Actual
    /// missing/failed observations remain visible in the retained receipts.
    /// # Safety
    /// Source returns fresh exclusive native RAM under the same actual domain
    /// and coherent requester qualification as start. Observations are the
    /// actual pre-EBS GetVariable results, retained in protected canonical
    /// handoff storage; no invented/default observation qualifies.
    pub unsafe fn begin_pnvm(
        &mut self,
        provider: &'a dyn resources::Provider,
        observations: Observations,
        source: &dyn PageSource,
    ) -> Result<PnvmProgress, Error> {
        if self.state != State::Alive {
            return Err(Error::State);
        }
        let sku = self.alive_sku.ok_or(Error::State)?;
        let prepared = calibration::prepare(&self.profile, sku, observations, provider)?;
        if sku == [0; 3] {
            self.platform = Some(PlatformPhase {
                receipts: prepared.receipts,
                tables: Vec::new(),
                notification: None,
                released_tables: 0,
            });
            self.state = State::PnvmObserved;
            return Ok(PnvmProgress::Skipped);
        }
        if self
            .firmware
            .command_version(0xc, 0xfe)
            .is_none_or(|v| v.notification_version != 1)
        {
            return Err(Error::PnvmNotification);
        }
        let mut tables = Vec::new();
        let mut fields = Vec::new();
        if self.profile.family() == Family::Ax210 {
            for (offset, chunks) in [(16, &prepared.pnvm), (60, &prepared.reduced_power)] {
                if chunks.is_empty() {
                    continue;
                }
                // SAFETY: covered by this function's own safety contract.
                let table = unsafe {
                    MappedTable::prepare(
                        chunks,
                        self.firmware.supports_capability(32),
                        source,
                        Some(self.domain.clone()),
                    )?
                };
                fields.push(offset);
                tables.push(table);
            }
        }
        // Retain the whole real requester and every table before even the
        // first possibly visible scratch field store (not just the doorbell).
        self.platform = Some(PlatformPhase {
            receipts: prepared.receipts,
            tables,
            notification: None,
            released_tables: 0,
        });
        self.state = State::PnvmWaiting;
        let result = (|| {
            let platform = self.platform.as_mut().unwrap();
            let mut configurations = Vec::new();
            for table in &mut platform.tables {
                configurations.push(table.expose_for_scratch()?);
            }
            if let Some(memory) = &self.ax210 {
                for (offset, config) in fields.into_iter().zip(configurations) {
                    let mut field = [0; 16];
                    field[..8].copy_from_slice(&config.address.to_le_bytes());
                    field[8..12].copy_from_slice(&config.bytes.to_le_bytes());
                    // SAFETY: These PNVM/reduced fields are host-owned until this
                    // protocol's doorbell; other scratch ranges remain live.
                    unsafe {
                        memory.scratch.write_owned(offset, &field)?;
                    }
                }
            }
            fence(Ordering::Release);
            let offset = if self.profile.family() == Family::Ax210 {
                0x300000
            } else {
                0
            };
            self.prph_write(0xa05c04 + offset, 1 << 20)?;
            Ok(PnvmProgress::Waiting)
        })();
        if result.is_err() {
            self.state = State::Poisoned;
        }
        result
    }
    pub fn platform_receipts(&self) -> Option<&calibration::Receipts<'a>> {
        self.platform.as_ref().map(|p| &p.receipts)
    }
    pub fn pnvm_notification(&self) -> Option<&PnvmNotification> {
        self.platform.as_ref().and_then(|p| p.notification.as_ref())
    }
    /// Observe only the actual retained-epoch group0xc/op0xfe/version1 packet.
    /// A timeout/requested cancel is never a completion or DMA release proof.
    pub fn poll_pnvm(&mut self) -> Result<PnvmProgress, Error> {
        if self.state != State::PnvmWaiting {
            return Err(Error::State);
        }
        let result = self.poll_pnvm_inner();
        if result.is_err() {
            self.state = State::Poisoned;
        }
        result
    }
    fn poll_pnvm_inner(&mut self) -> Result<PnvmProgress, Error> {
        let causes = self.read_register(8)?;
        self.write(8, causes | !(1 | (1 << 31)))?;
        if causes & ((1 << 29) | (1 << 25)) != 0 {
            return Err(Error::DeviceError(causes));
        }
        if self.read_register(0x24)? & 0x08000000 == 0 {
            return Err(Error::RfKilled);
        }
        while let Some(bytes) = self.completed_buffer()? {
            let mut observed = false;
            for packet in Packets::new(self.profile.family(), 0, &bytes)? {
                let packet = packet?;
                if packet.command != 0xfe || packet.group != 0xc {
                    self.hcmd.retain_notification(&packet)?;
                    continue;
                }
                if observed {
                    return Err(Error::PnvmNotification);
                }
                let raw = packet.payload();
                if raw.len() < 4 {
                    return Err(Error::PnvmNotification);
                }
                let notification = PnvmNotification {
                    status: u32::from_le_bytes(raw[..4].try_into().unwrap()),
                    raw: raw.to_vec(),
                };
                self.platform.as_mut().ok_or(Error::State)?.notification = Some(notification);
                self.state = State::PnvmObserved;
                observed = true;
            }
            if observed {
                return Ok(PnvmProgress::Observed);
            }
        }
        Ok(PnvmProgress::Waiting)
    }
    /// Poll actual CSR causes and DMA producer state once in process context.
    /// CSR_ALIVE only allows restocking; only completed RX ALIVE returns data.
    pub fn poll(&mut self) -> Result<Option<AliveReport>, Error> {
        if !matches!(self.state, State::Published | State::Restocked) {
            return Err(Error::State);
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.state = State::Poisoned;
        }
        result
    }
    fn poll_inner(&mut self) -> Result<Option<AliveReport>, Error> {
        let causes = self.read_register(8)?;
        self.write(8, causes | !(1 | (1 << 31)))?;
        if causes & ((1 << 29) | (1 << 25)) != 0 {
            return Err(Error::DeviceError(causes));
        }
        if self.read_register(0x24)? & 0x08000000 == 0 {
            return Err(Error::RfKilled);
        }
        if self.state == State::Published && causes & 1 != 0 {
            self.restock()?;
        }
        if self.state == State::Restocked {
            self.receive()
        } else {
            Ok(None)
        }
    }
    /// Actual source bus-master stop acknowledgement plus reset, followed by
    /// invalidations. Failed acknowledgements never free device-visible pages;
    /// failed invalidations remain retryable with the exact owner retained.
    pub fn stop(&mut self) -> Result<(), Error> {
        if self.state == State::Stopped {
            return Err(Error::State);
        }
        if self.state != State::Quiescent {
            self.state = State::Poisoned;
            self.write(12, 0)?;
            if self.read_register(12)? != 0 {
                return Err(Error::Rejected { register: 12 });
            }
            self.set(0x20, 0x200)?;
            self.poll_register(0x20, 0x100, 0x100, 100)?;
            self.set(0x20, 0x80)?;
            self.io().delay_us(5000)?;
            let gp = self.read_register(0x24)?;
            self.write(0x24, gp & !4)?;
            self.state = State::Quiescent;
        }
        // SAFETY: IRQs were never enabled, the exclusive polling owner has no
        // queued workers and actual master-disable/reset acknowledged all DMA.
        unsafe {
            if !self.images_stopped {
                self.images.release_after_stop()?;
                self.images_stopped = true;
            }
            self.context.release()?;
            if let Some(memory) = self.ax210.as_mut() {
                memory.iml.release()?;
                memory.scratch.release()?;
                memory.info.release()?;
            }
            self.free.release()?;
            self.used.release()?;
            self.status.release()?;
            self.command.release()?;
            self.hcmd.release_after_stop()?;
            if let Some(platform) = self.platform.as_mut() {
                while platform.released_tables < platform.tables.len() {
                    platform.tables[platform.released_tables].release_after_stop()?;
                    platform.released_tables += 1;
                }
            }
            for buffer in &mut self.buffers {
                buffer.allocation.release()?;
            }
        }
        self.state = State::Stopped;
        Ok(())
    }
}
impl<Q: BootIo> Drop for RomBoot<'_, Q> {
    fn drop(&mut self) {
        if !matches!(self.state, State::Prepared | State::Stopped)
            && let Some(owner) = self.io.take()
        {
            core::mem::forget(owner);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{
        dma::tests::{Domain, Records, Source},
        identity::Observed,
        power::ManagementSession,
    };
    use super::*;
    use alloc::collections::BTreeMap;
    use core::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Read(u32),
        Write(u32, u32),
        Write8(u32, u8),
        Delay(u32),
    }
    struct Owner(Arc<AtomicUsize>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct Model {
        state: Arc<Mutex<ModelState>>,
        _owner: Owner,
    }
    struct ModelState {
        registers: BTreeMap<u32, u32>,
        ops: Vec<Op>,
        fail: Option<usize>,
        fail_read: Option<u32>,
        all_ff: bool,
        stop_ack: bool,
        sentinel: Option<(usize, u32)>,
    }
    impl Default for ModelState {
        fn default() -> Self {
            Self {
                registers: BTreeMap::from([(0x28, 0x340), (0x9c, 0x10a000), (0x24, 0x08000001)]),
                ops: Vec::new(),
                fail: None,
                fail_read: None,
                all_ff: false,
                stop_ack: true,
                sentinel: None,
            }
        }
    }
    impl Model {
        fn operation(
            &mut self,
            op: Op,
        ) -> Result<std::sync::MutexGuard<'_, ModelState>, power::AccessError> {
            let mut state = self.state.lock().unwrap();
            let index = state.ops.len();
            state.ops.push(op);
            if state.fail == Some(index) {
                return Err(power::AccessError::Unavailable);
            }
            Ok(state)
        }
    }
    impl Csr for Model {
        fn read32(&mut self, register: u32) -> Result<u32, power::AccessError> {
            let state = self.operation(Op::Read(register))?;
            if state.fail_read == Some(register) {
                return Err(power::AccessError::Unavailable);
            }
            if state.all_ff {
                return Ok(u32::MAX);
            }
            let value = if let Some((at, value)) = state.sentinel
                && at == state.ops.len() - 1
            {
                value
            } else {
                state.registers.get(&register).copied().unwrap_or(0)
            };
            Ok(
                if register == 0x20 && value & 0x200 != 0 && state.stop_ack {
                    value | 0x100
                } else {
                    value
                },
            )
        }
        fn write32(&mut self, register: u32, value: u32) -> Result<(), power::AccessError> {
            let mut state = self.operation(Op::Write(register, value))?;
            if register == 8 || register == 16 {
                let prior = state.registers.entry(register).or_default();
                *prior &= !value;
            } else {
                state.registers.insert(register, value);
            }
            Ok(())
        }
        fn delay_us(&mut self, microseconds: u32) -> Result<(), power::AccessError> {
            drop(self.operation(Op::Delay(microseconds))?);
            Ok(())
        }
    }
    // SAFETY: real owned synchronous CSR/requester model; no alternate accesses
    // occur except explicit serialized device events through its shared state.
    unsafe impl BootIo for Model {
        fn write8(&mut self, register: u32, value: u8) -> Result<(), power::AccessError> {
            let mut state = self.operation(Op::Write8(register, value))?;
            let word = state.registers.entry(register & !3).or_default();
            let shift = (register & 3) * 8;
            *word = (*word & !(0xff << shift)) | (u32::from(value) << shift);
            Ok(())
        }
    }
    fn profile() -> Profile {
        Profile::select(Observed {
            vendor: 0x8086,
            device: 0x2723,
            subsystem_vendor: 0x8086,
            subsystem_device: 0x84,
            pci_revision: 0x1a,
            hardware_revision: 0x340,
            radio_id: 0x10a000,
        })
        .unwrap()
    }
    fn awake(state: Arc<Mutex<ModelState>>, drops: Arc<AtomicUsize>) -> Power<Model> {
        awake_profile(state, drops, profile())
    }
    fn awake_profile(
        state: Arc<Mutex<ModelState>>,
        drops: Arc<AtomicUsize>,
        profile: Profile,
    ) -> Power<Model> {
        let mut power = Power::new(
            Model {
                state: state.clone(),
                _owner: Owner(drops),
            },
            profile,
        );
        power.wake(ManagementSession::NotConnected).unwrap();
        state.lock().unwrap().ops.clear();
        power
    }
    fn firmware_bytes() -> Vec<u8> {
        let mut bytes = vec![0; 88];
        bytes[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
        bytes[72..76].copy_from_slice(&(77u32 << 8).to_le_bytes());
        let mut tlv = |kind: u32, data: &[u8]| {
            bytes.extend(kind.to_le_bytes());
            bytes.extend((data.len() as u32).to_le_bytes());
            bytes.extend(data);
            while !bytes.len().is_multiple_of(4) {
                bytes.push(0);
            }
        };
        tlv(27, &2u32.to_le_bytes());
        tlv(32, &4096u32.to_le_bytes());
        tlv(48, &[1, 0, 99, 6, 0xfe, 0xc, 99, 1]);
        tlv(23, &0x2du32.to_le_bytes());
        for (offset, n, seed) in [
            (0u32, 16, 1u8),
            (0xffffcccc, 0, 0),
            (0x1000, 16, 2),
            (0xaaaabbbb, 0, 0),
            (0, 16, 3),
            (0x2000, 4096, 4),
        ] {
            let mut data = offset.to_le_bytes().to_vec();
            data.extend((0..n).map(|n| seed.wrapping_add(n as u8)));
            tlv(19, &data);
        }
        bytes
    }
    fn catalog_for(profile: &Profile, name: &str, bytes: &[u8]) -> resources::Catalog {
        let request = profile.firmware_request();
        catalog_for_target(request.requirement().target, name, bytes)
    }
    fn catalog_for_target(
        target: resources::Target<'_>,
        name: &str,
        bytes: &[u8],
    ) -> resources::Catalog {
        use sha2::{Digest, Sha256};
        resources::Catalog::from_handoff(vec![resources::Resource {
            name,
            target,
            provenance: resources::Provenance {
                source: "test",
                revision: "immutable",
                member: name,
                license: "LicenseRef-Local-Test-Fixture",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(bytes).into(),
            bytes: bytes.to_vec(),
        }])
        .unwrap()
    }
    fn start<'a>(
        catalog: &'a resources::Catalog,
        source: &Source,
        domain: &Arc<Domain>,
        state: &Arc<Mutex<ModelState>>,
        drops: &Arc<AtomicUsize>,
    ) -> Ax200Boot<'a, Model> {
        // SAFETY: fixture owns fresh actual host RAM and a synchronous isolated
        // coherent domain/device; no IRQ, competing worker or real DMA exists.
        unsafe {
            Ax200Boot::start(
                awake(state.clone(), drops.clone()),
                super::super::identity::stage(&profile(), catalog).unwrap(),
                source,
                Some(domain.clone()),
                32,
            )
            .unwrap()
        }
    }
    fn id(address: u64) -> u64 {
        (address - 0x100000) / 0x10000
    }
    fn phase_catalog(
        profile: &Profile,
        sku: [u32; 3],
        bios: bool,
        reduced: bool,
    ) -> (Observations, resources::Catalog) {
        use super::super::platform::{CapturedVariable, Observation, Stage, Variable};
        use sha2::{Digest, Sha256};
        fn tlv(bytes: &mut Vec<u8>, kind: u32, data: &[u8]) {
            bytes.extend(kind.to_le_bytes());
            bytes.extend((data.len() as u32).to_le_bytes());
            bytes.extend(data);
            bytes.resize(bytes.len().next_multiple_of(4), 0);
        }
        let mut pnvm = Vec::new();
        let sku_bytes: Vec<_> = sku.into_iter().flat_map(u32::to_le_bytes).collect();
        tlv(&mut pnvm, 64, &sku_bytes);
        let observed = profile.observed();
        let mut hw = Vec::new();
        hw.extend((((observed.hardware_revision & 0xfff0) >> 4) as u16).to_le_bytes());
        hw.extend((((observed.radio_id & 0xfff000) >> 12) as u16).to_le_bytes());
        tlv(&mut pnvm, 58, &hw);
        tlv(&mut pnvm, 62, &0x12345678u32.to_le_bytes());
        for n in 0..2 {
            let mut chunk = (0x1234u32 + n).to_le_bytes().to_vec();
            chunk.extend(vec![0x40 + n as u8; 16 + n as usize]);
            tlv(&mut pnvm, 19, &chunk);
        }
        let mut power = Vec::new();
        tlv(&mut power, 64, &sku_bytes);
        for n in 0..2 {
            let mut chunk = (0xf0000000u32 + n).to_le_bytes().to_vec();
            chunk.extend((12u32 + n).to_le_bytes());
            chunk.extend(vec![0x60 + n as u8; 12 + n as usize]);
            tlv(&mut power, 7, &chunk);
        }
        let mut ppackage = vec![0; 14];
        ppackage.extend(&pnvm);
        let mut rpackage = vec![0; 14];
        rpackage.extend(power);
        let mut pc = CapturedVariable::from_variable(Variable::OemPnvm, ppackage, 7, None).unwrap();
        let mut rc =
            CapturedVariable::from_variable(Variable::ReducedPower, rpackage, 7, None).unwrap();
        let absent = Observation::from_error(Stage::Probe, (1 << 63) | 14, None);
        let observations = Observations {
            oem_pnvm: if bios { pc.observation() } else { absent },
            reduced_power: if reduced { rc.observation() } else { absent },
            step: Observation::NotCaptured,
            ..Observations::default()
        };
        let mut resources = Vec::new();
        if bios {
            resources.push(pc.take_resource().unwrap());
        }
        if reduced {
            resources.push(rc.take_resource().unwrap());
        }
        let request = profile.pnvm_request();
        if let Some(ref request) = request {
            resources.push(resources::Resource {
                name: request.name,
                target: request.requirement().target,
                provenance: resources::Provenance {
                    source: "test",
                    revision: "immutable",
                    member: request.name,
                    license: "LicenseRef-Local-Test-Fixture",
                },
                expected_length: pnvm.len(),
                expected_sha256: Sha256::digest(&pnvm).into(),
                bytes: pnvm,
            });
        }
        (
            observations,
            resources::Catalog::from_handoff(resources).unwrap(),
        )
    }
    fn command_ready<'a>(
        mut boot: RomBoot<'a, Model>,
        empty: &'a resources::Catalog,
        source: &Source,
        domain: &Domain,
        state: &Arc<Mutex<ModelState>>,
    ) -> RomBoot<'a, Model> {
        event(state, 1);
        boot.poll().unwrap();
        let mut packet = rx_packet(1, 0xcafe, 0);
        set_sku(&mut packet, [0; 3]);
        complete(&boot, domain, 0, 1, &packet);
        boot.poll().unwrap().unwrap();
        assert!(matches!(
            unsafe { boot.begin_pnvm(empty, Observations::default(), source) }.unwrap(),
            PnvmProgress::Skipped
        ));
        boot
    }
    fn command_packet(id: super::super::command::Id, sequence: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        bytes[..4].copy_from_slice(&(4u32 + payload.len() as u32).to_le_bytes());
        bytes[4] = id.opcode;
        bytes[5] = id.group;
        bytes[6..8].copy_from_slice(&sequence.to_le_bytes());
        bytes[8..8 + payload.len()].copy_from_slice(payload);
        let next = (8 + payload.len()).next_multiple_of(64);
        bytes[next..next + 4].copy_from_slice(&0x55550000u32.to_le_bytes());
        bytes
    }
    fn command_id() -> super::super::command::Id {
        super::super::command::Id {
            group: 2,
            opcode: 3,
            version: 1,
        }
    }
    #[test]
    fn hcmd_real_tfd_writeback_and_rx_completion_own_payload_lifetime() {
        use super::super::command::{Command, Tfd};
        let bytes = ax210_bytes();
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let (observation, step_catalog) = step_fixture();
        let step = super::super::platform::load_step(observation, &step_catalog).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start_ax210(&catalog, step, &source, &domain, &state, &drops);
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        let ring = boot.command.region().address;
        let sentinel = device_read(&domain, ring, 0, 256);
        assert_eq!(u16::from_le_bytes(sentinel[..2].try_into().unwrap()), 1);
        let invalid = u64::from_le_bytes(sentinel[4..12].try_into().unwrap());
        assert_eq!(
            device_read(&domain, invalid, 0, 8),
            [6, 15, 255, 255, 0, 0, 0, 0]
        );
        for slot in 0..128 {
            assert_eq!(device_read(&domain, ring, slot * 256, 256), sentinel);
        }
        let payload: Vec<_> = (0..100u8).collect();
        let ticket = unsafe { boot.submit_command(command_id(), &payload, &source) }.unwrap();
        let pending_live = domain.records.lock().unwrap().live.len();
        assert!(matches!(
            unsafe { boot.submit_command(command_id(), &payload, &source) },
            Err(Error::CommandPending)
        ));
        assert_eq!(domain.records.lock().unwrap().live.len(), pending_live);
        let wire = device_read(&domain, ring, 0, 256);
        assert_eq!(u16::from_le_bytes(wire[..2].try_into().unwrap()), 2);
        let first = u64::from_le_bytes(wire[4..12].try_into().unwrap());
        let rest = u64::from_le_bytes(wire[14..22].try_into().unwrap());
        let cmd = Command::encode(command_id(), 0, 0, &payload).unwrap();
        assert_eq!(
            wire,
            Tfd::encode(&[
                super::super::context::Region {
                    address: first,
                    bytes: 20
                },
                super::super::context::Region {
                    address: rest,
                    bytes: 88
                },
            ])
            .unwrap()
            .bytes()
        );
        assert_eq!(device_read(&domain, first, 0, 20), cmd.first_tb());
        assert_eq!(device_read(&domain, rest, 0, 88), cmd.remainder());
        assert_eq!(state.lock().unwrap().registers.get(&0x460), Some(&1));
        device_write(&domain, first, 12, &[0xa5; 8], false);
        assert_eq!(
            boot.poll_command(&ticket).unwrap(),
            CommandProgress::Pending
        );
        assert_eq!(domain.records.lock().unwrap().live.len(), pending_live);
        complete(
            &boot,
            &domain,
            1,
            2,
            &command_packet(command_id(), ticket.sequence(), &[0xde, 0xad, 0, 0]),
        );
        let response = match boot.poll_command(&ticket).unwrap() {
            CommandProgress::Completed(r) => r,
            _ => panic!("not complete"),
        };
        assert_eq!(response.ticket, ticket);
        assert_eq!(response.raw, [0xde, 0xad, 0, 0]);
        assert_eq!(response.request, command_id());
        assert_eq!(device_read(&domain, ring, 0, 256), sentinel);
        assert_eq!(domain.records.lock().unwrap().live.len(), pending_live - 1);
        assert!(matches!(
            boot.poll_command(&ticket),
            Err(Error::CommandTicket)
        ));
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
    #[test]
    fn hcmd_source_no_reclaim_and_all_notifications_in_completed_rb_are_preserved() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        let raw = command_packet(command_id(), 0x1234, &[]);
        let mut forged = Packets::new(Family::Ax200, 0, &raw)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        forged.command = 0x1c;
        forged.group = 0;
        forged.sequence = 0x8000;
        let before = state.lock().unwrap().ops.len();
        assert_eq!(
            boot.hcmd.retain_notification(&forged),
            Err(Error::CommandSequence(0x1234))
        );
        assert!(boot.take_firmware_notification().is_none());
        assert_eq!(state.lock().unwrap().ops.len(), before);
        let ticket = unsafe { boot.submit_command(command_id(), &[0; 40], &source) }.unwrap();
        for (index, id, sequence) in [
            (1, command_id(), 0x8000),
            (
                2,
                super::super::command::Id {
                    group: 0,
                    opcode: 0x1c,
                    version: 0,
                },
                0,
            ),
        ] {
            complete(
                &boot,
                &domain,
                index,
                index + 1,
                &command_packet(id, sequence, &[1, 2]),
            );
            assert_eq!(
                boot.poll_command(&ticket).unwrap(),
                CommandProgress::Pending
            );
            let notification = boot.take_firmware_notification().unwrap();
            assert_eq!(notification.command, id.opcode);
        }
        let mut packet = command_packet(command_id(), ticket.sequence(), &[0xff]);
        let notification_id = super::super::command::Id {
            group: 0,
            opcode: 4,
            version: 0,
        };
        let second = command_packet(notification_id, 0x8000, &[0x42]);
        packet[64..128].copy_from_slice(&second[..64]);
        packet[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
        complete(&boot, &domain, 3, 4, &packet);
        assert!(matches!(
            boot.poll_command(&ticket).unwrap(),
            CommandProgress::Completed(_)
        ));
        assert_eq!(boot.take_firmware_notification().unwrap().raw, [0x42]);
        assert!(boot.take_firmware_notification().is_none());
        boot.stop().unwrap();
    }
    #[test]
    fn hcmd_completion_reclaim_retries_without_releasing_or_resubmitting() {
        for failure in 0..4 {
            let bytes = firmware_bytes();
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = start(&catalog, &source, &domain, &state, &drops);
            let mut boot = command_ready(boot, &empty, &source, &domain, &state);
            let ticket =
                unsafe { boot.submit_command(command_id(), &[0xa5; 40], &source) }.unwrap();
            let live = domain.records.lock().unwrap().live.len();
            complete(
                &boot,
                &domain,
                1,
                2,
                &command_packet(command_id(), ticket.sequence(), &[0x7f]),
            );
            {
                let mut r = domain.records.lock().unwrap();
                if failure == 0 {
                    r.sync_fail = Some(r.syncs);
                } else if failure == 1 {
                    r.unmap_fail = Some(r.unmaps);
                } else {
                    r.cpu_sync_fail = Some(r.cpu_syncs + failure - 1);
                }
            }
            assert!(matches!(
                boot.poll_command(&ticket),
                Err(Error::CommandReclaim(_))
            ));
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert!(matches!(
                unsafe { boot.submit_command(command_id(), &[], &source) },
                Err(Error::CommandPending)
            ));
            {
                let mut r = domain.records.lock().unwrap();
                r.sync_fail = None;
                r.unmap_fail = None;
                r.cpu_sync_fail = None;
            }
            assert!(
                matches!(boot.poll_command(&ticket).unwrap(),CommandProgress::Completed(CommandResponse{raw,..}) if raw==[0x7f])
            );
            assert_eq!(domain.records.lock().unwrap().live.len(), live - 1);
            boot.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
    #[test]
    fn hcmd_wrong_duplicate_and_foreign_completions_do_not_grant_reclaim() {
        for sequence in [0x100, 1, 0x4000, 0] {
            let bytes = firmware_bytes();
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = start(&catalog, &source, &domain, &state, &drops);
            let mut boot = command_ready(boot, &empty, &source, &domain, &state);
            let ticket = unsafe { boot.submit_command(command_id(), &[0; 40], &source) }.unwrap();
            let live = domain.records.lock().unwrap().live.len();
            let mut packet = command_packet(command_id(), sequence, &[1]);
            if sequence == 0 {
                let dup = packet.clone();
                packet[64..128].copy_from_slice(&dup[..64]);
                packet[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
            }
            complete(&boot, &domain, 1, 2, &packet);
            assert!(matches!(
                boot.poll_command(&ticket),
                Err(Error::CommandSequence(_))
            ));
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            assert!(matches!(
                boot.poll_command(&ticket),
                Err(Error::CommandTicket)
            ));
            boot.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let mut first = command_ready(boot, &empty, &source, &domain, &state);
        let ticket = unsafe { first.submit_command(command_id(), &[], &source) }.unwrap();
        let other_source = Source::default();
        let other_domain = Arc::new(Domain::default());
        let other_state = Arc::new(Mutex::new(ModelState::default()));
        let other_drops = Arc::new(AtomicUsize::new(0));
        let boot = start(
            &catalog,
            &other_source,
            &other_domain,
            &other_state,
            &other_drops,
        );
        let mut other = command_ready(boot, &empty, &other_source, &other_domain, &other_state);
        let other_ticket =
            unsafe { other.submit_command(command_id(), &[], &other_source) }.unwrap();
        assert_eq!(ticket.sequence(), other_ticket.sequence());
        assert_ne!(ticket, other_ticket);
        let before = other_state.lock().unwrap().ops.len();
        assert!(matches!(
            other.poll_command(&ticket),
            Err(Error::CommandTicket)
        ));
        assert_eq!(other_state.lock().unwrap().ops.len(), before);
        first.stop().unwrap();
        other.stop().unwrap();
    }
    #[test]
    fn hcmd_publication_faults_retain_real_owner_and_all_exposed_dma() {
        // Alloc/map/initial visibility/TB0 visibility precede descriptor
        // publication; descriptor visibility or producer failure is uncertain.
        for failure in 0..6 {
            let bytes = firmware_bytes();
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let mut source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = start(&catalog, &source, &domain, &state, &drops);
            let mut boot = command_ready(boot, &empty, &source, &domain, &state);
            let live = domain.records.lock().unwrap().live.len();
            if failure == 0 {
                source.fail_at = Some(source.calls.load(Ordering::Relaxed));
            }
            if failure == 1 {
                let mut r = domain.records.lock().unwrap();
                r.map_fail = Some(r.maps);
            }
            if (2..=4).contains(&failure) {
                let mut r = domain.records.lock().unwrap();
                r.sync_fail = Some(r.syncs + failure - 2);
            }
            if failure == 5 {
                let mut s = state.lock().unwrap();
                s.fail = Some(s.ops.len() + 1);
            }
            assert!(unsafe { boot.submit_command(command_id(), &[0; 40], &source) }.is_err());
            assert_eq!(
                domain.records.lock().unwrap().live.len(),
                live + usize::from(failure >= 4)
            );
            if failure >= 4 {
                assert_eq!(boot.state, State::Poisoned);
                state.lock().unwrap().stop_ack = false;
                assert!(boot.stop().is_err());
                drop(boot);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
                assert_eq!(domain.records.lock().unwrap().live.len(), live + 1);
            } else {
                assert_eq!(boot.state, State::PnvmObserved);
                state.lock().unwrap().fail = None;
                boot.stop().unwrap();
                assert!(domain.records.lock().unwrap().live.is_empty());
            }
        }
    }
    #[test]
    fn hcmd_ring_and_sequence_wrap_match_each_family_without_reusing_live_slots() {
        for ax210 in [false, true] {
            let p = if ax210 { ax210_profile() } else { profile() };
            let bytes = if ax210 {
                ax210_bytes()
            } else {
                firmware_bytes()
            };
            let catalog = catalog_for(&p, p.family().firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let (observation, step_catalog) = step_fixture();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = if ax210 {
                ax210_state()
            } else {
                Arc::new(Mutex::new(ModelState::default()))
            };
            let drops = Arc::new(AtomicUsize::new(0));
            let staged = super::super::identity::stage(&p, &catalog).unwrap();
            let awake = awake_profile(state.clone(), drops.clone(), p);
            let boot = if ax210 {
                unsafe {
                    RomBoot::start_ax210(
                        awake,
                        staged,
                        super::super::platform::load_step(observation, &step_catalog).unwrap(),
                        &source,
                        Some(domain.clone()),
                        256,
                        ProductResetPolicy::NoIwlmei,
                    )
                }
            } else {
                unsafe { RomBoot::start(awake, staged, &source, Some(domain.clone()), 512) }
            }
            .unwrap();
            let mut boot = command_ready(boot, &empty, &source, &domain, &state);
            let ring = boot.command.region().address;
            let sentinel = device_read(&domain, ring, 0, 256);
            let count = if ax210 { 132u16 } else { 260u16 };
            let slots = if ax210 { 128u16 } else { 32u16 };
            for n in 0..count {
                let ticket =
                    unsafe { boot.submit_command(command_id(), &[n as u8], &source) }.unwrap();
                assert_eq!(ticket.sequence(), n & 255);
                let wire = device_read(&domain, ring, usize::from(n & (slots - 1)) * 256, 256);
                let first = u64::from_le_bytes(wire[4..12].try_into().unwrap());
                let hdr = device_read(&domain, first, 0, 9);
                assert_eq!(u16::from_le_bytes(hdr[2..4].try_into().unwrap()), n & 255);
                assert_eq!(hdr[8], n as u8);
                assert_eq!(
                    state.lock().unwrap().registers.get(&0x460),
                    Some(&u32::from(if ax210 { n + 1 } else { (n + 1) & 255 }))
                );
                complete(
                    &boot,
                    &domain,
                    n + 1,
                    n + 2,
                    &command_packet(command_id(), ticket.sequence(), &[]),
                );
                assert!(matches!(
                    boot.poll_command(&ticket).unwrap(),
                    CommandProgress::Completed(_)
                ));
                assert_eq!(
                    device_read(&domain, ring, usize::from(n & (slots - 1)) * 256, 256),
                    sentinel
                );
            }
            boot.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
    #[test]
    fn hcmd_exhausted_boot_rx_credit_refuses_publication() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        // All posted credits are consumed by real completed RX notifications,
        // not by an invented successful repost in this boot-only receiver.
        let ticket = unsafe { boot.submit_command(command_id(), &[], &source) }.unwrap();
        for index in 1..24 {
            let seq = if index == 23 {
                ticket.sequence()
            } else {
                0x8000
            };
            complete(
                &boot,
                &domain,
                index,
                index + 1,
                &command_packet(command_id(), seq, &[]),
            );
            let result = boot.poll_command(&ticket).unwrap();
            assert_eq!(matches!(result, CommandProgress::Completed(_)), index == 23);
        }
        let ops = state.lock().unwrap().ops.len();
        let maps = domain.records.lock().unwrap().maps;
        assert!(matches!(
            unsafe { boot.submit_command(command_id(), &[0; 40], &source) },
            Err(Error::CompletionCredit)
        ));
        assert_eq!(state.lock().unwrap().ops.len(), ops);
        assert_eq!(domain.records.lock().unwrap().maps, maps);
        boot.stop().unwrap();
    }
    fn radio_bytes(ax210: bool) -> Vec<u8> {
        let mut bytes = unified_bytes(ax210);
        let mut at = 88;
        while at < bytes.len() {
            let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
            if kind == 23 {
                let word =
                    u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) | (3 << 16);
                bytes[at + 8..at + 12].copy_from_slice(&word.to_le_bytes());
            }
            at += 8 + len.next_multiple_of(4);
        }
        let versions = [
            0xd1,
            1,
            3,
            0,
            0x98,
            1,
            1,
            0,
            0x9b,
            1,
            6,
            0,
            1,
            2,
            2,
            0,
            0xc1,
            0,
            99,
            if ax210 { 5 } else { 4 },
            0x1c,
            1,
            if ax210 { 10 } else { 9 },
            7,
            0xf7,
            5,
            99,
            3,
        ];
        let mut at = 88;
        while at < bytes.len() {
            let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
            if kind == 48 {
                bytes.splice(at + 8 + len..at + 8 + len, versions);
                bytes[at + 4..at + 8]
                    .copy_from_slice(&((len + versions.len()) as u32).to_le_bytes());
                break;
            }
            at += 8 + len.next_multiple_of(4);
        }
        bytes.extend(30u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend((1u32 << 5).to_le_bytes());
        if ax210 {
            bytes.extend(29u32.to_le_bytes());
            bytes.extend(8u32.to_le_bytes());
            bytes.extend(2u32.to_le_bytes());
            bytes.extend((1u32 << 4).to_le_bytes());
        }
        bytes
    }
    fn drive_nvm<'a>(
        boot: RomBoot<'a, Model>,
        source: &Source,
        domain: &Domain,
        state: &Arc<Mutex<ModelState>>,
    ) -> UnifiedNvm<'a, Model> {
        use super::super::nvm::Request;
        state
            .lock()
            .unwrap()
            .registers
            .extend([(0x388, 0x02123456), (0x38c, 0x789a)]);
        let init = boot.initialize_on_device_nvm();
        let before = state.lock().unwrap().ops.len();
        let mut init = match init.begin_radio() {
            Err(owner) => *owner,
            Ok(_) => panic!("uninitialized owner admitted"),
        };
        assert_eq!(state.lock().unwrap().ops.len(), before);
        unsafe { init.advance(source) }.unwrap();
        complete(
            &init.boot,
            domain,
            1,
            2,
            &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
        );
        unsafe { init.advance(source) }.unwrap();
        complete(
            &init.boot,
            domain,
            2,
            3,
            &command_packet(Request::AccessComplete.id(), 1, &[]),
        );
        unsafe { init.advance(source) }.unwrap();
        complete(
            &init.boot,
            domain,
            3,
            4,
            &command_packet(
                super::super::command::Id {
                    group: 0,
                    opcode: 4,
                    version: 0,
                },
                0x8000,
                &[0x76],
            ),
        );
        unsafe { init.advance(source) }.unwrap();
        complete(
            &init.boot,
            domain,
            4,
            5,
            &command_packet(Request::GetInformation.id(), 2, &nvm_response()),
        );
        assert_eq!(
            unsafe { init.advance(source) }.unwrap(),
            InitializationProgress::Observed
        );
        init
    }
    #[test]
    fn cold_radio_real_prefix_retains_nvm_epoch_and_actual_command_completions() {
        exercise_cold_radio(false);
    }
    #[test]
    #[ignore = "requires actual pinned Intel firmware images"]
    fn cold_radio_actual_images_run_source_prefix_with_distinct_offload_and_latencies() {
        exercise_cold_radio(true);
    }
    fn exercise_cold_radio(actual: bool) {
        use super::super::radio::InitialPlan;
        for ax210 in [false, true] {
            let profile = if ax210 { ax210_profile() } else { profile() };
            let bytes = if actual {
                let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
                std::fs::read(std::path::Path::new(&root).join(profile.family().firmware_name()))
                    .unwrap()
            } else {
                radio_bytes(ax210)
            };
            let catalog = catalog_for(&profile, profile.family().firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let (observation, step_catalog) = step_fixture();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = if ax210 {
                ax210_state()
            } else {
                Arc::new(Mutex::new(ModelState::default()))
            };
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = if ax210 {
                start_ax210(
                    &catalog,
                    super::super::platform::load_step(observation, &step_catalog).unwrap(),
                    &source,
                    &domain,
                    &state,
                    &drops,
                )
            } else {
                start(&catalog, &source, &domain, &state, &drops)
            };
            let boot = command_ready(boot, &empty, &source, &domain, &state);
            let init = drive_nvm(boot, &source, &domain, &state);
            let expected = InitialPlan::prepare(
                &init.boot.firmware,
                profile.family(),
                &init.receipt().unwrap().information,
            )
            .unwrap();
            let mut copied = init.receipt().unwrap().clone();
            copied.information.tx_chains = 0xff;
            copied.address.bytes = [0; 6];
            let mut radio = init
                .begin_radio()
                .unwrap_or_else(|_| panic!("genuine NVM refused"));
            let before = state.lock().unwrap().ops.len();
            assert!(matches!(radio.poll_mpdu_observation(), Err(Error::State)));
            assert_eq!(state.lock().unwrap().ops.len(), before);
            assert_eq!(radio.initialized_nvm().information.tx_chains, 3);
            assert_ne!(radio.initialized_nvm().address.bytes, copied.address.bytes);
            assert_eq!(
                unsafe { radio.advance(&source) }.unwrap(),
                ColdRadioPhase::Waiting(expected.commands()[0].stage())
            );
            for (i, command) in expected.commands().iter().enumerate() {
                let sequence = 3 + i as u16;
                let boot = &radio.initialized.boot;
                let wire = device_read(
                    &domain,
                    boot.command.region().address,
                    usize::from(sequence) * 256,
                    256,
                );
                let first = u64::from_le_bytes(wire[4..12].try_into().unwrap());
                let encoded = super::super::command::Command::encode(
                    command.id(),
                    0,
                    sequence,
                    command.bytes(),
                )
                .unwrap();
                let mut emitted = device_read(&domain, first, 0, encoded.bytes().len().min(20));
                if encoded.bytes().len() > 20 {
                    let rest = u64::from_le_bytes(wire[14..22].try_into().unwrap());
                    emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
                }
                assert_eq!(emitted, encoded.bytes());
                let doorbell = state.lock().unwrap().registers[&0x460];
                assert_eq!(
                    unsafe { radio.advance(&source) }.unwrap(),
                    ColdRadioPhase::Waiting(command.stage())
                );
                assert_eq!(state.lock().unwrap().registers[&0x460], doorbell);
                let mut response_id = command.id();
                if response_id.group == 0 {
                    response_id.group = 1;
                }
                complete(
                    &radio.initialized.boot,
                    &domain,
                    5 + i as u16,
                    6 + i as u16,
                    &command_packet(response_id, sequence, &[0xa0 + i as u8]),
                );
                if i == 0 {
                    let mut r = domain.records.lock().unwrap();
                    r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                    drop(r);
                    assert!(matches!(
                        unsafe { radio.advance(&source) },
                        Err(Error::CommandReclaim(_))
                    ));
                    assert_eq!(radio.phase(), ColdRadioPhase::Waiting(command.stage()));
                    assert_eq!(state.lock().unwrap().registers[&0x460], doorbell);
                    domain.records.lock().unwrap().cpu_sync_fail = None;
                }
                let phase = unsafe { radio.advance(&source) }.unwrap();
                assert_eq!(
                    phase,
                    expected
                        .commands()
                        .get(i + 1)
                        .map_or(ColdRadioPhase::PlatformConfigurationRequired, |next| {
                            ColdRadioPhase::Waiting(next.stage())
                        })
                );
                assert_eq!(radio.prefix_responses().len(), i + 1);
                assert_eq!(radio.prefix_responses()[i].raw, [0xa0 + i as u8]);
            }
            let ops = state.lock().unwrap().ops.len();
            let allocations = source.calls.load(Ordering::Relaxed);
            assert_eq!(
                unsafe { radio.advance(&source) }.unwrap(),
                ColdRadioPhase::PlatformConfigurationRequired
            );
            assert_eq!(state.lock().unwrap().ops.len(), ops);
            assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
            exercise_mpdu_observations(&mut radio, &source, &domain, &state);
            radio.stop().unwrap();
            drop(radio);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    fn exercise_mpdu_observations(
        radio: &mut ColdRadio<'_, Model>,
        source: &Source,
        domain: &Arc<Domain>,
        state: &Arc<Mutex<ModelState>>,
    ) {
        use super::super::command::Id;
        let ax210 = radio.initialized.boot.profile.family() == Family::Ax210;
        radio.replenish_completed_receive().unwrap();
        let allocations = source.calls.load(Ordering::Relaxed);
        let maps = domain.records.lock().unwrap().maps;
        let mut preserved = None;
        let mut normalized_preserved = None;
        let wire_frame = |cycle: u8| {
            let mut bytes: Vec<_> = (0..45u8).map(|n| n.wrapping_add(cycle)).collect();
            bytes[..2].copy_from_slice(&0x4208u16.to_le_bytes());
            bytes[22..24].copy_from_slice(&(u16::from(cycle) << 4).to_le_bytes());
            bytes[24..32].copy_from_slice(&[cycle + 1, 0, 0, 0x60, 0, 0, 0, 0]);
            bytes
        };
        let complete_payload = |radio: &ColdRadio<'_, Model>, payload: &[u8]| {
            let boot = &radio.initialized.boot;
            let slot = boot.read;
            let stride = if ax210 { 16 } else { 8 };
            let free = device_read(
                domain,
                boot.free.region().address,
                usize::from(slot) * stride,
                stride,
            );
            let vid = if ax210 {
                u16::from_le_bytes(free[..2].try_into().unwrap())
            } else {
                (u64::from_le_bytes(free.try_into().unwrap()) & 0xfff) as u16
            };
            let mut packet = command_packet(
                Id {
                    group: 0,
                    opcode: 0xc1,
                    version: 0,
                },
                0x8000,
                payload,
            );
            let flags = u32::from_le_bytes(packet[..4].try_into().unwrap()) | (1 << 26);
            packet[..4].copy_from_slice(&flags.to_le_bytes());
            complete_from_free_slot(boot, domain, slot, vid, slot, &packet);
        };
        for cycle in 0..40u8 {
            let size = if ax210 { 64 } else { 48 };
            let mut payload = vec![0; size + 45];
            payload[..2].copy_from_slice(&45u16.to_le_bytes());
            payload[2] = 4 << 4; // 8 source-reported MIC/CRC bytes
            payload[3] = 0x20; // 2-byte pad after MAC + retained IV
            payload[7] = 1 << 6; // actual explicit band code 1 = 2.4 GHz
            payload[12..16].copy_from_slice(&0x0500026fu32.to_le_bytes());
            payload[16..20].copy_from_slice(&(127u32 << 24).to_le_bytes());
            let (rate, energy) = if ax210 { (36, 40) } else { (28, 32) };
            payload[rate..rate + 4].copy_from_slice(&(3u32 << 14).to_le_bytes());
            payload[energy..energy + 3].copy_from_slice(&[44, 56, 6]);
            payload[size..].copy_from_slice(&wire_frame(cycle));
            complete_payload(radio, &payload);
            let received = match radio.poll_mpdu_observation().unwrap() {
                MpduProgress::Observed(received) => received,
                _ => panic!("missing actual completed MPDU"),
            };
            assert_eq!(received.raw_mpdu(), &payload[size..]);
            assert_eq!(received.descriptor(), &payload[..size]);
            assert!(received.trailing().is_empty());
            assert_eq!(received.packet_flags() & (1 << 26), 1 << 26);
            assert_eq!(received.receive_queue(), 0);
            assert_eq!(received.metadata().status.station_id(), Some(5));
            assert_eq!(received.metadata().status.cipher_code(), 2);
            assert!(received.metadata().status.mic_ok_bit());
            assert!(!received.metadata().status.decrypted_bit());
            let normalized = received.normalize().unwrap();
            let mut expected = wire_frame(cycle)[..32].to_vec();
            expected.extend(&wire_frame(cycle)[34..37]);
            assert_eq!(normalized.frame().bytes(), expected);
            assert_eq!(normalized.frame().radio.frequency_mhz, 2437);
            assert_eq!(normalized.frame().security.key, None);
            assert_eq!(
                normalized.frame().security.integrity,
                crate::net::wifi::security::Integrity::Unknown
            );
            assert_eq!(
                normalized.frame().security.pn.unwrap().value(),
                u64::from(cycle) + 1
            );
            assert_eq!(normalized.key_index(), Some(1));
            assert!(normalized.crypto().decrypted);
            if cycle == 0 {
                preserved = Some(received);
                normalized_preserved = Some(normalized);
            }
            assert!(matches!(
                radio.poll_mpdu_observation().unwrap(),
                MpduProgress::Pending
            ));
            assert_eq!(radio.replenish_completed_receive().unwrap().returned, 1);
        }
        assert_eq!(preserved.unwrap().raw_mpdu(), wire_frame(0));
        let normalized = normalized_preserved.unwrap();
        let mut expected = wire_frame(0)[..32].to_vec();
        expected.extend(&wire_frame(0)[34..37]);
        assert_eq!(normalized.frame().bytes(), expected);
        assert_eq!(normalized.frame().security.pn.unwrap().value(), 1);
        // A malformed actual descriptor is retained as a rejection, never
        // retagged as a frame or allowed to poison the control/RX owner.
        let size = if ax210 { 64 } else { 48 };
        let mut bad = vec![0; size];
        bad[..2].copy_from_slice(&1u16.to_le_bytes());
        complete_payload(radio, &bad);
        let rejected = match radio.poll_mpdu_observation().unwrap() {
            MpduProgress::Rejected(r) => r,
            _ => panic!("malformed frame was not rejected"),
        };
        assert_eq!(
            rejected.error(),
            super::super::receive::mpdu::Error::MpduLength {
                declared: 1,
                available: 0
            }
        );
        assert_eq!(&rejected.raw_packet()[8..], bad);
        assert_eq!(radio.initialized.boot.state, State::PnvmObserved);
        radio.replenish_completed_receive().unwrap();
        // Queue-capacity fixture: canonical packet capture, not forged
        // public diagnostic restoration. One-RB reservation is family-specific.
        let count = if ax210 { 128 } else { 65 };
        for n in 0..count {
            let raw = command_packet(
                Id {
                    group: 2,
                    opcode: 0xe0,
                    version: 0,
                },
                0x8000,
                &[n as u8],
            );
            let packet = Packets::new(radio.initialized.boot.profile.family(), 0, &raw)
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
            radio
                .initialized
                .boot
                .hcmd
                .retain_notification(&packet)
                .unwrap();
        }
        let before = state.lock().unwrap().ops.len();
        let credits = radio.initialized.boot.credits;
        for _ in 0..3 {
            assert!(
                matches!(radio.poll_mpdu_observation().unwrap(),MpduProgress::Backpressure {notifications} if notifications==count)
            );
        }
        assert_eq!(state.lock().unwrap().ops.len(), before);
        assert_eq!(radio.initialized.boot.credits, credits);
        let mut notice = radio.take_firmware_notification().unwrap();
        assert_eq!(notice.raw, [0]);
        notice.command = 0xc1;
        notice.raw = vec![0; 64];
        assert!(matches!(
            radio.poll_mpdu_observation().unwrap(),
            MpduProgress::Pending
        ));
        for n in 1..count {
            let notification = radio.take_firmware_notification().unwrap();
            assert_eq!(
                (
                    notification.command,
                    notification.group,
                    notification.sequence
                ),
                (0xe0, 2, 0x8000)
            );
            assert_eq!(notification.raw, [n as u8]);
        }
        let foreign = hcmd::CapturedNotification {
            epoch: Arc::new(()),
            bytes: rejected.raw_packet().to_vec(),
        };
        assert!(matches!(
            radio.initialized.boot.decode_captured_mpdu(foreign),
            Err(Error::ReceiveEpoch)
        ));
        assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
        assert_eq!(domain.records.lock().unwrap().maps, maps);
        // Actual failed CPU handoff cannot issue an MPDU receipt or release
        // mappings. Actual bus-master/reset stop below still owns teardown.
        complete_payload(radio, &vec![0; size]);
        let live = domain.records.lock().unwrap().live.len();
        {
            let mut r = domain.records.lock().unwrap();
            r.cpu_sync_fail = Some(r.cpu_syncs);
        }
        assert!(matches!(radio.poll_mpdu_observation(), Err(Error::Dma(_))));
        assert_eq!(radio.initialized.boot.state, State::Poisoned);
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        domain.records.lock().unwrap().cpu_sync_fail = None;
        let before = state.lock().unwrap().ops.len();
        assert!(matches!(radio.poll_mpdu_observation(), Err(Error::State)));
        assert_eq!(state.lock().unwrap().ops.len(), before);
    }
    #[test]
    fn cold_radio_preflight_rfkill_wrong_response_and_uncertain_publication_fail_closed() {
        for case in 0..5 {
            let mut bytes = radio_bytes(false);
            if case == 0 {
                let mut at = 88;
                while at < bytes.len() {
                    let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                    let len =
                        u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
                    if kind == 48 {
                        for row in bytes[at + 8..at + 8 + len].as_chunks_mut::<4>().0 {
                            if row[..2] == [0xd1, 1] {
                                row[2] = 99;
                            }
                        }
                        break;
                    }
                    at += 8 + len.next_multiple_of(4);
                }
            }
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = start(&catalog, &source, &domain, &state, &drops);
            let boot = command_ready(boot, &empty, &source, &domain, &state);
            let init = drive_nvm(boot, &source, &domain, &state);
            let mut radio = init
                .begin_radio()
                .unwrap_or_else(|_| panic!("actual NVM rejected"));
            let before_ops = state.lock().unwrap().ops.len();
            let before_allocations = source.calls.load(Ordering::Relaxed);
            match case {
                1 => {
                    *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
                }
                3 => {
                    state.lock().unwrap().fail = Some(before_ops + 1);
                }
                4 => {
                    let mut r = domain.records.lock().unwrap();
                    r.map_fail = Some(r.maps);
                }
                _ => (),
            }
            let result = unsafe { radio.advance(&source) };
            match case {
                0 => {
                    assert_eq!(
                        result,
                        Err(Error::Radio(super::super::radio::Error::Version {
                            stage: super::super::radio::Stage::SmartFifo,
                            declared: 99
                        }))
                    );
                    assert_eq!(state.lock().unwrap().ops.len(), before_ops);
                    assert_eq!(source.calls.load(Ordering::Relaxed), before_allocations);
                }
                1 => assert_eq!(result, Err(Error::RfKilled)),
                2 => {
                    assert!(result.is_ok());
                    complete(
                        &radio.initialized.boot,
                        &domain,
                        5,
                        6,
                        &command_packet(
                            super::super::command::Id {
                                group: 2,
                                opcode: 0xfd,
                                version: 0,
                            },
                            3,
                            &[],
                        ),
                    );
                    assert_eq!(
                        unsafe { radio.advance(&source) },
                        Err(Error::InitializationResponse {
                            group: 2,
                            command: 0xfd
                        })
                    );
                    assert_eq!(state.lock().unwrap().registers[&0x460], 4);
                }
                3 => assert_eq!(result, Err(Error::Access(power::AccessError::Unavailable))),
                4 => assert!(matches!(result, Err(Error::Dma(_)))),
                _ => unreachable!(),
            }
            assert_eq!(radio.phase(), ColdRadioPhase::Failed);
            assert!(radio.prefix_responses().is_empty());
            let ops = state.lock().unwrap().ops.len();
            assert_eq!(unsafe { radio.advance(&source) }, Err(Error::State));
            assert_eq!(state.lock().unwrap().ops.len(), ops);
            if case == 3 {
                {
                    let mut s = state.lock().unwrap();
                    s.fail = None;
                    s.stop_ack = false;
                }
                assert!(radio.stop().is_err());
                let retained = domain.records.lock().unwrap().live.len();
                assert!(retained > 0);
                drop(radio);
                assert_eq!(domain.records.lock().unwrap().live.len(), retained);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
            } else {
                radio.stop().unwrap();
                drop(radio);
                assert!(domain.records.lock().unwrap().live.is_empty());
                assert_eq!(drops.load(Ordering::Relaxed), 1);
            }
        }
    }
    fn unified_bytes(ax210: bool) -> Vec<u8> {
        let mut b = if ax210 {
            ax210_bytes()
        } else {
            firmware_bytes()
        };
        let mut at = 88;
        loop {
            let kind = u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(b[at + 4..at + 8].try_into().unwrap()) as usize;
            if kind == 48 {
                b.splice(at + 8 + len..at + 8 + len, [2, 12, 1, 4]);
                b[at + 4..at + 8].copy_from_slice(&((len + 4) as u32).to_le_bytes());
                break;
            }
            at += 8 + len.next_multiple_of(4);
        }
        b.extend(29u32.to_le_bytes());
        b.extend(8u32.to_le_bytes());
        b.extend(1u32.to_le_bytes());
        b.extend((1u32 << 16).to_le_bytes());
        b
    }
    fn nvm_response() -> Vec<u8> {
        let mut b = vec![0; 468];
        for (at, word) in [
            (0, 1u32),
            (8, 0x8000001f),
            (12, 3),
            (16, 3),
            (20, 1),
            (24, 2),
            (28, 0x12345678),
            (32, 0xabcdef),
        ] {
            b[at..at + 4].copy_from_slice(&word.to_le_bytes());
        }
        b[4..8].copy_from_slice(&[0x34, 0x12, 0xa5, 4]);
        b
    }
    #[test]
    fn unified_real_commands_wait_for_actual_init_notification_and_nvm_with_rfkill() {
        exercise_unified_nvm(false);
    }
    #[test]
    #[ignore = "requires actual pinned Intel firmware images"]
    fn unified_actual_images_drive_real_command_and_notification_epoch() {
        exercise_unified_nvm(true);
    }
    fn exercise_unified_nvm(actual_image: bool) {
        use super::super::nvm::{AddressSource, Request};
        for ax210 in [false, true] {
            let p = if ax210 { ax210_profile() } else { profile() };
            let bytes = if actual_image {
                let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
                let b = std::fs::read(std::path::Path::new(&root).join(p.family().firmware_name()))
                    .unwrap();
                use sha2::{Digest, Sha256};
                assert_eq!(
                    std::format!("{:x}", Sha256::digest(&b)),
                    if ax210 {
                        "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0"
                    } else {
                        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
                    }
                );
                b
            } else {
                unified_bytes(ax210)
            };
            let catalog = catalog_for(&p, p.family().firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let (observation, step_catalog) = step_fixture();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = if ax210 {
                ax210_state()
            } else {
                Arc::new(Mutex::new(ModelState::default()))
            };
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = if ax210 {
                start_ax210(
                    &catalog,
                    super::super::platform::load_step(observation, &step_catalog).unwrap(),
                    &source,
                    &domain,
                    &state,
                    &drops,
                )
            } else {
                start(&catalog, &source, &domain, &state, &drops)
            };
            let mut boot = command_ready(boot, &empty, &source, &domain, &state);
            {
                let mut s = state.lock().unwrap();
                *s.registers.get_mut(&0x24).unwrap() &= !0x08000000;
                s.registers.extend(if ax210 {
                    [(0x388, 0x02123456), (0x38c, 0x789a)]
                } else {
                    [(0x380, 0x02123456), (0x384, 0x789a)]
                });
            }
            assert!(matches!(
                unsafe { boot.submit_command(command_id(), &[], &source) },
                Err(Error::RfKilled)
            ));
            let mut init = boot.initialize_on_device_nvm();
            assert_eq!(
                unsafe { init.advance(&source) }.unwrap(),
                InitializationProgress::Pending(InitializationPhase::ExtendedConfiguration)
            );
            let tfd = device_read(&domain, init.boot.command.region().address, 0, 256);
            let first = u64::from_le_bytes(tfd[4..12].try_into().unwrap());
            assert_eq!(
                device_read(&domain, first, 0, 12),
                [3, 2, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0]
            );
            assert_eq!(
                unsafe { init.advance(&source) }.unwrap(),
                InitializationProgress::Pending(InitializationPhase::ExtendedConfiguration)
            );
            complete(
                &init.boot,
                &domain,
                1,
                2,
                &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
            );
            // Retry actual completed-range CPU visibility without replaying the
            // command or losing its exact initialization stage.
            {
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs + 1);
            }
            assert!(matches!(
                unsafe { init.advance(&source) },
                Err(Error::CommandReclaim(_))
            ));
            assert_eq!(init.phase(), InitializationPhase::ExtendedConfiguration);
            domain.records.lock().unwrap().cpu_sync_fail = None;
            assert_eq!(
                unsafe { init.advance(&source) }.unwrap(),
                InitializationProgress::Pending(InitializationPhase::AccessComplete)
            );
            complete(
                &init.boot,
                &domain,
                2,
                3,
                &command_packet(Request::AccessComplete.id(), 1, &[]),
            );
            assert_eq!(
                unsafe { init.advance(&source) }.unwrap(),
                InitializationProgress::Pending(InitializationPhase::InitNotification)
            );
            assert_eq!(
                unsafe { init.advance(&source) }.unwrap(),
                InitializationProgress::Pending(InitializationPhase::InitNotification)
            );
            assert_eq!(state.lock().unwrap().registers.get(&0x460), Some(&2));
            let wrong = super::super::command::Id {
                group: 1,
                opcode: 4,
                version: 0,
            };
            complete(
                &init.boot,
                &domain,
                3,
                4,
                &command_packet(wrong, 0x8000, &[0x55]),
            );
            assert_eq!(
                unsafe { init.advance(&source) }.unwrap(),
                InitializationProgress::Pending(InitializationPhase::InitNotification)
            );
            let actual = super::super::command::Id {
                group: 0,
                opcode: 4,
                version: 0,
            };
            complete(
                &init.boot,
                &domain,
                4,
                5,
                &command_packet(actual, 0x8000, &[0x66]),
            );
            assert_eq!(
                unsafe { init.advance(&source) }.unwrap(),
                InitializationProgress::Pending(InitializationPhase::NvmInformation)
            );
            let raw = nvm_response();
            complete(
                &init.boot,
                &domain,
                5,
                6,
                &command_packet(Request::GetInformation.id(), 2, &raw),
            );
            assert_eq!(
                unsafe { init.advance(&source) }.unwrap(),
                InitializationProgress::Observed
            );
            let r = init.receipt().unwrap();
            assert_eq!(r.information.raw, raw);
            assert_eq!(r.information.channel_count, 2);
            assert_eq!(r.information.channel_profiles[1], 0xabcdef);
            assert_eq!(r.address.bytes, [2, 0x12, 0x34, 0x56, 0x78, 0x9a]);
            assert_eq!(
                r.address.source,
                if ax210 {
                    AddressSource::Strap
                } else {
                    AddressSource::Otp
                }
            );
            assert_eq!(r.init_complete.raw, [0x66]);
            assert_eq!(
                r.product_reset,
                ax210.then_some(ProductResetObservation {
                    sb_configuration: 0,
                    coordination: ProductResetCoordination::NotPerformedNoIwlmei
                })
            );
            assert_eq!(
                unsafe { init.advance(&source) }.unwrap(),
                InitializationProgress::Observed
            );
            let (mut boot, _) = match init.into_parts() {
                Ok(parts) => parts,
                Err(_) => panic!("missing observation"),
            };
            assert_eq!(boot.take_firmware_notification().unwrap().raw, [0x55]);
            let ops = state.lock().unwrap().ops.clone();
            if ax210 {
                assert!(!ops.contains(&Op::Read(0x380)));
                assert!(!ops.contains(&Op::Read(0x384)));
            }
            boot.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
    #[test]
    fn unified_wrong_response_and_bad_nvm_never_report_initialization() {
        use super::super::nvm::Request;
        for failure in 0..3 {
            let bytes = unified_bytes(false);
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = start(&catalog, &source, &domain, &state, &drops);
            let boot = command_ready(boot, &empty, &source, &domain, &state);
            let mut init = boot.initialize_on_device_nvm();
            unsafe { init.advance(&source) }.unwrap();
            let id = if failure == 0 {
                super::super::command::Id {
                    group: 0,
                    opcode: 2,
                    version: 0,
                }
            } else {
                Request::ExtendedConfiguration.id()
            };
            complete(&init.boot, &domain, 1, 2, &command_packet(id, 0, &[]));
            if failure == 0 {
                assert!(matches!(
                    unsafe { init.advance(&source) },
                    Err(Error::InitializationResponse {
                        command: 2,
                        group: 0
                    })
                ));
            } else {
                unsafe { init.advance(&source) }.unwrap();
                let mut packet = command_packet(Request::AccessComplete.id(), 1, &[]);
                let actual = super::super::command::Id {
                    group: 0,
                    opcode: 4,
                    version: 0,
                };
                let notification = command_packet(actual, 0x8000, &[]);
                packet[64..128].copy_from_slice(&notification[..64]);
                packet[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
                complete(&init.boot, &domain, 2, 3, &packet);
                unsafe { init.advance(&source) }.unwrap();
                unsafe { init.advance(&source) }.unwrap();
                let bytes = if failure == 1 {
                    vec![0; 467]
                } else {
                    nvm_response()
                };
                complete(
                    &init.boot,
                    &domain,
                    3,
                    4,
                    &command_packet(Request::GetInformation.id(), 2, &bytes),
                );
                assert!(matches!(
                    unsafe { init.advance(&source) },
                    Err(Error::Nvm(_))
                ));
            }
            assert_eq!(init.phase(), InitializationPhase::Failed);
            assert!(init.receipt().is_none());
            assert!(matches!(
                unsafe { init.advance(&source) },
                Err(Error::State)
            ));
            init.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
    #[test]
    fn ax210_product_reset_uses_explicit_unmanaged_policy_and_refuses_managed_without_provider() {
        let bytes = ax210_bytes();
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        state.lock().unwrap().registers.insert(0x448, 0x80);
        let step = super::super::platform::load_step(observation, &step_catalog).unwrap();
        let mut boot = start_ax210(&catalog, step, &source, &domain, &state, &drops);
        assert_eq!(
            boot.product_reset_observation(),
            Some(ProductResetObservation {
                sb_configuration: 0x80,
                coordination: ProductResetCoordination::NotPerformedNoIwlmei
            })
        );
        let ops = state.lock().unwrap().ops.clone();
        let sb = ops
            .iter()
            .position(|op| *op == Op::Write(0x440, 0x03d03088))
            .unwrap();
        let context = ops
            .iter()
            .position(|op| matches!(op, Op::Write(0x118, _)))
            .unwrap();
        assert!(sb < context);
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let power = awake_profile(state.clone(), drops.clone(), ax210_profile());
        let before = state.lock().unwrap().ops.len();
        let step = super::super::platform::load_step(observation, &step_catalog).unwrap();
        let result = unsafe {
            RomBoot::start_ax210(
                power,
                super::super::identity::stage(&ax210_profile(), &catalog).unwrap(),
                step,
                &source,
                Some(domain.clone()),
                32,
                ProductResetPolicy::ManagedSap,
            )
        };
        assert!(matches!(result, Err(Error::ManagedSapUnsupported)));
        assert_eq!(state.lock().unwrap().ops.len(), before);
        assert_eq!(source.calls.load(Ordering::Relaxed), 0);
        assert!(domain.records.lock().unwrap().live.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn unified_retains_actual_init_notification_across_alive_and_pnvm_buffers() {
        use super::super::nvm::Request;
        let bytes = unified_bytes(false);
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let sku = [1, 2, 3];
        let (observations, platform) = phase_catalog(&profile(), sku, true, true);
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        event(&state, 1);
        boot.poll().unwrap();
        let actual = super::super::command::Id {
            group: 0,
            opcode: 4,
            version: 0,
        };
        let mut alive = rx_packet(1, 0xcafe, 0);
        set_sku(&mut alive, sku);
        let early = command_packet(actual, 0x8000, &[0x11]);
        alive[192..256].copy_from_slice(&early[..64]);
        alive[256..260].copy_from_slice(&0x55550000u32.to_le_bytes());
        complete(&boot, &domain, 0, 1, &alive);
        boot.poll().unwrap().unwrap();
        unsafe { boot.begin_pnvm(&platform, observations, &source) }.unwrap();
        let mut pnvm = pnvm_packet(0x42);
        let side = command_packet(
            super::super::command::Id {
                group: 2,
                opcode: 0x55,
                version: 0,
            },
            0x8000,
            &[0x22],
        );
        pnvm[64..128].copy_from_slice(&side[..64]);
        pnvm[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
        complete(&boot, &domain, 1, 2, &pnvm);
        assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Observed);
        state
            .lock()
            .unwrap()
            .registers
            .extend([(0x388, 0x02123456), (0x38c, 0x789a)]);
        let mut init = boot.initialize_on_device_nvm();
        unsafe { init.advance(&source) }.unwrap();
        complete(
            &init.boot,
            &domain,
            2,
            3,
            &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
        );
        unsafe { init.advance(&source) }.unwrap();
        complete(
            &init.boot,
            &domain,
            3,
            4,
            &command_packet(Request::AccessComplete.id(), 1, &[]),
        );
        unsafe { init.advance(&source) }.unwrap();
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Pending(InitializationPhase::NvmInformation)
        );
        complete(
            &init.boot,
            &domain,
            4,
            5,
            &command_packet(Request::GetInformation.id(), 2, &nvm_response()),
        );
        assert_eq!(
            unsafe { init.advance(&source) }.unwrap(),
            InitializationProgress::Observed
        );
        assert_eq!(init.receipt().unwrap().init_complete.raw, [0x11]);
        let (mut boot, _) = match init.into_parts() {
            Ok(parts) => parts,
            Err(_) => panic!("missing observation"),
        };
        assert_eq!(boot.take_firmware_notification().unwrap().raw, [0x22]);
        assert!(boot.take_firmware_notification().is_none());
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
    #[test]
    fn unified_missing_unknown_or_contradictory_nvm_abi_refuses_before_commands() {
        for failure in 0..3 {
            let mut bytes = if failure == 0 {
                firmware_bytes()
            } else {
                unified_bytes(false)
            };
            if failure == 1 {
                let at = bytes.windows(4).position(|w| w == [2, 12, 1, 4]).unwrap();
                bytes[at + 3] = 6;
            }
            if failure == 2 {
                let n = bytes.len();
                bytes[n - 4..].fill(0);
            }
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = start(&catalog, &source, &domain, &state, &drops);
            let boot = command_ready(boot, &empty, &source, &domain, &state);
            let mut init = boot.initialize_on_device_nvm();
            let ops = state.lock().unwrap().ops.len();
            let maps = domain.records.lock().unwrap().maps;
            assert!(matches!(
                unsafe { init.advance(&source) },
                Err(Error::Nvm(_))
            ));
            assert_eq!(init.phase(), InitializationPhase::Failed);
            assert!(init.receipt().is_none());
            assert_eq!(state.lock().unwrap().ops.len(), ops);
            assert_eq!(domain.records.lock().unwrap().maps, maps);
            init.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
    #[test]
    fn unified_mac_data_words_allow_all_ff_fallback_and_valid_sentinel_patterns() {
        use super::super::nvm::{AddressSource, Request};
        for case in 0..8 {
            let bytes = unified_bytes(false);
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = start(&catalog, &source, &domain, &state, &drops);
            let boot = command_ready(boot, &empty, &source, &domain, &state);
            let mut init = boot.initialize_on_device_nvm();
            unsafe { init.advance(&source) }.unwrap();
            complete(
                &init.boot,
                &domain,
                1,
                2,
                &command_packet(Request::ExtendedConfiguration.id(), 0, &[]),
            );
            unsafe { init.advance(&source) }.unwrap();
            let mut packet = command_packet(Request::AccessComplete.id(), 1, &[]);
            let notification = command_packet(
                super::super::command::Id {
                    group: 0,
                    opcode: 4,
                    version: 0,
                },
                0x8000,
                &[],
            );
            packet[64..128].copy_from_slice(&notification[..64]);
            packet[128..132].copy_from_slice(&0x55550000u32.to_le_bytes());
            complete(&init.boot, &domain, 2, 3, &packet);
            unsafe { init.advance(&source) }.unwrap();
            unsafe { init.advance(&source) }.unwrap();
            let strap = match case {
                0 => [u32::MAX; 2],
                1 => [0x02123456, u32::MAX],
                5 => [0xa5a5a5a0, 0x789a],
                6 => [0x5a5a5a50, 0x789a],
                _ => [0x02123456, 0x789a],
            };
            {
                let mut s = state.lock().unwrap();
                s.registers.extend([
                    (0x388, strap[0]),
                    (0x38c, strap[1]),
                    (0x380, 0x02123456),
                    (0x384, 0x789a),
                ]);
                if case == 2 {
                    s.registers.insert(0x28, u32::MAX);
                }
                if case == 3 {
                    s.fail_read = Some(0x388);
                }
                if case == 7 {
                    s.all_ff = true;
                }
                // Three transport CSR operations precede the pre-read two
                // identity observations and the two actual MAC words.
                if case == 4 {
                    s.sentinel = Some((s.ops.len() + 7, u32::MAX));
                }
            }
            complete(
                &init.boot,
                &domain,
                3,
                4,
                &command_packet(Request::GetInformation.id(), 2, &nvm_response()),
            );
            let live = domain.records.lock().unwrap().live.len();
            let result = unsafe { init.advance(&source) };
            match case {
                7 => {
                    assert!(matches!(
                        result,
                        Err(Error::FailedRead {
                            register: 8,
                            value: u32::MAX
                        })
                    ));
                    assert!(init.receipt().is_none());
                }
                2 | 4 => {
                    assert!(matches!(
                        result,
                        Err(Error::FailedRead {
                            register: 0x28,
                            value: u32::MAX
                        })
                    ));
                    assert!(init.receipt().is_none());
                }
                3 => {
                    assert!(matches!(
                        result,
                        Err(Error::Access(power::AccessError::Unavailable))
                    ));
                    assert!(init.receipt().is_none());
                }
                _ => {
                    assert_eq!(result.unwrap(), InitializationProgress::Observed);
                    let address = init.receipt().unwrap().address;
                    assert_eq!(
                        address.source,
                        if matches!(case, 0 | 5) {
                            AddressSource::Otp
                        } else {
                            AddressSource::Strap
                        }
                    );
                    assert_eq!(
                        address.bytes,
                        match case {
                            1 => [2, 0x12, 0x34, 0x56, 0xff, 0xff],
                            6 => [0x5a, 0x5a, 0x5a, 0x50, 0x78, 0x9a],
                            _ => [2, 0x12, 0x34, 0x56, 0x78, 0x9a],
                        }
                    );
                    if matches!(case, 1 | 6) {
                        let s = state.lock().unwrap();
                        assert!(!s.ops.contains(&Op::Read(0x380)));
                        assert!(!s.ops.contains(&Op::Read(0x384)));
                    }
                }
            }
            state.lock().unwrap().fail_read = None;
            if case == 7 {
                assert!(init.stop().is_err());
                drop(init);
                assert_eq!(domain.records.lock().unwrap().live.len(), live);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
            } else {
                init.stop().unwrap();
                assert!(domain.records.lock().unwrap().live.is_empty());
            }
        }
    }
    #[test]
    fn rx_recycling_publishes_initial_tail_and_sustains_actual_command_ring_wraps() {
        exercise_rx_recycling(None);
    }
    #[test]
    #[ignore = "requires freshly built unchanged Intel RX restock oracle"]
    fn rx_recycling_unchanged_source_free_producer_and_vid_oracle() {
        use sha2::{Digest, Sha256};
        let bytes =
            std::fs::read(std::env::var("STELA_IWLWIFI_RX_RECYCLE_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "6b4528a5d64209cc87aa2976e58fd0c358f76a15642557e263f10e830af8732d"
        );
        exercise_rx_recycling(Some(core::str::from_utf8(&bytes).unwrap()));
    }
    fn exercise_rx_recycling(oracle: Option<&str>) {
        for ax210 in [false, true] {
            let mut reference = Vec::new();
            if let Some(oracle) = oracle {
                for line in oracle.lines() {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    if fields[1].parse::<u8>().unwrap() != u8::from(ax210) {
                        continue;
                    }
                    if fields[0] == "initial" {
                        assert_eq!(&fields[2..], ["31", "24"]);
                    } else {
                        assert_eq!(fields[0], "recycle");
                        let row: Vec<u16> =
                            fields[2..].iter().map(|v| v.parse().unwrap()).collect();
                        reference.push(row);
                    }
                }
                assert_eq!(reference.len(), 521);
                assert_eq!(reference[0], [0, 0, 1, 0, 0]);
            }
            let p = if ax210 { ax210_profile() } else { profile() };
            let bytes = if ax210 {
                ax210_bytes()
            } else {
                firmware_bytes()
            };
            let catalog = catalog_for(&p, p.family().firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let (observation, step_catalog) = step_fixture();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = if ax210 {
                ax210_state()
            } else {
                Arc::new(Mutex::new(ModelState::default()))
            };
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = if ax210 {
                start_ax210(
                    &catalog,
                    super::super::platform::load_step(observation, &step_catalog).unwrap(),
                    &source,
                    &domain,
                    &state,
                    &drops,
                )
            } else {
                start(&catalog, &source, &domain, &state, &drops)
            };
            let mut boot = command_ready(boot, &empty, &source, &domain, &state);
            let calls = source.calls.load(Ordering::Relaxed);
            let maps = domain.records.lock().unwrap().maps;
            assert_eq!(
                boot.replenish_completed_receive().unwrap(),
                Replenished {
                    returned: 1,
                    published: 8,
                    device_credits: 31,
                    waiting_for_completed_slot: false
                }
            );
            assert_eq!(state.lock().unwrap().registers.get(&0x1c80), Some(&0));
            let mut preserved = None;
            for n in 0..520u16 {
                let ticket =
                    unsafe { boot.submit_command(command_id(), &[n as u8], &source) }.unwrap();
                let slot = (n + 1) & 31;
                let stride = if ax210 { 16 } else { 8 };
                let free = device_read(
                    &domain,
                    boot.free.region().address,
                    usize::from(slot) * stride,
                    stride,
                );
                let (vid, address) = if ax210 {
                    (
                        u16::from_le_bytes(free[..2].try_into().unwrap()),
                        u64::from_le_bytes(free[8..16].try_into().unwrap()),
                    )
                } else {
                    let word = u64::from_le_bytes(free.try_into().unwrap());
                    ((word & 0xfff) as u16, word & !0xfff)
                };
                assert_eq!(
                    address,
                    boot.buffers[usize::from(vid - 1)]
                        .allocation
                        .region()
                        .address
                );
                if oracle.is_some() {
                    assert_eq!(
                        (
                            reference[usize::from(n) + 1][0],
                            reference[usize::from(n) + 1][1],
                            reference[usize::from(n) + 1][2]
                        ),
                        (n + 1, slot, vid)
                    );
                }
                complete_from_free_slot(
                    &boot,
                    &domain,
                    slot,
                    vid,
                    slot,
                    &command_packet(command_id(), ticket.sequence(), &[n as u8]),
                );
                let response = match boot.poll_command(&ticket).unwrap() {
                    CommandProgress::Completed(r) => r,
                    _ => panic!("no completion"),
                };
                assert_eq!(response.raw, [n as u8]);
                if n == 0 {
                    preserved = Some(response.raw);
                }
                let replenished = boot.replenish_completed_receive().unwrap();
                assert_eq!(replenished.returned, 1);
                assert!(!replenished.waiting_for_completed_slot);
                assert!(matches!(replenished.published, 0 | 8));
                let expected = ((32 + n + 1) & 31) & !7;
                assert_eq!(
                    state.lock().unwrap().registers.get(&0x1c80),
                    Some(&u32::from(expected))
                );
                if oracle.is_some() {
                    assert_eq!(reference[usize::from(n) + 1][4], expected);
                }
            }
            assert_eq!(preserved.unwrap(), [0]);
            assert_eq!(source.calls.load(Ordering::Relaxed), calls);
            assert_eq!(domain.records.lock().unwrap().maps, maps);
            boot.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
    #[test]
    fn rx_recycling_waits_for_actual_target_slot_completion_when_payloads_complete_out_of_order() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = start(&catalog, &source, &domain, &state, &drops);
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        boot.replenish_completed_receive().unwrap();
        for (index, vid, expected_return, expected_wait) in
            [(1, 3, 1, false), (2, 4, 0, true), (3, 2, 2, false)]
        {
            let ticket = unsafe { boot.submit_command(command_id(), &[], &source) }.unwrap();
            complete_from_free_slot(
                &boot,
                &domain,
                index,
                vid,
                vid - 1,
                &command_packet(command_id(), ticket.sequence(), &[]),
            );
            assert!(matches!(
                boot.poll_command(&ticket).unwrap(),
                CommandProgress::Completed(_)
            ));
            let r = boot.replenish_completed_receive().unwrap();
            assert_eq!(r.returned, expected_return);
            assert_eq!(r.waiting_for_completed_slot, expected_wait);
            assert_eq!(r.published, 0);
        }
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
    #[test]
    fn rx_recycling_visibility_and_producer_faults_keep_real_dma_and_requester() {
        for failure in 0..4 {
            let bytes = firmware_bytes();
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let boot = start(&catalog, &source, &domain, &state, &drops);
            let mut boot = command_ready(boot, &empty, &source, &domain, &state);
            if failure == 3 {
                boot.replenish_completed_receive().unwrap();
                let ticket = unsafe { boot.submit_command(command_id(), &[], &source) }.unwrap();
                complete(
                    &boot,
                    &domain,
                    1,
                    2,
                    &command_packet(command_id(), ticket.sequence(), &[]),
                );
                assert!(matches!(
                    boot.poll_command(&ticket).unwrap(),
                    CommandProgress::Completed(_)
                ));
                let mut r = domain.records.lock().unwrap();
                r.cpu_sync_fail = Some(r.cpu_syncs);
            } else if failure < 2 {
                let mut r = domain.records.lock().unwrap();
                r.sync_fail = Some(r.syncs + failure);
            } else {
                let mut s = state.lock().unwrap();
                s.fail = Some(s.ops.len());
            }
            let live = domain.records.lock().unwrap().live.len();
            assert!(boot.replenish_completed_receive().is_err());
            assert_eq!(boot.state, State::Poisoned);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            {
                let mut s = state.lock().unwrap();
                s.fail = None;
                s.stop_ack = false;
            }
            assert!(boot.stop().is_err());
            drop(boot);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
        }
    }
    fn pnvm_packet(status: u32) -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        bytes[..4].copy_from_slice(&12u32.to_le_bytes());
        bytes[4] = 0xfe;
        bytes[5] = 0xc;
        bytes[7] = 0x80;
        bytes[8..12].copy_from_slice(&status.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x12345678u32.to_le_bytes());
        bytes[64..68].copy_from_slice(&0x55550000u32.to_le_bytes());
        bytes
    }
    fn set_sku(bytes: &mut [u8], sku: [u32; 3]) {
        for (n, word) in sku.into_iter().enumerate() {
            bytes[124 + n * 4..128 + n * 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    fn alive_ax210<'a>(
        catalog: &'a resources::Catalog,
        step: StepConfiguration<'a>,
        source: &Source,
        domain: &Arc<Domain>,
        state: &Arc<Mutex<ModelState>>,
        drops: &Arc<AtomicUsize>,
    ) -> RomBoot<'a, Model> {
        let mut boot = start_ax210(catalog, step, source, domain, state, drops);
        event(state, 1);
        boot.poll().unwrap();
        complete(&boot, domain, 0, 1, &rx_packet(1, 0xcafe, 0));
        boot.poll().unwrap().unwrap();
        boot
    }
    fn device_write(domain: &Domain, address: u64, offset: usize, bytes: &[u8], complete: bool) {
        let mut r = domain.records.lock().unwrap();
        let id = id(address);
        assert!(matches!(
            r.permissions.get(&id),
            Some(Direction::FromDevice | Direction::Bidirectional)
        ));
        let pointer = r
            .live
            .get(&id)
            .unwrap()
            .address(
                (address - (0x100000 + id * 0x10000)) as usize + offset,
                bytes.len(),
            )
            .unwrap();
        // SAFETY: serialized model requester writes only actual mapped live RAM
        // with device-write permission, before publishing its completion status.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.as_ptr(), bytes.len());
        }
        if complete {
            assert!(r.completed.insert(id));
        }
    }
    fn device_read(domain: &Domain, address: u64, offset: usize, n: usize) -> Vec<u8> {
        let r = domain.records.lock().unwrap();
        let id = id(address);
        assert!(matches!(
            r.permissions.get(&id),
            Some(Direction::ToDevice | Direction::Bidirectional)
        ));
        let pointer = r
            .live
            .get(&id)
            .unwrap()
            .address((address - (0x100000 + id * 0x10000)) as usize + offset, n)
            .unwrap();
        let mut bytes = vec![0; n];
        unsafe {
            core::ptr::copy_nonoverlapping(pointer.as_ptr(), bytes.as_mut_ptr(), n);
        }
        bytes
    }
    fn rx_packet(command: u8, status: u16, queue: u8) -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        bytes[..4].copy_from_slice(&(148u32 | (u32::from(queue) << 16)).to_le_bytes());
        bytes[4] = command;
        bytes[7] = 0x80;
        bytes[8..10].copy_from_slice(&status.to_le_bytes());
        for (n, word) in [0x610d0u32, 0x1234, 0x55667788].iter().enumerate() {
            bytes[124 + n * 4..128 + n * 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes[192..196].copy_from_slice(&0x55550000u32.to_le_bytes());
        bytes
    }
    fn event(state: &Arc<Mutex<ModelState>>, cause: u32) {
        let mut s = state.lock().unwrap();
        *s.registers.entry(8).or_default() |= cause;
    }
    fn complete(boot: &Ax200Boot<'_, Model>, domain: &Domain, index: u16, vid: u16, packet: &[u8]) {
        complete_from_free_slot(boot, domain, index, vid, vid - 1, packet);
    }
    fn complete_from_free_slot(
        boot: &Ax200Boot<'_, Model>,
        domain: &Domain,
        index: u16,
        vid: u16,
        free_slot: u16,
        packet: &[u8],
    ) {
        let stride = if boot.profile.family() == Family::Ax210 {
            16
        } else {
            8
        };
        // Actual model requester consumed this emitted free descriptor before
        // completing its receive payload; this grants only that exact range.
        let mut r = domain.records.lock().unwrap();
        r.completed_ranges.insert((
            id(boot.free.region().address),
            usize::from(free_slot) * stride,
            usize::from(free_slot + 1) * stride,
        ));
        drop(r);
        // The device model's real matching HCMD response ends access to the
        // submitted slot/TB0 before publishing the RX completion. Merely
        // receiving an unsolicited/wrong sequence grants no such ownership.
        if let Ok(packets) = Packets::new(boot.profile.family(), 0, packet) {
            for response in packets.flatten() {
                if response.unsolicited() || (response.group == 0 && response.command == 0x1c) {
                    continue;
                }
                let slots = if boot.profile.family() == Family::Ax210 {
                    128
                } else {
                    32
                };
                let slot = response.sequence & (slots - 1);
                let tfd = device_read(
                    domain,
                    boot.command.region().address,
                    usize::from(slot) * 256,
                    256,
                );
                let first = u64::from_le_bytes(tfd[4..12].try_into().unwrap());
                let header = device_read(domain, first, 0, 8);
                if response.sequence == u16::from_le_bytes(header[2..4].try_into().unwrap()) {
                    let mut r = domain.records.lock().unwrap();
                    r.completed.insert(id(boot.command.region().address));
                    r.completed.insert(id(first));
                }
            }
        }
        let payload = &boot.buffers[usize::from(vid - 1)].allocation;
        device_write(domain, payload.region().address, 0, packet, true);
        let mut descriptor = [0; 32];
        let stride = if boot.profile.family() == Family::Ax210 {
            descriptor[4..6].copy_from_slice(&vid.to_le_bytes());
            32
        } else {
            descriptor[..4].copy_from_slice(&(0xf0000000 | u32::from(vid)).to_le_bytes());
            4
        };
        device_write(
            domain,
            boot.used.region().address,
            usize::from(index) * stride,
            &descriptor[..stride],
            false,
        );
        device_write(
            domain,
            boot.status.region().address,
            0,
            &(index + 1).to_le_bytes(),
            false,
        );
    }

    fn ax210_profile() -> Profile {
        let mut observed = profile().observed();
        observed.device = 0x2725;
        observed.hardware_revision = 0x420;
        observed.radio_id = 0x10d000;
        Profile::select(observed).unwrap()
    }
    fn ax210_state() -> Arc<Mutex<ModelState>> {
        let state = Arc::new(Mutex::new(ModelState::default()));
        state
            .lock()
            .unwrap()
            .registers
            .extend([(0x28, 0x420), (0x9c, 0x10d000), (0, 0x45678900)]);
        state
    }
    fn ax210_bytes() -> Vec<u8> {
        let mut bytes = firmware_bytes();
        bytes[72..76].copy_from_slice(&(89u32 << 8).to_le_bytes());
        bytes.extend(52u32.to_le_bytes());
        bytes.extend(64u32.to_le_bytes());
        bytes.extend([0xa5; 64]);
        bytes
    }
    fn step_fixture() -> (super::super::platform::Observation, resources::Catalog) {
        use super::super::platform::{CapturedVariable, Variable};
        let mut captured = CapturedVariable::from_variable(
            Variable::Step,
            vec![1, 0xab, 0x12, 0x34, 0x56, 0x78],
            7,
            Some(6),
        )
        .unwrap();
        (
            captured.observation(),
            resources::Catalog::from_handoff(vec![captured.take_resource().unwrap()]).unwrap(),
        )
    }
    fn start_ax210<'a>(
        catalog: &'a resources::Catalog,
        step: StepConfiguration<'a>,
        source: &Source,
        domain: &Arc<Domain>,
        state: &Arc<Mutex<ModelState>>,
        drops: &Arc<AtomicUsize>,
    ) -> RomBoot<'a, Model> {
        unsafe {
            RomBoot::start_ax210(
                awake_profile(state.clone(), drops.clone(), ax210_profile()),
                super::super::identity::stage(&ax210_profile(), catalog).unwrap(),
                step,
                source,
                Some(domain.clone()),
                32,
                ProductResetPolicy::NoIwlmei,
            )
            .unwrap()
        }
    }
    #[test]
    fn ax210_publishes_iml_scratch_dummy_tails_and_retains_pnvm_context_after_alive() {
        let bytes = ax210_bytes();
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        let step = super::super::platform::load_step(observation, &step_catalog).unwrap();
        let step_pointer = step.image().unwrap().bytes().as_ptr();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start_ax210(&catalog, step, &source, &domain, &state, &drops);
        assert_eq!(
            boot.step_configuration()
                .unwrap()
                .image()
                .unwrap()
                .bytes()
                .as_ptr(),
            step_pointer
        );
        let memory = boot.ax210.as_ref().unwrap();
        let context = boot.context.region().address;
        let scratch = memory.scratch.region().address;
        let info = memory.info.region().address;
        let iml = memory.iml.region().address;
        let wire = device_read(&domain, context, 0, 104);
        let addr = |at| u64::from_le_bytes(wire[at..at + 8].try_into().unwrap());
        assert_eq!(
            (addr(8), addr(24), addr(32), addr(88)),
            (info, info + 2048, info + 3072, scratch)
        );
        assert_eq!(
            device_read(&domain, scratch, 76, 8),
            [1, 0x12, 0x34, 0x56, 0x78, 0, 0, 0]
        );
        assert_eq!(device_read(&domain, iml, 0, 64), [0xa5; 64]);
        // The hardware may really write both dummy tail slots, including after
        // ALIVE; these are mapped writable RAM, never null/dummy host pointers.
        device_write(&domain, info, 2048, &0x1234u32.to_le_bytes(), false);
        device_write(&domain, info, 3072, &0x5678u32.to_le_bytes(), false);
        let ops = state.lock().unwrap().ops.clone();
        let publish = ops
            .iter()
            .position(|op| matches!(op, Op::Write(0x118, _)))
            .unwrap();
        assert_eq!(
            &ops[publish..publish + 8],
            &[
                Op::Write(0x118, context as u32),
                Op::Write(0x11c, (context >> 32) as u32),
                Op::Write(0x120, iml as u32),
                Op::Write(0x124, (iml >> 32) as u32),
                Op::Write(0x128, 64),
                Op::Read(0),
                Op::Write(0, 0x456f8902),
                Op::Write(0xd4, 0x88fa88fa)
            ]
        );
        assert!(ops.contains(&Op::Write(0x444, 0x03d05c44)));
        assert!(!ops.iter().any(|op| matches!(op, Op::Write(0x40 | 0x44, _))));
        let live = domain.records.lock().unwrap().live.len();
        assert_eq!(live, 45);
        event(&state, 1);
        assert!(boot.poll().unwrap().is_none());
        for (index, buffer) in boot.buffers.iter().enumerate() {
            let descriptor = device_read(&domain, boot.free.region().address, index * 16, 16);
            assert_eq!(
                u16::from_le_bytes(descriptor[..2].try_into().unwrap()),
                index as u16 + 1
            );
            assert_eq!(
                u64::from_le_bytes(descriptor[8..].try_into().unwrap()),
                buffer.allocation.region().address
            );
            assert_eq!(buffer.device_owned, index < 24);
        }
        complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
        let report = boot.poll().unwrap().unwrap();
        assert_eq!(report.sku, [0x610d0, 0x1234, 0x55667788]);
        assert_eq!(domain.records.lock().unwrap().live.len(), live - 3); // LMAC+UMAC+IML
        assert_eq!(boot.state, State::Alive);
        assert_eq!(
            boot.post_alive_plan().unwrap().pnvm,
            super::super::platform::PnvmSource::Bios {
                external_fallback: true
            }
        );
        for address in [context, scratch, info] {
            assert!(
                domain
                    .records
                    .lock()
                    .unwrap()
                    .live
                    .contains_key(&id(address))
            );
        }
        assert!(!domain.records.lock().unwrap().live.contains_key(&id(iml)));
        device_write(&domain, info, 3072, &0x99u32.to_le_bytes(), false);
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            source.calls.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
    }
    #[test]
    fn ax210_all_prepublication_faults_release_and_each_partial_stop_can_retry() {
        let bytes = ax210_bytes();
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        for stage in 0..3 {
            for fail in 0..if stage == 2 { 48 } else { 45 } {
                let source = Source {
                    fail_at: (stage == 0).then_some(fail),
                    ..Default::default()
                };
                let domain = Arc::new(Domain {
                    records: Mutex::new(Records {
                        map_fail: (stage == 1).then_some(fail),
                        sync_fail: (stage == 2).then_some(fail),
                        ..Default::default()
                    }),
                });
                let state = ax210_state();
                let drops = Arc::new(AtomicUsize::new(0));
                let result = unsafe {
                    RomBoot::start_ax210(
                        awake_profile(state.clone(), drops.clone(), ax210_profile()),
                        super::super::identity::stage(&ax210_profile(), &catalog).unwrap(),
                        super::super::platform::load_step(observation, &step_catalog).unwrap(),
                        &source,
                        Some(domain.clone()),
                        32,
                        ProductResetPolicy::NoIwlmei,
                    )
                };
                assert!(
                    matches!(result, Err(Error::Dma(_))),
                    "stage{stage} fail{fail}"
                );
                assert!(domain.records.lock().unwrap().live.is_empty());
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                assert!(
                    !state
                        .lock()
                        .unwrap()
                        .ops
                        .iter()
                        .any(|op| matches!(op, Op::Write(0x118, _)))
                );
                assert_eq!(
                    source.calls.load(Ordering::Relaxed) - (stage == 0) as usize,
                    source.released.load(Ordering::Relaxed)
                );
            }
        }
        for fail in 0..45 {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let mut boot = start_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            );
            domain.records.lock().unwrap().unmap_fail = Some(fail);
            assert!(matches!(
                boot.stop(),
                Err(Error::Dma(dma::Error::Dma(
                    crate::bus::dma::mapping::DmaError::InvalidationFailed
                )))
            ));
            assert_eq!(boot.state, State::Quiescent);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            boot.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
            drop(boot);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn ax210_every_launch_csr_fault_quarantines_actual_owner_after_publication() {
        let bytes = ax210_bytes();
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start_ax210(
            &catalog,
            super::super::platform::load_step(observation, &step_catalog).unwrap(),
            &source,
            &domain,
            &state,
            &drops,
        );
        let ops = state.lock().unwrap().ops.clone();
        let publication = ops
            .iter()
            .position(|op| matches!(op, Op::Write(0x118, _)))
            .unwrap();
        boot.stop().unwrap();
        drop(boot);
        for index in 0..ops.len() {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let power = awake_profile(state.clone(), drops.clone(), ax210_profile());
            state.lock().unwrap().fail = Some(index);
            let result = unsafe {
                RomBoot::start_ax210(
                    power,
                    super::super::identity::stage(&ax210_profile(), &catalog).unwrap(),
                    super::super::platform::load_step(observation, &step_catalog).unwrap(),
                    &source,
                    Some(domain.clone()),
                    32,
                    ProductResetPolicy::NoIwlmei,
                )
            };
            assert!(
                matches!(result, Err(Error::Access(power::AccessError::Unavailable))),
                "operation{index}"
            );
            assert_eq!(
                drops.load(Ordering::Relaxed),
                usize::from(index < publication)
            );
            assert_eq!(
                domain.records.lock().unwrap().live.is_empty(),
                index < publication
            );
        }
        for (index, op) in ops.iter().enumerate() {
            if !matches!(op, Op::Read(_)) {
                continue;
            }
            for value in [u32::MAX, 0xa5a5a5a0, 0x5a5a5a5f] {
                let source = Source::default();
                let domain = Arc::new(Domain::default());
                let state = ax210_state();
                let drops = Arc::new(AtomicUsize::new(0));
                let power = awake_profile(state.clone(), drops.clone(), ax210_profile());
                state.lock().unwrap().sentinel = Some((index, value));
                let result = unsafe {
                    RomBoot::start_ax210(
                        power,
                        super::super::identity::stage(&ax210_profile(), &catalog).unwrap(),
                        super::super::platform::load_step(observation, &step_catalog).unwrap(),
                        &source,
                        Some(domain.clone()),
                        32,
                        ProductResetPolicy::NoIwlmei,
                    )
                };
                assert!(matches!(result,Err(Error::FailedRead{value:actual,..})if actual==value));
                assert_eq!(
                    drops.load(Ordering::Relaxed),
                    usize::from(index < publication)
                );
            }
        }
    }
    #[test]
    fn ax210_wrong_protocol_missing_oversized_iml_and_unqualified_inputs_do_no_io_or_dma() {
        let (observation, step_catalog) = step_fixture();
        for mode in 0..5 {
            let mut bytes = if mode == 0 {
                let mut b = firmware_bytes();
                b[72..76].copy_from_slice(&(89u32 << 8).to_le_bytes());
                b
            } else {
                ax210_bytes()
            };
            if mode == 1 {
                bytes.truncate(bytes.len() - 72);
                bytes.extend(52u32.to_le_bytes());
                bytes.extend(32772u32.to_le_bytes());
                bytes.extend(vec![0xa5; 32772]);
            }
            let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let power = awake_profile(state.clone(), drops.clone(), ax210_profile());
            let staged = super::super::identity::stage(&ax210_profile(), &catalog).unwrap();
            let result = unsafe {
                if mode == 4 {
                    RomBoot::start(power, staged, &source, Some(domain.clone()), 32)
                } else {
                    RomBoot::start_ax210(
                        power,
                        staged,
                        super::super::platform::load_step(observation, &step_catalog).unwrap(),
                        &source,
                        if mode == 3 {
                            None
                        } else {
                            Some(domain.clone())
                        },
                        if mode == 2 { 2048 } else { 32 },
                        ProductResetPolicy::NoIwlmei,
                    )
                }
            };
            assert!(matches!(
                (&result, mode),
                (
                    Err(Error::Firmware(firmware::Error::Missing("AX210 IML"))),
                    0
                ) | (Err(Error::Dma(dma::Error::PayloadSize)), 1)
                    | (Err(Error::QueueSize), 2)
                    | (
                        Err(Error::Dma(dma::Error::Dma(
                            crate::bus::dma::mapping::DmaError::IommuUnavailable
                        ))),
                        3
                    )
                    | (Err(Error::Family), 4)
            ));
            assert!(state.lock().unwrap().ops.is_empty());
            assert_eq!(source.calls.load(Ordering::Relaxed), 0);
            assert_eq!(domain.records.lock().unwrap().maps, 0);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn actual_alive_bios_source_scratch_doorbell_and_raw_notification_preserve_tables() {
        for fragmented in [false, true] {
            let mut bytes = ax210_bytes();
            if fragmented {
                bytes.extend(30u32.to_le_bytes());
                bytes.extend(8u32.to_le_bytes());
                bytes.extend(1u32.to_le_bytes());
                bytes.extend(1u32.to_le_bytes());
            }
            let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
            let (observation, step_catalog) = step_fixture();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let (observations, provider) =
                phase_catalog(&ax210_profile(), [0x610d0, 0x1234, 0x55667788], true, true);
            let mut boot = alive_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            );
            let live = domain.records.lock().unwrap().live.len();
            assert_eq!(
                unsafe { boot.begin_pnvm(&provider, observations, &source) }.unwrap(),
                PnvmProgress::Waiting
            );
            let added = if fragmented { 6 } else { 2 };
            assert_eq!(domain.records.lock().unwrap().live.len(), live + added);
            assert!(matches!(
                boot.platform_receipts().unwrap().pnvm,
                calibration::Source::Bios { .. }
            ));
            assert_eq!(
                boot.platform_receipts().unwrap().pnvm_version,
                Some(0x12345678)
            );
            assert_eq!(
                boot.platform_receipts().unwrap().transfer,
                calibration::Transfer::ScratchV2
            );
            let memory = boot.ax210.as_ref().unwrap();
            let pnvm = device_read(&domain, memory.scratch.region().address, 16, 16);
            let power = device_read(&domain, memory.scratch.region().address, 60, 16);
            assert_eq!(u32::from_le_bytes(pnvm[8..12].try_into().unwrap()), 33);
            assert_eq!(u32::from_le_bytes(power[8..12].try_into().unwrap()), 25);
            assert!(
                state
                    .lock()
                    .unwrap()
                    .ops
                    .windows(2)
                    .any(|ops| ops == [Op::Write(0x444, 0x03d05c04), Op::Write(0x44c, 1 << 20)])
            );
            assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Waiting);
            complete(&boot, &domain, 1, 2, &pnvm_packet(0xdeadbeef));
            assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Observed);
            let notification = boot.pnvm_notification().unwrap();
            assert_eq!(notification.status, 0xdeadbeef);
            assert_eq!(
                notification.raw,
                [0xef, 0xbe, 0xad, 0xde, 0x78, 0x56, 0x34, 0x12]
            );
            assert_eq!(domain.records.lock().unwrap().live.len(), live + added);
            assert!(matches!(
                unsafe { boot.begin_pnvm(&provider, observations, &source) },
                Err(Error::State)
            ));
            boot.stop().unwrap();
            drop(boot);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn zero_sku_requests_nothing_and_missing_capture_or_bad_bios_never_fake_fallback() {
        use core::cell::RefCell;
        struct Spy<'a> {
            catalog: &'a resources::Catalog,
            requests: RefCell<Vec<alloc::string::String>>,
        }
        impl resources::Provider for Spy<'_> {
            fn load<'p>(
                &'p self,
                r: resources::Requirement<'_>,
            ) -> Result<resources::Image<'p>, resources::Error> {
                self.requests.borrow_mut().push(r.name.into());
                resources::Provider::load(self.catalog, r)
            }
        }
        for mode in 0..4 {
            let bytes = ax210_bytes();
            let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
            let (observation, step_catalog) = step_fixture();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let mut sku = if mode == 0 {
                [0; 3]
            } else {
                [0x610d0, 0x1234, 0x55667788]
            };
            if mode == 2 {
                sku[0] ^= 1;
            }
            let (mut observations, provider) =
                phase_catalog(&ax210_profile(), sku, mode != 3, false);
            if mode == 0 || mode == 1 {
                observations = Observations::default();
            }
            let spy = Spy {
                catalog: &provider,
                requests: RefCell::new(Vec::new()),
            };
            let mut boot = start_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            );
            event(&state, 1);
            boot.poll().unwrap();
            let mut packet = rx_packet(1, 0xcafe, 0);
            if mode == 0 {
                set_sku(&mut packet, [0; 3]);
            }
            complete(&boot, &domain, 0, 1, &packet);
            boot.poll().unwrap().unwrap();
            let calls = source.calls.load(Ordering::Relaxed);
            state.lock().unwrap().ops.clear();
            let result = unsafe { boot.begin_pnvm(&spy, observations, &source) };
            match mode {
                0 => {
                    assert_eq!(result.unwrap(), PnvmProgress::Skipped);
                    assert!(spy.requests.borrow().is_empty());
                    assert!(state.lock().unwrap().ops.is_empty());
                }
                1 => {
                    assert!(matches!(
                        result,
                        Err(Error::Calibration(calibration::Error::Observation { .. }))
                    ));
                    assert!(spy.requests.borrow().is_empty());
                    assert!(state.lock().unwrap().ops.is_empty());
                }
                2 => {
                    assert!(matches!(
                        result,
                        Err(Error::Calibration(calibration::Error::Selection(_)))
                    ));
                    assert_eq!(
                        spy.requests.borrow().as_slice(),
                        [super::super::platform::Variable::OemPnvm.resource_name()]
                    );
                    assert!(state.lock().unwrap().ops.is_empty());
                }
                _ => {
                    assert_eq!(result.unwrap(), PnvmProgress::Waiting);
                    assert_eq!(
                        spy.requests.borrow().as_slice(),
                        ["iwlwifi-ty-a0-gf-a0.pnvm"]
                    );
                    assert!(matches!(
                        boot.platform_receipts().unwrap().pnvm,
                        calibration::Source::External {
                            bios_fallback: Some(_),
                            ..
                        }
                    ));
                    assert!(matches!(
                        boot.platform_receipts().unwrap().reduced_power,
                        calibration::Source::Unavailable { .. }
                    ));
                }
            }
            if mode < 3 {
                assert_eq!(source.calls.load(Ordering::Relaxed), calls);
            }
            boot.stop().unwrap();
            drop(boot);
            assert!(domain.records.lock().unwrap().live.is_empty());
        }
    }
    #[test]
    fn pnvm_each_new_mapping_visibility_and_partial_stop_failure_preserves_epoch() {
        let mut bytes = ax210_bytes();
        bytes.extend(30u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        let (observations, provider) =
            phase_catalog(&ax210_profile(), [0x610d0, 0x1234, 0x55667788], true, true);
        for stage in 0..3 {
            for fail in 0..if stage == 2 { 10 } else { 6 } {
                let mut source = Source::default();
                let domain = Arc::new(Domain::default());
                let state = ax210_state();
                let drops = Arc::new(AtomicUsize::new(0));
                let mut boot = alive_ax210(
                    &catalog,
                    super::super::platform::load_step(observation, &step_catalog).unwrap(),
                    &source,
                    &domain,
                    &state,
                    &drops,
                );
                let live = domain.records.lock().unwrap().live.len();
                if stage == 0 {
                    source.fail_at = Some(source.calls.load(Ordering::Relaxed) + fail);
                }
                {
                    let mut records = domain.records.lock().unwrap();
                    if stage == 1 {
                        records.map_fail = Some(records.maps + fail);
                    }
                    if stage == 2 {
                        records.sync_fail = Some(records.syncs + fail);
                    }
                }
                state.lock().unwrap().ops.clear();
                let result = unsafe { boot.begin_pnvm(&provider, observations, &source) };
                assert!(
                    matches!(result, Err(Error::PnvmDma(_)) | Err(Error::Dma(_))),
                    "stage{stage} fail{fail}"
                );
                if stage == 2 && fail >= 8 {
                    assert_eq!(boot.state, State::Poisoned);
                    assert_eq!(domain.records.lock().unwrap().live.len(), live + 6);
                } else {
                    assert_eq!(boot.state, State::Alive);
                    assert_eq!(domain.records.lock().unwrap().live.len(), live);
                }
                assert!(
                    !state
                        .lock()
                        .unwrap()
                        .ops
                        .iter()
                        .any(|op| matches!(op, Op::Write(0x44c, 0x100000)))
                );
                boot.stop().unwrap();
                drop(boot);
                assert!(domain.records.lock().unwrap().live.is_empty());
                assert_eq!(drops.load(Ordering::Relaxed), 1);
            }
        }
        for fail in 0..48 {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let mut boot = alive_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            );
            unsafe {
                boot.begin_pnvm(&provider, observations, &source).unwrap();
            }
            {
                let mut records = domain.records.lock().unwrap();
                records.unmap_fail = Some(records.unmaps + fail);
            }
            assert!(boot.stop().is_err(), "unmap{fail}");
            assert_eq!(boot.state, State::Quiescent);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            boot.stop().unwrap();
            drop(boot);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn pnvm_wrong_short_and_failed_doorbell_never_release_or_synthesize_status() {
        let bytes = ax210_bytes();
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        let (observations, provider) =
            phase_catalog(&ax210_profile(), [0x610d0, 0x1234, 0x55667788], true, true);
        for mode in 0..3 {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let mut boot = alive_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            );
            if mode == 2 {
                let mut model = state.lock().unwrap();
                model.fail = Some(model.ops.len());
            }
            let result = unsafe { boot.begin_pnvm(&provider, observations, &source) };
            let live = domain.records.lock().unwrap().live.len();
            if mode == 2 {
                assert!(result.is_err());
                assert_eq!(boot.state, State::Poisoned);
            } else {
                result.unwrap();
                let mut packet = pnvm_packet(0);
                if mode == 0 {
                    packet[5] = 4;
                } else {
                    packet[..4].copy_from_slice(&6u32.to_le_bytes());
                }
                complete(&boot, &domain, 1, 2, &packet);
                if mode == 0 {
                    assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Waiting);
                } else {
                    assert_eq!(boot.poll_pnvm(), Err(Error::PnvmNotification));
                }
            }
            assert!(boot.pnvm_notification().is_none());
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            boot.stop().unwrap();
            drop(boot);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn ax200_retains_actual_bios_receipts_and_explicit_pre_v2_no_payload_transfer() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let (observations, provider) =
            phase_catalog(&profile(), [0x610d0, 0x1234, 0x55667788], true, true);
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        event(&state, 1);
        boot.poll().unwrap();
        complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
        boot.poll().unwrap().unwrap();
        let maps = domain.records.lock().unwrap().maps;
        let live = domain.records.lock().unwrap().live.len();
        assert_eq!(
            unsafe { boot.begin_pnvm(&provider, observations, &source) }.unwrap(),
            PnvmProgress::Waiting
        );
        assert_eq!(
            boot.platform_receipts().unwrap().transfer,
            calibration::Transfer::NotUsedBeforeAx210
        );
        assert!(matches!(
            boot.platform_receipts().unwrap().pnvm,
            calibration::Source::Bios { .. }
        ));
        assert_eq!(domain.records.lock().unwrap().maps, maps);
        assert!(
            state
                .lock()
                .unwrap()
                .ops
                .windows(2)
                .any(|ops| ops == [Op::Write(0x444, 0x03005c04), Op::Write(0x44c, 1 << 20)])
        );
        complete(&boot, &domain, 1, 2, &pnvm_packet(0x123));
        assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Observed);
        assert_eq!(boot.pnvm_notification().unwrap().status, 0x123);
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        boot.stop().unwrap();
        drop(boot);
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
    #[test]
    #[ignore = "requires actual AX210 firmware and PNVM assets; see THIRD_PARTY.md"]
    fn actual_ax210_ucode_external_pnvm_source_dma_doorbell_and_notification() {
        use super::super::platform::{Observation, Stage};
        use sha2::{Digest, Sha256};
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        let root = std::path::Path::new(&root);
        let bytes = std::fs::read(root.join(Family::Ax210.firmware_name())).unwrap();
        let pnvm = std::fs::read(root.join("iwlwifi-ty-a0-gf-a0.pnvm")).unwrap();
        let digest: [u8; 32] = Sha256::digest(&pnvm).into();
        assert_eq!(
            digest,
            [
                0x96, 0x97, 0xe3, 0x27, 0xf8, 0x17, 0x14, 0x54, 0xb3, 0xc1, 0x9b, 0x1e, 0xc9, 0x44,
                0x97, 0x53, 0xd5, 0xb9, 0x34, 0xd4, 0xe9, 0x17, 0x22, 0xf4, 0x69, 0x61, 0x68, 0x18,
                0xa6, 0xd4, 0x77, 0xb0
            ]
        );
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        let request = ax210_profile().pnvm_request().unwrap();
        let provider = resources::Catalog::from_handoff(vec![resources::Resource {
            name: request.name,
            target: request.requirement().target,
            provenance: resources::Provenance {
                source: "linux-firmware",
                revision: "59f9fc2ef8d1e312d2a613d4e1ffad2ff31a0a01",
                member: "intel/iwlwifi/iwlwifi-ty-a0-gf-a0.pnvm",
                license: "LicenseRef-LICENCE.iwlwifi_firmware",
            },
            expected_length: pnvm.len(),
            expected_sha256: digest,
            bytes: pnvm,
        }])
        .unwrap();
        let observations = Observations {
            oem_pnvm: Observation::NotCaptured,
            reduced_power: Observation::from_error(Stage::Probe, (1 << 63) | 14, None),
            step: observation,
            ..Observations::default()
        };
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start_ax210(
            &catalog,
            super::super::platform::load_step(observation, &step_catalog).unwrap(),
            &source,
            &domain,
            &state,
            &drops,
        );
        event(&state, 1);
        boot.poll().unwrap();
        let mut packet = rx_packet(1, 0xcafe, 0);
        set_sku(&mut packet, [0x610d0, 0, 0]);
        complete(&boot, &domain, 0, 1, &packet);
        boot.poll().unwrap().unwrap();
        assert_eq!(domain.records.lock().unwrap().live.len(), 65);
        assert_eq!(
            unsafe { boot.begin_pnvm(&provider, observations, &source) }.unwrap(),
            PnvmProgress::Waiting
        );
        assert_eq!(domain.records.lock().unwrap().live.len(), 68);
        let receipts = boot.platform_receipts().unwrap();
        assert_eq!(receipts.pnvm_version, Some(0xe1c4fa8e));
        assert!(matches!(
            receipts.pnvm,
            calibration::Source::External {
                bios_fallback: None,
                ..
            }
        ));
        let memory = boot.ax210.as_ref().unwrap();
        let field = device_read(&domain, memory.scratch.region().address, 16, 16);
        assert_eq!(u32::from_le_bytes(field[8..12].try_into().unwrap()), 13652);
        complete(&boot, &domain, 1, 2, &pnvm_packet(0));
        assert_eq!(boot.poll_pnvm().unwrap(), PnvmProgress::Observed);
        assert_eq!(domain.records.lock().unwrap().live.len(), 68);
        boot.stop().unwrap();
        drop(boot);
        assert!(domain.records.lock().unwrap().live.is_empty());
        assert_eq!(
            source.calls.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
    }
    #[test]
    fn ax210_fragmented_wide_invalid_and_duplicate_completions_never_release_iml() {
        let bytes = ax210_bytes();
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        for mode in 0..5 {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = ax210_state();
            let drops = Arc::new(AtomicUsize::new(0));
            let mut boot = start_ax210(
                &catalog,
                super::super::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            );
            event(&state, 1);
            boot.poll().unwrap();
            let live = domain.records.lock().unwrap().live.len();
            match mode {
                0 => {
                    complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
                    device_write(&domain, boot.used.region().address, 6, &[1, 0], false);
                }
                1 | 2 => {
                    device_write(
                        &domain,
                        boot.used.region().address,
                        4,
                        &if mode == 1 { 0xffffu16 } else { 31u16 }.to_le_bytes(),
                        false,
                    );
                    device_write(
                        &domain,
                        boot.status.region().address,
                        0,
                        &1u16.to_le_bytes(),
                        false,
                    );
                }
                3 => {
                    complete(&boot, &domain, 0, 1, &rx_packet(2, 0xcafe, 0));
                    assert!(boot.poll().unwrap().is_none());
                    device_write(
                        &domain,
                        boot.used.region().address,
                        36,
                        &1u16.to_le_bytes(),
                        false,
                    );
                    device_write(
                        &domain,
                        boot.status.region().address,
                        0,
                        &2u16.to_le_bytes(),
                        false,
                    );
                }
                _ => {
                    complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
                    domain.records.lock().unwrap().cpu_sync_fail = Some(0);
                }
            }
            assert!(boot.poll().is_err(), "mode{mode}");
            assert_eq!(boot.state, State::Poisoned);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            boot.stop().unwrap();
            drop(boot);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    #[ignore = "requires pinned actual AX210 firmware; see THIRD_PARTY.md"]
    fn actual_ax210_image_iml_rom_rx_alive_preserves_pnvm_allocations() {
        use sha2::{Digest, Sha256};
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        let bytes =
            std::fs::read(std::path::Path::new(&root).join(Family::Ax210.firmware_name())).unwrap();
        let sha: alloc::string::String = Sha256::digest(&bytes)
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect();
        assert_eq!(
            sha,
            "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0"
        );
        let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = ax210_state();
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start_ax210(
            &catalog,
            super::super::platform::load_step(observation, &step_catalog).unwrap(),
            &source,
            &domain,
            &state,
            &drops,
        );
        assert_eq!(domain.records.lock().unwrap().live.len(), 97);
        let expected = boot.firmware.iml().unwrap();
        let memory = boot.ax210.as_ref().unwrap();
        assert_eq!(
            device_read(&domain, memory.iml.region().address, 0, expected.len()),
            expected
        );
        event(&state, 1);
        boot.poll().unwrap();
        complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
        let report = boot.poll().unwrap().unwrap();
        assert_eq!(report.notification_version, 6);
        assert_eq!(domain.records.lock().unwrap().live.len(), 65); // 31 transient + IML
        let memory = boot.ax210.as_ref().unwrap();
        for address in [
            memory.info.region().address,
            memory.scratch.region().address,
            boot.context.region().address,
        ] {
            assert!(
                domain
                    .records
                    .lock()
                    .unwrap()
                    .live
                    .contains_key(&id(address))
            );
        }
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            source.calls.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
    }
    #[test]
    fn actual_rom_pointer_csr_alive_restock_and_dma_alive_are_distinct_owned_states() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        let request = profile().firmware_request();
        let original = resources::Provider::load(&catalog, request.requirement()).unwrap();
        assert_eq!(boot.firmware_source().name(), request.name);
        assert_eq!(
            boot.firmware_source().target(),
            request.requirement().target
        );
        assert_eq!(boot.firmware_source().sha256(), original.sha256());
        assert_eq!(boot.firmware_source().provenance(), original.provenance());
        assert_eq!(
            boot.firmware_source().bytes().as_ptr(),
            original.bytes().as_ptr()
        );
        let context = device_read(&domain, boot.context.region().address, 0, 1792);
        assert_eq!(
            u64::from_le_bytes(context[24..32].try_into().unwrap()),
            boot.free.region().address
        );
        assert_eq!(
            u64::from_le_bytes(context[48..56].try_into().unwrap()),
            boot.command.region().address
        );
        {
            let locked = state.lock().unwrap();
            let registers = &locked.registers;
            assert_eq!(registers.get(&12), Some(&0));
            assert_eq!(registers.get(&0xd4), Some(&0x88fa88fa));
            assert_eq!(registers.get(&0x444), Some(&0x03005c44));
            assert_eq!(registers.get(&0x44c), Some(&1));
        }
        assert!(boot.poll().unwrap().is_none());
        assert_eq!(boot.state, State::Published);
        let live = domain.records.lock().unwrap().live.len();
        assert_eq!(boot.post_alive_plan(), Err(Error::State));
        event(&state, 1);
        assert!(boot.poll().unwrap().is_none());
        assert_eq!(boot.state, State::Restocked);
        assert_eq!(boot.credits, 24);
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        assert_eq!(state.lock().unwrap().registers.get(&0x1c80), Some(&24));
        for (n, buffer) in boot.buffers.iter().enumerate() {
            let raw = device_read(&domain, boot.free.region().address, n * 8, 8);
            assert_eq!(
                u64::from_le_bytes(raw.try_into().unwrap()),
                buffer.allocation.region().address | (n as u64 + 1)
            );
            assert_eq!(buffer.device_owned, n < 24);
        }
        complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
        event(&state, 1 << 31);
        let report = boot.poll().unwrap().unwrap();
        assert_eq!(report.sku, [0x610d0, 0x1234, 0x55667788]);
        assert_eq!(report.notification_version, 6);
        assert_eq!(boot.state, State::Alive);
        assert_eq!(
            boot.post_alive_plan().unwrap().pnvm,
            super::super::platform::PnvmSource::Bios {
                external_fallback: false
            }
        );
        assert_eq!(domain.records.lock().unwrap().cpu_syncs, 1);
        assert_eq!(domain.records.lock().unwrap().live.len(), live - 3);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            source.calls.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
    }
    #[test]
    fn duplicate_unsubmitted_wrong_queue_failed_alive_and_bad_producer_never_release_rom() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        for mode in 0..7 {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let mut boot = start(&catalog, &source, &domain, &state, &drops);
            let live = domain.records.lock().unwrap().live.len();
            event(&state, 1);
            boot.poll().unwrap();
            match mode {
                0 => {
                    complete(&boot, &domain, 0, 1, &rx_packet(2, 0xcafe, 0));
                    assert!(boot.poll().unwrap().is_none());
                    device_write(
                        &domain,
                        boot.used.region().address,
                        4,
                        &1u32.to_le_bytes(),
                        false,
                    );
                    device_write(
                        &domain,
                        boot.status.region().address,
                        0,
                        &2u16.to_le_bytes(),
                        false,
                    );
                }
                1 => {
                    device_write(
                        &domain,
                        boot.used.region().address,
                        0,
                        &31u32.to_le_bytes(),
                        false,
                    );
                    device_write(
                        &domain,
                        boot.status.region().address,
                        0,
                        &1u16.to_le_bytes(),
                        false,
                    );
                }
                2 => complete(&boot, &domain, 0, 1, &rx_packet(1, 0xdead, 0)),
                3 => complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 2)),
                4 => device_write(
                    &domain,
                    boot.status.region().address,
                    0,
                    &25u16.to_le_bytes(),
                    false,
                ),
                _ => {
                    device_write(
                        &domain,
                        boot.used.region().address,
                        0,
                        &(if mode == 5 { 0u32 } else { 1000 }).to_le_bytes(),
                        false,
                    );
                    device_write(
                        &domain,
                        boot.status.region().address,
                        0,
                        &1u16.to_le_bytes(),
                        false,
                    );
                }
            }
            assert!(boot.poll().is_err(), "mode{mode}");
            assert_eq!(boot.state, State::Poisoned);
            assert_eq!(domain.records.lock().unwrap().live.len(), live);
            boot.stop().unwrap();
            drop(boot);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn failed_stop_ack_and_partial_invalidation_retain_actual_owner_and_allow_retry() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        for fail in 0..42 {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let mut boot = start(&catalog, &source, &domain, &state, &drops);
            domain.records.lock().unwrap().unmap_fail = Some(fail);
            assert!(
                matches!(
                    boot.stop(),
                    Err(Error::Dma(dma::Error::Dma(
                        crate::bus::dma::mapping::DmaError::InvalidationFailed
                    )))
                ),
                "unmap{fail}"
            );
            assert_eq!(boot.state, State::Quiescent);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            boot.stop().unwrap();
            assert!(domain.records.lock().unwrap().live.is_empty());
            drop(boot);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        state.lock().unwrap().stop_ack = false;
        let live = domain.records.lock().unwrap().live.len();
        assert!(matches!(
            boot.stop(),
            Err(Error::Timeout { register: 0x20 })
        ));
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        state.lock().unwrap().stop_ack = true;
        boot.stop().unwrap();
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn every_allocation_map_and_visibility_failure_before_pointer_publication_releases() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        for stage in 0..3 {
            for fail in 0..if stage == 2 { 43 } else { 42 } {
                let source = Source {
                    fail_at: (stage == 0).then_some(fail),
                    ..Default::default()
                };
                let domain = Arc::new(Domain {
                    records: Mutex::new(Records {
                        map_fail: (stage == 1).then_some(fail),
                        sync_fail: (stage == 2).then_some(fail),
                        ..Default::default()
                    }),
                });
                let state = Arc::new(Mutex::new(ModelState::default()));
                let drops = Arc::new(AtomicUsize::new(0));
                let result = unsafe {
                    Ax200Boot::start(
                        awake(state.clone(), drops.clone()),
                        super::super::identity::stage(&profile(), &catalog).unwrap(),
                        &source,
                        Some(domain.clone()),
                        32,
                    )
                };
                assert!(
                    matches!(
                        (&result, stage),
                        (
                            Err(Error::Dma(dma::Error::Memory(
                                crate::bus::dma::memory::MemoryError::OutOfMemory
                            ))),
                            0
                        ) | (
                            Err(Error::Dma(dma::Error::Dma(
                                crate::bus::dma::mapping::DmaError::MappingFailed
                            ))),
                            1
                        ) | (
                            Err(Error::Dma(dma::Error::Dma(
                                crate::bus::dma::mapping::DmaError::VisibilityFailed
                            ))),
                            2
                        )
                    ),
                    "stage{stage} fail{fail}"
                );
                assert!(domain.records.lock().unwrap().live.is_empty());
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                assert!(
                    !state
                        .lock()
                        .unwrap()
                        .ops
                        .iter()
                        .any(|op| matches!(op, Op::Write(0x40, _)))
                );
            }
        }
    }
    #[test]
    fn every_csr_start_failure_after_first_possible_publication_quarantines_bar_and_dma() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        let ops = state.lock().unwrap().ops.clone();
        let publication = ops
            .iter()
            .position(|op| matches!(op, Op::Write(0x40, _)))
            .unwrap();
        boot.stop().unwrap();
        drop(boot);
        for fail in 0..ops.len() {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let power = awake(state.clone(), drops.clone());
            state.lock().unwrap().fail = Some(fail);
            let result = unsafe {
                Ax200Boot::start(
                    power,
                    super::super::identity::stage(&profile(), &catalog).unwrap(),
                    &source,
                    Some(domain.clone()),
                    32,
                )
            };
            assert!(
                matches!(result, Err(Error::Access(power::AccessError::Unavailable))),
                "operation{fail}"
            );
            if fail < publication {
                assert!(domain.records.lock().unwrap().live.is_empty());
                assert_eq!(drops.load(Ordering::Relaxed), 1);
            } else {
                assert!(!domain.records.lock().unwrap().live.is_empty());
                assert_eq!(drops.load(Ordering::Relaxed), 0);
            }
        }
    }
    #[test]
    fn failed_csr_read_sentinels_and_cpu_visibility_never_become_alive() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        let ops = state.lock().unwrap().ops.clone();
        boot.stop().unwrap();
        drop(boot);
        for (index, op) in ops.iter().enumerate() {
            if !matches!(op, Op::Read(_)) {
                continue;
            }
            for value in [u32::MAX, 0xa5a5a5a0, 0x5a5a5a5f] {
                let source = Source::default();
                let domain = Arc::new(Domain::default());
                let state = Arc::new(Mutex::new(ModelState::default()));
                let drops = Arc::new(AtomicUsize::new(0));
                let power = awake(state.clone(), drops.clone());
                state.lock().unwrap().sentinel = Some((index, value));
                let result = unsafe {
                    Ax200Boot::start(
                        power,
                        super::super::identity::stage(&profile(), &catalog).unwrap(),
                        &source,
                        Some(domain),
                        32,
                    )
                };
                assert!(matches!(result,Err(Error::FailedRead{value:actual,..}) if actual==value));
            }
        }
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        event(&state, 1);
        boot.poll().unwrap();
        let live = domain.records.lock().unwrap().live.len();
        complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
        domain.records.lock().unwrap().cpu_sync_fail = Some(0);
        assert!(matches!(
            boot.poll(),
            Err(Error::Dma(dma::Error::Dma(
                crate::bus::dma::mapping::DmaError::VisibilityFailed
            )))
        ));
        assert_eq!(domain.records.lock().unwrap().live.len(), live);
        boot.stop().unwrap();
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    #[ignore = "requires pinned actual AX200 firmware; see THIRD_PARTY.md"]
    fn actual_ax200_image_publishes_owned_context_and_consumes_completed_alive() {
        use sha2::{Digest, Sha256};
        let directory = std::env::var("STELA_IWLWIFI_IMAGES").expect("image directory");
        let bytes =
            std::fs::read(std::path::Path::new(&directory).join(Family::Ax200.firmware_name()))
                .unwrap();
        let sha: alloc::string::String = Sha256::digest(&bytes)
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect();
        assert_eq!(
            sha,
            "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
        );
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = Arc::new(Mutex::new(ModelState::default()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut boot = start(&catalog, &source, &domain, &state, &drops);
        let live = domain.records.lock().unwrap().live.len();
        assert_eq!(live, 86);
        event(&state, 1);
        assert!(boot.poll().unwrap().is_none());
        complete(&boot, &domain, 0, 1, &rx_packet(1, 0xcafe, 0));
        assert_eq!(
            boot.poll().unwrap().unwrap().sku,
            [0x610d0, 0x1234, 0x55667788]
        );
        assert_eq!(domain.records.lock().unwrap().live.len(), live - 30);
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
        drop(boot);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            source.calls.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
    }
    #[test]
    fn missing_domain_invalid_ring_size_and_unwoken_epoch_allocate_nothing() {
        let bytes = firmware_bytes();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        for mode in 0..3 {
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let power = if mode == 2 {
                Power::new(
                    Model {
                        state: state.clone(),
                        _owner: Owner(drops.clone()),
                    },
                    profile(),
                )
            } else {
                awake(state, drops.clone())
            };
            let result = unsafe {
                Ax200Boot::start(
                    power,
                    super::super::identity::stage(&profile(), &catalog).unwrap(),
                    &source,
                    if mode == 0 {
                        None
                    } else {
                        Some(domain.clone())
                    },
                    if mode == 1 { 7 } else { 32 },
                )
            };
            assert!(matches!(
                (&result, mode),
                (
                    Err(Error::Dma(dma::Error::Dma(
                        crate::bus::dma::mapping::DmaError::IommuUnavailable
                    ))),
                    0
                ) | (Err(Error::QueueSize), 1)
                    | (Err(Error::Power(power::Error::State)), 2)
            ));
            assert_eq!(source.calls.load(Ordering::Relaxed), 0);
            assert_eq!(domain.records.lock().unwrap().maps, 0);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn staged_profile_diagnostic_name_board_and_driver_swaps_refuse_before_io_or_dma() {
        struct Redirect<'p>(resources::Image<'p>);
        impl resources::Provider for Redirect<'_> {
            fn load<'p>(
                &'p self,
                _: resources::Requirement<'_>,
            ) -> Result<resources::Image<'p>, resources::Error> {
                Ok(self.0)
            }
        }
        let bytes = firmware_bytes();
        for mode in 0..6 {
            let mut observed = profile().observed();
            if mode == 0 {
                observed.subsystem_device ^= 1;
            }
            if mode == 1 {
                observed.pci_revision ^= 1;
            }
            let other = Profile::select(observed).unwrap();
            let request = other.firmware_request();
            let mut target = request.requirement().target;
            if mode == 3 {
                target.board = Some("different-board");
            }
            if mode == 4 {
                target.driver = "diagnostic-driver";
            }
            if mode == 5 {
                target.revision = "different-raw-revision";
            }
            let name = if mode == 2 {
                "intel-diagnostic.ucode"
            } else {
                request.name
            };
            let catalog = catalog_for_target(target, name, &bytes);
            let image = resources::Provider::load(
                &catalog,
                resources::Requirement {
                    name,
                    target,
                    minimum_bytes: 1,
                },
            )
            .unwrap();
            let provider = Redirect(image);
            let staged = super::super::identity::stage(&other, &provider).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let power = awake(state.clone(), drops.clone());
            let result =
                unsafe { Ax200Boot::start(power, staged, &source, Some(domain.clone()), 32) };
            assert!(matches!(result, Err(Error::FirmwareBinding)), "swap{mode}");
            assert_eq!(source.calls.load(Ordering::Relaxed), 0);
            assert_eq!(domain.records.lock().unwrap().maps, 0);
            assert!(state.lock().unwrap().ops.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    struct RadioBios {
        drops: Arc<AtomicUsize>,
        unavailable: bool,
        absent: bool,
    }
    impl Drop for RadioBios {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    // SAFETY: this peripheral model executes exact namespace reads for the
    // same modeled function; production service attachment remains external.
    unsafe impl super::super::radio::bios::service::BiosIo for RadioBios {
        fn evaluate(
            &mut self,
            request: super::super::radio::bios::service::Request,
        ) -> Result<
            super::super::radio::bios::service::Object,
            super::super::radio::bios::service::IoError,
        > {
            use super::super::radio::bios::service::{IoError, Object, Request};
            if self.unavailable {
                return Err(IoError::Unavailable);
            }
            if self.absent {
                return Err(IoError::NotFound);
            }
            assert_eq!(request, Request::Glai);
            Ok(Object::Package(vec![
                Object::Integer(0),
                Object::Package(vec![Object::Integer(7), Object::Integer(1)]),
            ]))
        }
        fn variable(
            &mut self,
            variable: super::super::platform::Variable,
        ) -> Result<Vec<u8>, super::super::radio::bios::service::IoError> {
            use super::super::platform::Variable;
            if self.absent {
                return Err(super::super::radio::bios::service::IoError::NotFound);
            }
            Ok(match variable {
                Variable::GeneralConfiguration => {
                    let mut raw = vec![4];
                    for i in 0..32u32 {
                        raw.extend(if i == 0 { u32::MAX } else { i }.to_le_bytes());
                    }
                    raw
                }
                Variable::Wbem => vec![0, 3, 0, 0, 0],
                _ => panic!("unrequested source"),
            })
        }
    }
    fn lari_bytes(ax210: bool, schema: u8) -> Vec<u8> {
        let mut bytes = radio_bytes(ax210);
        let mut at = 88;
        while at < bytes.len() {
            let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
            if kind == 48 {
                bytes.splice(at + 8 + len..at + 8 + len, [1, 12, schema, 0, 8, 12, 1, 0]);
                bytes[at + 4..at + 8].copy_from_slice(&((len + 8) as u32).to_le_bytes());
                break;
            }
            at += 8 + len.next_multiple_of(4);
        }
        bytes
    }
    fn drive_cold_prefix<'a>(
        init: UnifiedNvm<'a, Model>,
        source: &Source,
        domain: &Domain,
    ) -> (ColdRadio<'a, Model>, u16, u16) {
        let expected = super::super::radio::InitialPlan::prepare(
            &init.boot.firmware,
            init.boot.profile.family(),
            &init.receipt().unwrap().information,
        )
        .unwrap();
        let mut radio = init.begin_radio().unwrap_or_else(|_| panic!("actual NVM"));
        unsafe { radio.advance(source) }.unwrap();
        for (i, command) in expected.commands().iter().enumerate() {
            let mut id = command.id();
            if id.group == 0 {
                id.group = 1;
            }
            complete(
                &radio.initialized.boot,
                domain,
                5 + i as u16,
                6 + i as u16,
                &command_packet(id, 3 + i as u16, &[]),
            );
            unsafe { radio.advance(source) }.unwrap();
        }
        assert_eq!(radio.phase(), ColdRadioPhase::PlatformConfigurationRequired);
        let count = expected.commands().len() as u16;
        (radio, 3 + count, 5 + count)
    }
    #[test]
    fn lari_actual_bios_source_commands_and_dma_retirement_both_families() {
        exercise_lari_bios(false);
    }
    #[test]
    #[ignore = "requires actual pinned Intel firmware images"]
    fn lari_actual_images_drive_lari6_without_extension_and_lari8_with_extension() {
        exercise_lari_bios(true);
    }
    fn exercise_lari_bios(actual: bool) {
        for ax210 in [false, true] {
            let profile = if ax210 { ax210_profile() } else { profile() };
            let bytes = if actual {
                use sha2::{Digest, Sha256};
                let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
                let bytes = std::fs::read(
                    std::path::Path::new(&root).join(profile.family().firmware_name()),
                )
                .unwrap();
                assert_eq!(
                    std::format!("{:x}", Sha256::digest(&bytes)),
                    if ax210 {
                        "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0"
                    } else {
                        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
                    }
                );
                bytes
            } else {
                lari_bytes(ax210, if ax210 { 12 } else { 6 })
            };
            let expected_ids = if actual && !ax210 {
                vec![1]
            } else {
                vec![8, 1]
            };
            let catalog = catalog_for(&profile, profile.family().firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = if ax210 {
                ax210_state()
            } else {
                Arc::new(Mutex::new(ModelState::default()))
            };
            let drops = Arc::new(AtomicUsize::new(0));
            let bios_drops = Arc::new(AtomicUsize::new(0));
            let (observation, step_catalog) = step_fixture();
            let boot = if ax210 {
                start_ax210(
                    &catalog,
                    super::super::platform::load_step(observation, &step_catalog).unwrap(),
                    &source,
                    &domain,
                    &state,
                    &drops,
                )
            } else {
                start(&catalog, &source, &domain, &state, &drops)
            };
            let boot = command_ready(boot, &empty, &source, &domain, &state);
            let init = drive_nvm(boot, &source, &domain, &state);
            let cold = init.begin_radio().unwrap_or_else(|_| panic!("actual NVM"));
            let before = state.lock().unwrap().ops.len();
            let rejected = unsafe {
                cold.begin_lari(RadioBios {
                    drops: bios_drops.clone(),
                    unavailable: false,
                    absent: false,
                })
            }
            .err()
            .unwrap();
            assert_eq!(state.lock().unwrap().ops.len(), before);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
            let (mut cold, bios) = *rejected;
            // Resume the original owner, without copying its initialization.
            let expected = super::super::radio::InitialPlan::prepare(
                &cold.initialized.boot.firmware,
                profile.family(),
                &cold.initialized_nvm().information,
            )
            .unwrap();
            unsafe { cold.advance(&source) }.unwrap();
            for (i, command) in expected.commands().iter().enumerate() {
                let mut id = command.id();
                if id.group == 0 {
                    id.group = 1;
                }
                complete(
                    &cold.initialized.boot,
                    &domain,
                    5 + i as u16,
                    6 + i as u16,
                    &command_packet(id, 3 + i as u16, &[]),
                );
                unsafe { cold.advance(&source) }.unwrap();
            }
            let mut lari =
                unsafe { cold.begin_lari(bios) }.unwrap_or_else(|_| panic!("real prefix"));
            assert_eq!(
                unsafe { lari.advance(&source) }.unwrap(),
                LariPhase::Waiting {
                    command: expected_ids[0]
                }
            );
            let commands: Vec<_> = lari
                .plan()
                .unwrap()
                .commands()
                .map(|(id, b)| (id, b.to_vec()))
                .collect();
            assert_eq!(
                commands.iter().map(|(id, _)| id.opcode).collect::<Vec<_>>(),
                expected_ids
            );
            assert_eq!(
                lari.plan().unwrap().schema(),
                if ax210 {
                    if actual { 8 } else { 12 }
                } else {
                    6
                }
            );
            assert_eq!(lari.platform_reads().len(), 3); // actual GLAI, GeneralCfg, WBEM
            let mut copied = lari.plan().unwrap().clone();
            let copied_inputs = *copied.inputs();
            copied = super::super::radio::lari::Plan::prepare(
                &lari.radio.initialized.boot.firmware,
                0,
                copied_inputs,
            )
            .unwrap();
            assert_eq!(copied.commands().count(), commands.len()); // no owner/advancement authority
            let base = expected.commands().len() as u16;
            for (i, (id, payload)) in commands.iter().enumerate() {
                let sequence = 3 + base + i as u16;
                let boot = &lari.radio.initialized.boot;
                let descriptor = device_read(
                    &domain,
                    boot.command.region().address,
                    usize::from(sequence) * 256,
                    256,
                );
                let first = u64::from_le_bytes(descriptor[4..12].try_into().unwrap());
                let encoded =
                    super::super::command::Command::encode(*id, 0, sequence, payload).unwrap();
                let mut emitted = device_read(&domain, first, 0, encoded.bytes().len().min(20));
                if encoded.bytes().len() > 20 {
                    let rest = u64::from_le_bytes(descriptor[14..22].try_into().unwrap());
                    emitted.extend(device_read(&domain, rest, 0, encoded.bytes().len() - 20));
                }
                assert_eq!(emitted, encoded.bytes());
                let bell = state.lock().unwrap().registers[&0x460];
                assert_eq!(
                    unsafe { lari.advance(&source) }.unwrap(),
                    LariPhase::Waiting { command: id.opcode }
                );
                assert_eq!(state.lock().unwrap().registers[&0x460], bell);
                complete(
                    &lari.radio.initialized.boot,
                    &domain,
                    5 + base + i as u16,
                    6 + base + i as u16,
                    &command_packet(*id, sequence, &[0xa5 + i as u8]),
                );
                if i == 0 {
                    let mut r = domain.records.lock().unwrap();
                    r.cpu_sync_fail = Some(r.cpu_syncs + 1);
                    drop(r);
                    assert!(matches!(
                        unsafe { lari.advance(&source) },
                        Err(LariError::Boot(Error::CommandReclaim(_)))
                    ));
                    assert_eq!(lari.phase(), LariPhase::Waiting { command: id.opcode });
                    assert_eq!(state.lock().unwrap().registers[&0x460], bell);
                    domain.records.lock().unwrap().cpu_sync_fail = None;
                }
                assert_eq!(
                    unsafe { lari.advance(&source) }.unwrap(),
                    commands
                        .get(i + 1)
                        .map_or(LariPhase::RxQueueConfigurationRequired, |(id, _)| {
                            LariPhase::Waiting { command: id.opcode }
                        })
                );
            }
            assert_eq!(lari.responses().len(), commands.len());
            for (i, response) in lari.responses().iter().enumerate() {
                assert_eq!(response.raw, [0xa5 + i as u8]);
            }
            let ops = state.lock().unwrap().ops.len();
            assert_eq!(
                unsafe { lari.advance(&source) }.unwrap(),
                LariPhase::RxQueueConfigurationRequired
            );
            assert_eq!(state.lock().unwrap().ops.len(), ops);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
            lari.stop().unwrap();
            drop(lari);
            assert!(domain.records.lock().unwrap().live.is_empty());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn lari_schema_missing_services_rfkill_and_uncertain_command_keep_original_owner() {
        for case in 0..7 {
            let bytes = lari_bytes(false, if case == 0 { 99 } else { 6 });
            let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
            let empty = resources::Catalog::from_handoff(vec![]).unwrap();
            let source = Source::default();
            let domain = Arc::new(Domain::default());
            let state = Arc::new(Mutex::new(ModelState::default()));
            let drops = Arc::new(AtomicUsize::new(0));
            let bios_drops = Arc::new(AtomicUsize::new(0));
            let boot = start(&catalog, &source, &domain, &state, &drops);
            let boot = command_ready(boot, &empty, &source, &domain, &state);
            let init = drive_nvm(boot, &source, &domain, &state);
            let (cold, sequence, entry) = drive_cold_prefix(init, &source, &domain);
            let mut lari = unsafe {
                cold.begin_lari(RadioBios {
                    drops: bios_drops.clone(),
                    unavailable: case == 1,
                    absent: case == 6,
                })
            }
            .unwrap_or_else(|_| panic!("prefix"));
            let ops = state.lock().unwrap().ops.len();
            let allocations = source.calls.load(Ordering::Relaxed);
            if case == 2 {
                *state.lock().unwrap().registers.get_mut(&0x24).unwrap() &= !0x08000000;
            }
            if case == 4 {
                let mut r = domain.records.lock().unwrap();
                r.sync_fail = Some(r.syncs + 2);
            }
            let result = unsafe { lari.advance(&source) };
            match case {
                0 => {
                    assert_eq!(
                        result,
                        Err(LariError::Plan(super::super::radio::lari::Error::Version(
                            99
                        )))
                    );
                    assert!(lari.platform_reads().is_empty());
                }
                1 => {
                    use super::super::radio::bios::service::{
                        Error as BiosError, IoError, Request,
                    };
                    assert_eq!(
                        result,
                        Err(LariError::Platform(BiosError::IncompleteAcpi(
                            Request::Glai,
                            IoError::Unavailable
                        )))
                    );
                }
                2 => assert_eq!(result, Err(LariError::Boot(Error::RfKilled))),
                3 => {
                    result.unwrap();
                    complete(
                        &lari.radio.initialized.boot,
                        &domain,
                        entry,
                        entry + 1,
                        &command_packet(
                            super::super::command::Id {
                                group: 12,
                                opcode: 1,
                                version: 0,
                            },
                            sequence,
                            &[0xde, 0xad, 0, 0xff],
                        ),
                    );
                    assert_eq!(
                        unsafe { lari.advance(&source) },
                        Err(LariError::Boot(Error::InitializationResponse {
                            group: 12,
                            command: 1
                        }))
                    );
                    assert_eq!(lari.responses().len(), 1);
                    let response = &lari.responses()[0];
                    assert_eq!(response.raw, [0xde, 0xad, 0, 0xff]);
                    assert_eq!((response.command, response.group), (1, 12));
                    assert_eq!((response.request.opcode, response.request.group), (8, 12));
                    assert_eq!(response.ticket.sequence(), sequence);
                    let doorbell = state.lock().unwrap().registers[&0x460];
                    assert_eq!(
                        unsafe { lari.advance(&source) },
                        Err(LariError::Boot(Error::State))
                    );
                    assert_eq!(state.lock().unwrap().registers[&0x460], doorbell);
                    assert_eq!(lari.responses().len(), 1);
                }
                4 => {
                    assert!(matches!(result, Err(LariError::Boot(Error::Dma(_)))));
                }
                5 => {
                    result.unwrap();
                }
                6 => {
                    assert_eq!(result, Ok(LariPhase::RxQueueConfigurationRequired));
                    assert_eq!(lari.plan().unwrap().commands().count(), 0);
                    assert!(lari.responses().is_empty());
                    assert_eq!(state.lock().unwrap().ops.len(), ops);
                    assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
                }
                _ => unreachable!(),
            }
            if case <= 1 {
                assert_eq!(state.lock().unwrap().ops.len(), ops);
                assert_eq!(source.calls.load(Ordering::Relaxed), allocations);
            }
            if case == 4 || case == 5 {
                if case == 5 {
                    let mut s = state.lock().unwrap();
                    s.fail = Some(s.ops.len() + 1);
                    drop(s);
                    assert!(lari.stop().is_err());
                }
                let live = domain.records.lock().unwrap().live.len();
                assert!(live > 0);
                drop(lari);
                assert_eq!(bios_drops.load(Ordering::Relaxed), 0);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
                assert_eq!(domain.records.lock().unwrap().live.len(), live);
            } else {
                assert_eq!(
                    lari.phase(),
                    if case == 6 {
                        LariPhase::RxQueueConfigurationRequired
                    } else {
                        LariPhase::Failed
                    }
                );
                let rejected = (case == 3).then(|| lari.responses()[0].clone());
                lari.stop().unwrap();
                if let Some(original) = rejected {
                    assert_eq!(lari.responses(), [original]);
                }
                drop(lari);
                assert_eq!(bios_drops.load(Ordering::Relaxed), 1);
                assert_eq!(drops.load(Ordering::Relaxed), 1);
            }
        }
    }
    // Kept with the original boot peripheral model: these cases exercise the
    // same physical-owner/DMA epoch through post-LARI command retirement.
    mod ax200_scan_tests;
    mod ax200_tests;
}
