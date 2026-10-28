// SPDX-License-Identifier: GPL-2.0-only
//! One actual native epoch. IRQ callbacks mask; a sole process owner speaks IPC.
use super::{
    descriptor,
    protocol::{Engine, Frame},
    registers::*,
    *,
};
use crate::{
    Clock,
    bus::{
        dma::mapping::DmaDomain,
        irq::{
            self, Disposition, Handler, IrqController, IrqRegistration, Route, RouteRequest, Source,
        },
        pci::{
            Address, CapabilityError, Function, Layout,
            msi::{self, DisabledMsiConfig, MsiConfig, MsiConfigSpace, RetainedOwner},
            owned::OwnedConfig,
        },
    },
};
use alloc::{boxed::Box, rc::Rc, sync::Arc, vec::Vec};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

/// Actual retained original config owner, or the explicit native register peer.
/// # Safety
/// Native reads/writes use the sole original config mapping and real BDF under
/// its exclusive reset/resource/root epoch; no alias/config writer may race.
pub unsafe trait Configuration: MsiConfigSpace + 'static {
    fn owned_address(&self) -> Address;
}
// SAFETY: OwnedConfig supplies actual original exclusive mapped native config.
unsafe impl Configuration for OwnedConfig {
    fn owned_address(&self) -> Address {
        self.address()
    }
}
/// Actual monotonic advancing native clock, or an explicit advancing model.
/// # Safety
/// Includes time spent in native register/config/domain operations, never
/// regresses, and advances in every admitted process/deferred wait context.
pub unsafe trait Time: 'static {
    fn now_us(&self) -> u64;
}
pub struct NativeClock(Clock);
impl NativeClock {
    /// # Safety
    /// This is the platform's calibrated invariant, advancing TSC on the owning
    /// CPU. A rate number alone establishes none of those native facts.
    pub unsafe fn new(clock: Clock) -> Result<Self> {
        if clock.ticks_per_microsecond == 0 {
            return Err(Error::Requirement("qualified advancing native TSC"));
        }
        Ok(Self(clock))
    }
}
// SAFETY: constructor requires the actual calibrated invariant monotonic clock.
unsafe impl Time for NativeClock {
    fn now_us(&self) -> u64 {
        self.0.now_us()
    }
}

pub struct Inputs<
    C: Configuration = OwnedConfig,
    R: Registers = MappedRegisters,
    T: Time = NativeClock,
> {
    pub function: Function<C>,
    pub retained: RetainedOwner,
    pub registers: R,
    pub domain: Arc<dyn DmaDomain>,
    pub interrupts: &'static dyn IrqController,
    pub clock: T,
}
struct Signals {
    pending: AtomicBool,
    /// Register+1 of the first IRQ access/readback failure. This diagnostic does
    /// not fabricate a process-context copy of an arbitrary backend error.
    fault: AtomicU32,
    ever_armed: AtomicBool,
    terminal: AtomicBool,
}
struct Shared<R: Registers> {
    registers: R,
    signals: Signals,
    mask: u32,
    enabled: u32,
}
impl<R: Registers> Shared<R> {
    fn mask(&self) -> Result<()> {
        store(&self.registers, PIMR, self.mask)
    }
    fn irq_fault(&self, at: u32) {
        let _ = self
            .signals
            .fault
            .compare_exchange(0, at + 1, Ordering::AcqRel, Ordering::Acquire);
        self.signals.pending.store(true, Ordering::Release);
    }
    fn fault(&self) -> Result<()> {
        let at = self.signals.fault.load(Ordering::Acquire);
        if at != 0 {
            Err(Error::Access(at - 1))
        } else {
            Ok(())
        }
    }
}
struct Callback<R: Registers>(Arc<Shared<R>>);
impl<R: Registers> Handler for Callback<R> {
    fn handle(&self) -> Disposition {
        let s = &self.0;
        let cause = match read(&s.registers, PISR) {
            Ok(v) => v,
            Err(_) => {
                s.irq_fault(PISR);
                let _ = s.mask();
                return Disposition::Handled;
            }
        };
        let doorbell = match read(&s.registers, I2H) {
            Ok(v) => v,
            Err(_) => {
                s.irq_fault(I2H);
                let _ = s.mask();
                return Disposition::Handled;
            }
        };
        if cause == 0 && doorbell & BUSY == 0 {
            return Disposition::NotMine;
        }
        // Sole IRQ register write is this immutable exact mask, never an RMW.
        if s.mask().is_err() {
            s.irq_fault(PIMR);
        }
        s.signals.pending.store(true, Ordering::Release);
        Disposition::Handled
    }
}
struct ConfigState<C: Configuration> {
    msi: MsiConfig<C>,
    disabled: Option<DisabledMsiConfig<C>>,
    failure: Option<Error>,
}
struct NativeSource<C: Configuration, R: Registers> {
    config: Rc<RefCell<ConfigState<C>>>,
    shared: Arc<Shared<R>>,
}
// SAFETY: fresh admission is independently stopped/drained. After any route
// programming this source cannot claim posted-MSI completion: quiesce refuses
// and every owner stays retained. No inferred barrier grants route reuse.
unsafe impl<C: Configuration, R: Registers> Source for NativeSource<C, R> {
    fn mask(&mut self) -> core::result::Result<(), irq::IrqError> {
        let result = (|| {
            self.shared.mask()?;
            let mut c = self.config.borrow_mut();
            if c.disabled.is_none() {
                c.msi.mask().map_err(Error::Msi)?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            self.config.borrow_mut().failure.get_or_insert(e);
            return Err(irq::IrqError::Mask);
        }
        Ok(())
    }
    fn quiesce(&mut self) -> core::result::Result<(), irq::IrqError> {
        if self.shared.signals.ever_armed.load(Ordering::Acquire) {
            Err(irq::IrqError::Drain)
        } else {
            Ok(())
        }
    }
    fn route(&self) -> RouteRequest {
        RouteRequest::Msi
    }
    unsafe fn program(&mut self, route: Route) -> core::result::Result<(), irq::IrqError> {
        let Route::Msi(message) = route else {
            return Err(irq::IrqError::Route);
        };
        self.shared
            .signals
            .ever_armed
            .store(true, Ordering::Release);
        // SAFETY: exact typed route is owned and published by the actual registry.
        let result = { unsafe { self.config.borrow_mut().msi.program(message) } };
        result.map_err(|e| {
            self.config
                .borrow_mut()
                .failure
                .get_or_insert(Error::Msi(e));
            irq::IrqError::Route
        })
    }
    unsafe fn unmask(&mut self) -> core::result::Result<(), irq::IrqError> {
        if self.shared.signals.terminal.load(Ordering::Acquire) {
            return Err(irq::IrqError::Mask);
        }
        // The controller remains masked until the sole process starts IPC.
        // SAFETY: registry retains its actual callback/route and original owners.
        let result = { unsafe { self.config.borrow_mut().msi.unmask() } };
        result.map_err(|e| {
            self.config
                .borrow_mut()
                .failure
                .get_or_insert(Error::Msi(e));
            irq::IrqError::Mask
        })
    }
    unsafe fn synchronize(&mut self) -> core::result::Result<(), irq::IrqError> {
        self.quiesce()
    }
}

pub struct Native<
    C: Configuration = OwnedConfig,
    R: Registers = MappedRegisters,
    T: Time = NativeClock,
> {
    function: Option<Function<C>>,
    retained: Option<RetainedOwner>,
    domain: Option<Arc<dyn DmaDomain>>,
    shared: Option<Arc<Shared<R>>>,
    config: Option<Rc<RefCell<ConfigState<C>>>>,
    registration: Option<Box<dyn IrqRegistration>>,
    interrupts: &'static dyn IrqController,
    clock: T,
    engine: Engine,
    revision: u8,
    started: bool,
    running: bool,
    accept_reset: bool,
    reset_ready: bool,
    reset_generation: u64,
    stop_attempted: bool,
    failure: Option<Error>,
    cleanup_failure: Option<Error>,
    identity: Option<FirmwareIdentity>,
}
impl<C: Configuration, R: Registers, T: Time> Native<C, R, T> {
    /// # Safety
    /// Inputs retain the actual exclusive native9d35 endpoint, original config,
    /// complete UC BAR0, powered D0 root/resource/reset/firmware epoch and the
    /// requester's DMA domain, isolated or the passthrough domain, meeting the
    /// `DmaDomain` contract for its kind. No old DMA/postedMSI, IRQ/worker, alias,
    /// firmware or reset/removal user remains; this is independently drained,
    /// never inferred from disabled bits. MSI routing is genuinely qualified.
    /// The same retained root producer has examined the complete actual PCI
    /// inventory and excluded Intel a309/a30a Mehlow platforms, as original
    /// Linux probe requires. This constructor cannot establish that global fact;
    /// local IDs, a boolean or numeric token cannot substitute. No automatic
    /// producer or attachment is implied. One owning-CPU process serializes all
    /// service/stop; only the documented IRQ callback accesses shared registers.
    /// Clock/domain/native access contracts remain valid for every retained owner.
    /// Rejection returns exact original owners without any native write.
    #[allow(clippy::result_large_err)]
    pub unsafe fn new(
        mut inputs: Inputs<C, R, T>,
    ) -> core::result::Result<Self, (Error, Inputs<C, R, T>)> {
        let validation = (|| {
            let f = &mut inputs.function;
            let owned = f.config().owned_address();
            if f.vendor != 0x8086 || f.device != 0x9d35 || f.address != owned {
                return Err(Error::Requirement("actual retained 8086:9d35 endpoint"));
            }
            let c = f.config();
            let id = c.read32(0);
            let class = c.read32(8);
            let subsystem = c.read32(0x2c);
            if id != 0x9d35_8086
                || class == u32::MAX
                || subsystem == u32::MAX
                || c.read8(0x0e) & 0x7f != 0
            {
                return Err(Error::Requirement(
                    "readable same native endpoint identity/header",
                ));
            }
            if class >> 8 != 0x118000 {
                return Err(Error::Requirement("SPT ISH signal-processing class"));
            }
            validate_capabilities(c)?;
            let command = c.read16(4);
            if command == u16::MAX || command & 4 != 0 || command & 0x400 == 0 || command & 2 == 0 {
                return Err(Error::Requirement(
                    "independently stopped BM-off MEM-enabled INTx-disabled source",
                ));
            }
            let low = c.read32(0x10);
            if low == u32::MAX || low & 9 != 0 || !matches!(low & 6, 0 | 4) {
                return Err(Error::Requirement("ordinary nonprefetchable memory BAR0"));
            }
            let high = if low & 4 != 0 {
                let h = c.read32(0x14);
                if h == u32::MAX {
                    return Err(Error::Config(0x14));
                }
                h
            } else {
                0
            };
            let base = u64::from(low & !15) | (u64::from(high) << 32);
            let span = inputs.registers.span();
            if base == 0 || span.start() != base || span.bytes() < 0x400 {
                return Err(Error::Requirement("same actual complete BAR0 mapping"));
            }
            if read(&inputs.registers, PIMR)? & IRQ_ENABLE != 0
                || read(&inputs.registers, RMP2)? != 0
                || read(&inputs.registers, FWSTS)? & IN_DMA != 0
                || read(&inputs.registers, HOST_COMM)? & 0x80 != 0
                || read(&inputs.registers, H2I)? & BUSY != 0
                || read(&inputs.registers, I2H)? & BUSY != 0
            {
                return Err(Error::Requirement(
                    "actual inactive controller and acknowledged initial DMA state",
                ));
            }
            let fw = read(&inputs.registers, FWSTS)?;
            if !matches!((fw >> 12) & 15, 4 | 7 | 8 | 15) {
                return Err(Error::Requirement("resident firmware observed state"));
            }
            let base_mask = read(&inputs.registers, PIMR)? & !(IRQ_ENABLE | BUSY_CLEAR);
            Ok((class as u8, base_mask))
        })();
        let (revision, mask) = match validation {
            Ok(v) => v,
            Err(e) => return Err((e, inputs)),
        };
        let Inputs {
            function,
            retained,
            registers,
            domain,
            interrupts,
            clock,
        } = inputs;
        Ok(Self {
            function: Some(function),
            retained: Some(retained),
            domain: Some(domain),
            shared: Some(Arc::new(Shared {
                registers,
                signals: Signals {
                    pending: AtomicBool::new(false),
                    fault: AtomicU32::new(0),
                    ever_armed: AtomicBool::new(false),
                    terminal: AtomicBool::new(false),
                },
                mask,
                enabled: mask | IRQ_ENABLE,
            })),
            config: None,
            registration: None,
            interrupts,
            clock,
            engine: Engine::new(),
            revision,
            started: false,
            running: false,
            accept_reset: false,
            reset_ready: false,
            reset_generation: 0,
            stop_attempted: false,
            failure: None,
            cleanup_failure: None,
            identity: None,
        })
    }
    fn shared(&self) -> &Shared<R> {
        self.shared.as_ref().unwrap()
    }
    fn regs(&self) -> &R {
        &self.shared().registers
    }
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }
    pub fn cleanup_failure(&self) -> Option<Error> {
        self.cleanup_failure
    }
    pub fn firmware(&self) -> Option<&FirmwareIdentity> {
        self.identity.as_ref()
    }
    pub fn devices(&self) -> &[Device] {
        &self.engine.devices
    }
    pub fn timestamp_support(&self) -> TimestampSupport {
        TimestampSupport::FirmwareClockSynchronizationUnsupported
    }
    pub fn irq_handled(&self) -> Result<u64> {
        self.registration
            .as_ref()
            .ok_or(Error::Requirement("actual live IRQ registration"))?
            .handled()
            .map_err(Error::Irq)
    }
    pub fn service_pending(&self) -> bool {
        self.shared().signals.pending.load(Ordering::Acquire)
    }
    fn usable(&self) -> Result<()> {
        if self.failure.is_some() || self.stop_attempted {
            Err(Error::Terminal)
        } else {
            Ok(())
        }
    }
    fn record<U>(&mut self, result: Result<U>) -> Result<U> {
        if let Err(e) = result {
            self.failure.get_or_insert(e);
            self.running = false;
            self.identity = None;
            self.engine.invalidate();
            self.shared()
                .signals
                .terminal
                .store(true, Ordering::Release);
            let mask = self.shared().mask();
            if let Err(e) = mask {
                self.cleanup_failure.get_or_insert(e);
            }
            if let Some(c) = &self.config {
                let mask = c.borrow_mut().msi.mask().map_err(Error::Msi);
                if let Err(e) = mask {
                    self.cleanup_failure.get_or_insert(e);
                }
            }
        }
        result
    }
    fn deadline(&self, us: u64) -> Result<u64> {
        self.clock
            .now_us()
            .checked_add(us)
            .ok_or(Error::Requirement("nonoverflowing native deadline"))
    }
    fn wait_until(
        &mut self,
        us: u64,
        label: &'static str,
        mut ready: impl FnMut(&Self) -> Result<bool>,
    ) -> Result<()> {
        let deadline = self.deadline(us)?;
        let mut previous = self.clock.now_us();
        loop {
            let before = self.clock.now_us();
            if before < previous {
                return Err(Error::Requirement("monotonic native clock"));
            }
            if before >= deadline {
                return Err(Error::Timeout(label));
            }
            self.pump()?;
            let after = self.clock.now_us();
            if after < before {
                return Err(Error::Requirement("monotonic native clock"));
            }
            if after >= deadline {
                return Err(Error::Timeout(label));
            }
            let is_ready = ready(self)?;
            let sealed = self.clock.now_us();
            if sealed < after {
                return Err(Error::Requirement("monotonic native clock"));
            }
            if sealed >= deadline {
                return Err(Error::Timeout(label));
            }
            if is_ready {
                return Ok(());
            }
            previous = sealed;
            core::hint::spin_loop();
        }
    }

    pub fn start(&mut self) -> Result<()> {
        let result = self.start_inner();
        self.record(result)
    }
    fn start_inner(&mut self) -> Result<()> {
        self.usable()?;
        if self.started {
            return Err(Error::Requirement("one native ISH startup"));
        }
        self.started = true;
        let f = self.function.as_mut().unwrap();
        let c = f.config();
        if c.read32(0) != 0x9d35_8086 || c.read32(8) as u8 != self.revision {
            return Err(Error::Requirement(
                "unchanged actual endpoint before startup",
            ));
        }
        // Original config owner enables BME only under the already attached real
        // isolated domain. RMP2 remains0 until the actual route is published.
        let observed = c.read16(4);
        if observed == u16::MAX {
            return Err(Error::Config(4));
        }
        let command = observed | 0x406;
        c.write16(4, command);
        if c.read16(4) != command {
            return Err(Error::Config(4));
        }
        let function = self.function.take().unwrap();
        let retained = self.retained.take().unwrap();
        // SAFETY: same actual original owners; fresh IRQ/posted/drained epoch.
        let msi = match unsafe { MsiConfig::new(function, retained) } {
            Ok(msi) => msi,
            Err((e, (function, retained))) => {
                self.function = Some(function);
                self.retained = Some(retained);
                return Err(Error::Msi(e));
            }
        };
        let config = Rc::new(RefCell::new(ConfigState {
            msi,
            disabled: None,
            failure: None,
        }));
        self.config = Some(config.clone());
        let shared = self.shared.as_ref().unwrap().clone();
        let source = Box::new(NativeSource {
            config,
            shared: shared.clone(),
        });
        let callback = Arc::new(Callback(shared));
        self.registration = Some(match self.interrupts.request(source, callback) {
            Ok(registration) => registration,
            Err(error) => {
                return Err(self
                    .config
                    .as_ref()
                    .unwrap()
                    .borrow()
                    .failure
                    .unwrap_or(Error::Irq(error)));
            }
        });
        self.accept_reset = true;
        self.reset_ready = false;
        let host = read(self.regs(), HOST_COMM)?;
        store(self.regs(), HOST_COMM, host | 0x80)?;
        store(self.regs(), RMP2, 1)?;
        self.enable_irq()?;
        self.engine.management(3, &[1, 0, 0, 0])?;
        self.wait_until(10_000_000, "IPC reset acknowledgement", |s| {
            Ok(s.reset_ready && s.engine.frames.is_empty() && read(s.regs(), H2I)? & BUSY == 0)
        })?;
        self.wait_until(2_000_000, "IPC input ready", |s| {
            Ok(read(s.regs(), H2I)? & BUSY == 0)
        })?;
        self.wait_until(2_000_000, "firmware ILUP and ISHTP ready", |s| {
            Ok(read(s.regs(), FWSTS)? & 3 == 3)
        })?;
        let mut generation = self.reset_generation;
        let mut settled = None;
        self.wait_until(2_000_000, "real firmware settle interval", |s| {
            let ready = read(s.regs(), FWSTS)? & 3 == 3
                && s.engine.frames.is_empty()
                && read(s.regs(), H2I)? & BUSY == 0
                && read(s.regs(), I2H)? & BUSY == 0
                && !s.shared().signals.pending.load(Ordering::Acquire);
            if generation != s.reset_generation || !ready {
                generation = s.reset_generation;
                settled = None;
                return Ok(false);
            }
            if let Some(deadline) = settled {
                Ok(s.clock.now_us() >= deadline)
            } else {
                settled = Some(s.deadline(300_000)?);
                Ok(false)
            }
        })?;
        if self.irq_handled()? == 0 {
            return Err(Error::Requirement(
                "actual IRQ callback observed during native startup",
            ));
        }
        self.accept_reset = false;
        self.engine.start()?;
        self.wait_until(7_000_000, "HBM discovery and HID connect", |s| {
            Ok(s.engine.connected())
        })?;
        let bytes = self.exchange(33, 0, None, &[])?;
        self.engine.enumerate_devices(&bytes)?;
        for index in 0..self.engine.devices.len() {
            let id = self.engine.devices[index].id;
            let hid = self.exchange(0, id, None, &[])?;
            if hid.len() != 9 || hid[0] != 9 || hid[1] != 0x21 || hid[5] != 1 || hid[6] != 0x22 {
                return Err(Error::Requirement(
                    "ordinary actual nine-byte HID descriptor",
                ));
            }
            let declared = usize::from(u16::from_le_bytes([hid[7], hid[8]]));
            let report = self.exchange(1, id, None, &[])?;
            if report.len() != declared {
                return Err(Error::Protocol("HID report descriptor declared length"));
            }
            let reports = descriptor::parse(&report)?;
            let max = self.engine.client.as_ref().unwrap().max_message_length as usize;
            if reports.iter().any(|r| r.bytes + 6 > max) {
                return Err(Error::Requirement(
                    "HID reports fit actual ISHTP client bound",
                ));
            }
            let d = &mut self.engine.devices[index];
            d.hid_descriptor = hid;
            d.report_descriptor = report;
            d.reports = reports;
        }
        self.engine.hid_ready = true;
        self.running = true;
        self.identity = Some(FirmwareIdentity {
            pci_revision: self.revision,
            observed_status: read(self.regs(), FWSTS)?,
            hbm_firmware_max: self.engine.fw_max,
            hid_client: self.engine.client.as_ref().unwrap().clone(),
            timestamps: self.timestamp_support(),
        });
        Ok(())
    }
    fn exchange(&mut self, cmd: u8, id: u8, report: Option<u8>, payload: &[u8]) -> Result<Vec<u8>> {
        self.engine.request(cmd, id, report, payload)?;
        self.wait_until(3_000_000, "correlated HID response", |s| {
            Ok(s.engine.response.is_some())
        })?;
        Ok(self.engine.take_response().unwrap())
    }
    pub fn get_report(&mut self, device: u8, kind: ReportKind, report_id: u8) -> Result<Vec<u8>> {
        self.usable()?;
        if !self.running {
            return Err(Error::Requirement("running native HID transport"));
        }
        let command = match kind {
            ReportKind::Input => 4,
            ReportKind::Feature => 2,
            ReportKind::Output => {
                return Err(Error::Requirement("ISH output report controls unsupported"));
            }
        };
        let d = self
            .engine
            .devices
            .iter()
            .find(|d| d.id == device)
            .ok_or(Error::Protocol("unknown HID device"))?;
        if !d
            .reports
            .iter()
            .any(|r| r.kind == kind && r.report_id == report_id)
        {
            return Err(Error::Protocol(
                "request absent from actual report descriptor",
            ));
        }
        self.engine.request_ready()?;
        let result = self.exchange(command, device, Some(report_id), &[]);
        self.record(result)
    }
    /// Return the actual bounded acknowledgement payload, including nonempty
    /// firmware acknowledgements; do not invent an empty-response requirement.
    pub fn set_feature(&mut self, device: u8, bytes: &[u8]) -> Result<Vec<u8>> {
        self.usable()?;
        if !self.running {
            return Err(Error::Requirement("running native HID transport"));
        }
        let d = self
            .engine
            .devices
            .iter()
            .find(|d| d.id == device)
            .ok_or(Error::Protocol("unknown HID device"))?;
        descriptor::validate(&d.reports, ReportKind::Feature, bytes)?;
        self.engine.request_ready()?;
        let result = self.exchange(3, device, None, bytes);
        self.record(result)
    }
    pub fn service(&mut self) -> Result<()> {
        let result = (|| {
            self.usable()?;
            if !self.running {
                return Err(Error::Requirement("running native HID transport"));
            }
            self.pump()
        })();
        self.record(result)
    }
    pub fn next_input(&mut self) -> Result<Option<InputReport>> {
        self.service()?;
        let report = self.engine.inputs.pop_front();
        let result = self.engine.replenish();
        self.record(result)?;
        Ok(report)
    }
    fn transmit(&mut self) -> Result<()> {
        if self.engine.frames.is_empty() || read(self.regs(), H2I)? & BUSY != 0 {
            return Ok(());
        }
        let frame = self.engine.frames.front().unwrap();
        for (index, part) in frame.bytes.chunks(4).enumerate() {
            let mut word = [0; 4];
            word[..part.len()].copy_from_slice(part);
            self.regs()
                .write32(TX + 4 * index as u32, u32::from_le_bytes(word))?;
        }
        let Frame {
            protocol,
            management,
            bytes,
        } = frame;
        let doorbell = BUSY
            | (u32::from(*protocol) << 10)
            | (u32::from(*management) << 16)
            | bytes.len() as u32;
        self.regs().write32(H2I, doorbell)?;
        read(self.regs(), FWSTS)?;
        let frame = self.engine.frames.pop_front().unwrap();
        self.engine.published(&frame)?;
        Ok(())
    }
    fn receive_one(&mut self, doorbell: u32) -> Result<()> {
        let length = (doorbell & 0x3ff) as usize;
        let protocol = (doorbell >> 10) & 15;
        let management = ((doorbell >> 16) & 15) as u8;
        if length > 128 || doorbell & !(BUSY | 0x000f_0000 | 0x3fff) != 0 {
            return Err(Error::Protocol("IPC doorbell reserved/length bits"));
        }
        let mut bytes = Vec::with_capacity(length);
        for index in 0..length.div_ceil(4) {
            // Payload all-ones DWORDs are valid. Removal sentinels belong to
            // control/status reads, never to arbitrary HID/descriptor bytes.
            let word = self.regs().read32(RX + 4 * index as u32)?.to_le_bytes();
            let take = (length - bytes.len()).min(4);
            bytes.extend_from_slice(&word[..take]);
        }
        self.regs().write32(I2H, 0)?;
        read(self.regs(), FWSTS)?;
        match protocol {
            1 if management == 0 => self.engine.receive(&bytes),
            3 => match management {
                2 => Ok(()),
                3 | 4 => {
                    if !self.accept_reset {
                        self.engine.invalidate();
                        self.identity = None;
                        return Err(Error::FirmwareReset);
                    }
                    if bytes.len() != 4 || bytes[2..] != [0, 0] {
                        return Err(Error::Protocol("IPC reset payload"));
                    }
                    if management == 4 && bytes[..2] != [1, 0] {
                        return Err(Error::Protocol("stale IPC reset acknowledgement"));
                    }
                    if management == 3 {
                        let host = read(self.regs(), HOST_COMM)?;
                        store(self.regs(), HOST_COMM, host | 0x80)?;
                        self.engine.management(4, &bytes)?;
                    }
                    self.reset_generation = self
                        .reset_generation
                        .checked_add(1)
                        .ok_or(Error::Protocol("bounded reset generation"))?;
                    self.reset_ready = true;
                    Ok(())
                }
                _ => Err(Error::Requirement("unsupported IPC management command")),
            },
            _ => Err(Error::Requirement("unsupported IPC protocol")),
        }
    }
    fn enable_irq(&self) -> Result<()> {
        self.regs().write32(PIMR, self.shared().enabled)?;
        let observed = read(self.regs(), PIMR)?;
        if observed != self.shared().enabled
            && !(observed == self.shared().mask
                && self.shared().signals.pending.load(Ordering::Acquire))
        {
            return Err(Error::Readback(PIMR));
        }
        self.shared().fault()
    }
    fn pump(&mut self) -> Result<()> {
        self.shared().fault()?;
        if let Some(c) = &self.config
            && let Some(e) = c.borrow().failure
        {
            return Err(e);
        }
        if read(self.regs(), PIMR)? == self.shared().enabled {
            self.transmit()?;
        }
        self.shared().mask()?;
        // Bounded batch; another actual IRQ or service call drains a later batch.
        for _ in 0..64 {
            self.shared()
                .signals
                .pending
                .store(false, Ordering::Release);
            let cause = read(self.regs(), PISR)?;
            // Original BXT observed write-back: only busy-clear is RW, other
            // bits RO. Do not invent generic W1C or filter away busy-clear.
            if cause != 0 {
                self.regs().write32(PISR, cause)?;
            }
            let doorbell = read(self.regs(), I2H)?;
            if doorbell & BUSY != 0 {
                self.receive_one(doorbell)?;
            }
            self.transmit()?;
            self.shared().fault()?;
            if read(self.regs(), I2H)? & BUSY != 0 {
                continue;
            }
            if self.shared().signals.terminal.load(Ordering::Acquire) {
                return Ok(());
            }
            self.enable_irq()?;
            let pending = self.shared().signals.pending.load(Ordering::Acquire);
            let cause = read(self.regs(), PISR)?;
            let doorbell = read(self.regs(), I2H)?;
            if pending || cause != 0 || doorbell & BUSY != 0 {
                self.shared().mask()?;
                continue;
            }
            // A later callback masks and leaves pending=true for the next call.
            return Ok(());
        }
        self.shared().signals.pending.store(true, Ordering::Release);
        self.shared().mask()
    }
    pub fn stop(&mut self) -> Result<()> {
        if self.stop_attempted {
            return Err(Error::Terminal);
        }
        self.stop_attempted = true;
        let mut primary = None;
        if self.running && self.failure.is_none() {
            let disconnect = (|| {
                self.engine.disconnect()?;
                self.wait_until(1_000_000, "HID disconnect", |s| Ok(s.engine.disconnected))?;
                self.engine.host_stop()?;
                self.wait_until(1_000_000, "HBM host stop", |s| Ok(s.engine.stopped))
            })();
            if let Err(e) = disconnect {
                primary = Some(e);
            }
        }
        self.running = false;
        self.identity = None;
        self.engine.invalidate();
        self.shared()
            .signals
            .terminal
            .store(true, Ordering::Release);
        let result = self.contain_and_drain();
        if let Err(e) = result {
            if primary.is_none() {
                primary = Some(e);
            } else {
                self.cleanup_failure.get_or_insert(e);
            }
        }
        let e = primary.unwrap_or(Error::PostedMsiRetirementUnavailable);
        self.failure.get_or_insert(e);
        Err(e)
    }
    fn contain_and_drain(&mut self) -> Result<()> {
        self.shared().mask()?;
        if let Some(c) = &self.config {
            let mut state = c.borrow_mut();
            let disabled = state.msi.begin_device_retirement().map_err(Error::Msi)?;
            state.disabled = Some(disabled);
        }
        store(self.regs(), RMP2, 0)?;
        let end = self.deadline(20_000)?;
        let mut previous = self.clock.now_us();
        loop {
            let before = self.clock.now_us();
            if before < previous {
                return Err(Error::Requirement("monotonic native clock"));
            }
            if before >= end {
                return Err(Error::Timeout("actual firmware DMA stop"));
            }
            let active = read(self.regs(), FWSTS)? & IN_DMA;
            let after = self.clock.now_us();
            if after < before {
                return Err(Error::Requirement("monotonic native clock"));
            }
            if after >= end {
                return Err(Error::Timeout("actual firmware DMA stop"));
            }
            if active == 0 {
                break;
            }
            previous = after;
            core::hint::spin_loop();
        }
        let stop_config = |c: &mut C| -> Result<()> {
            if c.read32(0) != 0x9d35_8086 {
                return Err(Error::Config(0));
            }
            let command = c.read16(4);
            if command == u16::MAX {
                return Err(Error::Config(4));
            }
            let wanted = (command | 0x400) & !4;
            c.write16(4, wanted);
            if c.read16(4) != wanted {
                return Err(Error::Config(4));
            }
            Ok(())
        };
        if let Some(c) = &self.config {
            // SAFETY: one terminal narrow BME-clear on original config, with all
            // native mappings/domain/IRQ owners retained; no reset or release.
            unsafe {
                c.borrow_mut()
                    .disabled
                    .as_mut()
                    .unwrap()
                    .with_device_stop(stop_config)
            }
            .map_err(Error::Msi)??;
        } else if let Some(function) = &mut self.function {
            stop_config(function.config())?;
        }
        let host = read(self.regs(), HOST_COMM)?;
        store(self.regs(), HOST_COMM, host & !0x80)?;
        // SAFETY: submissions/firmware DMA are terminal and acknowledged idle;
        // exact original domain/root/config/IRQ/mappings remain retained.
        unsafe { self.domain.as_ref().unwrap().drain_posted_writes() }.map_err(Error::Dma)?;
        // Deliberately no registration.retire/release/unmap. Translated payload
        // completion does not drain already posted MSI on the original route.
        Err(Error::PostedMsiRetirementUnavailable)
    }
}
impl<C: Configuration, R: Registers, T: Time> Drop for Native<C, R, T> {
    fn drop(&mut self) {
        // Neither Drop nor a failed stop can certify original posted-MSI/root
        // completion. Preserve every actual uncertain owner, even after panic.
        if let Some(v) = self.registration.take() {
            core::mem::forget(v);
        }
        if let Some(v) = self.config.take() {
            core::mem::forget(v);
        }
        if let Some(v) = self.function.take() {
            core::mem::forget(v);
        }
        if let Some(v) = self.retained.take() {
            core::mem::forget(v);
        }
        if let Some(v) = self.domain.take() {
            core::mem::forget(v);
        }
        if let Some(v) = self.shared.take() {
            core::mem::forget(v);
        }
    }
}
fn validate_capabilities<C: Configuration>(c: &C) -> Result<()> {
    if c.read16(6) == u16::MAX || c.read16(6) & 0x10 == 0 {
        return Err(Error::Requirement("actual native PCI capabilities"));
    }
    let mut msi = false;
    let mut pm = false;
    for entry in crate::bus::pci::capability::capabilities(c) {
        let entry = entry.map_err(|error| match error {
            CapabilityError::FailedRead { offset } => Error::Config(offset),
            CapabilityError::OutOfRange { .. } | CapabilityError::Overlap { .. } => {
                Error::Requirement("native capability extent")
            }
            _ => Error::Requirement("bounded nonoverlapping native capabilities"),
        })?;
        let at = entry.offset;
        match entry.id {
            5 => {
                if msi {
                    return Err(Error::Requirement("one actual MSI capability"));
                }
                msi = true;
                let flags = c.read16(at + 2);
                if flags & !0x1fe != 0
                    || (flags >> 1) & 7 > 5
                    || (flags >> 4) & 7 > (flags >> 1) & 7
                {
                    return Err(Error::Requirement("inactive supported single-message MSI"));
                }
            }
            1 => {
                if pm || c.read16(at + 4) & 3 != 0 {
                    return Err(Error::Requirement("actual single D0 PM capability"));
                }
                pm = true;
            }
            0x11 if c.read16(at + 2) & 0x8000 != 0 => {
                return Err(Error::Requirement(
                    "inactive MSI-X before native ISH admission",
                ));
            }
            _ if entry.layout == Layout::Unsupported => {
                return Err(Error::Msi(msi::MsiError::Unsupported));
            }
            _ => {}
        }
    }
    if !msi || !pm {
        return Err(Error::Requirement(
            "actual native MSI and D0 power capabilities",
        ));
    }
    Ok(())
}
