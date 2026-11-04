//! The owned SCI route: IRQ masking followed by BSP-context ACPICA work.
use crate::{
    native_irq::{self, ioapic},
    native_mmio,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_drivers::{
    bus::irq::{Disposition, Handler, IrqError, IrqRegistration, LineRoute, ParentMask},
    platform::acpi::Interrupt,
};
use stela_runtime::pc::power::HostPower;

pub(super) type Endpoint =
    ioapic::ParentMask<native_mmio::IoapicRegisters, native_irq::NativePlatform>;

pub(crate) struct Prepared {
    unit: Arc<native_mmio::IoapicUnit>,
    line: LineRoute,
    power: HostPower,
    irq: u32,
    legacy_pic: bool,
}
impl Prepared {
    /// # Safety
    /// The engine has stopped firmware IRQ ownership and owns every fixed/GPE
    /// SCI source and the controller's selector/window. PCI INTx aliases must
    /// be stopped before the route is admitted.
    pub(crate) unsafe fn capture(
        mmio: &native_mmio::Source,
        power: HostPower,
    ) -> Result<Self, IrqError> {
        if power.refused.is_some() || power.pm1[0].is_none() || power.pm1_event_bytes != 4 {
            return Err(IrqError::Unsupported);
        }
        let routing = mmio.routing().map_err(|_| IrqError::Route)?;
        let line = routing.sci(mmio.fadt()).map_err(|_| IrqError::Route)?;
        // SCI_INT is the original source number. MADT's override changes
        // its IOAPIC GSI without changing the legacy PIC input.
        let fadt = mmio.fadt();
        let irq = u32::from(u16::from_le_bytes([fadt[46], fadt[47]]));
        let legacy_pic = routing.has_legacy_pic();
        require_pic_masked(legacy_pic, irq)?;
        let mut units = Vec::new();
        for descriptor in &routing.units {
            // SAFETY: the caller grants the complete IOAPIC handoff.
            let unit = unsafe { mmio.ioapic(*descriptor) }.map_err(|_| IrqError::Unavailable)?;
            units.push((*descriptor, unit));
        }
        let spans: Vec<_> = units
            .iter()
            .map(|(descriptor, unit)| (*descriptor, unit.pins()))
            .collect();
        let owner = routing.owner(line, &spans).map_err(|_| IrqError::Route)?;
        let unit = units
            .into_iter()
            .find(|(descriptor, _)| *descriptor == owner)
            .map(|(_, unit)| unit)
            .ok_or(IrqError::Route)?;
        // SAFETY: former firmware route and contributors are owned by caller.
        unsafe { unit.mask_unclaimed(line.gsi) }?;
        Ok(Self {
            unit,
            line,
            power,
            irq,
            legacy_pic,
        })
    }

    pub(super) fn irq(&self) -> u32 {
        self.irq
    }

    /// # Safety
    /// Called once by this boot's ACPICA activation, with the same permanent
    /// provider/handler argument kept until acknowledged removal.
    pub(super) unsafe fn install(
        self,
        handler: Interrupt,
        argument: *mut c_void,
    ) -> Result<Armed, IrqError> {
        require_pic_masked(self.legacy_pic, self.irq)?;
        let pending = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let devices = Sources::new(self.power);
        // SAFETY: capture checked the owned physical route; Sources masks and
        // restores every fixed/GPE enable bit on this exclusive SCI line.
        let pin = unsafe { self.unit.claim(self.line, Box::new(devices)) }?;
        let parent = Arc::new(pin.parent_mask()?);
        let callback = Arc::new(Deferred {
            parent: parent.clone(),
            pending: pending.clone(),
            failed: failed.clone(),
        });
        let registration = native_irq::service()?.request(Box::new(pin), callback)?;
        Ok(Armed {
            pending,
            failed,
            parent,
            registration,
            handler,
            argument: argument as usize,
        })
    }
}

fn require_pic_masked(legacy_pic: bool, irq: u32) -> Result<(), IrqError> {
    if legacy_pic && irq < 16 {
        native_irq::NativePlatform::current()?;
        if crate::engine::host::in_interrupt() {
            return Err(IrqError::WrongCpu);
        }
        let port = if irq < 8 { 0x21 } else { 0xa1 };
        // SAFETY: MADT identifies an original PC/AT PIC. Reading its mask
        // neither programs the controller nor acknowledges an interrupt.
        let mask = unsafe { super::in8(port) };
        if mask & (1 << (irq & 7)) == 0 {
            return Err(IrqError::Mask);
        }
    }
    Ok(())
}

struct Enable {
    port: u16,
    wide: bool,
    saved: u16,
}
struct Sources {
    enables: Vec<Enable>,
    captured: bool,
}
impl Sources {
    fn new(power: HostPower) -> Self {
        let mut enables = Vec::new();
        for pm1 in power.blocks() {
            enables.push(Enable {
                port: power.enable_port(pm1),
                wide: true,
                saved: 0,
            });
        }
        for (_, port) in power
            .gpe
            .iter()
            .flatten()
            .flat_map(|block| block.registers())
        {
            enables.push(Enable {
                port,
                wide: false,
                saved: 0,
            });
        }
        Self {
            enables,
            captured: false,
        }
    }
}
impl Enable {
    fn read(&self) -> u16 {
        // SAFETY: the validated FADT's fixed/GPE enable port, exclusively owned
        // by this SCI contributor group; SCI status is a separate register.
        unsafe {
            if self.wide {
                super::in16(self.port)
            } else {
                u16::from(super::in8(self.port))
            }
        }
    }
    fn write(&self, value: u16) {
        // SAFETY: same owned FADT enable register and native port width.
        unsafe {
            if self.wide {
                super::out16(self.port, value)
            } else {
                super::out8(self.port, value as u8)
            }
        }
    }
}
// SAFETY: Sources keeps every checked fixed/GPE register. Masking disables
// and reads back all contributors before controller drain; only enable restores
// the saved mask after callback publication, on the same boot processor.
unsafe impl ioapic::Devices for Sources {
    fn mask(&mut self) -> Result<(), IrqError> {
        if !self.captured {
            for enable in &mut self.enables {
                enable.saved = enable.read();
            }
            self.captured = true;
        }
        for enable in &self.enables {
            enable.write(0);
            if enable.read() != 0 {
                return Err(IrqError::Mask);
            }
        }
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        self.mask()
    }
    unsafe fn enable(&mut self) -> Result<(), IrqError> {
        for enable in &self.enables {
            enable.write(enable.saved);
            if enable.read() != enable.saved {
                return Err(IrqError::Mask);
            }
        }
        Ok(())
    }
}

struct Deferred {
    parent: Arc<Endpoint>,
    pending: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
}
impl Handler for Deferred {
    fn handle(&self) -> Disposition {
        if self.parent.mask().is_err() {
            self.failed.store(true, Ordering::Release);
        }
        self.pending.store(true, Ordering::Release);
        Disposition::Handled
    }
}

pub(super) struct Armed {
    pending: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    parent: Arc<Endpoint>,
    registration: Box<dyn IrqRegistration>,
    handler: Interrupt,
    argument: usize,
}
impl Armed {
    /// Dispatch only in BSP process context under the provider's loader root.
    /// The hard IRQ has already returned through the registry's local EOI.
    pub(super) fn dispatch(&self) -> Result<bool, IrqError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(IrqError::Mask);
        }
        if !self.pending.swap(false, Ordering::AcqRel) {
            return Ok(false);
        }
        // SAFETY: activation keeps this exact ACPICA SCI callback/context;
        // BSP process context serializes calls until route retirement.
        let _handled = unsafe { (self.handler)(self.argument as *mut c_void) };
        // A level may deassert between hardware entry and deferred sampling.
        // ACPICA's zero means no live contributor, not a broken route; the
        // consumed native IRQ still requires parent rearm after its EOI.
        Ok(true)
    }
    /// # Safety
    /// ACPICA's ISR has completed under the provider root, acknowledging fixed
    /// events and disabling each contributor that owns deferred work.
    pub(super) unsafe fn rearm(&self) -> Result<(), IrqError> {
        if self.pending.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            return Err(IrqError::Drain);
        }
        // SAFETY: the caller completed the ISR; epoch, hardware drain and
        // local pending state are checked again by the endpoint.
        unsafe { self.parent.rearm() }
    }
    pub(super) fn retire(&mut self) -> Result<(), IrqError> {
        self.registration.retire()
    }
}
