// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 1997, 1998, 1999, 2000, 2009 Ingo Molnar, Hajnalka Szabo
// Multiple IO-APIC support (C) 1999 Ken-ichi Yaku and Hidemi Kishimoto;
// further tested and cleaned up by Zach Brown and Ingo Molnar.
//! Actual legacy IOAPIC ownership and redirection ordering. Protocol references:
//! Linux a804c5742bff224d4cb4d25dd383554d598be32b, arch/x86/kernel/apic/io_apic.c
//! and arch/x86/include/asm/io_apic.h (Ingo Molnar and contributors), recorded
//! in stela-drivers/src/platform/THIRD_PARTY.md. CPU/IDT/AP bootstrap is never
//! owned here.
use alloc::{boxed::Box, sync::Arc};
use core::{
    cell::UnsafeCell,
    mem::ManuallyDrop,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use stela_drivers::bus::irq::{
    FIRST_VECTOR, IrqError, LineRoute, Platform, Polarity, Route, RouteRequest, Source, Target,
    Trigger, VECTOR_COUNT,
};

const MASK: u32 = 1 << 16;
const REMOTE_IRR: u32 = 1 << 14;
const DELIVERY: u32 = 1 << 12;
const CONFIG: u32 = 0xff | 7 << 8 | 1 << 11 | 1 << 13 | 1 << 15 | MASK;
const MAX_PINS: usize = 120;

/// # Safety
/// Real IOREGSEL/IOWIN accesses to the one retained, root-stable UC mapping.
/// No other firmware/CPU/controller owner may touch the selector/window.
/// Every index passed here is <= 0xff. Operations must order actual MMIO.
pub unsafe trait Registers: Send + Sync {
    fn read(&self, index: u8) -> u32;
    fn write(&self, index: u8, value: u32);
}

pub struct Mmio(usize);
impl Mmio {
    /// # Safety
    /// `base` is an exclusive actual UC IOAPIC mapping of at least 32 bytes,
    /// aligned to 4 KiB and retained across all roots through final release or
    /// permanent quarantine. No WB/WC alias exists. No IRQ-context release.
    pub unsafe fn new(base: usize) -> Result<Self, IrqError> {
        if base == 0 || base & 4095 != 0 || base.checked_add(32).is_none() {
            return Err(IrqError::Route);
        }
        Ok(Self(base))
    }
}
// SAFETY: constructor qualifies actual retained UC MMIO; Unit serializes every
// selector/window pair with same-CPU IRQ-save, never across an interrupt window.
unsafe impl Registers for Mmio {
    fn read(&self, index: u8) -> u32 {
        unsafe {
            (self.0 as *mut u32).write_volatile(u32::from(index));
            ((self.0 + 16) as *const u32).read_volatile()
        }
    }
    fn write(&self, index: u8, value: u32) {
        unsafe {
            (self.0 as *mut u32).write_volatile(u32::from(index));
            ((self.0 + 16) as *mut u32).write_volatile(value);
        }
    }
}

/// Real contributors to one physical line, retained as an immutable group.
/// # Safety
/// Every physical sharer, SCI fixed/GPE source or PCI INTx contributor is
/// owned/retained here. Mask and stop acknowledge real device effects, drain
/// workers/timers/posted writes and exclude new causes until enable. No final
/// release in IRQ context. No missing sharer may keep this line asserted.
/// SharedHandlers membership and this source group must describe the same
/// pre-bound lifetime; dynamic join/remove is unavailable.
pub unsafe trait Devices: Send {
    fn mask(&mut self) -> Result<(), IrqError>;
    fn quiesce(&mut self) -> Result<(), IrqError>;
    /// # Safety
    /// The owned route and every retained callback are fully published.
    unsafe fn enable(&mut self) -> Result<(), IrqError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    pub masked: bool,
    pub remote_irr: bool,
    pub delivery_pending: bool,
}

pub struct Unit<R: Registers, P: Platform> {
    registers: R,
    platform: P,
    id: u8,
    gsi_base: u32,
    pins: u16,
    held: AtomicBool,
    claims: UnsafeCell<[bool; MAX_PINS]>,
    epochs: UnsafeCell<[u64; MAX_PINS]>,
    next_epoch: UnsafeCell<u64>,
    quarantined: AtomicU64,
}
// SAFETY: all selector/window and claim access is serialized by IRQ-save lock.
// The platform confines operations to the owning CPU. Arc lifetime is retained
// through every route or quarantined route; no hard-IRQ allocation/release.
unsafe impl<R: Registers, P: Platform> Sync for Unit<R, P> {}

impl<R: Registers, P: Platform> Unit<R, P> {
    /// # Safety
    /// Exclusive selector/window owner, matched actual MADT physical unit and
    /// ID. CPU adapter is initialized on the same BSP; local APIC EOI broadcast
    /// suppression is disabled and remains disabled through final retirement.
    /// No other CPU/SMM/firmware can program these redirection entries. Pin
    /// ownership/quiescence must separately be proved for each claim.
    pub unsafe fn attach(
        registers: R,
        platform: P,
        id: u8,
        gsi_base: u32,
    ) -> Result<Arc<Self>, IrqError> {
        platform.check_cpu()?;
        let saved = platform.save_and_disable();
        let raw_id = registers.read(0);
        let version = registers.read(1);
        unsafe { platform.restore(saved) };
        if raw_id == u32::MAX || version == u32::MAX {
            return Err(IrqError::FailedRead);
        }
        let pins = ((version >> 16) & 255) as u16 + 1;
        if raw_id >> 24 != u32::from(id)
            || !matches!(version & 255, 0x11 | 0x20)
            || pins as usize > MAX_PINS
            || gsi_base.checked_add(u32::from(pins)).is_none()
        {
            return Err(IrqError::Unsupported);
        }
        Ok(Arc::new(Self {
            registers,
            platform,
            id,
            gsi_base,
            pins,
            held: AtomicBool::new(false),
            claims: UnsafeCell::new([false; MAX_PINS]),
            epochs: UnsafeCell::new([0; MAX_PINS]),
            next_epoch: UnsafeCell::new(1),
            quarantined: AtomicU64::new(0),
        }))
    }
    pub fn id(&self) -> u8 {
        self.id
    }
    pub fn gsi_base(&self) -> u32 {
        self.gsi_base
    }
    pub fn pins(&self) -> u16 {
        self.pins
    }
    pub fn quarantine_count(&self) -> u64 {
        self.quarantined.load(Ordering::Relaxed)
    }
    pub fn state(&self, gsi: u32) -> Result<State, IrqError> {
        self.platform.check_cpu()?;
        let pin = gsi
            .checked_sub(self.gsi_base)
            .filter(|p| *p < u32::from(self.pins))
            .ok_or(IrqError::Route)? as u8;
        let _guard = self.lock();
        let low = self.low(pin)?;
        Ok(State {
            masked: low & MASK != 0,
            remote_irr: low & REMOTE_IRR != 0,
            delivery_pending: low & DELIVERY != 0,
        })
    }
    fn lock(&self) -> Guard<'_, R, P> {
        let saved = self.platform.save_and_disable();
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard { unit: self, saved }
    }
    fn low(&self, pin: u8) -> Result<u32, IrqError> {
        let raw = self.registers.read(0x10 + pin * 2);
        if raw == u32::MAX {
            Err(IrqError::FailedRead)
        } else {
            Ok(raw)
        }
    }
    /// # Safety
    /// Validated actual MADT electrical route, no NMI/PIRQ alias and ownership
    /// of every physical sharer. All contributors are stopped/drained with no
    /// old firmware/CPU callback, pending interrupt or worker. The initially
    /// masked entry is not evidence of this grant. Complete group retirement
    /// is required before reconfiguration or membership changes.
    pub unsafe fn claim(
        self: &Arc<Self>,
        line: LineRoute,
        devices: Box<dyn Devices>,
    ) -> Result<Pin<R, P>, IrqError> {
        self.platform.check_cpu()?;
        // This slice has an end-to-end level completion proof through actual
        // Remote IRR/EOI. Edge IOAPIC drain is not inferred from MSI coverage.
        if line.trigger != Trigger::Level {
            return Err(IrqError::Unsupported);
        }
        let pin = line
            .gsi
            .checked_sub(self.gsi_base)
            .filter(|p| *p < u32::from(self.pins))
            .ok_or(IrqError::Route)? as u8;
        let _guard = self.lock();
        let low = self.low(pin)?;
        if low & MASK == 0 || low & (REMOTE_IRR | DELIVERY) != 0 {
            return Err(IrqError::Drain);
        }
        let claims = unsafe { &mut *self.claims.get() };
        if claims[usize::from(pin)] {
            return Err(IrqError::Exhausted);
        }
        // Selector lock also owns the fixed pin metadata. Never wrap and make
        // an old handler's parent-mask endpoint valid for a later claim.
        let next_epoch = unsafe { &mut *self.next_epoch.get() };
        let epoch = *next_epoch;
        *next_epoch = next_epoch.checked_add(1).ok_or(IrqError::Exhausted)?;
        unsafe { (*self.epochs.get())[usize::from(pin)] = epoch };
        claims[usize::from(pin)] = true;
        Ok(Pin {
            unit: ManuallyDrop::new(self.clone()),
            devices: ManuallyDrop::new(devices),
            line,
            pin,
            epoch,
            target: None,
            retired: true,
        })
    }
}
struct Guard<'a, R: Registers, P: Platform> {
    unit: &'a Unit<R, P>,
    saved: u64,
}
impl<R: Registers, P: Platform> Drop for Guard<'_, R, P> {
    fn drop(&mut self) {
        self.unit.held.store(false, Ordering::Release);
        unsafe { self.unit.platform.restore(self.saved) };
    }
}

/// Process/deferred source; real callback/source group is owned by Registry.
/// An abandoned programmed pin retains/quarantines its unit, contributors and
/// claim rather than permitting uncertain delivery into a reused vector.
pub struct Pin<R: Registers, P: Platform> {
    unit: ManuallyDrop<Arc<Unit<R, P>>>,
    devices: ManuallyDrop<Box<dyn Devices>>,
    line: LineRoute,
    pin: u8,
    epoch: u64,
    target: Option<Target>,
    retired: bool,
}
impl<R: Registers, P: Platform> Pin<R, P> {
    /// Pre-bind a real parent mask endpoint in process context before callback
    /// publication. It never enables/programs a route or acquires a new pin.
    pub fn parent_mask(&self) -> Result<ParentMask<R, P>, IrqError> {
        self.unit.platform.check_cpu()?;
        let _guard = self.unit.lock();
        if unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] } != self.epoch {
            return Err(IrqError::Unregistered);
        }
        Ok(ParentMask {
            unit: Arc::clone(&self.unit),
            pin: self.pin,
            epoch: self.epoch,
        })
    }
}

/// Constructorless actual pin/epoch endpoint, retained by the fixed callback
/// group. Final Drop remains process/deferred, even though mask is IRQ-safe.
pub struct ParentMask<R: Registers, P: Platform> {
    unit: Arc<Unit<R, P>>,
    pin: u8,
    epoch: u64,
}
// SAFETY: Pin alone creates this endpoint from its actual Unit/claim. The
// existing IRQ-save selector lock checks the nonwrapping epoch and performs
// actual MASK/readback without allocation, callbacks or final owner release.
unsafe impl<R: Registers, P: Platform> stela_drivers::bus::irq::ParentMask for ParentMask<R, P> {
    fn mask(&self) -> Result<(), IrqError> {
        self.unit.platform.check_cpu()?;
        let _guard = self.unit.lock();
        if unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] } != self.epoch {
            return Err(IrqError::Unregistered);
        }
        let low = self.unit.low(self.pin)?;
        self.unit.registers.write(0x10 + self.pin * 2, low | MASK);
        if self.unit.low(self.pin)? & MASK == 0 {
            Err(IrqError::Mask)
        } else {
            Ok(())
        }
    }
}
// SAFETY: devices and unit are retained, physical ownership comes from claim's
// explicit grant. The canonical registry alone publishes/releases callbacks.
unsafe impl<R: Registers, P: Platform> Source for Pin<R, P> {
    fn mask(&mut self) -> Result<(), IrqError> {
        self.unit.platform.check_cpu()?;
        let result = {
            let _guard = self.unit.lock();
            let low = self.unit.low(self.pin)?;
            self.unit.registers.write(0x10 + self.pin * 2, low | MASK);
            if self.unit.low(self.pin)? & MASK == 0 {
                Err(IrqError::Mask)
            } else {
                Ok(())
            }
        };
        // Controller masks first, so a contributor cannot arrive during stop.
        result?;
        self.devices.mask()
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        self.devices.quiesce()
    }
    fn route(&self) -> RouteRequest {
        RouteRequest::Line(self.line)
    }
    unsafe fn program(&mut self, route: Route) -> Result<(), IrqError> {
        self.unit.platform.check_cpu()?;
        let Route::Line { target, line } = route else {
            return Err(IrqError::Route);
        };
        if line != self.line
            || target.destination == 255
            || target.vector < FIRST_VECTOR
            || usize::from(target.vector - FIRST_VECTOR) >= VECTOR_COUNT
        {
            return Err(IrqError::Route);
        }
        let _guard = self.unit.lock();
        if unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] } != self.epoch {
            return Err(IrqError::Unregistered);
        }
        let low = self.unit.low(self.pin)?;
        if low & MASK == 0 || low & (REMOTE_IRR | DELIVERY) != 0 {
            return Err(IrqError::Drain);
        }
        // From this point failure retains the complete route claim. LOW MASK
        // was acknowledged before any HIGH/destination change (Linux mask_entry).
        self.retired = false;
        self.target = Some(target);
        let expected = MASK
            | u32::from(target.vector)
            | if line.polarity == Polarity::Low {
                1 << 13
            } else {
                0
            }
            | if line.trigger == Trigger::Level {
                1 << 15
            } else {
                0
            };
        self.unit
            .registers
            .write(0x11 + self.pin * 2, u32::from(target.destination) << 24);
        self.unit.registers.write(0x10 + self.pin * 2, expected);
        let high = self.unit.registers.read(0x11 + self.pin * 2);
        let actual = self.unit.low(self.pin)?;
        if high == u32::MAX {
            return Err(IrqError::FailedRead);
        }
        if actual & CONFIG != expected
            || high >> 24 != u32::from(target.destination)
            || actual & (REMOTE_IRR | DELIVERY) != 0
        {
            return Err(IrqError::Route);
        }
        Ok(())
    }
    unsafe fn unmask(&mut self) -> Result<(), IrqError> {
        self.unit.platform.check_cpu()?;
        if self.target.is_none() || self.retired {
            return Err(IrqError::Route);
        }
        // Contributors may assert while IOAPIC is still masked; enabling the
        // final route observes an already asserted level and delivers it.
        unsafe { self.devices.enable() }?;
        let _guard = self.unit.lock();
        let low = self.unit.low(self.pin)?;
        if low & MASK == 0 || low & (REMOTE_IRR | DELIVERY) != 0 {
            return Err(IrqError::Drain);
        }
        self.unit.registers.write(0x10 + self.pin * 2, low & !MASK);
        if self.unit.low(self.pin)? & MASK != 0 {
            return Err(IrqError::Mask);
        }
        Ok(())
    }
    unsafe fn synchronize(&mut self) -> Result<(), IrqError> {
        self.unit.platform.check_cpu()?;
        self.devices.quiesce()?;
        let start = self.unit.platform.ticks();
        loop {
            let low = {
                let _guard = self.unit.lock();
                self.unit.low(self.pin)?
            };
            if low & MASK == 0 {
                return Err(IrqError::Mask);
            }
            if low & (REMOTE_IRR | DELIVERY) == 0 {
                break;
            }
            if self.unit.platform.ticks().wrapping_sub(start) >= self.unit.platform.timeout_ticks()
            {
                return Err(IrqError::Drain);
            }
            core::hint::spin_loop();
        }
        if let Some(target) = self.target
            && self.unit.platform.pending(target.vector)?
        {
            return Err(IrqError::Drain);
        }
        self.retired = true;
        // Controller and callback retirement completed. Keep the physical pin
        // claim until Source Drop, while refusing every old handler endpoint.
        let _guard = self.unit.lock();
        unsafe { (*self.unit.epochs.get())[usize::from(self.pin)] = 0 };
        Ok(())
    }
}
impl<R: Registers, P: Platform> Drop for Pin<R, P> {
    fn drop(&mut self) {
        if !self.retired || self.unit.platform.check_cpu().is_err() {
            self.unit.quarantined.fetch_add(1, Ordering::Relaxed);
            return;
        }
        {
            let _guard = self.unit.lock();
            unsafe {
                (*self.unit.claims.get())[usize::from(self.pin)] = false;
                (*self.unit.epochs.get())[usize::from(self.pin)] = 0;
            }
        }
        // Actual registry retirement proved callback lifetime + CPU/IOAPIC
        // drain; only this process-context final release frees contributors.
        unsafe {
            ManuallyDrop::drop(&mut self.devices);
            ManuallyDrop::drop(&mut self.unit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use core::sync::atomic::{AtomicPtr, AtomicUsize};
    use std::sync::Mutex;
    use stela_drivers::bus::irq::{Disposition, Handler, Registry, SharedHandlers};
    struct Hardware {
        regs: [u32; 256],
        asserted: u32,
        pending: bool,
        fail_read: bool,
        refuse_mask: bool,
        broken_eoi: bool,
        events: alloc::vec::Vec<&'static str>,
    }
    impl Hardware {
        fn service(&mut self) {
            let low = self.regs[0x22]; // GSI9, true level state, one pending vector.
            if self.asserted != 0 && low & (MASK | REMOTE_IRR) == 0 {
                assert_ne!(
                    low & (1 << 15),
                    0,
                    "fixture must be genuinely level-triggered"
                );
                self.regs[0x22] |= REMOTE_IRR;
                self.pending = true;
                self.events.push("deliver");
            }
        }
        fn eoi(&mut self) {
            self.pending = false;
            self.events.push("eoi");
            if !self.broken_eoi {
                self.regs[0x22] &= !REMOTE_IRR;
                self.service();
            }
        }
    }
    struct Board {
        hw: Mutex<Hardware>,
        ticks: AtomicU64,
        drops: AtomicUsize,
        calls: AtomicUsize,
        registry: AtomicPtr<Registry<Cpu>>,
        vector: core::sync::atomic::AtomicU8,
    }
    impl Board {
        fn new() -> Arc<Self> {
            let mut regs = [0; 256];
            regs[1] = 0x11 | 23 << 16;
            for pin in 0..24 {
                regs[0x10 + pin * 2] = MASK;
            }
            Arc::new(Self {
                hw: Mutex::new(Hardware {
                    regs,
                    asserted: 0,
                    pending: false,
                    fail_read: false,
                    refuse_mask: false,
                    broken_eoi: false,
                    events: alloc::vec::Vec::new(),
                }),
                ticks: AtomicU64::new(0),
                drops: AtomicUsize::new(0),
                calls: AtomicUsize::new(0),
                registry: AtomicPtr::new(core::ptr::null_mut()),
                vector: core::sync::atomic::AtomicU8::new(0),
            })
        }
    }
    struct Io(Arc<Board>);
    unsafe impl Registers for Io {
        fn read(&self, i: u8) -> u32 {
            let h = self.0.hw.lock().unwrap();
            if h.fail_read {
                u32::MAX
            } else {
                h.regs[usize::from(i)]
            }
        }
        fn write(&self, i: u8, v: u32) {
            let mut h = self.0.hw.lock().unwrap();
            let i = usize::from(i);
            if i >= 0x10 && i % 2 == 1 {
                assert_ne!(
                    h.regs[i - 1] & MASK,
                    0,
                    "destination changed before acknowledged mask"
                );
                assert_eq!(
                    h.regs[i - 1] & (REMOTE_IRR | DELIVERY),
                    0,
                    "live route was reprogrammed"
                );
                h.events.push("destination");
                h.regs[i] = v;
            } else if i >= 0x10 {
                let old = h.regs[i];
                if h.refuse_mask && v & MASK != 0 {
                    return;
                }
                if old & CONFIG != v & CONFIG && (old ^ v) & !MASK != 0 {
                    assert_ne!(old & MASK, 0, "electrical/vector changed before mask");
                    assert_eq!(old & (REMOTE_IRR | DELIVERY), 0);
                }
                // Actual hardware does not allow software to clear RO RemoteIRR.
                h.regs[i] = (v & !(REMOTE_IRR | DELIVERY)) | old & (REMOTE_IRR | DELIVERY);
                h.events.push(if v & MASK != 0 { "mask" } else { "unmask" });
                h.service();
            }
        }
    }
    struct Cpu(Arc<Board>);
    unsafe impl Platform for Cpu {
        fn check_cpu(&self) -> Result<(), IrqError> {
            Ok(())
        }
        fn save_and_disable(&self) -> u64 {
            0
        }
        unsafe fn restore(&self, s: u64) {
            assert_eq!(s, 0);
        }
        fn target(&self, v: u8) -> Result<Target, IrqError> {
            self.0.vector.store(v, Ordering::Relaxed);
            Ok(Target {
                destination: 3,
                vector: v,
            })
        }
        fn pending(&self, _: u8) -> Result<bool, IrqError> {
            Ok(self.0.hw.lock().unwrap().pending)
        }
        fn eoi(&self) {
            self.0.hw.lock().unwrap().eoi();
        }
        fn ticks(&self) -> u64 {
            self.0.ticks.fetch_add(1, Ordering::Relaxed)
        }
        fn timeout_ticks(&self) -> u64 {
            8
        }
        unsafe fn interrupt_window(&self) {
            let r = unsafe { &*self.0.registry.load(Ordering::Relaxed) };
            assert!(r.dispatch(self.0.vector.load(Ordering::Relaxed)));
        }
    }
    struct Contributors(Arc<Board>);
    unsafe impl Devices for Contributors {
        fn mask(&mut self) -> Result<(), IrqError> {
            self.0.hw.lock().unwrap().events.push("device_mask");
            Ok(())
        }
        fn quiesce(&mut self) -> Result<(), IrqError> {
            let mut h = self.0.hw.lock().unwrap();
            h.asserted = 0;
            h.events.push("stopped");
            Ok(())
        }
        unsafe fn enable(&mut self) -> Result<(), IrqError> {
            self.0.hw.lock().unwrap().events.push("device_enable");
            Ok(())
        }
    }
    impl Drop for Contributors {
        fn drop(&mut self) {
            self.0.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct Member(Arc<Board>, u32, bool);
    impl Handler for Member {
        fn handle(&self) -> Disposition {
            let mut h = self.0.hw.lock().unwrap();
            self.0.calls.fetch_add(1, Ordering::Relaxed);
            if h.asserted & self.1 == 0 {
                return Disposition::NotMine;
            }
            if self.2 {
                h.asserted &= !self.1;
                h.events.push("cause_ack");
            }
            Disposition::Handled
        }
    }
    type Fixture = (
        Arc<Board>,
        Arc<Unit<Io, Cpu>>,
        &'static Registry<Cpu>,
        LineRoute,
    );
    fn fixture() -> Fixture {
        let b = Board::new();
        let u = unsafe { Unit::attach(Io(b.clone()), Cpu(b.clone()), 0, 0) }.unwrap();
        let r = Box::leak(Box::new(Registry::new(Cpu(b.clone()))));
        b.registry.store(r, Ordering::Relaxed);
        (
            b,
            u,
            r,
            LineRoute {
                gsi: 9,
                polarity: Polarity::Low,
                trigger: Trigger::Level,
            },
        )
    }
    #[test]
    fn real_parent_mask_contains_asserted_level_and_stale_endpoint_cannot_mask_reused_pin() {
        struct FailedDemux(Arc<ParentMask<Io, Cpu>>);
        impl Handler for FailedDemux {
            fn handle(&self) -> Disposition {
                // Actual callback cannot ACK its device. It must acknowledge
                // parent MASK before Registry's EOI instead of returning live.
                stela_drivers::bus::irq::ParentMask::mask(&*self.0).unwrap();
                Disposition::Handled
            }
        }
        let (b, u, r, line) = fixture();
        let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
        let endpoint = Arc::new(pin.parent_mask().unwrap());
        let mut registration = r
            .request(Box::new(pin), Arc::new(FailedDemux(endpoint.clone())))
            .unwrap();
        {
            let mut h = b.hw.lock().unwrap();
            h.asserted = 1;
            h.service();
        }
        assert!(r.dispatch(registration.vector()));
        {
            let h = b.hw.lock().unwrap();
            assert_eq!(
                h.asserted, 1,
                "test must retain the unacknowledged child cause"
            );
            assert_ne!(h.regs[0x22] & MASK, 0);
            assert_eq!(h.regs[0x22] & REMOTE_IRR, 0);
            assert!(!h.pending, "masked parent must not retrigger after EOI");
        }
        registration.retire().unwrap();
        assert_eq!(
            stela_drivers::bus::irq::ParentMask::mask(&*endpoint),
            Err(IrqError::Unregistered)
        );
        let replacement = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
        let replacement_mask = replacement.parent_mask().unwrap();
        let mut replacement = r
            .request(Box::new(replacement), Arc::new(Member(b.clone(), 1, true)))
            .unwrap();
        assert_eq!(
            stela_drivers::bus::irq::ParentMask::mask(&*endpoint),
            Err(IrqError::Unregistered)
        );
        assert_eq!(
            b.hw.lock().unwrap().regs[0x22] & MASK,
            0,
            "stale endpoint changed the new live route"
        );
        assert_eq!(
            stela_drivers::bus::irq::ParentMask::mask(&replacement_mask),
            Ok(())
        );
        replacement.retire().unwrap();
    }

    #[test]
    fn parent_mask_readback_failures_are_errors_and_claim_epochs_never_wrap() {
        let (b, u, r, line) = fixture();
        let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
        let endpoint = pin.parent_mask().unwrap();
        let mut registration = r
            .request(Box::new(pin), Arc::new(Member(b.clone(), 1, true)))
            .unwrap();
        b.hw.lock().unwrap().refuse_mask = true;
        assert_eq!(
            stela_drivers::bus::irq::ParentMask::mask(&endpoint),
            Err(IrqError::Mask)
        );
        b.hw.lock().unwrap().fail_read = true;
        assert_eq!(
            stela_drivers::bus::irq::ParentMask::mask(&endpoint),
            Err(IrqError::FailedRead)
        );
        {
            let mut h = b.hw.lock().unwrap();
            h.fail_read = false;
            h.refuse_mask = false;
        }
        registration.retire().unwrap();
        {
            let _guard = u.lock();
            unsafe { *u.next_epoch.get() = u64::MAX };
        }
        assert!(matches!(
            unsafe { u.claim(line, Box::new(Contributors(b.clone()))) },
            Err(IrqError::Exhausted)
        ));
        assert_eq!(
            stela_drivers::bus::irq::ParentMask::mask(&endpoint),
            Err(IrqError::Unregistered)
        );
    }

    #[test]
    fn true_level_retriggers_after_eoi_until_cause_ack_then_shared_group_retires() {
        let (b, u, r, line) = fixture();
        let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
        let first: Arc<dyn Handler> = Arc::new(Member(b.clone(), 1, false));
        let second: Arc<dyn Handler> = Arc::new(Member(b.clone(), 2, true));
        let group =
            Arc::new(SharedHandlers::new(alloc::vec![first.clone(), second.clone()]).unwrap());
        let mut registration = r.request(Box::new(pin), group.clone()).unwrap();
        {
            let mut h = b.hw.lock().unwrap();
            h.asserted = 3;
            h.service();
        }
        assert!(r.dispatch(registration.vector()));
        {
            let h = b.hw.lock().unwrap();
            assert_eq!(h.asserted, 1);
            assert!(h.pending);
            assert_ne!(h.regs[0x22] & REMOTE_IRR, 0);
        }
        assert_eq!(registration.handled(), Ok(1));
        assert_eq!(Arc::strong_count(&group), 2);
        assert_eq!(Arc::strong_count(&first), 2);
        // A second actual delivery remains possible; removal must mask first,
        // stop every contributor, then drain CPU EOI and IOAPIC RemoteIRR.
        registration.retire().unwrap();
        let h = b.hw.lock().unwrap();
        assert!(!h.pending);
        assert_eq!(h.regs[0x22] & REMOTE_IRR, 0);
        assert_ne!(h.regs[0x22] & MASK, 0);
        let mask = h.events.iter().rposition(|s| *s == "mask").unwrap();
        let stop = h.events.iter().rposition(|s| *s == "stopped").unwrap();
        assert!(mask < stop);
        assert_eq!(
            b.calls.load(Ordering::Relaxed),
            2,
            "closing delivery must never enter members"
        );
        drop(h);
        assert_eq!(b.drops.load(Ordering::Relaxed), 1);
        assert_eq!(Arc::strong_count(&group), 1);
        let reused = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
        drop(reused);
    }
    #[test]
    fn failed_controller_eoi_or_read_retains_route_and_contributors_for_real_retry() {
        let (b, u, r, line) = fixture();
        let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
        let mut registration = r
            .request(Box::new(pin), Arc::new(Member(b.clone(), 1, true)))
            .unwrap();
        {
            let mut h = b.hw.lock().unwrap();
            h.asserted = 1;
            h.service();
            h.broken_eoi = true;
        }
        assert_eq!(registration.retire(), Err(IrqError::Drain));
        assert_eq!(b.drops.load(Ordering::Relaxed), 0);
        assert!(matches!(
            unsafe { u.claim(line, Box::new(Contributors(b.clone()))) },
            Err(IrqError::Drain)
        ));
        {
            let mut h = b.hw.lock().unwrap();
            h.fail_read = true;
        }
        assert_eq!(registration.retire(), Err(IrqError::FailedRead));
        {
            let mut h = b.hw.lock().unwrap();
            h.fail_read = false;
            h.broken_eoi = false;
            h.eoi();
        }
        registration.retire().unwrap();
        assert_eq!(u.quarantine_count(), 0);
    }
    #[test]
    fn electrical_route_mismatch_duplicate_claim_mask_failure_and_abandoned_pin_are_retained() {
        let (b, u, r, line) = fixture();
        assert!(matches!(
            unsafe {
                u.claim(
                    LineRoute {
                        trigger: Trigger::Edge,
                        ..line
                    },
                    Box::new(Contributors(b.clone())),
                )
            },
            Err(IrqError::Unsupported)
        ));
        let mut pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
        assert!(matches!(
            unsafe { u.claim(line, Box::new(Contributors(b.clone()))) },
            Err(IrqError::Exhausted)
        ));
        let mismatch = LineRoute { gsi: 8, ..line };
        assert_eq!(
            unsafe {
                pin.program(Route::Line {
                    target: Target {
                        destination: 3,
                        vector: FIRST_VECTOR,
                    },
                    line: mismatch,
                })
            },
            Err(IrqError::Route)
        );
        let mut registration = r
            .request(Box::new(pin), Arc::new(Member(b.clone(), 1, true)))
            .unwrap();
        b.hw.lock().unwrap().refuse_mask = true;
        assert_eq!(registration.retire(), Err(IrqError::Mask));
        let before = b.drops.load(Ordering::Relaxed);
        drop(registration);
        assert_eq!(r.quarantine_count(), 1);
        assert_eq!(b.drops.load(Ordering::Relaxed), before);
        // Raw source owner also cannot silently free a programmed pin without
        // the unsafe completed-synchronization proof supplied by Registry.
        b.hw.lock().unwrap().refuse_mask = false;
        let other = LineRoute { gsi: 10, ..line };
        let mut pin = unsafe { u.claim(other, Box::new(Contributors(b.clone()))) }.unwrap();
        unsafe {
            pin.program(Route::Line {
                target: Target {
                    destination: 3,
                    vector: FIRST_VECTOR + 1,
                },
                line: other,
            })
        }
        .unwrap();
        drop(pin);
        assert_eq!(u.quarantine_count(), 1);
    }
}
