// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Native NHI controller preparation from Linux pci.c/nhi.c.
//!
//! Intel force-power/FW_READY/LTR, USB4v2 host reset and interrupt
//! masking. This never claims CM ownership, enables PCI bus mastering, supplies
//! an identity DMA domain or starts rings/tunnels. Platform grants precede it.
use super::ring::{CAPABILITIES, Registers};
use crate::bus::pci::ConfigSpace;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
const RESET: usize = 0x39898;
const INTERRUPT: usize = 0x38200;
const MASK_CLEAR: usize = 0x38208;
const NOTIFY: usize = 0x37800;
const INT_CLEAR: usize = 0x37808;
const VS_FW_READY: u16 = 0xc8;
const VS_LTR: u16 = 0xe0;
const VS_MAX_LTR: u16 = 0xe4;
const VS_FORCE: u16 = 0xfc;
const FORCE: u32 = 1 << 1;
const DMA_DELAY: u32 = 0xff00_0000;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_controllers() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    IntelDiscrete,
    IntelIntegrated,
    Usb4Compliant,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptStyle {
    IntelAutoClear,
    Usb4MaskClear,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    vendor: u16,
    device: u16,
    class: u32,
    family: Family,
}
impl Profile {
    pub fn vendor(self) -> u16 {
        self.vendor
    }
    pub fn device(self) -> u16 {
        self.device
    }
    pub fn class(self) -> u32 {
        self.class
    }
    pub fn family(self) -> Family {
        self.family
    }
    pub fn interrupt_style(self) -> InterruptStyle {
        if self.vendor == 0x8086 {
            InterruptStyle::IntelAutoClear
        } else {
            InterruptStyle::Usb4MaskClear
        }
    }
    fn select(vendor: u16, device: u16, class: u32) -> Result<Self, Error> {
        if vendor == 0 || vendor == u16::MAX || device == u16::MAX || class == 0xff_ffff {
            return Err(Error::Identity);
        }
        if vendor == 0x8086 && matches!(device, 0x1513 | 0x151a | 0x1547 | 0x156a | 0x156c) {
            return Err(Error::LegacyUnsupported);
        }
        // pci.c::nhi_ids attaches icl_nhi_ops to these exact integrated IDs;
        // the generic USB4 class must not accidentally inherit vendor registers.
        let family = if vendor == 0x8086
            && matches!(
                device,
                0x8a0d
                    | 0x8a17
                    | 0x9a1b
                    | 0x9a1d
                    | 0x9a1f
                    | 0x9a21
                    | 0x463e
                    | 0x466d
                    | 0xa73e
                    | 0xa76d
                    | 0x7eb2
                    | 0x7ec2
                    | 0x7ec3
                    | 0xa833
                    | 0xa834
                    | 0xe333
                    | 0xe334
                    | 0xe433
                    | 0xe434
                    | 0x4d33
            ) {
            Family::IntelIntegrated
        } else if vendor == 0x8086
            && matches!(
                device,
                0x1575
                    | 0x1577
                    | 0x15dd
                    | 0x15bf
                    | 0x15dc
                    | 0x15d9
                    | 0x15d2
                    | 0x15de
                    | 0x15e8
                    | 0x15eb
                    | 0x5781
                    | 0x5784
            )
        {
            Family::IntelDiscrete
        } else if class == 0x0c0340 {
            Family::Usb4Compliant
        } else {
            return Err(Error::Unsupported);
        };
        if !matches!(class, 0x088000 | 0x0c0340) {
            return Err(Error::Identity);
        }
        Ok(Self {
            vendor,
            device,
            class,
            family,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub profile: Profile,
    pub capabilities: u32,
    pub hop_count: u16,
    pub version: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Unsupported,
    LegacyUnsupported,
    PciState,
    PciRead(u16),
    PciRejected(u16),
    Mapping,
    Capabilities,
    Busy,
    RegisterRead(usize),
    RegisterRejected(usize),
    ClockOverflow,
    ClockRegressed,
    FirmwareTimeout,
    ResetTimeout,
    Stopped,
    Poisoned,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    Firmware {
        next: u64,
        deadline: u64,
        reads: u16,
    },
    Reset {
        earliest: u64,
        deadline: u64,
    },
    Prepared,
    Fault,
}
/// Caller-serialized controller preparation. Clock observations use one
/// monotonic millisecond source; polls never sleep or invent timer progress.
pub struct Controller<'a, C: ConfigSpace, R: Registers> {
    configuration: &'a mut C,
    registers: Arc<R>,
    profile: Profile,
    capabilities: u32,
    phase: Phase,
    last_now: Option<u64>,
    mutated: bool,
}
impl<'a, C: ConfigSpace, R: Registers> Controller<'a, C, R> {
    /// # Safety
    /// ConfigSpace and Registers identify the same live physical NHI
    /// requester, ownership/reset epoch and BAR0. The kept Registers owns
    /// its PCI function/MMIO/power reservation, including quarantine.
    /// Native ACPI/platform services positively granted software CM ownership;
    /// no firmware ICM or other owner controls this NHI. Shared power
    /// resources and PCI D0/memory decode are established and kept. The
    /// platform resolves the firmware IMR_VALID property and rejects invalid
    /// firmware instead of substituting an unknown/default-success result. All
    /// prior NHI DMA/posted writes and IRQ/deferred work are stopped/drained;
    /// no active ring or tunneled path may be reset. PCI bus mastering stays
    /// disabled until its requester-isolating domain has been attached.
    ///
    /// Safe code cannot pair independent physical PCI and MMIO capabilities:
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::{pci::ConfigSpace, thunderbolt::{
    ///     controller::Controller, ring::Registers,
    /// }};
    /// fn pair<C: ConfigSpace, R: Registers>(pci: &mut C, registers: Arc<R>) {
    ///     let _controller = Controller::new(pci, registers);
    /// }
    /// ```
    pub unsafe fn new(configuration: &'a mut C, registers: Arc<R>) -> Result<Self, Error> {
        let identity = configuration.read32(0);
        if identity == u32::MAX {
            return Err(Error::PciRead(0));
        }
        let class = configuration.read32(8);
        if class == u32::MAX {
            return Err(Error::PciRead(8));
        }
        let profile = Profile::select(identity as u16, (identity >> 16) as u16, class >> 8)?;
        let header = configuration.read8(0x0e);
        if header & 0x7f != 0 {
            return Err(Error::Identity);
        }
        Self::pci_state(configuration)?;
        if registers.bytes() < RESET + 4 {
            return Err(Error::Mapping);
        }
        let capabilities = registers.read32(CAPABILITIES);
        if capabilities == u32::MAX || capabilities & 0x3ff == 0 {
            return Err(Error::Capabilities);
        }
        Ok(Self {
            configuration,
            registers,
            profile,
            capabilities,
            phase: Phase::New,
            last_now: None,
            mutated: false,
        })
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn registers(&self) -> Arc<R> {
        self.registers.clone()
    }
    fn pci_state(configuration: &C) -> Result<(), Error> {
        let command = configuration.read16(4);
        if command == u16::MAX {
            return Err(Error::PciRead(4));
        }
        if command & 2 == 0 || command & 4 != 0 {
            return Err(Error::PciState);
        }
        Ok(())
    }
    fn identity(&self) -> Result<(), Error> {
        let expected = u32::from(self.profile.vendor) | (u32::from(self.profile.device) << 16);
        if self.configuration.read32(0) != expected
            || self.configuration.read32(8) >> 8 != self.profile.class
        {
            return Err(Error::Identity);
        }
        Self::pci_state(self.configuration)
    }
    fn read_pci(&self, offset: u16) -> Result<u32, Error> {
        let value = self.configuration.read32(offset);
        if value == u32::MAX {
            Err(Error::PciRead(offset))
        } else {
            Ok(value)
        }
    }
    fn write_pci(&mut self, offset: u16, value: u32, mask: u32) -> Result<(), Error> {
        self.identity()?;
        self.mutated = true;
        self.configuration.write32(offset, value);
        if self.configuration.read32(offset) & mask != value & mask {
            return Err(Error::PciRejected(offset));
        }
        self.identity()
    }
    fn read_register(&self, offset: usize) -> Result<u32, Error> {
        let value = self.registers.read32(offset);
        if value == u32::MAX {
            Err(Error::RegisterRead(offset))
        } else {
            Ok(value)
        }
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.phase = Phase::Fault;
        Err(error)
    }
    fn preflight(&self) -> Result<(), Error> {
        self.identity()?;
        if self.read_register(CAPABILITIES)? != self.capabilities {
            return Err(Error::Capabilities);
        }
        for hop in 0..usize::from((self.capabilities & 0x3ff) as u16) {
            for base in [0x19800, 0x29800] {
                if self.read_register(base + hop * 32)? & (1 << 31) != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        Ok(())
    }
    fn force_power(&mut self, now: u64) -> Result<(), Error> {
        let deadline = now.checked_add(1050).ok_or(Error::ClockOverflow)?;
        let value = self.read_pci(VS_FORCE)?;
        let value = (value & !DMA_DELAY) | (0x22 << 24) | FORCE;
        self.write_pci(VS_FORCE, value, DMA_DELAY | FORCE)?;
        self.phase = Phase::Firmware {
            next: now,
            deadline,
            reads: 0,
        };
        Ok(())
    }
    fn reset_or_mask(&mut self, now: u64) -> Result<Option<Prepared>, Error> {
        if (self.capabilities >> 16) & 255 < 0x40 {
            return self.mask(now);
        }
        let earliest = now.checked_add(100).ok_or(Error::ClockOverflow)?;
        let deadline = earliest.checked_add(500).ok_or(Error::ClockOverflow)?;
        self.mutated = true;
        self.registers.write32(RESET, 1);
        // HRR can self-clear immediately; a zero read is not completion until
        // the source-required minimum 100 ms interval has elapsed.
        let _ = self.read_register(RESET)?;
        self.phase = Phase::Reset { earliest, deadline };
        Ok(None)
    }
    fn mask(&mut self, now: u64) -> Result<Option<Prepared>, Error> {
        self.identity()?;
        let hops = (self.capabilities & 0x3ff) as usize;
        for index in 0..(2 * hops).div_ceil(32) {
            let offset = index * 4;
            self.mutated = true;
            match self.profile.interrupt_style() {
                InterruptStyle::IntelAutoClear => {
                    // All-one interrupt enables are valid, not a bus-failure
                    // sentinel. Verify the zero write instead of rejecting it.
                    let _ = self.registers.read32(INTERRUPT + offset);
                    self.registers.write32(INTERRUPT + offset, 0);
                }
                InterruptStyle::Usb4MaskClear => {
                    self.registers.write32(MASK_CLEAR + offset, u32::MAX)
                }
            }
            if self.registers.read32(INTERRUPT + offset) != 0 {
                return Err(Error::RegisterRejected(INTERRUPT + offset));
            }
        }
        for index in 0..(3 * hops).div_ceil(32) {
            let offset = index * 4;
            match self.profile.interrupt_style() {
                InterruptStyle::IntelAutoClear => {
                    let _ = self.registers.read32(NOTIFY + offset);
                }
                InterruptStyle::Usb4MaskClear => {
                    self.registers.write32(INT_CLEAR + offset, u32::MAX)
                }
            }
        }
        // Same-function MMIO read flushes posted writes. These source-defined
        // mask/clear effects still do not drain platform IRQ/deferred handlers.
        if self.read_register(CAPABILITIES)? != self.capabilities {
            return Err(Error::Capabilities);
        }
        self.identity()?;
        if self.profile.family == Family::IntelIntegrated {
            self.force_power(now)?;
            return Ok(None);
        }
        self.prepared()
    }
    fn prepared(&mut self) -> Result<Option<Prepared>, Error> {
        self.identity()?;
        if self.read_register(CAPABILITIES)? != self.capabilities {
            return Err(Error::Capabilities);
        }
        self.phase = Phase::Prepared;
        Ok(Some(Prepared {
            profile: self.profile,
            capabilities: self.capabilities,
            hop_count: (self.capabilities & 0x3ff) as u16,
            version: (self.capabilities >> 16) as u8,
        }))
    }
    pub fn poll(&mut self, now_ms: u64) -> Result<Option<Prepared>, Error> {
        match self.phase {
            Phase::Prepared => return Err(Error::Stopped),
            Phase::Fault => return Err(Error::Poisoned),
            _ => {}
        }
        if self.last_now.is_some_and(|last| now_ms < last) {
            return self.fail(Error::ClockRegressed);
        }
        self.last_now = Some(now_ms);
        let result = (|| match self.phase {
            Phase::New => {
                self.preflight()?;
                let reset_budget = if (self.capabilities >> 16) & 255 >= 0x40 {
                    600
                } else {
                    0
                };
                let firmware_budget = if self.profile.family == Family::IntelIntegrated {
                    1050
                } else {
                    0
                };
                let _ = now_ms
                    .checked_add(reset_budget + firmware_budget)
                    .ok_or(Error::ClockOverflow)?;
                self.reset_or_mask(now_ms)
            }
            Phase::Firmware {
                next,
                deadline,
                reads,
            } => {
                if now_ms >= deadline {
                    return Err(Error::FirmwareTimeout);
                }
                if now_ms < next {
                    return Ok(None);
                }
                if reads >= 350 {
                    return Err(Error::FirmwareTimeout);
                }
                if self.read_pci(VS_FW_READY)? & (1 << 31) != 0 {
                    let ltr = self.read_pci(VS_MAX_LTR)? & 0xffff;
                    self.write_pci(VS_LTR, ltr | (ltr << 16), u32::MAX)?;
                    self.prepared()
                } else {
                    self.phase = Phase::Firmware {
                        next: now_ms.checked_add(3).ok_or(Error::ClockOverflow)?,
                        deadline,
                        reads: reads + 1,
                    };
                    Ok(None)
                }
            }
            Phase::Reset { earliest, deadline } => {
                if now_ms >= deadline {
                    return Err(Error::ResetTimeout);
                }
                if now_ms < earliest {
                    return Ok(None);
                }
                if self.read_register(RESET)? & 1 != 0 {
                    return Ok(None);
                }
                self.mask(now_ms)
            }
            _ => Err(Error::Stopped),
        })();
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }
}
impl<C: ConfigSpace, R: Registers> Drop for Controller<'_, C, R> {
    fn drop(&mut self) {
        if self.mutated && self.phase != Phase::Prepared {
            let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
            core::mem::forget(self.registers.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use std::sync::Mutex;
    struct PciState {
        values: Vec<u32>,
        writes: Vec<(u16, u32)>,
        fail: Option<u16>,
        reject: Option<u16>,
        ready_at: u64,
        ready_delay: u64,
    }
    struct Pci {
        state: Arc<Mutex<PciState>>,
        clock: Arc<AtomicU64>,
    }
    impl ConfigSpace for Pci {
        fn read32(&self, offset: u16) -> u32 {
            let state = self.state.lock().unwrap();
            if state.fail == Some(offset) {
                return u32::MAX;
            }
            let mut value = state.values[usize::from(offset) / 4];
            if offset == VS_FW_READY && self.clock.load(Ordering::Relaxed) >= state.ready_at {
                value |= 1 << 31;
            }
            value
        }
        fn write32(&mut self, offset: u16, value: u32) {
            let mut state = self.state.lock().unwrap();
            state.writes.push((offset, value));
            if state.reject != Some(offset) {
                state.values[usize::from(offset) / 4] = value;
                if offset == VS_FORCE && value & FORCE != 0 {
                    state.ready_at = self
                        .clock
                        .load(Ordering::Relaxed)
                        .saturating_add(state.ready_delay);
                }
            }
        }
    }
    struct RegistersState {
        values: BTreeMap<usize, u32>,
        writes: Vec<(usize, u32)>,
        masks: Vec<u32>,
        notify: Vec<u32>,
        reject: Option<usize>,
        fail: Option<usize>,
        reset_delay: u64,
        reset_clear_at: u64,
    }
    struct Model {
        state: Mutex<RegistersState>,
        clock: Arc<AtomicU64>,
        style: InterruptStyle,
    }
    // SAFETY: this model owns one synthetic PCI/MMIO requester and reset epoch;
    // its mutex preserves real read-clear/write-clear/reset failure effects.
    unsafe impl Registers for Model {
        fn bytes(&self) -> usize {
            RESET + 4
        }
        fn read32(&self, offset: usize) -> u32 {
            let mut state = self.state.lock().unwrap();
            if state.fail == Some(offset) {
                return u32::MAX;
            }
            if (INTERRUPT..INTERRUPT + state.masks.len() * 4).contains(&offset) {
                return state.masks[(offset - INTERRUPT) / 4];
            }
            if (NOTIFY..NOTIFY + state.notify.len() * 4).contains(&offset) {
                let index = (offset - NOTIFY) / 4;
                let value = state.notify[index];
                if self.style == InterruptStyle::IntelAutoClear {
                    state.notify[index] = 0;
                }
                return value;
            }
            if offset == RESET && self.clock.load(Ordering::Relaxed) >= state.reset_clear_at {
                state.values.insert(RESET, 0);
            }
            *state.values.get(&offset).unwrap_or(&0)
        }
        fn write32(&self, offset: usize, value: u32) {
            let mut state = self.state.lock().unwrap();
            state.writes.push((offset, value));
            if state.reject == Some(offset) {
                return;
            }
            if self.style == InterruptStyle::Usb4MaskClear
                && (MASK_CLEAR..MASK_CLEAR + state.masks.len() * 4).contains(&offset)
            {
                state.masks[(offset - MASK_CLEAR) / 4] &= !value;
                return;
            }
            if self.style == InterruptStyle::IntelAutoClear
                && (INTERRUPT..INTERRUPT + state.masks.len() * 4).contains(&offset)
            {
                state.masks[(offset - INTERRUPT) / 4] = value;
                return;
            }
            if self.style == InterruptStyle::Usb4MaskClear
                && (INT_CLEAR..INT_CLEAR + state.notify.len() * 4).contains(&offset)
            {
                state.notify[(offset - INT_CLEAR) / 4] &= !value;
                return;
            }
            state.values.insert(offset, value);
            if offset == RESET {
                state.reset_clear_at = self
                    .clock
                    .load(Ordering::Relaxed)
                    .saturating_add(state.reset_delay);
            }
        }
    }
    fn fixture(vendor: u16, device: u16, class: u32, version: u8, hops: u16) -> (Pci, Arc<Model>) {
        let clock = Arc::new(AtomicU64::new(0));
        let mut values = vec![0; 1024];
        values[0] = u32::from(vendor) | (u32::from(device) << 16);
        values[1] = 2;
        values[2] = (class << 8) | 3;
        values[usize::from(VS_FORCE) / 4] = 0x98ab5678;
        values[usize::from(VS_MAX_LTR) / 4] = 0xdead1234;
        let pci = Pci {
            state: Arc::new(Mutex::new(PciState {
                values,
                writes: Vec::new(),
                fail: None,
                reject: None,
                ready_at: u64::MAX,
                ready_delay: 6,
            })),
            clock: clock.clone(),
        };
        let mut registers = BTreeMap::new();
        registers.insert(CAPABILITIES, (u32::from(version) << 16) | u32::from(hops));
        let model = Arc::new(Model {
            state: Mutex::new(RegistersState {
                values: registers,
                writes: Vec::new(),
                masks: vec![u32::MAX; (usize::from(hops) * 2).div_ceil(32)],
                notify: vec![u32::MAX; (usize::from(hops) * 3).div_ceil(32)],
                reject: None,
                fail: None,
                reset_delay: 50,
                reset_clear_at: u64::MAX,
            }),
            clock,
            style: if vendor == 0x8086 {
                InterruptStyle::IntelAutoClear
            } else {
                InterruptStyle::Usb4MaskClear
            },
        });
        (pci, model)
    }
    fn poll(
        controller: &mut Controller<'_, Pci, Model>,
        now: u64,
    ) -> Result<Option<Prepared>, Error> {
        controller.registers.clock.store(now, Ordering::Relaxed);
        controller.poll(now)
    }
    #[test]
    fn intel_integrated_actual_force_ready_ltr_reset_and_interrupt_register_effects() {
        let (mut pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x40, 8);
        let state = pci.state.clone();
        // SAFETY: both surfaces are this same exclusively owned synthetic
        // requester/epoch, real modeled D0/decode, master off, no prior DMA/IRQ.
        let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
        assert_eq!(poll(&mut controller, 0).unwrap(), None);
        assert!(state.lock().unwrap().writes.is_empty());
        assert_eq!(model.state.lock().unwrap().writes, vec![(RESET, 1)]);
        assert_eq!(poll(&mut controller, 99).unwrap(), None);
        assert_eq!(poll(&mut controller, 100).unwrap(), None);
        assert_eq!(state.lock().unwrap().writes, vec![(VS_FORCE, 0x22ab567a)]);
        for now in [100, 101, 103, 105] {
            assert_eq!(poll(&mut controller, now).unwrap(), None);
        }
        let prepared = poll(&mut controller, 106).unwrap().unwrap();
        assert_eq!(
            state.lock().unwrap().writes,
            vec![(VS_FORCE, 0x22ab567a), (VS_LTR, 0x12341234)]
        );
        assert_eq!(prepared.hop_count, 8);
        assert_eq!(prepared.profile.family(), Family::IntelIntegrated);
        assert_eq!(prepared.version, 0x40);
        assert!(
            model
                .state
                .lock()
                .unwrap()
                .masks
                .iter()
                .all(|value| *value == 0)
        );
        assert!(
            model
                .state
                .lock()
                .unwrap()
                .notify
                .iter()
                .all(|value| *value == 0)
        );
        assert_eq!(poll(&mut controller, 107), Err(Error::Stopped));
        assert!(
            state
                .lock()
                .unwrap()
                .writes
                .iter()
                .all(|(offset, _)| *offset != 4)
        );
    }
    #[test]
    fn generic_usb4_amd_uses_source_mask_clear_banks_and_discrete_skips_icl_power() {
        for (vendor, device, class, version, hops) in [
            (0x1022, 0x1668, 0x0c0340, 0x40, 33),
            (0x8086, 0x1575, 0x088000, 0x20, 16),
        ] {
            let (mut pci, model) = fixture(vendor, device, class, version, hops);
            let state = pci.state.clone();
            // SAFETY: same synthetic physical requester, epoch and stopped
            // resources; all required native ownership grants are modeled.
            let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
            let result = poll(&mut controller, 0).unwrap();
            let prepared = if version >= 0x40 {
                assert_eq!(result, None);
                poll(&mut controller, 100).unwrap().unwrap()
            } else {
                result.unwrap()
            };
            assert_eq!(prepared.hop_count, hops);
            assert!(state.lock().unwrap().writes.is_empty());
            let model_state = model.state.lock().unwrap();
            assert!(model_state.masks.iter().all(|v| *v == 0));
            assert!(model_state.notify.iter().all(|v| *v == 0));
            if vendor != 0x8086 {
                assert_eq!(prepared.profile.family(), Family::Usb4Compliant);
                for index in 0..(usize::from(hops) * 2).div_ceil(32) {
                    assert!(
                        model_state
                            .writes
                            .contains(&(MASK_CLEAR + 4 * index, u32::MAX))
                    );
                }
            }
        }
    }
    #[test]
    fn identity_decode_mastering_active_ring_and_mapping_fail_before_mutation() {
        for case in 0..7 {
            let (mut pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x40, 8);
            let state = pci.state.clone();
            match case {
                0 => state.lock().unwrap().values[1] = 0,
                1 => state.lock().unwrap().values[1] = 6,
                2 => state.lock().unwrap().values[0] = u32::MAX,
                3 => state.lock().unwrap().values[0] = 0x15138086,
                4 => state.lock().unwrap().values[2] = 0x03000000,
                5 => {
                    model
                        .state
                        .lock()
                        .unwrap()
                        .values
                        .insert(CAPABILITIES, u32::MAX);
                }
                _ => {
                    model.state.lock().unwrap().values.insert(0x19800, 1 << 31);
                }
            }
            // SAFETY: synthetic identity/register faults test
            // validation; no other physical owner or DMA can exist.
            match unsafe { Controller::new(&mut pci, model.clone()) } {
                Ok(mut controller) => assert_eq!(poll(&mut controller, 0), Err(Error::Busy)),
                Err(_) => assert_ne!(case, 6),
            }
            assert!(state.lock().unwrap().writes.is_empty());
            assert!(model.state.lock().unwrap().writes.is_empty());
        }
    }
    #[test]
    fn firmware_timeout_failed_readback_and_reset_failure_quarantine_real_reservation() {
        for case in 0..5 {
            let integrated = case < 3;
            let (mut pci, model) = fixture(
                if integrated { 0x8086 } else { 0x1022 },
                if integrated { 0x9a1b } else { 0x1668 },
                0x0c0340,
                0x40,
                8,
            );
            let state = pci.state.clone();
            match case {
                0 => state.lock().unwrap().ready_delay = u64::MAX,
                1 => state.lock().unwrap().fail = Some(VS_FW_READY),
                2 => state.lock().unwrap().reject = Some(VS_LTR),
                3 => model.state.lock().unwrap().reset_delay = u64::MAX,
                _ => model.state.lock().unwrap().reject = Some(MASK_CLEAR),
            }
            // SAFETY: same stopped synthetic NHI; injected failures preserve
            // physical ownership rather than authorizing fallback startup.
            let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
            assert_eq!(poll(&mut controller, 0).unwrap(), None);
            if integrated {
                assert_eq!(poll(&mut controller, 100).unwrap(), None);
            }
            let error = match case {
                0 => {
                    for step in 0..350 {
                        assert_eq!(poll(&mut controller, 100 + step * 3).unwrap(), None);
                    }
                    poll(&mut controller, 1150)
                }
                1 => poll(&mut controller, 100),
                2 => poll(&mut controller, 106),
                3 => poll(&mut controller, 600),
                _ => poll(&mut controller, 100),
            };
            assert_eq!(
                error,
                Err(match case {
                    0 => Error::FirmwareTimeout,
                    1 => Error::PciRead(VS_FW_READY),
                    2 => Error::PciRejected(VS_LTR),
                    3 => Error::ResetTimeout,
                    _ => Error::RegisterRejected(INTERRUPT),
                })
            );
            let pci_writes = state.lock().unwrap().writes.len();
            let mmio_writes = model.state.lock().unwrap().writes.len();
            assert_eq!(poll(&mut controller, 2000), Err(Error::Poisoned));
            assert_eq!(state.lock().unwrap().writes.len(), pci_writes);
            assert_eq!(model.state.lock().unwrap().writes.len(), mmio_writes);
            drop(controller);
            assert!(
                Arc::strong_count(&model) >= 2,
                "uncertain reservation must remain retained"
            );
        }
    }
    #[test]
    fn clock_regression_and_overflow_never_claim_prepared_or_publish_new_work() {
        let (mut pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x40, 8);
        let state = pci.state.clone();
        // SAFETY: same synthetic requester and epoch contract.
        let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
        assert_eq!(poll(&mut controller, u64::MAX), Err(Error::ClockOverflow));
        assert!(state.lock().unwrap().writes.is_empty());
        drop(controller);
        let (mut pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x40, 8);
        let state = pci.state.clone();
        // SAFETY: independent synthetic requester/epoch, no prior work.
        let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
        poll(&mut controller, 10).unwrap();
        let writes = state.lock().unwrap().writes.len();
        assert_eq!(poll(&mut controller, 9), Err(Error::ClockRegressed));
        assert_eq!(state.lock().unwrap().writes.len(), writes);
    }

    #[test]
    #[ignore = "oracle: STELA_THUNDERBOLT_CONTROLLER_ORACLE"]
    fn unchanged_linux_controller_preparation_effects_and_match_table_agree() {
        use std::{env, fs};
        let trace = fs::read_to_string(
            env::var("STELA_THUNDERBOLT_CONTROLLER_ORACLE").expect("set controller trace"),
        )
        .unwrap();
        let mut count = 0;
        for line in trace.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(fields[0], "C");
            let data: Vec<u32> = fields[1..]
                .iter()
                .map(|word| word.parse().unwrap())
                .collect();
            let (mut pci, model) = fixture(
                data[0] as u16,
                data[1] as u16,
                data[2],
                data[3] as u8,
                data[4] as u16,
            );
            let state = pci.state.clone();
            // SAFETY: this same stopped synthetic requester/epoch is
            // represented by both PCI and MMIO; no independent owner is paired.
            let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
            let mut prepared = None;
            for now in 0..200 {
                prepared = poll(&mut controller, now).unwrap();
                if prepared.is_some() {
                    break;
                }
            }
            let prepared = prepared.expect("bounded source-modeled startup");
            assert_eq!(
                data[5],
                match prepared.profile.family() {
                    Family::IntelDiscrete => 0,
                    Family::IntelIntegrated => 1,
                    Family::Usb4Compliant => 2,
                }
            );
            let pci_count = data[6] as usize;
            let mut at = 7;
            let expected_pci: Vec<(u16, u32)> = (0..pci_count)
                .map(|_| {
                    let value = (data[at] as u16, data[at + 1]);
                    at += 2;
                    value
                })
                .collect();
            let mmio_count = data[at] as usize;
            at += 1;
            let expected_mmio: Vec<(usize, u32)> = (0..mmio_count)
                .map(|_| {
                    let value = (data[at] as usize, data[at + 1]);
                    at += 2;
                    value
                })
                .collect();
            assert_eq!(at, data.len());
            assert_eq!(state.lock().unwrap().writes, expected_pci, "{line}");
            assert_eq!(model.state.lock().unwrap().writes, expected_mmio, "{line}");
            count += 1;
        }
        assert_eq!(count, 350);
    }
}
