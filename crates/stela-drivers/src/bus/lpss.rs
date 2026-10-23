// SPDX-License-Identifier: GPL-2.0-only
// Intel LPSS private initialization adapted from Linux intel-lpss.c and
// intel-lpss-pci.c at a804c5742bff224d4cb4d25dd383554d598be32b.
// Copyright (C) 2015 Intel Corporation.
// Authors: Andy Shevchenko, Mika Westerberg, Heikki Krogerus, Jarkko Nikula.
//! Owned Sunrisepoint I²C platform resources. SPI/UART/iDMA and platform PM
//! are separate implementations. The explicit owner composes private resource
//! initialization with the shared DesignWare PIO engine and held-D0 lifetime.
use super::{
    mmio::owned::{CacheAttribute, Mapping, Protection},
    pci::{ConfigSpace, Function, owned::OwnedConfig, requester::StoppedRequester},
};
use core::ptr::NonNull;

mod child;
pub use child::{AttachError, AttachFailure, I2c, Retired};

const PRIVATE: usize = 0x200;
const WINDOW_BYTES: usize = 0x300;
const RESET: usize = PRIVATE + 0x04;
const REMAP_LOW: usize = PRIVATE + 0x40;
const REMAP_HIGH: usize = REMAP_LOW + 4;
const CAPS: usize = PRIVATE + 0xfc;
const CAPS_TYPE: u32 = 0xf << 4;
const RESET_FUNCTION_AND_IDMA: u32 = 7;
const PCI_COMMAND: u16 = 4;
const PCI_BUS_MASTER: u16 = 1 << 2;
const PCI_MEMORY: u16 = 1 << 1;
const PCI_INTX_DISABLE: u16 = 1 << 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Unsupported,
    Identity,
    Mapping,
    Configuration,
    Register {
        offset: usize,
        expected: u32,
        observed: u32,
    },
    Io,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
}
/// One exact source-selected I²C profile. These defaults are not board SCL
/// counts or authority to ignore an overlapping firmware resource reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    device: u16,
}
impl Profile {
    pub fn select(identity: Identity) -> Result<Self, Error> {
        if identity.vendor != 0x8086
            || !matches!(identity.device, 0x9d60..=0x9d65 | 0xa160..=0xa162)
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            device: identity.device,
        })
    }
    pub fn device(self) -> u16 {
        self.device
    }
    pub fn input_clock_hz(self) -> u32 {
        120_000_000
    }
    pub fn source_sda_hold_ns(self) -> u32 {
        230
    }
}
/// Actual retained function/root/reset and UC register authority.
///
/// # Safety
/// The provider owns the same actual powered D0 physical function, complete
/// BAR and configuration/reset epoch. Firmware, AML/SMM, IRQs and other CPUs
/// cannot access/revoke it. Prior engines, posted DMA, callbacks and work are
/// stopped/drained; bus mastering and interrupts remain disabled. All addresses
/// and identity are observations from those retained resources. Leaking this
/// provider retains its actual grants; no borrowed temporary owner is allowed.
pub unsafe trait Registers: 'static {
    fn identity(&mut self) -> Result<Identity, Error>;
    fn physical_base(&self) -> u64;
    fn read32(&mut self, offset: usize) -> Result<u32, Error>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error>;
}

/// Conventional, infallible child MMIO under the retained actual mapping.
/// # Safety
/// The full 0x200-byte child aperture has stable ordered native DWORD access.
/// Offsets are the actual DesignWare register definitions. Hardware fault values
/// remain observable; no fabricated success or temporary pointer is permitted.
/// The same provider retains actual power/clock/root grants if quarantined.
pub unsafe trait ChildAccess: Registers {
    fn child_read32(&mut self, offset: usize) -> u32;
    fn child_write32(&mut self, offset: usize, value: u32);
}

pub type NativeResources = (Function<OwnedConfig>, Mapping);
/// Real owned UC mapping and the canonical stopped requester's original
/// configuration owner. The CPU pointer is never a physical remap address.
pub struct NativeRegisters {
    function: Function<OwnedConfig>,
    mapping: Mapping,
    base: u64,
    pointer: NonNull<u32>,
}
impl NativeRegisters {
    /// # Safety
    /// Mapping is this stopped function's actual exclusive BAR0 reservation at
    /// the same retained root/firmware epoch, powered D0. It cannot be revoked
    /// through aliases. The original stopped producer's drainage contract holds.
    /// No implicit identity mapping or firmware-conflict override is permitted.
    pub unsafe fn claim(
        mut requester: StoppedRequester,
        mapping: Mapping,
    ) -> Result<Self, (Error, NativeResources)> {
        let stopped = requester.check_stopped().is_ok();
        let mut function = requester.into_function();
        let checked = (|| {
            if !stopped {
                return Err(Error::Configuration);
            }
            let config = function.config();
            let low = config.read32(0x10);
            if low == u32::MAX || low & 9 != 0 || !matches!(low & 6, 0 | 4) {
                return Err(Error::Mapping);
            }
            let high = if low & 6 == 4 { config.read32(0x14) } else { 0 };
            if high == u32::MAX {
                return Err(Error::Mapping);
            }
            let base = u64::from(high) << 32 | u64::from(low & !15);
            let span = mapping.physical_span().map_err(|_| Error::Mapping)?;
            if base == 0
                || span.start() != base
                || span.bytes() < WINDOW_BYTES as u64
                || mapping.attribute().map_err(|_| Error::Mapping)? != CacheAttribute::Uncached
                || mapping.protection().map_err(|_| Error::Mapping)? != Protection::ReadWrite
            {
                return Err(Error::Mapping);
            }
            let pointer = mapping
                .address(0, WINDOW_BYTES)
                .map_err(|_| Error::Mapping)?;
            if !(pointer.as_ptr() as usize).is_multiple_of(4) {
                return Err(Error::Mapping);
            }
            // Keep the source's memory decode, with no DMA or interrupt publish.
            let command = config.read16(PCI_COMMAND);
            if command == u16::MAX
                || command & (PCI_BUS_MASTER | PCI_MEMORY | PCI_INTX_DISABLE)
                    != PCI_MEMORY | PCI_INTX_DISABLE
            {
                return Err(Error::Configuration);
            }
            Ok((base, pointer.cast()))
        })();
        match checked {
            Ok((base, pointer)) => Ok(Self {
                function,
                mapping,
                base,
                pointer,
            }),
            Err(error) => Err((error, (function, mapping))),
        }
    }
    fn address(&self, offset: usize) -> Result<NonNull<u32>, Error> {
        if !offset.is_multiple_of(4) || offset > WINDOW_BYTES - 4 {
            return Err(Error::Mapping);
        }
        // SAFETY: claim validates the whole retained UC window; checked offset.
        Ok(unsafe { NonNull::new_unchecked(self.pointer.as_ptr().add(offset / 4)) })
    }
    fn into_resources(self) -> NativeResources {
        (self.function, self.mapping)
    }
}
// SAFETY: unsafe claim consumes canonical actual stopped ownership and UC
// mapping, validates real BAR/configuration and keeps both for every access.
unsafe impl Registers for NativeRegisters {
    fn identity(&mut self) -> Result<Identity, Error> {
        let expected = u32::from(self.function.vendor) | u32::from(self.function.device) << 16;
        let config = self.function.config();
        if config.read32(0) != expected {
            return Err(Error::Identity);
        }
        let subsystem = config.read32(0x2c);
        if subsystem == u32::MAX {
            return Err(Error::Identity);
        }
        Ok(Identity {
            vendor: expected as u16,
            device: (expected >> 16) as u16,
            subsystem_vendor: subsystem as u16,
            subsystem_device: (subsystem >> 16) as u16,
        })
    }
    fn physical_base(&self) -> u64 {
        self.base
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        let pointer = self.address(offset)?;
        // SAFETY: actual owned aligned UC window, no concurrent register owner.
        Ok(unsafe { pointer.as_ptr().read_volatile() })
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        let pointer = self.address(offset)?;
        // SAFETY: same actual retained UC register mapping and ordered DWORDs.
        unsafe { pointer.as_ptr().write_volatile(value) };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Unmodified,
    Programming,
    Ready,
    Retired,
}
pub struct Controller<R: Registers> {
    registers: Option<R>,
    profile: Profile,
    phase: Phase,
}
impl<R: Registers> Controller<R> {
    /// Consume actual authority. Rejected metadata returns an unmodified owner;
    /// errors after the first reset write retain all resources on Drop.
    pub fn initialize(mut registers: R) -> Result<Self, (Error, Option<R>)> {
        let profile = match registers.identity().and_then(Profile::select) {
            Ok(profile) => profile,
            Err(error) => return Err((error, Some(registers))),
        };
        let mut owner = Self {
            registers: Some(registers),
            profile,
            phase: Phase::Unmodified,
        };
        match owner.program() {
            Ok(()) => Ok(owner),
            Err(error) if owner.phase == Phase::Unmodified => Err((error, owner.registers.take())),
            Err(error) => {
                drop(owner);
                Err((error, None))
            }
        }
    }
    fn program(&mut self) -> Result<(), Error> {
        let caps = self.registers.as_mut().unwrap().read32(CAPS)?;
        if caps == u32::MAX || caps & CAPS_TYPE != 0 {
            return Err(Error::Unsupported);
        }
        let base = self.registers.as_ref().unwrap().physical_base();
        if base == 0
            || !base.is_multiple_of(4096)
            || base.checked_add(WINDOW_BYTES as u64).is_none()
        {
            return Err(Error::Mapping);
        }
        self.phase = Phase::Programming;
        self.write_verified(RESET, 0)?;
        self.write_verified(RESET, RESET_FUNCTION_AND_IDMA)?;
        // Source lo_hi_writeq uses ordered native low then high DWORD stores.
        self.registers
            .as_mut()
            .unwrap()
            .write32(REMAP_LOW, base as u32)?;
        self.registers
            .as_mut()
            .unwrap()
            .write32(REMAP_HIGH, (base >> 32) as u32)?;
        self.verify(REMAP_LOW, base as u32)?;
        self.verify(REMAP_HIGH, (base >> 32) as u32)?;
        self.phase = Phase::Ready;
        Ok(())
    }
    fn verify(&mut self, offset: usize, expected: u32) -> Result<(), Error> {
        let observed = self.registers.as_mut().unwrap().read32(offset)?;
        if observed != expected {
            return Err(Error::Register {
                offset,
                expected,
                observed,
            });
        }
        Ok(())
    }
    fn write_verified(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.registers.as_mut().unwrap().write32(offset, value)?;
        self.verify(offset, value)
    }
    /// # Safety
    /// The actual child has acknowledged disable, or no child has ever been
    /// published. No child register/IRQ/work users remain. This is not a DMA or
    /// external SDA/SCL recovery primitive; this PIO owner never enabled DMA.
    unsafe fn retire(mut self) -> Result<Retired<R>, Error> {
        self.phase = Phase::Programming;
        self.write_verified(RESET, 0)?;
        self.phase = Phase::Retired;
        Ok(Retired {
            registers: self.registers.take().unwrap(),
        })
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
}
impl<R: Registers> Drop for Controller<R> {
    fn drop(&mut self) {
        if matches!(self.phase, Phase::Programming | Phase::Ready)
            && let Some(registers) = self.registers.take()
        {
            core::mem::forget(registers);
        }
    }
}

// SAFETY: NativeRegisters retains the complete actual UC aperture and original
// function/root epoch. DesignWare offsets are bounded below private registers.
unsafe impl ChildAccess for NativeRegisters {
    fn child_read32(&mut self, offset: usize) -> u32 {
        assert!(offset < PRIVATE);
        self.read32(offset).expect("validated retained child DWORD")
    }
    fn child_write32(&mut self, offset: usize, value: u32) {
        assert!(offset < PRIVATE);
        self.write32(offset, value)
            .expect("validated retained child DWORD");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::pci::{
        Address,
        owned::tests::{Counters, fixture},
        requester::FunctionRole,
    };
    use alloc::sync::Arc;
    use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
    use core::{
        cell::{Cell, RefCell},
        sync::atomic::Ordering,
    };

    #[derive(Debug)]
    struct Hardware {
        identity: Identity,
        base: u64,
        words: [u32; WINDOW_BYTES / 4],
        writes: Vec<(usize, u32)>,
        calls: usize,
        fail: Option<(usize, bool)>,
        reject: Option<usize>,
        rx: VecDeque<u8>,
        commands: Vec<u32>,
        next_read: u8,
        stop: bool,
        stuck_disable: bool,
    }
    #[derive(Debug)]
    struct Model {
        hardware: Rc<RefCell<Hardware>>,
        drops: Rc<Cell<usize>>,
    }
    impl Drop for Model {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }
    impl Hardware {
        fn begin(&mut self) -> Result<bool, Error> {
            self.calls += 1;
            if self.fail == Some((self.calls, false)) {
                return Err(Error::Io);
            }
            Ok(self.fail == Some((self.calls, true)))
        }
    }
    // SAFETY: actual isolated owned register model and a distinct drop-counted
    // resource guard. No hardware, other process or asynchronous borrower exists.
    unsafe impl Registers for Model {
        fn identity(&mut self) -> Result<Identity, Error> {
            let mut h = self.hardware.borrow_mut();
            let late = h.begin()?;
            if late {
                Err(Error::Identity)
            } else {
                Ok(h.identity)
            }
        }
        fn physical_base(&self) -> u64 {
            self.hardware.borrow().base
        }
        fn read32(&mut self, offset: usize) -> Result<u32, Error> {
            let mut h = self.hardware.borrow_mut();
            let late = h.begin()?;
            let value = h.words[offset / 4];
            if late { Err(Error::Io) } else { Ok(value) }
        }
        fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
            let mut h = self.hardware.borrow_mut();
            let late = h.begin()?;
            h.writes.push((offset, value));
            if h.reject != Some(offset) {
                h.words[offset / 4] = value;
            }
            if late { Err(Error::Io) } else { Ok(()) }
        }
    }
    // SAFETY: actual isolated model aperture; command/FIFO/status effects are
    // independent of the production engine. There is no real DMA or IRQ.
    unsafe impl ChildAccess for Model {
        fn child_read32(&mut self, offset: usize) -> u32 {
            let mut h = self.hardware.borrow_mut();
            match offset {
                0xfc => 0x4457_0140,
                0xf4 => 2 | (1 << 7) | (2 << 2) | (3 << 16) | (3 << 8),
                0xf8 => 0x3131_312a,
                0x9c => {
                    if h.stuck_disable {
                        1
                    } else {
                        h.words[0x6c / 4] & 1
                    }
                }
                0x70 => 1 << 2,
                0x74 => 0,
                0x78 => h.rx.len() as u32,
                0x10 => u32::from(h.rx.pop_front().expect("actual queued RX byte")),
                0x34 => {
                    if h.stop {
                        1 << 9
                    } else {
                        0
                    }
                }
                0x40 | 0x60 => {
                    h.stop = false;
                    0
                }
                _ => h.words[offset / 4],
            }
        }
        fn child_write32(&mut self, offset: usize, value: u32) {
            let mut h = self.hardware.borrow_mut();
            assert!(offset < PRIVATE && offset.is_multiple_of(4));
            h.words[offset / 4] = value;
            if matches!(offset, 0x30 | 0x88) {
                assert_eq!(value, 0, "PIO never publishes IRQ/DMA");
            }
            if offset == 0x10 {
                assert_ne!(h.words[0x6c / 4] & 1, 0);
                h.commands.push(value);
                if value & (1 << 8) != 0 {
                    let byte = h.next_read;
                    h.rx.push_back(byte);
                    h.next_read = byte.wrapping_add(1);
                }
                if value & (1 << 9) != 0 {
                    h.stop = true;
                }
            }
        }
    }
    #[derive(Clone)]
    struct Time(Rc<Cell<u64>>);
    impl crate::bus::i2c::Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn relax(&self) {
            self.0.set(self.0.get().wrapping_add(1));
        }
    }
    fn timing() -> crate::bus::i2c::Config {
        crate::bus::i2c::Config {
            timing: crate::bus::i2c::Timing {
                speed: crate::bus::i2c::Speed::Standard,
                scl_high: 120,
                scl_low: 130,
                sda_hold: Some(28),
            },
            timeout_us: 100,
            recovery_timeout_us: 50,
        }
    }
    type ModelResources = (Model, Rc<RefCell<Hardware>>, Rc<Cell<usize>>);
    fn model(device: u16, base: u64, caps: u32) -> ModelResources {
        let mut words = [0xa5a5_a5a5; WINDOW_BYTES / 4];
        words[CAPS / 4] = caps;
        let hardware = Rc::new(RefCell::new(Hardware {
            identity: Identity {
                vendor: 0x8086,
                device,
                subsystem_vendor: 0x1234,
                subsystem_device: 0x5678,
            },
            base,
            words,
            writes: Vec::new(),
            calls: 0,
            fail: None,
            reject: None,
            rx: VecDeque::new(),
            commands: Vec::new(),
            next_read: 0x31,
            stop: false,
            stuck_disable: false,
        }));
        let drops = Rc::new(Cell::new(0));
        (
            Model {
                hardware: hardware.clone(),
                drops: drops.clone(),
            },
            hardware,
            drops,
        )
    }
    type NativeFixture = (Function<OwnedConfig>, Mapping, Arc<Counters>, Arc<Counters>);
    fn native_fixture() -> NativeFixture {
        let address = Address {
            segment: 0x1234,
            bus: 2,
            device: 3,
            function: 0,
        };
        let (mut config, config_counts) = fixture(address);
        let (window, bar_counts) = fixture(Address {
            function: 1,
            ..address
        });
        let mapping = window.into_mapping();
        let physical = mapping.physical_span().unwrap().start();
        assert!(physical <= u64::from(u32::MAX));
        config.write32(0, 0x9d60_8086);
        config.write32(8, 0x1180_0000);
        config.write16(PCI_COMMAND, PCI_MEMORY | PCI_INTX_DISABLE);
        // A real owned RAM mapping stands in for the exclusive actual BAR.
        // Its CPU pointer and symbolic physical address are deliberately distinct.
        config.write32(0x10, physical as u32 | 4);
        config.write32(0x14, 0);
        config.write32(0x2c, 0x1237_152d);
        let pointer = mapping.address(0, WINDOW_BYTES).unwrap().cast::<u32>();
        assert_ne!(pointer.as_ptr() as u64, physical);
        // SAFETY: fixture's isolated original RAM resource has no device,
        // asynchronous worker or other register owner.
        unsafe { pointer.as_ptr().add(CAPS / 4).write_volatile(0) };
        (
            Function::new(address, config).unwrap(),
            mapping,
            config_counts,
            bar_counts,
        )
    }
    fn stop_fixture(function: Function<OwnedConfig>) -> StoppedRequester {
        // SAFETY: actual owned fixture storage is drained, exclusively retained
        // and not exposed as any production device/coherency qualification.
        match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
            Ok(stopped) => stopped,
            Err((error, _)) => panic!("valid stopped fixture: {error:?}"),
        }
    }
    fn release_native(resources: NativeResources, config_counts: &Counters, bar_counts: &Counters) {
        let (function, mut mapping) = resources;
        let mut config = function.into_config().into_mapping();
        // SAFETY: the original isolated resources have no remaining register,
        // device or worker users after the synchronous owner was consumed.
        unsafe { mapping.retire() }.unwrap();
        unsafe { config.retire() }.unwrap();
        for counts in [config_counts, bar_counts] {
            assert_eq!(counts.unmaps.load(Ordering::Relaxed), 1);
            assert_eq!(counts.resource_drops.load(Ordering::Relaxed), 1);
            assert_eq!(counts.platform_drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn concrete_native_registers_use_actual_owned_mapping_and_acknowledged_reset_release() {
        let (function, mapping, config_counts, bar_counts) = native_fixture();
        let physical = mapping.physical_span().unwrap().start();
        // SAFETY: stopped exclusively owned RAM fixture and its actual mapping.
        let registers = match unsafe { NativeRegisters::claim(stop_fixture(function), mapping) } {
            Ok(registers) => registers,
            Err((error, _)) => panic!("valid mapped owner: {error:?}"),
        };
        let mut owner = match Controller::initialize(registers) {
            Ok(owner) => owner,
            Err((error, _)) => panic!("valid private core: {error:?}"),
        };
        assert_eq!(owner.profile().device(), 0x9d60);
        let registers = owner.registers.as_mut().unwrap();
        assert_eq!(registers.read32(RESET), Ok(7));
        assert_eq!(registers.read32(REMAP_LOW), Ok(physical as u32));
        assert_eq!(registers.read32(REMAP_HIGH), Ok((physical >> 32) as u32));
        assert_eq!(registers.read32(WINDOW_BYTES), Err(Error::Mapping));
        assert_eq!(registers.write32(1, 0), Err(Error::Mapping));
        for counts in [&config_counts, &bar_counts] {
            assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
            assert_eq!(counts.resource_drops.load(Ordering::Relaxed), 0);
        }
        // SAFETY: private core only; no child was published.
        let retired = unsafe { owner.retire() }.unwrap();
        release_native(retired.into_resources(), &config_counts, &bar_counts);
    }
    #[test]
    fn concrete_native_live_and_uncertain_child_owners_retain_original_platform_resources() {
        for stage in 0..4 {
            let (function, mapping, config_counts, bar_counts) = native_fixture();
            if stage >= 2 {
                let pointer = mapping.address(0, PRIVATE).unwrap().cast::<u32>();
                // SAFETY: no user has claimed these actual isolated registers;
                // source component words and frozen enable status are hardware
                // observations, independent of the production engine.
                unsafe {
                    pointer.as_ptr().add(0xfc / 4).write_volatile(0x4457_0140);
                    pointer
                        .as_ptr()
                        .add(0xf4 / 4)
                        .write_volatile(2 | (1 << 7) | (2 << 2) | (3 << 16) | (3 << 8));
                    pointer.as_ptr().add(0xf8 / 4).write_volatile(0x3131_312a);
                    pointer
                        .as_ptr()
                        .add(0x9c / 4)
                        .write_volatile(u32::from(stage == 2));
                }
            }
            // SAFETY: same retained actual stopped owner and isolated BAR fixture.
            let registers = match unsafe { NativeRegisters::claim(stop_fixture(function), mapping) }
            {
                Ok(registers) => registers,
                Err((error, _)) => panic!("valid mapped owner: {error:?}"),
            };
            let owner = match Controller::initialize(registers) {
                Ok(owner) => owner,
                Err((error, _)) => panic!("valid private core: {error:?}"),
            };
            if stage == 0 {
                drop(owner);
            } else {
                // SAFETY: exact isolated source clock/timing fixture. This
                // exercises real volatile NativeRegisters and the actual DW
                // constructor, not the generic protocol Register model.
                let child = unsafe { owner.into_i2c(Time(Rc::new(Cell::new(0))), timing()) };
                match stage {
                    1 => assert!(matches!(
                        child.err().unwrap().kind,
                        crate::bus::i2c::ErrorKind::ComponentType(0)
                    )),
                    2 => assert_eq!(
                        child.err().unwrap().kind,
                        crate::bus::i2c::ErrorKind::Timeout(crate::bus::i2c::Phase::Disable)
                    ),
                    3 => drop(child.unwrap()),
                    _ => unreachable!(),
                }
            }
            for counts in [&config_counts, &bar_counts] {
                assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
                assert_eq!(counts.resource_drops.load(Ordering::Relaxed), 0);
                assert_eq!(counts.platform_drops.load(Ordering::Relaxed), 0);
            }
        }
    }

    #[test]
    fn concrete_native_rejections_return_exact_unmodified_mapping_and_config_owners() {
        for scenario in 0..5 {
            let (mut function, mut mapping, config_counts, bar_counts) = native_fixture();
            match scenario {
                0 => function.config().write32(0x10, 0x1234_0004),
                1 => function.config().write32(0x10, 1),
                2 => function.config().write16(PCI_COMMAND, PCI_INTX_DISABLE),
                3 => function.config().write32(0x14, u32::MAX),
                4 => {
                    // SAFETY: no actual register user/engine exists; the retired
                    // mapping must not be silently resurrected by the adapter.
                    unsafe { mapping.retire() }.unwrap();
                }
                _ => unreachable!(),
            }
            // SAFETY: same isolated stopped fixture, deliberately invalid BAR
            // metadata or decode. Rejection must not produce any MMIO effect.
            let (error, resources) =
                match unsafe { NativeRegisters::claim(stop_fixture(function), mapping) } {
                    Err(rejected) => rejected,
                    Ok(_) => panic!("invalid resources admitted"),
                };
            assert_eq!(
                error,
                if scenario == 2 {
                    Error::Configuration
                } else {
                    Error::Mapping
                }
            );
            assert_eq!(config_counts.unmaps.load(Ordering::Relaxed), 0);
            if scenario != 4 {
                release_native(resources, &config_counts, &bar_counts);
            } else {
                let (function, mapping) = resources;
                assert!(mapping.address(0, 4).is_err());
                drop(mapping);
                let mut mapping = function.into_config().into_mapping();
                // SAFETY: same original no-user RAM fixture.
                unsafe { mapping.retire() }.unwrap();
                assert_eq!(config_counts.unmaps.load(Ordering::Relaxed), 1);
                assert_eq!(bar_counts.unmaps.load(Ordering::Relaxed), 1);
            }
        }
    }

    #[test]
    fn exact_nine_profiles_program_source_reset_and_full_physical_remap() {
        for device in [
            0x9d60, 0x9d61, 0x9d62, 0x9d63, 0x9d64, 0x9d65, 0xa160, 0xa161, 0xa162,
        ] {
            for base in [0x8000_0000, 0x1_0000_0000, 0x7fff_e123_4000] {
                for caps in [0, 1 << 8] {
                    let (registers, h, drops) = model(device, base, caps);
                    let owner = Controller::initialize(registers).unwrap();
                    assert_eq!(owner.profile().device(), device);
                    assert_eq!(owner.profile().input_clock_hz(), 120_000_000);
                    assert_eq!(owner.profile().source_sda_hold_ns(), 230);
                    assert_eq!(
                        h.borrow().writes,
                        [
                            (RESET, 0),
                            (RESET, 7),
                            (REMAP_LOW, base as u32),
                            (REMAP_HIGH, (base >> 32) as u32)
                        ]
                    );
                    assert_eq!(drops.get(), 0);
                    // SAFETY: no child was published; model has no async users.
                    let retired = unsafe { owner.retire() }.unwrap();
                    assert_eq!(h.borrow().writes.last(), Some(&(RESET, 0)));
                    drop(retired.registers);
                    assert_eq!(drops.get(), 1);
                }
            }
        }
    }
    #[test]
    fn metadata_refusals_return_actual_unmodified_resources_without_register_writes() {
        for (device, base, caps) in [
            (0x9d5f, 0x8000_0000, 0),
            (0xa163, 0x8000_0000, 0),
            (0x9d60, 0, 0),
            (0x9d60, 0x8000_0001, 0),
            (0x9d60, 0x8000_0000, 0x10),
            (0x9d60, 0x8000_0000, 0x20),
            (0x9d60, 0x8000_0000, u32::MAX),
        ] {
            let (registers, h, drops) = model(device, base, caps);
            let (_, registers) = Controller::initialize(registers).err().unwrap();
            assert!(registers.is_some());
            assert!(h.borrow().writes.is_empty());
            assert_eq!(drops.get(), 0);
            drop(registers);
            assert_eq!(drops.get(), 1);
        }
    }
    #[test]
    fn every_access_fault_preserves_original_failure_and_actual_post_effect_owners() {
        for call in 1..=10 {
            for after in [false, true] {
                let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
                h.borrow_mut().fail = Some((call, after));
                let (error, returned) = Controller::initialize(registers).err().unwrap();
                assert!(matches!(error, Error::Io | Error::Identity));
                assert_eq!(returned.is_some(), call <= 2);
                assert_eq!(drops.get(), 0);
                if let Some(registers) = returned {
                    drop(registers);
                    assert_eq!(drops.get(), 1);
                } else {
                    assert_eq!(
                        drops.get(),
                        0,
                        "uncertain real register owner must stay retained"
                    );
                }
                assert_eq!(
                    h.borrow().calls,
                    call,
                    "no retry after the first uncertain effect"
                );
            }
        }
    }
    #[test]
    fn ignored_program_and_retirement_writes_do_not_release_actual_owners() {
        for offset in [RESET, REMAP_LOW, REMAP_HIGH] {
            let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
            h.borrow_mut().reject = Some(offset);
            let (error, returned) = Controller::initialize(registers).err().unwrap();
            assert!(matches!(error, Error::Register { offset: actual, .. } if actual == offset));
            assert!(returned.is_none());
            assert_eq!(drops.get(), 0);
        }
        let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
        let owner = Controller::initialize(registers).unwrap();
        h.borrow_mut().reject = Some(RESET);
        // SAFETY: no child was published; actual reset failure must quarantine.
        assert!(unsafe { owner.retire() }.is_err());
        assert_eq!(drops.get(), 0);
        let (registers, _, drops) = model(0x9d60, 0x1_2345_0000, 0);
        drop(Controller::initialize(registers).unwrap());
        assert_eq!(drops.get(), 0, "live Drop is not acknowledged retirement");
    }
    #[test]
    fn real_designware_child_drives_combined_pio_and_acknowledged_retirement() {
        use crate::bus::i2c::{Address, Bus, Operation};
        let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
        let owner = Controller::initialize(registers).unwrap();
        // SAFETY: literal timing belongs to this exact modeled source clock and
        // finite peer; no guessed production board authority is supplied.
        let mut bus =
            unsafe { owner.into_i2c(Time(Rc::new(Cell::new(u64::MAX - 10))), timing()) }.unwrap();
        let mut bytes = [0; 2];
        bus.transaction(
            Address::SevenBit(0x2c),
            &mut [Operation::Write(&[0x80, 0x55]), Operation::Read(&mut bytes)],
        )
        .unwrap();
        assert_eq!(bytes, [0x31, 0x32]);
        assert_eq!(
            h.borrow().commands,
            [0x80, 0x55, (1 << 8) | (1 << 10), (1 << 8) | (1 << 9)]
        );
        assert_eq!(h.borrow().words[0x30 / 4], 0);
        assert_eq!(h.borrow().words[0x88 / 4], 0);
        assert_eq!(drops.get(), 0);
        let (retired, _) = bus.shutdown().unwrap();
        assert_eq!(h.borrow().writes.last(), Some(&(RESET, 0)));
        drop(retired.registers);
        assert_eq!(drops.get(), 1);
    }
    #[test]
    fn real_child_init_shutdown_and_live_drop_failures_retain_actual_platform_grants() {
        for stage in 0..3 {
            let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
            let owner = Controller::initialize(registers).unwrap();
            if stage == 0 {
                h.borrow_mut().stuck_disable = true;
            }
            // SAFETY: same isolated literal timing and actual model owner.
            let result = unsafe { owner.into_i2c(Time(Rc::new(Cell::new(0))), timing()) };
            if stage == 0 {
                assert!(result.is_err());
            } else {
                let bus = result.unwrap();
                if stage == 1 {
                    h.borrow_mut().stuck_disable = true;
                    assert!(bus.shutdown().is_err());
                } else {
                    drop(bus);
                }
            }
            assert_eq!(
                drops.get(),
                0,
                "failed/live child never releases root/mapping authority"
            );
        }
    }
    #[test]
    #[ignore = "requires fresh unchanged pinned LPSS source trace"]
    fn unchanged_source_reset_remap_effects() {
        extern crate std;
        let trace =
            std::fs::read_to_string(std::env::var("STELA_LPSS_ORACLE").expect("source trace path"))
                .unwrap();
        let mut cases = 0;
        for line in trace.lines() {
            let fields: Vec<_> = line.split(',').collect();
            let type_field: u32 = fields[0].parse().unwrap();
            let absent: u32 = fields[1].parse().unwrap();
            let old: u32 = fields[2].parse().unwrap();
            let base: u64 = fields[3].parse().unwrap();
            let (registers, h, drops) = model(0x9d60, base, type_field << 4 | absent << 8);
            h.borrow_mut().words[RESET / 4] = old;
            if type_field == 0 {
                let owner = Controller::initialize(registers).unwrap();
                let actual: Vec<_> = h
                    .borrow()
                    .writes
                    .iter()
                    .map(|(offset, value)| alloc::format!("{}:{}", offset - PRIVATE, value))
                    .collect();
                assert_eq!(actual, fields[4..]);
                // SAFETY: pure source model, no child/IRQ/DMA publication.
                drop(unsafe { owner.retire() }.unwrap().registers);
            } else {
                let (error, returned) = Controller::initialize(registers).err().unwrap();
                assert_eq!(error, Error::Unsupported);
                assert!(h.borrow().writes.is_empty());
                drop(returned);
            }
            assert_eq!(drops.get(), 1);
            cases += 1;
        }
        assert_eq!(cases, 6144);
    }
}
