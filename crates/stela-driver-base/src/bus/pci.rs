//! PCI configuration space through ECAM: enumeration, BAR decoding and
//! sizing, capabilities and interrupt discovery. Memory decoding and bus
//! mastering are independent of interrupt policy. The current boot drivers
//! use [`Function::enable_polled`]; interrupt-driven ports must arrange
//! delivery with the mount before enabling their interrupt sources.
use super::mmio::Mmio;
use crate::{Clock, block::BlockError};
use alloc::vec::Vec;
use core::{
    fmt,
    ops::{Range, RangeInclusive},
};

mod aspm;
pub mod capability;
pub mod hotplug;
pub mod msi;
pub mod msix;
pub mod native;
pub mod owned;
pub mod power;
pub mod regs;
pub mod requester;
pub use aspm::{
    aspm_control, disable_aspm_l1_2_link, disable_aspm_link, link_control_word, link_speed,
    native as native_aspm,
};
pub use capability::{
    Capabilities, Capability, CapabilityError, ExtendedCapabilities, ExtendedCapability, Layout,
};

/// MSI-X Message Control: enable, and mask every vector.
const MSIX_ENABLE: u16 = 1 << 15;
const MSIX_FUNCTION_MASK: u16 = 1 << 14;
/// MSI Message Control: enable, and Multiple Message Enable.
const MSI_ENABLE: u16 = 1 << 0;
const MSI_MULTIPLE_ENABLE: u16 = 0b111 << 4;
/// An MSI-X table entry's bytes.
const MSIX_ENTRY_BYTES: u64 = 16;
/// Memory BAR type field: 64-bit (PCI 3.0 §6.2.5.1).
const BAR_MEMORY_64: u32 = 2 << 1;
const BAR_MEMORY_TYPE: u32 = 3 << 1;
const BAR_PREFETCHABLE: u32 = 1 << 3;
const BAR_IO: u32 = 1;
const BARS: usize = 6;

/// Power Management Control/Status (PCI PM 1.2 §3.2.4).
const PM_CONTROL: u16 = 4;
const PM_STATE: u16 = 3;
const PM_NO_SOFT_RESET: u16 = 1 << 3;
/// D3hot and D2 exit delays (PCI PM 1.2 Table 5-1; Linux `PCI_PM_D3HOT_WAIT`,
/// `PCI_PM_D2_DELAY`).
const D3HOT_DELAY_US: u64 = 10_000;
const D2_DELAY_US: u64 = 200;
const D2: u16 = 2;
const D3HOT: u16 = 3;

/// The legacy entry requires only its maximum 10 ms exit delay. Keep
/// that exact contract when sharing the provider-based PM transition path.
struct PowerUpClock<'a>(&'a Clock);
// SAFETY: this borrowed original Clock performs canonical checked real waits;
// its producer's calibration/context grant remains required for every access.
unsafe impl power::Timer for PowerUpClock<'_> {
    fn check(&self) -> Result<(), power::Error> {
        self.0
            .check_duration(D3HOT_DELAY_US)
            .map_err(|_| power::Error::Clock)
    }
    fn wait_us(&self, microseconds: u64) -> Result<(), power::Error> {
        self.0
            .try_delay(microseconds)
            .map_err(|_| power::Error::Clock)
    }
}

pub const CAPABILITY_POWER: u8 = 0x01;
pub const CAPABILITY_MSI: u8 = 0x05;
pub const CAPABILITY_VENDOR: u8 = 0x09;
pub const CAPABILITY_MSIX: u8 = 0x11;
pub const CAPABILITY_EXPRESS: u8 = 0x10;

const HEADER_BRIDGE: u8 = 1;
const SECONDARY_BUS: u16 = 0x19;
/// The PCI Express capability's flags, device control 2 and their fields.
const EXPRESS_FLAGS: u16 = 2;
const EXPRESS_TYPE_SHIFT: u16 = 4;
const EXPRESS_ROOT_PORT: u16 = 4;
const EXPRESS_DOWNSTREAM: u16 = 6;
const EXPRESS_DEVICE_CONTROL_2: u16 = 0x28;
const ARI_FORWARDING: u16 = 1 << 5;
/// The ARI extended capability's ID.
const EXTENDED_ARI: u16 = 0x0e;
/// The Vendor ID a function still initializing answers with Configuration
/// RRS Software Visibility on.
const VENDOR_NOT_READY: u16 = 0x0001;

/// One ECAM window of the ACPI MCFG table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcamWindow {
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl EcamWindow {
    /// The configuration bytes this window decodes.
    pub fn range(&self) -> Range<u64> {
        let start = self.base + (u64::from(self.start_bus) << 20);
        start..self.base + ((u64::from(self.end_bus) + 1) << 20)
    }

    /// The configuration space of one function in this window.
    ///
    /// # Safety
    /// The window is mapped, and the caller excludes every other accessor of
    /// the function while it holds the configuration.
    pub unsafe fn config(&self, bus: u8, device: u8, function: u8) -> EcamConfig {
        let offset =
            (u64::from(bus) << 20) | (u64::from(device) << 15) | (u64::from(function) << 12);
        // SAFETY: forwarded.
        unsafe { EcamConfig::raw(self.base + offset) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{}",
            self.segment, self.bus, self.device, self.function
        )
    }
}

/// Access to one function's configuration space. Real configuration-space
/// implementations must override `write8` and `write16` with narrow stores:
/// a wider read/modify/write can acknowledge unrelated write-one-to-clear status.
pub trait ConfigSpace {
    fn read32(&self, offset: u16) -> u32;
    fn write32(&mut self, offset: u16, value: u32);

    fn read16(&self, offset: u16) -> u16 {
        (self.read32(offset & !3) >> ((offset & 2) * 8)) as u16
    }

    fn read8(&self, offset: u16) -> u8 {
        (self.read32(offset & !3) >> ((offset & 3) * 8)) as u8
    }

    /// Fallback for simple memory models. Real configuration-space accessors
    /// must override this with a native byte store; neighboring bytes can be
    /// write-one-to-clear status or vendor control registers.
    fn write8(&mut self, offset: u16, value: u8) {
        let shift = (offset & 3) * 8;
        let word = self.read32(offset & !3) & !(0xff << shift) | u32::from(value) << shift;
        self.write32(offset & !3, word);
    }

    fn write16(&mut self, offset: u16, value: u16) {
        let shift = (offset & 2) * 8;
        let word = self.read32(offset & !3) & !(0xffff << shift) | u32::from(value) << shift;
        self.write32(offset & !3, word);
    }

    /// The standard capability list ([`capability::capabilities`]).
    fn capabilities(&self) -> Capabilities<capability::Config<'_, Self>>
    where
        Self: Sized,
    {
        capability::capabilities(self)
    }

    /// The extended capability list ([`capability::extended_capabilities`]).
    fn extended_capabilities(&self) -> ExtendedCapabilities<capability::Config<'_, Self>>
    where
        Self: Sized,
    {
        capability::extended_capabilities(self)
    }
}

/// A function's 4 KiB of ECAM configuration space.
/// A context-bound config transport. Owned and kept-owned arms delegate
/// every effect to the original mapping owner; no copied pointer bypass exists.
pub struct EcamConfig {
    transport: EcamTransport,
    _context: core::marker::PhantomData<*mut ()>,
}
enum EcamTransport {
    Raw(Mmio),
    Owned(owned::OwnedConfig),
    Retained(&'static mut owned::OwnedConfig),
}
impl EcamConfig {
    pub fn from_owned(config: owned::OwnedConfig) -> Self {
        Self {
            transport: EcamTransport::Owned(config),
            _context: core::marker::PhantomData,
        }
    }
    /// Borrow exactly one whole-boot configuration owner. The exclusive
    /// borrow cannot outlive or duplicate its original resource grant.
    pub fn from_retained(config: &'static mut owned::OwnedConfig) -> Self {
        Self {
            transport: EcamTransport::Retained(config),
            _context: core::marker::PhantomData,
        }
    }
    pub fn into_owned(self) -> Result<owned::OwnedConfig, Self> {
        match self.transport {
            EcamTransport::Owned(config) => Ok(config),
            _ => Err(self),
        }
    }
    unsafe fn raw(base: u64) -> Self {
        Self {
            // SAFETY: caller owns this live mapped UC ECAM function
            // and excludes every competing accessor for the transport life.
            transport: EcamTransport::Raw(unsafe { Mmio::new(base) }),
            _context: core::marker::PhantomData,
        }
    }
}
impl ConfigSpace for EcamConfig {
    fn read8(&self, offset: u16) -> u8 {
        match &self.transport {
            EcamTransport::Raw(registers) => registers.read8(usize::from(offset)),
            EcamTransport::Owned(config) => config.read8(offset),
            EcamTransport::Retained(config) => config.read8(offset),
        }
    }
    fn write8(&mut self, offset: u16, value: u8) {
        match &mut self.transport {
            EcamTransport::Raw(registers) => registers.write8(usize::from(offset), value),
            EcamTransport::Owned(config) => config.write8(offset, value),
            EcamTransport::Retained(config) => config.write8(offset, value),
        }
    }
    fn read16(&self, offset: u16) -> u16 {
        match &self.transport {
            EcamTransport::Raw(registers) => registers.read16(usize::from(offset)),
            EcamTransport::Owned(config) => config.read16(offset),
            EcamTransport::Retained(config) => config.read16(offset),
        }
    }
    fn write16(&mut self, offset: u16, value: u16) {
        match &mut self.transport {
            EcamTransport::Raw(registers) => registers.write16(usize::from(offset), value),
            EcamTransport::Owned(config) => config.write16(offset, value),
            EcamTransport::Retained(config) => config.write16(offset, value),
        }
    }
    fn read32(&self, offset: u16) -> u32 {
        match &self.transport {
            EcamTransport::Raw(registers) => registers.read32(usize::from(offset)),
            EcamTransport::Owned(config) => config.read32(offset),
            EcamTransport::Retained(config) => config.read32(offset),
        }
    }
    fn write32(&mut self, offset: u16, value: u32) {
        match &mut self.transport {
            EcamTransport::Raw(registers) => registers.write32(usize::from(offset), value),
            EcamTransport::Owned(config) => config.write32(offset, value),
            EcamTransport::Retained(config) => config.write32(offset, value),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    Memory {
        address: u64,
        size: u64,
        prefetchable: bool,
        wide: bool,
    },
    Io {
        port: u32,
        size: u32,
    },
}

impl Bar {
    /// The bytes a memory BAR decodes; none for I/O or a range past 2^64.
    pub fn memory(&self) -> Option<Range<u64>> {
        match *self {
            Self::Memory { address, size, .. } => Some(address..address.checked_add(size)?),
            Self::Io { .. } => None,
        }
    }
}

/// The size a BAR decodes: its lowest writable address bit, as Linux
/// `pci_size` takes it, so read-only upper address bits cannot inflate it.
fn bar_size(writable: u64) -> u64 {
    writable.isolate_lowest_one()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msi {
    pub offset: u8,
    pub vectors: u8,
    pub wide: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiX {
    pub offset: u8,
    pub vectors: u16,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pending_bar: u8,
    pub pending_offset: u32,
}

/// The message-signalled interrupts a function offers. Discovery alone
/// neither programs nor enables interrupt delivery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Interrupts {
    pub msi: Option<Msi>,
    pub msix: Option<MsiX>,
}

/// Copied discovery observation, never proof of current configuration,
/// mapping, controller or reset ownership. Revalidate after owned attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    pub class: [u8; 3],
}

/// One present PCI function.
pub struct Function<C = EcamConfig> {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    /// Base class, subclass and programming interface.
    pub class: [u8; 3],
    config: C,
}

impl<C> Function<C> {
    /// Copy the already observed fields without additional config reads.
    /// This data grants no configuration or takeover capability.
    pub fn identity(&self) -> Identity {
        Identity {
            address: self.address,
            vendor: self.vendor,
            device: self.device,
            class: self.class,
        }
    }
}

impl<C: ConfigSpace> Function<C> {
    pub fn new(address: Address, config: C) -> Option<Self> {
        Self::try_new(address, config).ok()
    }

    /// Return the config owner on absent/CRS responses. No device
    /// quiescence or mapping-retirement permission follows from either value.
    pub fn try_new(address: Address, config: C) -> Result<Self, C> {
        let id = config.read32(regs::VENDOR_ID);
        if matches!(id as u16, 0xffff | VENDOR_NOT_READY) {
            return Err(config);
        }
        let class = config.read32(regs::CLASS_REVISION);
        Ok(Self {
            address,
            vendor: id as u16,
            device: (id >> 16) as u16,
            class: [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
            config,
        })
    }

    /// Scan config owners and release each read-only observation before
    /// returning copied discovery DATA. The callbacks keep all mapping/root
    /// permission; the result grants no current configuration or device access.
    pub fn inventory_with<E>(
        window: &EcamWindow,
        mut open: impl FnMut(Address) -> Result<Option<Self>, E>,
        mut release: impl FnMut(Self) -> Result<(), E>,
    ) -> Result<Vec<Identity>, E> {
        let mut scans = [None; 256];
        scans[usize::from(window.start_bus)] = Some(BusScan::All);
        let mut identities = Vec::new();
        for bus in window.start_bus..=window.end_bus {
            let Some(scan) = scans[usize::from(bus)] else {
                continue;
            };
            let mut observe = |function: Self| -> Result<(bool, u8), E> {
                let multi = function.config.read8(regs::HEADER_TYPE) & 0x80 != 0;
                let next = if scan == BusScan::Ari {
                    function
                        .extended_capability(EXTENDED_ARI)
                        .map_or(0, |ari| (function.config.read32(ari + 4) >> 8) as u8)
                } else {
                    0
                };
                if let Some((secondary, scan)) = function.secondary()
                    && secondary > bus
                {
                    scans[usize::from(secondary)] = Some(scan);
                }
                identities.push(function.identity());
                release(function)?;
                Ok((multi, next))
            };
            match scan {
                BusScan::Ari => {
                    let mut number = 0u8;
                    loop {
                        let address = Address {
                            segment: window.segment,
                            bus,
                            device: number >> 3,
                            function: number & 7,
                        };
                        let Some(function) = open(address)? else {
                            break;
                        };
                        let (_, next) = observe(function)?;
                        if next <= number {
                            break;
                        }
                        number = next;
                    }
                }
                scan => {
                    for device in 0..if scan == BusScan::OneChild { 1 } else { 32 } {
                        for number in 0..8 {
                            let address = Address {
                                segment: window.segment,
                                bus,
                                device,
                                function: number,
                            };
                            let Some(function) = open(address)? else {
                                if number == 0 {
                                    break;
                                }
                                continue;
                            };
                            let (multi, _) = observe(function)?;
                            if number == 0 && !multi {
                                break;
                            }
                        }
                    }
                }
            }
        }
        Ok(identities)
    }

    pub fn config(&mut self) -> &mut C {
        &mut self.config
    }

    /// Transfer the original configuration owner without creating another
    /// access path or ending its mapping/resource lifetime.
    pub fn into_config(self) -> C {
        self.config
    }

    fn header_type(&self) -> u8 {
        self.config.read8(regs::HEADER_TYPE) & 0x7f
    }

    /// Decode and size every BAR of a type 0 header. Decoding is off while
    /// a BAR holds all ones. A 64-bit BAR in the last slot has no upper
    /// register and is left out.
    pub fn bars(&mut self) -> [Option<Bar>; BARS] {
        let mut bars = [None; BARS];
        if self.header_type() != 0 {
            return bars;
        }
        let command = self.config.read16(regs::COMMAND);
        self.config.write16(
            regs::COMMAND,
            command & !(regs::COMMAND_IO | regs::COMMAND_MEMORY),
        );
        let mut index = 0;
        while index < BARS {
            let offset = regs::BASE_ADDRESS_0 + 4 * index as u16;
            let (low, low_mask) = self.size_register(offset);
            if low & BAR_IO != 0 {
                let size = bar_size(u64::from(low_mask & !3));
                if size != 0 {
                    bars[index] = Some(Bar::Io {
                        port: low & !3,
                        size: size as u32,
                    });
                }
                index += 1;
                continue;
            }
            let wide = low & BAR_MEMORY_TYPE == BAR_MEMORY_64;
            if wide && index + 1 == BARS {
                break;
            }
            let (high, high_mask) = if wide {
                self.size_register(offset + 4)
            } else {
                (0, 0)
            };
            let size = bar_size(u64::from(high_mask) << 32 | u64::from(low_mask & !15));
            if size != 0 {
                bars[index] = Some(Bar::Memory {
                    address: u64::from(high) << 32 | u64::from(low & !15),
                    size,
                    prefetchable: low & BAR_PREFETCHABLE != 0,
                    wide,
                });
            }
            index += if wide { 2 } else { 1 };
        }
        self.config.write16(regs::COMMAND, command);
        bars
    }

    /// A BAR register's value and the bits that read back as writable.
    fn size_register(&mut self, offset: u16) -> (u32, u32) {
        let value = self.config.read32(offset);
        self.config.write32(offset, u32::MAX);
        let mask = self.config.read32(offset);
        self.config.write32(offset, value);
        (value, mask)
    }

    /// Bring the function to D0 as Linux `pci_power_up` does: clear the whole
    /// PMCSR (PME_Status is write-one-to-clear and stays pending), wait the
    /// state's exit delay, and restore the BARs a D3hot soft reset cleared.
    /// Functions without a power management capability are always in D0.
    pub fn power_up(&mut self, clock: &Clock) -> Result<(), BlockError> {
        self.power_up_with_timer(&PowerUpClock(clock))
    }

    /// Run the identical transition under a native timer or
    /// an explicitly checked symbolic device model. Validate before config
    /// access; a provider failure never becomes a successful hardware delay.
    pub fn power_up_with_timer(&mut self, timer: &impl power::Timer) -> Result<(), BlockError> {
        timer.check().map_err(|_| {
            BlockError::Unsupported("PCI power transition requires calibrated timing")
        })?;
        self.power_up_with(|microseconds| {
            timer.wait_us(microseconds).map_err(|_| {
                BlockError::Unsupported("PCI power transition requires calibrated timing")
            })
        })
    }

    fn power_up_with(
        &mut self,
        mut delay: impl FnMut(u64) -> Result<(), BlockError>,
    ) -> Result<(), BlockError> {
        let Some((offset, _)) = self
            .capabilities()
            .into_iter()
            .find(|(_, id)| *id == CAPABILITY_POWER)
        else {
            return Ok(());
        };
        let control = u16::from(offset) + PM_CONTROL;
        let value = self.config.read16(control);
        if value == u16::MAX {
            return Err(BlockError::Unsupported("PCI function does not answer"));
        }
        let state = value & PM_STATE;
        if state == 0 {
            return Ok(());
        }
        let bars: [u32; BARS] =
            core::array::from_fn(|i| self.config.read32(regs::BASE_ADDRESS_0 + 4 * i as u16));
        self.config.write16(control, 0);
        delay(match state {
            D3HOT => D3HOT_DELAY_US,
            D2 => D2_DELAY_US,
            _ => 0,
        })?;
        if self.config.read16(control) & PM_STATE != 0 {
            return Err(BlockError::Unsupported("PCI function did not enter D0"));
        }
        if state == D3HOT && value & PM_NO_SOFT_RESET == 0 && self.header_type() == 0 {
            for (index, bar) in bars.into_iter().enumerate() {
                self.config
                    .write32(regs::BASE_ADDRESS_0 + 4 * index as u16, bar);
            }
        }
        Ok(())
    }

    /// Offsets and IDs of the capability list, up to its first malformed
    /// entry, as Linux's `__pci_find_next_cap_ttl` stops.
    pub fn capabilities(&self) -> Vec<(u8, u8)> {
        capability::capabilities(&self.config)
            .map_while(Result::ok)
            .map(|entry| (entry.offset as u8, entry.id))
            .collect()
    }

    pub fn interrupts(&self) -> Interrupts {
        let mut interrupts = Interrupts::default();
        for (offset, id) in self.capabilities() {
            let base = u16::from(offset);
            let control = self.config.read16(base + 2);
            match id {
                CAPABILITY_MSI => {
                    interrupts.msi = Some(Msi {
                        offset,
                        vectors: 1 << ((control >> 1) & 7).min(5),
                        wide: control & (1 << 7) != 0,
                    })
                }
                CAPABILITY_MSIX => {
                    let table = self.config.read32(base + 4);
                    let pending = self.config.read32(base + 8);
                    interrupts.msix = Some(MsiX {
                        offset,
                        vectors: (control & 0x7ff) + 1,
                        table_bar: (table & 7) as u8,
                        table_offset: table & !7,
                        pending_bar: (pending & 7) as u8,
                        pending_offset: pending & !7,
                    })
                }
                _ => {}
            }
        }
        interrupts
    }

    /// Set or clear Bus Master Enable alone, by a native word store that
    /// leaves the Status register's write-one-to-clear bits alone, and report
    /// whether the function reads back exactly that Command value.
    pub fn set_bus_master(&mut self, enabled: bool) -> bool {
        let previous = self.config.read16(regs::COMMAND);
        let desired = if enabled {
            previous | regs::COMMAND_MASTER
        } else {
            previous & !regs::COMMAND_MASTER
        };
        self.config.write16(regs::COMMAND, desired);
        self.config.read16(regs::COMMAND) == desired
    }

    /// Enable memory decoding and bus mastering without changing interrupt
    /// controls. The driver must first establish its DMA and interrupt policy.
    /// This does not program MSI/MSI-X routes or install interrupt handlers.
    pub fn enable_memory_and_bus_master(&mut self) {
        let command = self.config.read16(regs::COMMAND);
        self.config.write16(
            regs::COMMAND,
            command | regs::COMMAND_MEMORY | regs::COMMAND_MASTER,
        );
    }

    /// Enable a polling driver: memory decoding and bus mastering on,
    /// INTx, MSI and MSI-X off.
    pub fn enable_polled(&mut self) {
        let interrupts = self.interrupts();
        if let Some(msi) = interrupts.msi {
            let control = self.config.read16(u16::from(msi.offset) + 2);
            self.config
                .write16(u16::from(msi.offset) + 2, control & !MSI_ENABLE);
        }
        if let Some(msix) = interrupts.msix {
            let control = self.config.read16(u16::from(msix.offset) + 2);
            self.config
                .write16(u16::from(msix.offset) + 2, control & !(1 << 15));
        }
        let command = self.config.read16(regs::COMMAND);
        self.config.write16(
            regs::COMMAND,
            command | regs::COMMAND_MEMORY | regs::COMMAND_MASTER | regs::COMMAND_INTX_DISABLE,
        );
    }

    /// Turn on MSI-X for a function [`Self::enable_polled`] set up, as
    /// Linux's `msix_capability_init` does: enabled with every vector masked
    /// while `program` writes the table, then the function mask cleared.
    /// The function's other vectors stay masked as `program` leaves them.
    pub fn enable_msix<T>(
        &mut self,
        msix: MsiX,
        program: impl FnOnce() -> Result<T, BlockError>,
    ) -> Result<T, BlockError> {
        let control = u16::from(msix.offset) + 2;
        let value = self.config.read16(control);
        self.config
            .write16(control, value | MSIX_ENABLE | MSIX_FUNCTION_MASK);
        let programmed = program();
        let value = self.config.read16(control);
        let value = match programmed {
            Ok(_) => value & !MSIX_FUNCTION_MASK,
            Err(_) => value & !MSIX_ENABLE,
        };
        self.config.write16(control, value);
        programmed
    }

    /// Turn on MSI for a function [`Self::enable_polled`] set up, with one
    /// vector sending `message`, as Linux's `msi_capability_init` and
    /// `pci_write_msg_msi` do: the address and data written while MSI is
    /// off, then MSI enabled with one message.
    pub fn enable_msi(&mut self, msi: Msi, message: crate::bus::irq::MsiMessage) {
        let control = u16::from(msi.offset) + 2;
        let value = self.config.read16(control);
        self.config
            .write16(control, value & !(MSI_ENABLE | MSI_MULTIPLE_ENABLE));
        self.config
            .write32(u16::from(msi.offset) + 4, message.address as u32);
        let data = if msi.wide {
            self.config
                .write32(u16::from(msi.offset) + 8, (message.address >> 32) as u32);
            u16::from(msi.offset) + 12
        } else {
            u16::from(msi.offset) + 8
        };
        self.config.write16(data, message.data as u16);
        let value = self.config.read16(control);
        self.config
            .write16(control, (value & !MSI_MULTIPLE_ENABLE) | MSI_ENABLE);
    }

    /// Send `message` from the function's first MSI-X entry when its table
    /// is mapped in `bars`, otherwise from MSI, as Linux's
    /// `pci_alloc_irq_vectors` tries them for one vector. Whether the
    /// function offers either.
    pub fn enable_message(
        &mut self,
        handoff: &crate::Handoff,
        bars: &[Option<Bar>],
        message: crate::bus::irq::MsiMessage,
    ) -> Result<bool, BlockError> {
        let interrupts = self.interrupts();
        let table = interrupts.msix.and_then(|msix| {
            let bar = bars.get(usize::from(msix.table_bar)).copied().flatten();
            crate::registers(handoff, bar, u64::from(msix.table_offset), MSIX_ENTRY_BYTES)
                .ok()
                .map(|table| (msix, table))
        });
        if let Some((msix, table)) = table {
            self.enable_msix(msix, || {
                table.write32(0, message.address as u32);
                table.write32(4, (message.address >> 32) as u32);
                table.write32(8, message.data);
                table.write32(12, 0);
                Ok(())
            })?;
            return Ok(true);
        }
        if let Some(msi) = interrupts.msi {
            self.enable_msi(msi, message);
            return Ok(true);
        }
        Ok(false)
    }
}

/// How a bus's functions are found, from the bridge above it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BusScan {
    /// Every device number: a root bus or below a conventional bridge.
    All,
    /// Device 0 alone, below a PCI Express root or downstream port, whose
    /// link has one device. Some devices answer at every device number
    /// there, as Linux's `only_one_child` notes.
    OneChild,
    /// Device 0's functions by their ARI chain, below a port forwarding ARI.
    Ari,
}

impl<C: ConfigSpace> Function<C> {
    /// The offset of the PCI Express extended capability `id`.
    fn extended_capability(&self, id: u16) -> Option<u16> {
        capability::extended_capabilities(&self.config)
            .map_while(Result::ok)
            .find(|entry| entry.id == id)
            .map(|entry| entry.offset)
    }

    /// The bus below this bridge and how to scan it; None for a function
    /// that is no bridge.
    fn secondary(&self) -> Option<(u8, BusScan)> {
        if self.header_type() != HEADER_BRIDGE {
            return None;
        }
        let bus = self.config.read8(SECONDARY_BUS);
        let express = self
            .capabilities()
            .into_iter()
            .find(|&(_, id)| id == CAPABILITY_EXPRESS)
            .map(|(offset, _)| u16::from(offset));
        let scan = match express {
            Some(express) => {
                let kind =
                    (self.config.read16(express + EXPRESS_FLAGS) >> EXPRESS_TYPE_SHIFT) & 0xf;
                let control = self.config.read16(express + EXPRESS_DEVICE_CONTROL_2);
                match kind {
                    EXPRESS_ROOT_PORT | EXPRESS_DOWNSTREAM if control & ARI_FORWARDING != 0 => {
                        BusScan::Ari
                    }
                    EXPRESS_ROOT_PORT | EXPRESS_DOWNSTREAM => BusScan::OneChild,
                    _ => BusScan::All,
                }
            }
            None => BusScan::All,
        };
        Some((bus, scan))
    }
}

impl Function {
    /// Every present function below `window`'s root bus, its first bus: the
    /// root bus, then each bus a bridge leads to, as Linux's
    /// `pci_scan_child_bus` descends. A bus no bridge leads to holds no
    /// function, as the window is one host bridge's ([`rooted`]). Each bus is
    /// scanned as the bridge above it allows: one device below a PCI Express
    /// port, its ARI functions where the port forwards ARI. A function still
    /// initializing (Vendor ID 0x0001) is not returned.
    ///
    /// # Safety
    ///
    /// The window must be mapped uncached, and nothing else may access the
    /// configuration space of the functions this returns.
    pub unsafe fn enumerate(window: &EcamWindow) -> Vec<Self> {
        let at = |bus: u8, device: u8, function: u8| {
            let address = Address {
                segment: window.segment,
                bus,
                device,
                function,
            };
            // SAFETY: forwarded exclusive mapped-window contract.
            let config = unsafe { window.config(bus, device, function) };
            (address, config)
        };
        let mut scans = [None; 256];
        scans[usize::from(window.start_bus)] = Some(BusScan::All);
        let mut functions = Vec::new();
        for bus in window.start_bus..=window.end_bus {
            let Some(scan) = scans[usize::from(bus)] else {
                continue;
            };
            let first = functions.len();
            match scan {
                BusScan::Ari => {
                    // Functions 0-255 of device 0, each naming the next.
                    let mut number = 0u8;
                    loop {
                        let (address, config) = at(bus, number >> 3, number & 7);
                        let Some(present) = Function::new(address, config) else {
                            break;
                        };
                        let next = present
                            .extended_capability(EXTENDED_ARI)
                            .map_or(0, |ari| (present.config.read32(ari + 4) >> 8) as u8);
                        functions.push(present);
                        if next <= number {
                            break;
                        }
                        number = next;
                    }
                }
                scan => {
                    let devices = if scan == BusScan::OneChild { 1 } else { 32 };
                    for device in 0..devices {
                        for function in 0..8u8 {
                            let (address, config) = at(bus, device, function);
                            let multifunction = config.read8(regs::HEADER_TYPE) & 0x80 != 0;
                            match Function::new(address, config) {
                                Some(present) => functions.push(present),
                                None if function == 0 => break,
                                None => {}
                            }
                            if function == 0 && !multifunction {
                                break;
                            }
                        }
                    }
                }
            }
            for bridge in &functions[first..] {
                if let Some((secondary, scan)) = bridge.secondary()
                    && secondary > bus
                {
                    scans[usize::from(secondary)] = Some(scan);
                }
            }
        }
        functions
    }
}

/// The MCFG's windows narrowed to host bridges: for each root bridge, given
/// as its segment and its bus range (the bus-number descriptor of its
/// `_CRS`), the part of its segment's window that decodes the range, from
/// its root bus. Bridges no window decodes are left out.
pub fn rooted(windows: &[EcamWindow], bridges: &[(u16, RangeInclusive<u8>)]) -> Vec<EcamWindow> {
    bridges
        .iter()
        .filter_map(|(segment, buses)| {
            let window = windows.iter().find(|window| {
                window.segment == *segment
                    && (window.start_bus..=window.end_bus).contains(buses.start())
            })?;
            Some(EcamWindow {
                start_bus: *buses.start(),
                end_bus: window.end_bus.min(*buses.end()),
                ..*window
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
