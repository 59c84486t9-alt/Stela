//! PCI configuration space through ECAM: enumeration, BAR decoding and
//! sizing, capabilities and interrupt discovery. Memory decoding and bus
//! mastering are independent of interrupt policy. The current boot drivers
//! use [`Function::enable_polled`]; interrupt-driven ports must arrange
//! delivery with the mount before enabling their interrupt sources.
use super::mmio::Mmio;
use crate::{Clock, block::BlockError};
use alloc::vec::Vec;
use core::{fmt, ops::Range};

mod aspm;
pub mod msi;
pub use aspm::{disable_aspm_l1_2_link, disable_aspm_link};

const VENDOR: u16 = 0x00;
const COMMAND: u16 = 0x04;
const STATUS: u16 = 0x06;
const CLASS: u16 = 0x08;
const HEADER_TYPE: u16 = 0x0e;
const BAR0: u16 = 0x10;
const CAPABILITIES: u16 = 0x34;

const COMMAND_IO: u16 = 1 << 0;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;
const COMMAND_INTX_DISABLE: u16 = 1 << 10;
const STATUS_CAPABILITIES: u16 = 1 << 4;
/// Memory BAR type field: 64-bit (PCI 3.0 §6.2.5.1).
const BAR_MEMORY_64: u32 = 2 << 1;
const BAR_MEMORY_TYPE: u32 = 3 << 1;
const BAR_PREFETCHABLE: u32 = 1 << 3;
const BAR_IO: u32 = 1;
const BARS: usize = 6;
/// Capability IDs after this one are not followed (Linux `__pci_find_next_cap_ttl`).
const CAPABILITY_LIST_END: u8 = 0xff;
const CAPABILITY_LIMIT: usize = 48;

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

pub const CAPABILITY_POWER: u8 = 0x01;
pub const CAPABILITY_MSI: u8 = 0x05;
pub const CAPABILITY_VENDOR: u8 = 0x09;
pub const CAPABILITY_MSIX: u8 = 0x11;

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
}

/// A function's 4 KiB of ECAM configuration space.
pub struct EcamConfig {
    registers: Mmio,
}

impl ConfigSpace for EcamConfig {
    fn read8(&self, offset: u16) -> u8 {
        self.registers.read8(usize::from(offset))
    }

    fn read16(&self, offset: u16) -> u16 {
        self.registers.read16(usize::from(offset))
    }

    fn read32(&self, offset: u16) -> u32 {
        self.registers.read32(usize::from(offset))
    }

    fn write32(&mut self, offset: u16, value: u32) {
        self.registers.write32(usize::from(offset), value)
    }

    fn write8(&mut self, offset: u16, value: u8) {
        self.registers.write8(usize::from(offset), value)
    }

    fn write16(&mut self, offset: u16, value: u16) {
        self.registers.write16(usize::from(offset), value)
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

/// One present PCI function.
pub struct Function<C = EcamConfig> {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    /// Base class, subclass and programming interface.
    pub class: [u8; 3],
    config: C,
}

impl<C: ConfigSpace> Function<C> {
    pub fn new(address: Address, config: C) -> Option<Self> {
        let id = config.read32(VENDOR);
        if id as u16 == 0xffff {
            return None;
        }
        let class = config.read32(CLASS);
        Some(Self {
            address,
            vendor: id as u16,
            device: (id >> 16) as u16,
            class: [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
            config,
        })
    }

    pub fn config(&mut self) -> &mut C {
        &mut self.config
    }

    fn header_type(&self) -> u8 {
        self.config.read8(HEADER_TYPE) & 0x7f
    }

    /// Decode and size every BAR of a type 0 header. Decoding is off while
    /// a BAR holds all ones. A 64-bit BAR in the last slot has no upper
    /// register and is left out.
    pub fn bars(&mut self) -> [Option<Bar>; BARS] {
        let mut bars = [None; BARS];
        if self.header_type() != 0 {
            return bars;
        }
        let command = self.config.read16(COMMAND);
        self.config
            .write16(COMMAND, command & !(COMMAND_IO | COMMAND_MEMORY));
        let mut index = 0;
        while index < BARS {
            let offset = BAR0 + 4 * index as u16;
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
        self.config.write16(COMMAND, command);
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
        let bars: [u32; BARS] = core::array::from_fn(|i| self.config.read32(BAR0 + 4 * i as u16));
        self.config.write16(control, 0);
        clock.delay(match state {
            D3HOT => D3HOT_DELAY_US,
            D2 => D2_DELAY_US,
            _ => 0,
        });
        if self.config.read16(control) & PM_STATE != 0 {
            return Err(BlockError::Unsupported("PCI function did not enter D0"));
        }
        if state == D3HOT && value & PM_NO_SOFT_RESET == 0 && self.header_type() == 0 {
            for (index, bar) in bars.into_iter().enumerate() {
                self.config.write32(BAR0 + 4 * index as u16, bar);
            }
        }
        Ok(())
    }

    /// Offsets and IDs of the capability list, bounded against loops.
    pub fn capabilities(&self) -> Vec<(u8, u8)> {
        let mut found = Vec::new();
        if self.config.read16(STATUS) & STATUS_CAPABILITIES == 0 {
            return found;
        }
        let mut offset = self.config.read8(CAPABILITIES) & !3;
        while offset >= 0x40 && found.len() < CAPABILITY_LIMIT {
            let header = self.config.read16(u16::from(offset));
            let id = header as u8;
            if id == CAPABILITY_LIST_END {
                break;
            }
            found.push((offset, id));
            offset = (header >> 8) as u8 & !3;
        }
        found
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

    /// Enable memory decoding and bus mastering without changing interrupt
    /// controls. The driver must first establish its DMA and interrupt policy.
    /// This does not program MSI/MSI-X routes or install interrupt handlers.
    pub fn enable_memory_and_bus_master(&mut self) {
        let command = self.config.read16(COMMAND);
        self.config
            .write16(COMMAND, command | COMMAND_MEMORY | COMMAND_BUS_MASTER);
    }

    /// Enable a polling driver: memory decoding and bus mastering on,
    /// INTx, MSI and MSI-X off.
    pub fn enable_polled(&mut self) {
        let interrupts = self.interrupts();
        if let Some(msi) = interrupts.msi {
            let control = self.config.read16(u16::from(msi.offset) + 2);
            self.config.write16(u16::from(msi.offset) + 2, control & !1);
        }
        if let Some(msix) = interrupts.msix {
            let control = self.config.read16(u16::from(msix.offset) + 2);
            self.config
                .write16(u16::from(msix.offset) + 2, control & !(1 << 15));
        }
        let command = self.config.read16(COMMAND);
        self.config.write16(
            COMMAND,
            command | COMMAND_MEMORY | COMMAND_BUS_MASTER | COMMAND_INTX_DISABLE,
        );
    }
}

impl Function {
    /// Every present function in `window`.
    ///
    /// # Safety
    ///
    /// The window must be mapped uncached, and nothing else may access the
    /// configuration space of the functions this returns.
    pub unsafe fn enumerate(window: &EcamWindow) -> Vec<Self> {
        let mut functions = Vec::new();
        for bus in window.start_bus..=window.end_bus {
            for device in 0..32u8 {
                for function in 0..8u8 {
                    let address = Address {
                        segment: window.segment,
                        bus,
                        device,
                        function,
                    };
                    let offset = (u64::from(bus) << 20)
                        | (u64::from(device) << 15)
                        | (u64::from(function) << 12);
                    // SAFETY: the window is mapped; this is one function's page.
                    let config = EcamConfig {
                        // SAFETY: covered by this function's own safety contract.
                        registers: unsafe { Mmio::new(window.base + offset) },
                    };
                    let multifunction = config.read8(HEADER_TYPE) & 0x80 != 0;
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
        functions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_ecam_narrow_stores_preserve_adjacent_status_and_vendor_bytes() {
        let mut words = [0xa5c3_5a7eu32; 1024];
        let mut config = EcamConfig {
            // SAFETY: this test exclusively owns the aligned backing allocation.
            registers: unsafe { Mmio::new(words.as_mut_ptr() as u64) },
        };
        config.write8(0x44, 0x78);
        assert_eq!(config.read32(0x44), 0xa5c3_5a78);
        config.write8(0x47, 0x12);
        assert_eq!(config.read32(0x44), 0x12c3_5a78);
        config.write16(COMMAND, 0x0406);
        assert_eq!(config.read32(COMMAND), 0xa5c3_0406);
    }

    /// A configuration space whose BAR registers keep only their writable
    /// bits, as hardware does.
    struct Fake {
        words: [u32; 64],
        bar_masks: [u32; 6],
    }

    impl ConfigSpace for Fake {
        fn read32(&self, offset: u16) -> u32 {
            self.words[usize::from(offset / 4)]
        }

        fn write32(&mut self, offset: u16, value: u32) {
            let index = usize::from(offset / 4);
            self.words[index] = match index.checked_sub(4) {
                Some(bar) if bar < 6 => {
                    let mask = self.bar_masks[bar];
                    value & mask | self.words[index] & !mask
                }
                _ => value,
            };
        }

        fn write16(&mut self, offset: u16, value: u16) {
            let shift = (offset & 2) * 8;
            let word = &mut self.words[usize::from(offset / 4)];
            *word = *word & !(0xffff << shift) | u32::from(value) << shift;
        }

        fn write8(&mut self, offset: u16, value: u8) {
            let shift = (offset & 3) * 8;
            let word = &mut self.words[usize::from(offset / 4)];
            *word = *word & !(0xff << shift) | u32::from(value) << shift;
        }
    }

    fn fake() -> Fake {
        let mut words = [0; 64];
        words[0] = 0x1042_1af4;
        words[1] = 0x0010_0007; // capabilities; IO, memory and master on
        words[2] = 0x0108_0200;
        words[13] = 0x40;
        // MSI-X at 0x40: 4 vectors, table in BAR 4 at 0, PBA in BAR 4 at 0x800.
        words[16] = 0x0003_5011;
        words[17] = 0x0000_0004;
        words[18] = 0x0000_0804;
        // MSI at 0x50: 64-bit, up to 8 vectors, end of list.
        words[20] = 0x0086_0005;
        Fake {
            words,
            bar_masks: [0; 6],
        }
    }

    #[test]
    fn bars_decode_and_size_memory_wide_and_io() {
        let mut config = fake();
        // BAR0: 16 KiB 32-bit memory; BAR1: 256-byte I/O; BAR2+3: 64-bit
        // prefetchable 1 MiB above 4 GiB; BAR4 unimplemented; BAR5 4 KiB.
        config.words[4] = 0xfebf_0000;
        config.bar_masks[0] = 0xffff_c000;
        config.words[5] = 0xc001;
        config.bar_masks[1] = 0xffff_ff00;
        config.words[6] = 0x0010_000c;
        config.bar_masks[2] = 0xfff0_0000;
        config.words[7] = 0x80;
        config.bar_masks[3] = 0xffff_ffff;
        config.words[9] = 0xfeb0_0000;
        config.bar_masks[5] = 0xffff_f000;
        let mut function = Function::new(Address::default_for_tests(), config).unwrap();
        let bars = function.bars();
        assert_eq!(
            bars[0],
            Some(Bar::Memory {
                address: 0xfebf_0000,
                size: 0x4000,
                prefetchable: false,
                wide: false
            })
        );
        assert_eq!(
            bars[1],
            Some(Bar::Io {
                port: 0xc000,
                size: 0x100
            })
        );
        assert_eq!(
            bars[2],
            Some(Bar::Memory {
                address: 0x80_0010_0000,
                size: 0x10_0000,
                prefetchable: true,
                wide: true
            })
        );
        assert_eq!(bars[3], None);
        assert_eq!(bars[4], None);
        assert_eq!(
            bars[5].and_then(|bar| bar.memory()),
            Some(0xfeb0_0000..0xfeb0_1000)
        );
        // Sizing restores every BAR and the command register.
        assert_eq!(function.config().words[4], 0xfebf_0000);
        assert_eq!(function.config().words[7], 0x80);
        assert_eq!(function.config().read16(COMMAND), 0x0007);
        assert_eq!(function.class, [1, 8, 2]);
    }

    #[test]
    fn interrupts_are_discovered_and_left_off() {
        let mut function = Function::new(Address::default_for_tests(), fake()).unwrap();
        function.config().words[16] |= 1 << 31; // MSI-X enabled by firmware
        function.config().words[20] |= 1 << 16; // MSI enabled by firmware
        let interrupts = function.interrupts();
        assert_eq!(
            interrupts.msix,
            Some(MsiX {
                offset: 0x40,
                vectors: 4,
                table_bar: 4,
                table_offset: 0,
                pending_bar: 4,
                pending_offset: 0x800
            })
        );
        assert_eq!(
            interrupts.msi,
            Some(Msi {
                offset: 0x50,
                vectors: 8,
                wide: true
            })
        );
        function.enable_polled();
        assert_eq!(function.config().words[16] >> 31, 0);
        assert_eq!(function.config().words[20] >> 16 & 1, 0);
        let command = function.config().read16(COMMAND);
        assert_eq!(command & 0x406, 0x406);
    }

    #[test]
    fn memory_enable_does_not_choose_an_interrupt_policy() {
        for intx in [0, COMMAND_INTX_DISABLE] {
            let mut config = fake();
            config.words[1] = (config.words[1] & !0xffff) | u32::from(intx);
            config.words[16] |= 1 << 31;
            config.words[20] |= 1 << 16;
            let mut function = Function::new(Address::default_for_tests(), config).unwrap();
            function.enable_memory_and_bus_master();
            let config = function.config();
            assert_eq!(
                config.read16(COMMAND),
                intx | COMMAND_MEMORY | COMMAND_BUS_MASTER
            );
            assert_eq!(config.words[16] >> 31, 1);
            assert_eq!(config.words[20] >> 16 & 1, 1);
        }
    }

    #[test]
    fn a_looping_capability_list_is_bounded() {
        let mut config = fake();
        config.words[20] = 0x0086_4005; // MSI points back at MSI-X
        let function = Function::new(Address::default_for_tests(), config).unwrap();
        assert_eq!(function.capabilities().len(), 48);
    }

    #[test]
    fn bar_sizes_come_from_the_lowest_writable_address_bit() {
        let mut config = fake();
        // BAR0+1: 64-bit 1 MiB whose upper dword is read-only zero; BAR2:
        // 32-bit range ending at 4 GiB; BAR5: 64-bit type with no upper register.
        config.words[4] = 0xfe00_0004;
        config.bar_masks[0] = 0xfff0_0000;
        config.words[6] = 0xffff_f000;
        config.bar_masks[2] = 0xffff_f000;
        config.words[9] = 0xfd00_0004;
        config.bar_masks[5] = 0xffff_f000;
        let mut function = Function::new(Address::default_for_tests(), config).unwrap();
        let bars = function.bars();
        assert_eq!(
            bars[0],
            Some(Bar::Memory {
                address: 0xfe00_0000,
                size: 0x10_0000,
                prefetchable: false,
                wide: true
            })
        );
        assert_eq!(
            bars[2].and_then(|bar| bar.memory()),
            Some(0xffff_f000..0x1_0000_0000)
        );
        assert_eq!(bars[5], None);
        let overflowing = Bar::Memory {
            address: u64::MAX - 0xfff,
            size: 0x2000,
            prefetchable: false,
            wide: true,
        };
        assert_eq!(overflowing.memory(), None);
    }

    #[test]
    fn the_capability_walk_stops_at_an_all_ones_id() {
        let mut config = fake();
        config.words[16] = 0x0003_50ff; // first capability reads as all ones
        let function = Function::new(Address::default_for_tests(), config).unwrap();
        assert!(function.capabilities().is_empty());
    }

    /// A function whose D3hot exit performs the internal reset that
    /// No_Soft_Reset clear advertises: its BARs read back as zero.
    struct SoftReset(Fake);

    impl ConfigSpace for SoftReset {
        fn read32(&self, offset: u16) -> u32 {
            self.0.read32(offset)
        }

        fn write32(&mut self, offset: u16, value: u32) {
            self.0.write32(offset, value)
        }

        fn write16(&mut self, offset: u16, value: u16) {
            let before = self.0.read16(offset);
            self.0.write16(offset, value);
            if offset == 0x64 && before & PM_STATE == D3HOT && before & PM_NO_SOFT_RESET == 0 {
                self.0.words[4..10].fill(0);
            }
        }
    }

    #[test]
    fn power_up_leaves_d3hot_and_restores_soft_reset_bars() {
        for no_soft_reset in [0, PM_NO_SOFT_RESET] {
            let mut config = fake();
            config.words[20] = 0x0086_6005; // MSI, next capability at 0x60
            config.words[24] = 0x0003_0001; // power management, end of list
            config.words[25] = u32::from(D3HOT | no_soft_reset | 1 << 15);
            config.words[4] = 0xfebf_0000;
            config.bar_masks[0] = 0xffff_c000;
            let mut function =
                Function::new(Address::default_for_tests(), SoftReset(config)).unwrap();
            let clock = Clock {
                ticks_per_microsecond: 0,
            };
            function.power_up(&clock).unwrap();
            assert_eq!(function.config().read16(0x64), 0);
            assert_eq!(function.config().read32(BAR0), 0xfebf_0000);
        }
    }

    #[test]
    fn power_up_reports_a_function_that_stays_in_d3hot() {
        let mut config = fake();
        config.words[20] = 0x0086_6005;
        config.words[24] = 0x0003_0001;
        config.words[25] = u32::from(D3HOT);
        struct Stuck(Fake);
        impl ConfigSpace for Stuck {
            fn read32(&self, offset: u16) -> u32 {
                self.0.read32(offset)
            }
            fn write32(&mut self, offset: u16, value: u32) {
                self.0.write32(offset, value)
            }
            fn write16(&mut self, offset: u16, value: u16) {
                if offset != 0x64 {
                    self.0.write16(offset, value)
                }
            }
        }
        let mut function = Function::new(Address::default_for_tests(), Stuck(config)).unwrap();
        let clock = Clock {
            ticks_per_microsecond: 0,
        };
        assert_eq!(
            function.power_up(&clock),
            Err(BlockError::Unsupported("PCI function did not enter D0"))
        );
    }

    #[test]
    fn ecam_ranges_cover_the_decoded_buses() {
        let window = EcamWindow {
            base: 0xb000_0000,
            segment: 0,
            start_bus: 2,
            end_bus: 3,
        };
        assert_eq!(window.range(), 0xb020_0000..0xb040_0000);
    }

    impl Address {
        fn default_for_tests() -> Self {
            Self {
                segment: 0,
                bus: 0,
                device: 3,
                function: 0,
            }
        }
    }
}
