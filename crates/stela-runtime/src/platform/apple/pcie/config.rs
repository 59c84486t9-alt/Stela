//! Explicitly described PCI configuration registers and memory BARs.
//!
//! Field encodings: Linux v6.17 `include/uapi/linux/pci_regs.h`. Device
//! identities and capabilities must be supplied from the selected device's
//! evidence; this module supplies no Apple or downstream-device identity.
use super::super::bus::Width;
use alloc::vec::Vec;

pub const COMMAND: u16 = 0x04;
pub const MEMORY_ENABLE: u16 = 1 << 1;
pub const BUS_MASTER_ENABLE: u16 = 1 << 2;
pub const INTX_DISABLE: u16 = 1 << 10;
const BAR_FIRST: u16 = 0x10;
const BAR_BYTES: u16 = 4;
const CONFIG_BYTES: u16 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    Layout,
    Access,
    Unsupported,
}

/// One aligned dword. Unlisted dwords refuse, including capabilities whose
/// effects are not modeled. RO bits ignore writes as PCI requires; W1C bits
/// clear only the written lanes. `writable` and `clear` must be disjoint.
#[derive(Debug, Clone, Copy)]
pub struct Register {
    pub offset: u16,
    pub reset: u32,
    pub writable: u32,
    pub clear: u32,
}

#[derive(Debug, Clone)]
struct State {
    description: Register,
    value: u32,
}

/// A 32-bit or paired 64-bit memory BAR. A probe returns the size mask;
/// writes to partial lanes update only those lanes and retain type bits.
#[derive(Debug, Clone)]
pub struct MemoryBar {
    index: u8,
    bytes: u64,
    wide: bool,
    prefetch: bool,
    address: u64,
}
impl MemoryBar {
    pub fn new(index: u8, bytes: u64, wide: bool, prefetch: bool) -> Result<Self, ConfigError> {
        if index >= 6
            || (wide && index == 5)
            || bytes < 16
            || !bytes.is_power_of_two()
            || (!wide && bytes > 1u64 << 32)
        {
            return Err(ConfigError::Layout);
        }
        Ok(Self {
            index,
            bytes,
            wide,
            prefetch,
            address: 0,
        })
    }
    fn flags(&self) -> u64 {
        (u64::from(self.wide) * 4) | (u64::from(self.prefetch) * 8)
    }
    fn mask(&self) -> u64 {
        let width = if self.wide {
            u64::MAX
        } else {
            u64::from(u32::MAX)
        };
        !(self.bytes - 1) & width
    }
    fn contains(&self, offset: u16) -> bool {
        let first = BAR_FIRST + u16::from(self.index) * BAR_BYTES;
        offset == first || (self.wide && offset == first + BAR_BYTES)
    }
    fn shift(&self, offset: u16) -> u32 {
        u32::from(offset - BAR_FIRST - u16::from(self.index) * BAR_BYTES) * 8
    }
    fn read(&self, offset: u16) -> u32 {
        ((self.address | self.flags()) >> self.shift(offset)) as u32
    }
    fn write(&mut self, offset: u16, value: u32, lanes: u32) {
        let shift = self.shift(offset);
        let lanes = u64::from(lanes) << shift;
        let value = u64::from(value) << shift;
        self.address = ((self.address & !lanes) | (value & lanes)) & self.mask();
    }
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[derive(Debug, Clone)]
pub struct ConfigSpace {
    registers: Vec<State>,
    bars: Vec<MemoryBar>,
}
impl ConfigSpace {
    /// All ordinary registers, including identity, header type, command and
    /// bridge windows, are explicit descriptions. No inferred capability list.
    pub fn new(registers: &[Register], bars: Vec<MemoryBar>) -> Result<Self, ConfigError> {
        for (index, reg) in registers.iter().enumerate() {
            if reg.offset >= CONFIG_BYTES
                || reg.offset % 4 != 0
                || reg.writable & reg.clear != 0
                || registers[..index]
                    .iter()
                    .any(|other| other.offset == reg.offset)
                || bars.iter().any(|bar| bar.contains(reg.offset))
            {
                return Err(ConfigError::Layout);
            }
        }
        for (index, bar) in bars.iter().enumerate() {
            if bars[..index].iter().any(|other| {
                other.contains(BAR_FIRST + u16::from(bar.index) * 4)
                    || (bar.wide && other.contains(BAR_FIRST + u16::from(bar.index + 1) * 4))
            }) {
                return Err(ConfigError::Layout);
            }
        }
        Ok(Self {
            registers: registers
                .iter()
                .map(|&description| State {
                    value: description.reset,
                    description,
                })
                .collect(),
            bars,
        })
    }
    /// The owned-bank adapter currently implements standard memory routing,
    /// bus mastering, INTx masking and secondary reset only. Capability state
    /// needs an actual endpoint protocol, not an arbitrary RW register image.
    pub(super) fn check_header_contract(&self, bridge: bool) -> Result<(), &'static str> {
        for register in &self.registers {
            let d = register.description;
            if d.offset >= 0x40
                || (d.offset == 0x34 && d.reset & 0xff != 0)
                || (d.offset == COMMAND && d.reset & 0x0010_0000 != 0)
            {
                return Err(
                    "PCIe capability protocols require an actual qualified configuration adapter",
                );
            }
            let supported = match d.offset {
                COMMAND => u32::from(MEMORY_ENABLE | BUS_MASTER_ENABLE | INTX_DISABLE),
                0x18 if bridge => 0x00ff_ffff,
                0x20 | 0x24 if bridge => 0xfff0_fff0,
                0x28 | 0x2c if bridge => u32::MAX,
                0x3c if bridge => 1 << 22,
                _ => 0,
            };
            if d.writable & !supported != 0 || d.clear != 0 {
                return Err("PCIe configuration side effects exceed the qualified header contract");
            }
            if d.offset == COMMAND && d.reset & 0xffff & !supported != 0 {
                return Err("PCIe initial command enables an unsupported protocol");
            }
        }
        Ok(())
    }
    fn access(offset: u16, width: Width) -> Result<(u16, u32, u32), ConfigError> {
        if width == Width::Double
            || !u64::from(offset).is_multiple_of(width.bytes())
            || u64::from(offset) + width.bytes() > u64::from(CONFIG_BYTES)
        {
            return Err(ConfigError::Access);
        }
        let shift = u32::from(offset % 4) * 8;
        Ok((offset & !3, shift, (width.mask() as u32) << shift))
    }
    pub fn read(&self, offset: u16, width: Width) -> Result<u64, ConfigError> {
        let (word, shift, _) = Self::access(offset, width)?;
        let value = if let Some(bar) = self.bars.iter().find(|bar| bar.contains(word)) {
            bar.read(word)
        } else {
            self.registers
                .iter()
                .find(|reg| reg.description.offset == word)
                .ok_or(ConfigError::Unsupported)?
                .value
        };
        Ok(u64::from(value >> shift) & width.mask())
    }
    pub fn write(&mut self, offset: u16, width: Width, value: u64) -> Result<(), ConfigError> {
        let (word, shift, lanes) = Self::access(offset, width)?;
        let value = (value as u32) << shift;
        if let Some(bar) = self.bars.iter_mut().find(|bar| bar.contains(word)) {
            bar.write(word, value, lanes);
        } else {
            let reg = self
                .registers
                .iter_mut()
                .find(|reg| reg.description.offset == word)
                .ok_or(ConfigError::Unsupported)?;
            let writable = reg.description.writable & lanes;
            reg.value = ((reg.value & !writable) | (value & writable))
                & !(value & lanes & reg.description.clear);
        }
        Ok(())
    }
    pub fn reset(&mut self) {
        for reg in &mut self.registers {
            reg.value = reg.description.reset;
        }
        for bar in &mut self.bars {
            bar.address = 0;
        }
    }
    pub fn command(&self) -> u16 {
        self.registers
            .iter()
            .find(|reg| reg.description.offset == COMMAND)
            .map_or(0, |reg| reg.value as u16)
    }
    pub fn bar_bytes(&self, index: u8) -> Option<u64> {
        self.bars
            .iter()
            .find(|bar| bar.index == index)
            .map(|bar| bar.bytes)
    }
    pub fn bar_count(&self) -> usize {
        self.bars.len()
    }
    /// Endpoint-relative BAR selection; bridge/root-complex windows must
    /// independently admit the complete transaction before calling this.
    pub fn memory(&self, address: u64, bytes: u64) -> Option<(u8, u64)> {
        self.memory_decode(address, bytes).ok().flatten()
    }
    pub(super) fn memory_decode(
        &self,
        address: u64,
        bytes: u64,
    ) -> Result<Option<(u8, u64)>, ConfigError> {
        if bytes == 0 || self.command() & MEMORY_ENABLE == 0 {
            return Ok(None);
        }
        let Some(end) = address.checked_add(bytes) else {
            return Ok(None);
        };
        let mut matches = self.bars.iter().filter_map(|bar| {
            let last = bar.address.checked_add(bar.bytes)?;
            (address >= bar.address && end <= last).then(|| (bar.index, address - bar.address))
        });
        let first = matches.next();
        if matches.next().is_some() {
            return Err(ConfigError::Layout);
        }
        Ok(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configuration() -> ConfigSpace {
        ConfigSpace::new(
            &[
                Register {
                    offset: 0,
                    reset: 0x5678_1234,
                    writable: 0,
                    clear: 0,
                },
                Register {
                    offset: 4,
                    reset: 0xf900_0000,
                    writable: 0x406,
                    clear: 0xf900_0000,
                },
            ],
            alloc::vec![MemoryBar::new(0, 0x4000, true, false).unwrap()],
        )
        .unwrap()
    }
    #[test]
    fn config_byte_lanes_preserve_identity_and_w1c_status() {
        let mut c = configuration();
        c.write(0, Width::Word, 0).unwrap();
        assert_eq!(c.read(0, Width::Word), Ok(0x5678_1234));
        c.write(4, Width::Byte, 6).unwrap();
        assert_eq!(c.read(4, Width::Word), Ok(0xf900_0006));
        c.write(7, Width::Byte, 0x88).unwrap();
        assert_eq!(c.read(4, Width::Word), Ok(0x7100_0006));
        assert_eq!(c.read(8, Width::Word), Err(ConfigError::Unsupported));
        assert_eq!(c.read(4094, Width::Word), Err(ConfigError::Access));
    }
    #[test]
    fn paired_bar_size_probe_assignment_decode_and_reset() {
        let mut c = configuration();
        c.write(0x10, Width::Word, u64::from(u32::MAX)).unwrap();
        c.write(0x14, Width::Word, u64::from(u32::MAX)).unwrap();
        assert_eq!(c.read(0x10, Width::Word), Ok(0xffff_c004));
        assert_eq!(c.read(0x14, Width::Word), Ok(0xffff_ffff));
        c.write(0x14, Width::Word, 6).unwrap();
        c.write(0x10, Width::Word, 0xa000_000f).unwrap();
        assert_eq!(c.memory(0x6_a000_0000, 4), None);
        c.write(4, Width::Half, u64::from(MEMORY_ENABLE)).unwrap();
        assert_eq!(c.memory(0x6_a000_3ffc, 4), Some((0, 0x3ffc)));
        assert_eq!(c.memory(0x6_a000_3ffc, 8), None);
        assert_eq!(c.memory(u64::MAX, 8), None);
        c.reset();
        assert_eq!(c.read(0x10, Width::Word), Ok(4));
        assert_eq!(c.command(), 0);
    }
    #[test]
    fn overlapping_or_incompatible_register_layouts_refuse() {
        assert!(
            ConfigSpace::new(
                &[],
                alloc::vec![
                    MemoryBar::new(0, 0x1000, true, false).unwrap(),
                    MemoryBar::new(1, 0x1000, false, false).unwrap(),
                ]
            )
            .is_err()
        );
        assert!(MemoryBar::new(5, 0x1000, true, false).is_err());
        assert!(MemoryBar::new(0, 0x1800, false, false).is_err());
    }
    #[test]
    fn zero_bar_is_a_real_decoder_and_overlapping_bars_do_not_choose_a_winner() {
        let mut c = configuration();
        c.write(4, Width::Half, u64::from(MEMORY_ENABLE)).unwrap();
        assert_eq!(c.memory(0, 4), Some((0, 0)));
        let mut c = ConfigSpace::new(
            &[Register {
                offset: 4,
                reset: 2,
                writable: 0x406,
                clear: 0,
            }],
            alloc::vec![
                MemoryBar::new(0, 0x1000, false, false).unwrap(),
                MemoryBar::new(1, 0x1000, false, false).unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(c.memory(0, 4), None);
        c.write(0x14, Width::Word, 0x1000).unwrap();
        assert_eq!(c.memory(0, 4), Some((0, 0)));
        assert_eq!(c.memory(0x1000, 4), Some((1, 0)));
    }
    #[test]
    fn owned_header_admission_cannot_turn_stored_capability_bits_into_device_support() {
        let mut c = configuration();
        assert!(c.check_header_contract(false).is_err()); // unsupported W1C status protocol
        c.registers[1].description.clear = 0;
        assert!(c.check_header_contract(false).is_ok());
        c.registers[1].description.reset |= 1 << 20; // capability-list-present
        assert!(c.check_header_contract(false).is_err());
        c.registers[1].description.reset &= !(1 << 20);
        c.registers.push(State {
            description: Register {
                offset: 0x50,
                reset: 0,
                writable: 1,
                clear: 0,
            },
            value: 0,
        });
        assert!(c.check_header_contract(false).is_err());
    }
}
