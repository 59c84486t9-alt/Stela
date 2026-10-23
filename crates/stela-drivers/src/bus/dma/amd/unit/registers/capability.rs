// SPDX-License-Identifier: GPL-2.0-only
// PCI capability encodings follow Linux include/uapi/linux/pci_regs.h at
// cc9de5d4b5ab6459f5774946aa3195ad51236fa8, Copyright 1994 Drew Eckhardt
// and 1997–1999 Martin Mares. AMD register layouts follow AMD 48882 rev 3.11.
//! Complete conventional capability framing for one retained remapper function.
use super::*;

pub(super) struct Capabilities {
    pub(super) entries: [Option<Configuration>; CAP_LIMIT],
    pub(super) count: usize,
    pub(super) has_msix: bool,
}

fn config32<C: ConfigSpace>(config: &C, offset: u16) -> Result<u32, Error> {
    let value = config.read32(offset);
    if value == u32::MAX {
        Err(Error::ReadFailed(offset))
    } else {
        Ok(value)
    }
}

/// Complete conventional list, not Function::capabilities' partial discovery.
/// Extents occupy four-byte cells; overlap detection also bounds cycles.
pub(super) fn scan<C: ConfigSpace>(config: &C) -> Result<Capabilities, Error> {
    let mut result = Capabilities {
        entries: [None; CAP_LIMIT],
        count: 0,
        has_msix: false,
    };
    if config.read16(6) & STATUS_CAPABILITIES == 0 {
        return Ok(result);
    }
    let mut offset = u16::from(config.read8(0x34));
    let mut occupied = 0u64;
    let mut singleton = 0u32;
    while offset != 0 {
        if !(CAP_FIRST..CONFIG_LIMIT).contains(&offset) || !offset.is_multiple_of(4) {
            return Err(Error::Capability(offset));
        }
        let header = config32(config, offset)?;
        let id = header as u8;
        let bytes = capability_bytes(config, offset, header)?;
        let end = offset
            .checked_add(bytes)
            .filter(|end| *end <= CONFIG_LIMIT)
            .ok_or(Error::Capability(offset))?;
        let mut cells = 0u64;
        for cell in (offset / 4)..end.div_ceil(4) {
            cells |= 1u64 << cell;
        }
        if occupied & cells != 0 {
            return Err(Error::Capability(offset));
        }
        occupied |= cells;
        result.has_msix |= id == 0x11;
        if !matches!(id, SECURE_DEVICE | 9) {
            let bit = 1u32 << id;
            if singleton & bit != 0 {
                return Err(Error::Capability(offset));
            }
            singleton |= bit;
        }
        if id == SECURE_DEVICE {
            if result.count == CAP_LIMIT {
                return Err(Error::Capability(offset));
            }
            let range = config32(config, offset + 12)?;
            if range & RANGE_VALID != 0 && (range >> 16) as u8 > (range >> 24) as u8 {
                return Err(Error::Range(offset));
            }
            result.entries[result.count] = Some(Configuration {
                capability_offset: offset,
                header,
                base_low: config32(config, offset + 4)?,
                base_high: config32(config, offset + 8)?,
                range,
                miscellaneous: config32(config, offset + 16)?,
                miscellaneous_1: if header & CAP_EXTENDED != 0 {
                    Some(config32(config, offset + 20)?)
                } else {
                    None
                },
            });
            result.count += 1;
        }
        offset = ((header >> 8) & 0xff) as u16;
    }
    Ok(result)
}

fn capability_bytes<C: ConfigSpace>(config: &C, offset: u16, header: u32) -> Result<u16, Error> {
    let id = header as u8;
    let flags = (header >> 16) as u16;
    match id {
        SECURE_DEVICE => {
            if (header >> 16) & 7 != IOMMU_TYPE || (header >> 19) & 31 != IOMMU_REVISION {
                return Err(Error::UnsupportedLayout(offset));
            }
            Ok(if header & CAP_EXTENDED != 0 { 24 } else { 20 })
        }
        1 if (1..=3).contains(&(flags & 7)) => Ok(8),
        5 => {
            let maximum = (flags >> 1) & 7;
            let enabled = (flags >> 4) & 7;
            if flags & !0x1ff != 0 || maximum > 5 || enabled > maximum {
                return Err(Error::Capability(offset));
            }
            Ok(match (flags & 0x80 != 0, flags & 0x100 != 0) {
                (false, false) => 10,
                (true, false) => 14,
                (false, true) => 20,
                (true, true) => 24,
            })
        }
        9 => {
            let bytes = u16::from(config.read8(offset + 2));
            if bytes < 3 {
                return Err(Error::Capability(offset));
            }
            Ok(bytes)
        }
        0x10 => {
            let version = flags & 15;
            let kind = (flags >> 4) & 15;
            if !matches!(version, 1 | 2) || !matches!(kind, 0 | 1 | 9) || flags & 0x100 != 0 {
                return Err(Error::UnsupportedLayout(offset));
            }
            Ok(match (kind == 9, version) {
                (true, 1) => 12,
                (true, _) => 44,
                (false, 1) => 20,
                (false, _) => 52,
            })
        }
        0x11 => Ok(12),
        1 => Err(Error::UnsupportedLayout(offset)),
        _ => Err(Error::UnsupportedCapability { offset, id }),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    const CAP: u16 = 0x40;
    struct Config {
        words: [u32; 64],
        reads: Mutex<Vec<u16>>,
    }
    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            self.reads.lock().unwrap().push(offset);
            self.words[usize::from(offset / 4)]
        }
        fn write32(&mut self, _: u16, _: u32) {
            panic!("read-only discovery wrote config");
        }
    }
    fn make_config(header: u32) -> Config {
        let mut config = Config {
            words: [0; 64],
            reads: Mutex::new(Vec::new()),
        };
        config.words[1] = u32::from(STATUS_CAPABILITIES) << 16;
        config.words[0x34 / 4] = u32::from(CAP);
        config.words[usize::from(CAP / 4)] = header;
        config
    }
    fn secure_header() -> u32 {
        u32::from(SECURE_DEVICE) | IOMMU_TYPE << 16 | IOMMU_REVISION << 19
    }

    #[test]
    fn capability_extents_and_reserved_optional_register_reads_are_bounded() {
        for extended in [false, true] {
            let config = make_config(secure_header() | if extended { CAP_EXTENDED } else { 0 });
            let result = scan(&config).unwrap();
            assert_eq!(result.count, 1);
            let reads = config.reads.lock().unwrap();
            assert_eq!(reads.contains(&(CAP + 20)), extended);
            assert!(!reads.contains(&(CAP + 24)));
        }
        let mut config = make_config(secure_header() | CAP_EXTENDED);
        config.words[0x34 / 4] = 0xec;
        config.words[0xec / 4] = secure_header() | CAP_EXTENDED;
        assert_eq!(scan(&config).err(), Some(Error::Capability(0xec)));
        assert!(!config.reads.lock().unwrap().contains(&0xf0));
    }

    #[test]
    fn full_chain_rejects_cycles_overlap_misalignment_duplicates_and_unknown_layouts() {
        for (first, second, expected) in [
            (secure_header() | 0x4000, 0, Error::Capability(CAP)),
            (
                secure_header() | 0x4400,
                0x0001_0001,
                Error::Capability(0x44),
            ),
            (secure_header() | 0x6100, 0, Error::Capability(0x61)),
            (
                secure_header() | 0x6000,
                0x0000_0008,
                Error::UnsupportedCapability {
                    offset: 0x60,
                    id: 8,
                },
            ),
            (
                secure_header() | 0x6000,
                0x0000_000f,
                Error::UnsupportedLayout(0x60),
            ),
            (secure_header() | 0x6000, u32::MAX, Error::ReadFailed(0x60)),
        ] {
            let mut config = make_config(first);
            config.words[0x60 / 4] = second;
            if ((first >> 8) & 0xff) == 0x44 {
                config.words[0x44 / 4] = second;
            }
            assert_eq!(scan(&config).err(), Some(expected));
        }
        let mut config = make_config(0x0000_6005);
        config.words[0x60 / 4] = 5;
        assert_eq!(scan(&config).err(), Some(Error::Capability(0x60)));
    }
}
