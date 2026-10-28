//! Unchanged-source wire/control comparison; actual DMA effects have separate peers.
use super::*;
use crate::bus::dma::RegionAllocator;
use alloc::vec;

struct Controls {
    byte: u8,
    word: u16,
    ignore: bool,
    writes: usize,
    low: u32,
    high: u32,
}
impl Registers for Controls {
    fn read8(&mut self, at: usize) -> u8 {
        assert_eq!(at, HOST_CONTROL);
        self.byte
    }
    fn read16(&mut self, at: usize) -> u16 {
        assert_eq!(at, HOST_CONTROL2);
        self.word
    }
    fn read32(&mut self, at: usize) -> u32 {
        match at {
            ADMA_ADDRESS => self.low,
            ADMA_ADDRESS_HIGH => self.high,
            _ => panic!("only modeled DMA address registers"),
        }
    }
    fn write8(&mut self, at: usize, value: u8) {
        assert_eq!(at, HOST_CONTROL);
        self.byte = value;
    }
    fn write16(&mut self, at: usize, value: u16) {
        assert_eq!(at, HOST_CONTROL2);
        self.writes += 1;
        if !self.ignore {
            self.word = value;
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        match at {
            ADMA_ADDRESS => self.low = value,
            ADMA_ADDRESS_HIGH => self.high = value,
            _ => panic!("no command/doorbell in wire oracle"),
        }
    }
}

#[test]
#[ignore = "oracle: STELA_SDHCI_ADMA_ORACLE"]
fn unchanged_linux_v4_capability_controls_and_adma_descriptors_match_native() {
    extern crate std;
    let records = std::fs::read_to_string(
        std::env::var_os("STELA_SDHCI_ADMA_ORACLE").expect("set STELA_SDHCI_ADMA_ORACLE"),
    )
    .unwrap();
    let mut count = 0;
    for line in records.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 12);
        assert_eq!(fields[0], "D");
        let number = |at: usize| fields[at].parse::<u64>().unwrap();
        let capability = if number(2) & 1 != 0 { CAP_64 } else { 0 }
            | if number(2) & 2 != 0 { 1 << 27 } else { 0 };
        let wide = wide_capability(number(1) as u8, capability);
        assert_eq!(u64::from(wide), number(5), "{line}");
        let mut registers = Controls {
            byte: 0x3f,
            word: 0x1088,
            ignore: false,
            writes: 0,
            low: 0,
            high: 0xfeed_1234,
        };
        let control = configure(&mut registers, wide).unwrap();
        registers.write8(HOST_CONTROL, control);
        assert_eq!(u64::from(registers.byte), number(6), "{line}");
        assert_eq!(u64::from(registers.word), number(7), "{line}");
        let mut backing = vec![0u64; 64];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: isolated descriptor RAM remains live; no pointer/doorbell is
        // submitted to a device by this bounded wire-format source comparison.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let mut table = dma.allocate(64, 8).unwrap();
        let address = if number(4) == 0 {
            0x1234_5000
        } else {
            0x0123_4567_8000
        };
        command::adma_address(&mut registers, address, wide);
        assert_eq!(u64::from(registers.low), number(9), "{line}");
        assert_eq!(u64::from(registers.high), number(10), "{line}");
        descriptor(&mut table, address, number(3) as usize, wide);
        let bytes: Vec<_> = (0..fields[11].len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&fields[11][at..at + 2], 16).unwrap())
            .collect();
        assert_eq!(bytes.len(), number(8) as usize);
        assert_eq!(&table.bytes()[..bytes.len()], &bytes, "{line}");
        count += 1;
    }
    assert_eq!(count, 64);
}

#[test]
fn missing_v4_mode_and_unacknowledged_64bit_width_never_authorize_dma_control() {
    for word in [0u16, u16::MAX] {
        let mut registers = Controls {
            byte: 0x3f,
            word,
            ignore: false,
            writes: 0,
            low: 0,
            high: 0,
        };
        assert!(configure(&mut registers, true).is_err());
        assert_eq!(registers.writes, 0);
    }
    let mut registers = Controls {
        byte: 0x3f,
        word: 0x1088,
        ignore: true,
        writes: 0,
        low: 0,
        high: 0,
    };
    assert!(configure(&mut registers, true).is_err());
    assert_eq!(registers.word, 0x1088);
    assert_eq!(registers.writes, 1);
}
