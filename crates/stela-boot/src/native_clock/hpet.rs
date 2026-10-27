//! HPET source candidate. This parser grants no mapping or hardware ownership.
use sha2::{Digest, Sha256};
use stela_drivers::{bus::mmio::owned::PhysicalSpan, platform::work::WorkError};

const BLOCK_BYTES: u64 = 1024;
const ID_MASK: u32 = !0x4000;

/// Exact original firmware description, with no numeric constructor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Descriptor {
    registers: PhysicalSpan,
    table_sha256: [u8; 32],
    block_id: u32,
    number: u8,
}
impl Descriptor {
    pub(crate) fn from_sdt(table: &[u8]) -> Result<Self, WorkError> {
        if table.len() != 56
            || &table[..4] != b"HPET"
            || u32::from_le_bytes(table[4..8].try_into().unwrap()) != 56
            || table[8] != 1
            || table.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0
        {
            return Err(WorkError::Unavailable);
        }
        let gas = &table[40..52];
        // Historical HPET GAS has a reserved fourth byte. Width zero is an
        // unspecified GAS width; HPET's own register layout defines accesses.
        if gas[0] != 0
            || !matches!(gas[1], 0 | 64)
            || gas[2] != 0
            || gas[3] != 0
            || table[55] & 15 > 2
        {
            return Err(WorkError::Unavailable);
        }
        let base = u64::from_le_bytes(gas[4..12].try_into().unwrap());
        if base == 0 || !base.is_multiple_of(4096) {
            return Err(WorkError::Unavailable);
        }
        Ok(Self {
            registers: PhysicalSpan::new(base, BLOCK_BYTES).map_err(|_| WorkError::Unavailable)?,
            table_sha256: Sha256::digest(table).into(),
            block_id: u32::from_le_bytes(table[36..40].try_into().unwrap()),
            number: table[52],
        })
    }
    pub(crate) fn registers(self) -> PhysicalSpan {
        self.registers
    }
    pub(crate) fn table_sha256(self) -> [u8; 32] {
        self.table_sha256
    }
    pub(crate) fn block_id(self) -> u32 {
        self.block_id
    }
    pub(crate) fn number(self) -> u8 {
        self.number
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Geometry {
    pub(super) period_fs: u32,
    pub(super) timers: usize,
}
impl Geometry {
    pub(super) fn qualify(
        descriptor: Descriptor,
        id: u32,
        period_fs: u32,
    ) -> Result<Self, WorkError> {
        let timers = ((id >> 8) & 31) as usize + 1;
        if id & ID_MASK != descriptor.block_id & ID_MASK
            || id & 0x2000 == 0 || id & 255 == 0
            || !(100_000..=100_000_000).contains(&period_fs)
            // Refuse an implementation whose last configuration register
            // would extend outside the exact firmware-described 1KiB block.
            || 0x100 + (timers - 1) * 0x20 + 8 > BLOCK_BYTES as usize
        {
            return Err(WorkError::Unavailable);
        }
        Ok(Self { period_fs, timers })
    }
    pub(super) fn ns(self, ticks: u64) -> Result<u64, WorkError> {
        u64::try_from(u128::from(ticks) * u128::from(self.period_fs) / 1_000_000)
            .map_err(|_| WorkError::Exhausted)
    }
}

/// A coherent low word lies between two unchanged high observations.
/// Used only after three ordered actual UC reads; no elapsed time inference.
pub(super) fn coherent_counter(first: u32, low: u32, last: u32) -> Option<u64> {
    (first == last).then_some(u64::from(last) << 32 | u64::from(low))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn table() -> [u8; 56] {
        let mut bytes = [0u8; 56];
        bytes[..4].copy_from_slice(b"HPET");
        bytes[4..8].copy_from_slice(&56u32.to_le_bytes());
        bytes[8] = 1;
        bytes[36..40].copy_from_slice(&0x8086_a201u32.to_le_bytes());
        bytes[41] = 64;
        bytes[44..52].copy_from_slice(&0xfed0_0000u64.to_le_bytes());
        seal(&mut bytes);
        bytes
    }
    fn seal(bytes: &mut [u8]) {
        bytes[9] = 0;
        bytes[9] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)));
    }
    #[test]
    fn exact_firmware_descriptor_and_geometry() {
        let d = Descriptor::from_sdt(&table()).unwrap();
        assert_eq!(d.registers().start(), 0xfed0_0000);
        assert_eq!(d.registers().bytes(), 1024);
        let g = Geometry::qualify(d, 0x8086_a201, 10_000_000).unwrap();
        assert_eq!(g.timers, 3);
        assert_eq!(g.ns(12345).unwrap(), 123450);
        assert!(Geometry::qualify(d, 0x8086_8201, 10_000_000).is_err());
        assert!(Geometry::qualify(d, 0x8086_a201, 0).is_err());
        assert!(g.ns(u64::MAX).is_err());
    }
    #[test]
    fn table_integrity_geometry_and_unsupported_profiles_refuse() {
        let original = table();
        let mut b = original;
        b[10] ^= 1;
        assert!(Descriptor::from_sdt(&b).is_err());
        for (index, value) in [(8, 2), (40, 1), (41, 32), (42, 1), (43, 4), (55, 3)] {
            let mut b = original;
            b[index] = value;
            seal(&mut b);
            assert!(Descriptor::from_sdt(&b).is_err());
        }
        let mut b = original;
        b[41] = 0;
        seal(&mut b);
        assert!(Descriptor::from_sdt(&b).is_ok());
        let mut b = original;
        b[44..52].fill(0);
        seal(&mut b);
        assert!(Descriptor::from_sdt(&b).is_err());
        let mut b = original;
        b[36..40].copy_from_slice(&0x8086_bf01u32.to_le_bytes());
        seal(&mut b);
        assert!(
            Geometry::qualify(Descriptor::from_sdt(&b).unwrap(), 0x8086_bf01, 10_000_000).is_err()
        );
    }
    #[test]
    fn rejects_torn_low_rollover_and_accepts_only_stable_high() {
        assert_eq!(coherent_counter(0, u32::MAX, 1), None);
        assert_eq!(coherent_counter(0, 0, 1), None);
        assert_eq!(coherent_counter(u32::MAX, 0, 0), None);
        assert_eq!(coherent_counter(1, 0, 1), Some(1u64 << 32));
        assert_eq!(coherent_counter(1, u32::MAX, 1), Some((2u64 << 32) - 1));
        assert_eq!(
            coherent_counter(u32::MAX, u32::MAX, u32::MAX),
            Some(u64::MAX)
        );
    }
}
