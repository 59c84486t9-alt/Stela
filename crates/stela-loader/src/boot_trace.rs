//! Boot-stage telemetry in iBoot's recovered BTRD format.
//!
//! J473 26A434 iBoot initializes the 16-byte header at file `0xf8244`,
//! appends 24-byte records at `0xf830c`, and migrates its 16 KiB buffer to
//! carveout 55 at `0xf83a4`. A record holds a counter, native callsite,
//! four-character tag and argument. The header's last word is the counter
//! frequency. See `docs/research/installer-warnings.md#boot-stage-trace`.
use crate::{apple_device_tree::DeviceTree, carveouts::MEMORY_MAP};
use alloc::{vec, vec::Vec};
use anyhow::{Result, ensure};

pub const REGION_ID: u16 = 55;
pub const BUFFER_BYTES: usize = 16 << 10;
pub const HEADER_BYTES: usize = 16;
pub const RECORD_BYTES: usize = 24;
pub const MAX_RECORDS: usize = (BUFFER_BYTES - HEADER_BYTES) / RECORD_BYTES;
pub const MAGIC: u32 = u32::from_be_bytes(*b"BTRD");

/// The original trace region. Its full allocation remains reserved even
/// when only part contains records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub bytes: u64,
}

impl Region {
    /// Locate the original decimal-named carveout. Absence means that the
    /// board's trace storage has not been established; malformed storage
    /// refuses rather than writing to a guessed address.
    pub fn from_tree(tree: &DeviceTree) -> Result<Option<Self>> {
        let Some(data) = tree.property(MEMORY_MAP, "region-id-55") else {
            return Ok(None);
        };
        ensure!(
            data.value.len() == 16,
            "boot trace region needs an address/length pair"
        );
        let base = u64::from_le_bytes(data.value[..8].try_into()?);
        let bytes = u64::from_le_bytes(data.value[8..].try_into()?);
        ensure!(
            base != 0 && base.is_multiple_of(8),
            "boot trace region has an invalid base"
        );
        ensure!(
            bytes >= BUFFER_BYTES as u64,
            "boot trace region is smaller than 16 KiB"
        );
        ensure!(base.checked_add(bytes).is_some(), "boot trace region wraps");
        Ok(Some(Self { base, bytes }))
    }

    /// Trace storage must be backed, reserved memory below the managed
    /// range, without overlapping any loaded region's address/length pair.
    pub fn validate(
        self,
        dram_base: u64,
        managed_base: u64,
        occupied: impl IntoIterator<Item = (u64, u64)>,
    ) -> Result<()> {
        ensure!(
            self.base != 0 && self.base.is_multiple_of(8) && self.bytes >= BUFFER_BYTES as u64,
            "boot trace region has an invalid base or length"
        );
        ensure!(
            self.base >= dram_base
                && self
                    .base
                    .checked_add(self.bytes)
                    .is_some_and(|end| end <= managed_base),
            "boot trace region is outside reserved guest DRAM"
        );
        let trace_end = self.base + self.bytes;
        for (base, bytes) in occupied {
            let end = base
                .checked_add(bytes)
                .ok_or_else(|| anyhow::anyhow!("loaded region wraps"))?;
            ensure!(
                bytes == 0 || base >= trace_end || end <= self.base,
                "boot trace aliases a loaded region"
            );
        }
        Ok(())
    }
}

/// A bounded, newly observed stage's trace. This does not synthesize prior
/// firmware stages or reinterpret an older-format trace.
pub struct Trace {
    bytes: Vec<u8>,
    count: usize,
    last: Option<u64>,
}

impl Trace {
    pub fn new(frequency_hz: u32) -> Result<Self> {
        ensure!(frequency_hz != 0, "boot trace counter frequency is zero");
        let mut bytes = vec![0; BUFFER_BYTES];
        bytes[..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[8..12].copy_from_slice(&8u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&frequency_hz.to_le_bytes());
        Ok(Self {
            bytes,
            count: 0,
            last: None,
        })
    }

    /// Append an observation. `pc` names the producer's native code,
    /// not an invented guest ARM callsite; `tag` identifies that producer's
    /// event. Counts share the architectural counter's origin and frequency.
    /// Capacity exhaustion and a regressing clock leave the trace unchanged.
    pub fn record(&mut self, counter: u64, pc: u64, tag: [u8; 4], argument: u32) -> Result<()> {
        ensure!(self.count < MAX_RECORDS, "boot trace is full");
        ensure!(
            self.last.is_none_or(|last| counter >= last),
            "boot trace counter regressed"
        );
        let offset = HEADER_BYTES + self.count * RECORD_BYTES;
        self.bytes[offset..offset + 8].copy_from_slice(&counter.to_le_bytes());
        self.bytes[offset + 8..offset + 16].copy_from_slice(&pc.to_le_bytes());
        self.bytes[offset + 16..offset + 20]
            .copy_from_slice(&u32::from_be_bytes(tag).to_le_bytes());
        self.bytes[offset + 20..offset + 24].copy_from_slice(&argument.to_le_bytes());
        self.count += 1;
        self.bytes[4..8].copy_from_slice(&(self.count as u32).to_le_bytes());
        self.last = Some(counter);
        Ok(())
    }

    /// The full original allocation, with unused records zeroed.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }
    fn double(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }
    fn tree(base: u64, bytes: u64) -> DeviceTree {
        let mut tree = DeviceTree {
            root: crate::apple_device_tree::Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "chosen").unwrap();
        tree.ensure_child("/chosen", "carveout-memory-map").unwrap();
        tree.set_property(
            MEMORY_MAP,
            "region-id-55",
            [base.to_le_bytes(), bytes.to_le_bytes()].concat(),
        )
        .unwrap();
        tree
    }

    #[test]
    fn records_preserve_actual_clock_code_tag_and_argument() {
        let mut trace = Trace::new(24_000_000).unwrap();
        trace
            .record(1_234_567, 0xfeed_1234_5678, *b"SVFY", 17)
            .unwrap();
        trace
            .record(25_234_567, 0xfeed_8765_4321, *b"EVFY", 18)
            .unwrap();
        let data = trace.bytes();
        assert_eq!(data.len(), 16_384);
        assert_eq!(
            (word(data, 0), word(data, 4), word(data, 8), word(data, 12)),
            (0x4254_5244, 2, 8, 24_000_000)
        );
        assert_ne!(word(data, 0), u32::from_be_bytes(*b"BTRC"));
        assert_eq!(
            (
                double(data, 16),
                double(data, 24),
                word(data, 32),
                word(data, 36)
            ),
            (1_234_567, 0xfeed_1234_5678, 0x5356_4659, 17)
        );
        assert_eq!(
            (
                double(data, 40),
                double(data, 48),
                word(data, 56),
                word(data, 60)
            ),
            (25_234_567, 0xfeed_8765_4321, 0x4556_4659, 18)
        );
        assert!(data[64..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn capacity_and_clock_errors_do_not_change_existing_observations() {
        assert!(Trace::new(0).is_err());
        let mut trace = Trace::new(24_000_000).unwrap();
        trace.record(8, 9, *b"TEST", 10).unwrap();
        let prior = trace.bytes().to_vec();
        assert!(trace.record(7, 11, *b"TEST", 12).is_err());
        assert_eq!(trace.bytes(), prior);
        for _ in 1..MAX_RECORDS {
            trace.record(8, 9, *b"TEST", 10).unwrap();
        }
        assert_eq!(MAX_RECORDS, 682);
        let prior = trace.bytes().to_vec();
        assert!(trace.record(9, 11, *b"FULL", 12).is_err());
        assert_eq!(trace.bytes(), prior);
        assert_eq!(word(trace.bytes(), 4), 682);
    }

    #[test]
    fn region_requires_an_exact_nonwrapping_reserved_range() {
        assert_eq!(
            Region::from_tree(&DeviceTree {
                root: crate::apple_device_tree::Node::named("device-tree").unwrap()
            })
            .unwrap(),
            None
        );
        let region = Region::from_tree(&tree(0x8000_0000, 16_384))
            .unwrap()
            .unwrap();
        region.validate(0x8000_0000, 0x8020_0000, []).unwrap();
        assert!(region.validate(0x8000_0008, 0x8020_0000, []).is_err());
        assert!(region.validate(0x8000_0000, 0x8000_2000, []).is_err());
        region
            .validate(0x8000_0000, 0x8020_0000, [(0x8000_4000, 0x1000)])
            .unwrap();
        for occupied in [
            (0x8000_0000, 1),
            (0x7fff_ffff, 2),
            (0x8000_3fff, 2),
            (u64::MAX, 1),
        ] {
            assert!(
                region
                    .validate(0x8000_0000, 0x8020_0000, [occupied])
                    .is_err()
            );
        }
        for (base, bytes) in [
            (0, 16_384),
            (1, 16_384),
            (0x8000_0000, 16_383),
            (u64::MAX - 7, 16_384),
        ] {
            assert!(Region::from_tree(&tree(base, bytes)).is_err());
        }
        let mut invalid = tree(0x8000_0000, 16_384);
        invalid
            .set_property(MEMORY_MAP, "region-id-55", vec![0; 15])
            .unwrap();
        assert!(Region::from_tree(&invalid).is_err());
    }
}
