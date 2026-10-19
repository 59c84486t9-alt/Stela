//! SART v3 (`sart,coastguard`): sixteen identity-mapped DMA allow-list
//! entries. Linux `drivers/soc/apple/sart.c`, `sart3_{get,set}_entry`, gives
//! CONFIG at 4*i, PADDR at 0x40+4*i and SIZE at 0x80+4*i; addresses and
//! lengths are in 4 KiB units. SPTM writes SIZE as the page count less one
//! unless the SART's DT node has `exclusive-bounds` ([`Bounds`]). Only flags
//! 0 (disabled) and 0xff (allow) have known semantics. Other flags refuse
//! rather than widening permissions.
//!
//! On ANS2 the allow-list covers only what the coprocessor reaches at raw
//! addresses carried in commands, the tunnel buffers: the NVMe engine reads
//! queues, TCBs, PRPs and data at physical addresses (`ans`).
//!
//! The J473AP kernel's `IOCoastGuardSARTMapper::start` (file 0x2ccada8)
//! passes `reg[0]` and `sart-version` to SPTM, which programs these entries.
//! Its map/unmap paths (0x2ccb20c/0x2ccb4b0) write 0/1 to `reg[2]` +
//! `sart-power-reg-offset`. This is an idle request, not a DMA bypass.
//! Stela hands off with no allowed regions and no idle request, a boot-chain
//! choice: it has no RTKit firmware buffers to preserve.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use crate::platform::dma::{DmaError, Iommu, Memory};

const NAME: &str = "sart";
pub const ENTRIES: usize = 16;
pub const PAGE: u64 = 4096;
pub const REGISTER_BYTES: u64 = 0x8028;
const ENTRY_BYTES: u64 = 0xc0;
/// SPTM sart_sanity_check_throttles, VA 0xfffffff0270cb7bc..270cb838,
/// with version-3 layout at 0xfffffff027019ac0: three nonzero boot
/// configuration words, snapshotted before mappings can be installed.
/// Emulated die / boot-chain choice: one synchronous transaction per
/// channel. There is no buffered work to throttle. SPTM also writes 0
/// while it changes entries and then restores the snapshot; the model
/// stores 0 and refuses translated DMA until every word is restored,
/// since what 0 does to traffic is not recovered. Other values refuse.
const THROTTLES: [u64; 3] = [0x8014, 0x801c, 0x8024];
const SYNCHRONOUS_CHANNEL: u32 = 1;
/// Bus-local offset used to map the separate, DT-placed idle word.
pub const IDLE: u64 = 0x1000;
const BASE: u64 = 0x40;
const SIZE: u64 = 0x80;
const SIZE_MASK: u32 = (1 << 30) - 1;
const ALLOW: u32 = 0xff;

#[derive(Clone, Copy, Default)]
struct Entry {
    flags: u32,
    base: u32,
    pages: u32,
}

/// How an entry's SIZE counts its pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bounds {
    /// SIZE is the last page's index: SIZE + 1 pages.
    Inclusive,
    /// SIZE is the page count (`exclusive-bounds`).
    Exclusive,
}

pub struct Sart {
    entries: [Entry; ENTRIES],
    bounds: Bounds,
    idle: bool,
    throttles: [u32; 3],
}

impl Sart {
    pub fn new(bounds: Bounds) -> Self {
        Self {
            entries: [Entry::default(); ENTRIES],
            bounds,
            idle: false,
            throttles: [SYNCHRONOUS_CHANNEL; 3],
        }
    }

    /// Both directions use the same allow-list. Every byte must be inside
    /// one enabled entry; arithmetic must not wrap the physical address.
    pub fn allows(&self, first: u64, last: u64) -> bool {
        first <= last
            && self.entries.iter().any(|entry| {
                let pages = u64::from(entry.pages) + u64::from(self.bounds == Bounds::Inclusive);
                let base = u64::from(entry.base) * PAGE;
                let end = base + pages * PAGE;
                entry.flags == ALLOW && first >= base && last < end
            })
    }

    fn register(&self, offset: u64) -> Option<u32> {
        if offset >= ENTRY_BYTES || !offset.is_multiple_of(4) {
            return None;
        }
        let entry = self.entries[(offset % BASE / 4) as usize];
        Some(match offset / BASE {
            0 => entry.flags,
            1 => entry.base,
            2 => entry.pages,
            _ => unreachable!(),
        })
    }
}

impl Iommu for Sart {
    fn page(&self) -> u64 {
        PAGE
    }

    fn translate(
        &mut self,
        _memory: &mut dyn Memory,
        stream: usize,
        iova: u64,
        last: u64,
        _write: bool,
        _access: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        if stream != 0 {
            return Err(DmaError::Unsupported("SART has no stream selector"));
        }
        if self.throttles.contains(&0) {
            return Err(DmaError::Unsupported(
                "SART DMA while a throttle word is 0 is not modeled",
            ));
        }
        if !self.allows(iova, last) {
            // No fault syndrome/interrupt is documented for this hardware.
            return Err(DmaError::Unsupported("DMA outside the SART allow-list"));
        }
        Ok(iova)
    }
}

impl MmioDevice for Sart {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if width == Width::Word {
            if let Some(channel) = THROTTLES.iter().position(|&o| o == offset) {
                return Ok(u64::from(self.throttles[channel]));
            }
            if offset == IDLE {
                return Ok(u64::from(self.idle));
            }
            if let Some(value) = self.register(offset) {
                return Ok(u64::from(value));
            }
        }
        Err(refuse(
            NAME,
            offset,
            width,
            Direction::Read,
            "SART register or width without a model",
        ))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word || value > u64::from(u32::MAX) {
            return Err(fail("SART requires a 32-bit word"));
        }
        if let Some(channel) = THROTTLES.iter().position(|&o| o == offset) {
            // 0 while SPTM changes entries, or a restore of the snapshot.
            if value > u64::from(SYNCHRONOUS_CHANNEL) {
                return Err(fail("SART throttle configuration change is not modeled"));
            }
            self.throttles[channel] = value as u32;
            return Ok(());
        }
        if offset == IDLE {
            if value > 1 {
                return Err(fail("SART idle request is Boolean"));
            }
            self.idle = value == 1;
            return Ok(());
        }
        if self.register(offset).is_none() {
            return Err(fail("SART register without a model"));
        }
        let value = value as u32;
        let entry = &mut self.entries[(offset % BASE / 4) as usize];
        match offset / BASE {
            0 if value == 0 || value == ALLOW => entry.flags = value,
            0 => return Err(fail("SART permission bits without known semantics")),
            1 => entry.base = value,
            2 if value & !SIZE_MASK == 0 => entry.pages = value,
            2 => return Err(fail("SART size exceeds thirty bits")),
            _ => unreachable!(),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::interrupt::InterruptLatch,
        dma::{Port, tests::Ram},
    };

    #[test]
    fn throttle_words_hold_the_boot_value_or_zero_and_never_grant_dma() {
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for offset in THROTTLES {
            assert_eq!(sart.read(offset, Width::Word, &mut access), Ok(1));
            sart.write(offset, Width::Word, 1, &mut access).unwrap();
            assert!(sart.write(offset, Width::Word, 2, &mut access).is_err());
            assert!(sart.read(offset, Width::Double, &mut access).is_err());
        }
        // A word held at 0 stops translated DMA until it is restored.
        for (offset, value) in [(BASE, 1), (SIZE, 1), (0, u64::from(ALLOW))] {
            sart.write(offset, Width::Word, value, &mut access).unwrap();
        }
        let mut memory = Ram::new(0, 0x3000);
        let mut translate = |sart: &mut Sart, access: &mut Access<'_>| {
            sart.translate(&mut memory, 0, 0x1000, 0x1fff, false, access)
        };
        assert_eq!(translate(&mut sart, &mut access), Ok(0x1000));
        sart.write(THROTTLES[1], Width::Word, 0, &mut access)
            .unwrap();
        assert_eq!(sart.read(THROTTLES[1], Width::Word, &mut access), Ok(0));
        assert!(translate(&mut sart, &mut access).is_err());
        sart.write(THROTTLES[1], Width::Word, 1, &mut access)
            .unwrap();
        assert_eq!(translate(&mut sart, &mut access), Ok(0x1000));
        assert!(!Sart::new(Bounds::Exclusive).allows(0x1000, 0x1fff));
    }

    #[test]
    fn entries_filter_both_directions_and_removal_revokes_access() {
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut ram = Ram::new(0x8_0000_0000, 8192);
        let address = ram.base;
        assert!(!sart.allows(address, address));
        for (offset, value) in [(BASE + 60, address / PAGE), (SIZE + 60, 1), (60, 0xff)] {
            sart.write(offset, Width::Word, value, &mut access).unwrap();
            assert_eq!(sart.read(offset, Width::Word, &mut access), Ok(value));
        }
        let mut port = Port {
            iommu: &mut sart,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        port.write(address + 4095, &[0xaa]).unwrap();
        assert!(port.write(address + 4096, &[1]).is_err());
        let mut byte = [0];
        port.read(address + 4095, &mut byte).unwrap();
        assert_eq!(byte, [0xaa]);
        sart.write(60, Width::Word, 0, &mut access).unwrap();
        assert!(!sart.allows(address, address));
        assert!(!sart.allows(u64::MAX, 0));
    }

    #[test]
    fn inclusive_sizes_count_the_last_page() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let address = 0x8_0000_0000;
        for (bounds, size, pages) in [
            (Bounds::Inclusive, 0, 1),
            (Bounds::Inclusive, 1, 2),
            (Bounds::Exclusive, 0, 0),
            (Bounds::Exclusive, 1, 1),
        ] {
            let mut sart = Sart::new(bounds);
            for (offset, value) in [(BASE, address / PAGE), (SIZE, size), (0, 0xff)] {
                sart.write(offset, Width::Word, value, &mut access).unwrap();
            }
            let end = address + pages * PAGE;
            assert_eq!(
                sart.allows(address, address),
                pages > 0,
                "{bounds:?} {size}"
            );
            assert!(pages == 0 || sart.allows(address, end - 1));
            assert!(!sart.allows(end, end));
        }
    }

    #[test]
    fn unknown_permissions_widths_and_holes_refuse_without_effects() {
        let mut sart = Sart::new(Bounds::Exclusive);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (offset, width, value) in [
            (0, Width::Word, 1),
            (SIZE, Width::Word, 1 << 30),
            (BASE, Width::Double, 0),
            (0xc0, Width::Word, 0),
            (1, Width::Word, 0),
            (IDLE, Width::Word, 2),
        ] {
            assert!(sart.write(offset, width, value, &mut access).is_err());
        }
        assert_eq!(sart.read(0, Width::Word, &mut access), Ok(0));
        sart.write(IDLE, Width::Word, 1, &mut access).unwrap();
        assert_eq!(sart.read(IDLE, Width::Word, &mut access), Ok(1));
        assert!(!sart.allows(0, 0));
    }
}
