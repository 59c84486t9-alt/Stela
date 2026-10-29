//! SART (`sart,coastguard`): identity-mapped DMA allow-list entries in the
//! four layouts SPTM knows ([`Layout`]). Linux `drivers/soc/apple/sart.c`,
//! `sart3_{get,set}_entry`, gives v3's sixteen as CONFIG at 4*i, PADDR at
//! 0x40+4*i and SIZE at 0x80+4*i; addresses and lengths are in 4 KiB units.
//! SPTM writes SIZE as the page count less one unless the SART's DT node has
//! `exclusive-bounds` ([`Bounds`]). Only no permission (0) and the
//! read-write pattern SPTM writes have known semantics; other permission
//! bits refuse rather than widening or narrowing access.
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
//!
//! The 26A434 J873GAP (M6) SPTM's `sart_bootstrap_parse_edt` (VA
//! 0xfffffff0270d9f80..0xfffffff0270da2bc) selects an entry layout by
//! `sart-version` from a table of four at 0xfffffff027019b30 and a throttle
//! layout by `sart-throttle-version` (default `sart-version`) from a table
//! of four at 0xfffffff027019a80, whose throttle and status words it offsets
//! by `sart-throttle-offset` (default 0) ([`Layout`]). The J813AP (M5)
//! SPTM has the same tables at 0xfffffff02701a9c8 and 0xfffffff02701a918,
//! and the T8103 (M1) SPTM at 0xfffffff027017b20 and 0xfffffff027017a70
//! (`sart_bootstrap_parse_edt` 0xfffffff0270cbc00..0xfffffff0270cc0dc). With
//! `power-canary-offset` it maps `reg[1]` and, while it holds the SART
//! powered, keeps 0xabfedeed in the word at that offset: it writes it when
//! its reference count leaves 0 (0xfffffff0270d94c0) and panics unless the
//! word still holds it when the count returns to 0 (0xfffffff0270d8c9c), so
//! a lost write shows a power loss. Here the word is plain storage at
//! [`CANARY`]; the SART refuses non-retained power loss.
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};
use {stela_contracts::dma::DmaError, stela_contracts::dma::Iommu, stela_contracts::dma::Memory};

const NAME: &str = "sart";
/// SPTM sart_sanity_check_throttles, VA 0xfffffff0270cb7bc..270cb838,
/// with version-3 layout at 0xfffffff027019ac0: three nonzero boot
/// configuration words, snapshotted before mappings can be installed.
/// Emulated die / boot-chain choice: one synchronous transaction per
/// channel. There is no buffered work to throttle. SPTM also writes 0
/// while it changes entries and then restores the snapshot; the model
/// stores 0 and refuses translated DMA until every word is restored,
/// since what 0 does to traffic is not recovered. Other values refuse.
#[cfg(test)]
use stela_soc_data::sart::THROTTLES;
use stela_soc_data::sart::{Bounds, Layout, MAX_ENTRIES, PAGE};
const SYNCHRONOUS_CHANNEL: u32 = 1;
/// The channel status words beside the throttles, from the same layout.
/// SPTM's entry-change quiesce (0x270ca7a0..0x270ca944) zeroes every
/// throttle, then reads each status once: bits 15:0 set on any channel
/// fail the change, whatever bits 16 and 24 say; otherwise it restores the
/// throttle snapshot. DMA here completes within the access that starts it,
/// so no channel ever has outstanding work and each word reads 0. Bits 16
/// and 24 are not recovered and only matter while a channel is busy.
#[cfg(test)]
use stela_soc_data::sart::STATUS;
/// Bus-local offset used to map the separate, DT-placed idle word.
pub const IDLE: u64 = 0x1000;
/// Bus-local offset used to map the `power-canary-offset` word.
pub const CANARY: u64 = 0x2000;
#[cfg(test)]
const BASE: u64 = 0x40;
#[cfg(test)]
const SIZE: u64 = 0x80;
#[cfg(test)]
const ALLOW: u32 = 0xff;

/// One entry's registers as written.
#[derive(Clone, Copy, Default)]
struct Entry {
    config: u32,
    base: u32,
    size: u32,
}

pub struct Sart {
    lifecycle: LifecycleState,
    layout: Layout,
    entries: [Entry; MAX_ENTRIES],
    bounds: Bounds,
    idle: bool,
    throttles: [u32; 4],
    canary: u32,
}

impl Sart {
    #[cfg(test)]
    pub fn new(bounds: Bounds) -> Self {
        Self::with_layout(bounds, Layout::V3)
    }

    pub fn with_layout(bounds: Bounds, layout: Layout) -> Self {
        Self {
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            },
            layout,
            entries: [Entry::default(); MAX_ENTRIES],
            bounds,
            idle: false,
            throttles: [SYNCHRONOUS_CHANNEL; 4],
            canary: 0,
        }
    }

    /// Both directions use the same allow-list. Every byte must be inside
    /// one enabled entry; arithmetic must not wrap the physical address.
    pub fn allows(&self, first: u64, last: u64) -> bool {
        self.executing()
            && first <= last
            && self.entries[..self.layout.entries()].iter().any(|&entry| {
                let (flags, size) = self.layout.decode(entry.config, entry.size);
                let pages = u64::from(size) + u64::from(self.bounds == Bounds::Inclusive);
                let base = u64::from(entry.base) * PAGE;
                let end = base + pages * PAGE;
                flags == self.layout.permission_mask() && first >= base && last < end
            })
    }

    fn executing(&self) -> bool {
        self.lifecycle.powered
            && self.lifecycle.clocked
            && !self.lifecycle.quiesced
            && !self.lifecycle.reset
    }

    fn accessible(&self) -> Result<(), &'static str> {
        if !self.lifecycle.powered {
            return Err("SART power is gated");
        }
        if !self.lifecycle.clocked {
            return Err("SART clock is gated");
        }
        if self.lifecycle.reset {
            return Err("SART reset is asserted");
        }
        Ok(())
    }

    fn register(&self, offset: u64) -> Option<u32> {
        let (index, field) = self.layout.entry(offset)?;
        let entry = self.entries[index];
        Some([entry.config, entry.base, entry.size][field])
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
        if !self.executing() {
            return Err(DmaError::Unsupported(
                "SART DMA while PMGR inhibits execution",
            ));
        }
        if stream != 0 {
            return Err(DmaError::Unsupported("SART has no stream selector"));
        }
        if self.throttles[..self.layout.throttle_offsets().len()].contains(&0) {
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

impl Lifecycle for Sart {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        // The protected SPTM mapper's allow-list and throttle restoration
        // around a physical ANS rail/reset are distinct from its documented
        // idle protocol. Do not infer their reset values from CC.EN reset.
        if proposed.reset && !self.lifecycle.reset
            || !proposed.powered && self.lifecycle.powered && !proposed.retention
        {
            return Err(
                "SART physical reset or nonretained power loss requires protected mapper restore semantics",
            );
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _access: &mut Access<'_>) {
        self.lifecycle = proposed;
    }
}

impl MmioDevice for Sart {
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        self.accessible()
            .map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))?;
        if width == Width::Word {
            if let Some(channel) = self.layout.throttle(offset) {
                return Ok(u64::from(self.throttles[channel]));
            }
            if self.layout.status_offsets().contains(&offset) {
                return Ok(0);
            }
            if offset == IDLE {
                return Ok(u64::from(self.idle));
            }
            if offset == CANARY {
                return Ok(u64::from(self.canary));
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
        self.accessible()
            .map_err(|reason| refuse(NAME, offset, width, Direction::Write, reason))?;
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word || value > u64::from(u32::MAX) {
            return Err(fail("SART requires a 32-bit word"));
        }
        if let Some(channel) = self.layout.throttle(offset) {
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
        if offset == CANARY {
            self.canary = value as u32;
            return Ok(());
        }
        let Some((index, field)) = self.layout.entry(offset) else {
            return Err(fail("SART register without a model"));
        };
        let value = value as u32;
        let layout = self.layout;
        let entry = &mut self.entries[index];
        match field {
            0 => {
                let (flags, _) = layout.decode(value, entry.size);
                if flags != 0 && flags != layout.permission_mask() {
                    return Err(fail("SART permission bits without known semantics"));
                }
                entry.config = value;
            }
            1 if value & !layout.base_mask() == 0 => entry.base = value,
            1 => return Err(fail("SART address exceeds its field")),
            2 if value & !layout.size_mask() == 0 => entry.size = value,
            2 => return Err(fail("SART size exceeds its field")),
            _ => unreachable!(),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {
        stela_contracts::dma::Port, stela_contracts::dma::test_support::Ram,
        stela_contracts::interrupt::InterruptLatch,
    };

    #[test]
    fn retained_physical_gates_revoke_both_allow_queries_and_actual_translation() {
        let mut sart = Sart::new(Bounds::Exclusive);
        let active = sart.lifecycle;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (offset, value) in [(BASE, 1), (SIZE, 1), (0, u64::from(ALLOW))] {
            sart.write(offset, Width::Word, value, &mut access).unwrap();
        }
        let mut memory = Ram::new(0, 0x3000);
        for gated in [
            LifecycleState {
                clocked: false,
                ..active
            },
            LifecycleState {
                quiesced: true,
                ..active
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..active
            },
        ] {
            sart.check_lifecycle(gated).unwrap();
            sart.set_lifecycle(gated, &mut access);
            assert!(!sart.allows(0x1000, 0x1fff));
            assert!(
                sart.translate(&mut memory, 0, 0x1000, 0x1fff, false, &mut access)
                    .is_err()
            );
            assert!(
                sart.check_lifecycle(LifecycleState {
                    reset: true,
                    ..active
                })
                .is_err()
            );
            sart.set_lifecycle(active, &mut access);
            assert_eq!(
                sart.translate(&mut memory, 0, 0x1000, 0x1fff, true, &mut access),
                Ok(0x1000)
            );
        }
    }

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
        // Status words report no outstanding work and take no writes.
        for offset in STATUS {
            assert_eq!(sart.read(offset, Width::Word, &mut access), Ok(0));
            assert!(sart.write(offset, Width::Word, 0, &mut access).is_err());
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

    #[test]
    fn layouts_follow_the_sptm_tables_and_throttle_offset() {
        assert_eq!(Layout::new(3, 3, 0), Ok(Layout::V3));
        assert_eq!(Layout::V3.register_bytes(), 0x8028);
        // T6050 and T8152: version 4 throughout.
        let v4 = Layout::new(4, 4, 0).unwrap();
        assert_eq!(v4.register_bytes(), 0x8020);
        assert_eq!(v4.entry(0x5c), Some((23, 0)));
        assert_eq!(v4.entry(0x60), Some((0, 1)));
        assert_eq!(v4.entry(0xc0 + 4 * 23), Some((23, 2)));
        assert_eq!(v4.entry(0x120), None);
        // T8142: version 3 entries with the version 4 throttles 0x10 up.
        let m5 = Layout::new(3, 4, 0x10).unwrap();
        assert_eq!(m5.throttle_offsets(), &[0x8018, 0x801c, 0x8024, 0x802c]);
        assert_eq!(m5.status_offsets(), &[0x8010, 0x8014, 0x8020, 0x8028]);
        assert_eq!(m5.register_bytes(), 0x8030);
        assert_eq!(m5.entry(0x40), Some((0, 1)));
        // T8103: version 2 entries, whose SIZE is in CONFIG, and throttles.
        let m1 = Layout::new(2, 2, 0).unwrap();
        assert_eq!(m1.register_bytes(), 0x8028);
        assert_eq!(m1.permission_mask(), 0xff00_0000);
        assert_eq!(m1.entry(0x3c), Some((15, 0)));
        assert_eq!(m1.entry(0x40), Some((0, 1)));
        assert_eq!(m1.entry(0x80), None);
        assert_eq!(Layout::new(1, 1, 0).unwrap().permission_mask(), 0x6fc0_0000);
        assert_eq!(ALLOW, 0xff);
        for (version, throttle, offset) in [(0, 2, 0), (5, 4, 0), (3, 5, 0), (3, 4, 2)] {
            assert!(Layout::new(version, throttle, offset).is_err());
        }
    }

    #[test]
    fn packed_layouts_carry_size_in_config_beside_the_permissions() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let address = 0x8_0000_0000;
        for (version, allow, size_bits) in [(1, 0x6fc0_0000u32, 19), (2, 0xff00_0000, 24)] {
            let mut sart =
                Sart::with_layout(Bounds::Exclusive, Layout::new(version, version, 0).unwrap());
            // SPTM's order: permissions alone, PADDR, then permissions and SIZE.
            let entry = 4 * 15;
            for (offset, value) in [
                (entry, u64::from(allow)),
                (BASE + entry, address / PAGE),
                (entry, u64::from(allow | 2)),
            ] {
                sart.write(offset, Width::Word, value, &mut access).unwrap();
                assert_eq!(sart.read(offset, Width::Word, &mut access), Ok(value));
            }
            assert!(sart.allows(address, address + 2 * PAGE - 1));
            assert!(!sart.allows(address, address + 2 * PAGE));
            // A size field filled to its top bit still decodes as size.
            let full = (1u32 << size_bits) - 1;
            sart.write(entry, Width::Word, u64::from(allow | full), &mut access)
                .unwrap();
            assert!(sart.allows(address, address + u64::from(full) * PAGE - 1));
            // Bits outside SIZE and the read-write pattern, a PADDR wider
            // than its field and the SIZE words of v3 refuse.
            for (offset, value) in [
                (entry, u64::from(1u32 << size_bits)),
                (entry, u64::from(allow & (allow - 1))),
                (BASE + entry, 1 << 24),
                (SIZE, 1),
            ] {
                assert!(sart.write(offset, Width::Word, value, &mut access).is_err());
            }
            sart.write(entry, Width::Word, 2, &mut access).unwrap();
            assert!(!sart.allows(address, address));
            let throttle = sart.layout.throttle_offsets()[0];
            assert_eq!(sart.read(throttle, Width::Word, &mut access), Ok(1));
        }
    }

    #[test]
    fn a_v4_sart_has_24_entries_four_throttles_and_a_canary_word() {
        let mut sart = Sart::with_layout(Bounds::Exclusive, Layout::new(4, 4, 0).unwrap());
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let address = 0x8_0000_0000;
        for (offset, value) in [
            (0x60 + 4 * 23, address / PAGE),
            (0xc0 + 4 * 23, 1),
            (0x5c, 0xff),
        ] {
            sart.write(offset, Width::Word, value, &mut access).unwrap();
        }
        assert!(sart.allows(address, address + PAGE - 1));
        for (throttle, status) in [
            (0x8008, 0x8000),
            (0x800c, 0x8004),
            (0x8014, 0x8010),
            (0x801c, 0x8018),
        ] {
            assert_eq!(sart.read(throttle, Width::Word, &mut access), Ok(1));
            assert_eq!(sart.read(status, Width::Word, &mut access), Ok(0));
        }
        sart.write(0x801c, Width::Word, 0, &mut access).unwrap();
        let mut memory = stela_contracts::dma::test_support::Ram::new(0, 0x1000);
        assert!(
            sart.translate(&mut memory, 0, address, address, false, &mut access)
                .is_err()
        );
        // The v3 entry offsets past 0x60 are other fields or nothing.
        assert!(sart.read(0x8024, Width::Word, &mut access).is_err());
        assert!(sart.read(0x120, Width::Word, &mut access).is_err());
        // SPTM's power canary is plain storage.
        sart.write(CANARY, Width::Word, 0xabfe_deed, &mut access)
            .unwrap();
        assert_eq!(sart.read(CANARY, Width::Word, &mut access), Ok(0xabfe_deed));
    }
}
