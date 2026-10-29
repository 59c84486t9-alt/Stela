//! Original gen3 region construction and handoff verification.
//!
//! SPTM d5398..d54c8 validates a 56-byte `tz` property; ceff4..cf10c
//! verifies its native register image. J873g mBoot file155300..155624
//! constructs and verifies the 0x4400 address-region records. These owners
//! preserve the complete recovered software records. They do not implement
//! native region matching, tag normalization, DMA offset effects or faults,
//! and expose no MMIO profile or invented absent-property reset image.

const PAGE: u64 = 0x4000;
const ADDRESS_LIMIT: u64 = 1 << 42;
const REGION_ADDRESS: u32 = 0x3fff_fffc;
const TAG_PROTECTION: u32 = 0x18;
const ADDRESS_PROTECTION: u32 = 2;
pub const TAG_PROPERTY_BYTES: usize = 56;

/// The native TZ dead-index validator's lookup levels. These are not the
/// MAP_TABLE ABI's target levels: its root is included as level zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadIndexLevel {
    Root,
    Context,
    Segment,
    Page,
}

impl DeadIndexLevel {
    const fn projection(self) -> (u64, u32) {
        // mac18g __PRELINK_TEXT741d988/741d9a8, respectively.
        match self {
            Self::Root => (0x3e_0000_0000, 33),
            Self::Context => (0x1_ffc0_0000, 22),
            Self::Segment => (0x3f_f800, 11),
            Self::Page => (0x7ff, 0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagRegion {
    start: u32,
    end: u32,
    offset: u32,
}

impl TagRegion {
    pub const fn words(self) -> [u32; 3] {
        [self.start, self.end, self.offset]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tagger {
    select: u32,
    config: u32,
    regions: [TagRegion; 3],
    opaque: u32,
    dead_page: u64,
    inclusive: bool,
}

/// Register observations supplied by the owning register boundary.
/// No default implementation substitutes zeros for unavailable observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagRegisters {
    pub select: u32,
    pub config: u32,
    pub regions: [[u32; 3]; 3],
    pub protect: u32,
    pub lock: u32,
}

impl Tagger {
    /// Parse the original complete handoff property, keeping its opaque
    /// word and dead-page value. There is no absent-property constructor:
    /// an original restore DT is not an observed post-mBoot register image.
    pub fn parse(property: &[u8], inclusive: bool) -> Result<Self, &'static str> {
        if property.len() != TAG_PROPERTY_BYTES {
            return Err("gen3 DART tz handoff property must contain exactly 56 bytes");
        }
        let words: [u32; 14] = core::array::from_fn(|index| {
            u32::from_le_bytes(property[index * 4..index * 4 + 4].try_into().unwrap())
        });
        let select = words[0];
        let config = words[1];
        if select > 1 || config > 7 {
            return Err("gen3 DART tz selector or region-enable mask exceeds the source contract");
        }
        let regions = core::array::from_fn(|index| TagRegion {
            start: words[2 + index * 3],
            end: words[3 + index * 3],
            offset: words[4 + index * 3],
        });
        for (index, region) in regions.iter().enumerate() {
            if config & (1 << index) == 0 {
                if region.words() != [0; 3] {
                    return Err("gen3 DART disabled tz region has nonzero bounds or offset");
                }
            } else if region.start == 0
                || region.end == 0
                || region.offset != 0
                || region
                    .end
                    .checked_add(u32::from(inclusive))
                    .is_none_or(|end| region.start >= end)
            {
                return Err("gen3 DART enabled tz region has unsupported bounds or nonzero offset");
            }
        }
        Ok(Self {
            select,
            config,
            regions,
            opaque: words[11],
            dead_page: u64::from(words[12]) | u64::from(words[13]) << 32,
            inclusive,
        })
    }

    pub const fn select(self) -> u32 {
        self.select
    }
    pub const fn config(self) -> u32 {
        self.config
    }
    pub const fn regions(self) -> [TagRegion; 3] {
        self.regions
    }
    pub const fn dead_page(self) -> u64 {
        self.dead_page
    }
    pub const fn inclusive(self) -> bool {
        self.inclusive
    }

    /// Execute mac18g `_validateTzDeadPage`'s supplied-index guard
    /// (928c074..928c0c4). It projects each enabled region independently;
    /// it never normalizes a DMA address or validates the physical dead-page
    /// value in the property. In particular the original upper comparison
    /// is inclusive after its separate `inclusive-tz-range` adjustment.
    pub fn validate_dead_index(
        self,
        index: u32,
        level: DeadIndexLevel,
    ) -> Result<(), &'static str> {
        let (mask, shift) = level.projection();
        for (slot, region) in self.regions.iter().enumerate() {
            if self.config & (1 << slot) == 0 {
                continue;
            }
            let start = u64::from(region.start >> 2) & 0x0fff_ffff;
            // The native code shifts first, adds in a 32-bit register and
            // then masks to 28 page bits. Do not clamp or change a wrapped
            // upper endpoint into a saturated range.
            let end = u64::from((region.end >> 2) + u32::from(self.inclusive)) & 0x0fff_ffff;
            if (start & mask) >> shift <= u64::from(index)
                && u64::from(index) <= (end & mask) >> shift
            {
                return Ok(());
            }
        }
        Err("gen3 DART dead-table index is outside its enabled TZ region projections")
    }

    pub fn property(self) -> [u8; TAG_PROPERTY_BYTES] {
        let mut words = [0; 14];
        words[0] = self.select;
        words[1] = self.config;
        for (index, region) in self.regions.iter().enumerate() {
            words[2 + index * 3..5 + index * 3].copy_from_slice(&region.words());
        }
        words[11] = self.opaque;
        words[12] = self.dead_page as u32;
        words[13] = (self.dead_page >> 32) as u32;
        let mut property = [0; TAG_PROPERTY_BYTES];
        for (bytes, word) in property.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        property
    }

    /// The original SPTM powerup predicate, including its explicit capability
    /// and lock-check exception. Success verifies these supplied observations;
    /// it does not check active tagger DMA, kept power or reset effects.
    pub fn verify(
        self,
        parameters4: u32,
        registers: Option<&TagRegisters>,
        locks_required: bool,
    ) -> Result<(), &'static str> {
        if parameters4 & 4 == 0 {
            return if self.dead_page == 0 {
                Ok(())
            } else {
                Err("gen3 DART tz dead page requires native tagger capability")
            };
        }
        let registers = registers.ok_or("gen3 DART tagger register observations are missing")?;
        if registers.protect & TAG_PROTECTION != TAG_PROTECTION
            || (locks_required && registers.lock & TAG_PROTECTION != TAG_PROTECTION)
        {
            return Err("gen3 DART tz configuration is not protected and locked as required");
        }
        if registers.select & 1 != self.select || registers.config & 7 != self.config {
            return Err("gen3 DART tz selector or enabled regions disagree with the handoff");
        }
        for (expected, actual) in self.regions.iter().zip(registers.regions) {
            if expected.words() != actual.map(|word| word & REGION_ADDRESS) {
                return Err("gen3 DART tz region registers disagree with the handoff");
            }
        }
        Ok(())
    }
}

/// The two original constructor paths. Zero names the cleared bounds and
/// control 2 payload; it does not claim the native record matches no address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressRequest {
    Range { input: u64, output: u64, bytes: u64 },
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRegion {
    control: u32,
    start: u32,
    last: u32,
    offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRegisters {
    pub control: u32,
    pub start: u32,
    pub last: u32,
    pub offset: u32,
    pub enable: u32,
    pub lock: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressAction {
    Frozen,
    Verify,
    Rewrite,
}

impl AddressRegion {
    pub fn construct(request: AddressRequest) -> Result<Self, &'static str> {
        let (input, output, bytes, control) = match request {
            AddressRequest::Range {
                input,
                output,
                bytes,
            } => (input, output, bytes, 3),
            AddressRequest::Zero => (0, 0, 0, 2),
        };
        if (input | output | bytes) & (PAGE - 1) != 0 {
            return Err("gen3 DART address-region construction requires 16 KiB alignment");
        }
        // The original final-page calculation uses 32-bit (size - 1).
        // Exactly 4 GiB fits that count; larger sizes would truncate.
        if bytes > 1 << 32 {
            return Err("gen3 DART address-region size exceeds the recovered constructor width");
        }
        // These explicit validation bounds prevent unmodeled truncation;
        // the original local constructor itself checks only alignment.
        for base in [input, output] {
            if base >= ADDRESS_LIMIT
                || base
                    .checked_add(bytes)
                    .is_none_or(|end| end > ADDRESS_LIMIT)
            {
                return Err(
                    "gen3 DART address-region construction exceeds its recovered address width",
                );
            }
        }
        let start = (input >> 12) as u32;
        let last = if bytes == 0 {
            0
        } else {
            ((input + bytes - PAGE) >> 12) as u32
        };
        let offset = ((output >> 12) as u32).wrapping_sub(start);
        Ok(Self {
            control,
            start,
            last,
            offset,
        })
    }

    /// The control/start/final-page/offset payload fields. Publication first
    /// clears control/enable, stores bounds/offset, then control and enable.
    /// The offset write keeps its upper bits; original readback compares
    /// the native 30-bit masked field, including a negative encoded difference.
    pub const fn words(self) -> [u32; 4] {
        [self.control, self.start, self.last, self.offset]
    }

    pub fn register_offset(index: usize, parameters_c: u32) -> Result<u64, &'static str> {
        if index >= (parameters_c >> 28) as usize {
            return Err("gen3 DART address-region index exceeds its native record count");
        }
        Ok(0x4400 + index as u64 * 0x40)
    }

    fn bounds_match(self, actual: &AddressRegisters) -> bool {
        actual.start == self.start
            && actual.last & REGION_ADDRESS == self.last
            && actual.offset == self.offset & REGION_ADDRESS
    }

    fn matches(self, actual: &AddressRegisters) -> bool {
        actual.control == self.control && self.bounds_match(actual)
    }

    /// Select the original constructor's path before any register effect.
    /// A frozen record's bounds/offset must agree; that original path does
    /// not inspect control or enable. An unlocked record requires both global
    /// domain 1 controls clear. This is not a hardware write emulator.
    pub fn prepare(
        self,
        actual: &AddressRegisters,
        protect: u32,
        domain_lock: u32,
    ) -> Result<AddressAction, &'static str> {
        if actual.lock & 1 != 0 {
            return if self.bounds_match(actual) {
                Ok(AddressAction::Frozen)
            } else {
                Err("gen3 DART frozen address-region record disagrees with its construction")
            };
        }
        if (protect | domain_lock) & ADDRESS_PROTECTION != 0 {
            return Err("gen3 DART address-region construction requires unprotected domain 1");
        }
        Ok(if self.matches(actual) {
            AddressAction::Verify
        } else {
            AddressAction::Rewrite
        })
    }

    /// Verify fresh observations after programming and an optional lock.
    /// Barriers, writes and observations belong to the owning boundary.
    pub fn verify(
        self,
        actual: &AddressRegisters,
        lock_requested: bool,
    ) -> Result<(), &'static str> {
        if actual.enable & 1 == 0
            || (lock_requested && actual.lock & 1 == 0)
            || !self.matches(actual)
        {
            return Err("gen3 DART address-region publication has not reached its expected state");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn property(
        select: u32,
        config: u32,
        regions: [[u32; 3]; 3],
        dead_page: u64,
    ) -> [u8; TAG_PROPERTY_BYTES] {
        let mut bytes = [0; TAG_PROPERTY_BYTES];
        let words = [
            select,
            config,
            regions[0][0],
            regions[0][1],
            regions[0][2],
            regions[1][0],
            regions[1][1],
            regions[1][2],
            regions[2][0],
            regions[2][1],
            regions[2][2],
            0x1234_5678,
            dead_page as u32,
            (dead_page >> 32) as u32,
        ];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn native_dead_index_guard_projects_each_enabled_zone_at_every_lookup_level() {
        let bytes = property(1, 4, [[0; 3], [0; 3], [0x1040_8040, 0x1040_807c, 0]], 0);
        let original = Tagger::parse(&bytes, false).unwrap();
        let inclusive = Tagger::parse(&bytes, true).unwrap();
        for (level, first, last) in [
            (DeadIndexLevel::Root, 0, 0),
            (DeadIndexLevel::Context, 16, 16),
            (DeadIndexLevel::Segment, 0x204, 0x204),
            (DeadIndexLevel::Page, 0x10, 0x1f),
        ] {
            original.validate_dead_index(first, level).unwrap();
            original.validate_dead_index(last, level).unwrap();
            assert!(original.validate_dead_index(last + 1, level).is_err());
            if first != 0 {
                assert!(original.validate_dead_index(first - 1, level).is_err());
            }
            assert!(original.validate_dead_index(u32::MAX, level).is_err());
        }
        inclusive
            .validate_dead_index(0x20, DeadIndexLevel::Page)
            .unwrap();
        assert!(
            inclusive
                .validate_dead_index(0x21, DeadIndexLevel::Page)
                .is_err()
        );
        assert_eq!(original.property(), bytes);

        // No enabled regions means no reserved dead index, including zero.
        // Selector choice does not change this software predicate.
        for select in [0, 1] {
            let absent = Tagger::parse(&property(select, 0, [[0; 3]; 3], 0), false).unwrap();
            for level in [
                DeadIndexLevel::Root,
                DeadIndexLevel::Context,
                DeadIndexLevel::Segment,
                DeadIndexLevel::Page,
            ] {
                assert!(absent.validate_dead_index(0, level).is_err());
            }
        }
    }

    #[test]
    fn native_dead_index_end_adjustment_wraps_before_projection_without_range_repair() {
        let bytes = property(
            0,
            1,
            [[0xffff_ff00, 0xffff_fffc, 0], [0; 3], [0; 3]],
            u64::MAX,
        );
        let exclusive = Tagger::parse(&bytes, false).unwrap();
        let inclusive = Tagger::parse(&bytes, true).unwrap();
        for (level, last) in [
            (DeadIndexLevel::Context, 63),
            (DeadIndexLevel::Segment, 2047),
            (DeadIndexLevel::Page, 2047),
        ] {
            exclusive.validate_dead_index(last, level).unwrap();
            assert!(inclusive.validate_dead_index(last, level).is_err());
            assert!(inclusive.validate_dead_index(0, level).is_err());
        }
        // Root projection is zero at both endpoints even after wrapping.
        inclusive
            .validate_dead_index(0, DeadIndexLevel::Root)
            .unwrap();
        // A successful supplied-index guard does not validate this address.
        assert_eq!(inclusive.dead_page(), u64::MAX);

        let bytes = property(0, 1, [[0x1ffc, 0x2000, 0], [0; 3], [0; 3]], 0);
        let tagger = Tagger::parse(&bytes, false).unwrap();
        // Projection across an 11-bit index wrap does not become a union.
        assert!(
            tagger
                .validate_dead_index(2047, DeadIndexLevel::Page)
                .is_err()
        );
        assert!(tagger.validate_dead_index(0, DeadIndexLevel::Page).is_err());
        tagger
            .validate_dead_index(0, DeadIndexLevel::Segment)
            .unwrap();
        tagger
            .validate_dead_index(1, DeadIndexLevel::Segment)
            .unwrap();
    }

    #[test]
    fn complete_tz_handoff_preserves_opaque_bytes_and_verifies_actual_register_observations() {
        let regions = [[0x1000, 0x2000, 0], [0x8000, 0xc000, 0], [0; 3]];
        let bytes = property(1, 3, regions, 0x8_0000_4000);
        let tagger = Tagger::parse(&bytes, false).unwrap();
        assert_eq!(tagger.select(), 1);
        assert_eq!(tagger.config(), 3);
        assert_eq!(tagger.regions().map(TagRegion::words), regions);
        assert_eq!(tagger.dead_page(), 0x8_0000_4000);
        assert!(!tagger.inclusive());
        assert_eq!(tagger.property(), bytes);
        let mut actual = TagRegisters {
            select: 1,
            config: 3,
            regions,
            protect: 0x18,
            lock: 0x18,
        };
        tagger.verify(4, Some(&actual), true).unwrap();
        for index in 0..3 {
            for field in 0..3 {
                let mut changed = actual;
                changed.regions[index][field] ^= 4;
                assert!(tagger.verify(4, Some(&changed), true).is_err());
            }
        }
        let mut ignored_bits = actual;
        ignored_bits.select |= 0xffff_fffe;
        ignored_bits.config |= 0xffff_fff8;
        ignored_bits.regions = regions.map(|region| region.map(|word| word | !REGION_ADDRESS));
        tagger.verify(4, Some(&ignored_bits), true).unwrap();
        assert!(tagger.verify(4, None, true).is_err());
        assert!(tagger.verify(0, None, true).is_err());
        actual.lock = 0;
        assert!(tagger.verify(4, Some(&actual), true).is_err());
        tagger.verify(4, Some(&actual), false).unwrap();
        actual.protect = 8;
        assert!(tagger.verify(4, Some(&actual), false).is_err());
        actual.protect = 0x18;
        actual.regions[1][1] += 4;
        assert!(tagger.verify(4, Some(&actual), false).is_err());
        actual.regions = regions;
        actual.select = 0;
        assert!(tagger.verify(4, Some(&actual), false).is_err());
        actual.select = 1;
        actual.config = 7;
        assert!(tagger.verify(4, Some(&actual), false).is_err());
        // This is the source verifier's no-tagger branch, not permission
        // to expose invented zero registers or perform active region DMA.
        Tagger::parse(&property(1, 3, regions, 0), false)
            .unwrap()
            .verify(0, None, true)
            .unwrap();
    }

    #[test]
    fn tz_validation_checks_every_enabled_and_disabled_region_without_inventing_an_absent_image() {
        for length in [0, 52, 55, 57, 60] {
            assert!(Tagger::parse(&[0; 60][..length], false).is_err());
        }
        assert!(Tagger::parse(&property(2, 0, [[0; 3]; 3], 0), false).is_err());
        assert!(Tagger::parse(&property(0, 8, [[0; 3]; 3], 0), false).is_err());
        for index in 0..3 {
            for field in 0..3 {
                let mut regions = [[0; 3]; 3];
                regions[index][field] = 4;
                assert!(Tagger::parse(&property(0, 0, regions, 0), false).is_err());
            }
            for region in [
                [0, 8, 0],
                [4, 0, 0],
                [4, 8, 4],
                [8, 4, 0],
                [4, 4, 0],
                [4, u32::MAX, 0],
            ] {
                let mut regions = [[0; 3]; 3];
                regions[index] = region;
                let inclusive = region[1] == u32::MAX;
                assert!(Tagger::parse(&property(0, 1 << index, regions, 0), inclusive).is_err());
            }
            let mut regions = [[0; 3]; 3];
            regions[index] = [4, 4, 0];
            assert!(Tagger::parse(&property(0, 1 << index, regions, 0), false).is_err());
            assert!(Tagger::parse(&property(0, 1 << index, regions, 0), true).is_ok());
        }
        // Software bounds validation does not silently normalize bits which
        // the native masked readback cannot reproduce.
        let regions = [[0x4000_0000, 0x4000_0004, 0], [0; 3], [0; 3]];
        let tagger = Tagger::parse(&property(0, 1, regions, 0), false).unwrap();
        let actual = TagRegisters {
            select: 0,
            config: 1,
            regions,
            protect: 0x18,
            lock: 0x18,
        };
        assert!(tagger.verify(4, Some(&actual), true).is_err());
    }

    fn observations(region: AddressRegion) -> AddressRegisters {
        let [control, start, last, offset] = region.words();
        AddressRegisters {
            control,
            start,
            last,
            offset: offset & REGION_ADDRESS,
            enable: 1,
            lock: 0,
        }
    }

    #[test]
    fn address_region_construction_retains_signed_offsets_and_final_page_inclusion() {
        let region = AddressRegion::construct(AddressRequest::Range {
            input: 1 << 40,
            output: 0x8_0000_0000,
            bytes: 2 * PAGE,
        })
        .unwrap();
        assert_eq!(region.words(), [3, 0x1000_0000, 0x1000_0004, 0xf080_0000]);
        let actual = observations(region);
        assert_eq!(actual.offset, 0x3080_0000);
        assert_eq!(region.prepare(&actual, 0, 0), Ok(AddressAction::Verify));
        region.verify(&actual, false).unwrap();
        let last = AddressRegion::construct(AddressRequest::Range {
            input: ADDRESS_LIMIT - PAGE,
            output: ADDRESS_LIMIT - PAGE,
            bytes: PAGE,
        })
        .unwrap();
        assert_eq!(last.words(), [3, REGION_ADDRESS, REGION_ADDRESS, 0]);
        for bad in [1, 2, PAGE - 1, ADDRESS_LIMIT + PAGE, u64::MAX] {
            for request in [
                AddressRequest::Range {
                    input: bad,
                    output: 0,
                    bytes: PAGE,
                },
                AddressRequest::Range {
                    input: 0,
                    output: bad,
                    bytes: PAGE,
                },
                AddressRequest::Range {
                    input: 0,
                    output: 0,
                    bytes: bad,
                },
            ] {
                assert!(AddressRegion::construct(request).is_err());
            }
        }
        assert!(
            AddressRegion::construct(AddressRequest::Range {
                input: ADDRESS_LIMIT - PAGE,
                output: 0,
                bytes: 2 * PAGE,
            })
            .is_err()
        );
        assert!(
            AddressRegion::construct(AddressRequest::Range {
                input: 0,
                output: ADDRESS_LIMIT - PAGE,
                bytes: 2 * PAGE,
            })
            .is_err()
        );
        assert_eq!(
            AddressRegion::construct(AddressRequest::Zero)
                .unwrap()
                .words(),
            [2, 0, 0, 0]
        );
        assert_eq!(
            AddressRegion::construct(AddressRequest::Range {
                input: 0,
                output: 0,
                bytes: 0
            })
            .unwrap()
            .words(),
            [3, 0, 0, 0]
        );
        assert!(
            AddressRegion::construct(AddressRequest::Range {
                input: 0,
                output: 0,
                bytes: (1 << 32) + PAGE,
            })
            .is_err()
        );
        assert_eq!(
            AddressRegion::construct(AddressRequest::Range {
                input: 0,
                output: 0,
                bytes: 1 << 32,
            })
            .unwrap()
            .words(),
            [3, 0, 0x000f_fffc, 0]
        );
        assert!(AddressRegion::register_offset(0, 0).is_err());
        assert_eq!(AddressRegion::register_offset(14, 15 << 28), Ok(0x4780));
        assert!(AddressRegion::register_offset(15, 15 << 28).is_err());
    }

    #[test]
    fn address_region_inspection_never_rewrites_a_frozen_record_or_invents_publication() {
        let region = AddressRegion::construct(AddressRequest::Range {
            input: 0x4000,
            output: 0x8000,
            bytes: PAGE,
        })
        .unwrap();
        let mut actual = observations(region);
        for (protect, lock) in [(2, 0), (0, 2), (2, 2)] {
            assert!(region.prepare(&actual, protect, lock).is_err());
        }
        actual.control = 0;
        assert_eq!(region.prepare(&actual, 0, 0), Ok(AddressAction::Rewrite));
        assert!(region.verify(&actual, false).is_err());
        actual = observations(region);
        actual.enable = 0;
        assert_eq!(region.prepare(&actual, 0, 0), Ok(AddressAction::Verify));
        assert!(region.verify(&actual, false).is_err());
        actual.enable = 1;
        assert!(region.verify(&actual, true).is_err());
        actual.lock = 1;
        region.verify(&actual, true).unwrap();
        assert_eq!(region.prepare(&actual, 2, 2), Ok(AddressAction::Frozen));
        let saved = actual;
        actual.control = 0;
        actual.enable = 0;
        assert_eq!(region.prepare(&actual, 2, 2), Ok(AddressAction::Frozen));
        assert!(region.verify(&actual, true).is_err());
        actual = saved;
        actual.offset ^= 4;
        assert!(region.prepare(&actual, 0, 0).is_err());
        actual = saved;
        actual.start ^= 4;
        assert!(region.verify(&actual, true).is_err());
        actual = saved;
        actual.last ^= 4;
        assert!(region.verify(&actual, true).is_err());
        assert_eq!(
            saved,
            AddressRegisters {
                control: 3,
                start: 4,
                last: 4,
                offset: 4,
                enable: 1,
                lock: 1
            }
        );
    }
}
