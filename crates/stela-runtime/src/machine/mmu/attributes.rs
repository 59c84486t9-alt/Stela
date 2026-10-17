//! Memory attributes of a translation (Arm ARM D8.6): the MAIR byte a
//! descriptor selects and its shareability, and the defaults with stage 1
//! disabled. Attributes travel as their PAR_EL1.ATTR byte, which on a chip
//! with FEAT_XS also carries the XS attribute (pseudocode EncodePARAttrs):
//! bit 0 of a Device byte, and `0x40` and `0xa0` for Non-cacheable and
//! Write-Through memory with XS 0. Every combination decodes the byte to its
//! form without XS first.

use super::MemoryType;

/// Device-nGnRnE: data accesses with the MMU off.
pub const DEVICE_NGNRNE: u8 = 0x00;
/// Normal Inner/Outer Write-Through, Read-Allocate: instruction fetch with the
/// MMU off and SCTLR.I set.
pub const NORMAL_WRITE_THROUGH: u8 = 0xaa;
/// Normal Inner/Outer Non-cacheable: instruction fetch with SCTLR.I clear.
pub const NORMAL_NON_CACHEABLE: u8 = 0x44;
/// SH encodings.
pub const NON_SHAREABLE: u8 = 0b00;
pub const OUTER_SHAREABLE: u8 = 0b10;
pub const INNER_SHAREABLE: u8 = 0b11;
/// Normal Inner/Outer Write-Back, Read/Write-Allocate, non-transient: the
/// EL1&0 default with stage 1 disabled and HCR_EL2.DC set.
pub const NORMAL_WRITE_BACK: u8 = 0xff;

const SCTLR_C: u64 = 1 << 2;
const SCTLR_I: u64 = 1 << 12;
const ATTRIBUTE_INDEX_SHIFT: u64 = 2;
const SHAREABILITY_SHIFT: u64 = 8;

/// Normal Inner/Outer Non-cacheable and Write-Through Read-Allocate with XS
/// 0 (FEAT_XS).
const NON_CACHEABLE_NOT_XS: u8 = 0x40;
const WRITE_THROUGH_NOT_XS: u8 = 0xa0;
const DEVICE_NOT_XS: u8 = 0b01;

/// The attribute byte, memory type and shareability of a descriptor. `xs`:
/// the chip implements FEAT_XS. Without it the XS encodings of MAIR are
/// reserved, and this implementation gives each the meaning of the encoding
/// without XS (Unpredictable_RESMAIR maps a reserved value to an allocated
/// one).
pub fn of_descriptor(mair: u64, descriptor: u64, xs: bool) -> (u8, MemoryType, u8) {
    let index = (descriptor >> ATTRIBUTE_INDEX_SHIFT) & 7;
    let (attribute, attribute_xs) = decoded((mair >> (index * 8)) as u8);
    let attribute = encoded(attribute, attribute_xs, xs);
    let memory = memory_type(attribute);
    let shareability = (descriptor >> SHAREABILITY_SHIFT) as u8 & 3;
    (
        attribute,
        memory,
        effective_shareability(attribute, shareability),
    )
}

/// An attribute byte without its XS encoding, and its XS attribute
/// (pseudocode S1DecodeMemAttrs): 0 for Device memory with bit 0 set, for
/// `0x40` and `0xa0`, and for Normal memory Write-Back at both levels.
pub fn decoded(attribute: u8) -> (u8, bool) {
    match attribute {
        NON_CACHEABLE_NOT_XS => (NORMAL_NON_CACHEABLE, false),
        WRITE_THROUGH_NOT_XS => (NORMAL_WRITE_THROUGH, false),
        attribute if device(attribute).is_some() => {
            (attribute & !DEVICE_NOT_XS, attribute & DEVICE_NOT_XS == 0)
        }
        attribute => (attribute, !write_back(attribute)),
    }
}

/// The attribute byte without XS encoding `attribute` with XS attribute `xs`,
/// as PAR_EL1.ATTR reports it (pseudocode EncodePARAttrs). `implemented`:
/// the chip has FEAT_XS; without it no XS encoding is allocated.
pub fn encoded(attribute: u8, xs: bool, implemented: bool) -> u8 {
    if !implemented || xs {
        return attribute;
    }
    let inner_write_through = cacheability(attribute & 15) == Cacheability::WriteThrough;
    match device(attribute) {
        Some(_) => attribute | DEVICE_NOT_XS,
        // Outer Write-Through non-transient Read-Allocate, inner
        // Write-Through.
        None if attribute >> 4 == 0b1010 && inner_write_through => WRITE_THROUGH_NOT_XS,
        None if attribute == NORMAL_NON_CACHEABLE => NON_CACHEABLE_NOT_XS,
        None => attribute,
    }
}

/// Normal memory Write-Back at both levels.
fn write_back(attribute: u8) -> bool {
    device(attribute).is_none()
        && cacheability(attribute >> 4) == Cacheability::WriteBack
        && cacheability(attribute & 15) == Cacheability::WriteBack
}

/// Normal Non-cacheable memory keeping the XS attribute of `attribute`, the
/// output with caches off (pseudocode AArch64.S1TreatAsNormalNC and
/// AArch64.S2TreatAsNormalNC keep the walk's XS).
pub fn non_cacheable(attribute: u8, implemented: bool) -> u8 {
    encoded(NORMAL_NON_CACHEABLE, decoded(attribute).1, implemented)
}

pub fn memory_type(attribute: u8) -> MemoryType {
    if attribute & 0xf0 == 0 {
        MemoryType::Device
    } else {
        MemoryType::Normal
    }
}

/// Device memory and Normal memory that is Non-cacheable at both levels are
/// Outer Shareable whatever SH says.
pub fn effective_shareability(attribute: u8, shareability: u8) -> u8 {
    if memory_type(attribute) == MemoryType::Device || decoded(attribute).0 == NORMAL_NON_CACHEABLE
    {
        OUTER_SHAREABLE
    } else {
        shareability
    }
}

/// The Device type (nGnRnE 0 to GRE 3) of a Device attribute byte.
fn device(attribute: u8) -> Option<u8> {
    (attribute & 0xf0 == 0).then_some((attribute >> 2) & 3)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cacheability {
    NonCacheable,
    WriteThrough,
    WriteBack,
}

/// The cacheability of one MAIR nibble of Normal memory: `0b0100` is
/// Non-cacheable, `0b00RW` and `0b10RW` Write-Through, `0b01RW` and `0b11RW`
/// Write-Back (bit 3 clear is transient).
fn cacheability(nibble: u8) -> Cacheability {
    match nibble {
        0b0100 => Cacheability::NonCacheable,
        nibble if nibble & 0b0100 == 0 => Cacheability::WriteThrough,
        _ => Cacheability::WriteBack,
    }
}

/// One level (inner or outer) of a stage-1 and stage-2 combination: the
/// weaker cacheability with the stage-1 transience and allocation hints
/// (pseudocode S2CombineS1AttrHints).
fn combined_nibble(first: u8, second: u8) -> u8 {
    match (cacheability(first), cacheability(second)) {
        (Cacheability::NonCacheable, _) | (_, Cacheability::NonCacheable) => 0b0100,
        (Cacheability::WriteThrough, _) | (_, Cacheability::WriteThrough) => first & 0b1011,
        _ => first,
    }
}

/// A stage-2 MemAttr field as a MAIR byte, or `None` for the reserved
/// encodings `0b0100` (FEAT_MTE_PERM is not in the profile) and `0b1x00`
/// (pseudocode S2DecodeMemAttrs). Normal memory carries no allocation hints
/// because the combination takes them from stage 1.
pub fn of_stage2(field: u8) -> Option<u8> {
    let level = |bits: u8| match bits & 3 {
        1 => 0b0100,
        2 => 0b1000,
        _ => 0b1100,
    };
    match field & 0xf {
        field @ 0..=3 => Some(field << 2),
        0b0100 | 0b1000 | 0b1100 => None,
        field => Some(level(field >> 2) << 4 | level(field)),
    }
}

/// The stage-1 attribute byte combined with stage 2's `second`, without XS
/// encoding, whose XS attribute is `second_xs` (pseudocode
/// S2CombineS1MemAttrs): Device beats Normal, the stronger Device type wins,
/// and Normal memory takes the weaker cacheability at each level. XS is 0
/// for Write-Back output and otherwise set only when both stages set it.
/// `implemented`: the chip has FEAT_XS.
pub fn combine(first: u8, second: u8, second_xs: bool, implemented: bool) -> u8 {
    let (first, first_xs) = decoded(first);
    let attribute = combined(first, second);
    let xs = !write_back(attribute) && first_xs && second_xs;
    encoded(attribute, xs, implemented)
}

fn combined(first: u8, second: u8) -> u8 {
    match (device(first), device(second)) {
        (Some(first), Some(second)) => first.min(second) << 2,
        (Some(_), None) => first,
        (None, Some(_)) => second,
        (None, None) => {
            combined_nibble(first >> 4, second >> 4) << 4 | combined_nibble(first & 15, second & 15)
        }
    }
}

/// The attribute byte with HCR_EL2.FWB set, where the stage-2 MemAttr field
/// overrides stage 1 (pseudocode AArch64.S2ApplyFWBMemAttrs): `0b0xx`
/// Device, `0b111` stage 1's attributes, `0b110` Write-Back keeping stage
/// 1's hints, and otherwise Non-cacheable unless stage 1 is Device. XS is
/// stage 1's, except 0 for forced Write-Back and with the descriptor's FnXS
/// (`no_xs`). `implemented`: the chip has FEAT_XS.
pub fn forced(first: u8, field: u8, no_xs: bool, implemented: bool) -> u8 {
    let (first, first_xs) = decoded(first);
    let xs = first_xs && field & 0b111 != 0b110 && !no_xs;
    encoded(forced_attribute(first, field), xs, implemented)
}

fn forced_attribute(first: u8, field: u8) -> u8 {
    if field & 0b0100 == 0 {
        let kind = field & 3;
        return device(first).map_or(kind, |first| first.min(kind)) << 2;
    }
    match field & 3 {
        0b11 => first,
        0b10 => {
            let level = |nibble: u8| {
                if device(first).is_none() && cacheability(nibble) != Cacheability::NonCacheable {
                    nibble | 0b0100
                } else {
                    0b1111
                }
            };
            level(first >> 4) << 4 | level(first & 15)
        }
        _ if device(first).is_some() => first,
        _ => NORMAL_NON_CACHEABLE,
    }
}

/// The SH field of a combination: the more shareable of the two (pseudocode
/// S2CombineS1Shareability). The reserved SH value `0b01` is CONSTRAINED
/// UNPREDICTABLE; this implementation takes it as Outer Shareable.
pub fn combine_shareability(first: u8, second: u8) -> u8 {
    let rank = |shareability: u8| match shareability & 3 {
        NON_SHAREABLE => 0,
        INNER_SHAREABLE => 1,
        _ => 2,
    };
    match rank(first).max(rank(second)) {
        0 => NON_SHAREABLE,
        1 => INNER_SHAREABLE,
        _ => OUTER_SHAREABLE,
    }
}

/// Stage 1 output is Normal Non-cacheable, Outer Shareable, for a data
/// access to Normal memory with SCTLR_ELx.C clear and for an instruction
/// fetch from Device memory or with SCTLR_ELx.I clear (pseudocode
/// AArch64.S1TreatAsNormalNC).
pub fn stage1_non_cacheable(sctlr: u64, attribute: u8, execute: bool) -> bool {
    let device = memory_type(attribute) == MemoryType::Device;
    if execute {
        device || sctlr & SCTLR_I == 0
    } else {
        !device && sctlr & SCTLR_C == 0
    }
}

/// Attributes with stage 1 disabled: data is Device-nGnRnE, and instruction
/// fetch is Normal, Write-Through cacheable when SCTLR.I is set; both Outer
/// Shareable.
pub fn disabled(sctlr: u64, execute: bool) -> (u8, MemoryType) {
    let attribute = match (execute, sctlr & SCTLR_I != 0) {
        (false, _) => DEVICE_NGNRNE,
        (true, true) => NORMAL_WRITE_THROUGH,
        (true, false) => NORMAL_NON_CACHEABLE,
    };
    (attribute, memory_type(attribute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mair_selects_the_byte_and_shareability_follows_the_type() {
        // Index 0 Device-nGnRE, 1 Normal write-back, 2 Normal Non-cacheable.
        let mair = 0x44_ff_04;
        let inner_shareable = 0b11 << 8;
        assert_eq!(
            of_descriptor(mair, 1 << 2 | inner_shareable, false),
            (0xff, MemoryType::Normal, 0b11)
        );
        assert_eq!(
            of_descriptor(mair, inner_shareable, false),
            (0x04, MemoryType::Device, OUTER_SHAREABLE)
        );
        assert_eq!(
            of_descriptor(mair, 2 << 2, false),
            (0x44, MemoryType::Normal, OUTER_SHAREABLE)
        );
        assert_eq!(disabled(0, false), (DEVICE_NGNRNE, MemoryType::Device));
        assert_eq!(
            disabled(SCTLR_I, true),
            (NORMAL_WRITE_THROUGH, MemoryType::Normal)
        );
        assert_eq!(
            disabled(0, true),
            (NORMAL_NON_CACHEABLE, MemoryType::Normal)
        );
        // SCTLR.C and I: Normal data and all fetches become Non-cacheable
        // when their cache is off; fetches from Device memory always do.
        assert!(stage1_non_cacheable(SCTLR_I, 0xff, false));
        assert!(!stage1_non_cacheable(SCTLR_C, 0xff, false));
        assert!(!stage1_non_cacheable(0, 0x04, false));
        assert!(stage1_non_cacheable(SCTLR_C, 0xff, true));
        assert!(!stage1_non_cacheable(SCTLR_I, 0xff, true));
        assert!(stage1_non_cacheable(SCTLR_I | SCTLR_C, 0x04, true));
    }

    #[test]
    fn stage_two_combines_type_cacheability_hints_and_shareability() {
        // MemAttr: Device-nGnRE, Normal outer WT inner WB, Normal NC, and
        // the reserved encodings.
        assert_eq!(of_stage2(0b0001), Some(0x04));
        assert_eq!(of_stage2(0b1011), Some(0x8c));
        assert_eq!(of_stage2(0b0101), Some(0x44));
        assert_eq!((of_stage2(0b0100), of_stage2(0b1000)), (None, None));
        // Device beats Normal and the stronger Device type wins.
        assert_eq!(combine(0xff, 0x08, true, false), 0x08);
        assert_eq!(combine(0x0c, 0xcc, true, false), 0x0c);
        assert_eq!(combine(0x0c, 0x04, true, false), 0x04);
        // Normal: the weaker cacheability with stage 1's hints. WB RA
        // non-transient against WT gives WT RA non-transient; a transient
        // WB RW nibble becomes transient WT; NC wins.
        assert_eq!(combine(0xee, 0x88, true, false), 0xaa);
        assert_eq!(combine(0x7f, 0xc8, true, false), 0x7b);
        assert_eq!(combine(0xff, 0x4c, true, false), 0x4f);
        assert_eq!(combine(0xaa, 0xcc, true, false), 0xaa);
        // FWB: Device, stage 1's attributes, forced Write-Back keeping
        // stage 1's hints, and Non-cacheable unless stage 1 is Device.
        assert_eq!(forced(0xff, 0b0010, false, false), 0x08);
        assert_eq!(forced(0x00, 0b0011, false, false), 0x00);
        assert_eq!(forced(0x4a, 0b0111, false, false), 0x4a);
        assert_eq!(forced(0x4a, 0b0110, false, false), 0xfe);
        assert_eq!(forced(0x04, 0b0110, false, false), 0xff);
        assert_eq!(
            (
                forced(0xff, 0b0101, false, false),
                forced(0x04, 0b0101, false, false)
            ),
            (0x44, 0x04)
        );
        assert_eq!(
            combine_shareability(NON_SHAREABLE, INNER_SHAREABLE),
            INNER_SHAREABLE
        );
        assert_eq!(
            combine_shareability(OUTER_SHAREABLE, INNER_SHAREABLE),
            OUTER_SHAREABLE
        );
        assert_eq!(combine_shareability(NON_SHAREABLE, 0b01), OUTER_SHAREABLE);
    }

    #[test]
    fn xs_travels_in_the_attribute_byte_on_chips_with_feat_xs() {
        // MAIR: 0 Device-nGnRE with XS 0, 1 Normal Non-cacheable with XS 0,
        // 2 Normal Write-Through with XS 0.
        let mair = 0xa0_40_05;
        let inner_shareable = 0b11 << 8;
        // With FEAT_XS each byte is its own PAR_EL1.ATTR encoding.
        assert_eq!(
            of_descriptor(mair, inner_shareable, true),
            (0x05, MemoryType::Device, OUTER_SHAREABLE)
        );
        assert_eq!(
            of_descriptor(mair, 1 << 2 | inner_shareable, true),
            (0x40, MemoryType::Normal, OUTER_SHAREABLE)
        );
        assert_eq!(
            of_descriptor(mair, 2 << 2 | inner_shareable, true),
            (0xa0, MemoryType::Normal, 0b11)
        );
        // Without it they are reserved and mean the encodings without XS.
        assert_eq!(
            of_descriptor(mair, inner_shareable, false),
            (0x04, MemoryType::Device, OUTER_SHAREABLE)
        );
        assert_eq!(
            of_descriptor(mair, 1 << 2 | inner_shareable, false),
            (0x44, MemoryType::Normal, OUTER_SHAREABLE)
        );
        assert_eq!(
            of_descriptor(mair, 2 << 2 | inner_shareable, false),
            (0xaa, MemoryType::Normal, 0b11)
        );
        // Caches off keep XS: Write-Back memory has XS 0.
        assert_eq!(non_cacheable(0xff, true), 0x40);
        assert_eq!(non_cacheable(0xaa, true), 0x44);
        assert_eq!(non_cacheable(0xff, false), 0x44);
        // Stage 2 sets XS only when both stages do, FnXS clears it, and
        // Write-Back output has XS 0.
        assert_eq!(combine(0x05, 0x04, true, true), 0x05);
        assert_eq!(combine(0x04, 0x04, false, true), 0x05);
        assert_eq!(combine(0x04, 0x0c, true, true), 0x04);
        assert_eq!(combine(0xa0, 0xcc, true, true), 0xa0);
        assert_eq!(combine(0xff, 0x44, true, true), 0x40);
        assert_eq!(combine(0xaa, 0x44, true, true), 0x44);
        assert_eq!(combine(0xaa, 0xcc, true, true), 0xaa);
        // FWB keeps stage 1's XS except for forced Write-Back and FnXS.
        assert_eq!(forced(0x04, 0b0111, false, true), 0x04);
        assert_eq!(forced(0x04, 0b0111, true, true), 0x05);
        assert_eq!(forced(0x40, 0b0110, false, true), 0xff);
        assert_eq!(forced(0x40, 0b0101, false, true), 0x40);
        assert_eq!(forced(0x44, 0b0101, false, true), 0x44);
        assert_eq!(forced(0x05, 0b0010, false, true), 0x05);
    }
}
