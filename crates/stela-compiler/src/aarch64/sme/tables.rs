//! Register-only SME2 table lookup, selection, widening and group permutations.
//!
//! These operations require streaming mode. Lookup additionally requires ZT0.
//! Group encodings enforce alignment and do not wrap at Z31.

use crate::aarch64::scalable::{ElementSize, VECTOR_REGISTER_COUNT};

const REGISTER_MASK: u32 = 31;
const QUAD_FIELD_MASK: u32 = 7;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const GROUP_SIZE_SHIFT: u32 = 22;
const LOOKUP_SIZE_SHIFT: u32 = 12;
const SIZE_MASK: u32 = 3;
const STRIDED_HIGH_SHIFT: u32 = 4;
const PREDICATE_SHIFT: u32 = 10;
const COUNTER_PREDICATE_BASE: u8 = 8;
const BYTE_BITS: u16 = 8;
const QUADWORD_BITS: u16 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    Sme2,
    Sme2p1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorGroup {
    pub first: u8,
    pub count: u8,
    pub stride: u8,
}

impl VectorGroup {
    fn new(first: u8, count: u8, stride: u8) -> Self {
        debug_assert!(first + (count - 1) * stride < VECTOR_REGISTER_COUNT);
        Self {
            first,
            count,
            stride,
        }
    }

    pub fn register(self, index: u8) -> u8 {
        assert!(index < self.count);
        self.first + index * self.stride
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermuteSources {
    Pair { left: u8, right: u8 },
    Quad { first: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Lookup {
        source: u8,
        index_bits: u8,
        segment: u8,
    },
    Select {
        left: VectorGroup,
        right: VectorGroup,
        predicate: u8,
    },
    Unpack {
        source: VectorGroup,
        signed: bool,
    },
    Permute {
        sources: PermuteSources,
        unzip: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub canonical_id: &'static str,
    pub destination: VectorGroup,
    pub element: ElementSize,
    pub feature: Feature,
    pub kind: Kind,
}

impl Operand {
    /// Both maximum supported SVL at decode and active SVL at execution must fit.
    pub fn minimum_svl_bits(self) -> usize {
        match self.kind {
            Kind::Permute { .. } => (self.element.bits() * usize::from(self.destination.count))
                .max(usize::from(QUADWORD_BITS)),
            _ => usize::from(QUADWORD_BITS),
        }
    }

    pub fn requires_zt0(self) -> bool {
        matches!(self.kind, Kind::Lookup { .. })
    }
}

#[derive(Clone, Copy)]
struct LookupEncoding {
    canonical_id: &'static str,
    mask: u32,
    value: u32,
    index_bits: u8,
    count: u8,
    stride: u8,
    immediate_shift: u32,
    immediate_mask: u32,
}

const LOOKUPS: [LookupEncoding; 10] = [
    LookupEncoding {
        canonical_id: "luti2_mz2_ztz_1",
        mask: 0xfffc_4c01,
        value: 0xc08c_4000,
        index_bits: 2,
        count: 2,
        stride: 1,
        immediate_shift: 15,
        immediate_mask: 7,
    },
    LookupEncoding {
        canonical_id: "luti2_mz2_ztz_8",
        mask: 0xfffc_4c08,
        value: 0xc09c_4000,
        index_bits: 2,
        count: 2,
        stride: 8,
        immediate_shift: 15,
        immediate_mask: 7,
    },
    LookupEncoding {
        canonical_id: "luti2_mz4_ztz_1",
        mask: 0xfffc_cc03,
        value: 0xc08c_8000,
        index_bits: 2,
        count: 4,
        stride: 1,
        immediate_shift: 16,
        immediate_mask: 3,
    },
    LookupEncoding {
        canonical_id: "luti2_mz4_ztz_4",
        mask: 0xfffc_cc0c,
        value: 0xc09c_8000,
        index_bits: 2,
        count: 4,
        stride: 4,
        immediate_shift: 16,
        immediate_mask: 3,
    },
    LookupEncoding {
        canonical_id: "luti2_z_ztz_",
        mask: 0xfffc_0c00,
        value: 0xc0cc_0000,
        index_bits: 2,
        count: 1,
        stride: 1,
        immediate_shift: 14,
        immediate_mask: 15,
    },
    LookupEncoding {
        canonical_id: "luti4_mz2_ztz_1",
        mask: 0xfffe_4c01,
        value: 0xc08a_4000,
        index_bits: 4,
        count: 2,
        stride: 1,
        immediate_shift: 15,
        immediate_mask: 3,
    },
    LookupEncoding {
        canonical_id: "luti4_mz2_ztz_8",
        mask: 0xfffe_4c08,
        value: 0xc09a_4000,
        index_bits: 4,
        count: 2,
        stride: 8,
        immediate_shift: 15,
        immediate_mask: 3,
    },
    LookupEncoding {
        canonical_id: "luti4_mz4_ztz_1",
        mask: 0xfffe_cc03,
        value: 0xc08a_8000,
        index_bits: 4,
        count: 4,
        stride: 1,
        immediate_shift: 16,
        immediate_mask: 1,
    },
    LookupEncoding {
        canonical_id: "luti4_mz4_ztz_4",
        mask: 0xfffe_cc0c,
        value: 0xc09a_8000,
        index_bits: 4,
        count: 4,
        stride: 4,
        immediate_shift: 16,
        immediate_mask: 1,
    },
    LookupEncoding {
        canonical_id: "luti4_z_ztz_",
        mask: 0xfffe_0c00,
        value: 0xc0ca_0000,
        index_bits: 4,
        count: 1,
        stride: 1,
        immediate_shift: 14,
        immediate_mask: 7,
    },
];

fn lookup(word: u32) -> Option<Operand> {
    let encoding = LOOKUPS
        .iter()
        .find(|encoding| word & encoding.mask == encoding.value)?;
    let element_bits = BYTE_BITS << ((word >> LOOKUP_SIZE_SHIFT) & SIZE_MASK);
    let strided = encoding.stride != 1;
    if element_bits > if strided { 16 } else { 32 }
        || (encoding.index_bits == 4 && encoding.count == 4 && element_bits < 16)
    {
        return None;
    }
    let first = if strided {
        let low_mask = u32::from(encoding.stride - 1);
        (((word >> STRIDED_HIGH_SHIFT) & 1) << 4 | (word & low_mask)) as u8
    } else {
        (word & REGISTER_MASK) as u8
    };
    Some(Operand {
        canonical_id: encoding.canonical_id,
        destination: VectorGroup::new(first, encoding.count, encoding.stride),
        element: ElementSize::from_bytes(usize::from(element_bits / BYTE_BITS)).unwrap(),
        feature: if strided {
            Feature::Sme2p1
        } else {
            Feature::Sme2
        },
        kind: Kind::Lookup {
            source: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
            index_bits: encoding.index_bits,
            segment: ((word >> encoding.immediate_shift) & encoding.immediate_mask) as u8,
        },
    })
}

fn group(word: u32, shift: u32, count: u8) -> VectorGroup {
    VectorGroup::new(
        (((word >> shift) & REGISTER_MASK) as u8) & !(count - 1),
        count,
        1,
    )
}

pub fn decode(word: u32) -> Option<Operand> {
    if let Some(operand) = lookup(word) {
        return Some(operand);
    }
    let element_bits = BYTE_BITS << ((word >> GROUP_SIZE_SHIFT) & SIZE_MASK);
    for (canonical_id, mask, value, count) in [
        ("sel_mz_p_zz_2", 0xff21_e021, 0xc120_8000, 2),
        ("sel_mz_p_zz_4", 0xff23_e063, 0xc121_8000, 4),
    ] {
        if word & mask == value {
            return Some(Operand {
                canonical_id,
                destination: group(word, 0, count),
                element: ElementSize::from_bytes(usize::from(element_bits / BYTE_BITS)).unwrap(),
                feature: Feature::Sme2,
                kind: Kind::Select {
                    left: group(word, SOURCE_SHIFT, count),
                    right: group(word, RIGHT_SHIFT, count),
                    predicate: COUNTER_PREDICATE_BASE
                        | ((word >> PREDICATE_SHIFT) & QUAD_FIELD_MASK) as u8,
                },
            });
        }
    }
    for (canonical_id, mask, value, count, signed) in [
        ("sunpk_mz_z_2", 0xff3f_fc01, 0xc125_e000, 2, true),
        ("sunpk_mz_z_4", 0xff3f_fc23, 0xc135_e000, 4, true),
        ("uunpk_mz_z_2", 0xff3f_fc01, 0xc125_e001, 2, false),
        ("uunpk_mz_z_4", 0xff3f_fc23, 0xc135_e001, 4, false),
    ] {
        if word & mask == value {
            if element_bits == BYTE_BITS {
                return None;
            }
            let source_count = count / 2;
            return Some(Operand {
                canonical_id,
                destination: group(word, 0, count),
                element: ElementSize::from_bytes(usize::from(element_bits / BYTE_BITS)).unwrap(),
                feature: Feature::Sme2,
                kind: Kind::Unpack {
                    source: VectorGroup::new(
                        ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
                        source_count,
                        1,
                    ),
                    signed,
                },
            });
        }
    }
    for (canonical_id, mask, value, count, wide, unzip) in [
        ("uzp_mz_z_4", 0xff3f_fc63, 0xc136_e002, 4, false, true),
        ("uzp_mz_z_4q", 0xffff_fc63, 0xc137_e002, 4, true, true),
        ("uzp_mz_zz_2", 0xff20_fc01, 0xc120_d001, 2, false, true),
        ("uzp_mz_zz_2q", 0xffe0_fc01, 0xc120_d401, 2, true, true),
        ("zip_mz_z_4", 0xff3f_fc63, 0xc136_e000, 4, false, false),
        ("zip_mz_z_4q", 0xffff_fc63, 0xc137_e000, 4, true, false),
        ("zip_mz_zz_2", 0xff20_fc01, 0xc120_d000, 2, false, false),
        ("zip_mz_zz_2q", 0xffe0_fc01, 0xc120_d400, 2, true, false),
    ] {
        if word & mask == value {
            return Some(Operand {
                canonical_id,
                destination: group(word, 0, count),
                element: if wide {
                    ElementSize::Quadword
                } else {
                    ElementSize::from_bytes(usize::from(element_bits / BYTE_BITS)).unwrap()
                },
                feature: Feature::Sme2,
                kind: Kind::Permute {
                    sources: if count == 2 {
                        PermuteSources::Pair {
                            left: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
                            right: ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8,
                        }
                    } else {
                        PermuteSources::Quad {
                            first: ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8,
                        }
                    },
                    unzip,
                },
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_groups_and_segments_do_not_wrap() {
        for encoding in LOOKUPS {
            for size in 0..4 {
                let element_bits = BYTE_BITS << size;
                let allocated = element_bits <= if encoding.stride == 1 { 32 } else { 16 }
                    && !(encoding.index_bits == 4 && encoding.count == 4 && element_bits < 16);
                for immediate in 0..=encoding.immediate_mask {
                    for source in 0..=REGISTER_MASK {
                        for destination in 0..=REGISTER_MASK {
                            let destination_field = if encoding.stride == 1 {
                                destination & !(u32::from(encoding.count) - 1)
                            } else {
                                destination & (u32::from(encoding.stride) - 1) | destination & 16
                            };
                            let word = encoding.value
                                | (size << LOOKUP_SIZE_SHIFT)
                                | (immediate << encoding.immediate_shift)
                                | (source << SOURCE_SHIFT)
                                | destination_field;
                            let operand = decode(word);
                            if !allocated {
                                assert!(operand.is_none(), "{word:08x}");
                                continue;
                            }
                            let operand = operand.unwrap();
                            assert_eq!(operand.canonical_id, encoding.canonical_id);
                            assert_eq!(operand.element.bits(), usize::from(element_bits));
                            assert_eq!(operand.destination.first, destination_field as u8);
                            assert_eq!(operand.destination.count, encoding.count);
                            assert_eq!(operand.destination.stride, encoding.stride);
                            assert!(
                                operand.destination.register(encoding.count - 1)
                                    < VECTOR_REGISTER_COUNT
                            );
                            assert_eq!(
                                operand.kind,
                                Kind::Lookup {
                                    source: source as u8,
                                    index_bits: encoding.index_bits,
                                    segment: immediate as u8,
                                }
                            );
                            assert_eq!(
                                operand.feature,
                                if encoding.stride == 1 {
                                    Feature::Sme2
                                } else {
                                    Feature::Sme2p1
                                }
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn select_preserves_aligned_groups_and_counter_predicate_roles() {
        for (base, count) in [(0xc120_8000, 2), (0xc121_8000, 4)] {
            for size in 0..4 {
                for destination in (0..VECTOR_REGISTER_COUNT).step_by(count as usize) {
                    for source in (0..VECTOR_REGISTER_COUNT).step_by(count as usize) {
                        for predicate in 0..8 {
                            let word = base
                                | (size << GROUP_SIZE_SHIFT)
                                | u32::from(destination)
                                | (u32::from(source) << SOURCE_SHIFT)
                                | (u32::from(source) << RIGHT_SHIFT)
                                | (predicate << PREDICATE_SHIFT);
                            let operand = decode(word).unwrap();
                            assert_eq!(
                                operand.destination,
                                VectorGroup::new(destination, count, 1)
                            );
                            assert_eq!(
                                operand.kind,
                                Kind::Select {
                                    left: VectorGroup::new(source, count, 1),
                                    right: VectorGroup::new(source, count, 1),
                                    predicate: predicate as u8 + COUNTER_PREDICATE_BASE,
                                }
                            );
                            assert_eq!(operand.element.bits(), usize::from(BYTE_BITS << size));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn unpack_rejects_byte_destinations_and_reads_half_as_many_registers() {
        for (base, count) in [(0xc125_e000, 2), (0xc135_e000, 4)] {
            for signed in [true, false] {
                for size in 0..4 {
                    for source in (0..VECTOR_REGISTER_COUNT).step_by((count / 2) as usize) {
                        let word = base
                            | u32::from(!signed)
                            | (size << GROUP_SIZE_SHIFT)
                            | (u32::from(source) << SOURCE_SHIFT)
                            | u32::from(VECTOR_REGISTER_COUNT - count);
                        let decoded = decode(word);
                        if size == 0 {
                            assert!(decoded.is_none());
                        } else {
                            let operand = decoded.unwrap();
                            assert_eq!(
                                operand.kind,
                                Kind::Unpack {
                                    source: VectorGroup::new(source, count / 2, 1),
                                    signed,
                                }
                            );
                            assert_eq!(
                                operand.destination.register(count - 1),
                                VECTOR_REGISTER_COUNT - 1
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn permutation_widths_define_current_and_maximum_svl_guards() {
        for (base, count, wide, unzip) in [
            (0xc136_e002, 4, false, true),
            (0xc137_e002, 4, true, true),
            (0xc120_d001, 2, false, true),
            (0xc120_d401, 2, true, true),
            (0xc136_e000, 4, false, false),
            (0xc137_e000, 4, true, false),
            (0xc120_d000, 2, false, false),
            (0xc120_d400, 2, true, false),
        ] {
            for size in 0..if wide { 1 } else { 4 } {
                let word = base
                    | (size << GROUP_SIZE_SHIFT)
                    | (28 << SOURCE_SHIFT)
                    | if count == 2 { 31 << RIGHT_SHIFT } else { 0 }
                    | u32::from(VECTOR_REGISTER_COUNT - count);
                let operand = decode(word).unwrap();
                assert_eq!(
                    operand.element.bits(),
                    usize::from(if wide {
                        QUADWORD_BITS
                    } else {
                        BYTE_BITS << size
                    })
                );
                assert_eq!(
                    operand.minimum_svl_bits(),
                    (operand.element.bits() * usize::from(count)).max(usize::from(QUADWORD_BITS))
                );
                assert_eq!(
                    operand.kind,
                    Kind::Permute {
                        sources: if count == 2 {
                            PermuteSources::Pair {
                                left: 28,
                                right: 31,
                            }
                        } else {
                            PermuteSources::Quad { first: 28 }
                        },
                        unzip,
                    }
                );
            }
        }
    }

    #[test]
    fn unrelated_and_reserved_encodings_are_not_accepted() {
        for word in [
            0,
            0xffff_ffff,
            0xd65f_03c0,
            0xc08c_7000,
            0xc09a_6000,
            0xc08a_8000,
            0xc09a_8000,
            0xc125_e000,
            0xc135_e001,
        ] {
            assert_eq!(decode(word), None, "{word:08x}");
        }
    }
}
