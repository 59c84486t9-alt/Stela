//! Arm A64 2026-06 saturating integer facts, including sticky FPSR.QC.
/// Architectural cumulative saturation bit; unrelated FPSR bits stay unchanged.
pub const FPSR_QC: u32 = 1 << 27;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Add {
        signed: bool,
    },
    Sub {
        signed: bool,
    },
    Abs,
    Neg,
    /// Source Rn and old Rd have opposite signedness; the result follows Rd.
    MixedAdd {
        unsigned_result: bool,
    },
    Narrow {
        unsigned_source: bool,
        unsigned_result: bool,
        upper: bool,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
    /// Result lane size; a narrowing source lane is twice as wide.
    pub lane_bytes: u8,
    pub bytes: u8,
}
const SCALAR: u32 = 1 << 28;
const Q: u32 = 1 << 30;
const SAME_MASK: u32 = 0xbf20fc00;
const UNARY_MASK: u32 = 0xbf3ffc00;
const SIGNED_ADD: u32 = 0x0e200c00;
const UNSIGNED_ADD: u32 = 0x2e200c00;
const SIGNED_SUB: u32 = 0x0e202c00;
const UNSIGNED_SUB: u32 = 0x2e202c00;
const SIGNED_ABS: u32 = 0x0e207800;
const SIGNED_NEG: u32 = 0x2e207800;
const SIGNED_MIXED_ADD: u32 = 0x0e203800;
const UNSIGNED_MIXED_ADD: u32 = 0x2e203800;
const SIGNED_NARROW: u32 = 0x0e214800;
const UNSIGNED_NARROW: u32 = 0x2e214800;
const SIGNED_TO_UNSIGNED_NARROW: u32 = 0x2e212800;

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let scalar = word & SCALAR != 0;
    let q = word & Q != 0;
    let normalized = word & !SCALAR;
    let kind = match normalized & SAME_MASK {
        SIGNED_ADD => Some(Kind::Add { signed: true }),
        UNSIGNED_ADD => Some(Kind::Add { signed: false }),
        SIGNED_SUB => Some(Kind::Sub { signed: true }),
        UNSIGNED_SUB => Some(Kind::Sub { signed: false }),
        _ => None,
    }
    .or(match normalized & UNARY_MASK {
        SIGNED_ABS => Some(Kind::Abs),
        SIGNED_NEG => Some(Kind::Neg),
        SIGNED_MIXED_ADD => Some(Kind::MixedAdd {
            unsigned_result: false,
        }),
        UNSIGNED_MIXED_ADD => Some(Kind::MixedAdd {
            unsigned_result: true,
        }),
        SIGNED_NARROW => Some(Kind::Narrow {
            unsigned_source: false,
            unsigned_result: false,
            upper: !scalar && q,
        }),
        UNSIGNED_NARROW => Some(Kind::Narrow {
            unsigned_source: true,
            unsigned_result: true,
            upper: !scalar && q,
        }),
        SIGNED_TO_UNSIGNED_NARROW => Some(Kind::Narrow {
            unsigned_source: false,
            unsigned_result: true,
            upper: !scalar && q,
        }),
        _ => None,
    })?;
    if scalar && !q {
        return None;
    } // fixed scalar class Q bit
    let lane_bytes = 1 << ((word >> 22) & 3);
    let narrow = matches!(kind, Kind::Narrow { .. });
    if (narrow && lane_bytes == 8) || (!narrow && !scalar && !q && lane_bytes == 8) {
        return Some(Err(()));
    }
    Some(Ok(Operand {
        kind,
        destination: (word & 31) as u8,
        left: ((word >> 5) & 31) as u8,
        right: ((word >> 16) & 31) as u8,
        lane_bytes,
        bytes: if scalar {
            lane_bytes
        } else if narrow || !q {
            8
        } else {
            16
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scalar_lane_widths_narrowing_halves_and_vector_reserved_forms_are_exact() {
        for base in [
            SIGNED_ADD,
            UNSIGNED_SUB,
            SIGNED_ABS,
            UNSIGNED_MIXED_ADD,
            SIGNED_NARROW,
            UNSIGNED_NARROW,
            SIGNED_TO_UNSIGNED_NARROW,
        ] {
            let narrow =
                [SIGNED_NARROW, UNSIGNED_NARROW, SIGNED_TO_UNSIGNED_NARROW].contains(&base);
            for scalar in [false, true] {
                for q in [false, true] {
                    for size in 0..4 {
                        let word = base
                            | (u32::from(scalar) << 28)
                            | (u32::from(q) << 30)
                            | (size << 22)
                            | (31 << 5)
                            | 31;
                        if scalar && !q {
                            assert!(decode(word).is_none());
                            continue;
                        }
                        let valid = if narrow {
                            size != 3
                        } else {
                            scalar || q || size != 3
                        };
                        assert_eq!(decode(word).unwrap().is_ok(), valid, "{word:08x}");
                        if let Some(Ok(operand)) = decode(word) {
                            assert_eq!(
                                operand.bytes,
                                if scalar {
                                    1 << size
                                } else if narrow || !q {
                                    8
                                } else {
                                    16
                                }
                            );
                            if let Kind::Narrow { upper, .. } = operand.kind {
                                assert_eq!(upper, !scalar && q);
                            }
                        }
                    }
                }
            }
        }
    }
}
