//! Exclusive scalar/pair transfers and local-monitor clearing.
use super::{Register, register};

const SCALAR_MASK: u32 = 0x3fa0_0000;
const SCALAR_CLASS: u32 = 0x0800_0000;
const PAIR_MASK: u32 = 0xbfa0_0000;
const PAIR_CLASS: u32 = 0x8820_0000;
const CLEAR_MASK: u32 = 0xffff_f0ff;
const CLEAR_CLASS: u32 = 0xd503_305f;
const SIZE_SHIFT: u32 = 30;
const LOAD_BIT: u32 = 1 << 22;
const ACQUIRE_RELEASE_BIT: u32 = 1 << 15;
const STATUS_SHIFT: u32 = 16;
const SECOND_SHIFT: u32 = 10;
const BASE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;
const PAIR_ELEMENT_BYTES: u8 = 4;
const PAIR_SIZE_MASK: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Data {
    Scalar(Register),
    Pair([Register; 2]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Load { acquire: bool },
    Store { release: bool, status: Register },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Clear,
    Transfer {
        element_bytes: u8,
        base: Register,
        data: Data,
        kind: Kind,
    },
}

/// These constrained aliases select the architectural UNDEF alternative.
/// A caller must deliver that exception or decline translation explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstrainedUndefined {
    PairLoadOutputs,
    StoreStatusData,
    StoreStatusBase,
    StoreStatusDataAndBase,
}

/// `None` is a class miss, including CASP, rather than a reserved exclusive.
/// All scalar size/L/o0 and pair sz/L/o0 combinations are allocated. CLREX
/// ignores every CRm value. Parenthesized Rs/Rt2 SBO fields select execute-as-one
/// and never become operands. Base31 is SP; all data/status31 operands are ZR.
/// LDAX* acquisition remains enabled when its output is discarded into ZR.
pub fn decode(word: u32) -> Option<Result<Operand, ConstrainedUndefined>> {
    if word & CLEAR_MASK == CLEAR_CLASS {
        return Some(Ok(Operand::Clear));
    }
    let first = word & REGISTER_MASK;
    let second = (word >> SECOND_SHIFT) & REGISTER_MASK;
    let (element_bytes, data) = if word & SCALAR_MASK == SCALAR_CLASS {
        (
            1 << (word >> SIZE_SHIFT),
            Data::Scalar(register(first, false)),
        )
    } else if word & PAIR_MASK == PAIR_CLASS {
        (
            PAIR_ELEMENT_BYTES << ((word >> SIZE_SHIFT) & PAIR_SIZE_MASK),
            Data::Pair([register(first, false), register(second, false)]),
        )
    } else {
        return None;
    };
    let base = (word >> BASE_SHIFT) & REGISTER_MASK;
    let ordered = word & ACQUIRE_RELEASE_BIT != 0;
    let kind = if word & LOAD_BIT != 0 {
        if matches!(data, Data::Pair(_)) && first == second {
            return Some(Err(ConstrainedUndefined::PairLoadOutputs));
        }
        Kind::Load { acquire: ordered }
    } else {
        let status = (word >> STATUS_SHIFT) & REGISTER_MASK;
        let data_overlap = status == first || matches!(data, Data::Pair(_)) && status == second;
        let base_overlap = status == base && base != REGISTER_MASK;
        let constraint = match (data_overlap, base_overlap) {
            (true, true) => Some(ConstrainedUndefined::StoreStatusDataAndBase),
            (true, false) => Some(ConstrainedUndefined::StoreStatusData),
            (false, true) => Some(ConstrainedUndefined::StoreStatusBase),
            (false, false) => None,
        };
        if let Some(constraint) = constraint {
            return Some(Err(constraint));
        }
        Kind::Store {
            release: ordered,
            status: register(status, false),
        }
    };
    Some(Ok(Operand::Transfer {
        element_bytes,
        base: register(base, true),
        data,
        kind,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SBO_STATUS: u32 = REGISTER_MASK << STATUS_SHIFT;
    const SBO_SECOND: u32 = REGISTER_MASK << SECOND_SHIFT;
    const CLEAR_OPTION_SHIFT: u32 = 8;
    const CLEAR_OPTION_MASK: u32 = 15;

    fn constraint(data: bool, base: bool) -> Result<(), ConstrainedUndefined> {
        match (data, base) {
            (true, true) => Err(ConstrainedUndefined::StoreStatusDataAndBase),
            (true, false) => Err(ConstrainedUndefined::StoreStatusData),
            (false, true) => Err(ConstrainedUndefined::StoreStatusBase),
            (false, false) => Ok(()),
        }
    }

    #[test]
    fn scalar_widths_orders_and_every_register_alias_are_explicit() {
        for size in 0..4 {
            for ordered in [false, true] {
                let class = SCALAR_CLASS
                    | (size << SIZE_SHIFT)
                    | if ordered { ACQUIRE_RELEASE_BIT } else { 0 };
                for first in 0..=REGISTER_MASK {
                    for base in 0..=REGISTER_MASK {
                        let fields = (base << BASE_SHIFT) | first;
                        let expected = Operand::Transfer {
                            element_bytes: 1 << size,
                            base: register(base, true),
                            data: Data::Scalar(register(first, false)),
                            kind: Kind::Load { acquire: ordered },
                        };
                        assert_eq!(
                            decode(class | LOAD_BIT | SBO_STATUS | SBO_SECOND | fields),
                            Some(Ok(expected))
                        );
                        for status in 0..=REGISTER_MASK {
                            let expected = constraint(
                                status == first,
                                status == base && base != REGISTER_MASK,
                            )
                            .map(|()| Operand::Transfer {
                                element_bytes: 1 << size,
                                base: register(base, true),
                                data: Data::Scalar(register(first, false)),
                                kind: Kind::Store {
                                    release: ordered,
                                    status: register(status, false),
                                },
                            });
                            assert_eq!(
                                decode(class | (status << STATUS_SHIFT) | SBO_SECOND | fields),
                                Some(expected)
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn pair_widths_orders_and_every_register_alias_are_explicit() {
        for size in 0..2 {
            for ordered in [false, true] {
                let class = PAIR_CLASS
                    | (size << SIZE_SHIFT)
                    | if ordered { ACQUIRE_RELEASE_BIT } else { 0 };
                for first in 0..=REGISTER_MASK {
                    for second in 0..=REGISTER_MASK {
                        for base in 0..=REGISTER_MASK {
                            let fields = (second << SECOND_SHIFT) | (base << BASE_SHIFT) | first;
                            let data =
                                Data::Pair([register(first, false), register(second, false)]);
                            let expected = if first == second {
                                Err(ConstrainedUndefined::PairLoadOutputs)
                            } else {
                                Ok(Operand::Transfer {
                                    element_bytes: PAIR_ELEMENT_BYTES << size,
                                    base: register(base, true),
                                    data,
                                    kind: Kind::Load { acquire: ordered },
                                })
                            };
                            assert_eq!(
                                decode(class | LOAD_BIT | SBO_STATUS | fields),
                                Some(expected)
                            );
                            for status in 0..=REGISTER_MASK {
                                let expected = constraint(
                                    status == first || status == second,
                                    status == base && base != REGISTER_MASK,
                                )
                                .map(|()| Operand::Transfer {
                                    element_bytes: PAIR_ELEMENT_BYTES << size,
                                    base: register(base, true),
                                    data,
                                    kind: Kind::Store {
                                        release: ordered,
                                        status: register(status, false),
                                    },
                                });
                                assert_eq!(
                                    decode(class | (status << STATUS_SHIFT) | fields),
                                    Some(expected)
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn soft_fixed_fields_ignore_noncanonical_register_encodings() {
        for size in 0..4 {
            for ordered in [false, true] {
                let class = SCALAR_CLASS
                    | (size << SIZE_SHIFT)
                    | if ordered { ACQUIRE_RELEASE_BIT } else { 0 };
                for ignored_status in 0..=REGISTER_MASK {
                    for ignored_second in 0..=REGISTER_MASK {
                        let word = class
                            | LOAD_BIT
                            | (ignored_status << STATUS_SHIFT)
                            | (ignored_second << SECOND_SHIFT)
                            | (REGISTER_MASK << BASE_SHIFT)
                            | REGISTER_MASK;
                        assert_eq!(
                            decode(word),
                            Some(Ok(Operand::Transfer {
                                element_bytes: 1 << size,
                                base: Register::Sp,
                                data: Data::Scalar(Register::Zero),
                                kind: Kind::Load { acquire: ordered },
                            }))
                        );
                        let store = class | (1 << BASE_SHIFT);
                        assert_eq!(
                            decode(store | (ignored_second << SECOND_SHIFT)),
                            decode(store | SBO_SECOND)
                        );
                    }
                }
            }
        }
        for size in 0..2 {
            for ignored_status in 0..=REGISTER_MASK {
                let word = PAIR_CLASS | (size << SIZE_SHIFT) | LOAD_BIT | (1 << SECOND_SHIFT);
                assert_eq!(
                    decode(word | (ignored_status << STATUS_SHIFT)),
                    decode(word | SBO_STATUS)
                );
            }
        }
    }

    #[test]
    fn clear_options_and_neighboring_classes_do_not_overlap() {
        for option in 0..=CLEAR_OPTION_MASK {
            assert_eq!(
                decode(CLEAR_CLASS | (option << CLEAR_OPTION_SHIFT)),
                Some(Ok(Operand::Clear))
            );
        }
        // Bit31=0 pair encodings belong to CASP, including its acquire bit22.
        for size in 0..2 {
            for acquire in [0, LOAD_BIT] {
                for release in [0, ACQUIRE_RELEASE_BIT] {
                    assert_eq!(
                        decode(
                            (PAIR_CLASS & !(1 << 31))
                                | (size << SIZE_SHIFT)
                                | acquire
                                | release
                                | SBO_SECOND
                        ),
                        None
                    );
                }
            }
        }
        // Ordered, limited-order, LSUI exclusives, LSE, and other barriers.
        for word in [
            0xc8df_fc20,
            0xc89f_fc20,
            0xc8df_7c20,
            0xc95f_7c20,
            0xc8a0_7c20,
            0xf820_8021,
            0xd503_3fbf,
            0xd503_3f9f,
            0xd503_3fdf,
        ] {
            assert_eq!(decode(word), None, "neighbor {word:08x}");
        }
    }
}
