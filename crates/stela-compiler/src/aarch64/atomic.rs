//! Scalar and pair LSE operations in the declared coherent Normal-WB memory profile.
use super::{Register, register};

const CAS_MASK: u32 = 0x3fa07c00;
const CAS_CLASS: u32 = 0x08a07c00;
const CASP_MASK: u32 = 0xbfa07c00;
const CASP_CLASS: u32 = 0x08207c00;
const RMW_MASK: u32 = 0x3f200c00;
const RMW_CLASS: u32 = 0x38200000;
const SIZE_SHIFT: u32 = 30;
const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 16;
const BASE_SHIFT: u32 = 5;
const PAIR_FIRST_ODD_BIT: u32 = 1;
const WORD_PAIR_BYTES: u8 = 8;
const RMW_OPERATION_SHIFT: u32 = 12;
const RMW_OPERATION_MASK: u32 = 15;
const CAS_ACQUIRE: u32 = 1 << 22;
const CAS_RELEASE: u32 = 1 << 15;
const RMW_ACQUIRE: u32 = 1 << 23;
const RMW_RELEASE: u32 = 1 << 22;
const ADD_OPCODE: u32 = 0;
const CLEAR_OPCODE: u32 = 1;
const XOR_OPCODE: u32 = 2;
const SET_OPCODE: u32 = 3;
const SIGNED_MAX_OPCODE: u32 = 4;
const SIGNED_MIN_OPCODE: u32 = 5;
const UNSIGNED_MAX_OPCODE: u32 = 6;
const UNSIGNED_MIN_OPCODE: u32 = 7;
const SWAP_OPCODE: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Relaxed,
    Acquire,
    Release,
    AcquireRelease,
}

impl Order {
    const fn decode(acquire: bool, release: bool) -> Self {
        match (acquire, release) {
            (false, false) => Self::Relaxed,
            (true, false) => Self::Acquire,
            (false, true) => Self::Release,
            (true, true) => Self::AcquireRelease,
        }
    }

    /// LSE acquisition is suppressed when its returned-old register is ZR.
    pub const fn acquires(self, result: Register) -> bool {
        !matches!(result, Register::Zero) && matches!(self, Self::Acquire | Self::AcquireRelease)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rmw {
    Add,
    Clear,
    Xor,
    Set,
    SignedMax,
    SignedMin,
    UnsignedMax,
    UnsignedMin,
    Swap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    CompareExchange {
        compare: Register,
        source: Register,
    },
    CompareExchangePair {
        compare: [Register; 2],
        source: [Register; 2],
    },
    ReadModifyWrite {
        operation: Rmw,
        source: Register,
        destination: Register,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub bytes: u8,
    pub base: Register,
    pub order: Order,
    pub kind: Kind,
}

/// Reserved RMW operations and odd CASP first registers decline explicitly.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let source = register((word >> SOURCE_SHIFT) & REGISTER_MASK, false);
    let destination = register(word & REGISTER_MASK, false);
    let (kind, order, bytes) = if word & CASP_MASK == CASP_CLASS {
        let first_compare = (word >> SOURCE_SHIFT) & REGISTER_MASK;
        let first_source = word & REGISTER_MASK;
        if (first_compare | first_source) & PAIR_FIRST_ODD_BIT != 0 {
            return Some(Err(()));
        }
        (
            Kind::CompareExchangePair {
                compare: [source, register(first_compare + 1, false)],
                source: [destination, register(first_source + 1, false)],
            },
            Order::decode(word & CAS_ACQUIRE != 0, word & CAS_RELEASE != 0),
            WORD_PAIR_BYTES << (word >> SIZE_SHIFT),
        )
    } else if word & CAS_MASK == CAS_CLASS {
        (
            Kind::CompareExchange {
                compare: source,
                source: destination,
            },
            Order::decode(word & CAS_ACQUIRE != 0, word & CAS_RELEASE != 0),
            1 << (word >> SIZE_SHIFT),
        )
    } else if word & RMW_MASK == RMW_CLASS {
        let operation = match (word >> RMW_OPERATION_SHIFT) & RMW_OPERATION_MASK {
            ADD_OPCODE => Rmw::Add,
            CLEAR_OPCODE => Rmw::Clear,
            XOR_OPCODE => Rmw::Xor,
            SET_OPCODE => Rmw::Set,
            SIGNED_MAX_OPCODE => Rmw::SignedMax,
            SIGNED_MIN_OPCODE => Rmw::SignedMin,
            UNSIGNED_MAX_OPCODE => Rmw::UnsignedMax,
            UNSIGNED_MIN_OPCODE => Rmw::UnsignedMin,
            SWAP_OPCODE => Rmw::Swap,
            _ => return Some(Err(())),
        };
        (
            Kind::ReadModifyWrite {
                operation,
                source,
                destination,
            },
            Order::decode(word & RMW_ACQUIRE != 0, word & RMW_RELEASE != 0),
            1 << (word >> SIZE_SHIFT),
        )
    } else {
        return None;
    };
    Some(Ok(Operand {
        bytes,
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
        order,
        kind,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_orders_and_all_register_roles_preserve_aliases() {
        for size in 0..4 {
            for acquire in [false, true] {
                for release in [false, true] {
                    for index in 0..=REGISTER_MASK {
                        let fields = (index << SOURCE_SHIFT) | (index << BASE_SHIFT) | index;
                        let cas = decode(
                            CAS_CLASS
                                | (size << SIZE_SHIFT)
                                | fields
                                | if acquire { CAS_ACQUIRE } else { 0 }
                                | if release { CAS_RELEASE } else { 0 },
                        )
                        .unwrap()
                        .unwrap();
                        assert_eq!(cas.bytes, 1 << size);
                        assert_eq!(cas.base, register(index, true));
                        assert_eq!(cas.order, Order::decode(acquire, release));
                        assert_eq!(
                            cas.kind,
                            Kind::CompareExchange {
                                compare: register(index, false),
                                source: register(index, false),
                            }
                        );
                        assert_eq!(
                            cas.order.acquires(register(index, false)),
                            acquire && index != 31
                        );
                        for operation in 0..=8 {
                            let rmw = decode(
                                RMW_CLASS
                                    | (size << SIZE_SHIFT)
                                    | fields
                                    | (operation << RMW_OPERATION_SHIFT)
                                    | if acquire { RMW_ACQUIRE } else { 0 }
                                    | if release { RMW_RELEASE } else { 0 },
                            )
                            .unwrap()
                            .unwrap();
                            assert_eq!(rmw.bytes, cas.bytes);
                            assert_eq!(rmw.base, cas.base);
                            assert_eq!(rmw.order, cas.order);
                            assert!(
                                matches!(rmw.kind, Kind::ReadModifyWrite { source, destination, .. }
                                if source == register(index, false) && destination == source)
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn pair_widths_orders_even_inputs_and_every_base_preserve_aliases() {
        for size in 0..2 {
            for acquire in [false, true] {
                for release in [false, true] {
                    for compare in 0..=REGISTER_MASK {
                        for source in 0..=REGISTER_MASK {
                            for base in 0..=REGISTER_MASK {
                                let word = CASP_CLASS
                                    | (size << SIZE_SHIFT)
                                    | (compare << SOURCE_SHIFT)
                                    | (base << BASE_SHIFT)
                                    | source
                                    | if acquire { CAS_ACQUIRE } else { 0 }
                                    | if release { CAS_RELEASE } else { 0 };
                                let decoded = decode(word).unwrap();
                                if (compare | source) & PAIR_FIRST_ODD_BIT != 0 {
                                    assert_eq!(decoded, Err(()));
                                } else {
                                    assert_eq!(
                                        decoded,
                                        Ok(Operand {
                                            bytes: WORD_PAIR_BYTES << size,
                                            base: register(base, true),
                                            order: Order::decode(acquire, release),
                                            kind: Kind::CompareExchangePair {
                                                compare: [
                                                    register(compare, false),
                                                    register(compare + 1, false)
                                                ],
                                                source: [
                                                    register(source, false),
                                                    register(source + 1, false)
                                                ],
                                            },
                                        })
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        // Bit 31 selects a different allocated/reserved class, never a wider CASP.
        assert_eq!(decode(CASP_CLASS | (1 << 31)), None);
    }

    #[test]
    fn reserved_operations_and_neighbor_classes_remain_explicit() {
        for operation in 9..=RMW_OPERATION_MASK {
            assert_eq!(
                decode(RMW_CLASS | (operation << RMW_OPERATION_SHIFT)),
                Some(Err(()))
            );
        }
        for word in [
            0xc85f7c00, 0xc8007c00, 0xc8dffc00, 0xf8606800, 0xf8400800, 0xf9800000,
        ] {
            assert_eq!(decode(word), None, "{word:#x}");
        }
    }
}
