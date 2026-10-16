//! Integer across-lane reductions, pairwise combines and per-lane bit counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Combine {
    Add,
    Minimum { signed: bool },
    Maximum { signed: bool },
    LongAdd { signed: bool },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Lanes,
    Pairs,
    Across,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitCount {
    Population,
    LeadingZeros,
    LeadingSign,
    Reverse,
    Not,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Combine { operation: Combine, shape: Shape },
    Bits(BitCount),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
    pub bytes: u8,
    pub lane_bytes: u8,
}

macro_rules! encodings {
    ($($name:ident => ($mask:expr, $value:expr)),+ $(,)?) => {
        #[derive(Clone, Copy)]
        enum Encoding { $($name),+ }
        impl Encoding {
            fn matches(self, word: u32) -> bool {
                let (mask,value)=match self { $(Self::$name=>($mask,$value)),+ };
                word&mask==value
            }
        }
    };
}
encodings! {
    SignedMin => (0xbf20fc00,0x0e206c00), SignedMax => (0xbf20fc00,0x0e206400),
    UnsignedMin => (0xbf20fc00,0x2e206c00), UnsignedMax => (0xbf20fc00,0x2e206400),
    SignedMinPair => (0xbf20fc00,0x0e20ac00), SignedMaxPair => (0xbf20fc00,0x0e20a400),
    UnsignedMinPair => (0xbf20fc00,0x2e20ac00), UnsignedMaxPair => (0xbf20fc00,0x2e20a400),
    SignedMinAcross => (0xbf3ffc00,0x0e31a800), SignedMaxAcross => (0xbf3ffc00,0x0e30a800),
    UnsignedMinAcross => (0xbf3ffc00,0x2e31a800), UnsignedMaxAcross => (0xbf3ffc00,0x2e30a800),
    AddAcross => (0xbf3ffc00,0x0e31b800), AddPair => (0xbf20fc00,0x0e20bc00),
    AddScalar => (0xfffffc00,0x5ef1b800),
    SignedLongAcross => (0xbf3ffc00,0x0e303800), UnsignedLongAcross => (0xbf3ffc00,0x2e303800),
    Population => (0xbf3ffc00,0x0e205800), LeadingZeros => (0xbf3ffc00,0x2e204800),
    LeadingSign => (0xbf3ffc00,0x0e204800), Reverse => (0xbffffc00,0x2e605800),
    Not => (0xbffffc00,0x2e205800),
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    use Encoding::*;
    let q = word & (1 << 30) != 0;
    let size = ((word >> 22) & 3) as u8;
    let mut operand = Operand {
        kind: Kind::Bits(BitCount::Not),
        destination: (word & 31) as u8,
        left: ((word >> 5) & 31) as u8,
        right: ((word >> 16) & 31) as u8,
        bytes: if q { 16 } else { 8 },
        lane_bytes: 1 << size,
    };
    if AddScalar.matches(word) {
        operand.kind = Kind::Combine {
            operation: Combine::Add,
            shape: Shape::Across,
        };
        operand.bytes = 16;
        operand.lane_bytes = 8;
        return Some(Ok(operand));
    }
    let bits = [
        (Population, BitCount::Population),
        (LeadingZeros, BitCount::LeadingZeros),
        (LeadingSign, BitCount::LeadingSign),
        (Reverse, BitCount::Reverse),
        (Not, BitCount::Not),
    ]
    .into_iter()
    .find(|(encoding, _)| encoding.matches(word));
    if let Some((_, kind)) = bits {
        if (kind == BitCount::Population && size != 0)
            || (matches!(kind, BitCount::LeadingZeros | BitCount::LeadingSign) && size == 3)
        {
            return Some(Err(()));
        }
        if matches!(kind, BitCount::Reverse | BitCount::Not) {
            operand.lane_bytes = 1;
        }
        operand.kind = Kind::Bits(kind);
        return Some(Ok(operand));
    }
    let operations = [
        (SignedMin, Combine::Minimum { signed: true }, Shape::Lanes),
        (SignedMax, Combine::Maximum { signed: true }, Shape::Lanes),
        (
            UnsignedMin,
            Combine::Minimum { signed: false },
            Shape::Lanes,
        ),
        (
            UnsignedMax,
            Combine::Maximum { signed: false },
            Shape::Lanes,
        ),
        (
            SignedMinPair,
            Combine::Minimum { signed: true },
            Shape::Pairs,
        ),
        (
            SignedMaxPair,
            Combine::Maximum { signed: true },
            Shape::Pairs,
        ),
        (
            UnsignedMinPair,
            Combine::Minimum { signed: false },
            Shape::Pairs,
        ),
        (
            UnsignedMaxPair,
            Combine::Maximum { signed: false },
            Shape::Pairs,
        ),
        (
            SignedMinAcross,
            Combine::Minimum { signed: true },
            Shape::Across,
        ),
        (
            SignedMaxAcross,
            Combine::Maximum { signed: true },
            Shape::Across,
        ),
        (
            UnsignedMinAcross,
            Combine::Minimum { signed: false },
            Shape::Across,
        ),
        (
            UnsignedMaxAcross,
            Combine::Maximum { signed: false },
            Shape::Across,
        ),
        (AddAcross, Combine::Add, Shape::Across),
        (AddPair, Combine::Add, Shape::Pairs),
        (
            SignedLongAcross,
            Combine::LongAdd { signed: true },
            Shape::Across,
        ),
        (
            UnsignedLongAcross,
            Combine::LongAdd { signed: false },
            Shape::Across,
        ),
    ];
    let (_, operation, shape) = operations
        .into_iter()
        .find(|(encoding, _, _)| encoding.matches(word))?;
    if (size == 3 && !(operation == Combine::Add && shape == Shape::Pairs && q))
        || (shape == Shape::Across && size == 2 && !q)
    {
        return Some(Err(()));
    }
    operand.kind = Kind::Combine { operation, shape };
    Some(Ok(operand))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allocated_sizes_shapes_and_fixed_fields_are_distinct() {
        for q in 0..2 {
            for size in 0..4 {
                for (base, across) in [
                    (0x0e206c00, false),
                    (0x2e20a400, false),
                    (0x0e31b800, true),
                    (0x2e303800, true),
                ] {
                    let word = base | (q << 30) | (size << 22) | (31 << 5) | 31;
                    let expected = size != 3 && (!across || q != 0 || size != 2);
                    assert_eq!(decode(word).unwrap().is_ok(), expected, "{word:08x}");
                }
                assert_eq!(
                    decode(0x0e205800 | (q << 30) | (size << 22))
                        .unwrap()
                        .is_ok(),
                    size == 0
                );
                assert_eq!(
                    decode(0x0e20bc00 | (q << 30) | (size << 22))
                        .unwrap()
                        .is_ok(),
                    q != 0 || size != 3
                );
            }
        }
        assert!(decode(0x5ef1b800).unwrap().is_ok());
        assert!(decode(0x5ef0b800).is_none());
        assert!(matches!(
            decode(0x2e605800),
            Some(Ok(Operand {
                kind: Kind::Bits(BitCount::Reverse),
                lane_bytes: 1,
                ..
            }))
        ));
    }
}
