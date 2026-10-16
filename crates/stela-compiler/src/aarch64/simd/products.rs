//! Integer multiplies and widening arithmetic (MUL, MLA, SMULL, UADDL, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accumulate {
    None,
    Add,
    Subtract,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dot {
        signed: bool,
    },
    RoundedDoublingAccumulate {
        subtract: bool,
    },
    Polynomial {
        widen: bool,
    },
    Doubling {
        high: bool,
        rounding: bool,
        accumulate: Accumulate,
    },
    Product {
        signed: bool,
        widen: bool,
        accumulate: Accumulate,
    },
    Arithmetic {
        signed: bool,
        wide_left: bool,
        subtract: bool,
    },
    Difference {
        signed: bool,
        widen: bool,
        accumulate: bool,
    },
}
impl Kind {
    pub fn widened(self) -> bool {
        matches!(
            self,
            Self::Polynomial { widen: true }
                | Self::Doubling { high: false, .. }
                | Self::Arithmetic { .. }
                | Self::Product { widen: true, .. }
                | Self::Difference { widen: true, .. }
        )
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
    pub lane_bytes: u8,
    pub bytes: u8,
    pub upper: bool,
    pub index: Option<u8>,
}
macro_rules! encodings {
    ($($name:ident => ($value:expr, $kind:expr)),+ $(,)?) => {
        #[derive(Clone, Copy)]
        enum Encoding { $($name),+ }
        impl Encoding {
            const ALL:&'static [Self]=&[$(Self::$name),+];
            fn facts(self)->(u32,Kind) {match self {$(Self::$name=>($value,$kind)),+}}
        }
    };
}
use Accumulate::{Add, None as NoAccumulate, Subtract};
use Kind::{Arithmetic, Difference, Product};
encodings! {
    Mul => (0x0e209c00,Product {signed:false,widen:false,accumulate:NoAccumulate}),
    Mla => (0x0e209400,Product {signed:false,widen:false,accumulate:Add}),
    Mls => (0x2e209400,Product {signed:false,widen:false,accumulate:Subtract}),
    Smull => (0x0e20c000,Product {signed:true,widen:true,accumulate:NoAccumulate}),
    Umull => (0x2e20c000,Product {signed:false,widen:true,accumulate:NoAccumulate}),
    Smlal => (0x0e208000,Product {signed:true,widen:true,accumulate:Add}),
    Umlal => (0x2e208000,Product {signed:false,widen:true,accumulate:Add}),
    Smlsl => (0x0e20a000,Product {signed:true,widen:true,accumulate:Subtract}),
    Umlsl => (0x2e20a000,Product {signed:false,widen:true,accumulate:Subtract}),
    Saddl => (0x0e200000,Arithmetic {signed:true,wide_left:false,subtract:false}),
    Uaddl => (0x2e200000,Arithmetic {signed:false,wide_left:false,subtract:false}),
    Ssubl => (0x0e202000,Arithmetic {signed:true,wide_left:false,subtract:true}),
    Usubl => (0x2e202000,Arithmetic {signed:false,wide_left:false,subtract:true}),
    Saddw => (0x0e201000,Arithmetic {signed:true,wide_left:true,subtract:false}),
    Uaddw => (0x2e201000,Arithmetic {signed:false,wide_left:true,subtract:false}),
    Ssubw => (0x0e203000,Arithmetic {signed:true,wide_left:true,subtract:true}),
    Usubw => (0x2e203000,Arithmetic {signed:false,wide_left:true,subtract:true}),
    Sabd => (0x0e207400,Difference {signed:true,widen:false,accumulate:false}),
    Uabd => (0x2e207400,Difference {signed:false,widen:false,accumulate:false}),
    Saba => (0x0e207c00,Difference {signed:true,widen:false,accumulate:true}),
    Uaba => (0x2e207c00,Difference {signed:false,widen:false,accumulate:true}),
    Sabdl => (0x0e207000,Difference {signed:true,widen:true,accumulate:false}),
    Uabdl => (0x2e207000,Difference {signed:false,widen:true,accumulate:false}),
    Sabal => (0x0e205000,Difference {signed:true,widen:true,accumulate:true}),
    Uabal => (0x2e205000,Difference {signed:false,widen:true,accumulate:true}),
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if let Some(decoded) = decode_dot(word) {
        return Some(decoded);
    }
    if let Some(decoded) = decode_indexed_product(word) {
        return Some(decoded);
    }
    if let Some(decoded) = decode_special(word) {
        return Some(decoded);
    }
    let opcode = word & 0xbf20fc00;
    let (_, kind) = Encoding::ALL
        .iter()
        .map(|e| e.facts())
        .find(|(value, _)| *value == opcode)?;
    let size = (word >> 22) & 3;
    if size == 3 {
        return Some(Err(()));
    }
    let q = word & (1 << 30) != 0;
    let widen = kind.widened();
    Some(Ok(Operand {
        kind,
        destination: (word & 31) as u8,
        left: ((word >> 5) & 31) as u8,
        right: ((word >> 16) & 31) as u8,
        lane_bytes: 1 << size,
        bytes: if widen || q { 16 } else { 8 },
        upper: widen && q,
        index: None,
    }))
}

#[derive(Clone, Copy)]
enum IndexedProductEncoding {
    Mul,
    Mla,
    Mls,
    Smull,
    Umull,
    Smlal,
    Umlal,
    Smlsl,
    Umlsl,
}
impl IndexedProductEncoding {
    const ALL: &'static [Self] = &[
        Self::Mul,
        Self::Mla,
        Self::Mls,
        Self::Smull,
        Self::Umull,
        Self::Smlal,
        Self::Umlal,
        Self::Smlsl,
        Self::Umlsl,
    ];
    fn facts(self) -> (u32, Kind) {
        let (opcode, signed, widen, accumulate) = match self {
            Self::Mul => (0x0f008000, false, false, NoAccumulate),
            Self::Mla => (0x2f000000, false, false, Add),
            Self::Mls => (0x2f004000, false, false, Subtract),
            Self::Smull => (0x0f00a000, true, true, NoAccumulate),
            Self::Umull => (0x2f00a000, false, true, NoAccumulate),
            Self::Smlal => (0x0f002000, true, true, Add),
            Self::Umlal => (0x2f002000, false, true, Add),
            Self::Smlsl => (0x0f006000, true, true, Subtract),
            Self::Umlsl => (0x2f006000, false, true, Subtract),
        };
        (
            opcode,
            Kind::Product {
                signed,
                widen,
                accumulate,
            },
        )
    }
}

#[allow(clippy::result_unit_err)]
fn decode_indexed_product(word: u32) -> Option<Result<Operand, ()>> {
    let (_, kind) = IndexedProductEncoding::ALL
        .iter()
        .map(|e| e.facts())
        .find(|(opcode, _)| word & 0xbf00f400 == *opcode)?;
    let size = (word >> 22) & 3;
    if !matches!(size, 1 | 2) {
        return Some(Err(()));
    }
    let q = word & (1 << 30) != 0;
    let h = ((word >> 11) & 1) as u8;
    let l = ((word >> 21) & 1) as u8;
    let m = ((word >> 20) & 1) as u8;
    Some(Ok(Operand {
        kind,
        destination: (word & 31) as u8,
        left: ((word >> 5) & 31) as u8,
        right: ((word >> 16) & if size == 1 { 15 } else { 31 }) as u8,
        lane_bytes: 1 << size,
        bytes: if kind.widened() || q { 16 } else { 8 },
        upper: kind.widened() && q,
        index: Some(if size == 1 {
            (h << 2) | (l << 1) | m
        } else {
            (h << 1) | l
        }),
    }))
}

#[derive(Clone, Copy)]
enum PolynomialEncoding {
    Multiply,
    MultiplyLong,
}
impl PolynomialEncoding {
    fn opcode(self) -> u32 {
        match self {
            Self::Multiply => 0x2e209c00,
            Self::MultiplyLong => 0x0e20e000,
        }
    }
}

#[derive(Clone, Copy)]
enum DoublingEncoding {
    MulHigh,
    RoundMulHigh,
    MulLong,
    AddLong,
    SubLong,
    RoundAddHigh,
    RoundSubHigh,
}
impl DoublingEncoding {
    const ALL: &'static [Self] = &[
        Self::MulHigh,
        Self::RoundMulHigh,
        Self::MulLong,
        Self::AddLong,
        Self::SubLong,
        Self::RoundAddHigh,
        Self::RoundSubHigh,
    ];
    fn facts(self) -> (u32, u32, Kind) {
        match self {
            Self::RoundAddHigh | Self::RoundSubHigh => {
                let subtract = matches!(self, Self::RoundSubHigh);
                return (
                    if subtract { 0x2e008c00 } else { 0x2e008400 },
                    if subtract { 0x2f00f000 } else { 0x2f00d000 },
                    Kind::RoundedDoublingAccumulate { subtract },
                );
            }
            _ => {}
        }
        let (register, indexed, high, rounding, accumulate) = match self {
            Self::MulHigh => (0x0e20b400, 0x0f00c000, true, false, NoAccumulate),
            Self::RoundMulHigh => (0x2e20b400, 0x0f00d000, true, true, NoAccumulate),
            Self::MulLong => (0x0e20d000, 0x0f00b000, false, false, NoAccumulate),
            Self::AddLong => (0x0e209000, 0x0f003000, false, false, Add),
            Self::SubLong => (0x0e20b000, 0x0f007000, false, false, Subtract),
            Self::RoundAddHigh | Self::RoundSubHigh => unreachable!(),
        };
        (
            register,
            indexed,
            Kind::Doubling {
                high,
                rounding,
                accumulate,
            },
        )
    }
}

#[derive(Clone, Copy)]
enum DotEncoding {
    Signed,
    Unsigned,
}
impl DotEncoding {
    const ALL: &'static [Self] = &[Self::Signed, Self::Unsigned];
    fn facts(self) -> (u32, u32, bool) {
        match self {
            Self::Signed => (0x0e009400, 0x0f00e000, true),
            Self::Unsigned => (0x2e009400, 0x2f00e000, false),
        }
    }
}

#[allow(clippy::result_unit_err)]
fn decode_dot(word: u32) -> Option<Result<Operand, ()>> {
    const REGISTER_MASK: u32 = 0xbf20fc00;
    const INDEXED_MASK: u32 = 0xbf00f400;
    const DWORD_SIZE: u32 = 2;
    let (_, indexed, signed) = DotEncoding::ALL
        .iter()
        .map(|encoding| encoding.facts())
        .find(|(register, indexed, _)| {
            word & REGISTER_MASK == *register || word & INDEXED_MASK == *indexed
        })?;
    if (word >> 22) & 3 != DWORD_SIZE {
        return Some(Err(()));
    }
    Some(Ok(Operand {
        kind: Kind::Dot { signed },
        destination: (word & 31) as u8,
        left: ((word >> 5) & 31) as u8,
        right: ((word >> 16) & 31) as u8,
        lane_bytes: 4,
        bytes: if word & (1 << 30) != 0 { 16 } else { 8 },
        upper: false,
        index: (word & INDEXED_MASK == indexed)
            .then_some((((word >> 11) & 1) << 1 | ((word >> 21) & 1)) as u8),
    }))
}
#[allow(clippy::result_unit_err)]
fn decode_special(word: u32) -> Option<Result<Operand, ()>> {
    let scalar = word & (1 << 28) != 0;
    let q = word & (1 << 30) != 0;
    let normalized = word & !(1 << 28);
    let size = (word >> 22) & 3;
    let mut index = None;
    let mut right = ((word >> 16) & 31) as u8;
    let kind =
        if !scalar && word & 0xbf20fc00 == PolynomialEncoding::Multiply.opcode() {
            if size != 0 {
                return Some(Err(()));
            }
            Kind::Polynomial { widen: false }
        } else if !scalar && word & 0xbf20fc00 == PolynomialEncoding::MultiplyLong.opcode() {
            if size != 0 && size != 3 {
                return Some(Err(()));
            }
            Kind::Polynomial { widen: true }
        } else {
            let (_, indexed, kind) = DoublingEncoding::ALL.iter().map(|e| e.facts()).find(
                |(register, indexed, _)| {
                    normalized & 0xbf20fc00 == *register || normalized & 0xbf00f400 == *indexed
                },
            )?;
            if !matches!(size, 1 | 2) || scalar && !q {
                return Some(Err(()));
            }
            if normalized & 0xbf00f400 == indexed {
                let h = ((word >> 11) & 1) as u8;
                let l = ((word >> 21) & 1) as u8;
                let m = ((word >> 20) & 1) as u8;
                if size == 1 {
                    right &= 15;
                    index = Some((h << 2) | (l << 1) | m);
                } else {
                    index = Some((h << 1) | l);
                }
            }
            kind
        };
    let lane = 1 << size;
    let widen = kind.widened();
    Some(Ok(Operand {
        kind,
        destination: (word & 31) as u8,
        left: ((word >> 5) & 31) as u8,
        right,
        lane_bytes: lane,
        bytes: if scalar {
            if widen { lane * 2 } else { lane }
        } else if widen || q {
            16
        } else {
            8
        },
        upper: widen && q && !scalar,
        index,
    }))
}

#[cfg(test)]
mod tests;
