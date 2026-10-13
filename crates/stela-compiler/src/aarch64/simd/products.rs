//! Arm A64 2026-06 non-saturating SIMD products and widened integer arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accumulate {
    None,
    Add,
    Subtract,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
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
            Self::Arithmetic { .. }
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
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_named_form_validates_lanes_source_half_and_vector_roles() {
        for encoding in Encoding::ALL {
            let (base, kind) = encoding.facts();
            for q in 0..2 {
                for size in 0..4 {
                    let word = base | (q << 30) | (size << 22) | (31 << 16) | (31 << 5) | 31;
                    let decoded = decode(word).unwrap();
                    if size == 3 {
                        assert!(decoded.is_err());
                        continue;
                    }
                    let operand = decoded.unwrap();
                    assert_eq!(operand.kind, kind);
                    assert_eq!(
                        (operand.destination, operand.left, operand.right),
                        (31, 31, 31)
                    );
                    assert_eq!(operand.bytes, if kind.widened() || q != 0 { 16 } else { 8 });
                    assert_eq!(operand.upper, kind.widened() && q != 0);
                }
            }
        }
        assert!(decode(0x2e209c00).is_none()); // PMUL is a separate polynomial form
        assert!(decode(0x5e209c00).is_none()); // these are vector forms only
    }
}
