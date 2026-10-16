//! Predicate generation: PTRUE, PFALSE, WHILE*, BRK* and PNEXT. PN registers are
//! P8-P15.

mod basic;
mod breaks;
mod whiles;

pub use basic::BasicOperand;
pub use breaks::{Boundary, BreakKind, BreakOperand};
pub use whiles::{Comparison, Destination, WhileOperand};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Basic(BasicOperand),
    Break(BreakOperand),
    While(WhileOperand),
}

impl Operand {
    /// Counter and paired-predicate destinations require the SME2 extension.
    pub const fn requires_sme2(self) -> bool {
        matches!(
            self,
            Self::Basic(BasicOperand::TrueCounter { .. })
                | Self::While(WhileOperand {
                    destination: Destination::Pair(_) | Destination::Counter { .. },
                    ..
                })
        )
    }
}

/// None means another decoder owns the word; Err means an owned but invalid
/// operand.
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if let Some(result) = basic::decode_basic(word) {
        return Some(result.map(Operand::Basic));
    }
    if let Some(result) = breaks::decode(word) {
        return Some(result.map(Operand::Break));
    }
    whiles::decode(word).map(|result| result.map(Operand::While))
}
