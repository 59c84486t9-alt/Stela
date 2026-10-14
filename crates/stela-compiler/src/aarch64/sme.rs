//! Scalable-matrix operands. Mode and feature checks are execution contracts.

pub mod length;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Length(length::Operand),
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    length::decode(word).map(|operand| Ok(Operand::Length(operand)))
}
