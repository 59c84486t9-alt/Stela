//! Scalable-matrix operands. Mode and feature checks are execution contracts.

pub mod integer_dots;
pub mod length;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    IntegerDots(integer_dots::Operand),
    Length(length::Operand),
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    integer_dots::decode(word)
        .map(|operand| Ok(Operand::IntegerDots(operand)))
        .or_else(|| length::decode(word).map(|operand| Ok(Operand::Length(operand))))
}
