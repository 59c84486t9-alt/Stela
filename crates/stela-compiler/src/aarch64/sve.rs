//! Streaming-SVE operands. Family modules validate their allocated encodings.
//! Feature, mode and execution-profile checks belong to the shared caller.

pub mod integer_logic;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    IntegerLogic(integer_logic::Operand),
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    integer_logic::decode(word).map(|operand| operand.map(Operand::IntegerLogic))
}
