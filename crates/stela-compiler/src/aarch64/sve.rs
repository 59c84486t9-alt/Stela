//! Streaming-SVE operands. Family modules validate their allocated encodings.
//! Feature, mode and execution-profile checks belong to the shared caller.

pub mod dot;
pub mod integer_arithmetic;
pub mod integer_logic;
pub mod integer_products;
pub mod integer_saturation;
pub mod sign;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Dot(dot::Operand),
    IntegerArithmetic(integer_arithmetic::Operand),
    IntegerLogic(integer_logic::Operand),
    IntegerProducts(integer_products::Operand),
    IntegerSaturation(integer_saturation::Operand),
    Sign(sign::Operand),
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    dot::decode_integer(word)
        .map(|operand| operand.map(Operand::Dot))
        .or_else(|| integer_logic::decode(word).map(|operand| operand.map(Operand::IntegerLogic)))
        .or_else(|| {
            integer_arithmetic::decode(word).map(|operand| operand.map(Operand::IntegerArithmetic))
        })
        .or_else(|| {
            integer_products::decode(word).map(|operand| operand.map(Operand::IntegerProducts))
        })
        .or_else(|| {
            integer_saturation::decode(word).map(|operand| operand.map(Operand::IntegerSaturation))
        })
        .or_else(|| sign::decode(word).map(|operand| operand.map(Operand::Sign)))
}
