//! Streaming-SVE operands. Family modules validate their allocated encodings.
//! Feature, mode and execution-profile checks belong to the shared caller.

pub mod address;
pub mod dot;
pub mod floating_copy;
pub mod integer_arithmetic;
pub mod integer_logic;
pub mod integer_products;
pub mod integer_saturation;
pub mod predicate_generation;
pub mod predicate_logic;
pub mod rearrange_extract;
pub mod rearrange_widen;
pub mod sign;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Address(address::Operand),
    Dot(dot::Operand),
    FloatingCopy(floating_copy::Operand),
    IntegerArithmetic(integer_arithmetic::Operand),
    IntegerLogic(integer_logic::Operand),
    IntegerProducts(integer_products::Operand),
    IntegerSaturation(integer_saturation::Operand),
    PredicateGeneration(predicate_generation::Operand),
    PredicateLogic(predicate_logic::Operand),
    RearrangeExtract(rearrange_extract::Operand),
    RearrangeWiden(rearrange_widen::Operand),
    Sign(sign::Operand),
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    address::decode(word)
        .map(|operand| operand.map(Operand::Address))
        .or_else(|| dot::decode_integer(word).map(|operand| operand.map(Operand::Dot)))
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
        .or_else(|| {
            predicate_generation::decode(word)
                .map(|operand| operand.map(Operand::PredicateGeneration))
        })
        .or_else(|| {
            predicate_logic::decode(word).map(|operand| operand.map(Operand::PredicateLogic))
        })
        .or_else(|| {
            rearrange_extract::decode(word).map(|operand| operand.map(Operand::RearrangeExtract))
        })
        .or_else(|| {
            rearrange_widen::decode(word).map(|operand| operand.map(Operand::RearrangeWiden))
        })
        .or_else(|| sign::decode(word).map(|operand| operand.map(Operand::Sign)))
        .or_else(|| floating_copy::decode(word).map(|operand| operand.map(Operand::FloatingCopy)))
}
