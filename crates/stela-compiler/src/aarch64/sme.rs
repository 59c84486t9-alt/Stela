//! SME operands. Callers check streaming mode, ZA state and features.

pub mod extrema_scale;
pub mod fp8_conversion;
pub mod fp8_matrix;
pub mod fp_matrix;
pub mod fp_vector;
pub mod integer_dots;
pub mod integer_matrix;
pub mod integer_vector;
pub mod length;
pub mod lut_v2;
pub mod memory;
pub mod movement;
pub mod tables;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    IntegerDots(integer_dots::Operand),
    IntegerMatrix(integer_matrix::Operand),
    IntegerVector(integer_vector::Operand),
    Length(length::Operand),
    Memory(memory::Operand),
    Movement(movement::Operand),
    Tables(tables::Operand),
    LutV2(lut_v2::Operand),
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if let Some(operand) = lut_v2::decode(word) {
        return Some(Ok(Operand::LutV2(operand)));
    }
    if let Some(operand) = memory::decode(word) {
        return Some(Ok(Operand::Memory(operand)));
    }
    if let Some(operand) = tables::decode(word) {
        return Some(Ok(Operand::Tables(operand)));
    }
    if let Some(operand) = movement::decode(word) {
        return Some(Ok(Operand::Movement(operand)));
    }
    if let Some(operand) = integer_vector::decode(word) {
        return Some(operand.map(Operand::IntegerVector));
    }
    integer_dots::decode(word)
        .map(|operand| Ok(Operand::IntegerDots(operand)))
        .or_else(|| integer_matrix::decode(word).map(|operand| Ok(Operand::IntegerMatrix(operand))))
        .or_else(|| length::decode(word).map(|operand| Ok(Operand::Length(operand))))
}
