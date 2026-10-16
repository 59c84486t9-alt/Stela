//! FCSEL, FABS and FNEG, including FPCR.AH/NEP behavior.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignOperation {
    Abs,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Select {
        destination: u8,
        left: u8,
        right: u8,
        lane_bytes: u8,
        condition: u8,
    },
    Sign {
        operation: SignOperation,
        destination: u8,
        source: u8,
        lane_bytes: u8,
        bytes: u8,
        scalar: bool,
    },
}

const SELECT_MASK: u32 = 0xff20_0c00;
const SELECT: u32 = 0x1e20_0c00;
const SCALAR_SIGN_MASK: u32 = 0xff3f_fc00;
const SCALAR_ABS: u32 = 0x1e20_c000;
const SCALAR_NEG: u32 = 0x1e21_4000;
const VECTOR_HALF_MASK: u32 = 0xbfff_fc00;
const VECTOR_HALF_ABS: u32 = 0x0ef8_f800;
const VECTOR_HALF_NEG: u32 = 0x2ef8_f800;
const VECTOR_FLOAT_MASK: u32 = 0xbfbf_fc00;
const VECTOR_FLOAT_ABS: u32 = 0x0ea0_f800;
const VECTOR_FLOAT_NEG: u32 = 0x2ea0_f800;

fn scalar_lane(word: u32) -> Result<u8, ()> {
    match (word >> 22) & 3 {
        0 => Ok(4),
        1 => Ok(8),
        3 => Ok(2),
        _ => Err(()),
    }
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let destination = (word & 31) as u8;
    let source = ((word >> 5) & 31) as u8;
    if word & SELECT_MASK == SELECT {
        return Some(scalar_lane(word).map(|lane_bytes| Operand::Select {
            destination,
            left: source,
            right: ((word >> 16) & 31) as u8,
            lane_bytes,
            condition: ((word >> 12) & 15) as u8,
        }));
    }
    let scalar = match word & SCALAR_SIGN_MASK {
        SCALAR_ABS => Some(SignOperation::Abs),
        SCALAR_NEG => Some(SignOperation::Neg),
        _ => None,
    };
    if let Some(operation) = scalar {
        return Some(scalar_lane(word).map(|lane_bytes| Operand::Sign {
            operation,
            destination,
            source,
            lane_bytes,
            bytes: lane_bytes,
            scalar: true,
        }));
    }
    let half = match word & VECTOR_HALF_MASK {
        VECTOR_HALF_ABS => Some(SignOperation::Abs),
        VECTOR_HALF_NEG => Some(SignOperation::Neg),
        _ => None,
    };
    let ordinary = match word & VECTOR_FLOAT_MASK {
        VECTOR_FLOAT_ABS => Some(SignOperation::Abs),
        VECTOR_FLOAT_NEG => Some(SignOperation::Neg),
        _ => None,
    };
    let operation = half.or(ordinary)?;
    let bytes = if word & (1 << 30) == 0 { 8 } else { 16 };
    let lane_bytes = if half.is_some() {
        2
    } else {
        4 << ((word >> 22) & 1)
    };
    if lane_bytes == 8 && bytes == 8 {
        return Some(Err(()));
    }
    Some(Ok(Operand::Sign {
        operation,
        destination,
        source,
        lane_bytes,
        bytes,
        scalar: false,
    }))
}

#[cfg(test)]
mod tests;
