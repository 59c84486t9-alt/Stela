//! Reviewed SIMD data movement and integer operations, with FP/AdvSIMD enabled.
//! Encoding facts: Arm ISA_A64_xml_A_profile-2026-06/{ldr_imm_fpsimd,
//! str_imm_fpsimd,ldur_fpsimd,stur_fpsimd,movi_advsimd,ldp_fpsimd,stp_fpsimd}.xml.
use super::{AddressMode, Register, register};
pub mod aes;
pub mod arithmetic;
pub mod bfloat16;
pub mod comparison;
pub mod complex;
pub mod conversion;
pub mod estimate;
pub mod extrema_scale;
pub mod floating;
pub mod fp8_conversion;
pub mod fused;
pub mod halving;
pub mod i8mm;
pub mod immediates;
pub mod lut;
pub mod memory;
pub mod minmax;
pub mod products;
pub mod rearrange;
pub mod reductions;
pub mod refinement;
pub mod rounding;
pub mod saturating;
pub mod sha1;
pub mod sha256;
pub mod sha3;
pub mod sha512;
pub mod shifts;
pub mod sqrt;
pub mod structure_memory;
pub mod widening;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerOperation {
    And,
    Bic,
    Orr,
    Orn,
    Eor,
    Bsl,
    Bit,
    Bif,
    Add,
    Sub,
    Abs,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Equal,
    Greater,
    GreaterEqual,
    Higher,
    HigherEqual,
    LessZero,
    LessEqualZero,
    Test,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Aes(aes::Operand),
    I8mm(i8mm::Operand),
    Sha1(sha1::Operand),
    Sha256(sha256::Operand),
    Sha3(sha3::Operand),
    Sha512(sha512::Operand),
    Floating(floating::Operand),
    MemoryRegisterOffset(memory::Operand),
    StructureMemory(structure_memory::Operand),
    Immediate(immediates::Operand),
    Halving(halving::Operand),
    Product(products::Operand),
    Saturate(saturating::Operand),
    Reduce(reductions::Operand),
    Shift(shifts::Operand),
    Rearrange(rearrange::Operand),
    Lut(lut::Operand),
    Compare {
        operation: Comparison,
        destination: u8,
        left: u8,
        right: Option<u8>,
        bytes: u8,
        lane_bytes: u8,
    },
    Integer {
        operation: IntegerOperation,
        destination: u8,
        left: u8,
        /// Unused for unary ABS/NEG. V31 is ordinary data in every role.
        right: u8,
        bytes: u8,
        lane_bytes: u8,
    },
    MemoryPair {
        load: bool,
        bytes: u8,
        /// V31 is ordinary vector data; GPR/SP base roles are independent.
        vectors: [u8; 2],
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
    Memory {
        load: bool,
        bytes: u8,
        /// SIMD register 31 is V31, not the integer zero register.
        vector: u8,
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
    MoveImmediate {
        vector: u8,
        /// Expanded 8-bit byte mask, one bit per 0x00/0xff byte.
        mask: u64,
        /// D writes clear the upper half; 2D replicates the mask.
        two_lanes: bool,
    },
}

/// None denotes another encoding class; Err is an unsupported/reserved member.
/// Each reviewed family validates its reserved encodings.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if let Some(operand) = lut::decode(word) {
        return Some(Ok(Operand::Lut(operand)));
    }
    if let Some(decoded) = structure_memory::decode(word) {
        return Some(decoded.map(Operand::StructureMemory));
    }
    if let Some(decoded) = aes::decode(word) {
        return Some(decoded.map(Operand::Aes));
    }
    if let Some(decoded) = i8mm::decode(word) {
        return Some(decoded.map(Operand::I8mm));
    }
    if let Some(decoded) = sha1::decode(word) {
        return Some(Ok(Operand::Sha1(decoded)));
    }
    if let Some(decoded) = sha256::decode(word) {
        return Some(Ok(Operand::Sha256(decoded)));
    }
    if let Some(decoded) = sha3::decode(word) {
        return Some(decoded.map(Operand::Sha3));
    }
    if let Some(decoded) = sha512::decode(word) {
        return Some(decoded.map(Operand::Sha512));
    }
    if let Some(decoded) = memory::decode(word) {
        return Some(decoded.map(Operand::MemoryRegisterOffset));
    }
    if let Some(decoded) = floating::decode(word) {
        return Some(decoded.map(Operand::Floating));
    }
    if let Some(decoded) = immediates::decode(word) {
        return Some(decoded.map(Operand::Immediate));
    }
    if let Some(decoded) = halving::decode(word) {
        return Some(decoded.map(Operand::Halving));
    }
    if let Some(decoded) = products::decode(word) {
        return Some(decoded.map(Operand::Product));
    }
    if let Some(decoded) = saturating::decode(word) {
        return Some(decoded.map(Operand::Saturate));
    }
    if let Some(decoded) = reductions::decode(word) {
        return Some(decoded.map(Operand::Reduce));
    }
    if let Some(decoded) = shifts::decode(word) {
        return Some(decoded.map(Operand::Shift));
    }
    if let Some(decoded) = rearrange::decode(word) {
        return Some(decoded.map(Operand::Rearrange));
    }
    let scalar = word & (1 << 28) != 0;
    let normalized = word & !(1 << 28);
    let comparison = match normalized & 0xbf20fc00 {
        0x2e208c00 => Some(Comparison::Equal),
        0x0e203400 => Some(Comparison::Greater),
        0x0e203c00 => Some(Comparison::GreaterEqual),
        0x2e203400 => Some(Comparison::Higher),
        0x2e203c00 => Some(Comparison::HigherEqual),
        0x0e208c00 => Some(Comparison::Test),
        _ => None,
    };
    let compare_zero = match normalized & 0xbf3ffc00 {
        0x0e209800 => Some(Comparison::Equal),
        0x0e208800 => Some(Comparison::Greater),
        0x2e208800 => Some(Comparison::GreaterEqual),
        0x0e20a800 => Some(Comparison::LessZero),
        0x2e209800 => Some(Comparison::LessEqualZero),
        _ => None,
    };
    if let Some(operation) = comparison.or(compare_zero) {
        let q = word & (1 << 30) != 0;
        let size = (word >> 22) & 3;
        // Other scalar sizes/Q values share space with scalar FP encodings;
        // they are outside this integer comparison class, not vector compares.
        if scalar && (!q || size != 3) {
            return None;
        }
        if !scalar && !q && size == 3 {
            return Some(Err(()));
        }
        return Some(Ok(Operand::Compare {
            operation,
            destination: (word & 31) as u8,
            left: ((word >> 5) & 31) as u8,
            right: comparison.map(|_| ((word >> 16) & 31) as u8),
            bytes: if scalar || !q { 8 } else { 16 },
            lane_bytes: 1 << size,
        }));
    }
    use IntegerOperation::*;
    let logical = match word & 0xbfe0fc00 {
        0x0e201c00 => Some(And),
        0x0e601c00 => Some(Bic),
        0x0ea01c00 => Some(Orr),
        0x0ee01c00 => Some(Orn),
        0x2e201c00 => Some(Eor),
        0x2e601c00 => Some(Bsl),
        0x2ea01c00 => Some(Bit),
        0x2ee01c00 => Some(Bif),
        _ => None,
    };
    let vector_math = match word & 0xbf20fc00 {
        0x0e208400 => Some(Add),
        0x2e208400 => Some(Sub),
        _ => None,
    }
    .or(match word & 0xbf3ffc00 {
        0x0e20b800 => Some(Abs),
        0x2e20b800 => Some(Neg),
        _ => None,
    });
    let scalar_math = match word & 0xffe0fc00 {
        0x5ee08400 => Some(Add),
        0x7ee08400 => Some(Sub),
        _ => None,
    }
    .or(match word & 0xfffffc00 {
        0x5ee0b800 => Some(Abs),
        0x7ee0b800 => Some(Neg),
        _ => None,
    });
    if let Some(operation) = logical.or(vector_math).or(scalar_math) {
        let q = word & (1 << 30) != 0;
        let lane_bytes = if logical.is_some() {
            1
        } else {
            1 << ((word >> 22) & 3)
        };
        if vector_math.is_some() && !q && lane_bytes == 8 {
            return Some(Err(()));
        }
        return Some(Ok(Operand::Integer {
            operation,
            destination: (word & 31) as u8,
            left: ((word >> 5) & 31) as u8,
            right: ((word >> 16) & 31) as u8,
            bytes: if scalar_math.is_some() || !q { 8 } else { 16 },
            lane_bytes,
        }));
    }
    if word & 0x3e000000 == 0x2c000000 {
        let opcode = word >> 30;
        let mode = match (word >> 23) & 3 {
            1 => AddressMode::PostIndex,
            2 => AddressMode::Offset,
            3 => AddressMode::PreIndex,
            _ => return Some(Err(())), // non-temporal pairs are a separate class
        };
        if opcode == 3 {
            return Some(Err(()));
        }
        let load = word & (1 << 22) != 0;
        let vectors = [(word & 31) as u8, ((word >> 10) & 31) as u8];
        // LDPOVERLAP permits UNKNOWN/UNDEF/NOP, not ordinary two-result writes.
        // Decline every duplicate destination, including the real V31 register.
        if load && vectors[0] == vectors[1] {
            return Some(Err(()));
        }
        let bytes = 4u8 << opcode;
        let immediate = ((word >> 15) & 127) as i32;
        return Some(Ok(Operand::MemoryPair {
            load,
            bytes,
            vectors,
            base: register((word >> 5) & 31, true),
            displacement: ((immediate << 25) >> 25) * i32::from(bytes),
            mode,
        }));
    }
    if word & 0xbff8fc00 == 0x2f00e400 {
        let immediate = ((word >> 16) & 7) << 5 | ((word >> 5) & 31);
        let mut mask = 0;
        for byte in 0..8 {
            if immediate & (1 << byte) != 0 {
                mask |= 0xffu64 << (byte * 8);
            }
        }
        return Some(Ok(Operand::MoveImmediate {
            vector: (word & 31) as u8,
            mask,
            two_lanes: word & (1 << 30) != 0,
        }));
    }
    let unsigned = word & 0x3f000000 == 0x3d000000;
    if !unsigned && word & 0x3f200000 != 0x3c000000 {
        return None;
    }
    let size = word >> 30;
    let opcode = (word >> 22) & 3;
    // opc[1] selects Q, whose size field must be 00.
    if opcode & 2 != 0 && size != 0 {
        return Some(Err(()));
    }
    let scale = if opcode & 2 != 0 { 4 } else { size };
    let (displacement, mode) = if unsigned {
        ((((word >> 10) & 4095) << scale) as i32, AddressMode::Offset)
    } else {
        let mode = match (word >> 10) & 3 {
            0 => AddressMode::Offset,
            1 => AddressMode::PostIndex,
            3 => AddressMode::PreIndex,
            _ => return Some(Err(())),
        };
        let immediate = ((word >> 12) & 511) as i32;
        ((immediate << 23) >> 23, mode)
    };
    Some(Ok(Operand::Memory {
        load: opcode & 1 != 0,
        bytes: 1 << scale,
        vector: (word & 31) as u8,
        base: register((word >> 5) & 31, true),
        displacement,
        mode,
    }))
}

#[cfg(test)]
mod tests;
