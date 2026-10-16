//! Decode architectural operand roles, including SP versus the zero register.
use crate::{GuestAddress, Lifter, UnsupportedReason};
pub mod atomic;
pub mod bitfield;
pub mod checked_pointer;
pub mod conditional_select;
pub mod constrained;
pub mod crc;
pub mod exclusive;
pub mod flags;
pub mod floating;
pub mod fp_register;
pub mod integer_math;
pub mod integer_minmax;
pub mod integer_unary;
pub mod literal;
pub mod non_temporal;
pub mod ordered;
pub mod pc_relative;
pub mod prefetch;
pub mod register_offset;
pub mod scalable;
pub mod simd;
pub mod sme;
pub mod sve;
pub mod system;
pub mod tag_arithmetic;
pub mod tag_memory;
pub mod unprivileged;

const CONDITIONAL_BRANCH_MASK: u32 = 0xff00_0000;
const CONDITIONAL_BRANCH_CLASS: u32 = 0x5400_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    W32,
    X64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    X(u8),
    Sp,
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideMove {
    Zero,
    Keep,
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterExtend {
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logical {
    And,
    Or,
    Xor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryTransfer {
    Store,
    Load { signed: bool, width: Width },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressMode {
    Offset,
    PreIndex,
    PostIndex,
}

/// Numerical instructions share a precise block boundary and transactional
/// completion, while each family keeps its own decoded operand contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatingPointOperation {
    Binary(simd::arithmetic::Operand),
    Fused(simd::fused::Operand),
    Widening(simd::widening::Operand),
    BFloat16(simd::bfloat16::Operand),
    Complex(simd::complex::Operand),
    Conversion(simd::conversion::Operand),
    Comparison(simd::comparison::Operand),
    ExtremaScale(simd::extrema_scale::Operand),
    MinMax(simd::minmax::Operand),
    Rounding(simd::rounding::Operand),
    SquareRoot(simd::sqrt::Operand),
    Estimate(simd::estimate::Operand),
    Refinement(simd::refinement::Operand),
}

impl FloatingPointOperation {
    #[allow(clippy::result_unit_err)]
    pub fn decode(word: u32) -> Option<Result<Self, ()>> {
        if let Some(result) = simd::arithmetic::decode(word) {
            Some(result.map(Self::Binary))
        } else if let Some(result) = simd::fused::decode(word) {
            Some(result.map(Self::Fused))
        } else if let Some(result) = simd::widening::decode(word) {
            Some(result.map(Self::Widening))
        } else if let Some(result) = simd::bfloat16::decode(word) {
            Some(result.map(Self::BFloat16))
        } else if let Some(result) = simd::complex::decode(word) {
            Some(result.map(Self::Complex))
        } else if let Some(result) = simd::conversion::decode(word) {
            Some(result.map(Self::Conversion))
        } else if let Some(result) = simd::extrema_scale::decode(word) {
            Some(result.map(Self::ExtremaScale))
        } else if let Some(result) = simd::comparison::decode(word) {
            Some(result.map(Self::Comparison))
        } else if let Some(result) = simd::minmax::decode(word) {
            Some(result.map(Self::MinMax))
        } else if let Some(result) = simd::rounding::decode(word) {
            Some(result.map(Self::Rounding))
        } else if let Some(result) = simd::sqrt::decode(word) {
            Some(result.map(Self::SquareRoot))
        } else if let Some(result) = simd::estimate::decode(word) {
            Some(result.map(Self::Estimate))
        } else {
            simd::refinement::decode(word).map(|result| result.map(Self::Refinement))
        }
    }
}

impl From<simd::arithmetic::Operand> for FloatingPointOperation {
    fn from(operand: simd::arithmetic::Operand) -> Self {
        Self::Binary(operand)
    }
}
impl From<simd::fused::Operand> for FloatingPointOperation {
    fn from(operand: simd::fused::Operand) -> Self {
        Self::Fused(operand)
    }
}
impl From<simd::widening::Operand> for FloatingPointOperation {
    fn from(operand: simd::widening::Operand) -> Self {
        Self::Widening(operand)
    }
}
impl From<simd::bfloat16::Operand> for FloatingPointOperation {
    fn from(operand: simd::bfloat16::Operand) -> Self {
        Self::BFloat16(operand)
    }
}
impl From<simd::complex::Operand> for FloatingPointOperation {
    fn from(operand: simd::complex::Operand) -> Self {
        Self::Complex(operand)
    }
}
impl From<simd::conversion::Operand> for FloatingPointOperation {
    fn from(operand: simd::conversion::Operand) -> Self {
        Self::Conversion(operand)
    }
}
impl From<simd::comparison::Operand> for FloatingPointOperation {
    fn from(operand: simd::comparison::Operand) -> Self {
        Self::Comparison(operand)
    }
}
impl From<simd::extrema_scale::Operand> for FloatingPointOperation {
    fn from(operand: simd::extrema_scale::Operand) -> Self {
        Self::ExtremaScale(operand)
    }
}
impl From<simd::minmax::Operand> for FloatingPointOperation {
    fn from(operand: simd::minmax::Operand) -> Self {
        Self::MinMax(operand)
    }
}
impl From<simd::rounding::Operand> for FloatingPointOperation {
    fn from(operand: simd::rounding::Operand) -> Self {
        Self::Rounding(operand)
    }
}
impl From<simd::sqrt::Operand> for FloatingPointOperation {
    fn from(operand: simd::sqrt::Operand) -> Self {
        Self::SquareRoot(operand)
    }
}
impl From<simd::estimate::Operand> for FloatingPointOperation {
    fn from(operand: simd::estimate::Operand) -> Self {
        Self::Estimate(operand)
    }
}
impl From<simd::refinement::Operand> for FloatingPointOperation {
    fn from(operand: simd::refinement::Operand) -> Self {
        Self::Refinement(operand)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    CheckedPointer(checked_pointer::Operand),
    Exclusive(exclusive::Operand),
    FloatingPoint(FloatingPointOperation),
    FloatingPointRegister(fp_register::Operand),
    Simd(simd::Operand),
    Bitfield(bitfield::Operand),
    PcRelative(pc_relative::Operand),
    ConditionalSelect(conditional_select::Operand),
    ConditionalCompare(conditional_select::CompareOperand),
    Crc(crc::Operand),
    Flags(flags::Operand),
    Synchronization(system::synchronization::Operation),
    IntegerMath(integer_math::Operand),
    IntegerMinMax(integer_minmax::Operand),
    TagArithmetic(tag_arithmetic::Operand),
    IntegerUnary(integer_unary::Operand),
    Literal(literal::Operand),
    MemoryRegisterOffset(register_offset::Operand),
    MemoryNonTemporal(non_temporal::Operand),
    MemoryUnprivileged(unprivileged::Operand),
    Atomic(atomic::Operand),
    Ordered(ordered::Operand),
    Prefetch(prefetch::Operand),
    MemoryPair {
        transfer: MemoryTransfer,
        bytes: u8,
        data: [Register; 2],
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
    Memory {
        transfer: MemoryTransfer,
        bytes: u8,
        data: Register,
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
    AddSubRegister {
        width: Width,
        subtract: bool,
        flags: bool,
        destination: Register,
        left: Register,
        right: Register,
        shift: Shift,
        amount: u8,
    },
    AddSubCarry {
        width: Width,
        subtract: bool,
        flags: bool,
        destination: Register,
        left: Register,
        right: Register,
    },
    AddSubExtended {
        width: Width,
        subtract: bool,
        flags: bool,
        destination: Register,
        left: Register,
        right: Register,
        extend: RegisterExtend,
        amount: u8,
    },
    LogicalRegister {
        width: Width,
        kind: Logical,
        invert: bool,
        flags: bool,
        destination: Register,
        left: Register,
        right: Register,
        shift: Shift,
        amount: u8,
    },
    LogicalImmediate {
        width: Width,
        kind: Logical,
        flags: bool,
        destination: Register,
        source: Register,
        immediate: u64,
    },
    Branch {
        target: GuestAddress,
    },
    BranchCondition {
        target: GuestAddress,
        condition: u8,
    },
    BranchZero {
        target: GuestAddress,
        source: Register,
        width: Width,
        nonzero: bool,
    },
    BranchBit {
        target: GuestAddress,
        source: Register,
        bit: u8,
        nonzero: bool,
    },
    MoveWide {
        width: Width,
        kind: WideMove,
        destination: Register,
        immediate: u16,
        shift: u8,
    },
    AddSub {
        width: Width,
        subtract: bool,
        flags: bool,
        destination: Register,
        source: Register,
        immediate: u32,
    },
    Nop,
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub pc: GuestAddress,
    pub operation: Operation,
}

pub struct Decoder;

fn register(value: u32, sp: bool) -> Register {
    if value == 31 {
        if sp { Register::Sp } else { Register::Zero }
    } else {
        Register::X(value as u8)
    }
}

/// Decode the logical-immediate subset of Arm's DecodeBitMasks operation.
/// Each element contains a rotated, nonempty run of ones shorter than the
/// element, then repeats to the operand width. High rotation bits are ignored.
fn logical_mask(width: Width, n: u32, rotation: u32, size: u32) -> Option<u64> {
    if width == Width::W32 && n != 0 {
        return None;
    }
    let selector = (n << 6) | ((!size) & 63);
    if selector < 2 {
        return None;
    }
    let element_bits = 1u32 << (31 - selector.leading_zeros());
    let levels = element_bits - 1;
    let ones = (size & levels) + 1;
    if ones == element_bits {
        return None;
    }
    let rotation = rotation & levels;
    // A valid run never fills a 64-bit element, so this shift cannot be 64.
    let run = (1u64 << ones) - 1;
    let rotated = if rotation == 0 {
        run
    } else {
        (run >> rotation) | (run << (element_bits - rotation))
    };
    let element = if element_bits == 64 {
        rotated
    } else {
        rotated & ((1u64 << element_bits) - 1)
    };
    let operand_bits = if width == Width::W32 { 32 } else { 64 };
    let mut mask = 0;
    for position in (0..operand_bits).step_by(element_bits as usize) {
        mask |= element << position;
    }
    Some(mask)
}

/// Bit 26 is set in every Advanced SIMD and floating-point encoding: the SIMD
/// and FP data-processing group and V=1 loads and stores. Clear words skip
/// those decoders.
const SIMD_FP: u32 = 1 << 26;

impl Lifter for Decoder {
    type Instruction = Instruction;
    fn lift(&self, pc: GuestAddress, word: u32) -> Result<Instruction, UnsupportedReason> {
        let unsupported = || UnsupportedReason::Instruction {
            address: pc,
            encoding: word,
        };
        let width = if word >> 31 == 0 {
            Width::W32
        } else {
            Width::X64
        };
        let target = |immediate: u32, bits: u32| {
            let signed = ((i64::from(immediate) << (64 - bits)) >> (64 - bits)) * 4;
            pc.0.checked_add_signed(signed)
                .map(GuestAddress)
                .ok_or_else(unsupported)
        };
        let shift = match (word >> 22) & 3 {
            0 => Shift::Lsl,
            1 => Shift::Lsr,
            2 => Shift::Asr,
            _ => Shift::Ror,
        };
        let amount = ((word >> 10) & 63) as u8;
        let simd_fp = word & SIMD_FP != 0;
        let operation = if word == 0xd65f03c0 {
            Operation::Return
        } else if word == 0xd503201f {
            Operation::Nop
        } else if let Some(decoded) = system::synchronization::decode(word).filter(|operation| {
            matches!(
                operation,
                system::synchronization::Operation::Yield
                    | system::synchronization::Operation::ConsumptionBarrier
                    | system::synchronization::Operation::SpeculationBarrier
            )
        }) {
            Operation::Synchronization(decoded)
        } else if let Some(decoded) = exclusive::decode(word) {
            Operation::Exclusive(decoded.map_err(|_| unsupported())?)
        } else if let Some(_reason) = constrained::decode(word) {
            // Pinned constrained outcomes select NOP under the declared FP-present,
            // unguarded-page/BTYPE=0 profile, before FP enablement or memory effects.
            Operation::Nop
        } else if let Some(decoded) = pc_relative::decode(pc, word) {
            Operation::PcRelative(decoded)
        } else if let Some(decoded) = bitfield::decode(word) {
            Operation::Bitfield(decoded)
        } else if let Some(decoded) = conditional_select::decode(word) {
            Operation::ConditionalSelect(decoded)
        } else if let Some(decoded) = conditional_select::decode_compare(word) {
            Operation::ConditionalCompare(decoded)
        } else if let Some(decoded) = crc::decode(word) {
            Operation::Crc(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = checked_pointer::decode(word) {
            Operation::CheckedPointer(decoded)
        } else if let Some(decoded) = flags::decode(word) {
            Operation::Flags(decoded)
        } else if simd_fp && let Some(decoded) = fp_register::decode(word) {
            Operation::FloatingPointRegister(decoded)
        } else if let Some(decoded) = integer_unary::decode(word) {
            Operation::IntegerUnary(decoded)
        } else if let Some(decoded) = integer_minmax::decode(word) {
            Operation::IntegerMinMax(decoded)
        } else if let Some(decoded) = tag_arithmetic::decode(word) {
            Operation::TagArithmetic(decoded)
        } else if let Some(decoded) = integer_math::decode(word) {
            Operation::IntegerMath(decoded.map_err(|()| unsupported())?)
        } else if simd_fp && let Some(decoded) = FloatingPointOperation::decode(word) {
            Operation::FloatingPoint(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = ordered::decode(word) {
            Operation::Ordered(decoded)
        } else if let Some(decoded) = atomic::decode(word) {
            Operation::Atomic(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = non_temporal::decode(word) {
            Operation::MemoryNonTemporal(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = unprivileged::decode(word) {
            Operation::MemoryUnprivileged(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = prefetch::decode(pc, word) {
            Operation::Prefetch(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = literal::decode(pc, word) {
            Operation::Literal(decoded.map_err(|()| unsupported())?)
        } else if simd_fp && let Some(decoded) = simd::decode(word) {
            Operation::Simd(decoded.map_err(|()| unsupported())?)
        } else if let Some(decoded) = register_offset::decode(word) {
            Operation::MemoryRegisterOffset(decoded.map_err(|()| unsupported())?)
        } else if word & 0x3e000000 == 0x28000000 {
            // Integer LDP/STP/LDPSW. SIMD, non-temporal pairs, tagged
            // stores and reserved opcodes are not interchangeable with these accesses.
            let opcode = word >> 30;
            let loading = word & (1 << 22) != 0;
            let bytes = match opcode {
                0 => 4,
                1 if loading => 4,
                2 => 8,
                _ => return Err(unsupported()),
            };
            let mode = match (word >> 23) & 3 {
                1 => AddressMode::PostIndex,
                2 => AddressMode::Offset,
                3 => AddressMode::PreIndex,
                _ => return Err(unsupported()),
            };
            let rn = (word >> 5) & 31;
            let rt = word & 31;
            let rt2 = (word >> 10) & 31;
            if (loading && rt == rt2)
                || (mode != AddressMode::Offset && rn != 31 && (rn == rt || rn == rt2))
            {
                return Err(unsupported());
            }
            let immediate = ((word >> 15) & 0x7f) as i32;
            Operation::MemoryPair {
                transfer: if loading {
                    MemoryTransfer::Load {
                        signed: opcode == 1,
                        width: if opcode == 0 { Width::W32 } else { Width::X64 },
                    }
                } else {
                    MemoryTransfer::Store
                },
                bytes,
                data: [register(rt, false), register(rt2, false)],
                base: register(rn, true),
                displacement: ((immediate << 25) >> 25) * i32::from(bytes),
                mode,
            }
        } else if word & 0x3f000000 == 0x39000000 || word & 0x3f200000 == 0x38000000 {
            // Scalar integer loads/stores only: VR=0. Reject PRFM, reserved
            // signed sizes, register offsets, atomics and unprivileged forms.
            let size = word >> 30;
            let transfer = match (word >> 22) & 3 {
                0 => MemoryTransfer::Store,
                1 => MemoryTransfer::Load {
                    signed: false,
                    width: if size == 3 { Width::X64 } else { Width::W32 },
                },
                2 if size < 3 => MemoryTransfer::Load {
                    signed: true,
                    width: Width::X64,
                },
                3 if size < 2 => MemoryTransfer::Load {
                    signed: true,
                    width: Width::W32,
                },
                _ => return Err(unsupported()),
            };
            let (displacement, mode) = if word & (1 << 24) != 0 {
                ((((word >> 10) & 0xfff) << size) as i32, AddressMode::Offset)
            } else {
                let immediate = ((word >> 12) & 0x1ff) as i32;
                let mode = match (word >> 10) & 3 {
                    0 => AddressMode::Offset,
                    1 => AddressMode::PostIndex,
                    3 => AddressMode::PreIndex,
                    _ => return Err(unsupported()),
                };
                ((immediate << 23) >> 23, mode)
            };
            let rn = (word >> 5) & 31;
            let rt = word & 31;
            // Writeback overlap has constrained-unpredictable semantics.
            // Reject it rather than choosing one possible architectural result.
            if mode != AddressMode::Offset && rn == rt && rn != 31 {
                return Err(unsupported());
            }
            Operation::Memory {
                transfer,
                bytes: 1 << size,
                data: register(rt, false),
                base: register(rn, true),
                displacement,
                mode,
            }
        } else if word & 0xfc000000 == 0x14000000 {
            Operation::Branch {
                target: target(word & 0x03ffffff, 26)?,
            }
        } else if word & CONDITIONAL_BRANCH_MASK == CONDITIONAL_BRANCH_CLASS {
            // B.cond and enabled FEAT_HBC BC.cond have identical architectural
            // effects. Bit 4 is only the consistent-direction prediction hint.
            Operation::BranchCondition {
                target: target((word >> 5) & 0x7ffff, 19)?,
                condition: (word & 15) as u8,
            }
        } else if word & 0x7e000000 == 0x34000000 {
            Operation::BranchZero {
                target: target((word >> 5) & 0x7ffff, 19)?,
                source: register(word & 31, false),
                width,
                nonzero: word & (1 << 24) != 0,
            }
        } else if word & 0x7e000000 == 0x36000000 {
            Operation::BranchBit {
                target: target((word >> 5) & 0x3fff, 14)?,
                source: register(word & 31, false),
                bit: (((word >> 26) & 32) | ((word >> 19) & 31)) as u8,
                nonzero: word & (1 << 24) != 0,
            }
        } else if word & 0x1fe0fc00 == 0x1a000000 {
            Operation::AddSubCarry {
                width,
                subtract: word & (1 << 30) != 0,
                flags: word & (1 << 29) != 0,
                destination: register(word & 31, false),
                left: register((word >> 5) & 31, false),
                right: register((word >> 16) & 31, false),
            }
        } else if word & 0x1fe00000 == 0x0b200000 {
            let amount = ((word >> 10) & 7) as u8;
            if amount > 4 {
                return Err(unsupported());
            }
            let flags = word & (1 << 29) != 0;
            let extend = match (word >> 13) & 7 {
                0 => RegisterExtend::Uxtb,
                1 => RegisterExtend::Uxth,
                2 => RegisterExtend::Uxtw,
                3 => RegisterExtend::Uxtx,
                4 => RegisterExtend::Sxtb,
                5 => RegisterExtend::Sxth,
                6 => RegisterExtend::Sxtw,
                _ => RegisterExtend::Sxtx,
            };
            Operation::AddSubExtended {
                width,
                subtract: word & (1 << 30) != 0,
                flags,
                destination: register(word & 31, !flags),
                left: register((word >> 5) & 31, true),
                right: register((word >> 16) & 31, false),
                extend,
                amount,
            }
        } else if word & 0x1f200000 == 0x0b000000 {
            if shift == Shift::Ror || (width == Width::W32 && amount >= 32) {
                return Err(unsupported());
            }
            Operation::AddSubRegister {
                width,
                subtract: word & (1 << 30) != 0,
                flags: word & (1 << 29) != 0,
                destination: register(word & 31, false),
                left: register((word >> 5) & 31, false),
                right: register((word >> 16) & 31, false),
                shift,
                amount,
            }
        } else if word & 0x1f000000 == 0x0a000000 {
            if width == Width::W32 && amount >= 32 {
                return Err(unsupported());
            }
            let opcode = (word >> 29) & 3;
            Operation::LogicalRegister {
                width,
                kind: match opcode {
                    0 | 3 => Logical::And,
                    1 => Logical::Or,
                    _ => Logical::Xor,
                },
                invert: word & (1 << 21) != 0,
                flags: opcode == 3,
                destination: register(word & 31, false),
                left: register((word >> 5) & 31, false),
                right: register((word >> 16) & 31, false),
                shift,
                amount,
            }
        } else if word & 0x1f800000 == 0x12000000 {
            let opcode = (word >> 29) & 3;
            Operation::LogicalImmediate {
                width,
                kind: match opcode {
                    0 | 3 => Logical::And,
                    1 => Logical::Or,
                    _ => Logical::Xor,
                },
                flags: opcode == 3,
                destination: register(word & 31, opcode != 3),
                source: register((word >> 5) & 31, false),
                immediate: logical_mask(
                    width,
                    (word >> 22) & 1,
                    (word >> 16) & 63,
                    (word >> 10) & 63,
                )
                .ok_or_else(unsupported)?,
            }
        } else if word & 0x1f800000 == 0x12800000 {
            let kind = match (word >> 29) & 3 {
                0 => WideMove::Not,
                2 => WideMove::Zero,
                3 => WideMove::Keep,
                _ => return Err(unsupported()),
            };
            let shift = (((word >> 21) & 3) * 16) as u8;
            if width == Width::W32 && shift >= 32 {
                return Err(unsupported());
            }
            Operation::MoveWide {
                width,
                kind,
                destination: register(word & 31, false),
                immediate: ((word >> 5) & 0xffff) as u16,
                shift,
            }
        } else if word & 0x1f800000 == 0x11000000 {
            let flags = word & (1 << 29) != 0;
            let immediate = ((word >> 10) & 0xfff) << if word & (1 << 22) != 0 { 12 } else { 0 };
            Operation::AddSub {
                width,
                subtract: word & (1 << 30) != 0,
                flags,
                destination: register(word & 31, !flags),
                source: register((word >> 5) & 31, true),
                immediate,
            }
        } else {
            return Err(unsupported());
        };
        Ok(Instruction { pc, operation })
    }
}

#[cfg(test)]
mod tests;
