//! Packed SSE2/checked-SSSE3 kernels for predicated scalable integer bit operations.
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, Predication, VectorLength},
        sve::integer_bits::{Kind, Operand},
    },
    x86_64::{
        isa::{ShiftOpcode as Shift, SimdOpcode as Host},
        scalable::{load_z_chunk, read_predicate_mask, store_z_chunk},
    },
};

mod scalar;

const ALTERNATING_BIT_MASK: u8 = 0x55;
const TWO_BIT_GROUP_MASK: u8 = 0x33;
const SCALAR_WORD_VECTOR_BYTES: usize = 256;
const MOV_RAX_IMM64: [u8; 2] = [0x48, 0xb8];
const PSADBW: [u8; 3] = [0x66, 0x0f, 0xf6];
const REGISTER_MODRM: u8 = 0xc0;
const SOURCE_XMM: u8 = 0;
const OLD_DESTINATION_XMM: u8 = 7;
const PREDICATE_XMM: u8 = 6;
const PREDICATE_SCRATCH_XMM: u8 = 5;
const BYTE_BITS: u8 = u8::BITS as u8;
const NIBBLE_BITS: u8 = BYTE_BITS / 2;
const DWORD_SIGN_SHIFT: u8 = u32::BITS as u8 - 1;
const QWORD_BYTES: usize = std::mem::size_of::<u64>();
const LOW_NIBBLE: u8 = 0x0f;
const SWAP_ADJACENT: u8 = 0xb1;
const REVERSE_FOUR: u8 = 0x1b;
const DUPLICATE_HIGH_DWORDS: u8 = 0xf5;

fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn constant_qword(code: &mut Vec<u8>, destination: u8, value: u64) {
    code.extend(MOV_RAX_IMM64);
    code.extend(value.to_le_bytes());
    packed(code, Host::MoveGprQword, destination, 0);
}

fn repeated_constant(code: &mut Vec<u8>, destination: u8, element: ElementSize, value: u64) {
    let source = value.to_le_bytes();
    let repeated = std::array::from_fn(|i| source[i % element.bytes()]);
    constant_qword(code, destination, u64::from_le_bytes(repeated));
    packed(code, Host::UnpackLowQword, destination, destination);
}

fn table_constant(code: &mut Vec<u8>, destination: u8, scratch: u8, values: [u8; 16]) {
    constant_qword(
        code,
        destination,
        u64::from_le_bytes(values[..QWORD_BYTES].try_into().unwrap()),
    );
    constant_qword(
        code,
        scratch,
        u64::from_le_bytes(values[QWORD_BYTES..].try_into().unwrap()),
    );
    packed(code, Host::UnpackLowQword, destination, scratch);
}

fn shuffle(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8, control: u8) {
    packed(code, opcode, destination, source);
    code.push(control);
}

fn add(element: ElementSize) -> Host {
    match element {
        ElementSize::Byte => Host::AddByte,
        ElementSize::Halfword => Host::AddWord,
        ElementSize::Word => Host::AddDword,
        ElementSize::Doubleword => Host::AddQword,
        ElementSize::Quadword => unreachable!("bit-operation decoder excludes 128-bit elements"),
    }
}

fn subtract(element: ElementSize) -> Host {
    match element {
        ElementSize::Byte => Host::SubByte,
        ElementSize::Halfword => Host::SubWord,
        ElementSize::Word => Host::SubDword,
        ElementSize::Doubleword => Host::SubQword,
        ElementSize::Quadword => unreachable!("bit-operation decoder excludes 128-bit elements"),
    }
}

/// Immediate logical element shifts. SSE2 byte shifts need a post-shift mask.
fn logical_shift(code: &mut Vec<u8>, xmm: u8, element: ElementSize, amount: u8, left: bool) {
    let opcode = match (element, left) {
        (ElementSize::Byte | ElementSize::Halfword, false) => Shift::RightWord,
        (ElementSize::Byte | ElementSize::Halfword, true) => Shift::LeftWord,
        (ElementSize::Word, false) => Shift::RightDword,
        (ElementSize::Word, true) => Shift::LeftDword,
        (ElementSize::Doubleword, false) => Shift::RightQword,
        (ElementSize::Doubleword, true) => Shift::LeftQword,
        (ElementSize::Quadword, _) => unreachable!("bit-operation decoder element"),
    };
    opcode.emit(code, xmm, amount);
    if element == ElementSize::Byte {
        let mask = if left {
            u8::MAX << amount
        } else {
            u8::MAX >> amount
        };
        repeated_constant(code, 6, ElementSize::Byte, u64::from(mask));
        packed(code, Host::And, xmm, 6);
    }
}

/// Compare against zero in XMM3. Qword equality requires both dwords to match.
fn equal_zero(code: &mut Vec<u8>, xmm: u8, element: ElementSize, target: TargetCpu) {
    if element == ElementSize::Doubleword && target.supports(TargetCpu::Sse41) {
        Host::EqualQword.register(code, xmm, 3, target);
        return;
    }
    let opcode = match element {
        ElementSize::Byte => Host::EqualByte,
        ElementSize::Halfword => Host::EqualWord,
        ElementSize::Word | ElementSize::Doubleword => Host::EqualDword,
        ElementSize::Quadword => unreachable!("bit-operation decoder element"),
    };
    packed(code, opcode, xmm, 3);
    if element == ElementSize::Doubleword {
        shuffle(code, Host::ShuffleDword, 4, xmm, SWAP_ADJACENT);
        packed(code, Host::And, xmm, 4);
    }
}

fn leading_count(code: &mut Vec<u8>, element: ElementSize, sign: bool, target: TargetCpu) {
    if sign {
        if element == ElementSize::Doubleword {
            packed(code, Host::MoveAligned, 1, SOURCE_XMM);
            Shift::ArithmeticDword.emit(code, 1, DWORD_SIGN_SHIFT);
            shuffle(code, Host::ShuffleDword, 1, 1, DUPLICATE_HIGH_DWORDS);
        } else {
            packed(code, Host::Xor, 1, 1);
            let compare = match element {
                ElementSize::Byte => Host::GreaterByte,
                ElementSize::Halfword => Host::GreaterWord,
                ElementSize::Word => Host::GreaterDword,
                _ => unreachable!("non-qword bit-operation element"),
            };
            packed(code, compare, 1, SOURCE_XMM);
        }
        packed(code, Host::Xor, SOURCE_XMM, 1);
    }
    packed(code, Host::Xor, 2, 2);
    packed(code, Host::Xor, 3, 3);
    let bits = element.bits() as u8;
    let mut step = bits / 2;
    while step != 0 {
        packed(code, Host::MoveAligned, 1, SOURCE_XMM);
        logical_shift(code, 1, element, bits - step, false);
        equal_zero(code, 1, element, target);
        repeated_constant(code, 4, element, u64::from(step));
        packed(code, Host::And, 4, 1);
        packed(code, add(element), 2, 4);
        packed(code, Host::MoveAligned, 4, SOURCE_XMM);
        logical_shift(code, 4, element, step, true);
        packed(code, Host::Xor, 4, SOURCE_XMM);
        packed(code, Host::And, 4, 1);
        packed(code, Host::Xor, SOURCE_XMM, 4);
        step /= 2;
    }
    equal_zero(code, SOURCE_XMM, element, target);
    repeated_constant(code, 1, element, 1);
    packed(code, Host::And, SOURCE_XMM, 1);
    packed(code, add(element), 2, SOURCE_XMM);
    if sign {
        packed(code, subtract(element), 2, 1);
    }
    packed(code, Host::MoveAligned, SOURCE_XMM, 2);
}

fn nibble_lookup(code: &mut Vec<u8>, reverse: bool, target: TargetCpu) {
    let values = std::array::from_fn(|i| {
        if reverse {
            (i as u8).reverse_bits() >> NIBBLE_BITS
        } else {
            (i as u8).count_ones() as u8
        }
    });
    table_constant(code, 2, 5, values);
    packed(code, Host::MoveAligned, 4, 2);
    packed(code, Host::MoveAligned, 1, SOURCE_XMM);
    repeated_constant(code, 3, ElementSize::Byte, u64::from(LOW_NIBBLE));
    packed(code, Host::And, SOURCE_XMM, 3);
    Shift::RightWord.emit(code, 1, NIBBLE_BITS);
    packed(code, Host::And, 1, 3);
    Host::ByteShuffle.register(code, 2, SOURCE_XMM, target);
    Host::ByteShuffle.register(code, 4, 1, target);
    if reverse {
        Shift::LeftWord.emit(code, 2, NIBBLE_BITS);
        packed(code, Host::Or, 2, 4);
    } else {
        packed(code, Host::AddByte, 2, 4);
    }
    packed(code, Host::MoveAligned, SOURCE_XMM, 2);
}

fn population_bytes(code: &mut Vec<u8>, target: TargetCpu) {
    if target.supports(TargetCpu::Ssse3) {
        nibble_lookup(code, false, target);
        return;
    }
    packed(code, Host::MoveAligned, 1, SOURCE_XMM);
    Shift::RightWord.emit(code, 1, 1);
    repeated_constant(code, 2, ElementSize::Byte, u64::from(ALTERNATING_BIT_MASK));
    packed(code, Host::And, 1, 2);
    packed(code, Host::SubByte, SOURCE_XMM, 1);
    packed(code, Host::MoveAligned, 1, SOURCE_XMM);
    Shift::RightWord.emit(code, 1, 2);
    repeated_constant(code, 2, ElementSize::Byte, u64::from(TWO_BIT_GROUP_MASK));
    packed(code, Host::And, SOURCE_XMM, 2);
    packed(code, Host::And, 1, 2);
    packed(code, Host::AddByte, SOURCE_XMM, 1);
    packed(code, Host::MoveAligned, 1, SOURCE_XMM);
    Shift::RightWord.emit(code, 1, NIBBLE_BITS);
    packed(code, Host::AddByte, SOURCE_XMM, 1);
    repeated_constant(code, 2, ElementSize::Byte, u64::from(LOW_NIBBLE));
    packed(code, Host::And, SOURCE_XMM, 2);
}

fn population(code: &mut Vec<u8>, element: ElementSize, target: TargetCpu) {
    population_bytes(code, target);
    if element == ElementSize::Doubleword {
        packed(code, Host::Xor, 1, 1);
        code.extend(PSADBW);
        code.push(REGISTER_MODRM | (SOURCE_XMM << 3) | 1);
        return;
    }
    for (width, shift, mask) in [
        (ElementSize::Halfword, BYTE_BITS, u64::from(u8::MAX)),
        (ElementSize::Word, 2 * BYTE_BITS, u64::from(u16::MAX)),
    ] {
        if element < width {
            break;
        }
        packed(code, Host::MoveAligned, 1, SOURCE_XMM);
        logical_shift(code, 1, width, shift, false);
        repeated_constant(code, 2, width, mask);
        packed(code, Host::And, SOURCE_XMM, 2);
        packed(code, add(width), SOURCE_XMM, 1);
    }
}

fn reverse_groups(code: &mut Vec<u8>, element: ElementSize, group: ElementSize) {
    if group == ElementSize::Byte {
        packed(code, Host::MoveAligned, 1, SOURCE_XMM);
        Shift::RightWord.emit(code, 1, BYTE_BITS);
        Shift::LeftWord.emit(code, SOURCE_XMM, BYTE_BITS);
        packed(code, Host::Or, SOURCE_XMM, 1);
    }
    if group <= ElementSize::Halfword && element >= ElementSize::Word {
        let control = if element == ElementSize::Word {
            SWAP_ADJACENT
        } else {
            REVERSE_FOUR
        };
        shuffle(code, Host::ShuffleLowWord, SOURCE_XMM, SOURCE_XMM, control);
        shuffle(code, Host::ShuffleHighWord, SOURCE_XMM, SOURCE_XMM, control);
    } else if group == ElementSize::Word {
        shuffle(
            code,
            Host::ShuffleDword,
            SOURCE_XMM,
            SOURCE_XMM,
            SWAP_ADJACENT,
        );
    }
}

fn reverse_bits(code: &mut Vec<u8>, element: ElementSize, target: TargetCpu) {
    if target.supports(TargetCpu::Ssse3) {
        nibble_lookup(code, true, target);
    } else {
        const BIT_SWAP_STAGES: [(u8, u8); 3] = [
            (1, ALTERNATING_BIT_MASK),
            (2, TWO_BIT_GROUP_MASK),
            (NIBBLE_BITS, LOW_NIBBLE),
        ];
        for (amount, mask) in BIT_SWAP_STAGES {
            packed(code, Host::MoveAligned, 1, SOURCE_XMM);
            Shift::RightWord.emit(code, 1, amount);
            repeated_constant(code, 2, ElementSize::Byte, u64::from(mask));
            packed(code, Host::And, 1, 2);
            packed(code, Host::And, SOURCE_XMM, 2);
            Shift::LeftWord.emit(code, SOURCE_XMM, amount);
            packed(code, Host::Or, SOURCE_XMM, 1);
        }
    }
    if element != ElementSize::Byte {
        reverse_groups(code, element, ElementSize::Byte);
    }
}

/// The selected BSR leading-count recipe requires an explicit DIT=0 profile.
/// Fixed-work packed recipes retain the existing profile admission.
pub(crate) fn requires_declared_dit_zero(operand: Operand, length: VectorLength) -> bool {
    matches!(operand.kind, Kind::LeadingSignBits | Kind::LeadingZeros)
        && (operand.element_size == ElementSize::Doubleword
            || (operand.element_size == ElementSize::Word
                && length.bytes() == SCALAR_WORD_VECTOR_BYTES))
}

pub fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    let Predication::Merging(predicate) = operand.predication else {
        unreachable!("bit-operation decoder owns only merging forms");
    };
    for chunk in 0..length.chunks() {
        load_z_chunk(code, operand.source, chunk, SOURCE_XMM, length, target);
        match operand.kind {
            Kind::LeadingSignBits | Kind::LeadingZeros => {
                let sign = operand.kind == Kind::LeadingSignBits;
                if requires_declared_dit_zero(operand, length) {
                    scalar::chunk(code, operand.element_size, sign);
                } else {
                    leading_count(code, operand.element_size, sign, target);
                }
            }
            Kind::PopulationCount => population(code, operand.element_size, target),
            Kind::ReverseBits => reverse_bits(code, operand.element_size, target),
            Kind::ReverseGroups { group_size } => {
                reverse_groups(code, operand.element_size, group_size)
            }
        }
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            OLD_DESTINATION_XMM,
            length,
            target,
        );
        read_predicate_mask(
            code,
            predicate,
            chunk,
            operand.element_size,
            PREDICATE_XMM,
            PREDICATE_SCRATCH_XMM,
            length,
            target,
        );
        // old XOR ((new XOR old) AND active-mask), preserving inactive bytes.
        packed(code, Host::Xor, SOURCE_XMM, OLD_DESTINATION_XMM);
        packed(code, Host::And, SOURCE_XMM, PREDICATE_XMM);
        packed(code, Host::Xor, SOURCE_XMM, OLD_DESTINATION_XMM);
        store_z_chunk(code, operand.destination, chunk, SOURCE_XMM, length, target);
    }
}
