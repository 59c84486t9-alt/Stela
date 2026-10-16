//! SVE unpacks and pairwise arithmetic. Sources are read before each destination
//! chunk is written.
use crate::TargetCpu;
use crate::aarch64::scalable::{ElementSize, Predication, VECTOR_CHUNK_BYTES, VectorLength};
use crate::aarch64::sve::integer_arithmetic::Binary;
use crate::aarch64::sve::rearrange_widen::{
    Arithmetic, Half, Kind, Operand, PairOperation, Signedness,
};
use crate::x86_64::isa::{ShiftOpcode, SimdOpcode as Host};
use crate::x86_64::scalable::{load_z_chunk, read_predicate_mask, store_z_chunk};
use crate::x86_64::sve::integer_arithmetic::emit_binary_chunk;
use alloc::vec::Vec;

const RESULT: u8 = 0;
const RIGHT: u8 = 1;
const TEMPORARY: u8 = 2;
const AUXILIARY: u8 = 3;
const CONSTANT: u8 = 4;
const PREDICATE: u8 = 5;
const PREDICATE_SCRATCH: u8 = 6;
const PREVIOUS: u8 = 7;
const QWORD_BYTES: usize = 8;
const QWORD_BITS: usize = QWORD_BYTES * 8;
const DWORD_BITS: u8 = 32;
const DWORD_SIGN_SHIFT: u8 = DWORD_BITS - 1;
const MODRM_REGISTER: u8 = 0xc0;
const REGISTER_SHIFT: u8 = 3;
const MOVABS_RAX: [u8; 2] = [0x48, 0xb8];
const SELECT_EVEN_DWORDS: u8 = 0x88;
const SELECT_ODD_DWORDS: u8 = 0xdd;
const REPEAT_HIGH_DWORDS: u8 = 0xf5;
const INTERLEAVE_PAIR_SUMS: u8 = 0xd8;
const EVEN_ODD_WORD_GROUPS: u8 = 0xd8;
const LOW_BYTE_MASK: u64 = 0x00ff_00ff_00ff_00ff;
const LOW_DWORD_MASK: u64 = 0x0000_0000_ffff_ffff;
const BYTE_WEIGHTS: u64 = 0x0101_0101_0101_0101;
const WORD_WEIGHTS: u64 = 0x0001_0001_0001_0001;

fn packed(code: &mut Vec<u8>, opcode: Host, destination: u8, source: u8) {
    opcode.register(code, destination, source, TargetCpu::Baseline);
}

fn copy(code: &mut Vec<u8>, destination: u8, source: u8) {
    packed(code, Host::MoveAligned, destination, source);
}

fn qword_constant(code: &mut Vec<u8>, destination: u8, value: u64) {
    code.extend(MOVABS_RAX);
    code.extend(value.to_le_bytes());
    Host::MoveGprQword.append(code, TargetCpu::Baseline);
    code.push(MODRM_REGISTER | destination << REGISTER_SHIFT);
}

fn constant(code: &mut Vec<u8>, destination: u8, value: u64) {
    qword_constant(code, destination, value);
    packed(code, Host::UnpackLowQword, destination, destination);
}

fn constant_bytes(code: &mut Vec<u8>, destination: u8, value: [u8; VECTOR_CHUNK_BYTES]) {
    let low = u64::from_le_bytes(value[..QWORD_BYTES].try_into().unwrap());
    let high = u64::from_le_bytes(value[QWORD_BYTES..].try_into().unwrap());
    qword_constant(code, destination, low);
    qword_constant(code, TEMPORARY, high);
    packed(code, Host::UnpackLowQword, destination, TEMPORARY);
}

fn repeated(value: u64, bits: usize) -> u64 {
    if bits == QWORD_BITS {
        return value;
    }
    let value = value & ((1u64 << bits) - 1);
    (0..QWORD_BITS / bits).fold(0, |result, lane| result | value << (lane * bits))
}

fn add(element: ElementSize) -> Host {
    match element {
        ElementSize::Byte => Host::AddByte,
        ElementSize::Halfword => Host::AddWord,
        ElementSize::Word => Host::AddDword,
        ElementSize::Doubleword => Host::AddQword,
        ElementSize::Quadword => unreachable!("integer decoder excludes quadwords"),
    }
}

fn subtract(element: ElementSize) -> Host {
    match element {
        ElementSize::Byte => Host::SubByte,
        ElementSize::Halfword => Host::SubWord,
        ElementSize::Word => Host::SubDword,
        ElementSize::Doubleword => Host::SubQword,
        ElementSize::Quadword => unreachable!("integer decoder excludes quadwords"),
    }
}

fn left_shift(element: ElementSize) -> ShiftOpcode {
    match element {
        ElementSize::Halfword => ShiftOpcode::LeftWord,
        ElementSize::Word => ShiftOpcode::LeftDword,
        ElementSize::Doubleword => ShiftOpcode::LeftQword,
        _ => unreachable!("widening decoder excludes byte and quadword results"),
    }
}

fn right_shift(element: ElementSize) -> ShiftOpcode {
    match element {
        ElementSize::Halfword => ShiftOpcode::RightWord,
        ElementSize::Word => ShiftOpcode::RightDword,
        ElementSize::Doubleword => ShiftOpcode::RightQword,
        _ => unreachable!("widening decoder excludes byte and quadword results"),
    }
}

fn shuffle(code: &mut Vec<u8>, destination: u8, source: u8, immediate: u8) {
    packed(code, Host::ShuffleDword, destination, source);
    code.push(immediate);
}

fn signed_qword(code: &mut Vec<u8>, destination: u8, input_size: ElementSize, target: TargetCpu) {
    if target.supports(TargetCpu::Sse41) {
        if input_size != ElementSize::Word {
            let shift = (ElementSize::Word.bits() - input_size.bits()) as u8;
            ShiftOpcode::LeftDword.emit(code, destination, shift);
            ShiftOpcode::ArithmeticDword.emit(code, destination, shift);
        }
        shuffle(code, destination, destination, SELECT_EVEN_DWORDS);
        Host::SignExtendDwordToQword.register(code, destination, destination, target);
    } else {
        let shift = (ElementSize::Doubleword.bits() - input_size.bits()) as u8;
        ShiftOpcode::LeftQword.emit(code, destination, shift);
        shuffle(code, TEMPORARY, destination, REPEAT_HIGH_DWORDS);
        ShiftOpcode::ArithmeticDword.emit(code, TEMPORARY, DWORD_SIGN_SHIFT);
        ShiftOpcode::RightQword.emit(code, destination, shift);
        ShiftOpcode::LeftQword.emit(code, TEMPORARY, input_size.bits() as u8);
        packed(code, Host::Or, destination, TEMPORARY);
    }
}

fn extension(
    code: &mut Vec<u8>,
    element: ElementSize,
    input_size: ElementSize,
    signedness: Signedness,
    target: TargetCpu,
) {
    if signedness == Signedness::Unsigned {
        constant(
            code,
            CONSTANT,
            repeated((1u64 << input_size.bits()) - 1, element.bits()),
        );
        packed(code, Host::And, RESULT, CONSTANT);
        return;
    }
    if element == ElementSize::Doubleword {
        signed_qword(code, RESULT, input_size, target);
        return;
    }
    let shift = (element.bits() - input_size.bits()) as u8;
    left_shift(element).emit(code, RESULT, shift);
    match element {
        ElementSize::Halfword => ShiftOpcode::ArithmeticWord,
        ElementSize::Word => ShiftOpcode::ArithmeticDword,
        _ => unreachable!("qword extension handled separately"),
    }
    .emit(code, RESULT, shift);
}

fn unpack(code: &mut Vec<u8>, element: ElementSize, signedness: Signedness, target: TargetCpu) {
    let checked = match (element, signedness) {
        (ElementSize::Word, Signedness::Signed) => Some(Host::SignExtendWordToDword),
        (ElementSize::Word, Signedness::Unsigned) => Some(Host::ZeroExtendWordToDword),
        (ElementSize::Doubleword, Signedness::Signed) => Some(Host::SignExtendDwordToQword),
        (ElementSize::Doubleword, Signedness::Unsigned) => Some(Host::ZeroExtendDwordToQword),
        _ => None,
    };
    if let Some(opcode) = checked.filter(|opcode| target.supports(opcode.requires())) {
        opcode.register(code, RESULT, RESULT, target);
        return;
    }
    packed(code, Host::Xor, RIGHT, RIGHT);
    if signedness == Signedness::Signed {
        packed(
            code,
            match element {
                ElementSize::Halfword => Host::GreaterByte,
                ElementSize::Word => Host::GreaterWord,
                ElementSize::Doubleword => Host::GreaterDword,
                _ => unreachable!("unpack output element allocation"),
            },
            RIGHT,
            RESULT,
        );
    }
    packed(
        code,
        match element {
            ElementSize::Halfword => Host::UnpackLowByte,
            ElementSize::Word => Host::UnpackLowWord,
            ElementSize::Doubleword => Host::UnpackLowDword,
            _ => unreachable!("unpack output element allocation"),
        },
        RESULT,
        RIGHT,
    );
}

fn narrow(
    code: &mut Vec<u8>,
    element: ElementSize,
    arithmetic: Arithmetic,
    round: bool,
    half: Half,
) {
    packed(
        code,
        if arithmetic == Arithmetic::Add {
            add(element)
        } else {
            subtract(element)
        },
        RESULT,
        RIGHT,
    );
    if round {
        packed(code, add(element), RESULT, CONSTANT);
    }
    if half == Half::Bottom {
        right_shift(element).emit(code, RESULT, (element.bits() / 2) as u8);
    } else {
        // Computed high fields are already at their final odd-half positions.
        packed(code, Host::And, RESULT, AUXILIARY);
        packed(code, Host::AndNot, AUXILIARY, PREVIOUS);
        packed(code, Host::Or, RESULT, AUXILIARY);
    }
}

fn signed_pair_dwords(code: &mut Vec<u8>, target: TargetCpu) {
    copy(code, RIGHT, RESULT);
    if target.supports(TargetCpu::Sse41) {
        shuffle(code, RESULT, RESULT, SELECT_EVEN_DWORDS);
        shuffle(code, RIGHT, RIGHT, SELECT_ODD_DWORDS);
        Host::SignExtendDwordToQword.register(code, RESULT, RESULT, target);
        Host::SignExtendDwordToQword.register(code, RIGHT, RIGHT, target);
        packed(code, Host::AddQword, RESULT, RIGHT);
        return;
    }
    // Sum unsigned dwords, then subtract 2^32 for each negative signed input.
    packed(code, Host::Xor, TEMPORARY, TEMPORARY);
    packed(code, Host::GreaterDword, TEMPORARY, RESULT);
    ShiftOpcode::RightDword.emit(code, TEMPORARY, DWORD_SIGN_SHIFT);
    copy(code, AUXILIARY, TEMPORARY);
    ShiftOpcode::RightQword.emit(code, TEMPORARY, DWORD_BITS);
    packed(code, Host::And, AUXILIARY, CONSTANT);
    packed(code, Host::AddQword, AUXILIARY, TEMPORARY);
    ShiftOpcode::LeftQword.emit(code, AUXILIARY, DWORD_BITS);
    packed(code, Host::And, RESULT, CONSTANT);
    ShiftOpcode::RightQword.emit(code, RIGHT, DWORD_BITS);
    packed(code, Host::AddQword, RESULT, RIGHT);
    packed(code, Host::SubQword, RESULT, AUXILIARY);
}

fn pair_delta(code: &mut Vec<u8>, element: ElementSize, signedness: Signedness, target: TargetCpu) {
    if element == ElementSize::Halfword && target.supports(TargetCpu::Ssse3) {
        if signedness == Signedness::Signed {
            // Unsigned weights times signed data: saturation cannot occur.
            copy(code, RIGHT, CONSTANT);
            Host::MultiplyAddUnsignedBytes.register(code, RIGHT, RESULT, target);
            copy(code, RESULT, RIGHT);
        } else {
            Host::MultiplyAddUnsignedBytes.register(code, RESULT, CONSTANT, target);
        }
        return;
    }
    if element == ElementSize::Word && signedness == Signedness::Signed {
        packed(code, Host::MultiplyAddWords, RESULT, CONSTANT);
        return;
    }
    if element == ElementSize::Doubleword && signedness == Signedness::Signed {
        signed_pair_dwords(code, target);
        return;
    }
    copy(code, RIGHT, RESULT);
    if signedness == Signedness::Signed {
        // The only remaining signed arrangement is paired bytes to halfwords.
        ShiftOpcode::LeftWord.emit(code, RESULT, 8);
        ShiftOpcode::ArithmeticWord.emit(code, RESULT, 8);
        ShiftOpcode::ArithmeticWord.emit(code, RIGHT, 8);
    } else {
        packed(code, Host::And, RESULT, CONSTANT);
        right_shift(element).emit(code, RIGHT, (element.bits() / 2) as u8);
    }
    packed(code, add(element), RESULT, RIGHT);
}

fn gather_even_odd(code: &mut Vec<u8>, register: u8, element: ElementSize, target: TargetCpu) {
    if target.supports(TargetCpu::Ssse3) {
        Host::ByteShuffle.register(code, register, CONSTANT, target);
    } else if element == ElementSize::Byte {
        copy(code, TEMPORARY, register);
        packed(code, Host::And, register, CONSTANT);
        ShiftOpcode::RightWord.emit(code, TEMPORARY, 8);
        // Every input word is 0..255, so PACKUSWB never saturates.
        packed(code, Host::PackUnsignedWordToByte, register, TEMPORARY);
    } else {
        Host::ShuffleLowWord.register(code, register, register, target);
        code.push(EVEN_ODD_WORD_GROUPS);
        Host::ShuffleHighWord.register(code, register, register, target);
        code.push(EVEN_ODD_WORD_GROUPS);
        shuffle(code, register, register, EVEN_ODD_WORD_GROUPS);
    }
}

fn pair_inputs(code: &mut Vec<u8>, element: ElementSize, target: TargetCpu) {
    if matches!(element, ElementSize::Byte | ElementSize::Halfword) {
        if target.supports(TargetCpu::Ssse3) {
            let mut shuffle_bytes = [0; VECTOR_CHUNK_BYTES];
            let lanes = VECTOR_CHUNK_BYTES / element.bytes();
            for lane in 0..lanes {
                let input_lane = (lane % (lanes / 2)) * 2 + lane / (lanes / 2);
                for byte in 0..element.bytes() {
                    shuffle_bytes[lane * element.bytes() + byte] =
                        (input_lane * element.bytes() + byte) as u8;
                }
            }
            constant_bytes(code, CONSTANT, shuffle_bytes);
        } else if element == ElementSize::Byte {
            constant(code, CONSTANT, LOW_BYTE_MASK);
        }
        gather_even_odd(code, RESULT, element, target);
        gather_even_odd(code, RIGHT, element, target);
    }
    copy(code, TEMPORARY, RESULT);
    let (low, high) = match element {
        ElementSize::Byte => (Host::UnpackLowByte, Host::UnpackHighByte),
        ElementSize::Halfword => (Host::UnpackLowWord, Host::UnpackHighWord),
        ElementSize::Word => (Host::UnpackLowDword, Host::UnpackHighDword),
        ElementSize::Doubleword => (Host::UnpackLowQword, Host::UnpackHighQword),
        ElementSize::Quadword => unreachable!("pair decoder excludes quadwords"),
    };
    packed(code, low, RESULT, RIGHT);
    packed(code, high, TEMPORARY, RIGHT);
    if element == ElementSize::Word {
        copy(code, RIGHT, RESULT);
        packed(code, Host::UnpackLowQword, RESULT, TEMPORARY);
        packed(code, Host::UnpackHighQword, RIGHT, TEMPORARY);
    } else {
        copy(code, RIGHT, TEMPORARY);
    }
}

fn pair(code: &mut Vec<u8>, element: ElementSize, operation: PairOperation, target: TargetCpu) {
    if operation == PairOperation::Add
        && element == ElementSize::Word
        && target.supports(TargetCpu::Ssse3)
    {
        Host::HorizontalAddDword.register(code, RESULT, RIGHT, target);
        shuffle(code, RESULT, RESULT, INTERLEAVE_PAIR_SUMS);
        return;
    }
    pair_inputs(code, element, target);
    let operation = match operation {
        PairOperation::Add => Binary::Add,
        PairOperation::Minimum(signedness) => Binary::Minimum {
            unsigned: signedness == Signedness::Unsigned,
        },
        PairOperation::Maximum(signedness) => Binary::Maximum {
            unsigned: signedness == Signedness::Unsigned,
        },
    };
    emit_binary_chunk(code, operation, element, target);
}

fn merge(
    code: &mut Vec<u8>,
    predicate: u8,
    chunk: usize,
    operand: Operand,
    length: VectorLength,
    target: TargetCpu,
) {
    read_predicate_mask(
        code,
        predicate,
        chunk,
        operand.element_size,
        PREDICATE,
        PREDICATE_SCRATCH,
        length,
        target,
    );
    packed(code, Host::And, RESULT, PREDICATE);
    packed(code, Host::AndNot, PREDICATE, PREVIOUS);
    packed(code, Host::Or, RESULT, PREDICATE);
}

// Complete-body measurements favor these SSE2 recipes despite available extensions.
fn recipe_target(operand: Operand, length: VectorLength, target: TargetCpu) -> TargetCpu {
    let prefer_baseline = match operand.kind {
        Kind::Unpack {
            signedness: Signedness::Unsigned,
            ..
        } => true,
        Kind::Pair {
            operation: PairOperation::Add,
            ..
        } => operand.element_size == ElementSize::Halfword && length.chunks() > 1,
        Kind::PairAccumulate {
            signedness: Signedness::Signed,
            ..
        } => operand.element_size == ElementSize::Halfword && length.chunks() == 1,
        _ => false,
    };
    if prefer_baseline {
        TargetCpu::Baseline
    } else {
        target
    }
}

pub fn emit(code: &mut Vec<u8>, operand: Operand, length: VectorLength, target: TargetCpu) {
    let target = recipe_target(operand, length, target);
    if let Kind::Unpack {
        source,
        signedness,
        half,
    } = operand.kind
    {
        let chunks = length.chunks();
        for index in 0..chunks {
            // Expanding the low half in place must consume its compact bytes backwards.
            let chunk = if half == Half::Bottom {
                chunks - 1 - index
            } else {
                index
            };
            let offset = chunk * QWORD_BYTES
                + if half == Half::Top {
                    length.bytes() / 2
                } else {
                    0
                };
            load_z_chunk(
                code,
                source,
                offset / VECTOR_CHUNK_BYTES,
                RESULT,
                length,
                target,
            );
            if !offset.is_multiple_of(VECTOR_CHUNK_BYTES) {
                ShiftOpcode::RightBytes.emit(code, RESULT, QWORD_BYTES as u8);
            }
            unpack(code, operand.element_size, signedness, target);
            store_z_chunk(code, operand.destination, chunk, RESULT, length, target);
        }
        return;
    }
    for chunk in 0..length.chunks() {
        match operand.kind {
            Kind::Extend {
                source,
                input_size,
                signedness,
            } => {
                load_z_chunk(code, source, chunk, RESULT, length, target);
                extension(code, operand.element_size, input_size, signedness, target);
            }
            Kind::NarrowHigh {
                left,
                right,
                arithmetic,
                round,
                half,
            } => {
                load_z_chunk(code, left, chunk, RESULT, length, target);
                load_z_chunk(code, right, chunk, RIGHT, length, target);
                if round {
                    constant(
                        code,
                        CONSTANT,
                        repeated(
                            1 << (operand.element_size.bits() / 2 - 1),
                            operand.element_size.bits(),
                        ),
                    );
                }
                if half == Half::Top {
                    constant(
                        code,
                        AUXILIARY,
                        repeated(
                            ((1u64 << (operand.element_size.bits() / 2)) - 1)
                                << (operand.element_size.bits() / 2),
                            operand.element_size.bits(),
                        ),
                    );
                    load_z_chunk(code, operand.destination, chunk, PREVIOUS, length, target);
                }
                narrow(code, operand.element_size, arithmetic, round, half);
            }
            Kind::Pair { right, operation } => {
                load_z_chunk(code, operand.destination, chunk, RESULT, length, target);
                load_z_chunk(code, right, chunk, RIGHT, length, target);
                pair(code, operand.element_size, operation, target);
            }
            Kind::PairAccumulate { source, signedness } => {
                load_z_chunk(code, source, chunk, RESULT, length, target);
                if chunk == 0 {
                    let constant_value = match (operand.element_size, signedness) {
                        (ElementSize::Halfword, Signedness::Signed)
                            if !target.supports(TargetCpu::Ssse3) =>
                        {
                            None
                        }
                        (ElementSize::Doubleword, Signedness::Signed)
                            if target.supports(TargetCpu::Sse41) =>
                        {
                            None
                        }
                        (ElementSize::Halfword, _) if target.supports(TargetCpu::Ssse3) => {
                            Some(BYTE_WEIGHTS)
                        }
                        (ElementSize::Halfword, _) => Some(LOW_BYTE_MASK),
                        (ElementSize::Word, Signedness::Signed) => Some(WORD_WEIGHTS),
                        (ElementSize::Word, Signedness::Unsigned) => {
                            Some(repeated(u64::from(u16::MAX), ElementSize::Word.bits()))
                        }
                        (ElementSize::Doubleword, _) => Some(LOW_DWORD_MASK),
                        _ => unreachable!(
                            "pair accumulate decoder excludes byte and quadword results"
                        ),
                    };
                    if let Some(value) = constant_value {
                        constant(code, CONSTANT, value);
                    }
                }
                pair_delta(code, operand.element_size, signedness, target);
                if let Predication::Merging(predicate) = operand.predication {
                    read_predicate_mask(
                        code,
                        predicate,
                        chunk,
                        operand.element_size,
                        PREDICATE,
                        PREDICATE_SCRATCH,
                        length,
                        target,
                    );
                    packed(code, Host::And, RESULT, PREDICATE);
                }
                load_z_chunk(code, operand.destination, chunk, PREVIOUS, length, target);
                packed(code, add(operand.element_size), RESULT, PREVIOUS);
            }
            Kind::Unpack { .. } => unreachable!("whole-vector unpack handled before local chunks"),
        }
        if !matches!(operand.kind, Kind::PairAccumulate { .. })
            && let Predication::Merging(predicate) = operand.predication
        {
            load_z_chunk(code, operand.destination, chunk, PREVIOUS, length, target);
            merge(code, predicate, chunk, operand, length, target);
        }
        store_z_chunk(code, operand.destination, chunk, RESULT, length, target);
    }
}
