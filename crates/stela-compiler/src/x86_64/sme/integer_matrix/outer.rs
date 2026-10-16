//! SME integer outer products.
use crate::{
    TargetCpu,
    aarch64::{
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sme::integer_matrix::{OuterKind, OuterOperation},
    },
    x86_64::{
        isa::{ShiftOpcode as Shift, SimdOpcode as Host},
        scalable::{load_z_chunk, read_predicate_chunk, read_predicate_mask},
        scalable_matrix::{load_za_chunk_at_r8, load_za_pointer_r8, store_za_chunk_at_r8},
        sme::integer_products::{
            PRODUCT_HIGH, PRODUCT_LEFT, PRODUCT_RIGHT, PRODUCT_TEMPORARY, word_products,
        },
    },
};
use alloc::vec::Vec;

const MIXED_CORRECTION: u8 = 5;
const WORD_SIGN_SHIFT: u8 = 15;

/// Exact 16-bit products with independent input signedness.
///
/// The same-sign paths retain `word_products` byte for byte. Mixed paths also
/// clobber XMM5. Correcting the unsigned high word by the unsigned other input
/// for each negative signed input reconstructs the full signed 32-bit product.
fn word_products_signedness(
    code: &mut Vec<u8>,
    left_signed: bool,
    right_signed: bool,
    target: TargetCpu,
) {
    if left_signed == right_signed {
        word_products(code, left_signed, target);
        return;
    }
    Host::MoveAligned.register(code, MIXED_CORRECTION, PRODUCT_LEFT, target);
    Host::MoveAligned.register(code, PRODUCT_TEMPORARY, PRODUCT_LEFT, target);
    Host::MultiplyLowWord.register(code, PRODUCT_LEFT, PRODUCT_RIGHT, target);
    Host::MultiplyHighUnsignedWord.register(code, PRODUCT_TEMPORARY, PRODUCT_RIGHT, target);
    if left_signed {
        Shift::ArithmeticWord.emit(code, MIXED_CORRECTION, WORD_SIGN_SHIFT);
        Host::And.register(code, MIXED_CORRECTION, PRODUCT_RIGHT, target);
    } else {
        Host::MoveAligned.register(code, PRODUCT_HIGH, PRODUCT_RIGHT, target);
        Shift::ArithmeticWord.emit(code, PRODUCT_HIGH, WORD_SIGN_SHIFT);
        Host::And.register(code, MIXED_CORRECTION, PRODUCT_HIGH, target);
    }
    Host::SubWord.register(code, PRODUCT_TEMPORARY, MIXED_CORRECTION, target);
    Host::MoveAligned.register(code, PRODUCT_HIGH, PRODUCT_LEFT, target);
    Host::UnpackLowWord.register(code, PRODUCT_LEFT, PRODUCT_TEMPORARY, target);
    Host::UnpackHighWord.register(code, PRODUCT_HIGH, PRODUCT_TEMPORARY, target);
}

const RESULT: u8 = 0;
const TEMP: u8 = 1;
const ROW: u8 = 2;
const SCRATCH: u8 = 3;
const HIGH: u8 = 4;
const WORK: u8 = 5;
const SAVED: u8 = 6;
const MASK_SCRATCH: u8 = 7;
const QWORD_BYTES: usize = core::mem::size_of::<u64>();
const REPEAT_LOW_DWORD: u8 = 0x00;
const REPEAT_LOW_QWORD: u8 = 0x44;
const SWAP_ADJACENT_DWORDS: u8 = 0xb1;
const EVEN_DWORDS_FIRST: u8 = 0x88;
const SWAP_QWORDS: u8 = 0x4e;
const DWORD_SIGN_SHIFT: u8 = 31;
const POPCOUNT_LOW_BITS_SHIFT: u8 = 26;
const SWAR_PAIRS: u32 = 0x5555_5555;
const SWAR_NIBBLES: u32 = 0x3333_3333;
const SWAR_BYTES: u32 = 0x0f0f_0f0f;
const BYTE_ONES: u32 = 0x0101_0101;
const WORD_ONES: u32 = 0x0001_0001;
const NIBBLE_POPCOUNTS: [u8; VECTOR_CHUNK_BYTES] = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];
const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];
const MOV_RSP_DISP32_RAX: &[u8] = &[0x48, 0x89, 0x84, 0x24];
const LEA_R11_RSP_DISP32: &[u8] = &[0x4c, 0x8d, 0x9c, 0x24];
const XOR_R9D_R9D: &[u8] = &[0x45, 0x31, 0xc9];
const BT_WORD_R11_R9W: &[u8] = &[0x66, 0x45, 0x0f, 0xa3, 0x0b];
const JNC_REL32: &[u8] = &[0x0f, 0x83];
const JB_REL32: &[u8] = &[0x0f, 0x82];
const ADD_R9D_IMM8: &[u8] = &[0x41, 0x83, 0xc1];
const ADD_R8_IMM32: &[u8] = &[0x49, 0x81, 0xc0];
const CMP_R9D_IMM32: &[u8] = &[0x41, 0x81, 0xf9];
const MOVD_ROW_RSP_R9: &[u8] = &[0x66, 0x42, 0x0f, 0x6e, 0x14, 0x0c];
const MOVQ_ROW_RSP_R9: &[u8] = &[0xf3, 0x42, 0x0f, 0x7e, 0x14, 0x0c];
const MOV_EAX_IMM32: u8 = 0xb8;
const MOVABS_RAX_IMM64: &[u8] = &[0x48, 0xb8];
const MOVD_XMM_EAX: &[u8] = &[0x66, 0x0f, 0x6e];
const XMM_MODRM_REGISTER: u8 = 0xc0;
const XMM_MODRM_RSP_DISP32: u8 = 0x84;
const RSP_SIB: u8 = 0x24;
const XMM_REGISTER_SHIFT: u8 = 3;

fn stack_chunk(code: &mut Vec<u8>, register: u8, offset: usize, store: bool, target: TargetCpu) {
    (if store {
        Host::StoreUnaligned
    } else {
        Host::LoadUnaligned
    })
    .append(code, target);
    code.push(XMM_MODRM_RSP_DISP32 | (register << XMM_REGISTER_SHIFT));
    code.push(RSP_SIB);
    code.extend((offset as u32).to_le_bytes());
}

fn splat_dword(code: &mut Vec<u8>, register: u8, value: u32, target: TargetCpu) {
    code.push(MOV_EAX_IMM32);
    code.extend(value.to_le_bytes());
    code.extend(MOVD_XMM_EAX);
    code.push(XMM_MODRM_REGISTER | (register << XMM_REGISTER_SHIFT));
    Host::ShuffleDword.register(code, register, register, target);
    code.push(REPEAT_LOW_DWORD);
}

fn shuffle(code: &mut Vec<u8>, dst: u8, src: u8, control: u8, target: TargetCpu) {
    Host::ShuffleDword.register(code, dst, src, target);
    code.push(control);
}

fn patch_relative(code: &mut [u8], immediate: usize, destination: usize) {
    let displacement = i32::try_from(destination as isize - (immediate + 4) as isize)
        .expect("bounded outer row body fits rel32");
    code[immediate..immediate + 4].copy_from_slice(&displacement.to_le_bytes());
}

fn stage_vector(
    code: &mut Vec<u8>,
    vector: u8,
    predicate: Option<u8>,
    source: ElementSize,
    offset: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    for chunk in 0..length.chunks() {
        load_z_chunk(code, vector, chunk, RESULT, length, target);
        if let Some(predicate) = predicate {
            read_predicate_mask(
                code, predicate, chunk, source, TEMP, SCRATCH, length, target,
            );
            Host::And.register(code, RESULT, TEMP, target);
        }
        stack_chunk(
            code,
            RESULT,
            offset + chunk * VECTOR_CHUNK_BYTES,
            true,
            target,
        );
    }
}

fn prepare_popcount(code: &mut Vec<u8>, target: TargetCpu) {
    if target.supports(TargetCpu::Ssse3) {
        splat_dword(code, HIGH, SWAR_BYTES, target);
        code.extend(MOVABS_RAX_IMM64);
        code.extend(
            u64::from_le_bytes(NIBBLE_POPCOUNTS[..QWORD_BYTES].try_into().unwrap()).to_le_bytes(),
        );
        Host::MoveGprQword.register(code, WORK, 0, target);
        code.extend(MOVABS_RAX_IMM64);
        code.extend(
            u64::from_le_bytes(NIBBLE_POPCOUNTS[QWORD_BYTES..].try_into().unwrap()).to_le_bytes(),
        );
        Host::MoveGprQword.register(code, SCRATCH, 0, target);
        Host::UnpackLowQword.register(code, WORK, SCRATCH, target);
        splat_dword(code, SAVED, BYTE_ONES, target);
        splat_dword(code, MASK_SCRATCH, WORD_ONES, target);
    } else {
        splat_dword(code, HIGH, SWAR_PAIRS, target);
        splat_dword(code, WORK, SWAR_NIBBLES, target);
        splat_dword(code, SAVED, SWAR_BYTES, target);
    }
}

fn popcount_dwords(code: &mut Vec<u8>, target: TargetCpu) {
    if target.supports(TargetCpu::Ssse3) {
        Host::MoveAligned.register(code, TEMP, RESULT, target);
        Host::And.register(code, RESULT, HIGH, target);
        Shift::RightWord.emit(code, TEMP, 4);
        Host::And.register(code, TEMP, HIGH, target);
        Host::MoveAligned.register(code, SCRATCH, WORK, target);
        Host::ByteShuffle.register(code, SCRATCH, RESULT, target);
        Host::MoveAligned.register(code, RESULT, WORK, target);
        Host::ByteShuffle.register(code, RESULT, TEMP, target);
        Host::AddByte.register(code, RESULT, SCRATCH, target);
        // Byte popcounts <=8, so the PMADDUBSW pair sum <=16 never saturates.
        Host::MultiplyAddUnsignedBytes.register(code, RESULT, SAVED, target);
        Host::MultiplyAddWords.register(code, RESULT, MASK_SCRATCH, target);
    } else {
        Host::MoveAligned.register(code, SCRATCH, RESULT, target);
        Shift::RightDword.emit(code, SCRATCH, 1);
        Host::And.register(code, SCRATCH, HIGH, target);
        Host::SubDword.register(code, RESULT, SCRATCH, target);
        Host::MoveAligned.register(code, SCRATCH, RESULT, target);
        Host::And.register(code, RESULT, WORK, target);
        Shift::RightDword.emit(code, SCRATCH, 2);
        Host::And.register(code, SCRATCH, WORK, target);
        Host::AddDword.register(code, RESULT, SCRATCH, target);
        Host::MoveAligned.register(code, SCRATCH, RESULT, target);
        Shift::RightDword.emit(code, SCRATCH, 4);
        Host::AddDword.register(code, RESULT, SCRATCH, target);
        Host::And.register(code, RESULT, SAVED, target);
        for amount in [8, 16] {
            Host::MoveAligned.register(code, SCRATCH, RESULT, target);
            Shift::RightDword.emit(code, SCRATCH, amount);
            Host::AddDword.register(code, RESULT, SCRATCH, target);
        }
        Shift::LeftDword.emit(code, RESULT, POPCOUNT_LOW_BITS_SHIFT);
        Shift::RightDword.emit(code, RESULT, POPCOUNT_LOW_BITS_SHIFT);
    }
}

fn adjacent_pair_sums(code: &mut Vec<u8>, target: TargetCpu) {
    if target.supports(TargetCpu::Ssse3) {
        Host::HorizontalAddDword.register(code, RESULT, HIGH, target);
    } else {
        shuffle(code, TEMP, RESULT, SWAP_ADJACENT_DWORDS, target);
        Host::AddDword.register(code, RESULT, TEMP, target);
        shuffle(code, TEMP, HIGH, SWAP_ADJACENT_DWORDS, target);
        Host::AddDword.register(code, HIGH, TEMP, target);
        shuffle(code, RESULT, RESULT, EVEN_DWORDS_FIRST, target);
        shuffle(code, HIGH, HIGH, EVEN_DWORDS_FIRST, target);
        Host::UnpackLowQword.register(code, RESULT, HIGH, target);
    }
}

fn extend_row_bytes(code: &mut Vec<u8>, signed: bool, target: TargetCpu) {
    Host::Xor.register(code, SCRATCH, SCRATCH, target);
    if signed {
        Host::GreaterByte.register(code, SCRATCH, ROW, target);
    }
    Host::UnpackLowByte.register(code, ROW, SCRATCH, target);
}

fn byte_dot(code: &mut Vec<u8>, right_signed: bool, target: TargetCpu) {
    Host::MoveAligned.register(code, HIGH, RESULT, target);
    Host::Xor.register(code, SCRATCH, SCRATCH, target);
    if right_signed {
        Host::GreaterByte.register(code, SCRATCH, RESULT, target);
    }
    Host::UnpackLowByte.register(code, RESULT, SCRATCH, target);
    Host::UnpackHighByte.register(code, HIGH, SCRATCH, target);
    Host::MultiplyAddWords.register(code, RESULT, ROW, target);
    Host::MultiplyAddWords.register(code, HIGH, ROW, target);
    adjacent_pair_sums(code, target);
}

fn sum_four_products_qword(code: &mut Vec<u8>, register: u8, signed: bool, target: TargetCpu) {
    Host::MoveAligned.register(code, WORK, register, target);
    if signed {
        Host::MoveAligned.register(code, SCRATCH, register, target);
        Shift::ArithmeticDword.emit(code, SCRATCH, DWORD_SIGN_SHIFT);
    } else {
        Host::Xor.register(code, SCRATCH, SCRATCH, target);
    }
    // Extend all four individual products before adding. No 32-bit pair sum.
    Host::UnpackLowDword.register(code, register, SCRATCH, target);
    Host::UnpackHighDword.register(code, WORK, SCRATCH, target);
    Host::AddQword.register(code, register, WORK, target);
    shuffle(code, TEMP, register, SWAP_QWORDS, target);
    Host::AddQword.register(code, register, TEMP, target);
}

pub(crate) fn emit_outer(
    code: &mut Vec<u8>,
    operand: &OuterOperation,
    length: VectorLength,
    target: TargetCpu,
) {
    let multiply = matches!(operand.kind, OuterKind::Multiply { .. });
    let vector_banks = if operand.vector_m.is_some() { 2 } else { 1 };
    let predicate_offset = vector_banks * length.bytes();
    let predicate_tail = if multiply {
        0
    } else {
        length
            .predicate_bytes()
            .next_multiple_of(VECTOR_CHUNK_BYTES)
    };
    let stack_bytes = predicate_offset + predicate_tail;
    let element_bytes = operand.accumulator_size.bytes();
    let source_size = match operand.kind {
        OuterKind::Multiply { products, .. } => {
            ElementSize::from_bytes(element_bytes / usize::from(products)).unwrap()
        }
        _ => operand.accumulator_size,
    };
    code.extend(SUB_RSP_IMM32);
    code.extend((stack_bytes as u32).to_le_bytes());
    stage_vector(
        code,
        operand.vector_n,
        multiply.then_some(operand.predicate_n),
        source_size,
        0,
        length,
        target,
    );
    if let Some(vector_m) = operand.vector_m {
        stage_vector(
            code,
            vector_m,
            multiply.then_some(operand.predicate_m),
            source_size,
            length.bytes(),
            length,
            target,
        );
    }
    if !multiply {
        for chunk in 0..length.predicate_bytes().div_ceil(QWORD_BYTES) {
            read_predicate_chunk(code, operand.predicate_n, chunk, length);
            code.extend(MOV_RSP_DISP32_RAX);
            code.extend(((predicate_offset + chunk * QWORD_BYTES) as u32).to_le_bytes());
        }
        code.extend(LEA_R11_RSP_DISP32);
        code.extend((predicate_offset as u32).to_le_bytes());
    }
    load_za_pointer_r8(code);
    code.extend(ADD_R8_IMM32);
    code.extend((usize::from(operand.tile) as u32 * length.bytes() as u32).to_le_bytes());
    if operand.kind == OuterKind::BitwiseXnor {
        prepare_popcount(code, target);
    }
    code.extend(XOR_R9D_R9D);
    let row_start = code.len();
    let inactive_row = if multiply {
        None
    } else {
        // R9 is the source group byte offset and therefore the row predicate
        // bit index. Word BT reads at most one staged two-byte predicate block.
        code.extend(BT_WORD_R11_R9W);
        code.extend(JNC_REL32);
        let immediate = code.len();
        code.extend(0i32.to_le_bytes());
        Some(immediate)
    };
    if operand.kind != OuterKind::AddHorizontal {
        code.extend(if element_bytes == QWORD_BYTES {
            MOVQ_ROW_RSP_R9
        } else {
            MOVD_ROW_RSP_R9
        });
        shuffle(
            code,
            ROW,
            ROW,
            if element_bytes == QWORD_BYTES {
                REPEAT_LOW_QWORD
            } else {
                REPEAT_LOW_DWORD
            },
            target,
        );
        if let OuterKind::Multiply { signed_n, .. } = operand.kind
            && source_size == ElementSize::Byte
        {
            extend_row_bytes(code, signed_n, target);
        }
    }
    for chunk in 0..length.chunks() {
        let offset = chunk * VECTOR_CHUNK_BYTES;
        match operand.kind {
            OuterKind::AddHorizontal => stack_chunk(code, RESULT, offset, false, target),
            OuterKind::AddVertical => Host::MoveAligned.register(code, RESULT, ROW, target),
            OuterKind::BitwiseXnor => {
                stack_chunk(code, RESULT, length.bytes() + offset, false, target);
                Host::Xor.register(code, RESULT, ROW, target);
                Host::EqualDword.register(code, SCRATCH, SCRATCH, target);
                Host::Xor.register(code, RESULT, SCRATCH, target);
                popcount_dwords(code, target);
            }
            OuterKind::Multiply {
                products,
                signed_n,
                signed_m,
            } => {
                if source_size == ElementSize::Byte {
                    stack_chunk(code, RESULT, length.bytes() + offset, false, target);
                    byte_dot(code, signed_m, target);
                } else {
                    Host::MoveAligned.register(code, RESULT, ROW, target);
                    stack_chunk(code, TEMP, length.bytes() + offset, false, target);
                    if products == 2 && signed_n && signed_m {
                        Host::MultiplyAddWords.register(code, RESULT, TEMP, target);
                    } else {
                        word_products_signedness(code, signed_n, signed_m, target);
                        if products == 2 {
                            adjacent_pair_sums(code, target);
                        } else {
                            let signed = signed_n || signed_m;
                            sum_four_products_qword(code, RESULT, signed, target);
                            Host::MoveAligned.register(code, SAVED, RESULT, target);
                            sum_four_products_qword(code, HIGH, signed, target);
                            Host::UnpackLowQword.register(code, SAVED, HIGH, target);
                            Host::MoveAligned.register(code, RESULT, SAVED, target);
                        }
                    }
                }
            }
        }
        if !multiply {
            // Constants XMM4..7 and row XMM2 survive this shared mask helper.
            read_predicate_mask(
                code,
                operand.predicate_m,
                chunk,
                operand.accumulator_size,
                TEMP,
                SCRATCH,
                length,
                target,
            );
            Host::And.register(code, RESULT, TEMP, target);
        }
        load_za_chunk_at_r8(code, TEMP, offset as u32, target);
        (match (operand.subtract, operand.accumulator_size) {
            (false, ElementSize::Word) => Host::AddDword,
            (false, ElementSize::Doubleword) => Host::AddQword,
            (true, ElementSize::Word) => Host::SubDword,
            (true, ElementSize::Doubleword) => Host::SubQword,
            _ => unreachable!("outer accumulators are word or doubleword"),
        })
        .register(code, TEMP, RESULT, target);
        store_za_chunk_at_r8(code, TEMP, offset as u32, target);
    }
    let row_advance = code.len();
    if let Some(immediate) = inactive_row {
        patch_relative(code, immediate, row_advance);
    }
    code.extend(ADD_R9D_IMM8);
    code.push(element_bytes as u8);
    code.extend(ADD_R8_IMM32);
    code.extend(((element_bytes * length.bytes()) as u32).to_le_bytes());
    code.extend(CMP_R9D_IMM32);
    code.extend((length.bytes() as u32).to_le_bytes());
    code.extend(JB_REL32);
    let immediate = code.len();
    code.extend(0i32.to_le_bytes());
    patch_relative(code, immediate, row_start);
    code.extend(ADD_RSP_IMM32);
    code.extend((stack_bytes as u32).to_le_bytes());
}
