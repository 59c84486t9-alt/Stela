//! SME integer outer products.
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, Size};
use crate::x86_64::simd::encode::stack;
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
use Gpr::{R8, R9, R11, Rax, Rsp};

const MIXED_CORRECTION: u8 = 5;
const WORD_SIGN_SHIFT: u8 = 15;

/// Exact 16-bit products with independent input signedness.
///
/// The same-sign paths keep `word_products` byte for byte. Mixed paths also
/// clobber XMM5. Correcting the unsigned high word by the unsigned other input
/// for each negative signed input reconstructs the full signed 32-bit product.
fn word_products_signedness(
    code: &mut Code,
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
/// R9 is the source group byte offset and the row predicate bit index; R11
/// points at the staged predicate.
const ROW_OFFSET: Gpr = R9;
const PREDICATE: Gpr = R11;

fn stack_chunk(code: &mut Code, register: u8, offset: usize, store: bool, target: TargetCpu) {
    (if store {
        Host::StoreUnaligned
    } else {
        Host::LoadUnaligned
    })
    .emit(code, register, stack(offset), target);
}

fn splat_dword(code: &mut Code, register: u8, value: u32, target: TargetCpu) {
    let mut asm = code.asm();
    asm.mov_imm32(Rax, value);
    asm.movd_to_xmm(register, Rax);
    Host::ShuffleDword.register_imm(code, register, register, REPEAT_LOW_DWORD, target);
}

fn shuffle(code: &mut Code, dst: u8, src: u8, control: u8, target: TargetCpu) {
    Host::ShuffleDword.register_imm(code, dst, src, control, target);
}

fn patch_relative(code: &mut Code, immediate: usize, destination: usize) {
    let displacement = i32::try_from(destination as isize - (immediate + 4) as isize)
        .expect("bounded outer row body fits rel32");
    code.patch(immediate, displacement.to_le_bytes());
}

fn stage_vector(
    code: &mut Code,
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
                code,
                predicate,
                chunk,
                source,
                crate::x86_64::scalable::MaskRegisters::new(TEMP, SCRATCH),
                length,
                target,
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

fn prepare_popcount(code: &mut Code, target: TargetCpu) {
    if target.supports(TargetCpu::Ssse3) {
        splat_dword(code, HIGH, SWAR_BYTES, target);
        code.asm().mov_imm64(
            Rax,
            u64::from_le_bytes(NIBBLE_POPCOUNTS[..QWORD_BYTES].try_into().unwrap()),
        );
        Host::MoveGprQword.register(code, WORK, 0, target);
        code.asm().mov_imm64(
            Rax,
            u64::from_le_bytes(NIBBLE_POPCOUNTS[QWORD_BYTES..].try_into().unwrap()),
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

fn popcount_dwords(code: &mut Code, target: TargetCpu) {
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

fn adjacent_pair_sums(code: &mut Code, target: TargetCpu) {
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

fn extend_row_bytes(code: &mut Code, signed: bool, target: TargetCpu) {
    Host::Xor.register(code, SCRATCH, SCRATCH, target);
    if signed {
        Host::GreaterByte.register(code, SCRATCH, ROW, target);
    }
    Host::UnpackLowByte.register(code, ROW, SCRATCH, target);
}

fn byte_dot(code: &mut Code, right_signed: bool, target: TargetCpu) {
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

fn sum_four_products_qword(code: &mut Code, register: u8, signed: bool, target: TargetCpu) {
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
    code: &mut Code,
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
    code.asm().reserve_stack(stack_bytes);
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
            code.asm().mov_store(
                Size::Qword,
                stack(predicate_offset + chunk * QWORD_BYTES),
                Rax,
            );
        }
        code.asm()
            .lea(Size::Qword, PREDICATE, stack(predicate_offset));
    }
    load_za_pointer_r8(code);
    code.asm().alu_imm32(
        Alu::Add,
        Size::Qword,
        R8,
        (usize::from(operand.tile) * length.bytes()) as i32,
    );
    if operand.kind == OuterKind::BitwiseXnor {
        prepare_popcount(code, target);
    }
    code.asm()
        .alu(Alu::Xor, Size::Dword, ROW_OFFSET, ROW_OFFSET);
    let row_start = code.len();
    let inactive_row = if multiply {
        None
    } else {
        // R9 is the source group byte offset and therefore the row predicate
        // bit index. Word BT reads at most one staged two-byte predicate block.
        let mut asm = code.asm();
        asm.bit(BitTest::Bt, Size::Word, Mem::base(PREDICATE, 0), ROW_OFFSET);
        Some(asm.jcc(Cond::Ae).offset())
    };
    if operand.kind != OuterKind::AddHorizontal {
        let row = Mem::indexed(Rsp, ROW_OFFSET, 1, 0);
        if element_bytes == QWORD_BYTES {
            Host::MoveQword.emit(code, ROW, row, target);
        } else {
            code.asm().movd_to_xmm(ROW, row);
        }
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
                crate::x86_64::scalable::MaskRegisters::new(TEMP, SCRATCH),
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
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Add, Size::Dword, ROW_OFFSET, element_bytes as i8);
    asm.alu_imm32(
        Alu::Add,
        Size::Qword,
        R8,
        (element_bytes * length.bytes()) as i32,
    );
    asm.alu_imm32(Alu::Cmp, Size::Dword, ROW_OFFSET, length.bytes() as i32);
    let immediate = asm.jcc(Cond::B).offset();
    patch_relative(code, immediate, row_start);
    code.asm().release_stack(stack_bytes);
}
