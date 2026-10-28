//! Long integer accumulation into ZA rows.
use crate::x86_64::asm::{Alu, Code, Gpr, ShiftOp, Size};
use crate::x86_64::simd::encode::guest;
use crate::{
    GuestState, TargetCpu,
    aarch64::{
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VECTOR_REGISTER_COUNT, VectorLength},
        sme::integer_matrix::LongOperation,
    },
    x86_64::{
        isa::{ShiftOpcode as Shift, SimdOpcode as Host},
        scalable::load_z_chunk,
        scalable_matrix::{load_za_chunk_at_r8, load_za_pointer_r8, store_za_chunk_at_r8},
        sme::integer_products::{PRODUCT_HIGH, PRODUCT_LEFT, PRODUCT_RIGHT, word_products},
    },
};

const ACCUMULATOR: u8 = 2;
const COMPONENT: u8 = 6;
const COMPONENT_HIGH: u8 = 7;
const DWORD_SIGN_SHIFT: u8 = 31;
const BYTE_BITS: u8 = u8::BITS as u8;
const WORD_BITS: u8 = u16::BITS as u8;
const DWORD_BITS: u8 = u32::BITS as u8;
const DWORD_BROADCAST: u8 = 0x55;
const EVEN_DWORDS: u8 = 0x88;
const ODD_DWORDS: u8 = 0xdd;
const REPEAT_LOW_QWORD: u8 = 0x44;
const REPEAT_HIGH_QWORD: u8 = 0xee;
const HALFWORDS_PER_QWORD: u8 = 4;
const BYTES_PER_DWORD: u8 = core::mem::size_of::<u32>() as u8;
const GPR_BYTES: usize = core::mem::size_of::<u64>();

/// Recipe controls; the parent selects the mapping.
#[derive(Clone, Copy)]
pub(crate) struct Recipe {
    pub(crate) multiply_dword: bool,
    pub(crate) widen_dword: bool,
}

impl Recipe {
    /// Measured checked kernels; unsigned byte products retain the SSE2 recipe.
    pub(super) fn selected(operand: &LongOperation, target: TargetCpu) -> Self {
        let sse41 = target.supports(TargetCpu::Sse41);
        Self {
            multiply_dword: sse41
                && operand.source_size == ElementSize::Byte
                && (operand.signed_left || operand.signed_right),
            widen_dword: sse41 && operand.accumulator_size == ElementSize::Doubleword,
        }
    }
}

fn shuffle(code: &mut Code, destination: u8, source: u8, control: u8, target: TargetCpu) {
    Host::ShuffleDword.register_imm(code, destination, source, control, target);
}

fn za_pointer(code: &mut Code, operand: &LongOperation, length: VectorLength) {
    load_za_pointer_r8(code);
    let mut asm = code.asm();
    asm.mov_load(
        Size::Dword,
        Gpr::Rcx,
        guest(
            (core::mem::offset_of!(GuestState, x) + usize::from(operand.selector) * GPR_BYTES)
                as u32,
        ),
    );
    if operand.offset != 0 {
        asm.alu_imm8(Alu::Add, Size::Dword, Gpr::Rcx, operand.offset as i8);
    }
    // Accepted SME lengths, group counts and component counts are powers of two.
    // Low32 addition retains the exact mathematical result modulo the partition.
    // Clear component bits in the same mask to align the first selected row.
    let partition_rows = length.bytes() / usize::from(operand.group_size);
    let row_mask = ((partition_rows - 1) & !(usize::from(operand.factor) - 1)) as u32;
    if row_mask <= i8::MAX as u32 {
        asm.alu_imm8(Alu::And, Size::Dword, Gpr::Rcx, row_mask as i8);
    } else {
        asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rcx, row_mask as i32);
    }
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Qword,
        Gpr::Rcx,
        length.bytes().trailing_zeros() as u8,
    );
    asm.alu(Alu::Add, Size::Qword, Gpr::R8, Gpr::Rcx);
}

fn broadcast_word(code: &mut Code, index: u8, target: TargetCpu) {
    let high = index >= HALFWORDS_PER_QWORD;
    (if high {
        Host::ShuffleHighWord
    } else {
        Host::ShuffleLowWord
    })
    .register_imm(
        code,
        PRODUCT_RIGHT,
        PRODUCT_RIGHT,
        (index % HALFWORDS_PER_QWORD) * DWORD_BROADCAST,
        target,
    );
    shuffle(
        code,
        PRODUCT_RIGHT,
        PRODUCT_RIGHT,
        if high {
            REPEAT_HIGH_QWORD
        } else {
            REPEAT_LOW_QWORD
        },
        target,
    );
}

/// Select one byte from every dword and sign/zero extend it to a dword.
fn extract_bytes(
    code: &mut Code,
    destination: u8,
    source: u8,
    component: u8,
    signed: bool,
    target: TargetCpu,
) {
    if destination != source {
        Host::MoveAligned.register(code, destination, source, target);
    }
    let left_shift = DWORD_BITS - BYTE_BITS * (component + 1);
    if left_shift != 0 {
        Shift::LeftDword.emit(code, destination, left_shift);
    }
    (if signed {
        Shift::ArithmeticDword
    } else {
        Shift::RightDword
    })
    .emit(code, destination, DWORD_BITS - BYTE_BITS);
}

fn extend_products(code: &mut Code, signed: bool, checked: bool, target: TargetCpu) {
    if checked {
        (if signed {
            Host::SignExtendDwordToQword
        } else {
            Host::ZeroExtendDwordToQword
        })
        .register(code, COMPONENT, COMPONENT, target);
    } else {
        if signed {
            Host::MoveAligned.register(code, COMPONENT_HIGH, COMPONENT, target);
            Shift::ArithmeticDword.emit(code, COMPONENT_HIGH, DWORD_SIGN_SHIFT);
        } else {
            Host::Xor.register(code, COMPONENT_HIGH, COMPONENT_HIGH, target);
        }
        Host::UnpackLowDword.register(code, COMPONENT, COMPONENT_HIGH, target);
    }
}

fn accumulate(
    code: &mut Code,
    product: u8,
    displacement: u32,
    operand: &LongOperation,
    target: TargetCpu,
) {
    load_za_chunk_at_r8(code, ACCUMULATOR, displacement, target);
    let arithmetic = match (operand.subtract, operand.accumulator_size) {
        (false, ElementSize::Word) => Host::AddDword,
        (false, ElementSize::Doubleword) => Host::AddQword,
        (true, ElementSize::Word) => Host::SubDword,
        (true, ElementSize::Doubleword) => Host::SubQword,
        _ => unreachable!("decoded long accumulator is a word or doubleword"),
    };
    arithmetic.register(code, ACCUMULATOR, product, target);
    store_za_chunk_at_r8(code, ACCUMULATOR, displacement, target);
}

/// The caller validates SME2, I16I64 where required, SM+ZA, SVL and live storage.
/// All inputs remain in architectural storage; only selected ZA rows are written.
/// R8 holds the selected ZA base, RDX is shared access scratch, XMM0..7 scratch.
pub(crate) fn emit_long(
    code: &mut Code,
    operand: &LongOperation,
    length: VectorLength,
    target: TargetCpu,
    recipe: Recipe,
) {
    if recipe.multiply_dword || recipe.widen_dword {
        assert!(target.supports(TargetCpu::Sse41));
    }
    za_pointer(code, operand, length);
    let partition_bytes = length.bytes() * length.bytes() / usize::from(operand.group_size);
    for group in 0..operand.group_size {
        let left = (operand.source_left + group) % VECTOR_REGISTER_COUNT;
        let right = operand.source_right + if operand.group_right { group } else { 0 };
        for chunk in 0..length.chunks() {
            let group_offset = usize::from(group) * partition_bytes + chunk * VECTOR_CHUNK_BYTES;
            if operand.source_size == ElementSize::Byte {
                load_z_chunk(code, left, chunk, COMPONENT, length, target);
                if let Some(index) = operand.indexed_lane {
                    load_z_chunk(code, right, chunk, PRODUCT_RIGHT, length, target);
                    shuffle(
                        code,
                        PRODUCT_RIGHT,
                        PRODUCT_RIGHT,
                        (index / BYTES_PER_DWORD) * DWORD_BROADCAST,
                        target,
                    );
                    extract_bytes(
                        code,
                        PRODUCT_RIGHT,
                        PRODUCT_RIGHT,
                        index % BYTES_PER_DWORD,
                        operand.signed_right,
                        target,
                    );
                } else {
                    load_z_chunk(code, right, chunk, COMPONENT_HIGH, length, target);
                }
                for component in 0..operand.factor {
                    extract_bytes(
                        code,
                        PRODUCT_LEFT,
                        COMPONENT,
                        component,
                        operand.signed_left,
                        target,
                    );
                    if operand.indexed_lane.is_none() {
                        extract_bytes(
                            code,
                            PRODUCT_RIGHT,
                            COMPONENT_HIGH,
                            component,
                            operand.signed_right,
                            target,
                        );
                    }
                    if recipe.multiply_dword {
                        Host::MultiplyLowDword.register(code, PRODUCT_LEFT, PRODUCT_RIGHT, target);
                    } else {
                        // Every byte product fits a signed word if either source
                        // is signed, otherwise an unsigned word. Unsigned inputs
                        // have zero high words, so PMULLW already forms dwords.
                        Host::MultiplyLowWord.register(code, PRODUCT_LEFT, PRODUCT_RIGHT, target);
                        if operand.signed_left || operand.signed_right {
                            Shift::LeftDword.emit(code, PRODUCT_LEFT, DWORD_BITS - WORD_BITS);
                            Shift::ArithmeticDword.emit(code, PRODUCT_LEFT, DWORD_BITS - WORD_BITS);
                        }
                    }
                    let displacement =
                        (group_offset + usize::from(component) * length.bytes()) as u32;
                    accumulate(code, PRODUCT_LEFT, displacement, operand, target);
                }
            } else {
                load_z_chunk(code, left, chunk, PRODUCT_LEFT, length, target);
                load_z_chunk(code, right, chunk, PRODUCT_RIGHT, length, target);
                if let Some(index) = operand.indexed_lane {
                    broadcast_word(code, index, target);
                }
                word_products(code, operand.signed_left, target);
                for component in 0..operand.factor {
                    let control = if operand.factor == 2 {
                        if component == 0 {
                            EVEN_DWORDS
                        } else {
                            ODD_DWORDS
                        }
                    } else {
                        component * DWORD_BROADCAST
                    };
                    shuffle(code, COMPONENT, PRODUCT_LEFT, control, target);
                    shuffle(code, COMPONENT_HIGH, PRODUCT_HIGH, control, target);
                    (if operand.factor == 2 {
                        Host::UnpackLowQword
                    } else {
                        Host::UnpackLowDword
                    })
                    .register(code, COMPONENT, COMPONENT_HIGH, target);
                    if operand.accumulator_size == ElementSize::Doubleword {
                        extend_products(code, operand.signed_left, recipe.widen_dword, target);
                    }
                    let displacement =
                        (group_offset + usize::from(component) * length.bytes()) as u32;
                    accumulate(code, COMPONENT, displacement, operand, target);
                }
            }
        }
    }
}
