//! ZA and ZT0 staging and slice addressing.
use super::{
    Scratch, Transfer, VALUE_XMM, ZT_BYTES, check_sp, load_guest, pointer, scalar_transfer, slot,
    stack_load, stack_store, stack_vector, transfer_loop,
};
use crate::aarch64::sme::memory::TileTransfer;
use crate::context::{SCALABLE_ZA_OFFSET, SCALABLE_ZT0_OFFSET};
use crate::x86_64::asm::Code;
use crate::x86_64::asm::{Alu, Cond, Gpr, Mem, ShiftOp, Size};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{VECTOR_CHUNK_BYTES, VectorLength},
        sme::memory::{Direction, Offset, Operand},
    },
    x86_64::isa::SimdOpcode as Host,
};
use alloc::vec::Vec;

const ZA_PACKED_PREDICATE_BYTES: usize = size_of::<u64>();
/// R8 walks the selected ZA rows; R9 walks the staged elements.
const ZA_CURSOR: Gpr = Gpr::R8;
const STAGING_CURSOR: Gpr = Gpr::R9;

/// `add r8, imm32`.
fn za_advance(code: &mut Code, bytes: usize) {
    code.asm().alu_imm32(
        Alu::Add,
        Size::Qword,
        ZA_CURSOR,
        u32::try_from(bytes).expect("ZA offset fits imm32") as i32,
    );
}

fn za_add_rax(code: &mut Code, immediate: usize) {
    if immediate != 0 {
        code.asm().alu_accumulator_imm32(
            Alu::Add,
            Size::Qword,
            u32::try_from(immediate).expect("ZA offset fits imm32") as i32,
        );
    }
}

fn za_shift_rax(code: &mut Code, shift: u32) {
    if shift != 0 {
        code.asm()
            .shift_imm(ShiftOp::Shl, Size::Qword, Gpr::Rax, shift as u8);
    }
}

fn za_selector(code: &mut Code, register: u8, offset: u8, count: usize, scale: usize) {
    debug_assert!(count.is_power_of_two() && scale.is_power_of_two());
    load_guest(code, Register::X(register));
    // Addition modulo32 is equivalent before the power-of-two slice modulus.
    let mut asm = code.asm();
    if offset != 0 {
        asm.alu_accumulator_imm32(Alu::Add, Size::Dword, offset.into());
    }
    asm.alu_accumulator_imm32(
        Alu::And,
        Size::Dword,
        u32::try_from(count - 1).expect("ZA selector mask fits u32") as i32,
    );
    za_shift_rax(code, scale.trailing_zeros());
}

fn za_selected_pointer(code: &mut Code, field: u32, selector: Option<u32>) {
    if field == SCALABLE_ZA_OFFSET {
        crate::x86_64::scalable_matrix::load_za_pointer_r8(code);
    } else {
        pointer(code, field);
    }
    if let Some(offset) = selector {
        stack_load(code, offset);
        code.asm().alu(Alu::Add, Size::Qword, ZA_CURSOR, Gpr::Rax);
    }
}

fn za_scalar_memory(code: &mut Code, load: bool, bytes: usize, offset: u32) {
    scalar_transfer(
        code,
        load,
        bytes,
        Mem::base_disp32(ZA_CURSOR, offset as i32),
    );
}

// Copy one internal-state chunk to/from staging; no guest RAM is accessed here.
fn za_copy_chunk(
    code: &mut Code,
    to_staging: bool,
    bank_offset: usize,
    data_offset: u32,
    target: TargetCpu,
) {
    let bank_offset = u32::try_from(bank_offset).expect("ZA bank offset fits disp32");
    if to_staging {
        crate::x86_64::scalable_matrix::load_za_chunk_at_r8(code, VALUE_XMM, bank_offset, target);
        stack_vector(code, false, VALUE_XMM, data_offset, target);
    } else {
        stack_vector(code, true, VALUE_XMM, data_offset, target);
        crate::x86_64::scalable_matrix::store_za_chunk_at_r8(code, VALUE_XMM, bank_offset, target);
    }
}

fn za_copy_bank(
    code: &mut Code,
    to_staging: bool,
    field: u32,
    selector: Option<u32>,
    bytes: usize,
    data: u32,
    target: TargetCpu,
) {
    za_selected_pointer(code, field, selector);
    for chunk in (0..bytes).step_by(VECTOR_CHUNK_BYTES) {
        za_copy_chunk(code, to_staging, chunk, data + chunk as u32, target);
    }
}

fn za_staging_pointer_scalar(code: &mut Code, load: bool, bytes: usize) {
    scalar_transfer(code, load, bytes, Mem::base(STAGING_CURSOR, 0));
}

fn za_copy_tile(
    code: &mut Code,
    to_staging: bool,
    transfer: &TileTransfer,
    length: VectorLength,
    scratch: &Scratch,
    target: TargetCpu,
) {
    let bytes = length.bytes();
    if !transfer.vertical {
        za_copy_bank(
            code,
            to_staging,
            SCALABLE_ZA_OFFSET,
            Some(scratch.selector),
            bytes,
            scratch.data,
            target,
        );
        return;
    }
    let element = transfer.element.bytes();
    // R8 steps through the ZA rows and R9 through private staging. The copy
    // loop makes no callbacks.
    za_selected_pointer(code, SCALABLE_ZA_OFFSET, Some(scratch.selector));
    if transfer.tile != 0 {
        za_advance(code, usize::from(transfer.tile) * bytes);
    }
    let mut asm = code.asm();
    asm.lea(Size::Qword, STAGING_CURSOR, slot(scratch.data));
    asm.mov_imm32(
        Gpr::Rcx,
        u32::try_from(bytes / element).expect("ZA lane count fits u32"),
    );
    let loop_start = code.len();
    let staged = Mem::base(STAGING_CURSOR, 0);
    if element == VECTOR_CHUNK_BYTES {
        if to_staging {
            crate::x86_64::scalable_matrix::load_za_chunk_at_r8(code, 0, 0, target);
            Host::StoreUnaligned.emit(code, 0, staged, TargetCpu::Baseline);
        } else {
            Host::LoadUnaligned.emit(code, 0, staged, TargetCpu::Baseline);
            crate::x86_64::scalable_matrix::store_za_chunk_at_r8(code, 0, 0, target);
        }
    } else if to_staging {
        za_scalar_memory(code, true, element, 0);
        za_staging_pointer_scalar(code, false, element);
    } else {
        za_staging_pointer_scalar(code, true, element);
        za_scalar_memory(code, false, element, 0);
    }
    za_advance(code, element * bytes);
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Add, Size::Qword, STAGING_CURSOR, element as i8);
    asm.dec(Size::Dword, Gpr::Rcx);
    let displacement = asm.jcc(Cond::Ne).offset();
    crate::x86_64::scalable::memory::patch_branch(code, displacement, loop_start);
}

pub(super) fn access_flags(direction: Direction, tag_checked: bool) -> u32 {
    use crate::context::memory::flags;
    flags::SME
        | if tag_checked { flags::TAG_CHECKED } else { 0 }
        | if direction == Direction::Store {
            flags::WRITE
        } else {
            0
        }
}

fn za_tile_body(
    code: &mut Code,
    transfer: &TileTransfer,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
    scratch: &Scratch,
    failures: &mut Vec<usize>,
) {
    check_sp(code, transfer.address.base, pc, failures);
    let bytes = length.bytes();
    let element = transfer.element.bytes();
    let selector_scale = if transfer.vertical {
        element
    } else {
        element * bytes
    };
    za_selector(
        code,
        transfer.slice_register,
        transfer.slice_offset,
        bytes / element,
        selector_scale,
    );
    if !transfer.vertical {
        za_add_rax(code, usize::from(transfer.tile) * bytes);
    }
    stack_store(code, scratch.selector);
    let Offset::Register(offset) = transfer.address.offset else {
        unreachable!("tile address is scalar plus scalar")
    };
    load_guest(code, offset);
    za_shift_rax(code, element.trailing_zeros());
    stack_store(code, scratch.address);
    load_guest(code, transfer.address.base);
    code.asm()
        .alu_load(Alu::Add, Size::Qword, Gpr::Rax, slot(scratch.address));
    stack_store(code, scratch.address);
    let loading = transfer.direction == Direction::Load;
    if loading {
        Host::Xor.register(code, VALUE_XMM, VALUE_XMM, target);
        for chunk in (0..bytes).step_by(VECTOR_CHUNK_BYTES) {
            stack_vector(code, false, 0, scratch.data + chunk as u32, target);
        }
    } else {
        za_copy_tile(code, true, transfer, length, scratch, target);
    }
    for chunk in 0..length.predicate_bytes().div_ceil(ZA_PACKED_PREDICATE_BYTES) {
        crate::x86_64::scalable::read_predicate_chunk(code, transfer.predicate, chunk, length);
        stack_store(
            code,
            scratch.predicate + (chunk * ZA_PACKED_PREDICATE_BYTES) as u32,
        );
    }
    stack_load(code, scratch.address);
    transfer_loop(
        code,
        Transfer {
            bytes: bytes as u32,
            element_bytes: element as u32,
            flags: access_flags(transfer.direction, true),
            predicated: true,
        },
        pc,
        scratch,
        failures,
    );
    if loading {
        za_copy_tile(code, false, transfer, length, scratch, target);
    }
}

fn za_whole_body(
    code: &mut Code,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
    scratch: &Scratch,
    failures: &mut Vec<usize>,
) {
    let (direction, base, vector) = match operand {
        Operand::ZaVector(transfer) => (
            transfer.direction,
            transfer.base,
            Some((transfer.vector_register, transfer.offset)),
        ),
        Operand::Zt(transfer) => (transfer.direction, transfer.base, None),
        _ => unreachable!("whole transfer requires ZA vector or ZT operand"),
    };
    check_sp(code, base, pc, failures);
    let (field, bytes, selector) = if let Some((register, offset)) = vector {
        za_selector(code, register, offset, length.bytes(), length.bytes());
        stack_store(code, scratch.selector);
        (SCALABLE_ZA_OFFSET, length.bytes(), Some(scratch.selector))
    } else {
        (SCALABLE_ZT0_OFFSET, ZT_BYTES, None)
    };
    load_guest(code, base);
    if let Some((_, offset)) = vector {
        za_add_rax(code, usize::from(offset) * length.bytes());
    }
    stack_store(code, scratch.address);
    let loading = direction == Direction::Load;
    if !loading {
        za_copy_bank(code, true, field, selector, bytes, scratch.data, target);
    }
    stack_load(code, scratch.address);
    transfer_loop(
        code,
        Transfer {
            bytes: bytes as u32,
            element_bytes: 1,
            flags: access_flags(direction, base != Register::Sp),
            predicated: false,
        },
        pc,
        scratch,
        failures,
    );
    if loading {
        za_copy_bank(code, false, field, selector, bytes, scratch.data, target);
    }
}

pub(super) fn emit_za_body(
    code: &mut Code,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
    scratch: &Scratch,
    failures: &mut Vec<usize>,
) {
    match operand {
        Operand::Tile(transfer) => {
            za_tile_body(code, transfer, length, target, pc, scratch, failures)
        }
        Operand::ZaVector(_) | Operand::Zt(_) => {
            za_whole_body(code, operand, length, target, pc, scratch, failures)
        }
        Operand::Vectors(_) => unreachable!("vector group body is parent-owned"),
    }
}
