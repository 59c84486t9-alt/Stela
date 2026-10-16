//! ZA/ZT staging and physical slice addressing around the shared transfer loop.
use super::{
    ADD_RAX_IMM32, SHL_RAX_IMM8, Scratch, Transfer, VALUE_XMM, ZT_BYTES, check_sp, load_guest,
    pointer, stack_load, stack_store, stack_vector, transfer_loop,
};
use crate::aarch64::sme::memory::TileTransfer;
use crate::context::{SCALABLE_ZA_OFFSET, SCALABLE_ZT0_OFFSET};
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
const ZA_LEA_R9_RSP_DISP32: &[u8] = &[0x4c, 0x8d, 0x8c, 0x24];
const ZA_ADD_R8_IMM32: &[u8] = &[0x49, 0x81, 0xc0];
const ZA_ADD_R9_IMM8: &[u8] = &[0x49, 0x83, 0xc1];
const ZA_MOV_ECX_IMM32: &[u8] = &[0xb9];
const ZA_DEC_ECX: &[u8] = &[0xff, 0xc9];
const ZA_JNZ_REL32: &[u8] = &[0x0f, 0x85];
const ZA_LOAD_BYTE_R9: &[u8] = &[0x41, 0x0f, 0xb6, 0x01];
const ZA_LOAD_HALFWORD_R9: &[u8] = &[0x41, 0x0f, 0xb7, 0x01];
const ZA_LOAD_WORD_R9: &[u8] = &[0x41, 0x8b, 0x01];
const ZA_LOAD_DOUBLEWORD_R9: &[u8] = &[0x49, 0x8b, 0x01];
const ZA_STORE_BYTE_R9: &[u8] = &[0x41, 0x88, 0x01];
const ZA_STORE_HALFWORD_R9: &[u8] = &[0x66, 0x41, 0x89, 0x01];
const ZA_STORE_WORD_R9: &[u8] = &[0x41, 0x89, 0x01];
const ZA_STORE_DOUBLEWORD_R9: &[u8] = &[0x49, 0x89, 0x01];
const ZA_LOAD_XMM0_R9: &[u8] = &[0xf3, 0x41, 0x0f, 0x6f, 0x01];
const ZA_STORE_XMM0_R9: &[u8] = &[0xf3, 0x41, 0x0f, 0x7f, 0x01];
const ZA_ADD_EAX_IMM32: &[u8] = &[0x05];
const ZA_AND_EAX_IMM32: &[u8] = &[0x25];
const ZA_ADD_R8_RAX: &[u8] = &[0x49, 0x01, 0xc0];
const ZA_ADD_RAX_RSP_DISP32: &[u8] = &[0x48, 0x03, 0x84, 0x24];
const ZA_LOAD_BYTE_R8_DISP32: &[u8] = &[0x41, 0x0f, 0xb6, 0x80];
const ZA_LOAD_HALFWORD_R8_DISP32: &[u8] = &[0x41, 0x0f, 0xb7, 0x80];
const ZA_LOAD_WORD_R8_DISP32: &[u8] = &[0x41, 0x8b, 0x80];
const ZA_LOAD_DOUBLEWORD_R8_DISP32: &[u8] = &[0x49, 0x8b, 0x80];
const ZA_STORE_BYTE_R8_DISP32: &[u8] = &[0x41, 0x88, 0x80];
const ZA_STORE_HALFWORD_R8_DISP32: &[u8] = &[0x66, 0x41, 0x89, 0x80];
const ZA_STORE_WORD_R8_DISP32: &[u8] = &[0x41, 0x89, 0x80];
const ZA_STORE_DOUBLEWORD_R8_DISP32: &[u8] = &[0x49, 0x89, 0x80];

fn za_add_rax(code: &mut Vec<u8>, immediate: usize) {
    if immediate != 0 {
        code.extend(ADD_RAX_IMM32);
        code.extend(
            u32::try_from(immediate)
                .expect("ZA offset fits imm32")
                .to_le_bytes(),
        );
    }
}

fn za_shift_rax(code: &mut Vec<u8>, shift: u32) {
    if shift != 0 {
        code.extend(SHL_RAX_IMM8);
        code.push(shift as u8);
    }
}

fn za_selector(code: &mut Vec<u8>, register: u8, offset: u8, count: usize, scale: usize) {
    debug_assert!(count.is_power_of_two() && scale.is_power_of_two());
    load_guest(code, Register::X(register));
    // Addition modulo32 is equivalent before the power-of-two slice modulus.
    if offset != 0 {
        code.extend(ZA_ADD_EAX_IMM32);
        code.extend(u32::from(offset).to_le_bytes());
    }
    code.extend(ZA_AND_EAX_IMM32);
    code.extend(
        u32::try_from(count - 1)
            .expect("ZA selector mask fits u32")
            .to_le_bytes(),
    );
    za_shift_rax(code, scale.trailing_zeros());
}

fn za_selected_pointer(code: &mut Vec<u8>, field: u32, selector: Option<u32>) {
    if field == SCALABLE_ZA_OFFSET {
        crate::x86_64::scalable_matrix::load_za_pointer_r8(code);
    } else {
        pointer(code, field);
    }
    if let Some(offset) = selector {
        stack_load(code, offset);
        code.extend(ZA_ADD_R8_RAX);
    }
}

fn za_scalar_memory(code: &mut Vec<u8>, load: bool, bytes: usize, offset: u32) {
    let encoding = match (load, bytes) {
        (true, 1) => ZA_LOAD_BYTE_R8_DISP32,
        (true, 2) => ZA_LOAD_HALFWORD_R8_DISP32,
        (true, 4) => ZA_LOAD_WORD_R8_DISP32,
        (true, 8) => ZA_LOAD_DOUBLEWORD_R8_DISP32,
        (false, 1) => ZA_STORE_BYTE_R8_DISP32,
        (false, 2) => ZA_STORE_HALFWORD_R8_DISP32,
        (false, 4) => ZA_STORE_WORD_R8_DISP32,
        (false, 8) => ZA_STORE_DOUBLEWORD_R8_DISP32,
        _ => unreachable!("ZA scalar transfers require 1,2,4 or8 bytes"),
    };
    code.extend(encoding);
    code.extend(offset.to_le_bytes());
}

// Copy one internal-state chunk to/from staging; no guest RAM is accessed here.
fn za_copy_chunk(
    code: &mut Vec<u8>,
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
    code: &mut Vec<u8>,
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

fn za_staging_pointer_scalar(code: &mut Vec<u8>, load: bool, bytes: usize) {
    code.extend(match (load, bytes) {
        (true, 1) => ZA_LOAD_BYTE_R9,
        (true, 2) => ZA_LOAD_HALFWORD_R9,
        (true, 4) => ZA_LOAD_WORD_R9,
        (true, 8) => ZA_LOAD_DOUBLEWORD_R9,
        (false, 1) => ZA_STORE_BYTE_R9,
        (false, 2) => ZA_STORE_HALFWORD_R9,
        (false, 4) => ZA_STORE_WORD_R9,
        (false, 8) => ZA_STORE_DOUBLEWORD_R9,
        _ => unreachable!("ZA scalar transfers require 1,2,4 or8 bytes"),
    });
}

fn za_copy_tile(
    code: &mut Vec<u8>,
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
    // R8 advances through compact ZA rows; R9 advances through private staging.
    // There are no callbacks within this bounded internal-state copy loop.
    za_selected_pointer(code, SCALABLE_ZA_OFFSET, Some(scratch.selector));
    if transfer.tile != 0 {
        code.extend(ZA_ADD_R8_IMM32);
        code.extend((u32::from(transfer.tile) * bytes as u32).to_le_bytes());
    }
    code.extend(ZA_LEA_R9_RSP_DISP32);
    code.extend(scratch.data.to_le_bytes());
    code.extend(ZA_MOV_ECX_IMM32);
    code.extend(
        u32::try_from(bytes / element)
            .expect("ZA lane count fits u32")
            .to_le_bytes(),
    );
    let loop_start = code.len();
    if element == VECTOR_CHUNK_BYTES {
        if to_staging {
            crate::x86_64::scalable_matrix::load_za_chunk_at_r8(code, 0, 0, target);
            code.extend(ZA_STORE_XMM0_R9);
        } else {
            code.extend(ZA_LOAD_XMM0_R9);
            crate::x86_64::scalable_matrix::store_za_chunk_at_r8(code, 0, 0, target);
        }
    } else if to_staging {
        za_scalar_memory(code, true, element, 0);
        za_staging_pointer_scalar(code, false, element);
    } else {
        za_staging_pointer_scalar(code, true, element);
        za_scalar_memory(code, false, element, 0);
    }
    code.extend(ZA_ADD_R8_IMM32);
    code.extend(
        u32::try_from(element * bytes)
            .expect("ZA row stride fits u32")
            .to_le_bytes(),
    );
    code.extend(ZA_ADD_R9_IMM8);
    code.push(element as u8);
    code.extend(ZA_DEC_ECX);
    code.extend(ZA_JNZ_REL32);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
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
    code: &mut Vec<u8>,
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
    code.extend(ZA_ADD_RAX_RSP_DISP32);
    code.extend(scratch.address.to_le_bytes());
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
    code: &mut Vec<u8>,
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
    code: &mut Vec<u8>,
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
