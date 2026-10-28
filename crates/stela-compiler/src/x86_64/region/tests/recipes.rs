//! Independent golden-byte and mutation oracle for shared memory recipes.
use super::super::{BYTE_LOAD_BYTES, DOUBLEWORD_LOAD_BYTES, HALFWORD_LOAD_BYTES, WORD_LOAD_BYTES};
use crate::aarch64::AddressMode;
use crate::x86_64::asm::Code;
use alloc::{vec, vec::Vec};

const REX: u8 = 0x40;
const REX_W: u8 = 8;
const REX_R: u8 = 4;
const REX_B: u8 = 1;
const MOV_LOAD: u8 = 0x8b;
const MOV_STORE: u8 = 0x89;
const TWO_BYTE_OPCODE: u8 = 0x0f;
const FRAME_STORE_BYTES: usize = 7;
const GPR_BYTES: usize = core::mem::size_of::<u64>();
const ECX_FROM_RAX_MEMORY: u8 = 0x08;
const FRAME_DISP32_FROM_RCX: u8 = 0x8f;
const FRAME_DISP32_FROM_R8: u8 = 0x87;
const R8D_FROM_RAX_DISP8: u8 = 0x40;

fn ordinary_address_ends(code: &[u8], base: usize, displacement: i32) -> Option<Vec<usize>> {
    use crate::x86_64::{RangeCheck, STACK_ALIGNMENT_CHECK, STACK_ALIGNMENT_CHECK_ENDS};
    const RAX_FROM_FRAME_DISP32: u8 = 0x87;
    const BASE_LOAD_BYTES: usize = 7;
    const SP: usize = 31;
    if code.get(0..3)? != [REX | REX_W, MOV_LOAD, RAX_FROM_FRAME_DISP32]
        || code.get(3..BASE_LOAD_BYTES)?
            != u32::try_from(base.checked_mul(GPR_BYTES)?)
                .ok()?
                .to_le_bytes()
    {
        return None;
    }
    let mut ends = vec![BASE_LOAD_BYTES];
    let mut cursor = BASE_LOAD_BYTES;
    // SCTLR_ELx.SA checks an SP base before the address addition.
    if base == SP && code[cursor..].starts_with(&STACK_ALIGNMENT_CHECK) {
        ends.extend(STACK_ALIGNMENT_CHECK_ENDS.map(|end| cursor + end));
        cursor += STACK_ALIGNMENT_CHECK.len();
    }
    // The Offset form's one LEA, or nothing for a zero offset.
    let mut add = Code::new();
    crate::x86_64::address_add(&mut add, displacement, AddressMode::Offset);
    if !add.is_empty() {
        if code.get(cursor..cursor + add.len())? != add {
            return None;
        }
        cursor += add.len();
        ends.push(cursor);
    }
    // A system-mode access checks the address against the guest's ranges.
    if let Some((_, check_ends)) = RangeCheck::at(&code[cursor..]) {
        ends.extend(check_ends.iter().map(|end| cursor + end));
    }
    Some(ends)
}

fn check_frame_store(code: &[u8], start: usize, guest: usize, rex: u8, modrm: u8) -> Option<usize> {
    check_frame_access(code, start, guest, [rex, MOV_STORE, modrm])
}

fn check_frame_access(code: &[u8], start: usize, guest: usize, opcode: [u8; 3]) -> Option<usize> {
    let end = start.checked_add(FRAME_STORE_BYTES)?;
    if code.get(start..start + 3)? != opcode
        || code.get(start + 3..end)?
            != u32::try_from(guest.checked_mul(GPR_BYTES)?)
                .ok()?
                .to_le_bytes()
    {
        return None;
    }
    Some(end)
}

/// Inspect the exact shared scalar load, including address, clobbers and commit.
/// The same memory emitter supplies bytes; this is not a second memory engine.
pub fn ordinary_load_ends(
    code: &[u8],
    bytes: u8,
    base: usize,
    data: Option<usize>,
    displacement: i32,
) -> Option<Vec<usize>> {
    const MOVZX_BYTE: u8 = 0xb6;
    const MOVZX_WORD: u8 = 0xb7;
    let memory_recipe: &[u8] = match bytes {
        BYTE_LOAD_BYTES => &[TWO_BYTE_OPCODE, MOVZX_BYTE, ECX_FROM_RAX_MEMORY],
        HALFWORD_LOAD_BYTES => &[TWO_BYTE_OPCODE, MOVZX_WORD, ECX_FROM_RAX_MEMORY],
        WORD_LOAD_BYTES => &[MOV_LOAD, ECX_FROM_RAX_MEMORY],
        DOUBLEWORD_LOAD_BYTES => &[REX | REX_W, MOV_LOAD, ECX_FROM_RAX_MEMORY],
        _ => return None,
    };
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let address_end = *ends.last()?;
    let load_end = address_end + memory_recipe.len();
    if code.get(address_end..load_end)? != memory_recipe {
        return None;
    }
    ends.push(load_end);
    let end = if let Some(guest) = data {
        let end = check_frame_store(code, load_end, guest, REX | REX_W, FRAME_DISP32_FROM_RCX)?;
        ends.push(end);
        end
    } else {
        load_end
    };
    (code.len() == end).then_some(ends)
}

/// Unsigned W and X pair recipe: RCX/R8 results, both accesses before either
/// commit. Writeback, signed pairs and duplicate destinations are not selected.
pub fn ordinary_pair_load_ends(
    code: &[u8],
    bytes: u8,
    base: usize,
    data: [Option<usize>; 2],
    displacement: i32,
) -> Option<Vec<usize>> {
    let (first, second): (&[u8], [u8; 4]) = match bytes {
        WORD_LOAD_BYTES => (
            &[MOV_LOAD, ECX_FROM_RAX_MEMORY],
            [REX | REX_R, MOV_LOAD, R8D_FROM_RAX_DISP8, WORD_LOAD_BYTES],
        ),
        DOUBLEWORD_LOAD_BYTES => (
            &[REX | REX_W, MOV_LOAD, ECX_FROM_RAX_MEMORY],
            [
                REX | REX_W | REX_R,
                MOV_LOAD,
                R8D_FROM_RAX_DISP8,
                DOUBLEWORD_LOAD_BYTES,
            ],
        ),
        _ => return None,
    };
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let address_end = *ends.last()?;
    let first_end = address_end + first.len();
    let second_end = first_end + second.len();
    if code.get(address_end..first_end)? != first || code.get(first_end..second_end)? != second {
        return None;
    }
    ends.extend([first_end, second_end]);
    let mut end = second_end;
    for (guest, rex, modrm) in [
        (data[0], REX | REX_W, FRAME_DISP32_FROM_RCX),
        (data[1], REX | REX_W | REX_R, FRAME_DISP32_FROM_R8),
    ] {
        if let Some(guest) = guest {
            end = check_frame_store(code, end, guest, rex, modrm)?;
            ends.push(end);
        }
    }
    (code.len() == end).then_some(ends)
}

/// The data of a store element staged in RCX (`second` false) or R8: its
/// frame load, or zero for ZR.
fn check_store_data(
    code: &[u8],
    start: usize,
    guest: Option<usize>,
    second: bool,
) -> Option<usize> {
    const ZERO_ECX: [u8; 2] = [0x31, 0xc9];
    const ZERO_R8D: [u8; 3] = [REX | REX_R | REX_B, 0x31, 0xc0];
    match (guest, second) {
        (Some(guest), false) => check_frame_access(
            code,
            start,
            guest,
            [REX | REX_W, MOV_LOAD, FRAME_DISP32_FROM_RCX],
        ),
        (Some(guest), true) => check_frame_access(
            code,
            start,
            guest,
            [REX | REX_W | REX_R, MOV_LOAD, FRAME_DISP32_FROM_R8],
        ),
        (None, false) => code
            .get(start..)?
            .starts_with(&ZERO_ECX)
            .then_some(start + ZERO_ECX.len()),
        (None, true) => code
            .get(start..)?
            .starts_with(&ZERO_R8D)
            .then_some(start + ZERO_R8D.len()),
    }
}

/// The exact shared store of one element staged in RCX to [RAX], without
/// the page-crossing split.
fn single_store(bytes: u8) -> Option<&'static [u8]> {
    const OPERAND_SIZE: u8 = 0x66;
    const MOV_BYTE_STORE: u8 = 0x88;
    Some(match bytes {
        BYTE_LOAD_BYTES => &[MOV_BYTE_STORE, ECX_FROM_RAX_MEMORY],
        HALFWORD_LOAD_BYTES => &[OPERAND_SIZE, MOV_STORE, ECX_FROM_RAX_MEMORY],
        WORD_LOAD_BYTES => &[MOV_STORE, ECX_FROM_RAX_MEMORY],
        DOUBLEWORD_LOAD_BYTES => &[REX | REX_W, MOV_STORE, ECX_FROM_RAX_MEMORY],
        _ => return None,
    })
}

/// Inspect the exact shared store: address, the data's frame load (or
/// zero) into RCX, and one host store, or with `crossing` the page-crossing
/// store recipe (`memory_store::crossing_store`), retaining its emitted
/// instruction boundaries. Branches stay within that recipe. Also returns the
/// index of the staged data's segment in the ends.
pub fn ordinary_store_ends(
    code: &[u8],
    bytes: u8,
    base: usize,
    data: Option<usize>,
    displacement: i32,
    crossing: bool,
) -> Option<(Vec<usize>, usize)> {
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let data_segment = ends.len();
    let data_end = check_store_data(code, *ends.last()?, data, false)?;
    ends.push(data_end);
    let recipe;
    let crossing_ends;
    let store = if crossing {
        (recipe, crossing_ends) = crate::x86_64::memory_store::crossing_store(bytes)?;
        &recipe[..]
    } else {
        crossing_ends = Vec::new();
        single_store(bytes)?
    };
    let end = data_end + store.len();
    if code.get(data_end..end)? != store {
        return None;
    }
    if crossing {
        ends.extend(crossing_ends.into_iter().map(|offset| data_end + offset));
    } else {
        ends.push(end);
    }
    (code.len() == end).then_some((ends, data_segment))
}

/// Inspect the exact shared W or X pair store: address, both elements'
/// data in RCX and R8, then one host store each, first element first. Also
/// the index of the first element's data segment in the ends.
pub fn ordinary_pair_store_ends(
    code: &[u8],
    bytes: u8,
    base: usize,
    data: [Option<usize>; 2],
    displacement: i32,
) -> Option<(Vec<usize>, usize)> {
    let second: [u8; 4] = match bytes {
        WORD_LOAD_BYTES => [REX | REX_R, MOV_STORE, R8D_FROM_RAX_DISP8, WORD_LOAD_BYTES],
        DOUBLEWORD_LOAD_BYTES => [
            REX | REX_W | REX_R,
            MOV_STORE,
            R8D_FROM_RAX_DISP8,
            DOUBLEWORD_LOAD_BYTES,
        ],
        _ => return None,
    };
    let mut ends = ordinary_address_ends(code, base, displacement)?;
    let data_segment = ends.len();
    let mut end = *ends.last()?;
    for (index, guest) in data.into_iter().enumerate() {
        end = check_store_data(code, end, guest, index == 1)?;
        ends.push(end);
    }
    let first = single_store(bytes)?;
    for store in [first, &second[..]] {
        let start = end;
        end += store.len();
        if code.get(start..end)? != store {
            return None;
        }
        ends.push(end);
    }
    (code.len() == end).then_some((ends, data_segment))
}
