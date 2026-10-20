//! Lane moves and permutes. All inputs are read before the destination is written.
use super::{Host, commit, packed, read_vector, vector_offset};
use crate::{
    TargetCpu,
    aarch64::simd::rearrange::{LaneSource, Operand},
};
use alloc::vec::Vec;

pub(super) fn constant(code: &mut Vec<u8>, xmm: u8, bytes: [u8; 16]) {
    // MOVQ from a GPR followed by PUNPCKLQDQ avoids constant-pool relocations.
    for (register, limb) in [(xmm, &bytes[..8]), (7, &bytes[8..])] {
        code.extend([0x48, 0xb9]); // movabs rcx,imm64
        code.extend(limb);
        packed(code, Host::MoveGprQword, register, 1);
    }
    packed(code, Host::UnpackLowQword, xmm, 7);
}

fn load_lane(code: &mut Vec<u8>, source: LaneSource, bytes: u8) {
    use crate::aarch64::Register;
    let offset = match source {
        LaneSource::General(Register::Zero) => {
            code.extend([0x31, 0xc0]);
            return;
        }
        LaneSource::General(Register::X(index)) => u32::from(index) * 8,
        LaneSource::Vector { register, byte } => vector_offset(register) + u32::from(byte),
        LaneSource::General(Register::Sp) => unreachable!("lane transfers use ZR, not SP"),
    };
    // Zero-extending load of the exact width into RAX, from GuestState.
    match bytes {
        1 => code.extend([0x0f, 0xb6, 0x87]),
        2 => code.extend([0x0f, 0xb7, 0x87]),
        4 => code.extend([0x8b, 0x87]),
        8 => code.extend([0x48, 0x8b, 0x87]),
        _ => unreachable!("reviewed lane size"),
    }
    code.extend(offset.to_le_bytes());
}

/// MOVD EAX,XMM0 and MOVQ RAX,XMM0.
const MOVD_EAX_XMM0: [u8; 4] = [0x66, 0x0f, 0x7e, 0xc0];
const MOVQ_RAX_XMM0: [u8; 5] = [0x66, 0x48, 0x0f, 0x7e, 0xc0];
/// MOVZX EAX,AL and MOVZX EAX,AX.
const MOVZX_EAX_AL: [u8; 3] = [0x0f, 0xb6, 0xc0];
const MOVZX_EAX_AX: [u8; 3] = [0x0f, 0xb7, 0xc0];

/// UMOV, SMOV and FMOV to a general register ([`Operand::Extract`]),
/// which ends with the destination's store from RAX. With `held`, XMM0
/// holds the source vector whole and the lane is its lowest.
pub(super) fn extract(code: &mut Vec<u8>, operand: &Operand, held: bool) {
    let Operand::Extract {
        destination,
        source,
        byte,
        lane_bytes,
        signed,
        x64,
    } = *operand
    else {
        unreachable!("an extract");
    };
    if held {
        debug_assert_eq!(byte, 0);
        match lane_bytes {
            1 | 2 | 4 => code.extend(MOVD_EAX_XMM0),
            8 => code.extend(MOVQ_RAX_XMM0),
            _ => unreachable!("reviewed lane size"),
        }
        match lane_bytes {
            1 => code.extend(MOVZX_EAX_AL),
            2 => code.extend(MOVZX_EAX_AX),
            _ => {}
        }
    } else {
        load_lane(
            code,
            LaneSource::Vector {
                register: source,
                byte,
            },
            lane_bytes,
        );
    }
    if signed {
        let shift = 64 - lane_bytes * 8;
        code.extend([0x48, 0xc1, 0xe0, shift, 0x48, 0xc1, 0xf8, shift]); // shl/sar rax for sign extension
        if !x64 {
            code.extend([0x89, 0xc0]); // W writes clear X high half
        }
    }
    // An unsigned lane of at most four bytes is zero-extended already.
    super::super::store(code, destination);
}

fn insert_lane(code: &mut Vec<u8>, destination: u8, byte: u8, bytes: u8) {
    // Only the selected lane changes; even scalar-size INS preserves all others.
    match bytes {
        1 => code.extend([0x88, 0x87]),
        2 => code.extend([0x66, 0x89, 0x87]),
        4 => code.extend([0x89, 0x87]),
        8 => code.extend([0x48, 0x89, 0x87]),
        _ => unreachable!("reviewed lane size"),
    }
    code.extend((vector_offset(destination) + u32::from(byte)).to_le_bytes());
}

fn permutation(
    code: &mut Vec<u8>,
    destination: u8,
    left: u8,
    right: u8,
    selection: [u8; 16],
    target: TargetCpu,
) {
    if target >= TargetCpu::Ssse3 {
        read_vector(code, left, 0);
        read_vector(code, right, 1);
        for (source, xmm) in [(0, 0), (16, 1)] {
            let mask = selection.map(|index| {
                if (source..source + 16).contains(&index) {
                    index - source
                } else {
                    0x80
                }
            });
            constant(code, 2, mask);
            Host::ByteShuffle.register(code, xmm, 2, target);
        }
        packed(code, Host::Or, 0, 1);
        commit(code, destination, 0);
        return;
    }
    // Scalar byte gather fallback. RAX/RDX accumulate both halves before stores;
    // RCX is the zero-extended byte scratch. No guest RAM or host stack accesses.
    code.extend([0x31, 0xc0, 0x31, 0xd2]);
    for (output, input) in selection.into_iter().enumerate() {
        if input == 255 {
            continue;
        }
        let vector = if input < 16 { left } else { right };
        code.extend([0x0f, 0xb6, 0x8f]); // movzx ecx,byte [rdi+disp32]
        code.extend((vector_offset(vector) + u32::from(input % 16)).to_le_bytes());
        accumulate_byte(code, output, false);
    }
    commit_halves(code, destination);
}

fn accumulate_byte(code: &mut Vec<u8>, output: usize, r8: bool) {
    let shift = (output % 8 * 8) as u8;
    if shift != 0 {
        code.extend(if r8 {
            [0x49, 0xc1, 0xe0, shift]
        } else {
            [0x48, 0xc1, 0xe1, shift]
        }); // shl r8/rcx,imm8
    }
    code.extend(match (r8, output < 8) {
        (false, true) => [0x48, 0x09, 0xc8],  // or rax,rcx
        (false, false) => [0x48, 0x09, 0xca], // or rdx,rcx
        (true, true) => [0x4c, 0x09, 0xc0],   // or rax,r8
        (true, false) => [0x4c, 0x09, 0xc2],  // or rdx,r8
    });
}
fn commit_halves(code: &mut Vec<u8>, destination: u8) {
    code.extend([0x48, 0x89, 0x87]); // mov [rdi+disp32],rax
    code.extend(vector_offset(destination).to_le_bytes());
    code.extend([0x48, 0x89, 0x97]); // mov [rdi+disp32+8],rdx
    code.extend((vector_offset(destination) + 8).to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn table(
    code: &mut Vec<u8>,
    destination: u8,
    first: u8,
    registers: u8,
    indices: u8,
    bytes: u8,
    preserve: bool,
    target: TargetCpu,
) {
    if target >= TargetCpu::Ssse3 {
        read_vector(code, indices, 1);
        packed(code, Host::Xor, 0, 0); // result
        packed(code, Host::Xor, 6, 6); // valid-index mask for TBX
        constant(code, 4, [0xf0; 16]);
        packed(code, Host::MoveAligned, 3, 1);
        packed(code, Host::And, 3, 4); // high nibble identifies table register, including unsigned OOB
        for index in 0..registers {
            constant(code, 5, [index * 16; 16]);
            packed(code, Host::EqualByte, 5, 3);
            packed(code, Host::Or, 6, 5);
            read_vector(code, (first + index) % 32, 2);
            Host::ByteShuffle.register(code, 2, 1, target);
            packed(code, Host::And, 2, 5);
            packed(code, Host::Or, 0, 2);
        }
        if preserve {
            read_vector(code, destination, 2);
            packed(code, Host::AndNot, 6, 2);
            packed(code, Host::Or, 0, 6);
        }
        if bytes == 8 {
            packed(code, Host::MoveQword, 0, 0);
        }
        commit(code, destination, 0);
        return;
    }
    code.extend([0x31, 0xc0, 0x31, 0xd2]);
    for output in 0..bytes {
        if preserve {
            code.extend([0x44, 0x0f, 0xb6, 0x87]); // movzx r8d,old destination byte
            code.extend((vector_offset(destination) + u32::from(output)).to_le_bytes());
        } else {
            code.extend([0x45, 0x31, 0xc0]);
        }
        code.extend([0x0f, 0xb6, 0x8f]); // movzx ecx,index byte
        code.extend((vector_offset(indices) + u32::from(output)).to_le_bytes());
        code.extend([0x83, 0xf9, registers * 16, 0x0f, 0x83]); // cmp ecx,bound; jae fallback
        let fixup = code.len();
        code.extend([0; 4]);
        code.extend([0x81, 0xc1]); // add ecx,first register byte offset
        code.extend((u32::from(first) * 16).to_le_bytes());
        code.extend([0x81, 0xe1]); // and ecx,511: vector bank wraps at V31
        code.extend((32u32 * 16 - 1).to_le_bytes());
        code.extend([0x44, 0x0f, 0xb6, 0x84, 0x0f]); // movzx r8d,[rdi+rcx+V0]
        code.extend(vector_offset(0).to_le_bytes());
        let distance = (code.len() - fixup - 4) as u32;
        code[fixup..fixup + 4].copy_from_slice(&distance.to_le_bytes());
        accumulate_byte(code, usize::from(output), true);
    }
    commit_halves(code, destination);
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    match *operand {
        Operand::Duplicate {
            destination,
            source,
            lane_bytes,
            bytes,
        } => {
            load_lane(code, source, lane_bytes);
            packed(code, Host::MoveGprQword, 0, 0);
            // Unpacks broadcast the low element without SSE3+ requirements.
            if bytes > lane_bytes {
                for opcode in [
                    Host::UnpackLowByte,
                    Host::UnpackLowWord,
                    Host::UnpackLowDword,
                    Host::UnpackLowQword,
                ]
                .into_iter()
                .skip(lane_bytes.trailing_zeros() as usize)
                {
                    packed(code, opcode, 0, 0);
                }
            }
            if bytes <= 8 {
                packed(code, Host::MoveQword, 0, 0);
            }
            commit(code, destination, 0);
        }
        Operand::Insert {
            destination,
            source,
            byte,
            lane_bytes,
        } => {
            load_lane(code, source, lane_bytes);
            insert_lane(code, destination, byte, lane_bytes);
        }
        Operand::Extract { .. } => extract(code, operand, false),
        Operand::Permute {
            destination,
            left,
            right,
            selection,
        } => permutation(code, destination, left, right, selection, target),
        Operand::Table {
            destination,
            first,
            registers,
            indices,
            bytes,
            preserve,
        } => table(
            code,
            destination,
            first,
            registers,
            indices,
            bytes,
            preserve,
            target,
        ),
    }
}
