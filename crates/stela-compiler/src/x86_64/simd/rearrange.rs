//! Lane moves and permutes. All inputs are read before the destination is written.
use super::{Host, commit, packed, read_vector, vector_offset};
use crate::x86_64::asm::{Alu, Code, Cond, Disp, Gpr, Mem, ShiftOp, Size, vector_extensions};
use crate::x86_64::simd::encode::guest;
use crate::{
    TargetCpu,
    aarch64::simd::rearrange::{LaneSource, Operand},
};
use Gpr::{R8, Rax, Rcx, Rdi, Rdx};

pub(super) fn constant(code: &mut Code, xmm: u8, bytes: [u8; 16]) {
    // MOVQ from a GPR followed by PUNPCKLQDQ avoids constant-pool relocations.
    for (register, limb) in [(xmm, &bytes[..8]), (7, &bytes[8..])] {
        let limb = u64::from_le_bytes(limb.try_into().expect("an eight-byte limb"));
        code.asm().mov_imm64(Rcx, limb);
        packed(code, Host::MoveGprQword, register, 1);
    }
    packed(code, Host::UnpackLowQword, xmm, 7);
}

/// Load `value` repeated in each `lane`-byte lane of `xmm` (clobbers RCX and XMM7).
pub(super) fn lane_constant(code: &mut Code, xmm: u8, lane: u8, value: u64) {
    let bytes = value.to_le_bytes();
    constant(
        code,
        xmm,
        core::array::from_fn(|i| bytes[i % usize::from(lane)]),
    );
}

/// Packed ADD or SUB for `lane`-byte lanes.
pub(super) fn add_or_subtract(lane: u8, subtract: bool) -> Host {
    match (subtract, lane) {
        (false, 1) => Host::AddByte,
        (false, 2) => Host::AddWord,
        (false, 4) => Host::AddDword,
        (false, 8) => Host::AddQword,
        (true, 1) => Host::SubByte,
        (true, 2) => Host::SubWord,
        (true, 4) => Host::SubDword,
        (true, 8) => Host::SubQword,
        _ => unreachable!("lane of 1, 2, 4 or 8 bytes"),
    }
}

fn load_lane(code: &mut Code, source: LaneSource, bytes: u8) {
    use crate::aarch64::Register;
    let offset = match source {
        LaneSource::General(Register::Zero) => {
            code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
            return;
        }
        LaneSource::General(Register::X(index)) => u32::from(index) * 8,
        LaneSource::Vector { register, byte } => vector_offset(register) + u32::from(byte),
        LaneSource::General(Register::Sp) => unreachable!("lane transfers use ZR, not SP"),
    };
    // Zero-extending load of the exact width into RAX, from GuestState.
    let mut asm = code.asm();
    match bytes {
        1 => asm.movzx(Size::Dword, Rax, Size::Byte, guest(offset)),
        2 => asm.movzx(Size::Dword, Rax, Size::Word, guest(offset)),
        4 => asm.mov_load(Size::Dword, Rax, guest(offset)),
        8 => asm.mov_load(Size::Qword, Rax, guest(offset)),
        _ => unreachable!("reviewed lane size"),
    }
}

/// UMOV, SMOV and FMOV to a general register ([`Operand::Extract`]),
/// which ends with the destination's store from RAX. With `held`, XMM0
/// holds the source vector whole and the lane is its lowest.
pub(super) fn extract(code: &mut Code, operand: &Operand, held: bool) {
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
        let mut asm = code.asm();
        match lane_bytes {
            1 | 2 | 4 => asm.movd_from_xmm(Rax, 0),
            8 => asm.movq_from_xmm(Rax, 0),
            _ => unreachable!("reviewed lane size"),
        }
        match lane_bytes {
            1 => asm.movzx(Size::Dword, Rax, Size::Byte, Rax),
            2 => asm.movzx(Size::Dword, Rax, Size::Word, Rax),
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
        let mut asm = code.asm();
        asm.shift_imm(ShiftOp::Shl, Size::Qword, Rax, shift);
        asm.shift_imm(ShiftOp::Sar, Size::Qword, Rax, shift);
        if !x64 {
            // W writes clear X high half.
            asm.mov(Size::Dword, Rax, Rax);
        }
    }
    // An unsigned lane of at most four bytes is zero-extended already.
    super::super::store(code, destination);
}

fn insert_lane(code: &mut Code, destination: u8, byte: u8, bytes: u8) {
    // Only the selected lane changes; even scalar-size INS preserves all others.
    let size = match bytes {
        1 => Size::Byte,
        2 => Size::Word,
        4 => Size::Dword,
        8 => Size::Qword,
        _ => unreachable!("reviewed lane size"),
    };
    code.asm().mov_store(
        size,
        guest(vector_offset(destination) + u32::from(byte)),
        Rax,
    );
}

fn permutation(
    code: &mut Code,
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
    clear_halves(code);
    for (output, input) in selection.into_iter().enumerate() {
        if input == 255 {
            continue;
        }
        let vector = if input < 16 { left } else { right };
        code.asm().movzx(
            Size::Dword,
            Rcx,
            Size::Byte,
            guest(vector_offset(vector) + u32::from(input % 16)),
        );
        accumulate_byte(code, output, false);
    }
    commit_halves(code, destination);
}

/// Clear RAX and RDX, the low and high halves of a gathered vector.
fn clear_halves(code: &mut Code) {
    let mut asm = code.asm();
    asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
    asm.alu(Alu::Xor, Size::Dword, Rdx, Rdx);
}

fn accumulate_byte(code: &mut Code, output: usize, r8: bool) {
    let shift = (output % 8 * 8) as u8;
    let byte = if r8 { R8 } else { Rcx };
    let mut asm = code.asm();
    if shift != 0 {
        asm.shift_imm(ShiftOp::Shl, Size::Qword, byte, shift);
    }
    let half = if output < 8 { Rax } else { Rdx };
    asm.alu(Alu::Or, Size::Qword, half, byte);
}
fn commit_halves(code: &mut Code, destination: u8) {
    let mut asm = code.asm();
    asm.mov_store(Size::Qword, guest(vector_offset(destination)), Rax);
    asm.mov_store(Size::Qword, guest(vector_offset(destination) + 8), Rdx);
}

fn table(code: &mut Code, operand: &Operand, target: TargetCpu) {
    let Operand::Table {
        destination,
        first,
        registers,
        indices,
        bytes,
        preserve,
    } = *operand
    else {
        unreachable!("a decoded table operation");
    };
    if vector_extensions::byte_table_supported(target) {
        read_vector(code, indices, 1);
        if preserve {
            read_vector(code, destination, 0);
        }
        let tables: alloc::vec::Vec<_> = (0..registers)
            .map(|index| guest(vector_offset((first + index) % 32)))
            .collect();
        vector_extensions::byte_table(code, 0, 1, &tables, preserve, [2, 3], target);
        if bytes == 8 {
            packed(code, Host::MoveQword, 0, 0);
        }
        commit(code, destination, 0);
        return;
    }
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
    clear_halves(code);
    for output in 0..bytes {
        let mut asm = code.asm();
        if preserve {
            // The old destination byte.
            asm.movzx(
                Size::Dword,
                R8,
                Size::Byte,
                guest(vector_offset(destination) + u32::from(output)),
            );
        } else {
            asm.alu(Alu::Xor, Size::Dword, R8, R8);
        }
        asm.movzx(
            Size::Dword,
            Rcx,
            Size::Byte,
            guest(vector_offset(indices) + u32::from(output)),
        );
        asm.alu_imm8(Alu::Cmp, Size::Dword, Rcx, (registers * 16) as i8);
        let fallback = asm.jcc(Cond::Ae);
        // The first register's byte offset; the vector bank wraps at V31.
        asm.alu_imm32(Alu::Add, Size::Dword, Rcx, i32::from(first) * 16);
        asm.alu_imm32(Alu::And, Size::Dword, Rcx, 32 * 16 - 1);
        asm.movzx(
            Size::Dword,
            R8,
            Size::Byte,
            Mem::indexed(Rdi, Rcx, 1, vector_offset(0) as i32).with_width(Disp::Dword),
        );
        asm.bind(fallback);
        accumulate_byte(code, usize::from(output), true);
    }
    commit_halves(code, destination);
}

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
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
        Operand::Table { .. } => table(code, operand, target),
    }
}
