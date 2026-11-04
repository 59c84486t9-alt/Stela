use super::{Host, round_pair, source_row};
use crate::{
    GuestAddress,
    aarch64::Instruction,
    x86_64::{
        asm::{Code, Map, Pp, Rm, Vex},
        simd::vector_memory,
    },
};
use alloc::vec::Vec;

#[cfg(test)]
mod tests;

/// Two independent in-place rounds that share a key and have adjacent frame
/// slots. All four source rows describe one fault-free native group.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    source_map: &mut Vec<(GuestAddress, usize)>,
    instructions: &[Instruction],
) -> Option<()> {
    let (first, opcode) = round_pair(instructions)?;
    let (second, other_opcode) = round_pair(instructions.get(2..)?)?;
    let (low, high, key) = (first.destination, second.destination, first.source);
    if instructions[1].pc.0.checked_add(4) != Some(instructions[2].pc.0)
        || low.checked_add(1) != Some(high)
        || key != second.source
        || key == low
        || key == high
        || opcode != other_opcode
    {
        return None;
    }
    let round = match opcode {
        Host::AesEncryptRound => 0xdc,
        Host::AesDecryptRound => 0xde,
        _ => unreachable!("a complete AES round"),
    };
    let move_unaligned = Vex {
        map: Map::M0f,
        pp: Pp::Pf3,
        w: false,
        l: true,
    };
    let xor = Vex {
        pp: Pp::None,
        ..move_unaligned
    };
    let aes = Vex {
        map: Map::M0f38,
        pp: Pp::P66,
        ..move_unaligned
    };
    let states = vector_memory(low).into();
    source_row(code, source_map, instructions[0].pc);
    let mut asm = code.asm();
    // VMOVDQU reads exactly the two adjacent vectors. VBROADCASTF128
    // reads the separate, possibly unaligned key slot only once.
    asm.vex(move_unaligned, 0x6f, 0, 0, states);
    asm.vex(aes, 0x1a, 1, 0, vector_memory(key).into());
    source_row(code, source_map, instructions[1].pc);
    code.asm().vex(xor, 0x57, 0, 0, Rm::Xmm(1));
    source_row(code, source_map, instructions[2].pc);
    let mut asm = code.asm();
    // Arm applies the key before the transforms. Both lanes of VAES use
    // a zero final key. VXORPS is bitwise and needs AVX, without AVX2.
    asm.vex(xor, 0x57, 1, 1, Rm::Xmm(1));
    asm.vex(aes, round, 0, 0, Rm::Xmm(1));
    source_row(code, source_map, instructions[3].pc);
    let mut asm = code.asm();
    asm.vex(move_unaligned, 0x7f, 0, 0, states);
    asm.vzeroupper();
    Some(())
}
