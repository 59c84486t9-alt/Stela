//! The NZCV word of pinned code.
//!
//! An Arm NZCV word takes nine host instructions to form, and every
//! flag-setting instruction forms one. So while pinned code runs,
//! `GuestState.nzcv` holds what LAHF and SETO leave in AX: N in bit 15, Z in
//! 14, C in 8 and V in 0, with C the Arm carry, which a subtraction's CMC
//! gives. Three instructions form it and leave the host flags with the same
//! meaning, so the next instruction may branch on them.
//!
//! The entry from the engine, the return to it and a fault's settlement
//! ([`super::pinned`]) convert, as does the frame a frame-bound emitter sees.
//! The engine and frame code see only Arm words. Code under PSTATE.DIT forms
//! the same word from the Arm one, as LAHF, SAHF and CMC are not on Intel's
//! data operand independent timing list.
use super::asm::{
    Alu, Asm, BitTest, Code, Cond,
    Gpr::{self, Rax, Rcx},
    Rm, ShiftOp, Size,
};

pub const NEGATIVE: u32 = 1 << 15;
pub const ZERO: u32 = 1 << 14;
pub const CARRY: u32 = 1 << 8;
pub const OVERFLOW: u32 = 1;
/// The bits of a word that hold flags; LAHF leaves others in AH.
pub const WORD_MASK: u32 = NEGATIVE | ZERO | CARRY | OVERFLOW;
/// Where an Arm word holds the four flags.
pub const ARM_SHIFT: u8 = 28;
pub const ARM_MASK: u32 = 0xf << ARM_SHIFT;
/// One product moves Arm's flags (N 3, Z 2, C 1, V 0) to bits 15, 14, 8 and
/// 0. No two partial products share a bit, so nothing carries.
pub const PACK_MULTIPLIER: u32 = (1 << 12) | (1 << 7) | 1;
/// One product moves bits 15, 14, 8 and 0 to 31, 30, 29 and 28. The partial
/// products below bit 28 are all different too, and the rest leave the word.
pub const UNPACK_MULTIPLIER: u32 = (1 << 16) | (1 << 21) | (1 << 28);

/// The word of Arm NZCV `flags`.
pub const fn packed(flags: u32) -> u32 {
    (flags >> ARM_SHIFT).wrapping_mul(PACK_MULTIPLIER) & WORD_MASK
}

/// The Arm NZCV of `word`.
pub const fn arm(word: u32) -> u32 {
    (word & WORD_MASK).wrapping_mul(UNPACK_MULTIPLIER) & ARM_MASK
}

/// Arm NZCV `flags` as `code` holds them.
pub(super) const fn constant(code: &Code, flags: u32) -> u32 {
    if code.is_pinned() {
        packed(flags)
    } else {
        flags
    }
}

/// `register`, an Arm NZCV word, as a word.
fn pack(asm: &mut Asm, register: Gpr) {
    asm.shift_imm(ShiftOp::Shr, Size::Dword, register, ARM_SHIFT);
    asm.imul_imm32(Size::Dword, register, register, PACK_MULTIPLIER as i32);
    asm.alu_imm32(Alu::And, Size::Dword, register, WORD_MASK as i32);
}

/// `register`, a word, as an Arm NZCV word.
fn unpack(asm: &mut Asm, register: Gpr) {
    asm.alu_imm32(Alu::And, Size::Dword, register, WORD_MASK as i32);
    asm.imul_imm32(Size::Dword, register, register, UNPACK_MULTIPLIER as i32);
    asm.alu_imm32(Alu::And, Size::Dword, register, ARM_MASK as i32);
}

/// The host flags as a word in AX, its C the Arm carry and so the host CF.
/// `borrow` takes C as an Arm subtraction does, the complement of the host
/// carry. Clobbers RDX under PSTATE.DIT.
pub(super) fn capture_in_rax(code: &mut Code, borrow: bool) {
    if code.constant_time() {
        super::capture_nzcv(code, borrow);
        pack(&mut code.asm(), Rax);
        return;
    }
    let mut asm = code.asm();
    if borrow {
        asm.cmc();
    }
    asm.lahf();
    asm.setcc(Cond::O, Rax);
}

/// `mov word [rdi+GuestState.nzcv],ax`. Only a capture ends so, which leaves
/// the host flags meaning what the word does.
pub(super) fn store_captured(asm: &mut Asm) {
    asm.with_flags(0, |asm, word| asm.mov_store(Size::Word, word, Rax));
}

/// [`capture_in_rax`] and [`store_captured`].
pub(super) fn capture(code: &mut Code, borrow: bool) {
    capture_in_rax(code, borrow);
    store_captured(&mut code.asm());
}

/// `mov dword [rdi+GuestState.nzcv],source`: a word in pinned code, an Arm
/// word in frame code.
pub(super) fn store(asm: &mut Asm, source: Gpr) {
    asm.with_flags(0, |asm, word| asm.mov_store(Size::Dword, word, source));
}

/// `mov dword [rdi+GuestState.nzcv],imm32`: a word in pinned code, an Arm
/// word in frame code.
pub(super) fn store_constant(asm: &mut Asm, value: u32) {
    asm.with_flags(0, |asm, word| {
        asm.mov_rm_imm32(Size::Dword, word, value as i32);
    });
}

/// CF = the guest's C, which frame code holds in `arm_bit`.
pub(super) fn carry(asm: &mut Asm, arm_bit: u8) {
    let bit = if asm.is_pinned() {
        CARRY.trailing_zeros() as u8
    } else {
        arm_bit
    };
    asm.with_flags(0, |asm, word| {
        asm.bit_imm(BitTest::Bt, Size::Dword, word, bit);
    });
}

/// `register` = the guest's Arm NZCV, from the word.
pub(super) fn load_arm(code: &mut Code, register: Gpr) {
    let mut asm = code.asm();
    asm.with_flags(0, |asm, word| {
        asm.movzx(Size::Dword, register, Size::Word, word);
    });
    unpack(&mut asm, register);
}

/// The frame's word as the Arm word frame code expects. Clobbers RCX, which
/// leaves a block's result in RAX.
pub(super) fn open(code: &mut Code) {
    load_arm(code, Rcx);
    store(&mut code.asm(), Rcx);
}

/// The frame's Arm word as a word, after [`open`]. Clobbers RCX.
pub(super) fn close(code: &mut Code) {
    let mut asm = code.asm();
    asm.with_flags(0, |asm, word| asm.mov_load(Size::Dword, Rcx, word));
    pack(&mut asm, Rcx);
    store(&mut asm, Rcx);
}

/// The host condition under which ARM `condition` (below 14) holds, from the
/// word, or from the host flags a capture just left when `live`. Clobbers EAX
/// and the host flags.
pub(super) fn condition(code: &mut Code, condition: u8, live: bool) -> Cond {
    let mut asm = code.asm();
    let (flag, positive, negative) = match condition / 2 {
        0 => (Some((1, ZERO >> 8)), Cond::E, Cond::Ne),
        1 => (Some((1, CARRY >> 8)), Cond::B, Cond::Ae),
        2 => (Some((1, NEGATIVE >> 8)), Cond::S, Cond::Ns),
        3 => (Some((0, OVERFLOW)), Cond::O, Cond::No),
        4 => (None, Cond::A, Cond::Be),
        5 => (None, Cond::Ge, Cond::L),
        _ => (None, Cond::G, Cond::Le),
    };
    if !live {
        match flag {
            Some((byte, mask)) => {
                asm.with_flags(byte, |asm, flags| {
                    asm.test_imm(Size::Byte, flags, mask as i32);
                });
                return if condition & 1 == 0 {
                    Cond::Ne
                } else {
                    Cond::E
                };
            }
            None => restore(&mut asm),
        }
    }
    // The host's A and BE read CF as a borrow.
    if condition / 2 == 4 {
        asm.cmc();
    }
    if condition & 1 == 0 {
        positive
    } else {
        negative
    }
}

/// The host flags as the word has them.
fn restore(asm: &mut Asm) {
    asm.with_flags(0, |asm, word| {
        asm.movzx(Size::Dword, Rax, Size::Word, word);
    });
    // OF = AL.
    asm.alu_byte_imm(Alu::Add, Rm::Reg(Rax), 0x7f);
    asm.sahf();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_nzcv_round_trips() {
        for flags in 0..16u32 {
            let word = packed(flags << ARM_SHIFT);
            assert_eq!(arm(word), flags << ARM_SHIFT);
            assert_eq!(
                [
                    word & NEGATIVE != 0,
                    word & ZERO != 0,
                    word & CARRY != 0,
                    word & OVERFLOW != 0,
                ],
                [
                    flags & 8 != 0,
                    flags & 4 != 0,
                    flags & 2 != 0,
                    flags & 1 != 0,
                ],
            );
        }
    }

    /// LAHF leaves AF, PF and its fixed bit in AH.
    #[test]
    fn the_other_bits_of_lahf_change_nothing() {
        for flags in 0..16u32 {
            let word = packed(flags << ARM_SHIFT) | 0b0001_0110 << 8;
            assert_eq!(arm(word), flags << ARM_SHIFT);
        }
    }
}
