//! The tagged variant's strip of an access address's top byte (Arm
//! `AddrTop`, TCR_ELx.TBI0 and TBI1), before the guest range check
//! ([`super::RangeCheck`]). The engine compiles a fetch page in this
//! variant once an access of the page had a top byte the regime ignores
//! (docs/design/system.md, "Host placement"): every other page keeps the
//! plain check, and so its bytes and its cost.
use super::asm::{self, Code};

/// Which halves of the address space a block's accesses ignore the top byte
/// of (Arm `AddrTop`: TCR_ELx.TBI0 for addresses whose bit 55 is clear, TBI1
/// for those whose bit 55 is set; TBID only concerns instruction addresses).
/// A data address the regime ignores the top byte of translates as its bits
/// 55:0 sign-extended from bit 55, which the shadow maps; any other address
/// keeps its top byte, and one that is not native fails the range check
/// after the clear as before it, so the engine takes its fault from the
/// guest's own registers.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum TopByte {
    /// No half: addresses are checked as they are (every block but the
    /// tagged variant's).
    #[default]
    Kept,
    /// TBI0 alone: an address whose bit 55 is clear loses its top byte
    /// (`mov rcx,rax; shl rcx,8; sar rcx,8; and rax,rcx`).
    Lower,
    /// TBI1 alone: an address whose bit 55 is set gets an all-ones top byte
    /// (`mov rcx,rax; shl rcx,8; sar rcx,8; or rax,rcx`).
    Upper,
    /// TBI0 and TBI1: every address is sign-extended from bit 55
    /// (`shl rax,8; sar rax,8`).
    Both,
}

impl TopByte {
    /// The halves TCR_ELx's TBI0 and TBI1 select.
    pub const fn of(lower: bool, upper: bool) -> Self {
        match (lower, upper) {
            (false, false) => Self::Kept,
            (true, false) => Self::Lower,
            (false, true) => Self::Upper,
            (true, true) => Self::Both,
        }
    }

    /// Whether `address`'s top byte is ignored.
    pub const fn ignores(self, address: u64) -> bool {
        match self {
            Self::Kept => false,
            Self::Lower => address & 1 << 55 == 0,
            Self::Upper => address & 1 << 55 != 0,
            Self::Both => true,
        }
    }

    /// The address the strip leaves for `address`.
    pub const fn strip(self, address: u64) -> u64 {
        if self.ignores(address) {
            (((address << 8) as i64) >> 8) as u64
        } else {
            address
        }
    }

    /// The strip of the access address in RAX; RCX and host flags are
    /// scratch, as for the range check that follows.
    pub(super) fn emit(self, code: &mut Code) {
        use asm::{
            Alu,
            Gpr::{Rax, Rcx},
            ShiftOp, Size,
        };
        const TOP_BITS: u8 = 8;
        let mut asm = code.asm();
        let alu = match self {
            Self::Kept => return,
            Self::Both => {
                asm.shift_imm(ShiftOp::Shl, Size::Qword, Rax, TOP_BITS);
                asm.shift_imm(ShiftOp::Sar, Size::Qword, Rax, TOP_BITS);
                return;
            }
            Self::Lower => Alu::And,
            Self::Upper => Alu::Or,
        };
        asm.mov(Size::Qword, Rcx, Rax);
        asm.shift_imm(ShiftOp::Shl, Size::Qword, Rcx, TOP_BITS);
        asm.shift_imm(ShiftOp::Sar, Size::Qword, Rcx, TOP_BITS);
        asm.alu(alu, Size::Qword, Rax, Rcx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    const LOWER: u64 = 0x0000_0001_0425_6e90;
    const UPPER: u64 = 0xffff_fe00_0000_1000;
    const TAG: u64 = 0x5a << 56;

    #[test]
    fn each_mode_strips_only_the_halves_it_names() {
        let lower_tagged = LOWER | TAG;
        // Bit 55 set, top byte not all ones: tagged in the upper half.
        let upper_tagged = UPPER & !(0xff << 56) | TAG;
        for (mode, lower, upper) in [
            (TopByte::Kept, lower_tagged, upper_tagged),
            (TopByte::Lower, LOWER, upper_tagged),
            (TopByte::Upper, lower_tagged, UPPER),
            (TopByte::Both, LOWER, UPPER),
        ] {
            assert_eq!(mode.strip(lower_tagged), lower, "{mode:?}");
            assert_eq!(mode.strip(upper_tagged), upper, "{mode:?}");
            // Untagged addresses never change.
            assert_eq!(mode.strip(LOWER), LOWER, "{mode:?}");
            assert_eq!(mode.strip(UPPER), UPPER, "{mode:?}");
        }
        assert_eq!(TopByte::of(false, false), TopByte::Kept);
        assert_eq!(TopByte::of(true, false), TopByte::Lower);
        assert_eq!(TopByte::of(false, true), TopByte::Upper);
        assert_eq!(TopByte::of(true, true), TopByte::Both);
        // PAC bits below the top byte stay, so the check still fails.
        let signed = LOWER | 0x0012 << 48 | TAG;
        assert_eq!(TopByte::Lower.strip(signed), LOWER | 0x0012 << 48);
    }

    #[test]
    fn the_strip_is_two_or_four_instructions_on_rax() {
        let bytes = |mode: TopByte| {
            let mut code = Code::new();
            mode.emit(&mut code);
            code.into_bytes()
        };
        assert!(bytes(TopByte::Kept).is_empty());
        // shl rax,8; sar rax,8
        assert_eq!(
            bytes(TopByte::Both),
            [0x48, 0xc1, 0xe0, 8, 0x48, 0xc1, 0xf8, 8]
        );
        // mov rcx,rax; shl rcx,8; sar rcx,8; and/or rax,rcx
        let copy = [0x48, 0x89, 0xc1, 0x48, 0xc1, 0xe1, 8, 0x48, 0xc1, 0xf9, 8];
        let mut lower = copy.to_vec();
        lower.extend([0x48, 0x21, 0xc8]);
        let mut upper = copy.to_vec();
        upper.extend([0x48, 0x09, 0xc8]);
        assert_eq!(bytes(TopByte::Lower), lower);
        assert_eq!(bytes(TopByte::Upper), upper);
    }

    /// The emitted strip, modelled instruction by instruction, gives
    /// [`TopByte::strip`] for addresses across both halves.
    #[test]
    fn the_emitted_sequence_computes_the_strip() {
        let shl_sar = |value: u64| (((value << 8) as i64) >> 8) as u64;
        let run = |mode: TopByte, rax: u64| match mode {
            TopByte::Kept => rax,
            TopByte::Both => shl_sar(rax),
            TopByte::Lower => rax & shl_sar(rax),
            TopByte::Upper => rax | shl_sar(rax),
        };
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..4096 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            for mode in [TopByte::Kept, TopByte::Lower, TopByte::Upper, TopByte::Both] {
                assert_eq!(run(mode, seed), mode.strip(seed), "{mode:?} {seed:#x}");
            }
        }
    }

    /// In a system-mode block, every access of the tagged variant strips
    /// right before its range check, none reusing an earlier access's
    /// address; the other variants' bytes do not change.
    #[test]
    fn only_the_tagged_variant_strips_and_it_checks_every_access() {
        use super::super::{MemoryChecks, RangeCheck};
        use crate::{
            GuestAddress, Options, TargetCpu,
            block::{BlockProfile, Features},
        };
        // ldr x2, [x9, #8]; ldr x3, [x9, #16]; ret
        let words: [u32; 3] = [0xf940_0522, 0xf940_0923, 0xd65f_03c0];
        let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let checks =
            MemoryChecks::system(true, false, true, true).with_range(RangeCheck::FIVE_LEVEL);
        let compile = |checks: MemoryChecks| {
            let options = Options::new(
                BlockProfile::new(Features::SYSTEM_MODE),
                TargetCpu::Baseline,
            )
            .with_memory_checks(checks);
            crate::compile(&source, GuestAddress(0x1_8000_0000), &options)
                .unwrap()
                .native
                .x86_64_code
        };
        // The strip, then the five-level check's copy and shift.
        let mut stripped_check = vec![0x48, 0x89, 0xc1, 0x48, 0xc1, 0xe1, 8, 0x48, 0xc1, 0xf9, 8];
        stripped_check.extend([0x48, 0x21, 0xc8, 0x48, 0x89, 0xc1, 0x48, 0xc1, 0xf9, 48]);
        let count = |code: &[u8]| {
            code.windows(stripped_check.len())
                .filter(|window| *window == stripped_check)
                .count()
        };
        let plain = compile(checks);
        assert_eq!(compile(checks.with_top_byte(TopByte::Kept)), plain);
        assert_eq!(count(&plain), 0);
        assert_eq!(count(&compile(checks.with_top_byte(TopByte::Lower))), 2);
    }
}
