//! Typed SSE, AVX and general-purpose forms the SIMD, SME and AMX lowerings
//! emit beyond the core encoder's (Intel SDM Vol. 2), built on its generic
//! legacy, SSE and VEX forms.
use crate::x86_64::asm::{Asm, Gpr, Rm, Size};

/// The general-purpose register numbered `number`.
pub(in crate::x86_64) const fn gpr(number: u8) -> Gpr {
    use Gpr::*;
    const REGISTERS: [Gpr; 16] = [
        Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15,
    ];
    REGISTERS[number as usize]
}

/// Legacy SSE forms `name xmm, xmm/m`: an optional mandatory prefix and the
/// opcode bytes.
macro_rules! sse {
    ($($(#[$doc:meta])* $name:ident => $prefix:expr, [$($opcode:literal),+];)+) => {
        impl Asm<'_> {
            $(
                $(#[$doc])*
                pub(in crate::x86_64) fn $name(&mut self, xmm: u8, rm: impl Into<Rm>) {
                    self.sse($prefix, &[$($opcode),+], xmm, rm);
                }
            )+
        }
    };
}

/// Legacy SSE forms `name xmm, xmm/m, imm8`.
macro_rules! sse_imm {
    ($($(#[$doc:meta])* $name:ident => $prefix:expr, [$($opcode:literal),+];)+) => {
        impl Asm<'_> {
            $(
                $(#[$doc])*
                pub(in crate::x86_64) fn $name(&mut self, xmm: u8, rm: impl Into<Rm>, immediate: u8) {
                    self.sse_imm($prefix, &[$($opcode),+], xmm, rm, immediate);
                }
            )+
        }
    };
}

sse! {
    /// `movlhps xmm, xmm`: the low qword of the source to the high qword.
    movlhps => None, [0x0f, 0x16];
    /// `movhlps xmm, xmm`: the high qword of the source to the low qword.
    movhlps => None, [0x0f, 0x12];
}

sse_imm! {
    /// `pinsrw xmm, r32/m16, imm8`.
    pinsrw => Some(0x66), [0x0f, 0xc4];
}

impl Asm<'_> {
    /// `vzeroupper` (AVX).
    pub(in crate::x86_64) fn vzeroupper(&mut self) {
        self.fixed(&[0xc5, 0xf8, 0x77]);
    }
    /// `movd xmm, r/m32`, zeroing the rest of `xmm`.
    pub(in crate::x86_64) fn movd_to_xmm(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.legacy(Size::Dword, Some(0x66), &[0x0f, 0x6e], xmm, false, rm.into());
    }
    /// `movd r/m32, xmm`.
    pub(in crate::x86_64) fn movd_from_xmm(&mut self, rm: impl Into<Rm>, xmm: u8) {
        self.legacy(Size::Dword, Some(0x66), &[0x0f, 0x7e], xmm, false, rm.into());
    }
    /// `movq r/m64, xmm` (66 REX.W 0F 7E).
    pub(in crate::x86_64) fn movq_store_xmm(&mut self, rm: impl Into<Rm>, xmm: u8) {
        self.legacy(Size::Qword, Some(0x66), &[0x0f, 0x7e], xmm, false, rm.into());
    }
    /// `stmxcsr m32`.
    pub(in crate::x86_64) fn stmxcsr(&mut self, memory: impl Into<Rm>) {
        self.legacy(Size::Dword, None, &[0x0f, 0xae], 3, false, memory.into());
    }
    /// `ldmxcsr m32`.
    pub(in crate::x86_64) fn ldmxcsr(&mut self, memory: impl Into<Rm>) {
        self.legacy(Size::Dword, None, &[0x0f, 0xae], 2, false, memory.into());
    }
    /// `test r/m, imm`: imm8 for a byte, imm16 for a word, otherwise imm32
    /// (sign-extended for a quadword).
    pub(in crate::x86_64) fn test_imm(&mut self, size: Size, rm: impl Into<Rm>, value: i32) {
        let opcode = if size == Size::Byte { 0xf6 } else { 0xf7 };
        self.legacy(size, None, &[opcode], 0, false, rm.into());
        match size {
            Size::Byte => self.data(&[value as u8]),
            Size::Word => self.data(&(value as u16).to_le_bytes()),
            Size::Dword | Size::Qword => self.data(&value.to_le_bytes()),
        }
    }
    /// `test al, imm8`, the accumulator short form.
    pub(in crate::x86_64) fn test_al_imm8(&mut self, value: u8) {
        self.fixed(&[0xa8]);
        self.data(&[value]);
    }
    /// `inc r/m`.
    pub(in crate::x86_64) fn inc(&mut self, size: Size, rm: impl Into<Rm>) {
        let opcode = if size == Size::Byte { 0xfe } else { 0xff };
        self.legacy(size, None, &[opcode], 0, false, rm.into());
    }
    /// `dec r/m`.
    pub(in crate::x86_64) fn dec(&mut self, size: Size, rm: impl Into<Rm>) {
        let opcode = if size == Size::Byte { 0xfe } else { 0xff };
        self.legacy(size, None, &[opcode], 1, false, rm.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::asm::{Code, Mem};

    fn one(build: impl FnOnce(&mut Asm)) -> Code {
        let mut code = Code::new();
        build(&mut code.asm());
        assert_eq!(code.instructions(), 1);
        code
    }

    #[test]
    fn forms_match_the_sdm_encodings() {
        use Gpr::*;
        assert_eq!(one(|a| a.vzeroupper()), [0xc5, 0xf8, 0x77]);
        assert_eq!(one(|a| a.movlhps(1, Rm::Xmm(2))), [0x0f, 0x16, 0xca]);
        assert_eq!(one(|a| a.movd_from_xmm(Rax, 6)), [0x66, 0x0f, 0x7e, 0xf0]);
        assert_eq!(one(|a| a.movd_to_xmm(4, Rax)), [0x66, 0x0f, 0x6e, 0xe0]);
        assert_eq!(
            one(|a| a.movq_store_xmm(Rax, 6)),
            [0x66, 0x48, 0x0f, 0x7e, 0xf0]
        );
        assert_eq!(
            one(|a| a.pinsrw(0, Rax, 1)),
            [0x66, 0x0f, 0xc4, 0xc0, 0x01]
        );
        assert_eq!(one(|a| a.stmxcsr(Mem::base(Rsp, 0))), [0x0f, 0xae, 0x1c, 0x24]);
        assert_eq!(
            one(|a| a.ldmxcsr(Mem::base(Rsp, 4))),
            [0x0f, 0xae, 0x54, 0x24, 0x04]
        );
        assert_eq!(
            one(|a| a.test_imm(Size::Dword, Mem::base_disp32(Rdi, 0x10), 0x20)),
            [0xf7, 0x87, 0x10, 0, 0, 0, 0x20, 0, 0, 0]
        );
        assert_eq!(
            one(|a| a.test_imm(Size::Byte, Mem::base_disp32(Rdi, 0x10), 0x10)),
            [0xf6, 0x87, 0x10, 0, 0, 0, 0x10]
        );
        assert_eq!(one(|a| a.test_al_imm8(0x3f)), [0xa8, 0x3f]);
        assert_eq!(one(|a| a.dec(Size::Dword, R8)), [0x41, 0xff, 0xc8]);
        assert_eq!(one(|a| a.inc(Size::Qword, Rcx)), [0x48, 0xff, 0xc1]);
    }

    #[test]
    fn registers_number_as_encoded() {
        assert_eq!(gpr(0), Gpr::Rax);
        assert_eq!(gpr(9), Gpr::R9);
    }
}
