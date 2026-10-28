//! Typed SSE, AVX and general-purpose forms the SIMD, SME and AMX lowerings
//! emit beyond the core encoder's (Intel SDM Vol. 2), built on its generic
//! legacy, SSE and VEX forms.
use crate::x86_64::asm::{Asm, Cond, Gpr, Mem, Rm, Size};

/// The general-purpose register numbered `number`.
pub(in crate::x86_64) const fn gpr(number: u8) -> Gpr {
    use Gpr::*;
    const REGISTERS: [Gpr; 16] = [
        Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15,
    ];
    REGISTERS[number as usize]
}

/// The condition numbered `number` in Jcc, SETcc and CMOVcc encodings; the
/// low nibble of a Jcc rel32 second opcode byte.
pub(in crate::x86_64) const fn cond(number: u8) -> Cond {
    use Cond::*;
    const CONDITIONS: [Cond; 16] = [O, No, B, Ae, E, Ne, Be, A, S, Ns, P, Np, L, Ge, Le, G];
    CONDITIONS[(number & 0xf) as usize]
}

/// `[rdi + offset]` in GuestState, with a 32-bit displacement.
pub(in crate::x86_64) const fn guest(offset: u32) -> Mem {
    Mem::base_disp32(Gpr::Rdi, offset as i32)
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
    /// `movq m64, xmm` (66 0F D6), named by its register first.
    movq_store => Some(0x66), [0x0f, 0xd6];
    /// `unpcklps xmm, xmm/m128`.
    unpcklps => None, [0x0f, 0x14];
    /// `unpcklpd xmm, xmm/m128`.
    unpcklpd => Some(0x66), [0x0f, 0x14];
    /// `unpckhpd xmm, xmm/m128`.
    unpckhpd => Some(0x66), [0x0f, 0x15];
    /// `cvtss2sd xmm, xmm/m32`.
    cvtss2sd => Some(0xf3), [0x0f, 0x5a];
    /// `cvtsd2ss xmm, xmm/m64`.
    cvtsd2ss => Some(0xf2), [0x0f, 0x5a];
    /// `cvtps2pd xmm, xmm/m64`.
    cvtps2pd => None, [0x0f, 0x5a];
    /// `cvtpd2ps xmm, xmm/m128`.
    cvtpd2ps => Some(0x66), [0x0f, 0x5a];
    /// `cvttps2dq xmm, xmm/m128`.
    cvttps2dq => Some(0xf3), [0x0f, 0x5b];
    /// `ucomiss xmm, xmm/m32`.
    ucomiss => None, [0x0f, 0x2e];
    /// `ucomisd xmm, xmm/m64`.
    ucomisd => Some(0x66), [0x0f, 0x2e];
}

/// The lanes an SSE floating-point operation covers, which select its
/// mandatory prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::x86_64) enum FloatLanes {
    PackedSingle,
    ScalarSingle,
    PackedDouble,
    ScalarDouble,
}

impl FloatLanes {
    const fn prefix(self) -> Option<u8> {
        match self {
            Self::PackedSingle => None,
            Self::ScalarSingle => Some(0xf3),
            Self::PackedDouble => Some(0x66),
            Self::ScalarDouble => Some(0xf2),
        }
    }
}

/// SSE floating-point operations that share the `0F op` opcode across the
/// four lane forms (`ps`, `ss`, `pd`, `sd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::x86_64) enum FloatOp {
    Add = 0x58,
    Mul = 0x59,
    Sub = 0x5c,
    Min = 0x5d,
    Div = 0x5e,
    Max = 0x5f,
}

sse_imm! {
    /// `pinsrw xmm, r32/m16, imm8`.
    pinsrw => Some(0x66), [0x0f, 0xc4];
    /// `shufps xmm, xmm/m128, imm8`.
    shufps => None, [0x0f, 0xc6];
}

/// Bit test operations, numbered by their group 8 ModRM reg digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::x86_64) enum BitTest {
    Bt = 4,
    Bts = 5,
    Btr = 6,
    Btc = 7,
}

impl Asm<'_> {
    /// `op{ps,ss,pd,sd} xmm, xmm/m`.
    pub(in crate::x86_64) fn float(
        &mut self,
        op: FloatOp,
        lanes: FloatLanes,
        xmm: u8,
        rm: impl Into<Rm>,
    ) {
        self.sse(lanes.prefix(), &[0x0f, op as u8], xmm, rm);
    }
    /// `cmp{ps,ss,pd,sd} xmm, xmm/m, predicate`.
    pub(in crate::x86_64) fn float_compare(
        &mut self,
        lanes: FloatLanes,
        xmm: u8,
        rm: impl Into<Rm>,
        predicate: u8,
    ) {
        self.sse_imm(lanes.prefix(), &[0x0f, 0xc2], xmm, rm, predicate);
    }
    /// `pextrw r32, xmm, imm8` (66 0F C5): zero-extends word `lane`.
    pub(in crate::x86_64) fn pextrw(&mut self, destination: Gpr, xmm: u8, lane: u8) {
        self.sse_imm(
            Some(0x66),
            &[0x0f, 0xc5],
            destination as u8,
            Rm::Xmm(xmm),
            lane,
        );
    }
    /// `cvtsi2ss`/`cvtsi2sd xmm, r/m32/64` (F3/F2 [REX.W] 0F 2A) for a scalar
    /// `lanes` form.
    pub(in crate::x86_64) fn cvtsi2float(
        &mut self,
        lanes: FloatLanes,
        size: Size,
        xmm: u8,
        rm: impl Into<Rm>,
    ) {
        self.legacy(size, lanes.prefix(), &[0x0f, 0x2a], xmm, false, rm.into());
    }
    /// `cvtss2si`/`cvtsd2si r32/64, xmm/m` (0F 2D), or the truncating
    /// `cvtt` forms (0F 2C), for a scalar `lanes` form.
    pub(in crate::x86_64) fn cvtfloat2si(
        &mut self,
        lanes: FloatLanes,
        truncate: bool,
        size: Size,
        destination: Gpr,
        rm: impl Into<Rm>,
    ) {
        let opcode = if truncate { 0x2c } else { 0x2d };
        self.legacy(
            size,
            lanes.prefix(),
            &[0x0f, opcode],
            destination as u8,
            false,
            rm.into(),
        );
    }
    /// `vzeroupper` (AVX).
    pub(in crate::x86_64) fn vzeroupper(&mut self) {
        self.fixed(&[0xc5, 0xf8, 0x77]);
    }
    /// `movd xmm, r/m32`, zeroing the rest of `xmm`.
    pub(in crate::x86_64) fn movd_to_xmm(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.legacy(
            Size::Dword,
            Some(0x66),
            &[0x0f, 0x6e],
            xmm,
            false,
            rm.into(),
        );
    }
    /// `movd r/m32, xmm`.
    pub(in crate::x86_64) fn movd_from_xmm(&mut self, rm: impl Into<Rm>, xmm: u8) {
        self.legacy(
            Size::Dword,
            Some(0x66),
            &[0x0f, 0x7e],
            xmm,
            false,
            rm.into(),
        );
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
    /// `test al/eax/rax, imm`, the accumulator short form (A8 ib, A9 id).
    pub(in crate::x86_64) fn test_accumulator_imm(&mut self, size: Size, value: i32) {
        match size {
            Size::Byte => {
                self.fixed(&[0xa8]);
                self.data(&[value as u8]);
            }
            Size::Dword => {
                self.fixed(&[0xa9]);
                self.data(&value.to_le_bytes());
            }
            Size::Qword => {
                self.fixed(&[0x48, 0xa9]);
                self.data(&value.to_le_bytes());
            }
            Size::Word => {
                self.fixed(&[0x66, 0xa9]);
                self.data(&(value as u16).to_le_bytes());
            }
        }
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
    /// `bt`, `bts`, `btr` or `btc r/m, imm8` (0F BA /digit ib).
    pub(in crate::x86_64) fn bit_imm(
        &mut self,
        op: BitTest,
        size: Size,
        rm: impl Into<Rm>,
        bit: u8,
    ) {
        self.legacy(size, None, &[0x0f, 0xba], op as u8, false, rm.into());
        self.data(&[bit]);
    }
    /// `bt`, `bts`, `btr` or `btc r/m, reg` (0F A3, AB, B3, BB).
    pub(in crate::x86_64) fn bit(
        &mut self,
        op: BitTest,
        size: Size,
        rm: impl Into<Rm>,
        source: Gpr,
    ) {
        let opcode = 0xa3 | (op as u8 - BitTest::Bt as u8) << 3;
        self.legacy(size, None, &[0x0f, opcode], source as u8, false, rm.into());
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
            one(|a| a.movq_store(1, Mem::base(Rax, 8))),
            [0x66, 0x0f, 0xd6, 0x48, 0x08]
        );
        assert_eq!(one(|a| a.pinsrw(0, Rax, 1)), [0x66, 0x0f, 0xc4, 0xc0, 0x01]);
        assert_eq!(
            one(|a| a.stmxcsr(Mem::base(Rsp, 0))),
            [0x0f, 0xae, 0x1c, 0x24]
        );
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
        assert_eq!(
            one(|a| a.test_accumulator_imm(Size::Byte, 0x3f)),
            [0xa8, 0x3f]
        );
        assert_eq!(
            one(|a| a.test_accumulator_imm(Size::Dword, 0x0f)),
            [0xa9, 0x0f, 0, 0, 0]
        );
        assert_eq!(one(|a| a.dec(Size::Dword, R8)), [0x41, 0xff, 0xc8]);
        assert_eq!(one(|a| a.inc(Size::Qword, Rcx)), [0x48, 0xff, 0xc1]);
        assert_eq!(
            one(|a| a.bit_imm(BitTest::Btr, Size::Qword, Rax, 63)),
            [0x48, 0x0f, 0xba, 0xf0, 63]
        );
        assert_eq!(
            one(|a| a.bit_imm(BitTest::Btc, Size::Qword, Rax, 63)),
            [0x48, 0x0f, 0xba, 0xf8, 63]
        );
        assert_eq!(
            one(|a| a.bit(BitTest::Bt, Size::Qword, Rax, Rcx)),
            [0x48, 0x0f, 0xa3, 0xc8]
        );
        assert_eq!(
            one(|a| a.shufps(0, Rm::Xmm(1), 0x88)),
            [0x0f, 0xc6, 0xc1, 0x88]
        );
        assert_eq!(one(|a| a.unpcklps(0, Rm::Xmm(1))), [0x0f, 0x14, 0xc1]);
        assert_eq!(one(|a| a.unpckhpd(0, Rm::Xmm(6))), [0x66, 0x0f, 0x15, 0xc6]);
        assert_eq!(one(|a| a.ucomisd(0, Rm::Xmm(1))), [0x66, 0x0f, 0x2e, 0xc1]);
        assert_eq!(one(|a| a.cvtss2sd(6, Rm::Xmm(6))), [0xf3, 0x0f, 0x5a, 0xf6]);
        assert_eq!(one(|a| a.cvtsd2ss(0, Rm::Xmm(1))), [0xf2, 0x0f, 0x5a, 0xc1]);
        assert_eq!(one(|a| a.cvtps2pd(6, Rm::Xmm(0))), [0x0f, 0x5a, 0xf0]);
        assert_eq!(one(|a| a.cvtpd2ps(0, Rm::Xmm(1))), [0x66, 0x0f, 0x5a, 0xc1]);
        assert_eq!(
            one(|a| a.cvtsi2float(FloatLanes::ScalarDouble, Size::Qword, 0, Rax)),
            [0xf2, 0x48, 0x0f, 0x2a, 0xc0]
        );
        assert_eq!(
            one(|a| a.cvtfloat2si(FloatLanes::ScalarSingle, true, Size::Dword, Rax, Rm::Xmm(0))),
            [0xf3, 0x0f, 0x2c, 0xc0]
        );
        assert_eq!(one(|a| a.pextrw(Rax, 0, 0)), [0x66, 0x0f, 0xc5, 0xc0, 0]);
        assert_eq!(
            one(|a| a.pextrw(Rcx, 9, 3)),
            [0x66, 0x41, 0x0f, 0xc5, 0xc9, 3]
        );
        assert_eq!(
            one(|a| a.float_compare(FloatLanes::ScalarSingle, 1, Rm::Xmm(0), 2)),
            [0xf3, 0x0f, 0xc2, 0xc8, 2]
        );
        assert_eq!(
            one(|a| a.float(FloatOp::Min, FloatLanes::ScalarDouble, 0, Rm::Xmm(1))),
            [0xf2, 0x0f, 0x5d, 0xc1]
        );
        assert_eq!(
            one(|a| a.float(FloatOp::Max, FloatLanes::PackedSingle, 6, Rm::Xmm(1))),
            [0x0f, 0x5f, 0xf1]
        );
    }

    #[test]
    fn registers_number_as_encoded() {
        assert_eq!(gpr(0), Gpr::Rax);
        assert_eq!(gpr(9), Gpr::R9);
        assert_eq!(cond(0x84), Cond::E);
        assert_eq!(cond(0x0f), Cond::G);
    }
}
