//! Typed forms of the scalable and SVE lowerings beyond the encoder core,
//! built on its generic legacy, SSE and VEX forms (Intel SDM Vol. 2).
use crate::TargetCpu;
use crate::x86_64::asm::{Alu, Asm, Gpr, Map, Mem, Pp, Rm, Size, Vex};
use crate::x86_64::isa::SimdOpcode;

impl Asm<'_> {
    // Integer forms.

    /// `test rm, imm32` (F7 /0), sign-extended for a quadword.
    pub(crate) fn test_imm32(&mut self, size: Size, rm: impl Into<Rm>, value: i32) {
        self.legacy(size, None, &[0xf7], 0, false, rm.into());
        self.data(&value.to_le_bytes());
    }
    /// `test rm8, imm8` (F6 /0).
    pub(crate) fn test_byte_imm(&mut self, rm: impl Into<Rm>, value: u8) {
        self.legacy(Size::Byte, None, &[0xf6], 0, false, rm.into());
        self.data(&[value]);
    }
    /// `test al, imm8` (A8).
    pub(crate) fn test_al_imm8(&mut self, value: u8) {
        self.fixed(&[0xa8]);
        self.data(&[value]);
    }
    /// `test eax, imm32` (A9).
    pub(crate) fn test_eax_imm32(&mut self, value: u32) {
        self.fixed(&[0xa9]);
        self.data(&value.to_le_bytes());
    }
    /// `op rm8, imm8` (80 /digit).
    pub(crate) fn alu_byte_imm(&mut self, op: Alu, rm: impl Into<Rm>, value: u8) {
        self.legacy(Size::Byte, None, &[0x80], op as u8, false, rm.into());
        self.data(&[value]);
    }
    /// `inc rm` (FF /0).
    pub(crate) fn inc(&mut self, size: Size, rm: impl Into<Rm>) {
        debug_assert!(size != Size::Byte);
        self.legacy(size, None, &[0xff], 0, false, rm.into());
    }
    /// `dec rm` (FF /1).
    pub(crate) fn dec(&mut self, size: Size, rm: impl Into<Rm>) {
        debug_assert!(size != Size::Byte);
        self.legacy(size, None, &[0xff], 1, false, rm.into());
    }
    /// `bt rm, bit`: CF becomes bit `bit` of `rm`, modulo the operand width
    /// for a register and unbounded for memory.
    pub(crate) fn bt(&mut self, size: Size, rm: impl Into<Rm>, bit: Gpr) {
        self.legacy(size, None, &[0x0f, 0xa3], bit as u8, false, rm.into());
    }
    /// The 0F BA group: `bt`, `bts`, `btr` or `btc rm, imm8` by digit.
    fn bit_imm(&mut self, digit: u8, size: Size, rm: Rm, bit: u8) {
        self.legacy(size, None, &[0x0f, 0xba], digit, false, rm);
        self.data(&[bit]);
    }
    /// `bt rm, imm8`.
    pub(crate) fn bt_imm(&mut self, size: Size, rm: impl Into<Rm>, bit: u8) {
        self.bit_imm(4, size, rm.into(), bit);
    }
    /// `bts rm, imm8`.
    pub(crate) fn bts_imm(&mut self, size: Size, rm: impl Into<Rm>, bit: u8) {
        self.bit_imm(5, size, rm.into(), bit);
    }
    /// `btr rm, imm8`.
    pub(crate) fn btr_imm(&mut self, size: Size, rm: impl Into<Rm>, bit: u8) {
        self.bit_imm(6, size, rm.into(), bit);
    }
    /// `shld rm, src, imm8`.
    pub(crate) fn shld_imm(&mut self, size: Size, rm: impl Into<Rm>, source: Gpr, amount: u8) {
        self.legacy(size, None, &[0x0f, 0xa4], source as u8, false, rm.into());
        self.data(&[amount]);
    }
    /// A BMI1 group 17 form (VEX.0F38 F3 /digit) writing `destination`.
    fn bmi1_group(&mut self, digit: u8, size: Size, destination: Gpr, rm: Rm) {
        self.vex(
            Vex {
                map: Map::M0f38,
                pp: Pp::None,
                w: size == Size::Qword,
                l: false,
            },
            0xf3,
            digit,
            destination as u8,
            rm,
        );
    }
    /// `blsi dst, rm`: the lowest set bit of `rm` (BMI1).
    pub(crate) fn blsi(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.bmi1_group(3, size, destination, rm.into());
    }
    /// `blsmsk dst, rm`: the bits up to and including the lowest set bit
    /// of `rm` (BMI1).
    pub(crate) fn blsmsk(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.bmi1_group(2, size, destination, rm.into());
    }
    /// `rep movsb`: copy RCX bytes from [RSI] to [RDI].
    pub(crate) fn rep_movsb(&mut self) {
        self.prefix(0xf3);
        self.fixed(&[0xa4]);
    }

    // SSE forms.

    /// `movd xmm, rm32`.
    pub(crate) fn movd_to_xmm(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x6e], xmm, rm);
    }
    /// `movd rm32, xmm`.
    pub(crate) fn movd_from_xmm(&mut self, rm: impl Into<Rm>, xmm: u8) {
        self.sse(Some(0x66), &[0x0f, 0x7e], xmm, rm);
    }
    /// `movdqu xmm, xmm/m128`.
    pub(crate) fn movdqu_load(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf3), &[0x0f, 0x6f], xmm, rm);
    }
    /// `movdqu xmm/m128, xmm`.
    pub(crate) fn movdqu_store(&mut self, rm: impl Into<Rm>, xmm: u8) {
        self.sse(Some(0xf3), &[0x0f, 0x7f], xmm, rm);
    }
    /// `cvtsi2sd xmm, rm`: convert a signed integer to double.
    pub(crate) fn cvtsi2sd(&mut self, size: Size, xmm: u8, rm: impl Into<Rm>) {
        self.legacy(size, Some(0xf2), &[0x0f, 0x2a], xmm, false, rm.into());
    }
    /// `cvtsi2ss xmm, rm`: convert a signed integer to single.
    pub(crate) fn cvtsi2ss(&mut self, size: Size, xmm: u8, rm: impl Into<Rm>) {
        self.legacy(size, Some(0xf3), &[0x0f, 0x2a], xmm, false, rm.into());
    }
    /// `cvttsd2si dst, xmm/m64`: truncate a double to a signed integer.
    pub(crate) fn cvttsd2si(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            size,
            Some(0xf2),
            &[0x0f, 0x2c],
            destination as u8,
            false,
            rm.into(),
        );
    }
    /// `cvttss2si dst, xmm/m32`: truncate a single to a signed integer.
    pub(crate) fn cvttss2si(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.legacy(
            size,
            Some(0xf3),
            &[0x0f, 0x2c],
            destination as u8,
            false,
            rm.into(),
        );
    }
    /// `cvtss2sd xmm, xmm/m32`.
    pub(crate) fn cvtss2sd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf3), &[0x0f, 0x5a], xmm, rm);
    }
    /// `cvtps2pd xmm, xmm/m64`.
    pub(crate) fn cvtps2pd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(None, &[0x0f, 0x5a], xmm, rm);
    }
    /// `cvtpd2ps xmm, xmm/m128`.
    pub(crate) fn cvtpd2ps(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x5a], xmm, rm);
    }
    /// `cvtdq2pd xmm, xmm/m64`.
    pub(crate) fn cvtdq2pd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf3), &[0x0f, 0xe6], xmm, rm);
    }
    /// `cvttps2dq xmm, xmm/m128`: truncate singles to signed dwords.
    pub(crate) fn cvttps2dq(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf3), &[0x0f, 0x5b], xmm, rm);
    }
    /// `sqrtps xmm, xmm/m128`.
    pub(crate) fn sqrtps(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(None, &[0x0f, 0x51], xmm, rm);
    }
    /// `sqrtpd xmm, xmm/m128`.
    pub(crate) fn sqrtpd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x51], xmm, rm);
    }
    /// `psadbw xmm, xmm/m128`: sums of absolute byte differences per qword.
    pub(crate) fn psadbw(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0xf6], xmm, rm);
    }
    /// `pblendvb xmm, xmm/m128, <xmm0>` (SSE4.1): bytes of `rm` where XMM0
    /// bytes have their sign set.
    pub(crate) fn pblendvb(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x38, 0x10], xmm, rm);
    }
    /// `movq xmm, xmm/m64`: the low qword, zeroing the high one.
    pub(crate) fn movq_xmm(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf3), &[0x0f, 0x7e], xmm, rm);
    }
    /// `pextrw r32, xmm, imm8`.
    pub(crate) fn pextrw(&mut self, destination: Gpr, xmm: u8, lane: u8) {
        self.sse_imm(
            Some(0x66),
            &[0x0f, 0xc5],
            destination as u8,
            Rm::Xmm(xmm),
            lane,
        );
    }
    /// `pextrd rm32, xmm, imm8` (SSE4.1).
    pub(crate) fn pextrd(&mut self, rm: impl Into<Rm>, xmm: u8, lane: u8) {
        self.sse_imm(Some(0x66), &[0x0f, 0x3a, 0x16], xmm, rm, lane);
    }
    /// `pinsrw xmm, rm, imm8`.
    pub(crate) fn pinsrw(&mut self, xmm: u8, rm: impl Into<Rm>, lane: u8) {
        self.sse_imm(Some(0x66), &[0x0f, 0xc4], xmm, rm, lane);
    }
    /// `pinsrd xmm, rm32, imm8` (SSE4.1).
    pub(crate) fn pinsrd(&mut self, xmm: u8, rm: impl Into<Rm>, lane: u8) {
        self.sse_imm(Some(0x66), &[0x0f, 0x3a, 0x22], xmm, rm, lane);
    }
    /// `stmxcsr m32`.
    pub(crate) fn stmxcsr(&mut self, memory: Mem) {
        self.legacy(Size::Dword, None, &[0x0f, 0xae], 3, false, Rm::Mem(memory));
    }
    /// `ldmxcsr m32`.
    pub(crate) fn ldmxcsr(&mut self, memory: Mem) {
        self.legacy(Size::Dword, None, &[0x0f, 0xae], 2, false, Rm::Mem(memory));
    }
    /// `vzeroupper`.
    pub(crate) fn vzeroupper(&mut self) {
        self.fixed(&[0xc5, 0xf8, 0x77]);
    }

    // Floating-point SSE forms.

    /// `addps xmm, xmm/m128`.
    pub(crate) fn addps(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(None, &[0x0f, 0x58], xmm, rm);
    }
    /// `subps xmm, xmm/m128`.
    pub(crate) fn subps(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(None, &[0x0f, 0x5c], xmm, rm);
    }
    /// `mulps xmm, xmm/m128`.
    pub(crate) fn mulps(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(None, &[0x0f, 0x59], xmm, rm);
    }
    /// `addpd xmm, xmm/m128`.
    pub(crate) fn addpd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x58], xmm, rm);
    }
    /// `mulpd xmm, xmm/m128`.
    pub(crate) fn mulpd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x59], xmm, rm);
    }
    /// `addss xmm, xmm/m32`.
    pub(crate) fn addss(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf3), &[0x0f, 0x58], xmm, rm);
    }
    /// `subss xmm, xmm/m32`.
    pub(crate) fn subss(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf3), &[0x0f, 0x5c], xmm, rm);
    }
    /// `subsd xmm, xmm/m64`.
    pub(crate) fn subsd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf2), &[0x0f, 0x5c], xmm, rm);
    }
    /// `ucomiss xmm, xmm/m32`: unordered compare into ZF/PF/CF.
    pub(crate) fn ucomiss(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(None, &[0x0f, 0x2e], xmm, rm);
    }
    /// `ucomisd xmm, xmm/m64`: unordered compare into ZF/PF/CF.
    pub(crate) fn ucomisd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x2e], xmm, rm);
    }
    /// `addsd xmm, xmm/m64`.
    pub(crate) fn addsd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf2), &[0x0f, 0x58], xmm, rm);
    }
    /// `mulsd xmm, xmm/m64`.
    pub(crate) fn mulsd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0xf2), &[0x0f, 0x59], xmm, rm);
    }
    /// `minps xmm, xmm/m128`: the second operand where either is NaN or both
    /// are zero.
    pub(crate) fn minps(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(None, &[0x0f, 0x5d], xmm, rm);
    }
    /// `maxps xmm, xmm/m128`, with MINPS's second-operand rule.
    pub(crate) fn maxps(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(None, &[0x0f, 0x5f], xmm, rm);
    }
    /// `minpd xmm, xmm/m128`, with MINPS's second-operand rule.
    pub(crate) fn minpd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x5d], xmm, rm);
    }
    /// `maxpd xmm, xmm/m128`, with MINPS's second-operand rule.
    pub(crate) fn maxpd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x5f], xmm, rm);
    }
    /// `unpcklpd xmm, xmm/m128`: the low doubles of both operands.
    pub(crate) fn unpcklpd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x14], xmm, rm);
    }
    /// `unpckhpd xmm, xmm/m128`: the high doubles of both operands.
    pub(crate) fn unpckhpd(&mut self, xmm: u8, rm: impl Into<Rm>) {
        self.sse(Some(0x66), &[0x0f, 0x15], xmm, rm);
    }
    /// `cmpps xmm, xmm/m128, predicate`.
    pub(crate) fn cmpps(&mut self, xmm: u8, rm: impl Into<Rm>, predicate: u8) {
        self.sse_imm(None, &[0x0f, 0xc2], xmm, rm, predicate);
    }
    /// `cmppd xmm, xmm/m128, predicate`.
    pub(crate) fn cmppd(&mut self, xmm: u8, rm: impl Into<Rm>, predicate: u8) {
        self.sse_imm(Some(0x66), &[0x0f, 0xc2], xmm, rm, predicate);
    }
    /// `shufps xmm, xmm/m128, imm8`.
    pub(crate) fn shufps(&mut self, xmm: u8, rm: impl Into<Rm>, control: u8) {
        self.sse_imm(None, &[0x0f, 0xc6], xmm, rm, control);
    }

    // The SIMD opcode catalog.

    /// The catalog instruction `opcode` on `xmm` and `rm`; the selected CPU
    /// must provide its features.
    pub(crate) fn simd(
        &mut self,
        opcode: SimdOpcode,
        xmm: u8,
        rm: impl Into<Rm>,
        target: TargetCpu,
    ) {
        assert!(
            target.supports(opcode.requires()),
            "selected CPU requirements cannot emit {}",
            opcode.mnemonic()
        );
        let rm = rm.into();
        match *opcode.encoding() {
            [0xc4, map, fields, code] => self.vex(
                Vex {
                    map: match map & 0x1f {
                        1 => Map::M0f,
                        2 => Map::M0f38,
                        _ => Map::M0f3a,
                    },
                    pp: match fields & 3 {
                        0 => Pp::None,
                        1 => Pp::P66,
                        2 => Pp::Pf3,
                        _ => Pp::Pf2,
                    },
                    w: fields & 0x80 != 0,
                    l: fields & 4 != 0,
                },
                code,
                xmm,
                !(fields >> 3) & 15,
                rm,
            ),
            [prefix @ (0x66 | 0xf2 | 0xf3), 0x48, ref opcode @ ..] => {
                self.legacy(Size::Qword, Some(prefix), opcode, xmm, false, rm);
            }
            [prefix @ (0x66 | 0xf2 | 0xf3), ref opcode @ ..] => {
                self.legacy(Size::Dword, Some(prefix), opcode, xmm, false, rm);
            }
            ref opcode => self.legacy(Size::Dword, None, opcode, xmm, false, rm),
        }
    }
    /// The catalog instruction `opcode` writing general-purpose
    /// `destination` from `xmm` (PMOVMSKB, MOVMSKPS).
    pub(crate) fn simd_to_gpr(
        &mut self,
        opcode: SimdOpcode,
        destination: Gpr,
        xmm: u8,
        target: TargetCpu,
    ) {
        self.simd(opcode, destination as u8, Rm::Xmm(xmm), target);
    }
    /// [`Self::simd`] with an 8-bit immediate.
    pub(crate) fn simd_imm(
        &mut self,
        opcode: SimdOpcode,
        xmm: u8,
        rm: impl Into<Rm>,
        immediate: u8,
        target: TargetCpu,
    ) {
        self.simd(opcode, xmm, rm, target);
        self.data(&[immediate]);
    }
}

#[cfg(test)]
mod tests {
    use crate::TargetCpu;
    use crate::x86_64::asm::{Alu, Asm, Gpr::*, Mem, Rm, Size::*};
    use crate::x86_64::isa::SimdOpcode;
    use alloc::vec;

    #[test]
    fn scalable_forms_match_the_sdm_encodings() {
        for (expected, build) in [
            (
                &[0xf7, 0xc1, 0x1f, 0, 0, 0][..],
                (|a: &mut Asm| a.test_imm32(Dword, Rcx, 0x1f)) as fn(&mut Asm),
            ),
            (&[0xf6, 0x84, 0x24, 8, 0, 0, 0, 1], |a| {
                a.test_byte_imm(Mem::base_disp32(Rsp, 8), 1)
            }),
            (&[0xa8, 1], |a| a.test_al_imm8(1)),
            (&[0xa9, 0xff, 0xff, 0xff, 0x1f], |a| {
                a.test_eax_imm32(0x1fff_ffff)
            }),
            (&[0x80, 0xf9, 0x10], |a| a.alu_byte_imm(Alu::Cmp, Rcx, 0x10)),
            (&[0x41, 0xff, 0xc3], |a| a.inc(Dword, R11)),
            (&[0x48, 0xff, 0xc8], |a| a.dec(Qword, Rax)),
            (&[0x48, 0x0f, 0xa3, 0xc8], |a| a.bt(Qword, Rax, Rcx)),
            (&[0x41, 0x0f, 0xba, 0xe0, 15], |a| a.bt_imm(Dword, R8, 15)),
            (&[0x48, 0x0f, 0xba, 0xe8, 3], |a| a.bts_imm(Qword, Rax, 3)),
            (&[0x48, 0x0f, 0xba, 0xf0, 63], |a| a.btr_imm(Qword, Rax, 63)),
            (&[0x48, 0x0f, 0xa4, 0xc2, 1], |a| {
                a.shld_imm(Qword, Rdx, Rax, 1)
            }),
            (&[0xc4, 0xc2, 0xb0, 0xf3, 0xdb], |a| a.blsi(Qword, R9, R11)),
            (&[0xc4, 0xc2, 0xf8, 0xf3, 0xd1], |a| {
                a.blsmsk(Qword, Rax, R9)
            }),
            (&[0x66, 0x0f, 0x6e, 0xf1], |a| a.movd_to_xmm(6, Rcx)),
            (&[0x66, 0x0f, 0x7e, 0xd0], |a| a.movd_from_xmm(Rax, 2)),
            (&[0xf3, 0x0f, 0x6f, 0x44, 0x24, 0x10], |a| {
                a.movdqu_load(0, Mem::base_disp8(Rsp, 0x10))
            }),
            (&[0xf3, 0x0f, 0x7f, 0x9c, 0x24, 0x20, 0, 0, 0], |a| {
                a.movdqu_store(Mem::base_disp32(Rsp, 0x20), 3)
            }),
            (&[0xf2, 0x48, 0x0f, 0x2a, 0xd0], |a| {
                a.cvtsi2sd(Qword, 2, Rax)
            }),
            (&[0xf3, 0x48, 0x0f, 0x2a, 0xf0], |a| {
                a.cvtsi2ss(Qword, 6, Rax)
            }),
            (&[0xf2, 0x48, 0x0f, 0x2c, 0xc2], |a| {
                a.cvttsd2si(Qword, Rax, Rm::Xmm(2))
            }),
            (&[0xf3, 0x0f, 0x2c, 0xc0], |a| {
                a.cvttss2si(Dword, Rax, Rm::Xmm(0))
            }),
            (&[0xf3, 0x0f, 0x5a, 0xf6], |a| a.cvtss2sd(6, Rm::Xmm(6))),
            (&[0x0f, 0x5a, 0xc0], |a| a.cvtps2pd(0, Rm::Xmm(0))),
            (&[0x66, 0x0f, 0x5a, 0xc1], |a| a.cvtpd2ps(0, Rm::Xmm(1))),
            (&[0x66, 0x0f, 0x51, 0xc0], |a| a.sqrtpd(0, Rm::Xmm(0))),
            (&[0x66, 0x0f, 0xc4, 0xc8, 3], |a| a.pinsrw(1, Rax, 3)),
            (&[0x66, 0x0f, 0x3a, 0x22, 0xc8, 2], |a| a.pinsrd(1, Rax, 2)),
            (&[0x0f, 0xae, 0x9c, 0x24, 4, 0, 0, 0], |a| {
                a.stmxcsr(Mem::base_disp32(Rsp, 4))
            }),
            (&[0x0f, 0xae, 0x94, 0x24, 4, 0, 0, 0], |a| {
                a.ldmxcsr(Mem::base_disp32(Rsp, 4))
            }),
            (&[0xc5, 0xf8, 0x77], |a| a.vzeroupper()),
            (&[0x0f, 0x58, 0xd4], |a| a.addps(2, Rm::Xmm(4))),
            (&[0x0f, 0x5c, 0xc1], |a| a.subps(0, Rm::Xmm(1))),
            (&[0x0f, 0x59, 0xc1], |a| a.mulps(0, Rm::Xmm(1))),
            (&[0x66, 0x0f, 0x58, 0xdc], |a| a.addpd(3, Rm::Xmm(4))),
            (&[0x66, 0x0f, 0x59, 0xe7], |a| a.mulpd(4, Rm::Xmm(7))),
            (&[0xf3, 0x0f, 0x58, 0xc0], |a| a.addss(0, Rm::Xmm(0))),
            (&[0xf3, 0x0f, 0x5c, 0xc7], |a| a.subss(0, Rm::Xmm(7))),
            (&[0xf2, 0x0f, 0x5c, 0xc7], |a| a.subsd(0, Rm::Xmm(7))),
            (&[0x0f, 0x2e, 0xc7], |a| a.ucomiss(0, Rm::Xmm(7))),
            (&[0x66, 0x0f, 0x2e, 0xc7], |a| a.ucomisd(0, Rm::Xmm(7))),
            (&[0xf2, 0x0f, 0x58, 0xc1], |a| a.addsd(0, Rm::Xmm(1))),
            (&[0xf2, 0x0f, 0x59, 0xc1], |a| a.mulsd(0, Rm::Xmm(1))),
            (&[0x0f, 0x5d, 0xf5], |a| a.minps(6, Rm::Xmm(5))),
            (&[0x0f, 0x5f, 0xf5], |a| a.maxps(6, Rm::Xmm(5))),
            (&[0x66, 0x0f, 0x5d, 0xc1], |a| a.minpd(0, Rm::Xmm(1))),
            (&[0x66, 0x0f, 0x5f, 0xc1], |a| a.maxpd(0, Rm::Xmm(1))),
            (&[0x66, 0x0f, 0x14, 0xea], |a| a.unpcklpd(5, Rm::Xmm(2))),
            (&[0x66, 0x0f, 0x15, 0xe2], |a| a.unpckhpd(4, Rm::Xmm(2))),
            (&[0x0f, 0xc2, 0xc1, 3], |a| a.cmpps(0, Rm::Xmm(1), 3)),
            (&[0x66, 0x41, 0x0f, 0xc2, 0xc0, 0], |a| {
                a.cmppd(0, Rm::Xmm(8), 0)
            }),
            (&[0x0f, 0xc6, 0xc1, 0x88], |a| a.shufps(0, Rm::Xmm(1), 0x88)),
        ] {
            let mut code = vec![];
            let mut asm = Asm::new(&mut code);
            build(&mut asm);
            assert_eq!(asm.instructions(), 1);
            assert_eq!(code, expected);
        }
    }

    #[test]
    fn catalog_forms_match_their_encodings() {
        for (expected, build) in [
            (
                &[0x66, 0x0f, 0xdb, 0xca][..],
                (|a: &mut Asm| a.simd(SimdOpcode::And, 1, Rm::Xmm(2), TargetCpu::X86_64_V3))
                    as fn(&mut Asm),
            ),
            (&[0x66, 0x48, 0x0f, 0x6e, 0xf8], |a| {
                a.simd(SimdOpcode::MoveGprQword, 7, Rax, TargetCpu::X86_64_V3)
            }),
            (&[0x0f, 0x50, 0xc1], |a| {
                a.simd(
                    SimdOpcode::DwordSignMask,
                    0,
                    Rm::Xmm(1),
                    TargetCpu::X86_64_V3,
                )
            }),
            (&[0x66, 0x0f, 0x70, 0xc1, 0x1b], |a| {
                a.simd_imm(
                    SimdOpcode::ShuffleDword,
                    0,
                    Rm::Xmm(1),
                    0x1b,
                    TargetCpu::X86_64_V3,
                )
            }),
            (&[0xf3, 0x0f, 0x6f, 0x87, 8, 1, 0, 0], |a| {
                a.simd(
                    SimdOpcode::LoadUnaligned,
                    0,
                    Mem::base_disp32(Rdi, 0x108),
                    TargetCpu::X86_64_V3,
                )
            }),
            (&[0xc4, 0xe2, 0x79, 0x13, 0xc1], |a| {
                a.simd(
                    SimdOpcode::ConvertHalfToSingle,
                    0,
                    Rm::Xmm(1),
                    TargetCpu::X86_64_V3,
                )
            }),
            (&[0xc4, 0xe3, 0x79, 0x1d, 0xc8, 4], |a| {
                a.simd_imm(
                    SimdOpcode::ConvertSingleToHalf,
                    1,
                    Rm::Xmm(0),
                    4,
                    TargetCpu::X86_64_V3,
                )
            }),
        ] {
            let mut code = vec![];
            let mut asm = Asm::new(&mut code);
            build(&mut asm);
            assert_eq!(asm.instructions(), 1);
            assert_eq!(code, expected);
        }
    }

    #[test]
    #[should_panic(expected = "selected CPU requirements cannot emit pmulld")]
    fn catalog_forms_require_their_features() {
        let mut code = vec![];
        Asm::new(&mut code).simd(
            SimdOpcode::MultiplyLowDword,
            0,
            Rm::Xmm(1),
            TargetCpu::Baseline,
        );
    }
}
