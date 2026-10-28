//! Typed memory-access, atomic and fence forms (Intel SDM Vol. 2) on the
//! generic legacy encoding.
use super::{Alu, Asm, Gpr, Mem, Rm, Size};

/// PREFETCHh cache hints, numbered by their ModRM reg digit (0F 18 /digit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Prefetch {
    /// `prefetchnta`: non-temporal, minimizing cache pollution.
    Nta,
    /// `prefetcht0`: into every cache level.
    T0,
    /// `prefetcht1`: into level 2 and outward.
    T1,
    /// `prefetcht2`: into level 3 and outward.
    T2,
}

impl Asm<'_> {
    /// `prefetchnta`, `prefetcht0`, `prefetcht1` or `prefetcht2 m8`
    /// (0F 18 /digit).
    pub(crate) fn prefetch(&mut self, hint: Prefetch, memory: Mem) {
        self.legacy(
            Size::Dword,
            None,
            &[0x0f, 0x18],
            hint as u8,
            false,
            Rm::Mem(memory),
        );
    }
    /// `rdtsc` (0F 31): EDX:EAX = the time-stamp counter.
    pub(crate) fn rdtsc(&mut self) {
        self.fixed(&[0x0f, 0x31]);
    }
    /// `mfence` (0F AE F0): order every earlier load and store before every
    /// later one.
    pub(crate) fn mfence(&mut self) {
        self.fixed(&[0x0f, 0xae, 0xf0]);
    }
    /// `op al, imm8`, the byte accumulator short form (04 + 8 * op, ib).
    pub(crate) fn alu_accumulator_imm8(&mut self, op: Alu, value: u8) {
        self.fixed(&[(op as u8) << 3 | 4]);
        self.data(&[value]);
    }
    /// `shrd r/m, src, cl` (0F AD).
    pub(crate) fn shrd_cl(&mut self, size: Size, rm: impl Into<Rm>, source: Gpr) {
        self.legacy(size, None, &[0x0f, 0xad], source as u8, false, rm.into());
    }
    /// `cmpxchg r/m, src` (0F B0, 0F B1): compare the accumulator with
    /// `rm`, storing `source` when equal and loading `rm` otherwise.
    pub(crate) fn cmpxchg(&mut self, size: Size, rm: impl Into<Rm>, source: Gpr) {
        let opcode = if size == Size::Byte { 0xb0 } else { 0xb1 };
        self.legacy(size, None, &[0x0f, opcode], source as u8, true, rm.into());
    }
    /// `xadd r/m, src` (0F C0, 0F C1): `rm` += `source`, and `source` the
    /// old `rm`.
    pub(crate) fn xadd(&mut self, size: Size, rm: impl Into<Rm>, source: Gpr) {
        let opcode = if size == Size::Byte { 0xc0 } else { 0xc1 };
        self.legacy(size, None, &[0x0f, opcode], source as u8, true, rm.into());
    }
    /// `xchg r/m, src` (86, 87), implicitly locked for memory.
    pub(crate) fn xchg(&mut self, size: Size, rm: impl Into<Rm>, source: Gpr) {
        let opcode = if size == Size::Byte { 0x86 } else { 0x87 };
        self.legacy(size, None, &[opcode], source as u8, true, rm.into());
    }
    /// `cmpxchg8b m64` (0F C7 /1): compare EDX:EAX with memory, storing
    /// ECX:EBX when equal and loading it otherwise.
    pub(crate) fn cmpxchg8b(&mut self, memory: Mem) {
        self.legacy(Size::Dword, None, &[0x0f, 0xc7], 1, false, Rm::Mem(memory));
    }
    /// `cmpxchg16b m128` (REX.W 0F C7 /1): compare RDX:RAX with memory,
    /// storing RCX:RBX when equal and loading it otherwise.
    pub(crate) fn cmpxchg16b(&mut self, memory: Mem) {
        self.legacy(Size::Qword, None, &[0x0f, 0xc7], 1, false, Rm::Mem(memory));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::asm::{Code, Gpr::*};

    fn one(build: impl FnOnce(&mut Asm)) -> Code {
        let mut code = Code::new();
        build(&mut code.asm());
        assert_eq!(code.instructions(), 1);
        code
    }

    #[test]
    fn forms_match_the_sdm_encodings() {
        use Size::*;
        let rdx = Mem::base(Rdx, 0);
        for (expected, code) in [
            (&[0x0f, 0x0b][..], one(|a| a.ud2())),
            (&[0x0f, 0x31], one(|a| a.rdtsc())),
            (
                &[0x0f, 0x18, 0x00],
                one(|a| a.prefetch(Prefetch::Nta, Mem::base(Rax, 0))),
            ),
            (
                &[0x0f, 0x18, 0x5c, 0xc8, 0x10],
                one(|a| a.prefetch(Prefetch::T2, Mem::indexed(Rax, Rcx, 8, 0x10))),
            ),
            (
                &[0x0f, 0x18, 0x90, 0, 1, 0, 0],
                one(|a| a.prefetch(Prefetch::T1, Mem::base(Rax, 0x100))),
            ),
            (&[0x0f, 0xae, 0xf0], one(|a| a.mfence())),
            (&[0x3c, 12], one(|a| a.alu_accumulator_imm8(Alu::Cmp, 12))),
            (
                &[0x4c, 0x0f, 0xad, 0xc0],
                one(|a| a.shrd_cl(Qword, Rax, R8)),
            ),
            (&[0x0f, 0xb0, 0x0a], one(|a| a.cmpxchg(Byte, rdx, Rcx))),
            (
                &[0x66, 0x44, 0x0f, 0xb1, 0x02],
                one(|a| a.cmpxchg(Word, rdx, R8)),
            ),
            (
                &[0x4c, 0x0f, 0xb1, 0x02],
                one(|a| a.cmpxchg(Qword, rdx, R8)),
            ),
            (&[0x0f, 0xc0, 0x02], one(|a| a.xadd(Byte, rdx, Rax))),
            (&[0x48, 0x0f, 0xc1, 0x02], one(|a| a.xadd(Qword, rdx, Rax))),
            (&[0x86, 0x02], one(|a| a.xchg(Byte, rdx, Rax))),
            (&[0x66, 0x87, 0x02], one(|a| a.xchg(Word, rdx, Rax))),
            (
                &[0x41, 0x0f, 0xc7, 0x08],
                one(|a| a.cmpxchg8b(Mem::base(R8, 0))),
            ),
            (
                &[0x49, 0x0f, 0xc7, 0x08],
                one(|a| a.cmpxchg16b(Mem::base(R8, 0))),
            ),
        ] {
            assert_eq!(code, expected);
        }
    }
}
