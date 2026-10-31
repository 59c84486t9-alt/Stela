//! Typed general-purpose forms (Intel SDM Vol. 2) beyond the core's ALU,
//! move, shift and branch forms.
use super::{Alu, Asm, Gpr, Map, Pp, Rm, Size, Vex};

/// Bit test operations, numbered by their group 8 ModRM reg digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum BitTest {
    Bt = 4,
    Bts = 5,
    Btr = 6,
    Btc = 7,
}

impl Asm<'_> {
    /// `lahf`: AH = SF:ZF:0:AF:0:PF:1:CF.
    pub(crate) fn lahf(&mut self) {
        self.fixed(&[0x9f]);
    }
    /// `sahf`: SF, ZF, AF, PF and CF from AH.
    pub(crate) fn sahf(&mut self) {
        self.fixed(&[0x9e]);
    }
    /// `cmc`: CF = !CF.
    pub(crate) fn cmc(&mut self) {
        self.fixed(&[0xf5]);
    }
    /// `sub rsp, imm32`: reserve `bytes` of private stack.
    pub(crate) fn reserve_stack(&mut self, bytes: usize) {
        self.alu_imm32(Alu::Sub, Size::Qword, Gpr::Rsp, bytes as i32);
    }
    /// `add rsp, imm32`: release `bytes` of private stack.
    pub(crate) fn release_stack(&mut self, bytes: usize) {
        self.alu_imm32(Alu::Add, Size::Qword, Gpr::Rsp, bytes as i32);
    }
    /// `op r/m8, imm8` (80 /digit).
    pub(crate) fn alu_byte_imm(&mut self, op: Alu, rm: impl Into<Rm>, value: u8) {
        self.legacy(Size::Byte, None, &[0x80], op as u8, false, rm.into());
        self.data(&[value]);
    }
    /// `test r/m, imm`: imm8 for a byte, imm16 for a word, otherwise imm32
    /// (sign-extended for a quadword).
    pub(crate) fn test_imm(&mut self, size: Size, rm: impl Into<Rm>, value: i32) {
        let opcode = if size == Size::Byte { 0xf6 } else { 0xf7 };
        self.legacy(size, None, &[opcode], 0, false, rm.into());
        match size {
            Size::Byte => self.data(&[value as u8]),
            Size::Word => self.data(&(value as u16).to_le_bytes()),
            Size::Dword | Size::Qword => self.data(&value.to_le_bytes()),
        }
    }
    /// `test al/ax/eax/rax, imm`, the accumulator short form (A8 ib, A9 iw/id).
    pub(crate) fn test_accumulator_imm(&mut self, size: Size, value: i32) {
        match size {
            Size::Byte => {
                self.fixed(&[0xa8]);
                self.data(&[value as u8]);
            }
            Size::Word => {
                self.fixed(&[0x66, 0xa9]);
                self.data(&(value as u16).to_le_bytes());
            }
            Size::Dword => {
                self.fixed(&[0xa9]);
                self.data(&value.to_le_bytes());
            }
            Size::Qword => {
                self.fixed(&[0x48, 0xa9]);
                self.data(&value.to_le_bytes());
            }
        }
    }
    /// `inc r/m`.
    pub(crate) fn inc(&mut self, size: Size, rm: impl Into<Rm>) {
        let opcode = if size == Size::Byte { 0xfe } else { 0xff };
        self.legacy(size, None, &[opcode], 0, false, rm.into());
    }
    /// `dec r/m`.
    pub(crate) fn dec(&mut self, size: Size, rm: impl Into<Rm>) {
        let opcode = if size == Size::Byte { 0xfe } else { 0xff };
        self.legacy(size, None, &[opcode], 1, false, rm.into());
    }
    /// `bt`, `bts`, `btr` or `btc r/m, imm8` (0F BA /digit ib).
    pub(crate) fn bit_imm(&mut self, op: BitTest, size: Size, rm: impl Into<Rm>, bit: u8) {
        self.legacy(size, None, &[0x0f, 0xba], op as u8, false, rm.into());
        self.data(&[bit]);
    }
    /// `bt`, `bts`, `btr` or `btc r/m, reg` (0F A3, AB, B3, BB): the bit
    /// index is modulo the operand width for a register and unbounded for
    /// memory.
    pub(crate) fn bit(&mut self, op: BitTest, size: Size, rm: impl Into<Rm>, source: Gpr) {
        let opcode = 0xa3 | (op as u8 - BitTest::Bt as u8) << 3;
        self.legacy(size, None, &[0x0f, opcode], source as u8, false, rm.into());
    }
    /// `shld r/m, src, imm8`.
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
    /// `blsi dst, r/m`: the lowest set bit of `rm` (BMI1).
    pub(crate) fn blsi(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.bmi1_group(3, size, destination, rm.into());
    }
    /// `blsmsk dst, r/m`: the bits up to and including the lowest set bit of
    /// `rm` (BMI1).
    pub(crate) fn blsmsk(&mut self, size: Size, destination: Gpr, rm: impl Into<Rm>) {
        self.bmi1_group(2, size, destination, rm.into());
    }
    /// `rep movsb`: copy RCX bytes from [RSI] to [RDI].
    pub(crate) fn rep_movsb(&mut self) {
        self.prefix(0xf3);
        self.fixed(&[0xa4]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::asm::{Code, Gpr::*, Mem};

    fn one(build: impl FnOnce(&mut Asm)) -> Code {
        let mut code = Code::new();
        build(&mut code.asm());
        assert_eq!(code.instructions(), 1);
        code
    }

    #[test]
    fn forms_match_the_sdm_encodings() {
        use BitTest::*;
        use Size::*;
        for (expected, code) in [
            (
                &[0xf7, 0xc1, 0x1f, 0, 0, 0][..],
                one(|a| a.test_imm(Dword, Rcx, 0x1f)),
            ),
            (
                &[0xf7, 0x87, 0x10, 0, 0, 0, 0x20, 0, 0, 0],
                one(|a| a.test_imm(Dword, Mem::base_disp32(Rdi, 0x10), 0x20)),
            ),
            (
                &[0xf6, 0x84, 0x24, 8, 0, 0, 0, 1],
                one(|a| a.test_imm(Byte, Mem::base_disp32(Rsp, 8), 1)),
            ),
            (&[0xa8, 0x3f], one(|a| a.test_accumulator_imm(Byte, 0x3f))),
            (
                &[0xa9, 0xff, 0xff, 0xff, 0x1f],
                one(|a| a.test_accumulator_imm(Dword, 0x1fff_ffff)),
            ),
            (
                &[0x80, 0xf9, 0x10],
                one(|a| a.alu_byte_imm(Alu::Cmp, Rcx, 0x10)),
            ),
            (&[0x41, 0xff, 0xc3], one(|a| a.inc(Dword, R11))),
            (&[0x48, 0xff, 0xc1], one(|a| a.inc(Qword, Rcx))),
            (&[0x41, 0xff, 0xc8], one(|a| a.dec(Dword, R8))),
            (
                &[0x48, 0x0f, 0xa3, 0xc8],
                one(|a| a.bit(Bt, Qword, Rax, Rcx)),
            ),
            (
                &[0x41, 0x0f, 0xba, 0xe0, 15],
                one(|a| a.bit_imm(Bt, Dword, R8, 15)),
            ),
            (
                &[0x48, 0x0f, 0xba, 0xe8, 3],
                one(|a| a.bit_imm(Bts, Qword, Rax, 3)),
            ),
            (
                &[0x48, 0x0f, 0xba, 0xf0, 63],
                one(|a| a.bit_imm(Btr, Qword, Rax, 63)),
            ),
            (
                &[0x48, 0x0f, 0xba, 0xf8, 63],
                one(|a| a.bit_imm(Btc, Qword, Rax, 63)),
            ),
            (
                &[0x48, 0x0f, 0xa4, 0xc2, 1],
                one(|a| a.shld_imm(Qword, Rdx, Rax, 1)),
            ),
            (
                &[0xc4, 0xc2, 0xb0, 0xf3, 0xdb],
                one(|a| a.blsi(Qword, R9, R11)),
            ),
            (
                &[0xc4, 0xc2, 0xf8, 0xf3, 0xd1],
                one(|a| a.blsmsk(Qword, Rax, R9)),
            ),
            (
                &[0x48, 0x81, 0xec, 0x40, 0, 0, 0],
                one(|a| a.reserve_stack(0x40)),
            ),
            (
                &[0x48, 0x81, 0xc4, 0x40, 0, 0, 0],
                one(|a| a.release_stack(0x40)),
            ),
        ] {
            assert_eq!(code, expected);
        }
    }
}
