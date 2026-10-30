//! APX new-destination integer forms; private until full recovery validation.
use super::{Alu, Asm, Gpr, Rm, Size};

/// A promoted ALU operation with independent destination and explicit flag policy.
pub(crate) struct AluOperands {
    pub(crate) operation: Alu,
    pub(crate) size: Size,
    pub(crate) destination: Gpr,
    pub(crate) left: Gpr,
    pub(crate) right: Gpr,
    pub(crate) preserve_flags: bool,
}

impl Asm<'_> {
    pub(crate) fn apx_alu(&mut self, operands: AluOperands) {
        let AluOperands {
            operation,
            size,
            destination,
            left,
            right,
            preserve_flags,
        } = operands;
        assert!(
            matches!(size, Size::Dword | Size::Qword),
            "APX guest integer ALU uses32/64-bit operands"
        );
        assert!(operation != Alu::Cmp, "CMP has no new destination");
        let destination = destination.number();
        let left_number = left.number();
        let right_number = right.number();
        self.code.extend([
            0x62,
            u8::from(right_number & 8 == 0) << 7
                | 0x40
                | u8::from(left_number & 8 == 0) << 5
                | u8::from(right_number & 16 == 0) << 4
                | u8::from(left_number & 16 != 0) << 3
                | 4,
            u8::from(size == Size::Qword) << 7 | (!destination & 15) << 3 | 4,
            0x10 | u8::from(destination & 16 == 0) << 3 | u8::from(preserve_flags) << 2,
            (operation as u8) << 3 | 1,
        ]);
        self.modrm(right_number, Rm::Reg(left));
        self.count();
    }
}

#[cfg(test)]
mod tests;
