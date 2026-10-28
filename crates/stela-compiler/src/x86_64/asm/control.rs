//! Typed control, flag-capture and absolute-address forms (Intel SDM Vol. 2)
//! beyond the core's branch, move and SETcc forms.
use super::{Asm, Cond};

/// The legacy high-byte registers AH, CH, DH and BH, which ModRM r/m
/// values 4 to 7 name in an instruction without a REX prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum HighByte {
    Ah = 4,
    Ch = 5,
    Dh = 6,
    Bh = 7,
}

impl Asm<'_> {
    /// `ud2` (0F 0B): raise #UD.
    pub(crate) fn ud2(&mut self) {
        self.fixed(&[0x0f, 0x0b]);
    }
    /// `setcc r/m8` (0F 90+cc /0) into AH, CH, DH or BH, without REX.
    pub(crate) fn setcc_high(&mut self, cond: Cond, register: HighByte) {
        self.fixed(&[0x0f, 0x90 | cond as u8, 0xc0 | register as u8]);
    }
    /// `mov rax, moffs64` (REX.W A1): RAX from the absolute `address`.
    pub(crate) fn mov_rax_moffs(&mut self, address: u64) {
        self.fixed(&[0x48, 0xa1]);
        self.data(&address.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::asm::Code;

    fn one(build: impl FnOnce(&mut Asm)) -> Code {
        let mut code = Code::new();
        build(&mut code.asm());
        assert_eq!(code.instructions(), 1);
        code
    }

    #[test]
    fn forms_match_the_sdm_encodings() {
        for (expected, code) in [
            (&[0x0f, 0x0b][..], one(|a| a.ud2())),
            (
                &[0x0f, 0x94, 0xc4],
                one(|a| a.setcc_high(Cond::E, HighByte::Ah)),
            ),
            (
                &[0x0f, 0x90, 0xc6],
                one(|a| a.setcc_high(Cond::O, HighByte::Dh)),
            ),
            (
                &[0x48, 0xa1, 8, 7, 6, 5, 4, 3, 2, 1],
                one(|a| a.mov_rax_moffs(0x0102_0304_0506_0708)),
            ),
        ] {
            assert_eq!(code, expected);
        }
    }
}
