//! FPCR/FPSR access under the enabled AArch64 FP/FP16/AFP register policy.
use super::{
    Register,
    floating::{
        EXCEPTIONS, FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ,
        FPCR_FZ16, FPCR_NEP, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT, FPSR_QC,
    },
    register,
};

const ENCODING_MASK: u32 = 0xffffffe0;
const MRS_FPCR: u32 = 0xd53b4400;
const MSR_FPCR: u32 = 0xd51b4400;
const MRS_FPSR: u32 = 0xd53b4420;
const MSR_FPSR: u32 = 0xd51b4420;
const REGISTER_MASK: u32 = 31;
const FPCR_ACCESS_MASK: u32 = FPCR_FIZ
    | FPCR_AH
    | FPCR_NEP
    | FPCR_EXCEPTION_ENABLE_MASK
    | FPCR_FZ16
    | (FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT)
    | FPCR_FZ
    | FPCR_DN
    | FPCR_AHP;
const FPSR_ACCESS_MASK: u32 = FPSR_QC | EXCEPTIONS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemRegister {
    Fpcr,
    Fpsr,
}

impl SystemRegister {
    pub(crate) const fn mask(self) -> u32 {
        match self {
            Self::Fpcr => FPCR_ACCESS_MASK,
            Self::Fpsr => FPSR_ACCESS_MASK,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Read {
        register: SystemRegister,
        destination: Register,
    },
    Write {
        register: SystemRegister,
        source: Register,
    },
}

/// Only these four system-register encodings belong to this enabled-access
/// profile. Register 31 means XZR for reads and writes, never SP.
pub fn decode(word: u32) -> Option<Operand> {
    let operand = register(word & REGISTER_MASK, false);
    match word & ENCODING_MASK {
        MRS_FPCR => Some(Operand::Read {
            register: SystemRegister::Fpcr,
            destination: operand,
        }),
        MRS_FPSR => Some(Operand::Read {
            register: SystemRegister::Fpsr,
            destination: operand,
        }),
        MSR_FPCR => Some(Operand::Write {
            register: SystemRegister::Fpcr,
            source: operand,
        }),
        MSR_FPSR => Some(Operand::Write {
            register: SystemRegister::Fpsr,
            source: operand,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_read_write_and_register_role_is_explicit() {
        for (encoding, system_register, read) in [
            (MRS_FPCR, SystemRegister::Fpcr, true),
            (MSR_FPCR, SystemRegister::Fpcr, false),
            (MRS_FPSR, SystemRegister::Fpsr, true),
            (MSR_FPSR, SystemRegister::Fpsr, false),
        ] {
            for index in 0..=REGISTER_MASK {
                let operand = if index == REGISTER_MASK {
                    Register::Zero
                } else {
                    Register::X(index as u8)
                };
                let expected = if read {
                    Operand::Read {
                        register: system_register,
                        destination: operand,
                    }
                } else {
                    Operand::Write {
                        register: system_register,
                        source: operand,
                    }
                };
                assert_eq!(decode(encoding | index), Some(expected));
            }
        }
    }

    #[test]
    fn access_masks_match_the_declared_profile() {
        assert_eq!(SystemRegister::Fpcr.mask(), 0x07c89f07);
        assert_eq!(SystemRegister::Fpsr.mask(), 0x0800009f);
    }

    #[test]
    fn neighboring_system_registers_remain_outside_this_family() {
        const MRS_FPMR: u32 = 0xd53b4440;
        const MSR_FPMR: u32 = 0xd51b4440;
        const MRS_NZCV: u32 = 0xd53b4200;
        const MSR_NZCV: u32 = 0xd51b4200;
        const MRS_TPIDRRO_EL0: u32 = 0xd53bd060;
        const MRS_CNTVCT_EL0: u32 = 0xd53be040;
        for encoding in [
            MRS_FPMR,
            MSR_FPMR,
            MRS_NZCV,
            MSR_NZCV,
            MRS_TPIDRRO_EL0,
            MRS_CNTVCT_EL0,
        ] {
            for index in 0..=REGISTER_MASK {
                assert_eq!(decode(encoding | index), None);
            }
        }
    }
}
