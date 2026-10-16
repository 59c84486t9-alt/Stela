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
