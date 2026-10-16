use super::*;

#[test]
fn zero_register_writes_are_normalized_even_for_literal_requests() {
    let encoding = Encoding::new(3, 3, 4, 2, 0);
    let constructor = Request::write(encoding, ZERO_REGISTER, u64::MAX);
    assert_eq!(constructor.write_value(), Some(0));
    let literal = Request {
        encoding,
        kind: AccessKind::Write { value: u64::MAX },
        rt: ZERO_REGISTER,
    };
    assert_eq!(literal.write_value(), Some(0));
    assert_eq!(Request::read(encoding, ZERO_REGISTER).write_value(), None);
}

#[test]
fn every_register_selector_and_rt_packs_the_original_word_syndrome() {
    const MRS_BASE: u32 = 0xd5200000;
    const READ_DIRECTION_BIT: u32 = 1 << 21;
    const OP0_WORD_SHIFT: u32 = 19;
    const OP1_WORD_SHIFT: u32 = 16;
    const CRN_WORD_SHIFT: u32 = 12;
    const CRM_WORD_SHIFT: u32 = 8;
    const OP2_WORD_SHIFT: u32 = 5;
    for op0 in 2..=3 {
        for op1 in 0..=7 {
            for crn in 0..=15 {
                for crm in 0..=15 {
                    for op2 in 0..=7 {
                        let encoding = Encoding::new(op0, op1, crn, crm, op2);
                        for rt in 0..=ZERO_REGISTER {
                            for read in [false, true] {
                                let request = if read {
                                    Request::read(encoding, rt)
                                } else {
                                    Request::write(encoding, rt, 0)
                                };
                                let word = (MRS_BASE & !READ_DIRECTION_BIT)
                                    | (u32::from(read) << 21)
                                    | (u32::from(op0) << OP0_WORD_SHIFT)
                                    | (u32::from(op1) << OP1_WORD_SHIFT)
                                    | (u32::from(crn) << CRN_WORD_SHIFT)
                                    | (u32::from(crm) << CRM_WORD_SHIFT)
                                    | (u32::from(op2) << OP2_WORD_SHIFT)
                                    | u32::from(rt);
                                let source_iss = (((word >> 19) & 3) << 20)
                                    | (((word >> 5) & 7) << 17)
                                    | (((word >> 16) & 7) << 14)
                                    | (((word >> 12) & 15) << 10)
                                    | ((word & 31) << 5)
                                    | (((word >> 8) & 15) << 1)
                                    | ((word >> 21) & 1);
                                assert_eq!(request.system_access_iss(), source_iss);
                                assert_eq!(request.system_access_esr(), 0x62000000 | source_iss);
                            }
                        }
                    }
                }
            }
        }
    }
}
