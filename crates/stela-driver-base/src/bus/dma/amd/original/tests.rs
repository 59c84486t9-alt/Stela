use super::*;

#[test]
fn literal_v_tv_mode_ir_iw_matrix_never_calls_identity_translation_or_v0_blocked() {
    for valid in [false, true] {
        for tv in [false, true] {
            for mode in 0..8u8 {
                for read in [false, true] {
                    for write in [false, true] {
                        let words = [
                            (u64::from(valid) * V)
                                | (u64::from(tv) * TV)
                                | (u64::from(mode) << 9)
                                | 0x1000
                                | (u64::from(read) * IR)
                                | (u64::from(write) * IW),
                            0,
                            0,
                            0,
                        ];
                        let decoded = data_mode(words);
                        if !valid {
                            assert_eq!(decoded, Ok(DataMode::Untranslated));
                        } else if !tv {
                            assert_eq!(decoded, Ok(DataMode::WalkTerminated));
                        } else if mode == 0 {
                            assert_eq!(decoded, Ok(DataMode::Identity { read, write }));
                        } else if mode < 7 {
                            assert_eq!(
                                decoded,
                                Ok(DataMode::Paged {
                                    levels: mode,
                                    root: 0x1000,
                                    domain: 0,
                                    read,
                                    write
                                })
                            );
                        } else {
                            assert_eq!(decoded, Err(Error::Reserved));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn tv0_does_not_erase_valid_smm_exclusion_io_and_iotlb_policies() {
    for policy in [
        1 << 40,
        2 << 40,
        3 << 40,
        EXCLUSION,
        1 << 35,
        2 << 35,
        3 << 35,
        IOTLB,
    ] {
        assert_eq!(data_mode([V, policy, 0, 0]), Ok(DataMode::WalkTerminated));
        assert_eq!(
            Dte::inspect_host([V, policy, 0, 0], 48),
            Err(Error::BypassPolicy)
        );
    }
}

#[test]
fn original_irq_words_and_sysmgt_zero_are_preserved_without_an_irq_grant() {
    for irq in [
        0,
        1,
        1 | (1 << 60),
        1 | (1 << 60) | (7 << 56) | (3 << 62) | (1 << 5),
    ] {
        let words = [V | TV | (4 << 9) | IR | IW | 0x4000, 0x1234, irq, 0];
        let dte = Dte::inspect_host(words, 48).unwrap();
        let blocked = dte.blocked_data();
        assert_eq!(blocked, [V, 0x1234, irq, 0]);
        assert_eq!(
            Dte::inspect_host(blocked, 48).unwrap().mode(),
            DataMode::WalkTerminated
        );
    }
}

#[test]
fn untranslated_unknown_writers_dormant_roots_and_interrupt_tables_refuse() {
    assert_eq!(Dte::inspect_host([0; 4], 48), Err(Error::Untranslated));
    for words in [[V | (1 << 7), 0, 0, 0], [V, 1 << 16, 0, 0], [V, 0, 0, 1]] {
        assert!(Dte::inspect_host(words, 48).is_err());
    }
    assert_eq!(
        Dte::inspect_host([V | 0x1000, 0, 0, 0], 48),
        Err(Error::DormantRoot)
    );
    assert_eq!(
        Dte::inspect_host([V, 0, 1 | (2 << 60) | 0x4000, 0], 48),
        Err(Error::InterruptTable)
    );
    assert_eq!(
        Dte::inspect_host([V, 0, 3 << 60, 0], 48),
        Err(Error::InterruptTable)
    );
}
