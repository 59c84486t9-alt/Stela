use super::*;

#[test]
fn every_condition_matches_the_architectural_truth_table() {
    // Bit k describes the condition at NZCV nibble k, independently of the
    // implementation's predicate expressions. AL and NV are unconditional.
    const TRUTH: [u16; 16] = [
        0xf0f0, 0x0f0f, 0xcccc, 0x3333, 0xff00, 0x00ff, 0xaaaa, 0x5555, 0x0c0c, 0xf3f3, 0xaa55,
        0x55aa, 0x0a05, 0xf5fa, 0xffff, 0xffff,
    ];
    for (condition, expected) in TRUTH.into_iter().enumerate() {
        for nibble in 0..16 {
            let nzcv = (nibble << NZCV_SHIFT) | ((1 << NZCV_SHIFT) - 1);
            assert_eq!(
                condition_holds(condition as u8, nzcv),
                expected & (1 << nibble) != 0,
                "condition={condition}, NZCV={nibble:x}"
            );
        }
    }
}

#[test]
fn ignored_crm_bits_and_all_rotate_operands_decode() {
    for crm in 0..=FLAG_MASK {
        for (base, expected) in [
            (CFINV, Operand::InvertCarry),
            (AXFLAG, Operand::ArmToExternal),
            (XAFLAG, Operand::ExternalToArm),
        ] {
            assert_eq!(decode(base | (crm << 8)), Some(expected));
        }
    }
    for source in 0..=REGISTER_MASK {
        for rotation in 0..=ROTATION_MASK {
            for mask in 0..=FLAG_MASK {
                assert_eq!(
                    decode(RMIF | (source << SOURCE_SHIFT) | (rotation << ROTATION_SHIFT) | mask),
                    Some(Operand::RotateMask {
                        source: register(source, false),
                        rotation: rotation as u8,
                        mask: mask as u8,
                    })
                );
            }
        }
        for (base, width) in [(SETF8, SetWidth::Byte), (SETF16, SetWidth::Halfword)] {
            assert_eq!(
                decode(base | (source << SOURCE_SHIFT)),
                Some(Operand::Set {
                    source: register(source, false),
                    width,
                })
            );
        }
    }
}

#[test]
fn fixed_bits_do_not_alias_another_flag_operation() {
    for (base, mask) in [
        (CFINV, PSTATE_MASK),
        (AXFLAG, PSTATE_MASK),
        (XAFLAG, PSTATE_MASK),
        (RMIF, RMIF_MASK),
        (SETF8, SETF_MASK),
        (SETF16, SETF_MASK),
    ] {
        for bit in 0..u32::BITS {
            if mask & (1 << bit) != 0 {
                assert_ne!(decode(base ^ (1 << bit)), decode(base));
            }
        }
    }
}
