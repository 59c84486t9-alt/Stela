use super::*;

#[test]
fn offset_fields_and_soft_fixed_bits_preserve_sp_roles() {
    for opcode in [ADDG, SUBG] {
        for address in 0..=ADDRESS_IMMEDIATE_MASK {
            for tag in 0..=TAG_MASK {
                for soft in 0..4 {
                    assert_eq!(
                        decode(
                            opcode
                                | (address << RIGHT_SHIFT)
                                | (soft << 14)
                                | (tag << TAG_IMMEDIATE_SHIFT)
                                | (31 << SOURCE_SHIFT)
                                | 31
                        ),
                        Some(Operand {
                            destination: Register::Sp,
                            kind: Kind::Offset {
                                source: Register::Sp,
                                subtract: opcode == SUBG,
                                address_offset: (address << ADDRESS_GRANULE_SHIFT) as u16,
                                tag_offset: tag as u8,
                            },
                        })
                    );
                }
            }
        }
    }
}

#[test]
fn register_forms_distinguish_source_sp_from_destination_zero() {
    for (opcode, kind) in [
        (
            SUBP,
            Kind::Difference {
                left: Register::Sp,
                right: Register::Sp,
                flags: false,
            },
        ),
        (
            SUBPS,
            Kind::Difference {
                left: Register::Sp,
                right: Register::Sp,
                flags: true,
            },
        ),
        (
            GMI,
            Kind::Mask {
                address: Register::Sp,
                mask: Register::Zero,
            },
        ),
    ] {
        assert_eq!(
            decode(opcode | (31 << RIGHT_SHIFT) | (31 << SOURCE_SHIFT) | 31),
            Some(Operand {
                destination: Register::Zero,
                kind
            })
        );
    }
}

#[test]
fn fixed_bits_do_not_absorb_unrelated_instructions() {
    for (opcode, mask) in [
        (ADDG, OFFSET_OPCODE_MASK),
        (SUBG, OFFSET_OPCODE_MASK),
        (SUBP, REGISTER_OPCODE_MASK),
        (SUBPS, REGISTER_OPCODE_MASK),
        (GMI, REGISTER_OPCODE_MASK),
    ] {
        for bit in 0..32 {
            if mask & (1 << bit) != 0 {
                let changed = opcode ^ (1 << bit);
                let belongs = [ADDG, SUBG].contains(&(changed & OFFSET_OPCODE_MASK))
                    || [SUBP, SUBPS, GMI].contains(&(changed & REGISTER_OPCODE_MASK));
                assert_eq!(decode(changed).is_some(), belongs);
            }
        }
    }
}
