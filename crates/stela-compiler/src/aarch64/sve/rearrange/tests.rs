use super::*;

mod prefix;
mod prefix_boundary;

#[test]
fn consecutive_operands_wrap_and_destructive_operands_are_explicit() {
    assert_eq!(
        decode(EXT_Z_ZI_CON_CLASS | (31 << SOURCE_SHIFT) | 4),
        Some(Ok(Operand::Extract {
            destination: 4,
            source: 31,
            second: 0,
            byte_offset: 0,
            segment: false,
        }))
    );
    assert_eq!(
        decode(EXT_Z_ZI_DES_CLASS | (31 << SOURCE_SHIFT) | 4),
        Some(Ok(Operand::Extract {
            destination: 4,
            source: 4,
            second: 31,
            byte_offset: 0,
            segment: false,
        }))
    );
}

#[test]
fn index_register_zero_and_signed_immediate_roles_are_explicit() {
    assert_eq!(
        decode(INDEX_Z_RI_CLASS | (16 << SECOND_SHIFT) | (31 << SOURCE_SHIFT)),
        Some(Ok(Operand::Index {
            destination: 0,
            start: IndexOperand::Register(Register::Zero),
            step: IndexOperand::Immediate(-16),
            element_size: ElementSize::Byte,
        }))
    );
}

#[test]
fn segment_duplicate_rejects_zero_size_and_decodes_all_other_values() {
    for encoded in 0..=REGISTER_MASK {
        let decoded = decode(DUPQ_Z_ZI_CLASS | (encoded << SECOND_SHIFT));
        if encoded & SEGMENT_IMMEDIATE_MASK == 0 {
            assert_eq!(decoded, Some(Err(())));
        } else {
            let Some(Ok(Operand::DuplicateSegment {
                element_size,
                index,
                ..
            })) = decoded
            else {
                panic!("allocated DUPQ failed");
            };
            assert!(usize::from(index) < 16 / element_size.bytes());
        }
    }
}

#[test]
fn logical_duplicate_uses_the_shared_reserved_mask_boundary() {
    for encoded in 0..=LOGICAL_IMMEDIATE_MASK {
        let expected = logical_mask(
            Width::X64,
            encoded >> LOGICAL_N_SHIFT,
            (encoded >> LOGICAL_ROTATION_SHIFT) & LOGICAL_FIELD_MASK,
            encoded & LOGICAL_FIELD_MASK,
        );
        let decoded = decode(DUPM_Z_I_CLASS | (encoded << SOURCE_SHIFT));
        assert_eq!(
            decoded.map(|result| result.map(|operand| match operand {
                Operand::DuplicateMask { mask, .. } => mask,
                _ => panic!("wrong duplicate allocation"),
            })),
            Some(expected.ok_or(()))
        );
    }
}

#[test]
fn reverse_double_requires_the_fixed_quadword_allocation() {
    assert_eq!(
        decode(REVD_Z_P_Z_M_CLASS),
        Some(Ok(Operand::ReverseDouble {
            destination: 0,
            source: 0,
            governing: 0,
        }))
    );
    for size in 1..=SIZE_MASK {
        assert_eq!(decode(REVD_Z_P_Z_M_CLASS | (size << SIZE_SHIFT)), None);
    }
    assert_eq!(decode(REVD_Z_P_Z_M_CLASS | (1 << 13)), None);
}
