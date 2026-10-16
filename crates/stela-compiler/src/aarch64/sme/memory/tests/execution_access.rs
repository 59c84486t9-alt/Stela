use super::*;
use alloc::vec::Vec;

const ORIGINAL_SP_BASE: u32 = REGISTER_MASK << BASE_SHIFT;

#[test]
fn source_helpers_preserve_group_and_zt_order() {
    use ScalableAccessCheck::{
        SmeAndZaEnabled, SmeEnabled, SmeZt0Enabled, StreamingSveAndZaEnabled, StreamingSveEnabled,
    };

    let cases: &[(u32, &[ScalableAccessCheck])] = &[
        (VECTOR_GROUP_CLASS, &[StreamingSveEnabled]),
        (TILE_BYTE_CLASS, &[StreamingSveAndZaEnabled]),
        (ZA_VECTOR_CLASS, &[SmeAndZaEnabled]),
        (ZT_CLASS, &[SmeEnabled, SmeZt0Enabled]),
    ];
    for &(class, expected) in cases {
        for direction in [0, STORE_BIT] {
            for base in [0, ORIGINAL_SP_BASE] {
                let operand = decode(class | direction | base).expect("valid memory operand");
                assert_eq!(
                    operand.execution_access_requirements(),
                    ScalableAccessRequirements::Known(expected.into())
                );
            }
        }
    }
}

#[test]
fn guest_quantity_uses_elements_and_whole_transfer_bytes() {
    let mut cases = Vec::new();
    for element in [
        ElementSize::Byte,
        ElementSize::Halfword,
        ElementSize::Word,
        ElementSize::Doubleword,
    ] {
        let encoded_size = element.bytes().trailing_zeros() << SIZE_SHIFT;
        cases.push((VECTOR_GROUP_CLASS | encoded_size, element));
    }
    cases.extend([
        (TILE_BYTE_CLASS, ElementSize::Byte),
        (TILE_HALFWORD_CLASS, ElementSize::Halfword),
        (TILE_WORD_CLASS, ElementSize::Word),
        (TILE_DOUBLEWORD_CLASS, ElementSize::Doubleword),
        (TILE_QUADWORD_CLASS, ElementSize::Quadword),
        (ZA_VECTOR_CLASS, ElementSize::Byte),
        (ZT_CLASS, ElementSize::Byte),
    ]);
    for (class, element) in cases {
        for direction in [0, STORE_BIT] {
            for base in [0, ORIGINAL_SP_BASE] {
                let operand = decode(class | direction | base).expect("valid memory operand");
                assert_eq!(
                    operand.guest_memory_quantity(),
                    GuestMemoryQuantity::Maximum(element)
                );
            }
        }
    }
}
