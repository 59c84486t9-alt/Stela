use super::*;
use crate::aarch64::{scalable::ElementSize, sve::memory_structure};
use alloc::vec::Vec;

const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
const TEST_PC: u64 = 0x1_4000_1000;
const MAX_REFERENCE_BODY_BYTES: usize = 8 * 1024;
const CALL_MEMORY_CALLBACK: &[u8] = &[
    0xff,
    0x57,
    crate::context::memory::MEMORY_CALLBACK_OFFSET as u8,
];

#[test]
fn requirements_bind_predication_tags_and_wide_read_capability() {
    const WIDTH_CLASSES: [(u32, ElementSize, bool); 10] = [
        (0xa420_e000, ElementSize::Byte, true),
        (0xa420_c000, ElementSize::Byte, false),
        (0xa4a0_e000, ElementSize::Halfword, true),
        (0xa4a0_c000, ElementSize::Halfword, false),
        (0xa520_e000, ElementSize::Word, true),
        (0xa520_c000, ElementSize::Word, false),
        (0xa5a0_e000, ElementSize::Doubleword, true),
        (0xa5a0_c000, ElementSize::Doubleword, false),
        (0xa490_e000, ElementSize::Quadword, true),
        (0xa4a0_8000, ElementSize::Quadword, false),
    ];
    const SP_ENCODING: u32 = 31 << 5;
    for (class, element, immediate) in WIDTH_CLASSES {
        for base in [0, SP_ENCODING] {
            let operand = memory_structure::decode(class | base).unwrap().unwrap();
            let required = requirements(operand);
            assert_eq!(
                required.required_sp_alignment,
                if base == SP_ENCODING {
                    SpAlignmentRequirement::Enabled
                } else {
                    SpAlignmentRequirement::Any
                }
            );
            let tag_checked = !immediate || base != SP_ENCODING;
            assert_eq!(
                required.required_flags,
                flags::SVE_PREDICATED | if tag_checked { flags::TAG_CHECKED } else { 0 }
            );
            let wide_read = element == ElementSize::Quadword
                || (element != ElementSize::Byte && base != SP_ENCODING);
            assert_eq!(
                required.required_host_caps,
                if wide_read {
                    host_caps::ATOMIC_LOAD16
                } else {
                    0
                }
            );
            assert_eq!(
                required.required_profile,
                profile_requirements::NATIVE_ACCESS
                    | if tag_checked {
                        profile_requirements::TAG_GRANULES
                            | profile_requirements::SCALABLE_TAG_CHECKS
                    } else {
                        0
                    }
            );
        }
    }
}

#[test]
fn private_staging_and_requests_are_disjoint_and_stack_aligned() {
    for bytes in LENGTHS {
        let length = VectorLength::from_bytes(bytes).unwrap();
        for registers in 2..=4 {
            let scratch = Scratch::new(registers, length);
            assert_eq!(scratch.bytes % STACK_ALIGNMENT, 0);
            assert_eq!(scratch.address, u32::from(registers) * bytes as u32);
            assert!(scratch.predicate + POINTER_BYTES <= scratch.request);
            assert_eq!(scratch.request + MEMORY_REQUEST_BYTES as u32, scratch.bytes);
        }
    }
}

#[test]
fn callback_body_grows_with_predicate_chunks_instead_of_each_byte_lane() {
    let operand = memory_structure::decode(0xa460_e000).unwrap().unwrap();
    assert_eq!(operand.element, ElementSize::Byte);
    for bytes in LENGTHS {
        let length = VectorLength::from_bytes(bytes).unwrap();
        let mut code = Vec::new();
        emit(&mut code, &operand, length, TargetCpu::Baseline, TEST_PC);
        let calls = code
            .windows(CALL_MEMORY_CALLBACK.len())
            .filter(|window| *window == CALL_MEMORY_CALLBACK)
            .count();
        assert_eq!(
            calls,
            usize::from(operand.registers) * bytes.div_ceil(PREDICATE_CHUNK_BITS)
        );
        assert!(code.len() < MAX_REFERENCE_BODY_BYTES);
        assert!(code.starts_with(SUB_RSP_IMM32));
        let cleanup = code
            .windows(ADD_RSP_IMM32.len())
            .rposition(|bytes| bytes == ADD_RSP_IMM32)
            .unwrap();
        let immediate = cleanup + ADD_RSP_IMM32.len();
        assert_eq!(
            &code[immediate..immediate + size_of::<u32>()],
            &Scratch::new(operand.registers, length).bytes.to_le_bytes()
        );
    }
}
