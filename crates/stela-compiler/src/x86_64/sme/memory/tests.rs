use super::*;
use crate::aarch64::sme::memory::decode;
use alloc::vec;

const GENERIC_HALFWORD_LOAD: u32 = 0xa140_2000;
const SP_HALFWORD_LOAD: u32 = 0xa140_23e0;
const QUADWORD_TILE_LOAD: u32 = 0xe1c0_0000;
const QUADWORD_TILE_STORE: u32 = 0xe1e0_0000;
const NOP: u8 = 0x90;

#[test]
fn missing_capabilities_decline_before_any_emitted_effect() {
    let length = VectorLength::from_bytes(VECTOR_CHUNK_BYTES).unwrap();
    for (word, target) in [
        (GENERIC_HALFWORD_LOAD, TargetCpu::Baseline),
        (GENERIC_HALFWORD_LOAD, TargetCpu::Cx16),
        (QUADWORD_TILE_LOAD, TargetCpu::Cx16),
        (QUADWORD_TILE_STORE, TargetCpu::AtomicLoad16),
    ] {
        let mut code = vec![NOP];
        assert!(emit(&mut code, &decode(word).unwrap(), length, target, 0).is_err());
        assert_eq!(code, [NOP]);
    }
}

#[test]
fn read_and_write_requirements_are_independent() {
    assert!(
        validate_target(
            &decode(QUADWORD_TILE_LOAD).unwrap(),
            TargetCpu::AtomicLoad16
        )
        .is_ok()
    );
    assert!(validate_target(&decode(QUADWORD_TILE_STORE).unwrap(), TargetCpu::Cx16).is_ok());
    assert!(validate_target(&decode(SP_HALFWORD_LOAD).unwrap(), TargetCpu::Baseline).is_ok());
    for word in [0xe100_0000, 0xe120_0000, 0xe11f_8000, 0xe13f_8000] {
        assert!(validate_target(&decode(word).unwrap(), TargetCpu::Baseline).is_ok());
    }
}

#[test]
fn private_scratch_covers_every_group_and_table_without_overlap() {
    for bytes in [16, 32, 64, 128, 256] {
        let scratch = Scratch::new(VectorLength::from_bytes(bytes).unwrap());
        assert_eq!(scratch.bytes % STACK_ALIGNMENT, 0);
        assert!(scratch.address >= scratch.request + MEMORY_REQUEST_BYTES as u32);
        assert!(scratch.selector >= scratch.address + HOST_WORD_BYTES);
        assert!(scratch.iteration >= scratch.selector + HOST_WORD_BYTES);
        assert!(scratch.predicate >= scratch.iteration + HOST_WORD_BYTES);
        assert!(
            scratch.data
                >= scratch.predicate
                    + (bytes * MAX_VECTOR_GROUP / PREDICATE_GROUP_BITS_PER_BYTE) as u32
        );
        assert!(scratch.bytes >= scratch.data + (bytes * MAX_VECTOR_GROUP).max(ZT_BYTES) as u32);
    }
}

#[test]
fn entry_requirements_keep_descriptor_roles_and_profile_preflight() {
    let generic = requirements(&decode(GENERIC_HALFWORD_LOAD).unwrap());
    assert_eq!(generic.required_flags, flags::TAG_CHECKED);
    assert_eq!(generic.required_host_caps, host_caps::ATOMIC_LOAD16);
    assert_eq!(generic.required_sp_alignment, SpAlignmentRequirement::Any);
    assert_eq!(
        generic.required_profile,
        profile_requirements::NATIVE_ACCESS
            | profile_requirements::SCALABLE_TAG_CHECKS
            | profile_requirements::TAG_GRANULES
    );
    let stack = requirements(&decode(SP_HALFWORD_LOAD).unwrap());
    assert_eq!(stack.required_flags, 0);
    assert_eq!(stack.required_host_caps, 0);
    assert_eq!(stack.required_sp_alignment, SpAlignmentRequirement::Enabled);
    assert_eq!(stack.required_profile, profile_requirements::NATIVE_ACCESS);
    let quad = requirements(&decode(QUADWORD_TILE_STORE).unwrap());
    assert_eq!(
        quad.required_flags,
        flags::SME | flags::TAG_CHECKED | flags::WRITE
    );
    assert_eq!(quad.required_host_caps, host_caps::CX16);
    assert_eq!(quad.required_sp_alignment, SpAlignmentRequirement::Any);
    assert_eq!(
        quad.required_profile,
        profile_requirements::NATIVE_ACCESS
            | profile_requirements::TAG_GRANULES
            | profile_requirements::SCALABLE_TAG_CHECKS
    );
    let table = requirements(&decode(0xe13f_83e0).unwrap());
    assert_eq!(table.required_flags, flags::SME | flags::WRITE);
    assert_eq!(table.required_host_caps, 0);
    assert_eq!(table.required_sp_alignment, SpAlignmentRequirement::Enabled);
    assert_eq!(table.required_profile, profile_requirements::NATIVE_ACCESS);
}
