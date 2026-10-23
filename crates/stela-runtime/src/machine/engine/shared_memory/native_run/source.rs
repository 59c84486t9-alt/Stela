//! Source instruction controls through the retained canonical RAM/table owner.
use super::super::{Controls, SharedMemory, mmu, policy};
use stela_compiler::context::memory::MemoryStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::machine::engine::shared_memory) enum FetchFailure {
    Fault(mmu::Fault),
    Refused(MemoryStatus),
}

pub(in crate::machine::engine::shared_memory) fn instruction(
    memory: &SharedMemory,
    controls: &Controls,
    pc: u64,
) -> Result<(u32, bool), FetchFailure> {
    let mut tables = policy::Tables::new(&memory.ram);
    let outcome = mmu::translate(
        &controls.translation,
        pc,
        mmu::Access::Execute,
        controls.requester,
        &mut tables,
    );
    if let Some(status) = tables.failure {
        return Err(FetchFailure::Refused(status));
    }
    let mapped = match outcome {
        mmu::Outcome::Mapped(mapped) => mapped,
        mmu::Outcome::Fault(fault) => {
            // A non-GL fetch of GL-only SPRR code has an unqualified GXF
            // abort-entry contract; do not turn that into an ordinary abort.
            if fault.kind == mmu::FaultKind::Permission
                && controls.requester.el != 0
                && !controls.requester.guarded
                && controls.translation.sprr.enabled()
            {
                let guarded = mmu::translate(
                    &controls.translation,
                    pc,
                    mmu::Access::Execute,
                    mmu::Requester {
                        guarded: true,
                        ..controls.requester
                    },
                    &mut tables,
                );
                if let Some(status) = tables.failure {
                    return Err(FetchFailure::Refused(status));
                }
                if matches!(guarded, mmu::Outcome::Mapped(_)) {
                    return Err(FetchFailure::Refused(MemoryStatus::Unsupported));
                }
            }
            return Err(FetchFailure::Fault(fault));
        }
        mmu::Outcome::Unsupported(_) => {
            return Err(FetchFailure::Refused(MemoryStatus::Unsupported));
        }
    };
    if mapped.memory != mmu::MemoryType::Normal
        || mapped.attributes == mmu::attributes::TAGGED
        || 4 > mapped.size - (mapped.physical & (mapped.size - 1))
    {
        return Err(FetchFailure::Refused(MemoryStatus::Unsupported));
    }
    let mut word = [0; 4];
    // SAFETY: private source staging, same all-reader owner and stopped writers.
    unsafe { memory.ram.read_physical(mapped.physical, &mut word) }
        .map_err(FetchFailure::Refused)?;
    Ok((u32::from_le_bytes(word), mapped.guarded))
}

/// Arm BTypeNext for an actual completed BR/BLR/RET at this source leaf.
/// Direct branches/fallthrough clear BTYPE. The source page, not its target,
/// supplies InGuardedPage; X16/X17 are independently the veneer registers.
pub(in crate::machine::engine::shared_memory) fn branch_type(word: u32, guarded: bool) -> u8 {
    match word & 0xffff_fc1f {
        0xd61f_0000 if matches!((word >> 5) & 31, 16 | 17) || !guarded => 0b01,
        0xd61f_0000 => 0b11,
        0xd63f_0000 => 0b10,
        _ => 0,
    }
}

/// Arm BTypeCompatible_BTI/PAC. Identical source rules to Machine's ordinary
/// entry check, applied to the actual canonical fetch before native dispatch.
pub(in crate::machine::engine::shared_memory) fn target_accepts(
    word: u32,
    btype: u8,
    sctlr: u64,
    el: u8,
) -> bool {
    if word & 0xffff_ff3f == 0xd503_241f {
        return match (word >> 6) & 3 {
            0 => btype == 0,
            1 => btype != 3,
            2 => btype != 2,
            _ => true,
        };
    }
    if matches!(word, 0xd503_233f | 0xd503_237f)
        || stela_compiler::block::pauth_lr::signs_with_implicit_bti(word)
    {
        let forbid = 1 << if el == 0 { 35 } else { 36 };
        return btype != 3 || sctlr & forbid == 0;
    }
    matches!(word & 0xffe0_001f, 0xd420_0000 | 0xd440_0000)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guarded_instruction_fetch_uses_the_same_canonical_descriptor_and_source_bytes() {
        let (mut machine, ram, events) = super::super::super::tests::machine();
        machine
            .install_shared_memory_for_processors(alloc::sync::Arc::clone(&ram), &events)
            .unwrap();
        let controls =
            Controls::capture(&machine.cpu, machine.profile.name, &machine.profile_missing)
                .unwrap();
        let memory = machine.cpu.canonical_memory.as_ref().unwrap();
        const LEAF: u64 = 0x13020;
        const DATA: u64 = 0x14000;
        const GP: u64 = 1 << 50;
        unsafe { ram.publish_physical(DATA, &0xd503_245fu32.to_le_bytes()) }.unwrap();
        assert_eq!(
            instruction(memory, &controls, 0x4000),
            Ok((0xd503_245f, false))
        );
        let mut bytes = [0; 8];
        unsafe { ram.read_physical(LEAF, &mut bytes) }.unwrap();
        let descriptor = u64::from_le_bytes(bytes);
        unsafe { ram.publish_physical(LEAF, &(descriptor | GP).to_le_bytes()) }.unwrap();
        assert_eq!(
            instruction(memory, &controls, 0x4000),
            Ok((0xd503_245f, true))
        );
        unsafe { ram.publish_physical(LEAF, &0u64.to_le_bytes()) }.unwrap();
        assert!(matches!(
            instruction(memory, &controls, 0x4000),
            Err(FetchFailure::Fault(_))
        ));
    }

    #[test]
    fn normal_fetch_hints_keep_exact_bytes_guard_and_tagged_refusal() {
        let (mut machine, ram, events) = super::super::super::tests::machine();
        machine
            .install_shared_memory_for_processors(alloc::sync::Arc::clone(&ram), &events)
            .unwrap();
        let mut controls =
            Controls::capture(&machine.cpu, machine.profile.name, &machine.profile_missing)
                .unwrap();
        let memory = machine.cpu.canonical_memory.as_ref().unwrap();
        const LEAF: u64 = 0x13020;
        const DATA: u64 = 0x14000;
        const GP: u64 = 1 << 50;
        let mut descriptor = [0; 8];
        unsafe { ram.read_physical(LEAF, &mut descriptor) }.unwrap();
        let descriptor = u64::from_le_bytes(descriptor) | GP;
        unsafe { ram.publish_physical(LEAF, &descriptor.to_le_bytes()) }.unwrap();
        let word = 0xd503_245fu32;
        unsafe { ram.publish_physical(DATA, &word.to_le_bytes()) }.unwrap();
        // S1TreatAsNormalNC also converts a Device descriptor's instruction
        // fetch to effective Normal NC. Data Device admission is unchanged.
        for attribute in [0, 0x44, 0xbb, 0xff, 0x4f, 0xf4, 0xa0, 0x40] {
            controls.translation.mair = attribute;
            for xs in [false, true] {
                controls.translation.xs = xs;
                assert_eq!(instruction(memory, &controls, 0x4000), Ok((word, true)));
                let mut bytes = [0; 4];
                assert_eq!(memory.fetch(&controls, 0x4000, &mut bytes), Ok(()));
                assert_eq!(u32::from_le_bytes(bytes), word);
            }
        }
        controls.translation.tagged = true;
        const SCTLR_I: u64 = 1 << 12;
        controls.translation.sctlr |= SCTLR_I;
        controls.translation.mair = u64::from(mmu::attributes::TAGGED);
        assert!(instruction(memory, &controls, 0x4000).is_err());
        let mut bytes = [0xa5; 4];
        assert_eq!(
            memory.fetch(&controls, 0x4000, &mut bytes),
            Err(MemoryStatus::Unsupported)
        );
        assert_eq!(bytes, [0xa5; 4]);
        // I clear likewise makes the actual fetch Normal NC, independently
        // of the original MAIR byte. Use the walk's output, not raw metadata.
        controls.translation.sctlr &= !SCTLR_I;
        assert_eq!(instruction(memory, &controls, 0x4000), Ok((word, true)));
        assert_eq!(memory.fetch(&controls, 0x4000, &mut bytes), Ok(()));
        assert_eq!(u32::from_le_bytes(bytes), word);
    }

    #[test]
    fn source_guard_and_register_determine_next_btype_independently_of_target() {
        for register in 0..32 {
            let br = 0xd61f_0000 | register << 5;
            assert_eq!(branch_type(br, false), 1);
            assert_eq!(
                branch_type(br, true),
                if matches!(register, 16 | 17) { 1 } else { 3 }
            );
            assert_eq!(branch_type(0xd63f_0000 | register << 5, true), 2);
            assert_eq!(branch_type(0xd65f_0000 | register << 5, true), 0);
        }
        assert_eq!(branch_type(0x1400_0000, true), 0);
    }
    #[test]
    fn bti_and_pac_entry_compatibility_preserve_exception_priority() {
        for btype in 1..=3 {
            assert_eq!(target_accepts(0xd503_245f, btype, 0, 1), btype != 3);
            assert_eq!(target_accepts(0xd503_249f, btype, 0, 1), btype != 2);
            assert!(target_accepts(0xd503_24df, btype, 0, 1));
            assert!(!target_accepts(0xd503_201f, btype, 0, 1));
            assert!(target_accepts(0xd503_233f, btype, 0, 1));
            assert_eq!(target_accepts(0xd503_233f, btype, 1 << 36, 1), btype != 3);
        }
    }
}
