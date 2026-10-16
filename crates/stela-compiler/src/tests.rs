use super::*;
use alloc::vec;
use alloc::vec::Vec;
#[test]
fn polynomial64_lowering_requires_independent_pclmul_and_selects_original_halves() {
    use x86_64::isa::SimdOpcode;
    let opcode = SimdOpcode::CarrylessMultiplyQword;
    assert_eq!(opcode.requires(), TargetCpu::Pclmulqdq);
    assert!(!TargetCpu::Sse42.supports(opcode.requires()));
    assert!(
        std::panic::catch_unwind(|| {
            opcode.register(&mut Vec::new(), 0, 1, TargetCpu::Sse42);
        })
        .is_err()
    );
    for (word, immediate) in [(0x0ee2e020u32, 0x00), (0x4ee2e020, 0x11)] {
        let source: Vec<_> = [word, 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let baseline = compile(&source, GuestAddress(0x1000)).unwrap();
        let sse42 = compile_for_target(&source, GuestAddress(0x1000), TargetCpu::Sse42).unwrap();
        assert_eq!(baseline.x86_64_code, sse42.x86_64_code);
        let pclmul =
            compile_for_target(&source, GuestAddress(0x1000), TargetCpu::Pclmulqdq).unwrap();
        let combined = compile_for_target(
            &source,
            GuestAddress(0x1000),
            TargetCpu::Sse42.with_pclmulqdq(),
        )
        .unwrap();
        assert_eq!(pclmul.x86_64_code, combined.x86_64_code);
        assert!(
            pclmul
                .x86_64_code
                .windows(6)
                .any(|bytes| bytes == [0x66, 0x0f, 0x3a, 0x44, 0xc1, immediate])
        );
        assert!(pclmul.x86_64_code.len() < baseline.x86_64_code.len());
        assert_eq!(pclmul.source_map.len(), baseline.source_map.len());
    }
    // Byte polynomial forms retain the lane-isolated SSE2 recipe.
    for word in [0x2e229c20u32, 0x0e22e020, 0x4e22e020] {
        let source: Vec<_> = [word, 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(
            compile(&source, GuestAddress(0x1000)).unwrap().x86_64_code,
            compile_for_target(&source, GuestAddress(0x1000), TargetCpu::Pclmulqdq)
                .unwrap()
                .x86_64_code,
        );
    }
}
#[test]
fn ordered_load_host_requirements_gate_leaf_and_block_before_output() {
    for word in [0xc8dffc20_u32, 0xf8bfc020] {
        let source: Vec<u8> = [word, 0xd65f03c0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert!(
            compile(&source, GuestAddress(0))
                .unwrap_err()
                .0
                .contains("HostCapabilityRequired")
        );
        assert!(compile_for_target(&source, GuestAddress(0), TargetCpu::AtomicLoad16).is_ok());
        let blocked = block::compile(&source, GuestAddress(0)).unwrap_err();
        assert!(blocked.0.contains("HostCapabilityRequired"));
        assert!(
            block::compile_for_target(
                &source,
                GuestAddress(0),
                block::BlockProfile::default(),
                TargetCpu::AtomicLoad16
            )
            .is_ok()
        );
    }
    for word in [0xc8dfffe0_u32, 0xf8bfc3e0, 0x08dffc20, 0xc89ffc20] {
        let source: Vec<u8> = [word, 0xd65f03c0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert!(compile(&source, GuestAddress(0)).is_ok());
    }
}

#[test]
fn pair_compare_exchange_requires_only_cx16_for_doubleword_pairs() {
    const CASP_WORD: u32 = 0x08207c82; // casp w0,w1,w2,w3,[x4]
    const CASP_DOUBLEWORD: u32 = 0x48207c82;
    const RET: u32 = 0xd65f03c0;
    for order in [0, 1 << 22, 1 << 15, (1 << 22) | (1 << 15)] {
        for (word, requires_cx16) in [(CASP_WORD, false), (CASP_DOUBLEWORD, true)] {
            let source: Vec<u8> = [word | order, RET]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            for target in [
                TargetCpu::Baseline,
                TargetCpu::AtomicLoad16,
                TargetCpu::Cx16,
            ] {
                let permitted = !requires_cx16 || target.supports(TargetCpu::Cx16);
                let leaf = compile_for_target(&source, GuestAddress(0), target);
                let block = block::compile_for_target(
                    &source,
                    GuestAddress(0),
                    block::BlockProfile::default(),
                    target,
                );
                assert_eq!(leaf.is_ok(), permitted);
                assert_eq!(block.is_ok(), permitted);
                if !permitted {
                    assert!(leaf.unwrap_err().0.contains("HostCapabilityRequired"));
                    assert!(block.unwrap_err().0.contains("HostCapabilityRequired"));
                } else {
                    const LOCK_CMPXCHG8B_R8: &[u8] = &[0xf0, 0x41, 0x0f, 0xc7, 0x08];
                    let uses_cx8 = leaf
                        .unwrap()
                        .x86_64_code
                        .windows(LOCK_CMPXCHG8B_R8.len())
                        .any(|body| body == LOCK_CMPXCHG8B_R8);
                    assert_eq!(uses_cx8, !requires_cx16 && target.supports(TargetCpu::Cx8));
                }
            }
        }
    }
}

#[test]
fn rejects_unknown_instructions_bad_boundaries_and_address_overflow() {
    for words in [
        vec![],
        vec![0xd503201fu32],
        vec![0x14000002, 0xd65f03c0], // branch falls outside the region
        vec![0xf8800800, 0xd65f03c0], // reserved unprivileged prefetch neighbor
        vec![0xd65f0000],
    ] {
        let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert!(compile(&bytes, GuestAddress(0)).is_err());
    }
    assert!(compile(&[0, 0, 0], GuestAddress(0)).is_err());
    assert!(compile(&0xd65f03c0u32.to_le_bytes(), GuestAddress(1)).is_err());
    let code: Vec<_> = [0xd503201fu32, 0xd65f03c0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    assert!(compile(&code, GuestAddress(u64::MAX - 3)).is_err());
}
