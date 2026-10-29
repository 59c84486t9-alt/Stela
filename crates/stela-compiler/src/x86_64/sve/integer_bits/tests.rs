//! Predicated bit-operation semantics, aliases and capability fallbacks.
mod costs;
use super::*;
use crate::x86_64::asm::vector_extensions::execution::Native;
use crate::{
    GuestState,
    context::{ExecutionContext, ScalableStateView},
};
use alloc::{vec, vec::Vec};

#[test]
fn rbit_byte_merge_preserves_every_predicate_mask_and_register_alias() {
    let target = TargetCpu::detect();
    if !target.supports(TargetCpu::Gfni.with_avx2().with_avx512f().with_avx512vl()) {
        return;
    }
    let length = VectorLength::from_bytes(16).unwrap();
    let mut cases = 0_usize;
    for destination in [1_u8, 2] {
        let operand = Operand {
            kind: Kind::ReverseBits,
            destination,
            source: 1,
            element_size: ElementSize::Byte,
            predication: Predication::Merging(0),
        };
        let binaries: Vec<_> = [Merge::Baseline, Merge::Blend, Merge::Ternary]
            .into_iter()
            .map(|merge| {
                let mut code = crate::scalable_context::context_wrapper();
                emit_with_merge(&mut code, operand, length, target, merge);
                code.asm().ret();
                Native::new(&code)
            })
            .collect();
        let mut predicates = [0_u8; 32];
        let mut scalable = ScalableStateView {
            svl_bytes: 16,
            reserved: [0; 6],
            svcr: 0,
            tpidr2_el0: 0,
            fpmr: 0,
            z_upper: core::ptr::null_mut(),
            predicates: predicates.as_mut_ptr(),
            ffr: core::ptr::null_mut(),
            za: core::ptr::null_mut(),
            zt0: core::ptr::null_mut(),
        };
        let mut context = ExecutionContext {
            scalable: &mut scalable,
            ..ExecutionContext::default()
        };
        for mask in 0_u32..=u16::MAX as u32 {
            predicates[..2].copy_from_slice(&(mask as u16).to_le_bytes());
            let before_predicates = predicates;
            let input: [u8; 16] = core::array::from_fn(|i| (i * 37 + mask as usize) as u8);
            let old: [u8; 16] = if destination == 1 {
                input
            } else {
                core::array::from_fn(|i| !input[15 - i])
            };
            let words = |bytes: [u8; 16]| {
                [
                    u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                    u64::from_le_bytes(bytes[8..].try_into().unwrap()),
                ]
            };
            let mut initial = GuestState {
                x: core::array::from_fn(|i| 0x123456789abcdef0_u64.wrapping_mul(i as u64 + 1)),
                nzcv: 0xa0000000,
                fpsr: 0x0800001f,
                fpcr: 0x1234,
                ..GuestState::default()
            };
            initial.v[1] = words(input);
            initial.v[destination as usize] = words(old);
            let mut expected = initial.clone();
            let bytes = core::array::from_fn(|i| {
                if mask & (1 << i) != 0 {
                    input[i].reverse_bits()
                } else {
                    old[i]
                }
            });
            expected.v[destination as usize] = words(bytes);
            for native in &binaries {
                let mut state = initial.clone();
                native.run(&mut state, &mut context);
                assert_eq!(
                    state, expected,
                    "mask={mask:#06x} destination={destination}"
                );
                assert_eq!(predicates, before_predicates);
                cases += 1;
            }
        }
    }
    std::println!(
        "RBIT_MERGE_NATIVE_CASES={cases} SOURCE_SHA256={}",
        crate::SOURCE_SHA256
    );
}

#[test]
fn merging_candidates_do_not_change_other_families_widths_or_dit() {
    let target = TargetCpu::Gfni.with_avx2().with_avx512f().with_avx512vl();
    let length = VectorLength::from_bytes(64).unwrap();
    for kind in [
        Kind::ReverseBits,
        Kind::PopulationCount,
        Kind::LeadingZeros,
        Kind::LeadingSignBits,
    ] {
        for element_size in [
            ElementSize::Byte,
            ElementSize::Halfword,
            ElementSize::Word,
            ElementSize::Doubleword,
        ] {
            if kind == Kind::ReverseBits && element_size == ElementSize::Byte {
                continue;
            }
            let operand = Operand {
                kind,
                destination: 2,
                source: 1,
                element_size,
                predication: Predication::Merging(0),
            };
            assert_eq!(selected_merge(operand, target), Merge::Baseline);
            let mut code = Code::new();
            emit(&mut code, operand, length, target);
            let mut baseline = Code::new();
            emit_with_merge(&mut baseline, operand, length, target, Merge::Baseline);
            assert_eq!(code, baseline);
        }
    }
    let operand = Operand {
        kind: Kind::ReverseBits,
        destination: 2,
        source: 1,
        element_size: ElementSize::Byte,
        predication: Predication::Merging(0),
    };
    assert_eq!(
        selected_merge(operand, target.with_data_independent_timing()),
        Merge::Baseline
    );
    assert_eq!(selected_merge(operand, TargetCpu::Gfni), Merge::Baseline);
    assert_eq!(
        selected_merge(operand, TargetCpu::Gfni.with_avx2()),
        Merge::Baseline
    );
    assert_eq!(selected_merge(operand, target), Merge::Ternary);
}

#[test]
fn merge_fallback_bytes() {
    let operand = Operand {
        kind: Kind::ReverseBits,
        destination: 2,
        source: 1,
        element_size: ElementSize::Byte,
        predication: Predication::Merging(0),
    };
    let length = VectorLength::from_bytes(16).unwrap();
    let mut baseline = Code::new();
    emit(&mut baseline, operand, length, TargetCpu::Baseline);
    for target in [
        TargetCpu::Avx512f,
        TargetCpu::Avx512vl,
        TargetCpu::Avx512f.with_avx512vl(),
        TargetCpu::Avx512f
            .with_avx512vl()
            .with_data_independent_timing(),
    ] {
        let mut code = Code::new();
        emit(&mut code, operand, length, target);
        assert_eq!(code, baseline);
    }
}

#[test]
fn packed_bit_extensions_preserve_predication_and_aliases() {
    let host = TargetCpu::detect();
    for target in [
        TargetCpu::Baseline,
        TargetCpu::Gfni,
        TargetCpu::Gfni.with_avx2(),
        TargetCpu::Gfni.with_avx512f().with_avx512vl(),
        TargetCpu::Avx512f.with_avx512vl(),
        TargetCpu::Avx512f.with_avx512vl().with_avx512bitalg(),
        TargetCpu::Avx512f.with_avx512vl().with_avx512vpopcntdq(),
        TargetCpu::Avx512f.with_avx512vl().with_avx512cd(),
    ] {
        if !host.supports(target) {
            continue;
        }
        for bytes in [16usize, 64, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            let upper_bytes = bytes - 16;
            for element_size in [
                ElementSize::Byte,
                ElementSize::Halfword,
                ElementSize::Word,
                ElementSize::Doubleword,
            ] {
                for kind in [
                    Kind::ReverseBits,
                    Kind::PopulationCount,
                    Kind::LeadingZeros,
                    Kind::LeadingSignBits,
                ] {
                    for destination in [1u8, 2] {
                        let operand = Operand {
                            kind,
                            destination,
                            source: 1,
                            element_size,
                            predication: Predication::Merging(0),
                        };
                        let mut code = crate::scalable_context::context_wrapper();
                        emit(&mut code, operand, length, target);
                        code.asm().ret();
                        let native = Native::new(&code);
                        for mask in [0u16, u16::MAX, 0xa5c3] {
                            let input: Vec<u8> = (0..bytes)
                                .map(|i| ((i * 37 + 91) ^ (i >> 2)) as u8)
                                .collect();
                            let old = if destination == 1 {
                                input.clone()
                            } else {
                                vec![0xa5; bytes]
                            };
                            let mut expected = old.clone();
                            let lane = element_size.bytes();
                            for at in (0..bytes).step_by(lane) {
                                if mask & (1 << (at % 16)) == 0 {
                                    continue;
                                }
                                let mut x = [0u8; 8];
                                x[..lane].copy_from_slice(&input[at..at + lane]);
                                let x = u64::from_le_bytes(x);
                                let bits = element_size.bits();
                                let result = match kind {
                                    Kind::ReverseBits => x.reverse_bits() >> (64 - bits),
                                    Kind::PopulationCount => u64::from(x.count_ones()),
                                    Kind::LeadingZeros => {
                                        u64::from(x.leading_zeros()) - (64 - bits) as u64
                                    }
                                    Kind::LeadingSignBits => {
                                        let shifted = (x << (64 - bits)) as i64;
                                        let unsigned = if shifted < 0 {
                                            !shifted as u64
                                        } else {
                                            shifted as u64
                                        };
                                        u64::from(unsigned.leading_zeros().min(bits as u32)) - 1
                                    }
                                    _ => unreachable!(),
                                };
                                expected[at..at + lane]
                                    .copy_from_slice(&result.to_le_bytes()[..lane]);
                            }
                            let words = |x: &[u8]| {
                                [
                                    u64::from_le_bytes(x[..8].try_into().unwrap()),
                                    u64::from_le_bytes(x[8..16].try_into().unwrap()),
                                ]
                            };
                            let mut state = GuestState {
                                fpsr: 0x0800_001f,
                                nzcv: 0xa000_0000,
                                ..GuestState::default()
                            };
                            state.v[1] = words(&input);
                            state.v[usize::from(destination)] = words(&old);
                            let mut upper = vec![0u8; 32 * upper_bytes];
                            upper[upper_bytes..2 * upper_bytes].copy_from_slice(&input[16..]);
                            upper[usize::from(destination) * upper_bytes
                                ..(usize::from(destination) + 1) * upper_bytes]
                                .copy_from_slice(&old[16..]);
                            let mut predicates = vec![0u8; 16 * length.predicate_bytes()];
                            for b in predicates[..length.predicate_bytes()]
                                .as_chunks_mut::<2>()
                                .0
                            {
                                b.copy_from_slice(&mask.to_le_bytes());
                            }
                            let original_predicates = predicates.clone();
                            let mut scalable = ScalableStateView {
                                svl_bytes: bytes as u16,
                                reserved: [0; 6],
                                svcr: 0,
                                tpidr2_el0: 0,
                                fpmr: 0,
                                z_upper: upper.as_mut_ptr(),
                                predicates: predicates.as_mut_ptr(),
                                ffr: core::ptr::null_mut(),
                                za: core::ptr::null_mut(),
                                zt0: core::ptr::null_mut(),
                            };
                            let mut context = ExecutionContext {
                                scalable: &mut scalable,
                                ..ExecutionContext::default()
                            };
                            native.run(&mut state, &mut context);
                            let mut result = state.v[usize::from(destination)]
                                .iter()
                                .flat_map(|w| w.to_le_bytes())
                                .collect::<Vec<_>>();
                            result.extend_from_slice(
                                &upper[usize::from(destination) * upper_bytes
                                    ..(usize::from(destination) + 1) * upper_bytes],
                            );
                            assert_eq!(
                                result, expected,
                                "{target:?} {bytes} {element_size:?} {kind:?} {destination} {mask:#x}"
                            );
                            assert_eq!(state.fpsr, 0x0800_001f);
                            assert_eq!(state.nzcv, 0xa000_0000);
                            assert_eq!(predicates, original_predicates);
                        }
                    }
                }
            }
        }
    }
}
