//! Manual costs of the compiled SVE bit-operation predicate merge.
use super::super::{Merge, with_merge};
use crate::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::scalable::{ScalableMode, VectorLength},
    context::{ExecutionContext, ScalableStateView},
    scalable_context::ScalableProfile,
    x86_64::asm::vector_extensions::execution::Native,
};
use alloc::{vec, vec::Vec};
use std::{hint::black_box, time::Instant};

#[test]
#[ignore = "manual: opt-in"]
fn sve_merge_costs() {
    const OPERATIONS: usize = 8;
    let target = TargetCpu::detect();
    assert!(
        target.supports(TargetCpu::Gfni.with_avx2().with_avx512f().with_avx512vl()),
        "requires GFNI, AVX2 and AVX-512 F/VL"
    );
    let output = std::env::temp_dir().join(std::format!(
        "stela-sve-merge-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir(&output).unwrap();
    std::println!(
        "MERGE_OUTPUT={} SOURCE_SHA256={}",
        output.display(),
        crate::SOURCE_SHA256
    );
    for bytes in [16, 32, 64, 128, 256] {
        let length = VectorLength::from_bytes(bytes).unwrap();
        let profile = ScalableProfile::new(length, ScalableMode::new(true, false));
        for dependent in [false, true] {
            let mut words: Vec<u32> = (0..OPERATIONS)
                .map(|index| {
                    let register = if dependent { 1 } else { index as u32 + 1 };
                    0x0527_8000 | (register << 5) | register // RBIT Zdn.B,P0/M,Zdn.B
                })
                .collect();
            words.push(0xd65f_03c0); // RET X30
            let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let cases: Vec<_> = [
                ("gfni", Merge::Baseline),
                ("gfni_blend", Merge::Blend),
                ("gfni_ternary", Merge::Ternary),
            ]
            .into_iter()
            .map(|(name, merge)| {
                let block = with_merge(merge, || {
                    crate::testing::context_leaf(&source, GuestAddress(0x1000), profile, target)
                        .unwrap()
                });
                let stem = std::format!(
                    "rbit-vl{bytes}-{}-{name}",
                    if dependent {
                        "dependent"
                    } else {
                        "independent"
                    }
                );
                std::fs::write(output.join(std::format!("{stem}.bin")), &block.x86_64_code)
                    .unwrap();
                std::fs::write(
                    output.join(std::format!("{stem}.source-map.txt")),
                    std::format!("{:?}", block.source_map),
                )
                .unwrap();
                let native = Native::new(&block.x86_64_code);
                (name, block, native)
            })
            .collect();
            let automatic =
                crate::testing::context_leaf(&source, GuestAddress(0x1000), profile, target)
                    .unwrap();
            assert_eq!(
                automatic.x86_64_code, cases[2].1.x86_64_code,
                "automatic policy uses the measured ternary recipe"
            );
            assert_eq!(automatic.source_map, cases[2].1.source_map);
            std::fs::write(
                output.join(std::format!(
                    "rbit-vl{bytes}-{}-automatic.bin",
                    if dependent {
                        "dependent"
                    } else {
                        "independent"
                    }
                )),
                &automatic.x86_64_code,
            )
            .unwrap();
            if std::env::var_os("STELA_MERGE_VERIFY_ONLY").is_some() {
                continue;
            }
            let mut state = GuestState::default();
            for (index, vector) in state.v.iter_mut().enumerate() {
                *vector = [
                    (index as u64 + 1).wrapping_mul(0x1234_5678_9abc_def1),
                    !(index as u64),
                ];
            }
            let upper_bytes = bytes - 16;
            let mut upper: Vec<u8> = (0..32 * upper_bytes)
                .map(|i| (i.wrapping_mul(37) ^ 91) as u8)
                .collect();
            let mut predicates = vec![0xa5; 16 * length.predicate_bytes()];
            let mut scalable = ScalableStateView {
                svl_bytes: bytes as u16,
                reserved: [0; 6],
                svcr: 1,
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
            for (_, _, native) in &cases {
                for _ in 0..1000 {
                    native.run(&mut state, &mut context);
                }
            }
            let iterations = 1_000_000 / length.chunks();
            let mut samples = [[0.0f64; 3]; 15];
            for (sample, values) in samples.iter_mut().enumerate() {
                for order in 0..3 {
                    let selected = (sample + order) % 3;
                    let start = Instant::now();
                    for _ in 0..iterations {
                        cases[selected].2.run(&mut state, &mut context);
                    }
                    values[selected] =
                        start.elapsed().as_nanos() as f64 / (iterations * OPERATIONS) as f64;
                    black_box(&state);
                }
            }
            for (index, (name, block, _)) in cases.iter().enumerate() {
                let mut samples = samples.map(|values| values[index]);
                samples.sort_by(f64::total_cmp);
                std::println!(
                    "MERGE bytes={bytes} dependent={dependent} target={name} code_bytes={} ns_per_guest_op={:.4} samples={samples:?}",
                    block.x86_64_code.len(),
                    samples[7]
                );
            }
        }
    }
}
