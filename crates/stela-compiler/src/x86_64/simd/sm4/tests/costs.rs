//! Manual hardware comparison of complete compiled SM4 leaves.
use super::*;
use crate::GuestAddress;
use alloc::{format, vec::Vec};
use std::{fs, hint::black_box, time::Instant};
#[test]
#[ignore = "manual: opt-in"]
fn sm4_costs() {
    let target = TargetCpu::detect();
    assert!(target.supports(TargetCpu::Gfni));
    let output = std::env::temp_dir().join(format!("stela-sm4-costs-{}", std::process::id()));
    fs::create_dir_all(&output).unwrap();
    std::println!(
        "SM4_COST_OUTPUT={} SOURCE_SHA256={}",
        output.display(),
        crate::SOURCE_SHA256
    );
    const OPERATIONS: usize = 8;
    for kind in [Kind::Encrypt, Kind::ExpandKey] {
        for dependent in [false, true] {
            let mut words: Vec<_> = (0..OPERATIONS)
                .map(|i| {
                    let d = if dependent { 1 } else { i as u32 + 1 };
                    match kind {
                        Kind::Encrypt => 0xcec08400 | d,
                        Kind::ExpandKey => 0xce60c800 | d | (d << 5),
                    }
                })
                .collect();
            words.push(0xd65f03c0);
            let source: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
            let cases: Vec<_> = [false, true]
                .into_iter()
                .map(|gfni| {
                    let block = with_sbox(gfni, || {
                        crate::testing::leaf_for(&source, GuestAddress(0x1000), target).unwrap()
                    });
                    let stem = format!("{kind:?}-dependent{dependent}-gfni{gfni}");
                    fs::write(output.join(format!("{stem}.bin")), &block.x86_64_code).unwrap();
                    fs::write(
                        output.join(format!("{stem}.source-map.txt")),
                        format!("{:?}", block.source_map),
                    )
                    .unwrap();
                    let native = Native::new(&block.x86_64_code);
                    (block, native)
                })
                .collect();
            let mut state = GuestState::default();
            for (i, v) in state.v.iter_mut().enumerate() {
                *v = [0x0123456789abcdef_u64.wrapping_mul(i as u64 + 1), !i as u64];
            }
            let mut context = ExecutionContext::default();
            let mut expected = state.clone();
            let mut actual = state.clone();
            cases[0].1.run(&mut expected, &mut context);
            cases[1].1.run(&mut actual, &mut context);
            assert_eq!(actual, expected);
            if std::env::var_os("STELA_SM4_VERIFY_ONLY").is_some() {
                continue;
            }
            for (_, native) in &cases {
                for _ in 0..128 {
                    native.run(&mut state, &mut context);
                }
            }
            let iterations = 10000;
            let mut samples = [[0.0_f64; 2]; 15];
            for (sample, values) in samples.iter_mut().enumerate() {
                for order in 0..2 {
                    let selected = (sample + order) % 2;
                    let start = Instant::now();
                    for _ in 0..iterations {
                        cases[selected].1.run(&mut state, &mut context);
                    }
                    values[selected] =
                        start.elapsed().as_nanos() as f64 / (iterations * OPERATIONS) as f64;
                    black_box(&state);
                }
            }
            for (index, (block, _)) in cases.iter().enumerate() {
                let mut values = samples.map(|x| x[index]);
                values.sort_by(f64::total_cmp);
                std::println!(
                    "SM4_COST kind={kind:?} dependent={dependent} gfni={} bytes={} median_ns_per_op={} samples={values:?}",
                    index == 1,
                    block.x86_64_code.len(),
                    values[7]
                );
            }
        }
    }
}
