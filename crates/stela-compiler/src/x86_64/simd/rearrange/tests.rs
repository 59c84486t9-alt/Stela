use super::*;
use crate::{
    GuestState, Options,
    block::{BlockProfile, CompilationPlan, Features},
    x86_64::{native, pinned},
};

const PC: GuestAddress = GuestAddress(0x1af89b3ac);
const DESKTOP: [u32; 2] = [0x6e01_6000, 0x6e02_6001];
const SUFFIX: u32 = 0x9100_4231; // ADD X17,X17,#16

fn compile(words: &[u32], pc: GuestAddress, target: TargetCpu, system: bool) -> crate::NativeBlock {
    let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let profile = if system {
        BlockProfile::new(Features::SYSTEM_MODE)
    } else {
        BlockProfile::ORDINARY
    };
    CompilationPlan::new(&source, pc, &Options::new(profile, target))
        .unwrap()
        .compile()
        .unwrap()
        .native
}

fn reference(state: &mut GuestState, bytes: usize, offset: usize, registers: [usize; 3]) {
    let [d, n, m] = registers;
    let a = state.v[n].map(u64::to_le_bytes).concat();
    let b = state.v[m].map(u64::to_le_bytes).concat();
    let joined = [&a[..bytes], &b[..bytes]].concat();
    let mut result = [0; 16];
    result[..bytes].copy_from_slice(&joined[offset..offset + bytes]);
    state.v[d] = core::array::from_fn(|lane| {
        u64::from_le_bytes(result[lane * 8..lane * 8 + 8].try_into().unwrap())
    });
}

fn input() -> GuestState {
    let mut state = GuestState::default();
    for (register, value) in state.v.iter_mut().enumerate() {
        *value = core::array::from_fn(|half| {
            let base = (register * 19 + half * 8) as u8;
            u64::from_le_bytes(core::array::from_fn(|byte| base.wrapping_add(byte as u8)))
        });
    }
    state
}

#[test]
fn byte_extract_preserves_all_widths_offsets_and_aliases() {
    for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
        if !TargetCpu::detect().supports(target) {
            continue;
        }
        for bytes in [8, 16] {
            for offset in 0..bytes {
                for [d, n, m] in [[0, 1, 2], [1, 1, 2], [2, 1, 2], [0, 1, 1], [31, 31, 31]] {
                    let word = 0x2e00_0000
                        | ((bytes == 16) as u32) << 30
                        | (m as u32) << 16
                        | (offset as u32) << 11
                        | (n as u32) << 5
                        | d as u32;
                    let block = compile(&[word], PC, target, false);
                    let mut actual = input();
                    let mut expected = actual.clone();
                    reference(&mut expected, bytes, offset, [d, n, m]);
                    assert_eq!(native::run(&block.x86_64_code, &mut actual), PC.0 + 4);
                    assert_eq!(actual, expected, "{target:?} {word:08x}");
                }
            }
        }
    }
}

#[test]
fn desktop_extracts_forward_the_committed_left_source() {
    let second_pc = GuestAddress(PC.0 + 4);
    let suffix_pc = GuestAddress(PC.0 + 8);
    for system in [false, true] {
        for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
            let block = compile(&[DESKTOP[0], DESKTOP[1], SUFFIX], PC, target, system);
            let alone = compile(&[DESKTOP[1], SUFFIX], second_pc, target, system);
            let [(first, from), (second, middle), (suffix, end)] = block.source_map.as_slice()
            else {
                panic!("three source rows");
            };
            assert_eq!([*first, *second, *suffix], [PC, second_pc, suffix_pc]);
            assert!(*from < *middle && *middle < *end);
            assert!(end - middle < alone.source_map[1].1 - alone.source_map[0].1);
            let prefix = &block.x86_64_code[*from..*end];
            let alignments = prefix
                .windows(4)
                .filter(|bytes| *bytes == Host::AlignBytes.encoding())
                .count();
            assert_eq!(
                alignments,
                if target.supports(TargetCpu::Ssse3) {
                    2
                } else {
                    0
                }
            );
            assert!(
                !prefix
                    .windows(4)
                    .any(|bytes| bytes == Host::ByteShuffle.encoding())
            );

            if !TargetCpu::detect().supports(target) {
                continue;
            }
            let code = if system {
                pinned::entered(&block.x86_64_code)
            } else {
                block.x86_64_code
            };
            let mut actual = input();
            let mut expected = actual.clone();
            reference(&mut expected, 16, 12, [0, 0, 1]);
            reference(&mut expected, 16, 12, [1, 0, 2]);
            expected.x[17] += 16;
            assert_eq!(native::run(&code, &mut actual), PC.0 + 12);
            assert_eq!(actual, expected);
        }
    }
}
