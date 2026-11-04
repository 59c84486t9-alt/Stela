use crate::{
    GuestAddress, Options, TargetCpu,
    block::{BlockProfile, CompilationPlan, CompiledBlock, Features, RecoverySiteKind},
};
use alloc::vec::Vec;

const PC: GuestAddress = GuestAddress(0xb6210);
const OPENSSL: [u32; 4] = [0x4e28_4a00, 0x4e28_6800, 0x4e28_4a01, 0x4e28_6821];
const VAESENC: [u8; 5] = [0xc4, 0xe2, 0x7d, 0xdc, 0xc1];
const VAESDEC: [u8; 5] = [0xc4, 0xe2, 0x7d, 0xde, 0xc1];

fn compile(
    words: &[u32],
    pc: GuestAddress,
    profile: BlockProfile,
    target: TargetCpu,
) -> CompiledBlock {
    let source: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    CompilationPlan::new(&source, pc, &Options::new(profile, target))
        .unwrap()
        .compile()
        .unwrap()
}

fn has_packed_round(block: &CompiledBlock) -> bool {
    block
        .native
        .x86_64_code
        .windows(VAESENC.len())
        .any(|bytes| bytes == VAESENC || bytes == VAESDEC)
}

#[test]
fn two_lane_vaes_keeps_source_rows_and_the_next_fault_boundary() {
    let system = BlockProfile::new(Features::SYSTEM_MODE);
    let end = GuestAddress(PC.0 + 16);
    let rows = [0, 17, 21, 30];
    let expected =
        core::array::from_fn::<_, 4, _>(|row| (GuestAddress(PC.0 + row as u64 * 4), rows[row]));
    for profile in [BlockProfile::ORDINARY, system] {
        // The target has VAES and its underlying OS AVX state without AVX2.
        let wide = compile(&OPENSSL, PC, profile, TargetCpu::Vaes);
        assert_eq!(wide.native.source_map, expected);
        assert!(wide.fault_recovery.is_empty());
        let bytes = &wide.native.x86_64_code;
        assert_eq!(&bytes[..8], &[0xc5, 0xfe, 0x6f, 0x87, 8, 1, 0, 0]);
        assert_eq!(&bytes[25..30], &VAESENC);
        assert_eq!(&bytes[38..41], &[0xc5, 0xf8, 0x77]);
        let legacy = compile(&OPENSSL, PC, profile, TargetCpu::Aes);
        assert_eq!(legacy.native.x86_64_code.len() - bytes.len(), 33);
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Ssse3,
            TargetCpu::Sse41,
            TargetCpu::Aes,
            TargetCpu::Vaes.with_aes().with_data_independent_timing(),
        ] {
            assert!(!has_packed_round(&compile(&OPENSSL, PC, profile, target)));
        }
    }
    let source = [OPENSSL[0], OPENSSL[1], OPENSSL[2], OPENSSL[3], 0xf940_0289];
    let with_access = compile(&source, PC, system, TargetCpu::Vaes);
    assert_eq!(with_access.native.source_map[4], (end, 41));
    let access = with_access
        .fault_recovery
        .iter()
        .find(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
        .unwrap();
    assert!(access.start >= 41);
    assert_eq!(access.retirement.instruction_pc(), end);
    assert_eq!(access.retirement.retired_before(), 4);
    assert!(access.bindings.is_empty());
}

#[test]
fn two_lane_vaes_declines_aliases_interior_entries_and_clipping() {
    let profile = BlockProfile::ORDINARY;
    let target = TargetCpu::Aes.with_vaes();
    let [a, b, c, d] = OPENSSL;
    for words in [
        [a, b, c ^ (1 << 5), d],              // Different keys.
        [a ^ (16 << 5), b, c ^ (16 << 5), d], // Key is V0.
        [a ^ (17 << 5), b, c ^ (17 << 5), d], // Key is V1.
        [a, b, a, b],                         // Both pairs write V0.
        [a, b, c ^ 3, d ^ (3 << 5) ^ 3],      // The second pair writes V2.
        [a, b, c ^ 0x1000, d ^ 0x1000],       // Encrypt then decrypt.
    ] {
        assert!(!has_packed_round(&compile(&words, PC, profile, target)));
    }
    for cut in 1..4 {
        let entry = GuestAddress(PC.0 + cut as u64 * 4);
        let independent = compile(&OPENSSL[cut..], entry, profile, target);
        assert_eq!(independent.native.source_map[0], (entry, 0));
        assert!(!has_packed_round(&independent));
        assert!(!has_packed_round(&compile(
            &OPENSSL[..cut],
            PC,
            profile,
            target
        )));
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn two_lane_vaes_matches_scalar_rounds_in_frame_and_pinned_code() {
    use crate::{
        GuestState,
        x86_64::{native::run, pinned},
    };

    let target = TargetCpu::Aes.with_vaes();
    if !TargetCpu::detect().supports(target) {
        return;
    }
    let system = BlockProfile::new(Features::SYSTEM_MODE);
    for profile in [BlockProfile::ORDINARY, system] {
        for inverse in [false, true] {
            let words = OPENSSL.map(|word| word ^ if inverse { 0x1000 } else { 0 });
            let wide = compile(&words, PC, profile, target);
            let scalar = compile(&words, PC, profile, TargetCpu::Baseline);
            assert!(has_packed_round(&wide));
            let entry = |block: CompiledBlock| {
                if profile == system {
                    pinned::entered(&block.native.x86_64_code)
                } else {
                    block.native.x86_64_code
                }
            };
            let (wide, scalar) = (entry(wide), entry(scalar));
            for input in 0..8 {
                let mut expected = GuestState {
                    x: [0xdead_beef_0123_4567; 31],
                    v: core::array::from_fn(|lane| {
                        let value = (0x0123_4567_89ab_cdefu64 ^ input).rotate_right(lane as u32);
                        [value, !value]
                    }),
                    nzcv: 0xa000_0000,
                    ..Default::default()
                };
                let mut actual = expected.clone();
                assert_eq!(run(&scalar, &mut expected), PC.0 + 16);
                assert_eq!(run(&wide, &mut actual), PC.0 + 16);
                assert_eq!(actual, expected);
            }
        }
    }
}
