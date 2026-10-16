//! Context-backed blocks with SME completion.
#![cfg(all(target_os = "macos", target_arch = "x86_64"))]
use super::*;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::features::NumericalFeatures,
        scalable::{
            PREDICATE_REGISTER_COUNT, ScalableMode, VECTOR_REGISTER_COUNT, VectorLength,
            features::{ScalableFeature as Feature, ScalableFeatures},
            profile::ScalableControls,
        },
    },
    extended::ScalableProfile,
};

const BASE: GuestAddress = GuestAddress(0x1000);
const WORD_BYTES: u64 = size_of::<u32>() as u64;
const ADD_X5_X5_ONE: u32 = 0x9100_04a5;
const FRINTN_PAIR: u32 = 0xc1a8_e000;
const FADD_ZA_SINGLE: u32 = 0xc1a0_1c00;
const UNSUPPORTED_SUFFIX: u32 = 0;
const INITIAL_X5: u64 = 41;
const PREFIX_REGISTER: usize = 5;
const SINGLE_BYTES: usize = size_of::<u32>();
const SOURCE_SINGLE: u32 = 0x3fc0_0000; // 1.5
const INITIAL_ZA_SINGLE: u32 = 0x3f80_0000; // 1.0
const ROUNDED_SINGLE: u32 = 0x4000_0000; // 2.0
const ADDED_SINGLE: u32 = 0x4020_0000; // 2.5
const PREDICATE_PATTERN: u8 = 0xa5;
const TPIDR2_CANARY: u64 = 0x1234_5678_9abc_def0;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Banks {
    vectors: Vec<Vec<u8>>,
    predicates: Vec<Vec<u8>>,
    za: Option<Vec<u8>>,
    mode: ScalableMode,
    tpidr2: u64,
}

fn repeated_single(bits: u32, bytes: usize) -> Vec<u8> {
    bits.to_le_bytes().repeat(bytes / SINGLE_BYTES)
}

fn banks(thread: &ThreadState, scalable: &ScalableState) -> Banks {
    let bytes = scalable.vector_length().bytes();
    let vectors = (0..VECTOR_REGISTER_COUNT)
        .map(|register| {
            let mut value = vec![0; bytes];
            scalable
                .read_z(&thread.registers, register, &mut value)
                .unwrap();
            value
        })
        .collect();
    let predicates = (0..PREDICATE_REGISTER_COUNT)
        .map(|register| {
            let mut value = vec![0; scalable.vector_length().predicate_bytes()];
            scalable.read_predicate(register, &mut value).unwrap();
            value
        })
        .collect();
    let za = scalable.mode().za_enabled().then(|| {
        let mut value = vec![0; bytes * bytes];
        scalable.read_za(0, &mut value).unwrap();
        value
    });
    Banks {
        vectors,
        predicates,
        za,
        mode: scalable.mode(),
        tpidr2: scalable.tpidr2_el0(),
    }
}

fn expected_primary_vector(bits: u32) -> [u64; 2] {
    let bytes = bits.to_le_bytes().repeat(2);
    [u64::from_le_bytes(bytes.try_into().unwrap()); 2]
}
const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];

fn profile(bytes: usize, za: bool) -> ExtendedBlockProfile {
    let scalable = ScalableProfile::new_with_features(
        VectorLength::from_bytes(bytes).unwrap(),
        ScalableMode::new(true, za),
        ScalableFeatures::of(Feature::Sme).with(Feature::Sme2),
        ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
    )
    .unwrap();
    ExtendedBlockProfile::new(
        scalable,
        BlockProfile::Ordinary,
        NumericalFeatures::default(),
    )
}

fn owner(bytes: usize, za: bool) -> (ThreadState, ScalableState) {
    let mut thread = ThreadState {
        registers: GuestState::default(),
        pc: BASE,
    };
    thread.registers.x[PREFIX_REGISTER] = INITIAL_X5;
    let mut scalable = ScalableState::new(VectorLength::from_bytes(bytes).unwrap(), false);
    scalable
        .apply_mode(&mut thread.registers, ScalableMode::new(true, za))
        .unwrap();
    for register in 0..VECTOR_REGISTER_COUNT {
        scalable
            .write_z(
                &mut thread.registers,
                register,
                &repeated_single(SOURCE_SINGLE, bytes),
            )
            .unwrap();
    }
    for register in 0..PREDICATE_REGISTER_COUNT {
        scalable
            .write_predicate(
                register,
                &vec![PREDICATE_PATTERN; scalable.vector_length().predicate_bytes()],
            )
            .unwrap();
    }
    if za {
        scalable
            .write_za(0, &repeated_single(INITIAL_ZA_SINGLE, bytes * bytes))
            .unwrap();
    }
    scalable.set_tpidr2_el0(TPIDR2_CANARY);
    (thread, scalable)
}

#[test]
fn sme_owned_completion_uses_exact_pc_without_replaying_native_prefix() {
    for bytes in LENGTHS {
        for (word, za) in [
            (FRINTN_PAIR, false),
            (FRINTN_PAIR, true),
            (FADD_ZA_SINGLE, true),
        ] {
            let source: Vec<u8> = [ADD_X5_X5_ONE, word, UNSUPPORTED_SUFFIX]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            let block = PreparedScalableBlock::prepare(
                &source,
                BASE,
                profile(bytes, za),
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(block.source(), &source[..2 * size_of::<u32>()]);
            assert_eq!(block.source_map()[1].0, GuestAddress(BASE.0 + WORD_BYTES));
            let (mut thread, mut scalable) = owner(bytes, za);
            let mut context = ExecutionContext::default();
            // SAFETY: bounded arithmetic over disjoint register storage, with
            // the declared SME2 streaming profile.
            let exit = unsafe { block.invoke(&mut thread, &mut scalable, &mut context) }.unwrap();
            assert_eq!(exit.kind, ExitKind::ScalableNumerical as u64);
            assert_eq!(exit.next_pc, BASE.0 + WORD_BYTES);
            assert_eq!(thread.pc, GuestAddress(exit.next_pc));
            assert_eq!(thread.registers.x[PREFIX_REGISTER], INITIAL_X5 + 1);
            let mut expected_banks = banks(&thread, &scalable);
            let mut expected_primary = thread.registers.clone();
            if word == FRINTN_PAIR {
                for register in 0..2 {
                    expected_banks.vectors[register] = repeated_single(ROUNDED_SINGLE, bytes);
                    expected_primary.v[register] = expected_primary_vector(ROUNDED_SINGLE);
                }
            } else {
                // Two horizontal groups select physical ZA rows 0 and SVL/2.
                let expected_za = expected_banks.za.as_mut().unwrap();
                for row in [0, bytes / 2] {
                    expected_za[row * bytes..(row + 1) * bytes]
                        .copy_from_slice(&repeated_single(ADDED_SINGLE, bytes));
                }
            }
            let pc = block
                .complete_numerical(&mut thread, &mut scalable, exit)
                .unwrap();
            assert_eq!(pc, GuestAddress(BASE.0 + 2 * WORD_BYTES));
            assert_eq!(thread.registers, expected_primary);
            assert_eq!(banks(&thread, &scalable), expected_banks);
            assert_eq!(thread.registers.x[PREFIX_REGISTER], INITIAL_X5 + 1);
        }
    }
}

#[test]
fn sme_owned_completion_declines_forged_exit_pc_and_current_owner_without_mutation() {
    for (word, za) in [(FRINTN_PAIR, false), (FADD_ZA_SINGLE, true)] {
        let block = PreparedScalableBlock::prepare(
            &word.to_le_bytes(),
            BASE,
            profile(16, za),
            TargetCpu::Baseline,
        )
        .unwrap();
        let (mut thread, mut scalable) = owner(16, za);
        let valid = BlockExit {
            next_pc: BASE.0,
            kind: ExitKind::ScalableNumerical as u64,
        };
        let before = thread.registers.clone();
        let before_banks = banks(&thread, &scalable);
        for invalid in [
            BlockExit {
                next_pc: BASE.0 + WORD_BYTES,
                ..valid
            },
            BlockExit {
                next_pc: BASE.0 + 1,
                ..valid
            },
            BlockExit {
                kind: ExitKind::Fallthrough as u64,
                ..valid
            },
        ] {
            assert!(
                block
                    .complete_numerical(&mut thread, &mut scalable, invalid)
                    .is_err()
            );
            assert_eq!(thread.registers, before);
            assert_eq!(banks(&thread, &scalable), before_banks);
            assert_eq!(thread.pc, BASE);
        }
        thread.pc = GuestAddress(BASE.0 + WORD_BYTES);
        assert!(
            block
                .complete_numerical(&mut thread, &mut scalable, valid)
                .is_err()
        );
        assert_eq!(thread.registers, before);
        assert_eq!(banks(&thread, &scalable), before_banks);
        assert_eq!(thread.pc, GuestAddress(BASE.0 + WORD_BYTES));
        thread.pc = BASE;
        let (_, mut wrong_length) = owner(32, za);
        let wrong_length_before = banks(&thread, &wrong_length);
        assert!(
            block
                .complete_numerical(&mut thread, &mut wrong_length, valid)
                .is_err()
        );
        assert_eq!(thread.registers, before);
        assert_eq!(thread.pc, BASE);
        assert_eq!(banks(&thread, &wrong_length), wrong_length_before);
        let (_, mut wrong_mode) = owner(16, !za);
        let wrong_mode_before = banks(&thread, &wrong_mode);
        assert!(
            block
                .complete_numerical(&mut thread, &mut wrong_mode, valid)
                .is_err()
        );
        assert_eq!(thread.registers, before);
        assert_eq!(thread.pc, BASE);
        assert_eq!(banks(&thread, &wrong_mode), wrong_mode_before);
    }
}
