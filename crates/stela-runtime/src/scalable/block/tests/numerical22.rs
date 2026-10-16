//! Context-backed blocks with numerical exits.
#![cfg(all(target_os = "macos", target_arch = "x86_64"))]

use super::*;
use std::{ffi::c_void, ptr::NonNull};
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_EXCEPTION_ENABLE_MASK, features::NumericalFeatures},
        scalable::{
            LOOKUP_TABLE_BYTES, PREDICATE_REGISTER_COUNT, ScalableMode, VECTOR_REGISTER_COUNT,
            VectorLength,
            features::{ScalableFeature, ScalableFeatures},
            profile::ScalableControls,
        },
    },
    context::ScalableStateView,
    extended::ScalableProfile,
};

const BASE: GuestAddress = GuestAddress(0x1000);
const WORD_BYTES: u64 = size_of::<u32>() as u64;
const NUMERICAL_PC: GuestAddress = GuestAddress(BASE.0 + WORD_BYTES);
const NEXT_PC: GuestAddress = GuestAddress(BASE.0 + 2 * WORD_BYTES);
const PREFIX_REGISTER: usize = 5;
const ADD_X5_X5_ONE: u32 = 0x9100_04a5;
const FADD_Z0_S_P0_Z0_Z1: u32 = 0x6580_8020;
const FADD_Z0_H_P0_Z0_Z1: u32 = 0x6540_8020;
const NOP: u32 = 0xd503_201f;
const UNSUPPORTED_SUFFIX: u32 = 0;
const ONE_SINGLE: u32 = 0x3f80_0000;
const TWO_SINGLE: u32 = 0x4000_0000;
const THREE_SINGLE: u32 = 0x4040_0000;
const QUIET_SINGLE_NAN: u32 = 0x7fc0_1234;
const ONE_HALF: u16 = 0x3c00;
const TWO_HALF: u16 = 0x4000;
const THREE_HALF: u16 = 0x4200;
const INITIAL_FPSR: u32 = 0x0800_0000;
const INITIAL_NZCV: u32 = 0xa000_0000;
const RESERVED_CANARY: u32 = 0x1234_5678;
const GPR_CANARY: u64 = 0x1111_2222_3333_4444;
const SP_CANARY: u64 = 0x5555_6666_7777_8888;
const TPIDR2_CANARY: u64 = 0x1234_5678_9abc_def0;
const FPMR_CANARY: u64 = 0x0123_4567;
const BYTE_PATTERN_MULTIPLIER: usize = 37;
const BYTE_PATTERN_SEED: usize = 83;
const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];

#[derive(Clone)]
struct Fixture {
    thread: ThreadState,
    scalable: ScalableState,
}

#[derive(Debug, PartialEq, Eq)]
struct StateSnapshot {
    registers: GuestState,
    pc: GuestAddress,
    length: usize,
    mode: ScalableMode,
    tpidr2: u64,
    fpmr: u64,
    z: Option<Vec<Vec<u8>>>,
    p: Option<Vec<Vec<u8>>>,
    ffr: Option<Vec<u8>>,
    za: Option<Vec<u8>>,
    zt0: Option<Vec<u8>>,
}

fn pattern(bytes: usize, salt: usize) -> Vec<u8> {
    (0..bytes)
        .map(|index| (index * BYTE_PATTERN_MULTIPLIER + BYTE_PATTERN_SEED + salt) as u8)
        .collect()
}

fn repeated(lane: &[u8], bytes: usize) -> Vec<u8> {
    assert!(bytes.is_multiple_of(lane.len()));
    lane.repeat(bytes / lane.len())
}

impl Fixture {
    fn new(bytes: usize, half: bool) -> Result<Self> {
        let length = VectorLength::from_bytes(bytes).unwrap();
        let mut registers = GuestState {
            sp: SP_CANARY,
            nzcv: INITIAL_NZCV,
            reserved: RESERVED_CANARY,
            ..GuestState::default()
        };
        for (index, value) in registers.x.iter_mut().enumerate() {
            *value = GPR_CANARY.wrapping_add(index as u64);
        }
        let mut scalable = ScalableState::new(length, true);
        scalable.apply_mode(&mut registers, ScalableMode::new(true, true))?;
        for register in 0..VECTOR_REGISTER_COUNT {
            scalable.write_z(
                &mut registers,
                register,
                &pattern(bytes, usize::from(register)),
            )?;
        }
        for register in 0..PREDICATE_REGISTER_COUNT {
            scalable.write_predicate(
                register,
                &pattern(length.predicate_bytes(), usize::from(register)),
            )?;
        }
        scalable.write_predicate(0, &vec![u8::MAX; length.predicate_bytes()])?;
        scalable.write_ffr(&pattern(length.predicate_bytes(), 1))?;
        scalable.write_za(0, &pattern(bytes * bytes, 2))?;
        scalable.write_zt0(0, &pattern(LOOKUP_TABLE_BYTES, 3))?;
        scalable.set_tpidr2_el0(TPIDR2_CANARY);
        scalable.set_fpmr(FPMR_CANARY);
        registers.fpcr = 0;
        registers.fpsr = INITIAL_FPSR;
        let (left, right) = if half {
            (
                repeated(&ONE_HALF.to_le_bytes(), bytes),
                repeated(&TWO_HALF.to_le_bytes(), bytes),
            )
        } else {
            (
                repeated(&ONE_SINGLE.to_le_bytes(), bytes),
                repeated(&TWO_SINGLE.to_le_bytes(), bytes),
            )
        };
        scalable.write_z(&mut registers, 0, &left)?;
        scalable.write_z(&mut registers, 1, &right)?;
        Ok(Self {
            thread: ThreadState {
                registers,
                pc: BASE,
            },
            scalable,
        })
    }

    fn snapshot(&self) -> Result<StateSnapshot> {
        let bytes = self.scalable.vector_length().bytes();
        let predicate_bytes = self.scalable.vector_length().predicate_bytes();
        let (z, p, ffr) = if self.scalable.mode().streaming() {
            let mut z = Vec::new();
            for register in 0..VECTOR_REGISTER_COUNT {
                let mut value = vec![0; bytes];
                self.scalable
                    .read_z(&self.thread.registers, register, &mut value)?;
                z.push(value);
            }
            let mut predicates = Vec::new();
            for register in 0..PREDICATE_REGISTER_COUNT {
                let mut value = vec![0; predicate_bytes];
                self.scalable.read_predicate(register, &mut value)?;
                predicates.push(value);
            }
            let mut ffr = vec![0; predicate_bytes];
            self.scalable.read_ffr(&mut ffr)?;
            (Some(z), Some(predicates), Some(ffr))
        } else {
            (None, None, None)
        };
        let (za, zt0) = if self.scalable.mode().za_enabled() {
            let mut za = vec![0; bytes * bytes];
            let mut zt0 = vec![0; LOOKUP_TABLE_BYTES];
            self.scalable.read_za(0, &mut za)?;
            self.scalable.read_zt0(0, &mut zt0)?;
            (Some(za), Some(zt0))
        } else {
            (None, None)
        };
        Ok(StateSnapshot {
            registers: self.thread.registers.clone(),
            pc: self.thread.pc,
            length: bytes,
            mode: self.scalable.mode(),
            tpidr2: self.scalable.tpidr2_el0(),
            fpmr: self.scalable.fpmr(),
            z,
            p,
            ffr,
            za,
            zt0,
        })
    }

    fn expected_prefix(&self, pc: GuestAddress) -> Self {
        let mut expected = self.clone();
        expected.thread.registers.x[PREFIX_REGISTER] =
            expected.thread.registers.x[PREFIX_REGISTER].wrapping_add(1);
        expected.thread.pc = pc;
        expected
    }

    fn set_result(&mut self, lane: &[u8]) -> Result<()> {
        let bytes = self.scalable.vector_length().bytes();
        self.scalable
            .write_z(&mut self.thread.registers, 0, &repeated(lane, bytes))
    }
}

fn profile(bytes: usize, features: NumericalFeatures) -> ExtendedBlockProfile {
    let length = VectorLength::from_bytes(bytes).unwrap();
    let mut declared = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
    if features.full_a64() {
        declared = declared.with(ScalableFeature::SmeFa64);
    }
    ExtendedBlockProfile::new(
        ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, true),
            declared,
            ScalableControls::new(length, false),
        )
        .unwrap(),
        BlockProfile::Ordinary,
        features,
    )
}

fn source(word: u32) -> Vec<u8> {
    [ADD_X5_X5_ONE, word, UNSUPPORTED_SUFFIX]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}

fn prepare(bytes: usize, word: u32, features: NumericalFeatures) -> Result<PreparedScalableBlock> {
    PreparedScalableBlock::prepare(
        &source(word),
        BASE,
        profile(bytes, features),
        TargetCpu::Baseline,
    )
}

fn context() -> ExecutionContext {
    ExecutionContext {
        memory: NonNull::<u8>::dangling().as_ptr().cast::<c_void>(),
        scalable: NonNull::<ScalableStateView>::dangling().as_ptr(),
        system: NonNull::<u32>::dangling().as_ptr().cast::<c_void>(),
        ..ExecutionContext::default()
    }
}

fn context_pointers(
    context: &ExecutionContext,
) -> (*mut c_void, *mut ScalableStateView, *mut c_void) {
    (context.memory, context.scalable, context.system)
}

#[test]
fn actual_owned_block_fast_path_returns_native_fallthrough_after_commit() -> Result<()> {
    for bytes in LENGTHS {
        let prepared = prepare(bytes, FADD_Z0_S_P0_Z0_Z1, NumericalFeatures::default())?;
        assert_eq!(
            prepared.source(),
            &source(FADD_Z0_S_P0_Z0_Z1)[..2 * size_of::<u32>()]
        );
        assert_eq!(prepared.source_map().len(), 2);
        let mut fixture = Fixture::new(bytes, false)?;
        let mut expected = fixture.expected_prefix(NEXT_PC);
        expected.set_result(&THREE_SINGLE.to_le_bytes())?;
        let mut context = context();
        let pointers = context_pointers(&context);
        // SAFETY: the declared DIT, SMCR and features match the fixture;
        // storage is disjoint and the block returns once.
        let exit =
            unsafe { prepared.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)? };
        assert_eq!(
            (exit.next_pc, exit.kind),
            (NEXT_PC.0, ExitKind::Fallthrough as u64)
        );
        assert_eq!(fixture.snapshot()?, expected.snapshot()?);
        assert_eq!(context_pointers(&context), pointers);
    }
    Ok(())
}

#[test]
fn guarded_nan_exit_keeps_exact_pc_and_completes_the_whole_original_instruction() -> Result<()> {
    for bytes in LENGTHS {
        let prepared = prepare(bytes, FADD_Z0_S_P0_Z0_Z1, NumericalFeatures::default())?;
        let mut fixture = Fixture::new(bytes, false)?;
        let mut input = repeated(&ONE_SINGLE.to_le_bytes(), bytes);
        let last_lane = bytes - size_of::<u32>();
        input[last_lane..].copy_from_slice(&QUIET_SINGLE_NAN.to_le_bytes());
        fixture
            .scalable
            .write_z(&mut fixture.thread.registers, 0, &input)?;
        let before_numerical = fixture.expected_prefix(NUMERICAL_PC);
        let mut context = context();
        let pointers = context_pointers(&context);
        // SAFETY: the same fixture and controls as above.
        let exit =
            unsafe { prepared.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)? };
        assert_eq!(
            (exit.next_pc, exit.kind),
            (NUMERICAL_PC.0, ExitKind::ScalableNumerical as u64)
        );
        assert_eq!(fixture.snapshot()?, before_numerical.snapshot()?);
        assert_eq!(context_pointers(&context), pointers);
        let proof = prepared.recover_numerical(exit)?;
        assert_eq!(proof.word(), FADD_Z0_S_P0_Z0_Z1);
        assert_eq!(proof.instruction_pc(), NUMERICAL_PC);
        assert_eq!(
            prepared.complete_numerical(&mut fixture.thread, &mut fixture.scalable, exit)?,
            NEXT_PC
        );
        let mut expected = before_numerical;
        expected.thread.pc = NEXT_PC;
        let mut output = repeated(&THREE_SINGLE.to_le_bytes(), bytes);
        output[last_lane..].copy_from_slice(&QUIET_SINGLE_NAN.to_le_bytes());
        expected
            .scalable
            .write_z(&mut expected.thread.registers, 0, &output)?;
        assert_eq!(fixture.snapshot()?, expected.snapshot()?);
        assert_eq!(context_pointers(&context), pointers);
    }
    Ok(())
}

#[test]
fn half_shape_uses_whole_instruction_service_without_prefix_reexecution() -> Result<()> {
    for bytes in LENGTHS {
        let mut caller_source = source(FADD_Z0_H_P0_Z0_Z1);
        let prepared = PreparedScalableBlock::prepare(
            &caller_source,
            BASE,
            profile(bytes, NumericalFeatures::default()),
            TargetCpu::Baseline,
        )?;
        caller_source.fill(0); // Owned source recovery must ignore this changed caller buffer.
        let mut fixture = Fixture::new(bytes, true)?;
        let before_numerical = fixture.expected_prefix(NUMERICAL_PC);
        let mut context = context();
        let pointers = context_pointers(&context);
        // SAFETY: the prepared copy owns this bounded source.
        let exit =
            unsafe { prepared.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)? };
        assert_eq!(
            (exit.next_pc, exit.kind),
            (NUMERICAL_PC.0, ExitKind::ScalableNumerical as u64)
        );
        assert_eq!(fixture.snapshot()?, before_numerical.snapshot()?);
        assert_eq!(context_pointers(&context), pointers);
        assert_eq!(
            prepared.complete_numerical(&mut fixture.thread, &mut fixture.scalable, exit)?,
            NEXT_PC
        );
        let mut expected = before_numerical;
        expected.thread.pc = NEXT_PC;
        expected.set_result(&THREE_HALF.to_le_bytes())?;
        assert_eq!(fixture.snapshot()?, expected.snapshot()?);
    }
    Ok(())
}

#[test]
fn unsupported_controls_retain_prefix_exact_pc_and_all_numerical_input_state() -> Result<()> {
    let features = NumericalFeatures::new(true, false, false);
    let prepared = prepare(64, FADD_Z0_S_P0_Z0_Z1, features)?;
    let mut fixture = Fixture::new(64, false)?;
    fixture.thread.registers.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    let expected = fixture.expected_prefix(NUMERICAL_PC);
    let mut context = context();
    let pointers = context_pointers(&context);
    // SAFETY: effective FA64 matches the declared FEAT_SME_FA64; unsupported
    // numerical controls must leave the instruction pending.
    let exit =
        unsafe { prepared.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)? };
    assert_eq!(
        (exit.next_pc, exit.kind),
        (NUMERICAL_PC.0, ExitKind::ScalableNumerical as u64)
    );
    assert_eq!(fixture.snapshot()?, expected.snapshot()?);
    assert_eq!(context_pointers(&context), pointers);
    let error = prepared
        .complete_numerical(&mut fixture.thread, &mut fixture.scalable, exit)
        .unwrap_err();
    assert!(matches!(error, CompletionError::UnsupportedControl(_)));
    assert_eq!(fixture.snapshot()?, expected.snapshot()?);
    assert_eq!(context_pointers(&context), pointers);
    Ok(())
}

#[test]
fn forged_exit_source_and_profile_are_rejected_before_any_completion_effect() -> Result<()> {
    let prepared = prepare(16, FADD_Z0_H_P0_Z0_Z1, NumericalFeatures::default())?;
    let mut fixture = Fixture::new(16, true)?;
    fixture.thread.pc = NUMERICAL_PC;
    let before = fixture.snapshot()?;
    for exit in [
        BlockExit {
            next_pc: BASE.0,
            kind: ExitKind::ScalableNumerical as u64,
        },
        BlockExit {
            next_pc: NEXT_PC.0,
            kind: ExitKind::ScalableNumerical as u64,
        },
        BlockExit {
            next_pc: NUMERICAL_PC.0 + 1,
            kind: ExitKind::ScalableNumerical as u64,
        },
        BlockExit {
            next_pc: NUMERICAL_PC.0,
            kind: ExitKind::Fallthrough as u64,
        },
    ] {
        assert!(
            prepared
                .complete_numerical(&mut fixture.thread, &mut fixture.scalable, exit)
                .is_err()
        );
        assert_eq!(fixture.snapshot()?, before);
    }
    let valid_exit = BlockExit {
        next_pc: NUMERICAL_PC.0,
        kind: ExitKind::ScalableNumerical as u64,
    };
    fixture.thread.pc = BASE;
    let wrong_pc = fixture.snapshot()?;
    assert!(
        prepared
            .complete_numerical(&mut fixture.thread, &mut fixture.scalable, valid_exit)
            .is_err()
    );
    assert_eq!(fixture.snapshot()?, wrong_pc);
    let mut forged_source = prepared.source().to_vec();
    forged_source[size_of::<u32>()..].copy_from_slice(&NOP.to_le_bytes());
    let accepted = prepared.identity().profile;
    assert!(
        validate_scalable_numerical_exit(
            BASE,
            NUMERICAL_PC,
            forged_source.len(),
            BASE.0,
            &forged_source,
            accepted.scalable(),
            accepted.numerical_features(),
        )
        .is_err()
    );
    let length = VectorLength::from_bytes(16).unwrap();
    let wrong_mode = ScalableProfile::new_with_features(
        length,
        ScalableMode::new(false, true),
        accepted.scalable().features(),
        ScalableControls::new(length, false),
    )?;
    assert!(
        validate_scalable_numerical_exit(
            BASE,
            NUMERICAL_PC,
            prepared.source().len(),
            BASE.0,
            prepared.source(),
            wrong_mode,
            accepted.numerical_features(),
        )
        .is_err()
    );
    assert!(
        validate_scalable_numerical_exit(
            BASE,
            NUMERICAL_PC,
            prepared.source().len(),
            BASE.0,
            prepared.source(),
            accepted.scalable(),
            NumericalFeatures::new(true, false, false),
        )
        .is_err()
    );
    assert_eq!(fixture.snapshot()?, wrong_pc);
    Ok(())
}

#[test]
fn entry_and_completion_reject_current_length_mode_pc_and_header_without_mutation() -> Result<()> {
    let prepared = prepare(16, FADD_Z0_H_P0_Z0_Z1, NumericalFeatures::default())?;
    enum EntryMismatch {
        Length,
        Mode,
        ProgramCounter,
        Header,
    }
    for case in [
        EntryMismatch::Length,
        EntryMismatch::Mode,
        EntryMismatch::ProgramCounter,
        EntryMismatch::Header,
    ] {
        let bytes = if matches!(case, EntryMismatch::Length) {
            32
        } else {
            16
        };
        let mut fixture = Fixture::new(bytes, true)?;
        if matches!(case, EntryMismatch::Mode) {
            fixture.scalable.apply_mode(
                &mut fixture.thread.registers,
                ScalableMode::new(false, true),
            )?;
        }
        if matches!(case, EntryMismatch::ProgramCounter) {
            fixture.thread.pc = NUMERICAL_PC;
        }
        let mut context = context();
        if matches!(case, EntryMismatch::Header) {
            context.version = 0;
        }
        let before = fixture.snapshot()?;
        let pointers = context_pointers(&context);
        // SAFETY: These rejection cases never enter native code; the existing
        // API checks metadata before borrowing or dereferencing any view.
        assert!(
            unsafe { prepared.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context) }
                .is_err()
        );
        assert_eq!(fixture.snapshot()?, before);
        assert_eq!(context_pointers(&context), pointers);
        if matches!(case, EntryMismatch::Length | EntryMismatch::Mode) {
            fixture.thread.pc = NUMERICAL_PC;
            let before_completion = fixture.snapshot()?;
            let exit = BlockExit {
                next_pc: NUMERICAL_PC.0,
                kind: ExitKind::ScalableNumerical as u64,
            };
            assert!(
                prepared
                    .complete_numerical(&mut fixture.thread, &mut fixture.scalable, exit)
                    .is_err()
            );
            assert_eq!(fixture.snapshot()?, before_completion);
        }
    }
    Ok(())
}

fn new19_features() -> ScalableFeatures {
    ScalableFeatures::of(ScalableFeature::Sme)
        .with(ScalableFeature::Sme2)
        .with(ScalableFeature::Fp8)
        .with(ScalableFeature::Fpmr)
        .with(ScalableFeature::FaMinMax)
        .with(ScalableFeature::Lut)
}

fn new19_profile(
    bytes: usize,
    declared: ScalableFeatures,
    access: bool,
    mode: ScalableMode,
    numerical: NumericalFeatures,
) -> Result<ExtendedBlockProfile> {
    Ok(ExtendedBlockProfile::new(
        ScalableProfile::new_with_features(
            VectorLength::from_bytes(bytes).unwrap(),
            mode,
            declared,
            ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false)
                .with_fpmr_enabled(access),
        )?,
        BlockProfile::Ordinary,
        numerical,
    ))
}

#[test]
fn new19_actual_admission_and_completion_rejections() -> Result<()> {
    use stela_compiler::block::scalable::{
        admit_scalable_numerical_instruction, decode_scalable_numerical_instruction,
    };
    const FP8: u32 = 0x650a_381f;
    const ABSOLUTE: u32 = 0x658e_9fdf;
    const LUT: u32 = 0x4520_bc20;
    let declared = new19_features();
    let mode = ScalableMode::new(true, true);
    let numerical = NumericalFeatures::default();
    // Missing EnFPM permission is refused after exact source re-decoding.
    let denied = new19_profile(32, declared, false, mode, numerical)?;
    assert!(
        PreparedScalableBlock::prepare(&source(FP8), BASE, denied, TargetCpu::Baseline).is_err()
    );
    let instruction = decode_scalable_numerical_instruction(NUMERICAL_PC, FP8)?.unwrap();
    assert!(
        admit_scalable_numerical_instruction(instruction, denied.scalable(), numerical).is_err()
    );
    let mut forged = instruction;
    forged.word ^= 1;
    let allowed = new19_profile(32, declared, true, mode, numerical)?;
    assert!(admit_scalable_numerical_instruction(forged, allowed.scalable(), numerical).is_err());
    // An M1-like absent-SME declaration cannot manufacture a scalable profile.
    assert!(
        new19_profile(
            32,
            ScalableFeatures::empty(),
            false,
            ScalableMode::new(false, false),
            numerical
        )
        .is_err()
    );
    assert!(
        new19_profile(
            32,
            ScalableFeatures::of(ScalableFeature::Sme),
            true,
            mode,
            numerical
        )
        .is_err()
    );
    for word in [FP8, ABSOLUTE, LUT] {
        let only_sme = new19_profile(
            32,
            ScalableFeatures::of(ScalableFeature::Sme),
            false,
            mode,
            numerical,
        )?;
        assert!(
            PreparedScalableBlock::prepare(&source(word), BASE, only_sme, TargetCpu::Baseline)
                .is_err()
        );
        let nonstreaming = new19_profile(
            32,
            declared,
            true,
            ScalableMode::new(false, false),
            numerical,
        )?;
        assert!(
            PreparedScalableBlock::prepare(&source(word), BASE, nonstreaming, TargetCpu::Baseline)
                .is_err()
        );
    }
    let short = new19_profile(16, declared, true, mode, numerical)?;
    assert!(
        PreparedScalableBlock::prepare(&source(LUT), BASE, short, TargetCpu::Baseline).is_err()
    );
    let entry = PreparedScalableBlock::prepare(&source(FP8), BASE, allowed, TargetCpu::Baseline)?;
    let mut fixture = Fixture::new(32, false)?;
    fixture.scalable.set_fpmr(0);
    let mut context = context();
    // SAFETY: the same profile and disjoint storage as above.
    let exit = unsafe { entry.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)? };
    assert_eq!(
        (exit.next_pc, exit.kind),
        (NUMERICAL_PC.0, ExitKind::ScalableNumerical as u64)
    );
    let before = fixture.snapshot()?;
    let wrong = BlockExit {
        next_pc: NEXT_PC.0,
        ..exit
    };
    assert!(
        entry
            .complete_numerical(&mut fixture.thread, &mut fixture.scalable, wrong)
            .is_err()
    );
    assert_eq!(fixture.snapshot()?, before);
    for length in [16, 32] {
        let mut mismatch = Fixture::new(length, false)?;
        if length == 32 {
            mismatch.scalable.apply_mode(
                &mut mismatch.thread.registers,
                ScalableMode::new(false, true),
            )?;
        }
        let before = mismatch.snapshot()?;
        // SAFETY: Invoke must decline the mismatching owner before native entry.
        assert!(
            unsafe { entry.invoke(&mut mismatch.thread, &mut mismatch.scalable, &mut context) }
                .is_err()
        );
        assert_eq!(mismatch.snapshot()?, before);
    }
    fixture.thread.pc = NEXT_PC;
    let before = fixture.snapshot()?;
    assert!(
        entry
            .complete_numerical(&mut fixture.thread, &mut fixture.scalable, exit)
            .is_err()
    );
    assert_eq!(fixture.snapshot()?, before);
    let fa64 = new19_profile(
        32,
        declared.with(ScalableFeature::SmeFa64),
        true,
        mode,
        NumericalFeatures::new(true, false, false),
    )?;
    for active in [false, true] {
        let entry =
            PreparedScalableBlock::prepare(&source(ABSOLUTE), BASE, fa64, TargetCpu::Baseline)?;
        let mut fixture = Fixture::new(32, false)?;
        fixture.thread.registers.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        fixture
            .scalable
            .write_predicate(7, &[if active { 255 } else { 0 }; 4])?;
        fixture.scalable.write_z(
            &mut fixture.thread.registers,
            31,
            &repeated(&ONE_SINGLE.to_le_bytes(), 32),
        )?;
        fixture.scalable.write_z(
            &mut fixture.thread.registers,
            30,
            &repeated(&TWO_SINGLE.to_le_bytes(), 32),
        )?;
        let expected = fixture.expected_prefix(if active { NUMERICAL_PC } else { NEXT_PC });
        // SAFETY: declared FA64 and controls, and owned input.
        let exit =
            unsafe { entry.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)? };
        assert_eq!(fixture.snapshot()?, expected.snapshot()?);
        if active {
            assert_eq!(
                (exit.next_pc, exit.kind),
                (NUMERICAL_PC.0, ExitKind::ScalableNumerical as u64)
            );
            let before = fixture.snapshot()?;
            assert!(matches!(
                entry.complete_numerical(&mut fixture.thread, &mut fixture.scalable, exit),
                Err(CompletionError::UnsupportedControl(_))
            ));
            assert_eq!(fixture.snapshot()?, before);
        } else {
            assert_eq!(
                (exit.next_pc, exit.kind),
                (NEXT_PC.0, ExitKind::Fallthrough as u64)
            );
        }
    }
    // Retained enables under effective FullA64 must refuse without partial commit.
    let entry = PreparedScalableBlock::prepare(&source(FP8), BASE, fa64, TargetCpu::Baseline)?;
    fixture.thread.pc = BASE;
    fixture.thread.registers.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    // SAFETY: the declared FA64 and control profile is bound.
    let exit = unsafe { entry.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)? };
    let before = fixture.snapshot()?;
    assert!(matches!(
        entry.complete_numerical(&mut fixture.thread, &mut fixture.scalable, exit),
        Err(CompletionError::UnsupportedControl(_))
    ));
    assert_eq!(fixture.snapshot()?, before);
    println!(
        "NEW19_ACTUAL_REJECTIONS source_redecode/enfpm/features/mode/length/exit/pc/retained_enables PASS"
    );
    Ok(())
}
