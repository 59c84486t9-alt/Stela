use super::*;
use anyhow::Result;

fn context_options(
    scalable: stela_compiler::scalable_context::ScalableProfile,
    numerical: stela_compiler::aarch64::floating::features::NumericalFeatures,
) -> Options {
    target_options(TargetCpu::Baseline, scalable, numerical)
}

fn target_options(
    target: TargetCpu,
    scalable: stela_compiler::scalable_context::ScalableProfile,
    numerical: stela_compiler::aarch64::floating::features::NumericalFeatures,
) -> Options {
    Options::new(BlockProfile::new(Features::CONTEXT), target)
        .with_scalable(scalable)
        .with_numerical_features(numerical)
}

mod fp8 {
    //! Fixed-width FP8 completion, access and failure.
    #![cfg(all(target_os = "macos", target_arch = "x86_64"))]
    use super::*;
    use std::{ffi::c_void, ptr::NonNull};
    use stela_compiler::{
        GuestState,
        aarch64::{
            floating::{FPCR_EXCEPTION_ENABLE_MASK, features::NumericalFeatures},
            scalable::{
                ScalableMode, VectorLength,
                features::{ScalableFeature as Feature, ScalableFeatures},
                profile::ScalableControls,
            },
        },
        context::ScalableStateView,
        scalable_context::ScalableProfile,
    };

    const BASE: GuestAddress = GuestAddress(0x8000);
    const ADD_X5_X5_ONE: u32 = 0x9100_04a5;
    const BF1CVTL_V0_V1: u32 = 0x2ea1_7820;
    const FCVTN_V1_UPPER_V1_V2: u32 = 0x4e02_f421;
    const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
    const INITIAL_FPSR: u32 = 1 << 27;
    const NUMERICAL_PC: GuestAddress = GuestAddress(BASE.0 + 4);
    const NEXT_PC: GuestAddress = GuestAddress(BASE.0 + 8);

    fn profile(bytes: usize, streaming: bool, enabled: bool, fp8: bool, fpmr: bool) -> Options {
        let length = VectorLength::from_bytes(bytes).unwrap();
        let mut features = ScalableFeatures::of(Feature::Sme);
        if fp8 {
            features = features.with(Feature::Fp8);
        }
        if fpmr {
            features = features.with(Feature::Fpmr);
        }
        if streaming {
            features = features.with(Feature::SmeFa64);
        }
        context_options(
            ScalableProfile::new_with_features(
                length,
                ScalableMode::new(streaming, false),
                features,
                ScalableControls::new(length, false).with_fpmr_enabled(enabled),
            )
            .unwrap(),
            NumericalFeatures::new(streaming, false, false),
        )
    }

    fn prepare(word: u32, bytes: usize, streaming: bool) -> Result<PreparedScalableBlock> {
        let source: Vec<_> = [ADD_X5_X5_ONE, word, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        Ok(PreparedScalableBlock::prepare(
            &source,
            BASE,
            &profile(bytes, streaming, true, true, true),
        )?)
    }

    fn owner(bytes: usize, streaming: bool) -> Result<(ThreadState, ScalableState)> {
        let mut registers = GuestState {
            fpsr: INITIAL_FPSR,
            nzcv: 0xa000_0000,
            ..GuestState::default()
        };
        registers.x[5] = 41;
        let mut scalable = ScalableState::new(VectorLength::from_bytes(bytes).unwrap(), false);
        scalable.apply_mode(&mut registers, ScalableMode::new(streaming, false))?;
        if streaming {
            for register in 0..32 {
                scalable.write_z(&mut registers, register, &vec![0x38; bytes])?;
            }
            for predicate in 0..16 {
                scalable.write_predicate(predicate, &vec![0xa5; bytes / 8])?;
            }
        } else {
            registers.v.fill([0x3838_3838_3838_3838; 2]);
        }
        // F8S1=E4M3 and LSCALE=1: 0x38 (1.0) converts to BF16 0.5.
        scalable.set_fpmr(1 | 1 << 16);
        scalable.set_tpidr2_el0(0x1234_5678_9abc_def0);
        Ok((
            ThreadState {
                registers,
                pc: BASE,
            },
            scalable,
        ))
    }

    fn context() -> ExecutionContext {
        ExecutionContext {
            memory: NonNull::<u8>::dangling().as_ptr().cast::<c_void>(),
            scalable: NonNull::<ScalableStateView>::dangling().as_ptr(),
            system: NonNull::<u32>::dangling().as_ptr().cast::<c_void>(),
            ..ExecutionContext::default()
        }
    }

    #[test]
    fn fixed_fp8_owned_completion_preserves_context_and_clears_upper_z() -> Result<()> {
        for bytes in LENGTHS {
            for streaming in [false, true] {
                let prepared = prepare(BF1CVTL_V0_V1, bytes, streaming)?;
                assert_eq!(prepared.source_map().len(), 2);
                let (mut thread, mut scalable) = owner(bytes, streaming)?;
                let mut expected = thread.registers.clone();
                expected.x[5] += 1;
                expected.v[0] = [0x3f00_3f00_3f00_3f00; 2];
                let mut context = context();
                let pointers = (context.memory, context.scalable, context.system);
                // SAFETY: fixed trusted source, disjoint owned state and the
                // declared FP8/FPMR/EnFPM/FA64 profile.
                let exit = unsafe { prepared.invoke(&mut thread, &mut scalable, &mut context)? };
                assert_eq!(thread.pc, NUMERICAL_PC);
                assert_eq!(exit.kind, ExitKind::ScalableNumerical as u64);
                assert_eq!(thread.registers.x[5], 42);
                assert_eq!((context.memory, context.scalable, context.system), pointers);
                assert_eq!(
                    prepared.complete_numerical(&mut thread, &mut scalable, exit)?,
                    NEXT_PC
                );
                assert_eq!(thread.registers, expected);
                assert_eq!(scalable.fpmr(), 1 | 1 << 16);
                assert_eq!(scalable.tpidr2_el0(), 0x1234_5678_9abc_def0);
                if streaming {
                    let mut destination = vec![0; bytes];
                    scalable.read_z(&thread.registers, 0, &mut destination)?;
                    assert_eq!(&destination[..16], &0x3f00u16.to_le_bytes().repeat(8));
                    assert!(destination[16..].iter().all(|&byte| byte == 0));
                    let mut source = vec![0; bytes];
                    scalable.read_z(&thread.registers, 1, &mut source)?;
                    assert_eq!(source, vec![0x38; bytes]);
                    let mut predicate = vec![0; bytes / 8];
                    scalable.read_predicate(0, &mut predicate)?;
                    assert_eq!(predicate, vec![0xa5; bytes / 8]);
                }
                // A settled numerical exit cannot execute again or replay prefix.
                assert!(
                    prepared
                        .complete_numerical(&mut thread, &mut scalable, exit)
                        .is_err()
                );
                assert_eq!(thread.registers.x[5], 42);
                assert_eq!(thread.pc, NEXT_PC);
            }
        }
        Ok(())
    }

    #[test]
    fn fixed_fp8_keeps_exception_enables_and_commits_nothing_on_failure() -> Result<()> {
        for bytes in LENGTHS {
            for streaming in [false, true] {
                let prepared = prepare(BF1CVTL_V0_V1, bytes, streaming)?;
                let (mut thread, mut scalable) = owner(bytes, streaming)?;
                thread.registers.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
                let mut expected = thread.registers.clone();
                expected.x[5] += 1;
                let mut context = context();
                // SAFETY: the same profile; enabled numerical traps must refuse
                // completion before any effect.
                let exit = unsafe { prepared.invoke(&mut thread, &mut scalable, &mut context)? };
                assert!(matches!(
                    prepared.complete_numerical(&mut thread, &mut scalable, exit),
                    Err(CompletionError::UnsupportedControl(_))
                ));
                assert_eq!(thread.registers, expected);
                assert_eq!(thread.pc, NUMERICAL_PC);
                assert_eq!(scalable.fpmr(), 1 | 1 << 16);
                if streaming {
                    let mut z = vec![0; bytes];
                    scalable.read_z(&thread.registers, 0, &mut z)?;
                    assert_eq!(z, vec![0x38; bytes]);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn fixed_fp8_reused_prepared_entry_reads_each_owners_current_fpmr() -> Result<()> {
        for bytes in LENGTHS {
            for streaming in [false, true] {
                let prepared = prepare(BF1CVTL_V0_V1, bytes, streaming)?;
                let identity = prepared.identity().clone();
                for (fpmr, expected_bfloat) in [(0, 0x3f00u16), (1, 0x3f80), (1 | 1 << 16, 0x3f00)]
                {
                    let (mut thread, mut scalable) = owner(bytes, streaming)?;
                    scalable.set_fpmr(fpmr);
                    thread.registers.fpcr = 0x0508_0001; // Ignored AHP/FZ/FZ16/FIZ.
                    let mut expected = thread.registers.clone();
                    expected.x[5] += 1;
                    let limb = u64::from_le_bytes(
                        expected_bfloat.to_le_bytes().repeat(4).try_into().unwrap(),
                    );
                    expected.v[0] = [limb; 2];
                    let mut context = context();
                    // SAFETY: each new state matches the same profile; FPMR values
                    // are state, not code parameters.
                    let exit =
                        unsafe { prepared.invoke(&mut thread, &mut scalable, &mut context)? };
                    prepared.complete_numerical(&mut thread, &mut scalable, exit)?;
                    assert_eq!(thread.registers, expected);
                    assert_eq!(thread.pc, NEXT_PC);
                    assert_eq!(scalable.fpmr(), fpmr);
                    assert_eq!(prepared.identity(), &identity);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn fixed_fp8_upper_narrow_snapshots_alias_before_insertion() -> Result<()> {
        for bytes in LENGTHS {
            let prepared = prepare(FCVTN_V1_UPPER_V1_V2, bytes, false)?;
            let (mut thread, mut scalable) = owner(bytes, false)?;
            let one = [0x3f80_0000_3f80_0000; 2];
            thread.registers.v[1] = one;
            thread.registers.v[2] = one;
            scalable.set_fpmr(1 << 6 | 1 << 24); // E4M3, NSCALE=+1 => 2.0 => 0x40.
            let mut context = context();
            // SAFETY: the same non-streaming profile; Vd aliases Vn.
            let exit = unsafe { prepared.invoke(&mut thread, &mut scalable, &mut context)? };
            prepared.complete_numerical(&mut thread, &mut scalable, exit)?;
            assert_eq!(thread.registers.v[1], [one[0], 0x4040_4040_4040_4040]);
            assert_eq!(thread.registers.v[2], one);
            assert_eq!(thread.registers.fpsr, INITIAL_FPSR);
        }
        Ok(())
    }

    #[test]
    fn fixed_fp8_denies_absent_features_or_disabled_indirect_access() {
        let source = BF1CVTL_V0_V1.to_le_bytes();
        for (enabled, fp8, fpmr) in [
            (false, true, true),
            (false, false, true),
            (false, true, false),
            (true, false, true),
        ] {
            assert!(
                PreparedScalableBlock::prepare(
                    &source,
                    BASE,
                    &profile(16, false, enabled, fp8, fpmr)
                )
                .is_err()
            );
        }
        let length = VectorLength::from_bytes(16).unwrap();
        let streaming_without_fa64 = context_options(
            ScalableProfile::new_with_features(
                length,
                ScalableMode::new(true, false),
                ScalableFeatures::of(Feature::Sme)
                    .with(Feature::Fp8)
                    .with(Feature::Fpmr),
                ScalableControls::new(length, false).with_fpmr_enabled(true),
            )
            .unwrap(),
            NumericalFeatures::default(),
        );
        assert!(PreparedScalableBlock::prepare(&source, BASE, &streaming_without_fa64).is_err());
    }
}
mod fp8_conversion {
    //! SME FP8 conversion preparation at every vector length.
    use super::*;
    use stela_compiler::{
        aarch64::{
            floating::features::NumericalFeatures,
            scalable::{
                ScalableMode, VectorLength,
                features::{ScalableFeature as Feature, ScalableFeatures},
                profile::ScalableControls,
            },
            sme::fp8_conversion::{
                self, BF1CVT_MZ2_Z8, BF1CVTL_MZ2_Z8, BF2CVT_MZ2_Z8, BF2CVTL_MZ2_Z8, BFCVT_Z8_MZ2,
                Conversion, ElementFormat,
            },
        },
        block::scalable::{
            ScalableNumericalOperation, admit_scalable_numerical_instruction,
            decode_scalable_numerical_instruction,
        },
        scalable_context::ScalableProfile,
    };

    const BASE: GuestAddress = GuestAddress(0x1000);
    const ADD_X5_X5_ONE: u32 = 0x9100_04a5;
    const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];

    fn profile(bytes: usize) -> ScalableProfile {
        let length = VectorLength::from_bytes(bytes).unwrap();
        ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, false),
            ScalableFeatures::of(Feature::Sme)
                .with(Feature::Sme2)
                .with(Feature::Fp8)
                .with(Feature::Fpmr),
            ScalableControls::new(length, false).with_fpmr_enabled(true),
        )
        .unwrap()
    }

    #[test]
    fn bfcvt_preparation_preserves_prefix_source_and_descriptor_integrity() -> Result<()> {
        let operand = fp8_conversion::decode(BFCVT_Z8_MZ2).unwrap();
        assert_eq!(operand.format, ElementFormat::BFloat16);
        assert!(matches!(operand.conversion, Conversion::Narrow { .. }));
        for bytes in LENGTHS {
            let profile = profile(bytes);
            let source: Vec<_> = [ADD_X5_X5_ONE, BFCVT_Z8_MZ2, 0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let prepared = PreparedScalableBlock::prepare(
                &source,
                BASE,
                &context_options(profile, NumericalFeatures::default()),
            )?;
            assert_eq!(prepared.source(), &source[..2 * size_of::<u32>()]);
            assert_eq!(prepared.source_map().len(), 2);
            assert_eq!(prepared.source_map()[0].0, BASE);
            assert_eq!(prepared.source_map()[1].0, GuestAddress(BASE.0 + 4));

            let mut decoded = decode_scalable_numerical_instruction(BASE, BFCVT_Z8_MZ2)?.unwrap();
            if let ScalableNumericalOperation::SmeFp8Conversion(ref mut operand) = decoded.operation
            {
                operand.canonical_id = "bf1cvt_mz2_z8_";
            }
            assert!(
                admit_scalable_numerical_instruction(
                    decoded,
                    profile,
                    NumericalFeatures::default()
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn bfloat_fp8_widening_remains_admitted_at_all_streaming_lengths() -> Result<()> {
        for bytes in LENGTHS {
            for word in [BF1CVT_MZ2_Z8, BF1CVTL_MZ2_Z8, BF2CVT_MZ2_Z8, BF2CVTL_MZ2_Z8] {
                let compiled = PreparedScalableBlock::prepare(
                    &word.to_le_bytes(),
                    BASE,
                    &context_options(profile(bytes), NumericalFeatures::default()),
                )?;
                assert_eq!(compiled.source(), word.to_le_bytes());
                assert_eq!(
                    compiled.source_map(),
                    &[(
                        BASE,
                        stela_compiler::scalable_context::CONTEXT_WRAPPER_BYTES
                    )]
                );
            }
        }
        Ok(())
    }
}
mod numerical22 {
    //! Context-backed blocks with numerical exits.
    #![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]

    use super::*;
    use std::{ffi::c_void, ptr::NonNull};
    use stela_compiler::{
        GuestState,
        aarch64::{
            floating::{
                FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FZ16, FPCR_ROUNDING_SHIFT,
                features::NumericalFeatures,
            },
            scalable::{
                LOOKUP_TABLE_BYTES, PREDICATE_REGISTER_COUNT, ScalableMode, VECTOR_REGISTER_COUNT,
                VectorLength,
                features::{ScalableFeature, ScalableFeatures},
                profile::ScalableControls,
            },
        },
        context::ScalableStateView,
        scalable_context::ScalableProfile,
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
            Ok(self
                .scalable
                .write_z(&mut self.thread.registers, 0, &repeated(lane, bytes))?)
        }
    }

    fn profile(bytes: usize, features: NumericalFeatures) -> Options {
        target_profile(TargetCpu::Baseline, bytes, features)
    }

    fn target_profile(target: TargetCpu, bytes: usize, features: NumericalFeatures) -> Options {
        let length = VectorLength::from_bytes(bytes).unwrap();
        let mut declared = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
        if features.full_a64() {
            declared = declared.with(ScalableFeature::SmeFa64);
        }
        target_options(
            target,
            ScalableProfile::new_with_features(
                length,
                ScalableMode::new(true, true),
                declared,
                ScalableControls::new(length, false),
            )
            .unwrap(),
            features,
        )
    }

    fn source(word: u32) -> Vec<u8> {
        [ADD_X5_X5_ONE, word, UNSUPPORTED_SUFFIX]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    }

    fn prepare(
        bytes: usize,
        word: u32,
        features: NumericalFeatures,
    ) -> Result<PreparedScalableBlock> {
        Ok(PreparedScalableBlock::prepare(
            &source(word),
            BASE,
            &profile(bytes, features),
        )?)
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
    fn owned_block_fast_path_returns_native_fallthrough_after_commit() -> Result<()> {
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
            let exit = unsafe {
                prepared.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)?
            };
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
    fn guarded_nan_exit_keeps_exact_pc_and_completes_the_whole_original_instruction() -> Result<()>
    {
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
            let exit = unsafe {
                prepared.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)?
            };
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
                &profile(bytes, NumericalFeatures::default()),
            )?;
            caller_source.fill(0); // Owned source recovery must ignore this changed caller buffer.
            let mut fixture = Fixture::new(bytes, true)?;
            let before_numerical = fixture.expected_prefix(NUMERICAL_PC);
            let mut context = context();
            let pointers = context_pointers(&context);
            // SAFETY: the prepared copy owns this bounded source.
            let exit = unsafe {
                prepared.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)?
            };
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

    /// A normal Half, or for a quarter of `kind`s one of any class.
    fn half_lane(kind: u64, bits: u64) -> u16 {
        let bits = bits as u16;
        match kind % 4 {
            0 => bits,
            1 => bits & 0x83ff | 0x3c00,
            _ => bits & 0x83ff | ((bits >> 4 & 15) + 8) << 10,
        }
    }

    /// Run `block` to its end, through completion when it exits; true when it
    /// ran inline.
    fn settle(block: &PreparedScalableBlock, fixture: &mut Fixture, word: u32) -> Result<bool> {
        // SAFETY: the block owns its bounded source and matches the fixture's
        // profile; storage is disjoint and the block returns once.
        let exit =
            unsafe { block.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context())? };
        if exit.kind == ExitKind::Fallthrough as u64 {
            return Ok(true);
        }
        assert_eq!(exit.kind, ExitKind::ScalableNumerical as u64, "{word:x}");
        block.complete_numerical(&mut fixture.thread, &mut fixture.scalable, exit)?;
        Ok(false)
    }

    /// Every Half form of the shared S/D pipelines runs on AVX512-FP16 and,
    /// inline or through its exit, ends as whole-instruction completion does.
    #[test]
    fn avx512fp16_half_forms_match_whole_instruction_completion() -> Result<()> {
        // llvm-mc: FADD, FSUB, FMUL, FSUBR, FABD, FMULX, FDIV, FDIVR; FADD, FSUB
        // and FMUL unpredicated; FADD #0.5, FSUB #1.0, FSUBR #0.5, FMUL #2.0;
        // FMUL Z2.H[5]; FMLA, FMLS, FNMLA, FNMLS, FMAD, FMSB, FNMAD, FNMSB; FMLA
        // Z2.H[6], FMLS Z2.H[1].
        const FORMS: [u32; 26] = [
            0x6540_8020,
            0x6541_8020,
            0x6542_8020,
            0x6543_8020,
            0x6548_8020,
            0x654a_8020,
            0x654d_8020,
            0x654c_8020,
            0x6542_0020,
            0x6542_0420,
            0x6542_0820,
            0x6558_8000,
            0x6559_8020,
            0x655b_8000,
            0x655a_8020,
            0x646a_2020,
            0x6562_0020,
            0x6562_2020,
            0x6562_4020,
            0x6562_6020,
            0x6562_8020,
            0x6562_a020,
            0x6562_c020,
            0x6562_e020,
            0x6472_0020,
            0x642a_0420,
        ];
        let target = TargetCpu::X86_64_V4.with_avx512fp16();
        if !stela_compiler::x86_64::modeled::host().supports(target) {
            return Ok(());
        }
        let mut random = 0x7137_4491_b5c0_fbcf_u64;
        let mut next = move || {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random
        };
        let features = NumericalFeatures::default();
        let mut inline = 0;
        for bytes in [16, 32, 64] {
            for word in FORMS {
                let native = PreparedScalableBlock::prepare(
                    &source(word),
                    BASE,
                    &target_profile(target, bytes, features),
                )?;
                let completion = prepare(bytes, word, features)?;
                for sample in 0..32 {
                    let mut fixture = Fixture::new(bytes, true)?;
                    fixture.thread.registers.fpcr = sample << FPCR_ROUNDING_SHIFT
                        | if sample & 4 != 0 { FPCR_FZ16 } else { 0 }
                        | if sample & 8 != 0 { FPCR_DN } else { 0 };
                    for register in 0..3 {
                        let kind = u64::from(sample) + 1;
                        let lanes: Vec<u8> = (0..bytes / 2)
                            .flat_map(|_| half_lane(kind, next()).to_le_bytes())
                            .collect();
                        fixture.scalable.write_z(
                            &mut fixture.thread.registers,
                            register,
                            &lanes,
                        )?;
                    }
                    let predicate: Vec<u8> = (0..bytes / 8)
                        .map(|_| {
                            if sample & 16 != 0 {
                                next() as u8
                            } else {
                                u8::MAX
                            }
                        })
                        .collect();
                    fixture.scalable.write_predicate(0, &predicate)?;
                    let mut expected = fixture.clone();
                    settle(&completion, &mut expected, word)?;
                    inline += u32::from(settle(&native, &mut fixture, word)?);
                    assert_eq!(
                        fixture.snapshot()?,
                        expected.snapshot()?,
                        "{word:x} {bytes} {sample}"
                    );
                }
            }
        }
        assert!(inline > 1000, "inline={inline}");
        Ok(())
    }

    #[test]
    fn unsupported_controls_keep_prefix_exact_pc_and_all_numerical_input_state() -> Result<()> {
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
        let accepted = prepared.identity().options;
        assert!(
            validate_scalable_numerical_exit(
                BASE,
                NUMERICAL_PC,
                forged_source.len(),
                BASE.0,
                &forged_source,
                accepted.scalable().unwrap(),
                accepted.numerical_features(),
            )
            .is_err()
        );
        let length = VectorLength::from_bytes(16).unwrap();
        let wrong_mode = ScalableProfile::new_with_features(
            length,
            ScalableMode::new(false, true),
            accepted.scalable().unwrap().features(),
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
                accepted.scalable().unwrap(),
                NumericalFeatures::new(true, false, false),
            )
            .is_err()
        );
        assert_eq!(fixture.snapshot()?, wrong_pc);
        Ok(())
    }

    #[test]
    fn entry_and_completion_reject_mismatches_without_mutation() -> Result<()> {
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
            assert!(
                // SAFETY: these rejection cases never enter native code; `invoke` checks
                // metadata before borrowing or dereferencing any view.
                unsafe {
                    prepared.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)
                }
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
    ) -> Result<Options> {
        Ok(context_options(
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(bytes).unwrap(),
                mode,
                declared,
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false)
                    .with_fpmr_enabled(access),
            )?,
            numerical,
        ))
    }

    #[test]
    fn new19_admission_and_completion_rejections() -> Result<()> {
        use stela_compiler::block::scalable::{
            admit_scalable_numerical_instruction, decode_scalable_numerical_instruction,
        };
        const FP8: u32 = 0x650a_381f;
        const ABSOLUTE: u32 = 0x658e_9fdf;
        const LUT: u32 = 0x4520_bc20;
        let declared = new19_features();
        let mode = ScalableMode::new(true, true);
        let numerical = NumericalFeatures::default();
        // Missing EnFPM permission is refused after source re-decoding.
        let denied = new19_profile(32, declared, false, mode, numerical)?;
        assert!(PreparedScalableBlock::prepare(&source(FP8), BASE, &denied).is_err());
        let instruction = decode_scalable_numerical_instruction(NUMERICAL_PC, FP8)?.unwrap();
        assert!(
            admit_scalable_numerical_instruction(
                instruction,
                denied.scalable().unwrap(),
                numerical
            )
            .is_err()
        );
        let mut forged = instruction;
        forged.word ^= 1;
        let allowed = new19_profile(32, declared, true, mode, numerical)?;
        assert!(
            admit_scalable_numerical_instruction(forged, allowed.scalable().unwrap(), numerical)
                .is_err()
        );
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
            assert!(PreparedScalableBlock::prepare(&source(word), BASE, &only_sme).is_err());
            let nonstreaming = new19_profile(
                32,
                declared,
                true,
                ScalableMode::new(false, false),
                numerical,
            )?;
            assert!(PreparedScalableBlock::prepare(&source(word), BASE, &nonstreaming).is_err());
        }
        let short = new19_profile(16, declared, true, mode, numerical)?;
        assert!(PreparedScalableBlock::prepare(&source(LUT), BASE, &short).is_err());
        let entry = PreparedScalableBlock::prepare(&source(FP8), BASE, &allowed)?;
        let mut fixture = Fixture::new(32, false)?;
        fixture.scalable.set_fpmr(0);
        let mut context = context();
        // SAFETY: the same profile and disjoint storage as above.
        let exit =
            unsafe { entry.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)? };
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
            assert!(
                // SAFETY: `invoke` declines the mismatching owner before native entry.
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
            let entry = PreparedScalableBlock::prepare(&source(ABSOLUTE), BASE, &fa64)?;
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
        // Enables under effective FullA64 must refuse without partial commit.
        let entry = PreparedScalableBlock::prepare(&source(FP8), BASE, &fa64)?;
        fixture.thread.pc = BASE;
        fixture.thread.registers.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        // SAFETY: the declared FA64 and control profile is bound.
        let exit =
            unsafe { entry.invoke(&mut fixture.thread, &mut fixture.scalable, &mut context)? };
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
}
mod sme_completion {
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
        scalable_context::ScalableProfile,
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

    fn profile(bytes: usize, za: bool) -> Options {
        let scalable = ScalableProfile::new_with_features(
            VectorLength::from_bytes(bytes).unwrap(),
            ScalableMode::new(true, za),
            ScalableFeatures::of(Feature::Sme).with(Feature::Sme2),
            ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
        )
        .unwrap();
        context_options(scalable, NumericalFeatures::default())
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
                let block =
                    PreparedScalableBlock::prepare(&source, BASE, &profile(bytes, za)).unwrap();
                assert_eq!(block.source(), &source[..2 * size_of::<u32>()]);
                assert_eq!(block.source_map()[1].0, GuestAddress(BASE.0 + WORD_BYTES));
                let (mut thread, mut scalable) = owner(bytes, za);
                let mut context = ExecutionContext::default();
                // SAFETY: bounded arithmetic over disjoint register storage, with
                // the declared SME2 streaming profile.
                let exit =
                    unsafe { block.invoke(&mut thread, &mut scalable, &mut context) }.unwrap();
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
            let block = PreparedScalableBlock::prepare(&word.to_le_bytes(), BASE, &profile(16, za))
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
}
