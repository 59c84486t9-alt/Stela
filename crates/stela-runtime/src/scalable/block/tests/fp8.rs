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
    extended::ScalableProfile,
};

const BASE: GuestAddress = GuestAddress(0x8000);
const ADD_X5_X5_ONE: u32 = 0x9100_04a5;
const BF1CVTL_V0_V1: u32 = 0x2ea1_7820;
const FCVTN_V1_UPPER_V1_V2: u32 = 0x4e02_f421;
const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
const INITIAL_FPSR: u32 = 1 << 27;
const NUMERICAL_PC: GuestAddress = GuestAddress(BASE.0 + 4);
const NEXT_PC: GuestAddress = GuestAddress(BASE.0 + 8);

fn profile(
    bytes: usize,
    streaming: bool,
    enabled: bool,
    fp8: bool,
    fpmr: bool,
) -> ExtendedBlockProfile {
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
    ExtendedBlockProfile::new(
        ScalableProfile::new_with_features(
            length,
            ScalableMode::new(streaming, false),
            features,
            ScalableControls::new(length, false).with_fpmr_enabled(enabled),
        )
        .unwrap(),
        BlockProfile::Ordinary,
        NumericalFeatures::new(streaming, false, false),
    )
}

fn prepare(word: u32, bytes: usize, streaming: bool) -> Result<PreparedScalableBlock> {
    let source: Vec<_> = [ADD_X5_X5_ONE, word, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    PreparedScalableBlock::prepare(
        &source,
        BASE,
        profile(bytes, streaming, true, true, true),
        TargetCpu::Baseline,
    )
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
            // SAFETY: Fixed trusted source, disjoint owned state and exact
            // declared FP8/FPMR/EnFPM/FullA64 profile for this synchronous call.
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
fn fixed_fp8_retains_exception_enables_and_commits_nothing_on_failure() -> Result<()> {
    for bytes in LENGTHS {
        for streaming in [false, true] {
            let prepared = prepare(BF1CVTL_V0_V1, bytes, streaming)?;
            let (mut thread, mut scalable) = owner(bytes, streaming)?;
            thread.registers.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
            let mut expected = thread.registers.clone();
            expected.x[5] += 1;
            let mut context = context();
            // SAFETY: Same bounded explicit profile; numerical trap delivery
            // is expected to decline completion before architectural effects.
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
            for (fpmr, expected_bfloat) in [(0, 0x3f00u16), (1, 0x3f80), (1 | 1 << 16, 0x3f00)] {
                let (mut thread, mut scalable) = owner(bytes, streaming)?;
                scalable.set_fpmr(fpmr);
                thread.registers.fpcr = 0x0508_0001; // Ignored AHP/FZ/FZ16/FIZ.
                let mut expected = thread.registers.clone();
                expected.x[5] += 1;
                let limb =
                    u64::from_le_bytes(expected_bfloat.to_le_bytes().repeat(4).try_into().unwrap());
                expected.v[0] = [limb; 2];
                let mut context = context();
                // SAFETY: Each fresh owned state matches the same immutable
                // profile; FPMR values are runtime state, never code parameters.
                let exit = unsafe { prepared.invoke(&mut thread, &mut scalable, &mut context)? };
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
        // SAFETY: Same fixed nonstreaming owned profile; Vd aliases Vn.
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
                profile(16, false, enabled, fp8, fpmr),
                TargetCpu::Baseline
            )
            .is_err()
        );
    }
    let length = VectorLength::from_bytes(16).unwrap();
    let streaming_without_fa64 = ExtendedBlockProfile::new(
        ScalableProfile::new_with_features(
            length,
            ScalableMode::new(true, false),
            ScalableFeatures::of(Feature::Sme)
                .with(Feature::Fp8)
                .with(Feature::Fpmr),
            ScalableControls::new(length, false).with_fpmr_enabled(true),
        )
        .unwrap(),
        BlockProfile::Ordinary,
        NumericalFeatures::default(),
    );
    assert!(
        PreparedScalableBlock::prepare(&source, BASE, streaming_without_fa64, TargetCpu::Baseline)
            .is_err()
    );
}
