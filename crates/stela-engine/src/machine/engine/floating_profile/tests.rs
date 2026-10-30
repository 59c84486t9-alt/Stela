use super::*;

#[test]
fn randomized_strata_sample_once_per_stratum_and_count_every_event() {
    for seed in [0, 1, u64::MAX, 0x1234_5678_9abc_def0] {
        let mut sampler = Sampler::new(seed);
        let mut per_stratum = [0; 32];
        for event in 0..(STRATUM * per_stratum.len() as u32) {
            if sampler.tick() {
                per_stratum[(event / STRATUM) as usize] += 1;
            }
            assert_eq!(
                sampler
                    .scheduled
                    .saturating_sub(u64::from(sampler.remaining)),
                u64::from(event + 1)
            );
        }
        assert_eq!(per_stratum, [1; 32]);
    }
}

#[test]
fn gap_extremes_partial_epochs_and_saturation_are_explicit() {
    assert_eq!(sample_gap(STRATUM - 1, 0), 1);
    assert_eq!(sample_gap(0, STRATUM - 1), 2 * STRATUM - 1);
    let mut sampler = Sampler::new(17);
    let first_slot = sampler.slot;
    for event in 1..=17 {
        let sampled = sampler.tick();
        assert_eq!(sampled, event == first_slot + 1);
        assert_eq!(sampler.snapshot().serviced_population, u64::from(event));
    }
    sampler.scheduled = u64::MAX - 1;
    sampler.remaining = 1;
    sampler.slot = 0;
    assert!(sampler.tick());
    assert!(!sampler.snapshot().population_exact);
    assert!(sampler.snapshot().counter_saturated);
    assert_eq!(sampler.scheduled, u64::MAX);
    let mut count = u64::MAX;
    let mut saturated = false;
    increment(&mut count, &mut saturated);
    assert_eq!(count, u64::MAX);
    assert!(saturated);
}

#[test]
fn typed_reservoir_does_not_advance_event_selection_and_cpu_site_is_before_completion() {
    let operation = FloatingPointOperation::decode(0x1e20_2820)
        .unwrap()
        .unwrap();
    let mut sampled = Sampler::new(11);
    let mut control = Sampler::new(11);
    let mut cpu = crate::machine::Cpu::new(0x4000, crate::machine::exception::Pstate::reset(0));
    cpu.retired = 123;
    for _ in 0..STRATUM * 128 {
        let selected = sampled.tick();
        assert_eq!(selected, control.tick());
        if selected {
            sampled
                .complete_at(&mut cpu, 0x1e20_2820, &operation)
                .unwrap();
        }
        assert_eq!(
            (sampled.random, sampled.remaining, sampled.scheduled),
            (control.random, control.remaining, control.scheduled)
        );
    }
    let snapshot = serde_json::to_value(sampled.snapshot()).unwrap();
    assert_eq!(snapshot["samples"], 128);
    assert_eq!(snapshot["typed"]["witness_population"], 128);
    for witness in snapshot["typed"]["witnesses"].as_array().unwrap() {
        assert_eq!(witness["guest_pc"], 0x4000);
        assert_eq!(witness["retired_before"], 123);
    }
    assert_eq!(cpu.pc, 0x4000);
    assert_eq!(cpu.retired, 123);
}

#[test]
fn sampled_completion_preserves_full_state_and_refusal() {
    let word = 0x1e20_2820; // FADD S0, S1, S0, including a source/destination alias.
    let operation = FloatingPointOperation::decode(word).unwrap().unwrap();
    for fpcr in [0, 1 << 24, 1 << 8] {
        let mut expected = GuestState {
            fpcr,
            fpsr: 0x0800_0097,
            ..Default::default()
        };
        expected.v[0] = [0x3f80_0000, u64::MAX];
        expected.v[1] = [0x4000_0000, u64::MAX];
        let mut actual = expected.clone();
        let outcome = crate::floating::complete(&mut expected, &operation);
        let mut sampler = Sampler::new(0);
        assert_eq!(sampler.complete(&mut actual, word, &operation), outcome);
        assert_eq!(actual, expected);
        let report = sampler.snapshot();
        assert_eq!(report.samples, 1);
        assert_eq!(report.rows[0].key.fpsr_before, 0x0800_0097);
        assert_eq!(
            report.rows[0].key.refused_enabled_exceptions,
            outcome.err().map(|e| e.enabled_exceptions)
        );
        assert!(report.operand_classification);
    }
}

#[test]
fn selected_capture_matches_sole_completion_across_typed_families_and_controls() {
    use stela_compiler::aarch64::{
        Register,
        floating::{
            Format,
            fused::FusedOperation,
            integer::{IntegerFormat, IntegerRounding, IntegerWidth},
            minmax::MinMaxOperation,
            precision::PrecisionRounding,
            rounding::RoundingOperation,
        },
        simd::{
            arithmetic::Shape, comparison, conversion, estimate, fused, minmax, rounding, sqrt,
        },
    };
    let integer = conversion::IntegerConversion {
        integer: conversion::IntegerOperand::Simd {
            register: 0,
            format: IntegerFormat {
                width: IntegerWidth::Bits16,
                signed: false,
            },
            shape: Shape::Vector128,
        },
        float: 1,
        format: Format::Half,
        frac_bits: 0,
    };
    let mut operations = Vec::from([
        FloatingPointOperation::decode(0x1e20_2820)
            .unwrap()
            .unwrap(),
        FloatingPointOperation::Fused(fused::Operand {
            operation: FusedOperation::Add,
            format: Format::Half,
            shape: Shape::Vector64,
            destination: 1,
            addend: 1,
            left: 0,
            right: 1,
            right_lane: Some(7),
        }),
        FloatingPointOperation::Conversion(conversion::Operand::FromInteger(integer)),
        FloatingPointOperation::Conversion(conversion::Operand::ToInteger {
            operand: integer,
            rounding: IntegerRounding::TowardZero,
        }),
        FloatingPointOperation::Conversion(conversion::Operand::JavaScript {
            destination: Register::X(0),
            source: 1,
        }),
        FloatingPointOperation::Comparison(comparison::Operand::ConditionalFlags {
            format: Format::Double,
            left: 1,
            right: 0,
            signal_all_nans: true,
            condition: 0,
            fallback: 11,
        }),
        FloatingPointOperation::Comparison(comparison::Operand::Predicate {
            operation: stela_compiler::aarch64::floating::comparison::Predicate::Equal,
            format: Format::Half,
            shape: Shape::Vector128,
            destination: 0,
            left: 0,
            right: comparison::CompareSource::Register(1),
        }),
        FloatingPointOperation::MinMax(minmax::Operand::Reduction {
            operation: MinMaxOperation::Maximum,
            format: Format::Half,
            shape: Shape::Vector128,
            destination: 1,
            source: 1,
        }),
        FloatingPointOperation::Estimate(estimate::Operand {
            kind: estimate::Kind::UnsignedReciprocal,
            format: Format::Single,
            shape: Shape::Vector128,
            destination: 0,
            source: 1,
        }),
        FloatingPointOperation::Estimate(estimate::Operand {
            kind: estimate::Kind::Reciprocal,
            format: Format::Half,
            shape: Shape::Vector64,
            destination: 1,
            source: 1,
        }),
        FloatingPointOperation::Rounding(rounding::Operand {
            operation: RoundingOperation::TowardZero,
            format: Format::Single,
            shape: Shape::Scalar,
            destination: 1,
            source: 1,
        }),
        FloatingPointOperation::SquareRoot(sqrt::Operand {
            format: Format::Half,
            shape: Shape::Vector128,
            destination: 0,
            source: 1,
        }),
    ]);
    for mode in [
        conversion::PrecisionMode::Widen {
            source: Format::Half,
            upper: true,
        },
        conversion::PrecisionMode::Narrow {
            destination: Format::Half,
            upper: true,
            rounding: PrecisionRounding::Fpcr,
        },
    ] {
        operations.push(FloatingPointOperation::Conversion(
            conversion::Operand::Precision(conversion::PrecisionOperand {
                mode,
                destination: 1,
                source: 1,
            }),
        ));
    }
    let mut sampler = Sampler::new(31);
    for operation in operations {
        for fpcr in [0, 1 << 24, 1 << 19, 1 << 26, 1 << 8, (1 << 8) | (1 << 1)] {
            for nzcv in [0, 1 << 30] {
                let state = GuestState {
                    fpcr,
                    nzcv,
                    fpsr: 0x0800_009f,
                    x: core::array::from_fn(|i| (i as u64).wrapping_mul(0xdead_beef)),
                    v: core::array::from_fn(|i| {
                        [0x3c00_8000_0001_7c01 ^ i as u64, 0x4000_7e00_0000_bc00]
                    }),
                    ..Default::default()
                };
                let mut expected = state.clone();
                let outcome = crate::floating::complete(&mut expected, &operation);
                let mut actual = state;
                assert_eq!(
                    sampler.complete_selected(&mut actual, 0x1234, &operation, 0x1000, 17),
                    outcome,
                    "{operation:?}"
                );
                assert_eq!(actual, expected, "{operation:?}, fpcr={fpcr:x}");
            }
        }
    }
    let json = serde_json::to_value(sampler.snapshot()).unwrap();
    assert!(json["typed"]["fresh_exceptions"].is_null());
    assert!(json["typed"]["observed_guard_branch"].is_null());
    assert!(
        json["typed"]["sites"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row[0][0] == 0x1000)
    );
    assert!(
        json["typed"]["witnesses"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["retired_before"] == 17)
    );
}

#[test]
fn row_cap_preserves_existing_keys_and_all_sample_totals() {
    let operation = FloatingPointOperation::decode(0x1e20_2820)
        .unwrap()
        .unwrap();
    let mut sampler = Sampler::new(7);
    for word in 0..ROW_LIMIT as u32 + 17 {
        sampler
            .complete(&mut GuestState::default(), word, &operation)
            .unwrap();
    }
    sampler
        .complete(&mut GuestState::default(), 0, &operation)
        .unwrap();
    let report = sampler.snapshot();
    assert_eq!(report.rows.len(), ROW_LIMIT);
    assert_eq!(report.detail_dropped, 17);
    assert_eq!(report.samples, ROW_LIMIT as u64 + 18);
    assert_eq!(
        report.family_samples[Family::Binary as usize],
        report.samples
    );
    assert_eq!(report.rows[0].samples, 2);
}

#[test]
fn preset_sticky_bits_remain_distinct_and_existing_row_saturation_is_reported() {
    let word = 0x1e20_2820;
    let operation = FloatingPointOperation::decode(word).unwrap().unwrap();
    let mut sampler = Sampler::new(3);
    for fpsr in [0, 1 << 4] {
        let mut state = GuestState {
            fpsr,
            ..Default::default()
        };
        sampler.complete(&mut state, word, &operation).unwrap();
    }
    assert_eq!(sampler.rows.len(), 2);
    let key = *sampler.rows.keys().next().unwrap();
    assert_eq!(key.fpsr_before, 0);
    assert_eq!(key.fpsr_after, 0);
    *sampler.rows.get_mut(&key).unwrap() = u64::MAX;
    sampler.samples = u64::MAX;
    sampler.families[Family::Binary as usize] = u64::MAX;
    sampler
        .complete(&mut GuestState::default(), word, &operation)
        .unwrap();
    let report = sampler.snapshot();
    assert!(report.counter_saturated);
    assert_eq!(report.samples, u64::MAX);
    assert_eq!(report.rows[0].samples, u64::MAX);
}
