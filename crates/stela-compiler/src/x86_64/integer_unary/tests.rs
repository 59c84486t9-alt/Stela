use super::*;
use alloc::vec::Vec;

fn emitted(kind: Kind, width: Width, source: Register, target: TargetCpu) -> Vec<u8> {
    let mut code = Vec::new();
    emit(
        &mut code,
        &Operand {
            kind,
            width,
            destination: Register::X(0),
            source,
        },
        target,
    );
    code
}

#[test]
fn optional_count_features_are_independent() {
    let baseline = TargetCpu::Baseline;
    let source = Register::X(1);
    for width in [Width::W32, Width::X64] {
        for (kind, required, unrelated) in [
            (Kind::PopulationCount, TargetCpu::Popcnt, TargetCpu::Bmi1),
            (Kind::TrailingZeros, TargetCpu::Bmi1, TargetCpu::Popcnt),
        ] {
            let ordinary = emitted(kind, width, source, baseline);
            let checked = emitted(kind, width, source, required);
            assert_eq!(emitted(kind, width, source, unrelated), ordinary);
            assert_eq!(
                emitted(kind, width, source, baseline.with_popcnt().with_bmi1()),
                checked
            );
            assert!(checked.len() < ordinary.len());
        }
    }
}

#[test]
fn known_zero_source_uses_the_same_short_path_for_every_target() {
    for kind in [Kind::Absolute, Kind::PopulationCount, Kind::TrailingZeros] {
        for width in [Width::W32, Width::X64] {
            let constant = emitted(kind, width, Register::Zero, TargetCpu::Baseline);
            assert!(
                constant.len() < emitted(kind, width, Register::X(1), TargetCpu::Baseline).len()
            );
            for target in [
                TargetCpu::Popcnt,
                TargetCpu::Bmi1,
                TargetCpu::Baseline.with_popcnt().with_bmi1(),
            ] {
                assert_eq!(emitted(kind, width, Register::Zero, target), constant);
            }
        }
    }
}

#[test]
fn discard_is_a_nonempty_no_effect_interval_for_every_target() {
    for kind in [Kind::Absolute, Kind::PopulationCount, Kind::TrailingZeros] {
        for width in [Width::W32, Width::X64] {
            for target in [
                TargetCpu::Baseline,
                TargetCpu::Baseline.with_popcnt().with_bmi1(),
            ] {
                let mut code = Vec::new();
                emit(
                    &mut code,
                    &Operand {
                        kind,
                        width,
                        destination: Register::Zero,
                        source: Register::X(1),
                    },
                    target,
                );
                assert_eq!(code, [NOP]);
            }
        }
    }
}
