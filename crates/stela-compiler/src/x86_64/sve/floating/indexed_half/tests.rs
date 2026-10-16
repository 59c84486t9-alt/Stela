use super::*;
use crate::aarch64::sve::floating::arithmetic;
use alloc::vec::Vec;

const INDEXED_FCMLA_HALF: u32 = 0x64a21020;
const INDEXED_FMLA_HALF: u32 = 0x64220020;
const INDEXED_FMLS_HALF: u32 = 0x64220420;
const INDEXED_FMUL_HALF: u32 = 0x64222020;

#[test]
fn measured_selector_keeps_slow_tied_and_unmeasured_choices_on_baseline() {
    for word in [
        INDEXED_FCMLA_HALF,
        INDEXED_FMLA_HALF,
        INDEXED_FMLS_HALF,
        INDEXED_FMUL_HALF,
    ] {
        let operand = arithmetic::decode_numerical(word).unwrap().unwrap();
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for target in [
                TargetCpu::Baseline,
                TargetCpu::Fma,
                TargetCpu::F16c,
                TargetCpu::Sse41.with_f16c().with_fma(),
            ] {
                let checked = target.supports(TargetCpu::F16c)
                    && (bytes == 64
                        || bytes == 16 && matches!(word, INDEXED_FMLA_HALF | INDEXED_FMLS_HALF));
                let recipe = selected_recipe(operand, length, target);
                assert_eq!(matches!(recipe, Recipe::CheckedWidening), checked);
                let mut selected = Vec::new();
                let mut explicit = Vec::new();
                let features = NumericalFeatures::new(false, true, true);
                let pc = GuestAddress(0x123456789abcdef0);
                assert!(emit(&mut selected, operand, length, features, pc, target).unwrap());
                assert!(
                    emit_candidate(
                        &mut explicit,
                        operand,
                        length,
                        features,
                        pc,
                        target,
                        if checked {
                            Recipe::CheckedWidening
                        } else {
                            Recipe::Baseline
                        }
                    )
                    .unwrap()
                );
                assert_eq!(selected, explicit);
            }
        }
    }
}
