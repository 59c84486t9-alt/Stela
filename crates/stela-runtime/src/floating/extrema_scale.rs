//! Transactional AdvSIMD FAMIN/MAX and FSCALE completion.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{UnsupportedControl, absolute_minmax, exponent},
        simd::extrema_scale::{Kind, Operand},
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    // Every source is snapshotted before staging, including Vd=Vn=Vm and V31.
    let left = state.v[usize::from(operand.left)];
    let right = state.v[usize::from(operand.right)];
    let mut result = [0; VECTOR_LIMBS];
    let mut exceptions = 0;
    for lane in 0..operand.shape.lane_count(operand.format) {
        let left = read_lane(&left, operand.format.bits(), lane);
        let right = read_lane(&right, operand.format.bits(), lane);
        let outcome = match operand.kind {
            Kind::Absolute(operation) => {
                absolute_minmax::evaluate(operand.format, operation, state.fpcr, left, right)
            }
            Kind::Scale => exponent::scale(operand.format, state.fpcr, left, right),
        }?;
        write_lane(&mut result, operand.format.bits(), lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        floating::{EXCEPTIONS, FPCR_EXCEPTION_ENABLE_SHIFT, FPSR_QC, INVALID, OVERFLOW},
        simd::extrema_scale,
    };

    #[test]
    fn scale_alias_signed_integer_and_upper_clear_preserve_other_state() {
        for (destination, left, right) in [(0_u8, 1_u8, 2_u8), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
            let mut state = GuestState::default();
            state.x[0] = 0xfeed;
            state.nzcv = 0xa000_0000;
            state.v[usize::from(left)] = [0x4000_0000_3f80_0000, u64::MAX];
            state.v[usize::from(right)] = [0xffff_ffff_0000_0001, u64::MAX];
            state.fpsr = FPSR_QC | INVALID;
            let operand = extrema_scale::decode(
                0x2ea0_fc00
                    | u32::from(destination)
                    | (u32::from(left) << 5)
                    | (u32::from(right) << 16),
            )
            .unwrap()
            .unwrap();
            let before = state.clone();
            let mut expected = before.clone();
            expected.v[usize::from(destination)] = if left == right {
                // Raw1 scaled by1 gives2; the second lane is an already quiet
                // negative NaN whose payload/sign survive the integer scale.
                [0xffff_ffff_0000_0002, 0]
            } else {
                [0x3f80_0000_4000_0000, 0]
            };
            complete(&mut state, &operand).unwrap();
            assert_eq!(state, expected);
        }
    }

    #[test]
    fn absolute_extrema_ignore_flush_keep_signed_nan_and_snapshot_aliases() {
        use stela_compiler::aarch64::floating::{FPCR_AH, FPCR_FIZ, FPCR_FZ, FPCR_FZ16};
        let mut state = GuestState {
            fpcr: FPCR_AH | FPCR_FIZ | FPCR_FZ | FPCR_FZ16,
            fpsr: FPSR_QC,
            ..GuestState::default()
        };
        state.v[1] = [0x8000_0001_8000_0000, 0xff80_0003_bf80_0000];
        state.v[2] = [0x0000_0002_0000_0000, 0x3f80_0000_4000_0000];
        let operand = extrema_scale::decode(0x6ea0_dc22 | (2 << 16))
            .unwrap()
            .unwrap();
        let mut expected = state.clone();
        expected.v[2] = [0x0000_0001_0000_0000, 0xffc0_0003_3f80_0000];
        expected.fpsr |= INVALID;
        complete(&mut state, &operand).unwrap();
        assert_eq!(state, expected);
    }

    #[test]
    fn enabled_exception_refusal_preserves_complete_state_for_all_six_forms() {
        for word in [
            0x0ea0_dc00,
            0x2ea0_dc00,
            0x2ea0_fc00,
            0x0ec0_1c00,
            0x2ec0_1c00,
            0x2ec0_3c00,
        ] {
            for enable in [INVALID, OVERFLOW, EXCEPTIONS] {
                let mut state = GuestState {
                    fpcr: enable << FPCR_EXCEPTION_ENABLE_SHIFT,
                    fpsr: FPSR_QC,
                    ..GuestState::default()
                };
                state.v[0] = [u64::MAX; VECTOR_LIMBS];
                let before = state.clone();
                let operand = extrema_scale::decode(word).unwrap().unwrap();
                assert!(complete(&mut state, &operand).is_err());
                assert_eq!(state, before);
            }
        }
    }
}
