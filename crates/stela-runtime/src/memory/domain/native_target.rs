//! A conservative limit, never CPU or memory execution authority. Keep the
//! current legacy native lane's known capabilities only; wider state and DIT
//! cannot be enabled by a caller-provided declaration.
use stela_compiler::TargetCpu;

pub(in crate::memory) fn restrict(actual: TargetCpu, limit: TargetCpu) -> TargetCpu {
    let mut target = [TargetCpu::Sse42, TargetCpu::Sse41, TargetCpu::Ssse3]
        .into_iter()
        .find(|tier| actual.supports(*tier) && limit.supports(*tier))
        .unwrap_or(TargetCpu::Baseline);
    for (capability, with) in [
        (
            TargetCpu::Pclmulqdq,
            TargetCpu::with_pclmulqdq as fn(_) -> _,
        ),
        (TargetCpu::Popcnt, TargetCpu::with_popcnt),
        (TargetCpu::Aes, TargetCpu::with_aes),
        (TargetCpu::Sha, TargetCpu::with_sha),
        (TargetCpu::Cx8, TargetCpu::with_cx8),
        (TargetCpu::Cx16, TargetCpu::with_cx16),
        (TargetCpu::AtomicLoad16, TargetCpu::with_atomic_load16),
    ] {
        if actual.supports(capability) && limit.supports(capability) {
            target = with(target);
        }
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neither_limit_nor_current_target_can_promote_the_other() {
        for left in [
            TargetCpu::Baseline,
            TargetCpu::Ssse3,
            TargetCpu::Sse41,
            TargetCpu::Sse42,
            TargetCpu::Sse42Complete,
            TargetCpu::Avx512Complete,
        ] {
            for right in [
                TargetCpu::Baseline,
                TargetCpu::Ssse3,
                TargetCpu::Sse41,
                TargetCpu::Sse42,
                TargetCpu::Aes,
                TargetCpu::Sha,
                TargetCpu::AtomicLoad16,
                TargetCpu::Sse42Complete,
            ] {
                let common = restrict(left, right);
                assert!(left.supports(common));
                assert!(right.supports(common));
                assert_eq!(common, restrict(right, left));
                assert_eq!(restrict(common, left), common);
            }
        }
    }

    #[test]
    fn independent_capability_loss_does_not_remove_other_admitted_recipes() {
        let actual = TargetCpu::Sse42.with_aes().with_sha().with_atomic_load16();
        let worker = TargetCpu::Sse41.with_aes().with_cx16();
        assert_eq!(restrict(actual, worker), TargetCpu::Sse41.with_aes());
        assert_eq!(
            restrict(TargetCpu::Baseline, TargetCpu::Avx512Complete),
            TargetCpu::Baseline
        );
    }

    #[test]
    fn caller_modes_and_extended_state_are_never_promoted_by_a_limit() {
        let rich = TargetCpu::Avx512Complete
            .with_doit()
            .with_line_atomic()
            .with_data_independent_timing();
        let common = restrict(rich, rich);
        assert!(!common.data_independent_timing());
        for excluded in [
            TargetCpu::Fma,
            TargetCpu::F16c,
            TargetCpu::Avx2,
            TargetCpu::Avx512f,
            TargetCpu::Bmi1,
            TargetCpu::Doit,
            TargetCpu::LineAtomic,
        ] {
            assert!(!common.supports(excluded));
        }
    }
}
