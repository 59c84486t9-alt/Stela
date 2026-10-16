use super::*;
use alloc::format;

const TIERS: [(TargetCpu, &str, &str); 4] = [
    (TargetCpu::Baseline, "baseline", "x86_64-baseline"),
    (TargetCpu::Ssse3, "ssse3", "x86_64-baseline+ssse3"),
    (TargetCpu::Sse41, "sse4.1", "x86_64-baseline+ssse3+sse4.1"),
    (
        TargetCpu::Sse42,
        "sse4.2",
        "x86_64-baseline+ssse3+sse4.1+sse4.2",
    ),
];
const FEATURES: [TargetCpu; 11] = [
    TargetCpu::Pclmulqdq,
    TargetCpu::Fma,
    TargetCpu::F16c,
    TargetCpu::Popcnt,
    TargetCpu::Bmi1,
    TargetCpu::Aes,
    TargetCpu::Sha,
    TargetCpu::AtomicLoad16,
    TargetCpu::Cx8,
    TargetCpu::Cx16,
    TargetCpu::Avx2,
];

fn profiles() -> impl Iterator<Item = TargetCpu> {
    TIERS.into_iter().flat_map(|(tier, _, _)| {
        (0..2048).map(move |bits| TargetCpu {
            pclmulqdq: bits & 1 != 0,
            fma: bits & 2 != 0,
            f16c: bits & 4 != 0,
            popcnt: bits & 8 != 0,
            bmi1: bits & 16 != 0,
            aes: bits & 32 != 0,
            sha: bits & 64 != 0,
            atomic_load16: bits & 128 != 0,
            cx8: bits & 256 != 0,
            cx16: bits & 512 != 0,
            avx2: bits & 1024 != 0,
            ..tier
        })
    })
}

#[test]
fn old_canonical_ids_and_aliases_keep_exact_bytes() {
    for (tier, alias, canonical) in TIERS {
        for (suffix, target) in [
            ("", tier),
            ("+pclmulqdq", tier.with_pclmulqdq()),
            ("+fma", tier.with_fma()),
            ("+pclmulqdq+fma", tier.with_pclmulqdq().with_fma()),
            ("+f16c", tier.with_f16c()),
            ("+pclmulqdq+f16c", tier.with_pclmulqdq().with_f16c()),
            ("+fma+f16c", tier.with_fma().with_f16c()),
            (
                "+pclmulqdq+fma+f16c",
                tier.with_pclmulqdq().with_fma().with_f16c(),
            ),
        ] {
            assert_eq!(target.id(), format!("{canonical}{suffix}"));
            assert_eq!(format!("{alias}{suffix}").parse::<TargetCpu>(), Ok(target));
        }
    }
}

#[test]
fn every_profile_has_one_canonical_identity_and_alias() {
    let mut ids = alloc::collections::BTreeSet::new();
    for target in profiles() {
        let id = target.id();
        assert!(ids.insert(id.clone()));
        assert_eq!(id.parse::<TargetCpu>(), Ok(target));
        let (_, alias, canonical) = TIERS
            .into_iter()
            .find(|(tier, _, _)| tier.tier == target.tier)
            .unwrap();
        let suffix = id.strip_prefix(canonical).unwrap();
        assert_eq!(format!("{alias}{suffix}").parse::<TargetCpu>(), Ok(target));
    }
    assert_eq!(ids.len(), 8192);
    assert_eq!(
        TargetCpu::Sse42
            .with_sha()
            .with_aes()
            .with_bmi1()
            .with_popcnt()
            .with_f16c()
            .with_fma()
            .with_pclmulqdq()
            .id(),
        "x86_64-baseline+ssse3+sse4.1+sse4.2+pclmulqdq+fma+f16c+popcnt+bmi1+aes+sha"
    );
}

#[test]
fn invalid_duplicate_and_reordered_suffixes_are_rejected() {
    for invalid in [
        "",
        "native",
        "fma",
        "f16c",
        "popcnt",
        "bmi1",
        "aes",
        "sha",
        "avx",
        "baseline+",
        "baseline+avx+fma",
        "baseline+avx+f16c",
        "baseline+avx2+cx16",
        "x86_64-baseline+sse4.2+fma",
        "baseline+fma+unknown",
        "baseline+f16c+fma",
        "baseline+sha+aes",
        "baseline+aes+bmi1",
        "baseline+bmi1+popcnt",
        "baseline+popcnt+f16c",
        "baseline+fma+pclmulqdq",
        "baseline+sha+ssse3",
        "baseline+POPCNT",
        "baseline+cx16+atomic-load16",
        "baseline+cx16+sha",
        "baseline+cx16+cx8",
        "baseline+cx8+atomic-load16",
    ] {
        assert!(invalid.parse::<TargetCpu>().is_err(), "{invalid}");
    }
    for suffix in [
        "pclmulqdq",
        "fma",
        "f16c",
        "popcnt",
        "bmi1",
        "aes",
        "sha",
        "atomic-load16",
        "cx16",
        "cx8",
        "avx2",
    ] {
        for tier in ["baseline", "x86_64-baseline+ssse3+sse4.1+sse4.2"] {
            let duplicate = format!("{tier}+{suffix}+{suffix}");
            assert!(duplicate.parse::<TargetCpu>().is_err(), "{duplicate}");
        }
    }
}

#[test]
fn every_independent_feature_requires_full_containment() {
    for host in profiles() {
        for (required, present) in FEATURES.into_iter().zip([
            host.pclmulqdq,
            host.fma,
            host.f16c,
            host.popcnt,
            host.bmi1,
            host.aes,
            host.sha,
            host.atomic_load16,
            host.cx8,
            host.cx16,
            host.avx2,
        ]) {
            assert_eq!(host.supports(required), present);
            assert_eq!(host >= required, present);
        }
        for (required, _, _) in TIERS {
            assert_eq!(host.supports(required), host.tier >= required.tier);
        }
        assert!(host.supports(host));
        assert!(host.supports(TargetCpu::Baseline));
    }
    for feature in FEATURES {
        assert!(!TargetCpu::Sse42.supports(feature));
        assert_eq!(TargetCpu::Sse42.partial_cmp(&feature), None);
        for other in FEATURES {
            assert_eq!(feature.supports(other), feature == other);
            assert_eq!(
                feature.partial_cmp(&other),
                if feature == other {
                    Some(core::cmp::Ordering::Equal)
                } else {
                    None
                }
            );
        }
    }
    let combined = TargetCpu::Ssse3.with_popcnt().with_aes();
    assert!(combined.supports(TargetCpu::Baseline.with_popcnt().with_aes()));
    assert!(!combined.supports(TargetCpu::Ssse3.with_popcnt().with_sha()));
    assert!(!combined.supports(TargetCpu::Sse41.with_popcnt().with_aes()));
    assert_eq!(
        combined.partial_cmp(&TargetCpu::Popcnt),
        Some(core::cmp::Ordering::Greater)
    );
    assert_eq!(
        TargetCpu::Aes.partial_cmp(&combined),
        Some(core::cmp::Ordering::Less)
    );
}

#[test]
fn tier_and_vex_detection_keep_each_prerequisite() {
    for bits in 0..128 {
        let ssse3 = bits & 1 != 0;
        let sse41 = bits & 2 != 0;
        let sse42 = bits & 4 != 0;
        let pclmulqdq = bits & 8 != 0;
        let avx = bits & 16 != 0;
        let fma = bits & 32 != 0;
        let f16c = bits & 64 != 0;
        let original = TargetCpu::for_features(ssse3, sse41, sse42, pclmulqdq);
        assert!(!original.supports(TargetCpu::Fma));
        assert!(!original.supports(TargetCpu::F16c));
        let target =
            TargetCpu::for_features_with_vex(ssse3, sse41, sse42, pclmulqdq, avx, fma, f16c);
        assert_eq!(target >= TargetCpu::Ssse3, ssse3);
        assert_eq!(target >= TargetCpu::Sse41, ssse3 && sse41);
        assert_eq!(target >= TargetCpu::Sse42, ssse3 && sse41 && sse42);
        assert_eq!(target.supports(TargetCpu::Pclmulqdq), pclmulqdq);
        assert_eq!(target.supports(TargetCpu::Fma), avx && fma);
        assert_eq!(target.supports(TargetCpu::F16c), avx && f16c);
        for independent in [
            TargetCpu::Popcnt,
            TargetCpu::Bmi1,
            TargetCpu::Aes,
            TargetCpu::Sha,
        ] {
            assert!(!target.supports(independent));
        }
    }
}

#[test]
fn native_detection_reads_independent_bits_without_tier_gating() {
    let target = TargetCpu::detect();
    #[cfg(target_arch = "x86_64")]
    {
        for (required, detected) in [
            (
                TargetCpu::Pclmulqdq,
                std::is_x86_feature_detected!("pclmulqdq"),
            ),
            (
                TargetCpu::Fma,
                std::is_x86_feature_detected!("avx") && std::is_x86_feature_detected!("fma"),
            ),
            (
                TargetCpu::F16c,
                std::is_x86_feature_detected!("avx") && std::is_x86_feature_detected!("f16c"),
            ),
            (TargetCpu::Popcnt, std::is_x86_feature_detected!("popcnt")),
            (TargetCpu::Bmi1, std::is_x86_feature_detected!("bmi1")),
            (TargetCpu::Aes, std::is_x86_feature_detected!("aes")),
            (TargetCpu::Sha, std::is_x86_feature_detected!("sha")),
            (
                TargetCpu::Avx2,
                std::is_x86_feature_detected!("avx") && std::is_x86_feature_detected!("avx2"),
            ),
            (
                TargetCpu::AtomicLoad16,
                core::arch::x86_64::__cpuid(CPUID_BASIC_FEATURES).ecx & CPUID_AVX_HARDWARE != 0,
            ),
            (
                TargetCpu::Cx16,
                core::arch::x86_64::__cpuid(CPUID_BASIC_FEATURES).ecx & CPUID_CX16 != 0,
            ),
            (
                TargetCpu::Cx8,
                core::arch::x86_64::__cpuid(CPUID_BASIC_FEATURES).edx & CPUID_CX8 != 0,
            ),
        ] {
            assert_eq!(target.supports(required), detected);
        }
        assert!(target.supported());
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        assert_eq!(target, TargetCpu::Baseline);
        assert!(!target.supported());
    }
}
