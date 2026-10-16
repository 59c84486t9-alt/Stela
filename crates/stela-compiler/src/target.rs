//! Host CPU feature requirements, detection and generated-code target identities.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
#[cfg(all(any(feature = "std", test), target_arch = "x86_64"))]
const CPUID_BASIC_FEATURES: u32 = 1;
#[cfg(all(any(feature = "std", test), target_arch = "x86_64"))]
const CPUID_AVX_HARDWARE: u32 = 1 << 28;
#[cfg(all(any(feature = "std", test), target_arch = "x86_64"))]
const CPUID_CX16: u32 = 1 << 13;
#[cfg(all(any(feature = "std", test), target_arch = "x86_64"))]
const CPUID_CX8: u32 = 1 << 8;

/// Explicit host requirements bind generated code and persistent cache identity.
/// SSE tiers are nested; every other capability is independent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TargetCpu {
    tier: SseTier,
    pclmulqdq: bool,
    fma: bool,
    f16c: bool,
    popcnt: bool,
    bmi1: bool,
    aes: bool,
    sha: bool,
    atomic_load16: bool,
    cx8: bool,
    cx16: bool,
    avx2: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SseTier {
    #[default]
    Baseline,
    Ssse3,
    Sse41,
    Sse42,
}

// Keep the published tier names and their cache identities.
#[allow(non_upper_case_globals)]
impl TargetCpu {
    pub const Baseline: Self = Self {
        tier: SseTier::Baseline,
        pclmulqdq: false,
        fma: false,
        f16c: false,
        popcnt: false,
        bmi1: false,
        aes: false,
        sha: false,
        atomic_load16: false,
        cx8: false,
        cx16: false,
        avx2: false,
    };
    pub const Ssse3: Self = Self {
        tier: SseTier::Ssse3,
        ..Self::Baseline
    };
    pub const Sse41: Self = Self {
        tier: SseTier::Sse41,
        ..Self::Baseline
    };
    pub const Sse42: Self = Self {
        tier: SseTier::Sse42,
        ..Self::Baseline
    };
    /// Minimum requirements for legacy XMM PCLMULQDQ, independent of SSE tiers.
    pub const Pclmulqdq: Self = Self::Baseline.with_pclmulqdq();
    /// Minimum requirements for VEX FMA3, including OS-enabled AVX register state.
    pub const Fma: Self = Self::Baseline.with_fma();
    /// Minimum requirements for F16C, including OS-enabled AVX register state.
    pub const F16c: Self = Self::Baseline.with_f16c();
    pub const Popcnt: Self = Self::Baseline.with_popcnt();
    pub const Bmi1: Self = Self::Baseline.with_bmi1();
    /// Minimum requirements for legacy XMM AES instructions, independent of SSE tiers.
    pub const Aes: Self = Self::Baseline.with_aes();
    /// Minimum requirements for legacy XMM SHA instructions, independent of SSE tiers.
    pub const Sha: Self = Self::Baseline.with_sha();
    /// Aligned16 atomic loads, enumerated by AVX hardware support. Lowering uses
    /// legacy SSE2 instructions, independently of OS-enabled AVX register state.
    pub const AtomicLoad16: Self = Self::Baseline.with_atomic_load16();
    /// CMPXCHG8B, independently enumerated for the W-pair optimized recipe.
    pub const Cx8: Self = Self::Baseline.with_cx8();
    /// CMPXCHG16B, independent of aligned16 load atomicity and AVX state.
    pub const Cx16: Self = Self::Baseline.with_cx16();
    /// AVX2 integer recipes, including OS-enabled XMM/YMM register state.
    pub const Avx2: Self = Self::Baseline.with_avx2();

    pub const fn with_pclmulqdq(self) -> Self {
        Self {
            pclmulqdq: true,
            ..self
        }
    }
    pub const fn with_fma(self) -> Self {
        Self { fma: true, ..self }
    }
    pub const fn with_f16c(self) -> Self {
        Self { f16c: true, ..self }
    }
    pub const fn with_popcnt(self) -> Self {
        Self {
            popcnt: true,
            ..self
        }
    }
    pub const fn with_bmi1(self) -> Self {
        Self { bmi1: true, ..self }
    }
    pub const fn with_aes(self) -> Self {
        Self { aes: true, ..self }
    }
    pub const fn with_sha(self) -> Self {
        Self { sha: true, ..self }
    }
    pub const fn with_atomic_load16(self) -> Self {
        Self {
            atomic_load16: true,
            ..self
        }
    }
    pub const fn with_cx8(self) -> Self {
        Self { cx8: true, ..self }
    }
    pub const fn with_cx16(self) -> Self {
        Self { cx16: true, ..self }
    }
    pub const fn with_avx2(self) -> Self {
        Self { avx2: true, ..self }
    }
    /// True only when every required feature is present in this target.
    pub fn supports(self, required: Self) -> bool {
        self.tier >= required.tier
            && (!required.pclmulqdq || self.pclmulqdq)
            && (!required.fma || self.fma)
            && (!required.f16c || self.f16c)
            && (!required.popcnt || self.popcnt)
            && (!required.bmi1 || self.bmi1)
            && (!required.aes || self.aes)
            && (!required.sha || self.sha)
            && (!required.atomic_load16 || self.atomic_load16)
            && (!required.cx16 || self.cx16)
            && (!required.cx8 || self.cx8)
            && (!required.avx2 || self.avx2)
    }
    /// Detect the host's usable CPU features. Freestanding callers supply a
    /// target explicitly.
    #[cfg(any(feature = "std", test))]
    pub fn detect() -> Self {
        static DETECTED: std::sync::OnceLock<TargetCpu> = std::sync::OnceLock::new();
        *DETECTED.get_or_init(Self::probe)
    }

    #[cfg(any(feature = "std", test))]
    fn probe() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let basic = core::arch::x86_64::__cpuid(CPUID_BASIC_FEATURES);
            Self {
                popcnt: std::is_x86_feature_detected!("popcnt"),
                bmi1: std::is_x86_feature_detected!("bmi1"),
                aes: std::is_x86_feature_detected!("aes"),
                sha: std::is_x86_feature_detected!("sha"),
                cx16: basic.ecx & CPUID_CX16 != 0,
                cx8: basic.edx & CPUID_CX8 != 0,
                // Hardware atomicity, rather than permission to execute VEX.
                atomic_load16: basic.ecx & CPUID_AVX_HARDWARE != 0,
                // Rust's detector checks CPUID and XSAVE/OSXSAVE/XCR0 state.
                avx2: std::is_x86_feature_detected!("avx") && std::is_x86_feature_detected!("avx2"),
                ..Self::for_features_with_vex(
                    std::is_x86_feature_detected!("ssse3"),
                    std::is_x86_feature_detected!("sse4.1"),
                    std::is_x86_feature_detected!("sse4.2"),
                    std::is_x86_feature_detected!("pclmulqdq"),
                    std::is_x86_feature_detected!("avx"),
                    std::is_x86_feature_detected!("fma"),
                    std::is_x86_feature_detected!("f16c"),
                )
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self::Baseline
        }
    }
    #[cfg(any(all(feature = "std", target_arch = "x86_64"), test))]
    fn for_features(ssse3: bool, sse41: bool, sse42: bool, pclmulqdq: bool) -> Self {
        let tier = match (ssse3, sse41, sse42) {
            (false, _, _) => SseTier::Baseline,
            (true, false, _) => SseTier::Ssse3,
            (true, true, false) => SseTier::Sse41,
            (true, true, true) => SseTier::Sse42,
        };
        Self {
            tier,
            pclmulqdq,
            ..Self::Baseline
        }
    }
    #[cfg(any(all(feature = "std", target_arch = "x86_64"), test))]
    fn for_features_with_vex(
        ssse3: bool,
        sse41: bool,
        sse42: bool,
        pclmulqdq: bool,
        avx: bool,
        fma: bool,
        f16c: bool,
    ) -> Self {
        // Rust's AVX detector checks XSAVE, OSXSAVE and XCR0's SSE/AVX state.
        // Gate each VEX feature independently on that usable register state.
        Self {
            fma: avx && fma,
            f16c: avx && f16c,
            ..Self::for_features(ssse3, sse41, sse42, pclmulqdq)
        }
    }
    /// Canonical metadata identity; serialization is outside emitted execution.
    pub fn id(self) -> String {
        let mut id = match self.tier {
            SseTier::Baseline => "x86_64-baseline",
            SseTier::Ssse3 => "x86_64-baseline+ssse3",
            SseTier::Sse41 => "x86_64-baseline+ssse3+sse4.1",
            SseTier::Sse42 => "x86_64-baseline+ssse3+sse4.1+sse4.2",
        }
        .to_owned();
        for (enabled, suffix) in [
            (self.pclmulqdq, "+pclmulqdq"),
            (self.fma, "+fma"),
            (self.f16c, "+f16c"),
            (self.popcnt, "+popcnt"),
            (self.bmi1, "+bmi1"),
            (self.aes, "+aes"),
            (self.sha, "+sha"),
            (self.atomic_load16, "+atomic-load16"),
            (self.cx8, "+cx8"),
            (self.cx16, "+cx16"),
            (self.avx2, "+avx2"),
        ] {
            if enabled {
                id.push_str(suffix);
            }
        }
        id
    }
    /// Check this target against the hosted process's usable capabilities.
    #[cfg(any(feature = "std", test))]
    pub fn supported(self) -> bool {
        cfg!(target_arch = "x86_64") && Self::detect().supports(self)
    }
}

// Ordering means feature containment, not an arbitrary rank.
impl PartialOrd for TargetCpu {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        match (self.supports(*other), other.supports(*self)) {
            (true, true) => Some(core::cmp::Ordering::Equal),
            (true, false) => Some(core::cmp::Ordering::Greater),
            (false, true) => Some(core::cmp::Ordering::Less),
            (false, false) => None,
        }
    }
}

impl core::str::FromStr for TargetCpu {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut target = Self::Baseline;
        let mut tier_name = value;
        // Strip each optional suffix once, in reverse order. A duplicate,
        // unknown or out-of-order suffix is left behind and fails parsing.
        for (suffix, enabled) in [
            ("+avx2", &mut target.avx2),
            ("+cx16", &mut target.cx16),
            ("+cx8", &mut target.cx8),
            ("+atomic-load16", &mut target.atomic_load16),
            ("+sha", &mut target.sha),
            ("+aes", &mut target.aes),
            ("+bmi1", &mut target.bmi1),
            ("+popcnt", &mut target.popcnt),
            ("+f16c", &mut target.f16c),
            ("+fma", &mut target.fma),
            ("+pclmulqdq", &mut target.pclmulqdq),
        ] {
            if let Some(prefix) = tier_name.strip_suffix(suffix) {
                tier_name = prefix;
                *enabled = true;
            }
        }
        target.tier = match tier_name {
            "baseline" | "x86_64-baseline" => SseTier::Baseline,
            "ssse3" | "x86_64-baseline+ssse3" => SseTier::Ssse3,
            "sse4.1" | "x86_64-baseline+ssse3+sse4.1" => SseTier::Sse41,
            "sse4.2" | "x86_64-baseline+ssse3+sse4.1+sse4.2" => SseTier::Sse42,
            _ => return Err(format!("unknown x86-64 CPU target {value}")),
        };
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
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
}
