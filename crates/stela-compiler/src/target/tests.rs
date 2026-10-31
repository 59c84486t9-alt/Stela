use super::*;
use alloc::format;
use alloc::vec::Vec;

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

/// The host features, one target each.
fn host_features() -> impl Iterator<Item = (Feature, TargetCpu)> {
    FEATURES
        .iter()
        .filter(|(feature, _, _)| MODES & 1 << *feature as u32 == 0)
        .map(|(feature, _, _)| (*feature, TargetCpu::Baseline.with_feature(*feature)))
}

/// Every tier with no feature, each single feature, each pair, and a
/// fixed pseudo-random sample of larger feature sets.
fn profiles() -> impl Iterator<Item = TargetCpu> {
    let count = FEATURES.len() as u32;
    let all = (1u64 << count) - 1;
    let mut sets = Vec::from([0, all]);
    for first in 0..count {
        for second in first..count {
            sets.push(1u64 << first | 1u64 << second);
        }
    }
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..512 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        sets.push(state & all);
    }
    TIERS.into_iter().flat_map(move |(tier, _, _)| {
        sets.clone()
            .into_iter()
            .map(move |features| TargetCpu { features, ..tier })
    })
}

#[test]
fn canonical_ids_and_aliases_keep_their_spelling() {
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
    let every = FEATURES
        .iter()
        .fold(TargetCpu::Sse42, |target, (feature, _, _)| {
            target.with_feature(*feature)
        });
    assert_eq!(
        every.id(),
        "x86_64-baseline+ssse3+sse4.1+sse4.2+pclmulqdq+fma+f16c+popcnt+bmi1+aes+sha\
         +atomic-load16+cx8+cx16+avx2+avx512f+lzcnt+bmi2+fast-pdep+movbe+gfni\
         +avx512vl+avx512bw+avx512cd+avx512dq+avx512vpopcntdq+avx512bitalg+avx512vbmi+avx512vnni\
         +avxvnni+avxvnniint8+avxvnniint16+avx512bf16+avxneconvert+avx512fp16+avx10.2+vaes+vpclmulqdq+sha512+sm3+sm4\
         +apx+apx-ndd+line-atomic+doit+dit"
    );
}

#[test]
fn every_profile_has_one_canonical_identity_and_alias() {
    let mut ids = alloc::collections::BTreeMap::new();
    for target in profiles() {
        let id = target.id();
        assert_eq!(*ids.entry(id.clone()).or_insert(target), target);
        assert_eq!(id.parse::<TargetCpu>(), Ok(target));
        let (_, alias, canonical) = TIERS
            .into_iter()
            .find(|(tier, _, _)| tier.tier == target.tier)
            .unwrap();
        let suffix = id.strip_prefix(canonical).unwrap();
        assert_eq!(format!("{alias}{suffix}").parse::<TargetCpu>(), Ok(target));
    }
}

#[test]
fn deserialization_parses_the_canonical_identity() {
    use serde::{Deserialize, de::value::StrDeserializer};
    fn parse(id: &str) -> Result<TargetCpu, serde::de::value::Error> {
        TargetCpu::deserialize(StrDeserializer::new(id))
    }
    let target = TargetCpu::X86_64_V3.with_line_atomic();
    assert_eq!(parse(&target.id()), Ok(target));
    assert!(parse("baseline+avx").is_err());
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
        "baseline+avx512f+avx2",
        "baseline+dit+doit",
        "baseline+doit+line-atomic",
        "baseline+line-atomic+avx512f",
        "avx512f",
    ] {
        assert_eq!(
            invalid.parse::<TargetCpu>().unwrap_err(),
            TargetParseError {
                identity: invalid.to_owned()
            }
        );
    }
    for (_, name, _) in FEATURES {
        for tier in ["baseline", "x86_64-baseline+ssse3+sse4.1+sse4.2"] {
            let duplicate = format!("{tier}{name}{name}");
            assert!(duplicate.parse::<TargetCpu>().is_err(), "{duplicate}");
        }
    }
}

#[test]
fn atomic_load16_requires_a_documented_vendor_and_independent_avx_hardware() {
    for vendor in [
        TargetCpu::INTEL_VENDOR,
        TargetCpu::AMD_VENDOR,
        TargetCpu::HYGON_VENDOR,
    ] {
        assert!(!TargetCpu::atomic_load16_guaranteed(vendor, 0));
        // OSXSAVE/XSAVE/CX16 do not grant the independent plain-load fact.
        assert!(!TargetCpu::atomic_load16_guaranteed(
            vendor,
            (1 << 13) | (1 << 26) | (1 << 27)
        ));
        assert!(TargetCpu::atomic_load16_guaranteed(
            vendor,
            CPUID_AVX_HARDWARE
        ));
    }
    for vendor in [
        [0; 3],
        vendor_id(b"  Shanghai  "),
        vendor_id(b"CentaurHauls"),
    ] {
        assert_eq!(Vendor::from_cpuid(vendor), Vendor::Other);
        assert!(!TargetCpu::atomic_load16_guaranteed(vendor, u32::MAX));
    }
}

/// A vendor string in CPUID leaf 0 EBX, EDX, ECX order.
fn vendor_id(name: &[u8; 12]) -> [u32; 3] {
    let word = |at: usize| u32::from_le_bytes(name[at..at + 4].try_into().unwrap());
    [word(0), word(4), word(8)]
}

#[test]
fn hygon_follows_amd_and_only_intel_is_line_atomic() {
    assert_eq!(vendor_id(b"HygonGenuine"), TargetCpu::HYGON_VENDOR);
    assert_eq!(vendor_id(b"AuthenticAMD"), TargetCpu::AMD_VENDOR);
    for (name, vendor) in [
        (b"GenuineIntel", Vendor::Intel),
        (b"AuthenticAMD", Vendor::Amd),
        (b"HygonGenuine", Vendor::Amd),
        (b"  Shanghai  ", Vendor::Other),
        (b"CentaurHauls", Vendor::Other),
    ] {
        assert_eq!(Vendor::from_cpuid(vendor_id(name)), vendor);
        let target = TargetCpu::from_cpuid(&HostCpuid {
            vendor: vendor_id(name),
            ..RICH
        });
        assert_eq!(
            target.supports(TargetCpu::LineAtomic),
            vendor == Vendor::Intel
        );
        assert_eq!(
            target.supports(TargetCpu::AtomicLoad16),
            vendor != Vendor::Other
        );
    }
}

#[test]
fn unqualified_plain_load_does_not_remove_v2_casp_or_cx16() {
    use crate::{GuestAddress, block::BlockProfile};
    let source: alloc::vec::Vec<_> = [0x4822_7c04u32, 0xd65f_03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let baseline = TargetCpu::X86_64_V2;
    assert!(!TargetCpu::atomic_load16_guaranteed([0; 3], u32::MAX));
    assert!(!baseline.supports(TargetCpu::AtomicLoad16));
    assert!(baseline.supports(TargetCpu::Cx16));
    let original = crate::testing::block_for(
        &source,
        GuestAddress(0x1000),
        BlockProfile::ORDINARY,
        baseline,
    )
    .unwrap();
    let optional = crate::testing::block_for(
        &source,
        GuestAddress(0x1000),
        BlockProfile::ORDINARY,
        baseline.with_atomic_load16(),
    )
    .unwrap();
    assert_eq!(original.native.x86_64_code, optional.native.x86_64_code);
    assert_eq!(original.native.source_map, optional.native.source_map);
    assert!(
        original
            .native
            .x86_64_code
            .windows(5)
            .any(|bytes| bytes == [0xf0, 0x49, 0x0f, 0xc7, 0x08])
    );
}

#[test]
fn every_independent_feature_requires_full_containment() {
    for host in profiles() {
        for (feature, required) in host_features() {
            assert_eq!(host.supports(required), host.has(feature));
            assert_eq!(host >= required, host.has(feature));
        }
        // The timing mode is no host requirement, but orders as a
        // feature: equality stays identity.
        let timed = host.with_data_independent_timing();
        assert!(host.supports(timed) && timed.supports(host));
        assert!(timed >= host);
        assert_eq!(host >= timed, host.data_independent_timing());
        for (required, _, _) in TIERS {
            assert_eq!(host.supports(required), host.tier >= required.tier);
        }
        assert!(host.supports(host));
        assert!(host.supports(TargetCpu::Baseline));
    }
    for (_, feature) in host_features() {
        assert!(!TargetCpu::Sse42.supports(feature));
        assert_eq!(TargetCpu::Sse42.partial_cmp(&feature), None);
        for (_, other) in host_features() {
            assert_eq!(feature.supports(other), feature == other);
            assert_eq!(
                feature.partial_cmp(&other),
                (feature == other).then_some(core::cmp::Ordering::Equal)
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
fn dit_code_compiles_for_the_largest_audited_tier_of_a_doit_host() {
    for host in profiles() {
        let expected = TargetCpu::DATA_INDEPENDENT_TIMING_TIERS
            .into_iter()
            .find(|tier| host.supports(*tier))
            .filter(|_| host.doit());
        let target = host.data_independent_timing_target();
        assert_eq!(target.is_some(), expected.is_some(), "{host:?}");
        if let (Some(target), Some(tier)) = (target, expected) {
            assert_eq!(target, tier.with_doit().with_data_independent_timing());
            assert!(host.supports(target));
        }
    }
    // The tiers nest, largest first.
    let [v4, v3, v2] = TargetCpu::DATA_INDEPENDENT_TIMING_TIERS;
    assert!(v4 > v3 && v3 > v2 && v2 > TargetCpu::X86_64_V2);
    assert!(v4 > TargetCpu::X86_64_V4 && v3 > TargetCpu::X86_64_V3);
    assert_eq!(
        v3.with_avx512f()
            .with_doit()
            .data_independent_timing_target(),
        Some(v3.with_doit().with_data_independent_timing())
    );
    assert_eq!(v3.data_independent_timing_target(), None);
}

/// CPUID values of an Intel family 6 host with every feature bit set.
const RICH: HostCpuid = HostCpuid {
    vendor: TargetCpu::INTEL_VENDOR,
    leaf1_eax: 6 << 8,
    leaf1_ecx: u32::MAX,
    leaf1_edx: u32::MAX,
    leaf7_ebx: u32::MAX,
    leaf7_ecx: u32::MAX,
    leaf7_edx: u32::MAX,
    leaf7_1_eax: u32::MAX,
    leaf7_1_edx: u32::MAX,
    leaf24_ebx: u32::MAX,
    leaf29_ebx: u32::MAX,
    extended1_ecx: u32::MAX,
    xcr0: XCR0_AVX_STATE | XCR0_AVX512_STATE | XCR0_APX_STATE,
    avx512_on_demand: false,
};

#[test]
fn a_rich_host_has_every_feature_and_the_psabi_levels() {
    let rich = TargetCpu::from_cpuid(&RICH);
    assert!(rich.supports(TargetCpu::X86_64_V4));
    for (feature, required) in host_features() {
        let declared = matches!(feature, Feature::Doit);
        assert_eq!(rich.supports(required), !declared, "{feature:?}");
    }
    assert!(TargetCpu::X86_64_V4 > TargetCpu::X86_64_V3);
    assert!(TargetCpu::X86_64_V3 > TargetCpu::X86_64_V2);
}

#[test]
fn apx_destinations_require_the_separate_cpuid_bit() {
    let foundation = TargetCpu::from_cpuid(&HostCpuid {
        leaf24_ebx: 0,
        leaf29_ebx: 0,
        ..RICH
    });
    assert!(foundation.supports(TargetCpu::Apx));
    assert!(!foundation.supports(TargetCpu::ApxNdd));
    let full = TargetCpu::from_cpuid(&RICH);
    assert!(full.supports(TargetCpu::Apx.with_apx_ndd()));
    assert!(full.id().contains("+apx+apx-ndd"));
    assert_eq!(full.id().parse::<TargetCpu>().unwrap(), full);
    for missing in [26, 27] {
        let disabled = TargetCpu::from_cpuid(&HostCpuid {
            leaf1_ecx: RICH.leaf1_ecx & !(1 << missing),
            ..RICH
        });
        assert!(!disabled.supports(TargetCpu::Apx));
        assert!(!disabled.supports(TargetCpu::ApxNdd));
    }
    for disabled in [
        HostCpuid {
            leaf7_1_edx: 0,
            ..RICH
        },
        HostCpuid {
            xcr0: RICH.xcr0 & !XCR0_APX_STATE,
            ..RICH
        },
    ] {
        let disabled = TargetCpu::from_cpuid(&disabled);
        assert!(!disabled.supports(TargetCpu::Apx));
        assert!(!disabled.supports(TargetCpu::ApxNdd));
    }
}

#[test]
fn evex_features_need_zmm_state_and_apx_its_own() {
    let no_zmm = TargetCpu::from_cpuid(&HostCpuid {
        xcr0: XCR0_AVX_STATE | XCR0_APX_STATE,
        ..RICH
    });
    for evex in [
        TargetCpu::Avx512vl,
        TargetCpu::Avx512bw,
        TargetCpu::Avx512cd,
        TargetCpu::Avx512dq,
        TargetCpu::Avx512vpopcntdq,
        TargetCpu::Avx512bitalg,
        TargetCpu::Avx512vnni,
        TargetCpu::Avx512bf16,
        TargetCpu::Avx512fp16,
    ] {
        assert!(!no_zmm.supports(evex), "{evex:?}");
    }
    assert!(no_zmm.supports(TargetCpu::AvxVnni.with_vaes().with_vpclmulqdq()));
    let no_apx = HostCpuid {
        xcr0: XCR0_AVX_STATE | XCR0_AVX512_STATE,
        ..RICH
    };
    assert!(!TargetCpu::from_cpuid(&no_apx).supports(TargetCpu::Apx));
}

#[test]
fn pdep_is_slow_on_amd_before_family_19h() {
    for (vendor, family, fast) in [
        (TargetCpu::INTEL_VENDOR, 6, true),
        (TargetCpu::AMD_VENDOR, 0x17, false),
        (TargetCpu::HYGON_VENDOR, 0x18, false),
        (TargetCpu::AMD_VENDOR, 0x19, true),
        (TargetCpu::AMD_VENDOR, 0x1a, true),
    ] {
        // Families from 10H carry the extended family over base 0FH.
        let leaf1_eax = if family > 0xf {
            0xf << 8 | (family - 0xf) << 20
        } else {
            family << 8
        };
        let target = TargetCpu::from_cpuid(&HostCpuid {
            vendor,
            leaf1_eax,
            ..RICH
        });
        assert!(target.supports(TargetCpu::Bmi2));
        assert_eq!(target.supports(TargetCpu::FastPdep), fast, "{family:#x}");
    }
}

#[test]
fn sse_tiers_nest_from_cpuid() {
    for bits in 0..8u32 {
        let (ssse3, sse41, sse42) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
        let leaf1_ecx = u32::from(ssse3) << 9 | u32::from(sse41) << 19 | u32::from(sse42) << 20;
        let target = TargetCpu::from_cpuid(&HostCpuid {
            leaf1_ecx,
            ..HostCpuid::default()
        });
        assert_eq!(target >= TargetCpu::Ssse3, ssse3);
        assert_eq!(target >= TargetCpu::Sse41, ssse3 && sse41);
        assert_eq!(target >= TargetCpu::Sse42, ssse3 && sse41 && sse42);
        assert_eq!(target.features, 0);
    }
}

#[test]
fn vex_features_need_os_enabled_avx_state() {
    let rich = TargetCpu::from_cpuid(&RICH);
    for tier in TargetCpu::DATA_INDEPENDENT_TIMING_TIERS {
        assert!(rich.supports(tier.with_line_atomic()));
    }
    assert!(!rich.doit() && !rich.data_independent_timing());
    let no_ymm = TargetCpu::from_cpuid(&HostCpuid { xcr0: 0x3, ..RICH });
    for vex in [
        TargetCpu::Fma,
        TargetCpu::F16c,
        TargetCpu::Avx2,
        TargetCpu::Avx512f,
    ] {
        assert!(!no_ymm.supports(vex), "{vex:?}");
    }
    // Legacy-encoded features, BMI1 off Intel and the plain-load
    // guarantee keep only their hardware bits.
    let amd_no_ymm = TargetCpu::from_cpuid(&HostCpuid {
        vendor: TargetCpu::AMD_VENDOR,
        xcr0: 0x3,
        ..RICH
    });
    let [_, _, v2] = TargetCpu::DATA_INDEPENDENT_TIMING_TIERS;
    assert!(amd_no_ymm.supports(v2.with_movbe().with_lzcnt().with_gfni()));
    assert!(!amd_no_ymm.supports(TargetCpu::X86_64_V3));
    let no_zmm = TargetCpu::from_cpuid(&HostCpuid {
        xcr0: XCR0_AVX_STATE,
        ..RICH
    });
    assert!(no_zmm.supports(TargetCpu::X86_64_V3));
    assert!(!no_zmm.supports(TargetCpu::Avx512f));
    let on_demand = TargetCpu::from_cpuid(&HostCpuid {
        xcr0: XCR0_AVX_STATE,
        avx512_on_demand: true,
        ..RICH
    });
    assert!(on_demand.supports(TargetCpu::Avx512f));
}

#[test]
fn intel_bmi_needs_avx() {
    let no_avx = HostCpuid { xcr0: 0, ..RICH };
    let bmi = TargetCpu::Bmi1.with_bmi2();
    for required in [TargetCpu::Bmi1, TargetCpu::Bmi2, TargetCpu::FastPdep] {
        assert!(!TargetCpu::from_cpuid(&no_avx).supports(required));
    }
    let amd = HostCpuid {
        vendor: TargetCpu::AMD_VENDOR,
        ..no_avx
    };
    assert!(TargetCpu::from_cpuid(&amd).supports(bmi));
}

#[test]
fn native_detection_matches_std_detect() {
    let target = TargetCpu::detect();
    #[cfg(target_arch = "x86_64")]
    {
        let cpuid = HostCpuid::read();
        for (required, detected) in [
            (TargetCpu::Ssse3, std::is_x86_feature_detected!("ssse3")),
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
                TargetCpu::Avx512f,
                std::is_x86_feature_detected!("avx512f") || darwin_on_demand_avx512f(),
            ),
            (
                TargetCpu::AtomicLoad16,
                TargetCpu::atomic_load16_guaranteed(cpuid.vendor, cpuid.leaf1_ecx),
            ),
            (TargetCpu::Cx16, std::is_x86_feature_detected!("cmpxchg16b")),
            (TargetCpu::Cx8, cpuid.leaf1_edx & 1 << 8 != 0),
            (
                TargetCpu::LineAtomic,
                Vendor::from_cpuid(cpuid.vendor) == Vendor::Intel,
            ),
            (TargetCpu::Lzcnt, std::is_x86_feature_detected!("lzcnt")),
            (TargetCpu::Bmi2, std::is_x86_feature_detected!("bmi2")),
            (TargetCpu::Movbe, std::is_x86_feature_detected!("movbe")),
            (TargetCpu::Gfni, std::is_x86_feature_detected!("gfni")),
            (TargetCpu::Vaes, std::is_x86_feature_detected!("vaes")),
            (
                TargetCpu::Vpclmulqdq,
                std::is_x86_feature_detected!("vpclmulqdq"),
            ),
            (TargetCpu::AvxVnni, std::is_x86_feature_detected!("avxvnni")),
            (
                TargetCpu::AvxVnniInt8,
                std::is_x86_feature_detected!("avxvnniint8"),
            ),
            (
                TargetCpu::AvxVnniInt16,
                std::is_x86_feature_detected!("avxvnniint16"),
            ),
            (
                TargetCpu::AvxNeConvert,
                std::is_x86_feature_detected!("avxneconvert"),
            ),
            (TargetCpu::Sha512, std::is_x86_feature_detected!("sha512")),
            (TargetCpu::Sm3, std::is_x86_feature_detected!("sm3")),
            (TargetCpu::Sm4, std::is_x86_feature_detected!("sm4")),
        ] {
            assert_eq!(target.supports(required), detected, "{required:?}");
        }
        // xnu enables ZMM state on demand, which std_detect does not see.
        if !darwin_on_demand_avx512f() {
            for (required, detected) in [
                (
                    TargetCpu::Avx512vl,
                    std::is_x86_feature_detected!("avx512vl"),
                ),
                (
                    TargetCpu::Avx512bw,
                    std::is_x86_feature_detected!("avx512bw"),
                ),
                (
                    TargetCpu::Avx512cd,
                    std::is_x86_feature_detected!("avx512cd"),
                ),
                (
                    TargetCpu::Avx512dq,
                    std::is_x86_feature_detected!("avx512dq"),
                ),
                (
                    TargetCpu::Avx512vbmi,
                    std::is_x86_feature_detected!("avx512vbmi"),
                ),
                (
                    TargetCpu::Avx512vpopcntdq,
                    std::is_x86_feature_detected!("avx512vpopcntdq"),
                ),
                (
                    TargetCpu::Avx512bitalg,
                    std::is_x86_feature_detected!("avx512bitalg"),
                ),
                (
                    TargetCpu::Avx512vnni,
                    std::is_x86_feature_detected!("avx512vnni"),
                ),
                (
                    TargetCpu::Avx512bf16,
                    std::is_x86_feature_detected!("avx512bf16"),
                ),
                (
                    TargetCpu::Avx512fp16,
                    std::is_x86_feature_detected!("avx512fp16"),
                ),
            ] {
                assert_eq!(target.supports(required), detected, "{required:?}");
            }
        }
        assert!(target.supported());
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        assert_eq!(target, TargetCpu::Baseline);
        assert!(!target.supported());
    }
}
