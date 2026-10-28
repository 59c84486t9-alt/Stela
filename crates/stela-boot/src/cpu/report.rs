//! CPUID feature and identity inventory for a diagnostics mount.
use super::*;
use alloc::{format, string::String, vec, vec::Vec};

const VENDOR: u32 = 0;
const VERSION: u32 = 1;
const BRAND: [u32; 3] = [0x8000_0002, 0x8000_0003, 0x8000_0004];
const ADDRESS_SIZES: u32 = 0x8000_0008;
const TSC_CRYSTAL: u32 = 0x15;
const FREQUENCY: u32 = 0x16;

const SSE3: Feature = bit("SSE3", 1, Ecx, 0);
const PCLMULQDQ: Feature = bit("PCLMULQDQ", 1, Ecx, 1);
const SSSE3: Feature = bit("SSSE3", 1, Ecx, 9);
const FMA: Feature = bit("FMA", 1, Ecx, 12);
const CX16: Feature = bit("CMPXCHG16B", 1, Ecx, 13);
const PCID: Feature = bit("PCID", 1, Ecx, 17);
const SSE41: Feature = bit("SSE4.1", 1, Ecx, 19);
const SSE42: Feature = bit("SSE4.2", 1, Ecx, 20);
pub const X2APIC: Feature = bit("x2APIC", 1, Ecx, 21);
const MOVBE: Feature = bit("MOVBE", 1, Ecx, 22);
const POPCNT: Feature = bit("POPCNT", 1, Ecx, 23);
pub const TSC_DEADLINE: Feature = bit("TSC-deadline", 1, Ecx, 24);
const AES: Feature = bit("AES", 1, Ecx, 25);
const XSAVE: Feature = bit("XSAVE", 1, Ecx, 26);
const OSXSAVE: Feature = bit("OSXSAVE", 1, Ecx, 27);
const AVX: Feature = bit("AVX", 1, Ecx, 28);
const F16C: Feature = bit("F16C", 1, Ecx, 29);
const RDRAND: Feature = bit("RDRAND", 1, Ecx, 30);
const HYPERVISOR: Feature = bit("hypervisor", 1, Ecx, 31);
const CX8: Feature = bit("CMPXCHG8B", 1, Edx, 8);
const APIC: Feature = bit("APIC", 1, Edx, 9);
pub const ARAT: Feature = bit("ARAT", 6, Eax, 2);
const FSGSBASE: Feature = bit("FSGSBASE", 7, Ebx, 0);
const BMI1: Feature = bit("BMI1", 7, Ebx, 3);
const AVX2: Feature = bit("AVX2", 7, Ebx, 5);
const SMEP: Feature = bit("SMEP", 7, Ebx, 7);
const BMI2: Feature = bit("BMI2", 7, Ebx, 8);
const ERMS: Feature = bit("ERMS", 7, Ebx, 9);
const INVPCID: Feature = bit("INVPCID", 7, Ebx, 10);
const AVX512F: Feature = bit("AVX512F", 7, Ebx, 16);
const AVX512DQ: Feature = bit("AVX512DQ", 7, Ebx, 17);
const RDSEED: Feature = bit("RDSEED", 7, Ebx, 18);
const SMAP: Feature = bit("SMAP", 7, Ebx, 20);
const AVX512CD: Feature = bit("AVX512CD", 7, Ebx, 28);
const SHA: Feature = bit("SHA", 7, Ebx, 29);
const AVX512BW: Feature = bit("AVX512BW", 7, Ebx, 30);
const AVX512VL: Feature = bit("AVX512VL", 7, Ebx, 31);
const FSRM: Feature = bit("FSRM", 7, Edx, 4);
const LAHF_LM: Feature = bit("LAHF/SAHF-64", 0x8000_0001, Ecx, 0);
const LZCNT: Feature = bit("LZCNT", 0x8000_0001, Ecx, 5);
const NX: Feature = bit("NX", 0x8000_0001, Edx, 20);
const PAGE_1G: Feature = bit("1GiB-pages", 0x8000_0001, Edx, 26);
const RDTSCP: Feature = bit("RDTSCP", 0x8000_0001, Edx, 27);

/// What Stela needs of any host: x86-64-v2 and NX.
pub const FLOOR: [Feature; 8] = [SSE3, SSSE3, SSE41, SSE42, POPCNT, CX16, LAHF_LM, NX];
/// x86-64-v3 beyond v2 (the psABI's microarchitecture levels).
const V3: [Feature; 9] = [AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, OSXSAVE];
/// x86-64-v4 beyond v3.
const V4: [Feature; 5] = [AVX512F, AVX512BW, AVX512CD, AVX512DQ, AVX512VL];
/// Everything the report lists.
const REPORTED: [Feature; 45] = [
    SSE3,
    SSSE3,
    SSE41,
    SSE42,
    POPCNT,
    CX16,
    LAHF_LM,
    NX,
    CX8,
    PCLMULQDQ,
    AES,
    SHA,
    AVX,
    AVX2,
    F16C,
    FMA,
    BMI1,
    BMI2,
    LZCNT,
    MOVBE,
    XSAVE,
    OSXSAVE,
    AVX512F,
    AVX512BW,
    AVX512CD,
    AVX512DQ,
    AVX512VL,
    ERMS,
    FSRM,
    RDRAND,
    RDSEED,
    FSGSBASE,
    RDTSCP,
    APIC,
    X2APIC,
    TSC_DEADLINE,
    ARAT,
    INVARIANT_TSC,
    LA57,
    PAGE_1G,
    PCID,
    INVPCID,
    SMEP,
    SMAP,
    HYPERVISOR,
];

/// The floor features this CPU lacks.
pub fn missing_floor() -> Vec<&'static str> {
    FLOOR
        .iter()
        .filter(|feature| !feature.present())
        .map(|feature| feature.name)
        .collect()
}

/// The highest x86-64 microarchitecture level CPUID enumerates.
pub fn level() -> u8 {
    let all = |features: &[Feature]| features.iter().all(Feature::present);
    match (all(&FLOOR), all(&V3), all(&V4)) {
        (false, _, _) => 1,
        (true, false, _) => 2,
        (true, true, false) => 3,
        (true, true, true) => 4,
    }
}

fn text(registers: &[u32]) -> String {
    let bytes: Vec<u8> = registers.iter().flat_map(|r| r.to_le_bytes()).collect();
    String::from_utf8_lossy(&bytes)
        .trim_matches(|c: char| c == '\0' || c == ' ')
        .into()
}

/// Lines of the CPU report: identity, address sizes, frequency leaves and
/// every reported feature, present and absent.
pub fn report() -> Vec<String> {
    let vendor = __cpuid(VENDOR);
    let version = __cpuid(VERSION).eax;
    let family = (version >> 8) & 0xf;
    let model = (version >> 4) & 0xf;
    let (family, model) = if family == 0xf {
        (
            family + ((version >> 20) & 0xff),
            model | ((version >> 12) & 0xf0),
        )
    } else if family == 0x6 {
        (family, model | ((version >> 12) & 0xf0))
    } else {
        (family, model)
    };
    let brand: Vec<u32> = BRAND
        .iter()
        .filter_map(|&l| leaf(l, 0))
        .flat_map(|r| [r.eax, r.ebx, r.ecx, r.edx])
        .collect();
    let mut lines = vec![format!(
        "vendor={:?} brand={:?} family={family:#x} model={model:#x} stepping={} max_leaf={:#x} \
         max_extended={:#x}",
        text(&[vendor.ebx, vendor.edx, vendor.ecx]),
        text(&brand),
        version & 0xf,
        vendor.eax,
        __cpuid(EXTENDED).eax,
    )];
    if let Some(sizes) = leaf(ADDRESS_SIZES, 0) {
        lines.push(format!(
            "address bits physical={} virtual={}",
            sizes.eax & 0xff,
            (sizes.eax >> 8) & 0xff
        ));
    }
    if let Some(crystal) = leaf(TSC_CRYSTAL, 0) {
        lines.push(format!(
            "leaf 0x15 tsc/crystal={}/{} crystal_hz={}",
            crystal.ebx, crystal.eax, crystal.ecx
        ));
    }
    if let Some(frequency) = leaf(FREQUENCY, 0) {
        lines.push(format!(
            "leaf 0x16 base_mhz={} max_mhz={} bus_mhz={}",
            frequency.eax & 0xffff,
            frequency.ebx & 0xffff,
            frequency.ecx & 0xffff
        ));
    }
    let (present, absent): (Vec<&Feature>, Vec<&Feature>) =
        REPORTED.iter().partition(|feature| feature.present());
    let names = |features: Vec<&Feature>| -> String {
        features
            .iter()
            .map(|feature| feature.name)
            .collect::<Vec<_>>()
            .join(" ")
    };
    lines.push(format!("present {}", names(present)));
    lines.push(format!("absent {}", names(absent)));
    lines.push(format!("x86-64 level v{}", level()));
    lines
}
