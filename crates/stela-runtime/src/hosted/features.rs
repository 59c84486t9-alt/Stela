//! The EL0-visible CPU features XNU publishes, derived from the hosted
//! PE's identification registers the way XNU derives them
//! (`osfmk/arm/commpage/commpage.c` `commpage_init_arm_optional_features_*`):
//! the commpage capability bits and the `hw.optional.arm.FEAT_*` sysctls
//! answer from the same rows, so they cannot disagree.
//!
//! One adaptation: XNU tests only the IMPLEMENTATION DEFINED PAC fields (API,
//! GPI), which Apple cores set. The engine implements the architected QARMA5
//! algorithm and reports APA and GPA instead, so the address and generic
//! fields are each the larger of the two.
use crate::machine::registers::encodings::{
    Encoding, ID_AA64ISAR0_EL1, ID_AA64ISAR1_EL1, ID_AA64ISAR2_EL1, ID_AA64MMFR0_EL1,
    ID_AA64MMFR1_EL1, ID_AA64MMFR2_EL1, ID_AA64PFR0_EL1, ID_AA64PFR1_EL1,
};

/// `osfmk/arm/cpu_capabilities.h` capability bits.
pub mod capability {
    pub const FEAT_FP16: u64 = 0x0000_0008;
    pub const CACHE32: u64 = 0x0000_0010;
    pub const CACHE64: u64 = 0x0000_0020;
    pub const CACHE128: u64 = 0x0000_0040;
    pub const FAST_THREAD_LOCAL_STORAGE: u64 = 0x0000_0080;
    pub const ADV_SIMD: u64 = 0x0000_0100;
    pub const ADV_SIMD_HPFP_CVT: u64 = 0x0000_0200;
    pub const VFP: u64 = 0x0000_0400;
    pub const EVENT: u64 = 0x0000_1000;
    pub const FMA: u64 = 0x0000_2000;
    pub const FEAT_FHM: u64 = 0x0000_4000;
    pub const UP: u64 = 0x0000_8000;
    pub const NUM_CPUS_SHIFT: u32 = 16;
    pub const ARMV8_CRYPTO: u64 = 0x0100_0000;
    pub const FEAT_LSE: u64 = 0x0200_0000;
    pub const ARMV8_CRC32: u64 = 0x0400_0000;
    pub const FEAT_SHA512: u64 = 0x8000_0000;
    pub const FEAT_SHA3: u64 = 0x0000_0001_0000_0000;
    pub const FEAT_FCMA: u64 = 0x0000_0002_0000_0000;
    pub const FEAT_AFP: u64 = 0x0000_0004_0000_0000;
    pub const FEAT_FLAGM: u64 = 0x0000_0100_0000_0000;
    pub const FEAT_FLAGM2: u64 = 0x0000_0200_0000_0000;
    pub const FEAT_DOTPROD: u64 = 0x0000_0400_0000_0000;
    pub const FEAT_RDM: u64 = 0x0000_0800_0000_0000;
    pub const FEAT_SPECRES: u64 = 0x0000_1000_0000_0000;
    pub const FEAT_SB: u64 = 0x0000_2000_0000_0000;
    pub const FEAT_FRINTTS: u64 = 0x0000_4000_0000_0000;
    pub const ARMV8_GPI: u64 = 0x0000_8000_0000_0000;
    pub const FEAT_LRCPC: u64 = 0x0001_0000_0000_0000;
    pub const FEAT_LRCPC2: u64 = 0x0002_0000_0000_0000;
    pub const FEAT_JSCVT: u64 = 0x0004_0000_0000_0000;
    pub const FEAT_PAUTH: u64 = 0x0008_0000_0000_0000;
    pub const FEAT_DPB: u64 = 0x0010_0000_0000_0000;
    pub const FEAT_DPB2: u64 = 0x0020_0000_0000_0000;
    pub const FEAT_LSE2: u64 = 0x0040_0000_0000_0000;
    pub const FEAT_CSV2: u64 = 0x0080_0000_0000_0000;
    pub const FEAT_CSV3: u64 = 0x0100_0000_0000_0000;
    pub const FEAT_DIT: u64 = 0x0200_0000_0000_0000;
}

/// One feature row: the `hw.optional.arm.` sysctl name, the register and
/// field, the minimum field value and the commpage bit, if any.
struct Row {
    sysctl: &'static str,
    register: Encoding,
    shift: u32,
    minimum: u64,
    bit: u64,
}

const fn row(sysctl: &'static str, register: Encoding, shift: u32, minimum: u64, bit: u64) -> Row {
    Row {
        sysctl,
        register,
        shift,
        minimum,
        bit,
    }
}

/// The ID_AA64ISAR1_EL1 fields XNU reads as the PAC algorithm fields.
const ISAR1_APA: u32 = 4;
const ISAR1_API: u32 = 8;
const ISAR1_GPA: u32 = 24;
const ISAR1_GPI: u32 = 28;
const PFR0_ADV_SIMD: u32 = 20;
const ADV_SIMD_ABSENT: u64 = 0xf;
const ADV_SIMD_FP16: u64 = 1;

use capability as c;
const ROWS: &[Row] = &[
    row("FEAT_FlagM", ID_AA64ISAR0_EL1, 52, 1, c::FEAT_FLAGM),
    row("FEAT_FlagM2", ID_AA64ISAR0_EL1, 52, 2, c::FEAT_FLAGM2),
    row("FEAT_FHM", ID_AA64ISAR0_EL1, 48, 1, c::FEAT_FHM),
    row("FEAT_DotProd", ID_AA64ISAR0_EL1, 44, 1, c::FEAT_DOTPROD),
    row("FEAT_SHA3", ID_AA64ISAR0_EL1, 32, 1, c::FEAT_SHA3),
    row("FEAT_RDM", ID_AA64ISAR0_EL1, 28, 1, c::FEAT_RDM),
    row("FEAT_LSE", ID_AA64ISAR0_EL1, 20, 2, c::FEAT_LSE),
    row("FEAT_SHA512", ID_AA64ISAR0_EL1, 12, 2, c::FEAT_SHA512),
    row("FEAT_CRC32", ID_AA64ISAR0_EL1, 16, 1, c::ARMV8_CRC32),
    row("FEAT_AES", ID_AA64ISAR0_EL1, 4, 1, c::ARMV8_CRYPTO),
    row("FEAT_PMULL", ID_AA64ISAR0_EL1, 4, 2, c::ARMV8_CRYPTO),
    row("FEAT_SHA1", ID_AA64ISAR0_EL1, 8, 1, c::ARMV8_CRYPTO),
    row("FEAT_SHA256", ID_AA64ISAR0_EL1, 12, 1, c::ARMV8_CRYPTO),
    row("FEAT_SB", ID_AA64ISAR1_EL1, 36, 1, c::FEAT_SB),
    row("FEAT_FRINTTS", ID_AA64ISAR1_EL1, 32, 1, c::FEAT_FRINTTS),
    row("FEAT_LRCPC", ID_AA64ISAR1_EL1, 20, 1, c::FEAT_LRCPC),
    row("FEAT_LRCPC2", ID_AA64ISAR1_EL1, 20, 2, c::FEAT_LRCPC2),
    row("FEAT_FCMA", ID_AA64ISAR1_EL1, 16, 1, c::FEAT_FCMA),
    row("FEAT_JSCVT", ID_AA64ISAR1_EL1, 12, 1, c::FEAT_JSCVT),
    row("FEAT_DPB", ID_AA64ISAR1_EL1, 0, 1, c::FEAT_DPB),
    row("FEAT_DPB2", ID_AA64ISAR1_EL1, 0, 2, c::FEAT_DPB2),
    row("FEAT_BF16", ID_AA64ISAR1_EL1, 44, 1, 0),
    row("FEAT_EBF16", ID_AA64ISAR1_EL1, 44, 2, 0),
    row("FEAT_I8MM", ID_AA64ISAR1_EL1, 52, 1, 0),
    row("FEAT_WFxT", ID_AA64ISAR2_EL1, 0, 2, 0),
    row("FEAT_RPRES", ID_AA64ISAR2_EL1, 4, 1, 0),
    row("FEAT_CSSC", ID_AA64ISAR2_EL1, 52, 1, 0),
    row("FEAT_HBC", ID_AA64ISAR2_EL1, 20, 1, 0),
    row("FEAT_ECV", ID_AA64MMFR0_EL1, 60, 1, 0),
    row("FEAT_AFP", ID_AA64MMFR1_EL1, 44, 1, c::FEAT_AFP),
    row("FEAT_LSE2", ID_AA64MMFR2_EL1, 32, 1, c::FEAT_LSE2),
    row("FEAT_CSV3", ID_AA64PFR0_EL1, 60, 1, c::FEAT_CSV3),
    row("FEAT_CSV2", ID_AA64PFR0_EL1, 56, 1, c::FEAT_CSV2),
    row("FEAT_DIT", ID_AA64PFR0_EL1, 48, 1, c::FEAT_DIT),
    row("FEAT_SSBS", ID_AA64PFR1_EL1, 4, 1, 0),
    row("FEAT_BTI", ID_AA64PFR1_EL1, 0, 1, 0),
];

/// The identification values of the hosted PE's profile.
pub struct Identification<'a>(pub &'a [(Encoding, u64)]);

impl Identification<'_> {
    fn register(&self, encoding: Encoding) -> u64 {
        self.0
            .iter()
            .find(|(register, _)| *register == encoding)
            .map_or(0, |(_, value)| *value)
    }

    fn field(&self, encoding: Encoding, shift: u32) -> u64 {
        (self.register(encoding) >> shift) & 0xf
    }

    /// API or APA, whichever algorithm the PE implements.
    fn address_authentication(&self) -> u64 {
        self.field(ID_AA64ISAR1_EL1, ISAR1_API)
            .max(self.field(ID_AA64ISAR1_EL1, ISAR1_APA))
    }

    fn generic_authentication(&self) -> u64 {
        self.field(ID_AA64ISAR1_EL1, ISAR1_GPI)
            .max(self.field(ID_AA64ISAR1_EL1, ISAR1_GPA))
    }

    /// Every `hw.optional.arm.FEAT_*` sysctl XNU publishes and its value.
    pub fn optional_features(&self) -> Vec<(&'static str, bool)> {
        let pac = self.address_authentication();
        let simd = self.field(ID_AA64PFR0_EL1, PFR0_ADV_SIMD);
        let mut features: Vec<(&'static str, bool)> = ROWS
            .iter()
            .map(|row| {
                (
                    row.sysctl,
                    self.field(row.register, row.shift) >= row.minimum,
                )
            })
            .collect();
        features.extend([
            ("FEAT_PAuth", pac >= 1),
            ("FEAT_PAuth2", pac >= 3),
            ("FEAT_FPAC", pac >= 4),
            ("FEAT_FPACCOMBINE", pac >= 5),
            ("FEAT_PACIMP", self.generic_authentication() >= 1),
            (
                "FEAT_FP16",
                simd != ADV_SIMD_ABSENT && simd >= ADV_SIMD_FP16,
            ),
            ("AdvSIMD", simd != ADV_SIMD_ABSENT),
            ("AdvSIMD_HPFPCvt", simd != ADV_SIMD_ABSENT),
        ]);
        features
    }

    /// The commpage's optional-feature bits.
    pub fn capability_bits(&self) -> u64 {
        let mut bits = ROWS
            .iter()
            .filter(|row| row.bit != 0 && self.field(row.register, row.shift) >= row.minimum)
            .fold(0, |bits, row| bits | row.bit);
        if self.address_authentication() >= 1 {
            bits |= c::FEAT_PAUTH;
        }
        if self.generic_authentication() >= 1 {
            bits |= c::ARMV8_GPI;
        }
        let simd = self.field(ID_AA64PFR0_EL1, PFR0_ADV_SIMD);
        if simd != ADV_SIMD_ABSENT {
            bits |= c::ADV_SIMD | c::ADV_SIMD_HPFP_CVT;
            if simd >= ADV_SIMD_FP16 {
                bits |= c::FEAT_FP16;
            }
        }
        bits
    }
}

/// `commpage_init_cpu_capabilities`: cache line, CPU count, the fixed
/// arm64 bits and the optional features. FP trap enables are RAZ/WI on
/// Apple cores, so `kHasFP_SyncExceptions` stays clear.
pub fn cpu_capabilities(identification: &Identification, cache_line: u32, cpus: u8) -> u64 {
    let cache = match cache_line {
        128 => c::CACHE128,
        64 => c::CACHE64,
        32 => c::CACHE32,
        _ => 0,
    };
    let single = if cpus == 1 { c::UP } else { 0 };
    cache
        | single
        | u64::from(cpus) << c::NUM_CPUS_SHIFT
        | c::FAST_THREAD_LOCAL_STORAGE
        | c::VFP
        | c::FMA
        | c::EVENT
        | identification.capability_bits()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_follow_xnu_thresholds() {
        let values = [
            // AES+PMULL (2), SHA2 512 (2), LSE (2), FlagM2 (2).
            (ID_AA64ISAR0_EL1, 2 << 4 | 2 << 12 | 2 << 20 | 2 << 52),
            // APA QARMA5 with FPACCOMBINE (5), GPA.
            (ID_AA64ISAR1_EL1, 5 << ISAR1_APA | 1 << ISAR1_GPA),
            // FP and AdvSIMD with FP16.
            (ID_AA64PFR0_EL1, 1 << 16 | 1 << 20),
        ];
        let identification = Identification(&values);
        let bits = identification.capability_bits();
        for bit in [
            c::ARMV8_CRYPTO,
            c::FEAT_SHA512,
            c::FEAT_LSE,
            c::FEAT_FLAGM,
            c::FEAT_FLAGM2,
            c::FEAT_PAUTH,
            c::ARMV8_GPI,
            c::ADV_SIMD,
            c::FEAT_FP16,
        ] {
            assert_ne!(bits & bit, 0, "{bit:#x}");
        }
        assert_eq!(bits & c::FEAT_SHA3, 0);
        let features = identification.optional_features();
        assert!(features.contains(&("FEAT_FPACCOMBINE", true)));
        assert!(features.contains(&("FEAT_SHA3", false)));
        let capabilities = cpu_capabilities(&identification, 128, 8);
        assert_eq!((capabilities >> c::NUM_CPUS_SHIFT) & 0xff, 8);
        assert_ne!(capabilities & c::CACHE128, 0);
        assert_eq!(capabilities & c::UP, 0);
    }
}
