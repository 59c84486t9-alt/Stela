//! The AArch64 identification registers the system engine presents.
//!
//! They advertise exactly what this engine implements, never more than the
//! M2 implements: each field is set from one table row whose architectural
//! feature must be in Apple clang's `apple-m2` feature set
//! (`isa/apple-codegen-profiles.json`, from `clang -mcpu=apple-m2
//! --print-enabled-extensions`) and whose basis must hold here. An
//! instruction feature holds when its sample encodings compile for the
//! system-mode block profile on the host target; any other feature is an
//! engine property stated with its reason. A field with no satisfied row reads
//! its "not implemented" value.
use super::registers::encodings::*;
use alloc::vec::Vec;
use stela_compiler::{
    GuestAddress, TargetCpu,
    aarch64::system::registers::Encoding,
    block::{BlockProfile, CompilationPlan},
};

/// Apple clang 2100.3.34.2 `-mcpu=apple-m2` architectural features.
pub const APPLE_M2_FEATURES: &[&str] = &[
    "FEAT_AES",
    "FEAT_AMUv1",
    "FEAT_AMUv1p1",
    "FEAT_AdvSIMD",
    "FEAT_BF16",
    "FEAT_BTI",
    "FEAT_CRC32",
    "FEAT_CSV2_2",
    "FEAT_DIT",
    "FEAT_DPB",
    "FEAT_DPB2",
    "FEAT_DotProd",
    "FEAT_ECV",
    "FEAT_FCMA",
    "FEAT_FGT",
    "FEAT_FHM",
    "FEAT_FP",
    "FEAT_FP16",
    "FEAT_FPAC",
    "FEAT_FRINTTS",
    "FEAT_FlagM",
    "FEAT_FlagM2",
    "FEAT_I8MM",
    "FEAT_JSCVT",
    "FEAT_LOR",
    "FEAT_LRCPC",
    "FEAT_LRCPC2",
    "FEAT_LSE",
    "FEAT_LSE2",
    "FEAT_MPAM",
    "FEAT_NV",
    "FEAT_NV2",
    "FEAT_PAN",
    "FEAT_PAN2",
    "FEAT_PAuth",
    "FEAT_PMULL",
    "FEAT_PMUv3",
    "FEAT_RAS",
    "FEAT_RASv1p1",
    "FEAT_RDM",
    "FEAT_SB",
    "FEAT_SEL2",
    "FEAT_SHA1",
    "FEAT_SHA256",
    "FEAT_SHA3",
    "FEAT_SHA512",
    "FEAT_SPECRES",
    "FEAT_SSBS",
    "FEAT_SSBS2",
    "FEAT_TLBIOS",
    "FEAT_TLBIRANGE",
    "FEAT_TRF",
    "FEAT_UAO",
    "FEAT_VHE",
];

/// Why a row's level holds on this engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// Every sample (clang-assembled A64 words) compiles for the system-mode
    /// profile on the host target, and the engine completes their exits.
    Instructions(&'static [u32]),
    /// An engine property, true or false, and why.
    Engine(bool, &'static str),
}

/// One level of one field. A field's rows are listed in increasing level;
/// the field reads the highest satisfied level, or `absent`.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub register: Encoding,
    pub shift: u8,
    pub level: u64,
    pub absent: u64,
    /// The `FEAT_` tag the M2 must have; `None` for fields the architecture
    /// fixes for any AArch64 PE.
    pub feature: Option<&'static str>,
    pub basis: Basis,
}

const fn row(
    register: Encoding,
    shift: u8,
    level: u64,
    absent: u64,
    feature: Option<&'static str>,
    basis: Basis,
) -> Row {
    Row {
        register,
        shift,
        level,
        absent,
        feature,
        basis,
    }
}

const fn feature(
    register: Encoding,
    shift: u8,
    level: u64,
    name: &'static str,
    basis: Basis,
) -> Row {
    row(register, shift, level, 0, Some(name), basis)
}

const fn fixed(register: Encoding, shift: u8, level: u64, reason: &'static str) -> Row {
    row(register, shift, level, 0, None, Basis::Engine(true, reason))
}

const fn engine(holds: bool, reason: &'static str) -> Basis {
    Basis::Engine(holds, reason)
}

const NO_EL2: &str = "the machine has no EL2";
const NO_MONITORS: &str = "no activity, performance or trace monitor is modeled";
const NO_GUARANTEE: &str = "translated code gives no such timing or speculation guarantee";

/// Every ID register the table defines; all their other fields read 0.
pub const REGISTERS: &[Encoding] = &[
    ID_AA64PFR0_EL1,
    ID_AA64PFR1_EL1,
    ID_AA64ISAR0_EL1,
    ID_AA64ISAR1_EL1,
    ID_AA64ISAR2_EL1,
    ID_AA64MMFR0_EL1,
    ID_AA64MMFR1_EL1,
    ID_AA64MMFR2_EL1,
    ID_AA64DFR0_EL1,
    ID_AA64DFR1_EL1,
    ID_AA64AFR0_EL1,
    ID_AA64AFR1_EL1,
    ID_AA64ZFR0_EL1,
    ID_AA64SMFR0_EL1,
    CTR_EL0,
];

pub const TABLE: &[Row] = &[
    // ID_AA64PFR0_EL1
    fixed(ID_AA64PFR0_EL1, 0, 1, "EL0 is AArch64-only"),
    fixed(ID_AA64PFR0_EL1, 4, 1, "EL1 is AArch64-only"),
    row(
        ID_AA64PFR0_EL1,
        16,
        0,
        0xf,
        Some("FEAT_FP"),
        Basis::Instructions(&[0x1e22_2820]),
    ),
    feature(
        ID_AA64PFR0_EL1,
        16,
        1,
        "FEAT_FP16",
        Basis::Instructions(&[0x1ee2_2820]),
    ),
    row(
        ID_AA64PFR0_EL1,
        20,
        0,
        0xf,
        Some("FEAT_AdvSIMD"),
        Basis::Instructions(&[0x4ea2_8420]),
    ),
    feature(
        ID_AA64PFR0_EL1,
        20,
        1,
        "FEAT_FP16",
        Basis::Instructions(&[0x4e42_1420]),
    ),
    feature(
        ID_AA64PFR0_EL1,
        28,
        1,
        "FEAT_RAS",
        engine(false, "no RAS error records are modeled"),
    ),
    feature(ID_AA64PFR0_EL1, 36, 1, "FEAT_SEL2", engine(false, NO_EL2)),
    feature(
        ID_AA64PFR0_EL1,
        40,
        1,
        "FEAT_MPAM",
        engine(false, "no MPAM is modeled"),
    ),
    feature(
        ID_AA64PFR0_EL1,
        44,
        1,
        "FEAT_AMUv1",
        engine(false, NO_MONITORS),
    ),
    feature(
        ID_AA64PFR0_EL1,
        48,
        1,
        "FEAT_DIT",
        engine(false, NO_GUARANTEE),
    ),
    feature(
        ID_AA64PFR0_EL1,
        56,
        2,
        "FEAT_CSV2_2",
        engine(false, NO_GUARANTEE),
    ),
    // ID_AA64PFR1_EL1
    feature(
        ID_AA64PFR1_EL1,
        0,
        1,
        "FEAT_BTI",
        engine(false, "BTYPE checking is not modeled"),
    ),
    feature(
        ID_AA64PFR1_EL1,
        4,
        1,
        "FEAT_SSBS",
        engine(true, "PSTATE.SSBS and MSR SSBS, #imm"),
    ),
    feature(
        ID_AA64PFR1_EL1,
        4,
        2,
        "FEAT_SSBS2",
        engine(true, "MRS and MSR of SSBS"),
    ),
    // ID_AA64ISAR0_EL1
    feature(
        ID_AA64ISAR0_EL1,
        4,
        1,
        "FEAT_AES",
        Basis::Instructions(&[0x4e28_4820]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        4,
        2,
        "FEAT_PMULL",
        Basis::Instructions(&[0x0ee2_e020]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        8,
        1,
        "FEAT_SHA1",
        Basis::Instructions(&[0x5e02_0020]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        12,
        1,
        "FEAT_SHA256",
        Basis::Instructions(&[0x5e02_4020]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        12,
        2,
        "FEAT_SHA512",
        Basis::Instructions(&[0xce62_8020]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        16,
        1,
        "FEAT_CRC32",
        Basis::Instructions(&[0x9ac2_4c20]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        20,
        2,
        "FEAT_LSE",
        Basis::Instructions(&[0xf820_0041, 0xc8e0_fc41]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        28,
        1,
        "FEAT_RDM",
        Basis::Instructions(&[0x6e82_8420]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        32,
        1,
        "FEAT_SHA3",
        Basis::Instructions(&[0xce02_0c20]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        44,
        1,
        "FEAT_DotProd",
        Basis::Instructions(&[0x4e82_9420]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        48,
        1,
        "FEAT_FHM",
        Basis::Instructions(&[0x0e22_ec20]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        52,
        1,
        "FEAT_FlagM",
        Basis::Instructions(&[0xd500_401f]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        52,
        2,
        "FEAT_FlagM2",
        Basis::Instructions(&[0xd500_405f]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        56,
        1,
        "FEAT_TLBIOS",
        engine(true, "every TLBI invalidates"),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        56,
        2,
        "FEAT_TLBIRANGE",
        engine(true, "every TLBI invalidates"),
    ),
    // ID_AA64ISAR1_EL1
    feature(
        ID_AA64ISAR1_EL1,
        0,
        1,
        "FEAT_DPB",
        Basis::Instructions(&[0xd50b_7c20]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        0,
        2,
        "FEAT_DPB2",
        Basis::Instructions(&[0xd50b_7d20]),
    ),
    // QARMA5 in the Classic policy; FPAC (level 4) needs faulting AUT.
    feature(
        ID_AA64ISAR1_EL1,
        4,
        1,
        "FEAT_PAuth",
        Basis::Instructions(&[0xdac1_0020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        4,
        4,
        "FEAT_FPAC",
        engine(false, "AUT failures poison, never fault"),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        12,
        1,
        "FEAT_JSCVT",
        Basis::Instructions(&[0x1e7e_0020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        16,
        1,
        "FEAT_FCMA",
        Basis::Instructions(&[0x6e82_c420]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        20,
        1,
        "FEAT_LRCPC",
        Basis::Instructions(&[0xf8bf_c020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        20,
        2,
        "FEAT_LRCPC2",
        Basis::Instructions(&[0xd940_0020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        24,
        1,
        "FEAT_PAuth",
        Basis::Instructions(&[0x9ac2_3020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        32,
        1,
        "FEAT_FRINTTS",
        Basis::Instructions(&[0x1e28_4020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        36,
        1,
        "FEAT_SB",
        Basis::Instructions(&[0xd503_30ff]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        40,
        1,
        "FEAT_SPECRES",
        engine(false, "CFP, DVP and CPP RCTX are not modeled"),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        44,
        1,
        "FEAT_BF16",
        Basis::Instructions(&[0x6e42_fc20]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        52,
        1,
        "FEAT_I8MM",
        Basis::Instructions(&[0x4e82_a420]),
    ),
    // ID_AA64MMFR0_EL1
    fixed(ID_AA64MMFR0_EL1, 0, 0b0101, "48-bit physical addresses"),
    fixed(ID_AA64MMFR0_EL1, 4, 0b0010, "16-bit ASIDs"),
    fixed(ID_AA64MMFR0_EL1, 20, 1, "16 KiB stage-1 granule"),
    row(
        ID_AA64MMFR0_EL1,
        24,
        0,
        0xf,
        None,
        engine(false, "the walker refuses 64 KiB granules"),
    ),
    row(
        ID_AA64MMFR0_EL1,
        28,
        0,
        0xf,
        None,
        engine(true, "4 KiB stage-1 granule"),
    ),
    fixed(ID_AA64MMFR0_EL1, 32, 1, "no stage 2"),
    fixed(ID_AA64MMFR0_EL1, 36, 1, "no stage 2"),
    fixed(ID_AA64MMFR0_EL1, 40, 1, "no stage 2"),
    feature(ID_AA64MMFR0_EL1, 56, 1, "FEAT_FGT", engine(false, NO_EL2)),
    feature(
        ID_AA64MMFR0_EL1,
        60,
        1,
        "FEAT_ECV",
        engine(false, "the CNTKCTL event stream is not modeled"),
    ),
    // ID_AA64MMFR1_EL1
    feature(ID_AA64MMFR1_EL1, 8, 1, "FEAT_VHE", engine(false, NO_EL2)),
    feature(
        ID_AA64MMFR1_EL1,
        16,
        1,
        "FEAT_LOR",
        engine(false, "LORegions are not modeled"),
    ),
    feature(
        ID_AA64MMFR1_EL1,
        20,
        1,
        "FEAT_PAN",
        engine(true, "PSTATE.PAN and SPAN"),
    ),
    feature(
        ID_AA64MMFR1_EL1,
        20,
        2,
        "FEAT_PAN2",
        engine(true, "AT S1E1RP and S1E1WP"),
    ),
    // ID_AA64MMFR2_EL1
    feature(
        ID_AA64MMFR2_EL1,
        4,
        1,
        "FEAT_UAO",
        engine(false, "LDTR/STTR permission checks are not modeled"),
    ),
    feature(ID_AA64MMFR2_EL1, 24, 1, "FEAT_NV", engine(false, NO_EL2)),
    feature(
        ID_AA64MMFR2_EL1,
        32,
        1,
        "FEAT_LSE2",
        engine(false, "unaligned single-copy atomicity is not guaranteed"),
    ),
    // ID_AA64DFR0_EL1
    fixed(
        ID_AA64DFR0_EL1,
        0,
        6,
        "the Armv8.0 debug architecture is mandatory; programming a breakpoint or \
         watchpoint stops explicitly",
    ),
    feature(
        ID_AA64DFR0_EL1,
        8,
        1,
        "FEAT_PMUv3",
        engine(false, NO_MONITORS),
    ),
    fixed(ID_AA64DFR0_EL1, 36, 0xf, "no OS Double Lock"),
    feature(
        ID_AA64DFR0_EL1,
        40,
        1,
        "FEAT_TRF",
        engine(false, NO_MONITORS),
    ),
    // CTR_EL0: bit 31 is RES1; 64-byte lines like the DC ZVA block; PIPT
    // instruction cache; instruction fetch needs IC (DIC 0) but no data
    // clean (IDC 1), because translation reads guest RAM directly.
    fixed(CTR_EL0, 0, 4, "64-byte instruction cache lines"),
    fixed(CTR_EL0, 14, 0b11, "PIPT instruction cache"),
    fixed(CTR_EL0, 16, 4, "64-byte data cache lines"),
    fixed(CTR_EL0, 20, 4, "64-byte exclusives reservation granule"),
    fixed(CTR_EL0, 24, 4, "64-byte writeback granule"),
    fixed(
        CTR_EL0,
        28,
        1,
        "IDC: no data clean for instruction coherence",
    ),
    fixed(CTR_EL0, 31, 1, "RES1"),
];

fn holds(row: &Row, target: TargetCpu) -> bool {
    if row
        .feature
        .is_some_and(|feature| !APPLE_M2_FEATURES.contains(&feature))
    {
        return false;
    }
    match row.basis {
        Basis::Engine(holds, _) => holds,
        Basis::Instructions(samples) => samples.iter().all(|word| {
            CompilationPlan::new(
                &word.to_le_bytes(),
                GuestAddress(0x1000),
                BlockProfile::SystemModeV1,
                target,
            )
            .and_then(CompilationPlan::compile)
            .is_ok()
        }),
    }
}

/// Every register of [`REGISTERS`] with its value for this host target.
pub fn derive(target: TargetCpu) -> Vec<(Encoding, u64)> {
    REGISTERS
        .iter()
        .map(|&register| {
            let mut value = 0u64;
            let mut fields: Vec<(u8, u64)> = Vec::new();
            for row in TABLE.iter().filter(|row| row.register == register) {
                let current = match fields.iter_mut().find(|(shift, _)| *shift == row.shift) {
                    Some(field) => field,
                    None => {
                        fields.push((row.shift, row.absent));
                        fields.last_mut().expect("just pushed")
                    }
                };
                if holds(row, target) {
                    current.1 = row.level;
                }
            }
            for (shift, field) in fields {
                value |= field << shift;
            }
            (register, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, path::Path};

    fn json(name: &str) -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../isa")
            .join(name);
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn the_cap_is_apple_clangs_m2_feature_set_and_every_row_names_a_known_feature() {
        let profiles = json("apple-codegen-profiles.json");
        let m2: BTreeSet<&str> = profiles["profiles"]["apple-m2"]["architectural_features"]
            .as_array()
            .unwrap()
            .iter()
            .map(|feature| feature.as_str().unwrap())
            .collect();
        assert_eq!(m2, APPLE_M2_FEATURES.iter().copied().collect());
        let known: BTreeSet<String> = profiles["profiles"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|profile| {
                profile["architectural_features"]
                    .as_array()
                    .unwrap()
                    .clone()
            })
            .map(|feature| feature.as_str().unwrap().to_owned())
            .collect();
        for row in TABLE {
            if let Some(feature) = row.feature {
                assert!(
                    known.contains(feature),
                    "{feature} is not an Apple clang feature"
                );
            }
        }
    }

    #[test]
    fn advertised_instruction_fields_match_what_the_decoder_compiles() {
        let target = TargetCpu::detect();
        let values = derive(target);
        let value = |register| values.iter().find(|(r, _)| *r == register).unwrap().1;
        for row in TABLE {
            let field = (value(row.register) >> row.shift) & 0xf;
            let Basis::Instructions(samples) = row.basis else {
                continue;
            };
            let compiles = samples.iter().all(|word| {
                CompilationPlan::new(
                    &word.to_le_bytes(),
                    GuestAddress(0x1000),
                    BlockProfile::SystemModeV1,
                    target,
                )
                .and_then(CompilationPlan::compile)
                .is_ok()
            });
            // A satisfied row means the field reads at least its level; an
            // unsatisfied lowest row means it reads `absent`.
            if compiles {
                assert!(
                    field == row.level || field > row.level && field != row.absent,
                    "{:?} field {} reads {field}",
                    row.register,
                    row.shift
                );
            }
            let lowest = TABLE
                .iter()
                .filter(|other| other.register == row.register && other.shift == row.shift)
                .map(|other| other.level)
                .min()
                .unwrap();
            if !compiles && row.level == lowest {
                assert_eq!(field, row.absent, "{:?} field {}", row.register, row.shift);
            }
        }
        // Features the M2 lacks are never advertised: SVE stays 0.
        assert_eq!(value(ID_AA64PFR0_EL1) >> 32 & 0xf, 0);
        assert_eq!(value(ID_AA64ZFR0_EL1), 0);
    }

    #[test]
    fn fixed_and_engine_fields() {
        let values = derive(TargetCpu::detect());
        let value = |register| values.iter().find(|(r, _)| *r == register).unwrap().1;
        // EL0/EL1 AArch64, no EL2/EL3; 48-bit PA, 16-bit ASID, 16K and 4K but
        // not 64K granules; PAN2; Armv8.0 debug without double lock.
        assert_eq!(value(ID_AA64PFR0_EL1) & 0xffff, 0x0011);
        assert_eq!(value(ID_AA64MMFR0_EL1) & 0xffff_ffff, 0x0f10_0025);
        assert_eq!(value(ID_AA64MMFR1_EL1) >> 20 & 0xf, 2);
        assert_eq!(value(ID_AA64DFR0_EL1) & 0xf, 6);
        assert_eq!(value(CTR_EL0), 0x9444_c004);
    }
}
