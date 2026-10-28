//! `cargo xtask sysregs --aarchmrs DIR` writes
//! `crates/stela-runtime/src/machine/system/generated.rs`: every AArch64
//! System register and System instruction accessor the Apple CPU profiles
//! have, from Arm's machine-readable specification (AARCHMRS) and its System
//! register XML, both release 2026-06. Arm publishes both on
//! developer.arm.com (Exploration Tools); `DIR` holds the two downloads under
//! their published names, each checked against its pinned SHA-256.
use crate::tools::root;
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use expression::{Profile, Truth, render};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

mod access;
mod codegen;
mod expression;
mod fold;
mod page;
mod resets;

const RELEASE: &str = "2026-06";
const ARCHIVE: &str = "AARCHMRS_OPENSOURCE_A_profile_FAT-2026-06.tar.gz";
const ARCHIVE_URI: &str = "https://developer.arm.com/-/cdn-downloads/permalink/\
    Exploration-Tools-OS-Machine-Readable-Data/AARCHMRS_BSD/\
    AARCHMRS_OPENSOURCE_A_profile_FAT-2026-06.tar.gz";
const ARCHIVE_SHA256: &str = "fe458c521745cc2d07244c416106add69ae8faa12fa3da8aad34fa76ab29399a";
const ARCHIVE_BYTES: usize = 5_696_585;
const MEMBERS: [&str; 2] = ["Registers.json", "Features.json"];

/// An Apple CPU of the platform: Apple clang's name for it, its Arm
/// architecture version (each entry's comment gives the evidence), and its
/// Apple clang cap, the architectural features `-mcpu` enables (Apple clang
/// 2100.3.34.2 feature export).
pub struct Chip {
    pub name: &'static str,
    version: &'static str,
    cap: &'static [&'static str],
}

/// The Apple CPUs whose Macs the platform profiles cover.
pub const CHIPS: [Chip; 6] = [
    Chip {
        name: "apple-m1",
        // Apple clang -mcpu=apple-m1 defines __ARM_ARCH_8_5__.
        version: "v8Ap5",
        cap: &[
            "FEAT_AES",
            "FEAT_AMUv1",
            "FEAT_AdvSIMD",
            "FEAT_BTI",
            "FEAT_CRC32",
            "FEAT_CSV2_2",
            "FEAT_DIT",
            "FEAT_DPB",
            "FEAT_DPB2",
            "FEAT_DotProd",
            "FEAT_FCMA",
            "FEAT_FHM",
            "FEAT_FP",
            "FEAT_FP16",
            "FEAT_FRINTTS",
            "FEAT_FlagM",
            "FEAT_FlagM2",
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
        ],
    },
    Chip {
        name: "apple-m2",
        // Apple clang -mcpu=apple-m2 defines __ARM_ARCH_8_6__.
        version: "v8Ap6",
        cap: &[
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
        ],
    },
    Chip {
        name: "apple-m3",
        // Apple clang -mcpu=apple-m3 defines __ARM_ARCH_8_6__.
        version: "v8Ap6",
        cap: &[
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
            "FEAT_HCX",
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
        ],
    },
    Chip {
        name: "apple-m4",
        // Apple clang -mcpu=apple-m4 defines __ARM_ARCH_8_7__.
        version: "v8Ap7",
        cap: &[
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
            "FEAT_HCX",
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
            "FEAT_SME",
            "FEAT_SME2",
            "FEAT_SME_F64F64",
            "FEAT_SME_I16I64",
            "FEAT_SPECRES",
            "FEAT_TLBIOS",
            "FEAT_TLBIRANGE",
            "FEAT_TRF",
            "FEAT_UAO",
            "FEAT_VHE",
            "FEAT_WFxT",
            "FEAT_XS",
        ],
    },
    Chip {
        name: "apple-m5",
        // FEAT_CSSC and FEAT_HBC need Armv8.7-A, and without FEAT_MOPS the CPU
        // is not Armv8.8-A.
        version: "v8Ap7",
        cap: &[
            "FEAT_AES",
            "FEAT_AMUv1",
            "FEAT_AMUv1p1",
            "FEAT_AdvSIMD",
            "FEAT_BF16",
            "FEAT_BTI",
            "FEAT_CRC32",
            "FEAT_CSSC",
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
            "FEAT_HBC",
            "FEAT_HCX",
            "FEAT_I8MM",
            "FEAT_JSCVT",
            "FEAT_LOR",
            "FEAT_LRCPC",
            "FEAT_LRCPC2",
            "FEAT_LSE",
            "FEAT_LSE2",
            "FEAT_MPAM",
            "FEAT_MTE",
            "FEAT_MTE2",
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
            "FEAT_SME",
            "FEAT_SME2",
            "FEAT_SME2p1",
            "FEAT_SME_B16B16",
            "FEAT_SME_F16F16",
            "FEAT_SME_F64F64",
            "FEAT_SME_I16I64",
            "FEAT_SPECRES",
            "FEAT_SPECRES2",
            "FEAT_SVE_B16B16",
            "FEAT_TLBIOS",
            "FEAT_TLBIRANGE",
            "FEAT_TRF",
            "FEAT_UAO",
            "FEAT_VHE",
            "FEAT_WFxT",
            "FEAT_XS",
        ],
    },
    Chip {
        name: "apple-m6",
        // FEAT_CSSC and FEAT_HBC need Armv8.7-A, and without FEAT_MOPS the CPU
        // is not Armv8.8-A.
        version: "v8Ap7",
        cap: &[
            "FEAT_AES",
            "FEAT_AMUv1",
            "FEAT_AMUv1p1",
            "FEAT_AdvSIMD",
            "FEAT_BF16",
            "FEAT_BTI",
            "FEAT_CPA",
            "FEAT_CRC32",
            "FEAT_CSSC",
            "FEAT_CSV2_2",
            "FEAT_DIT",
            "FEAT_DPB",
            "FEAT_DPB2",
            "FEAT_DotProd",
            "FEAT_ECV",
            "FEAT_FAMINMAX",
            "FEAT_FCMA",
            "FEAT_FGT",
            "FEAT_FHM",
            "FEAT_FP",
            "FEAT_FP16",
            "FEAT_FP8",
            "FEAT_FPAC",
            "FEAT_FRINTTS",
            "FEAT_FlagM",
            "FEAT_FlagM2",
            "FEAT_HBC",
            "FEAT_HCX",
            "FEAT_I8MM",
            "FEAT_JSCVT",
            "FEAT_LOR",
            "FEAT_LRCPC",
            "FEAT_LRCPC2",
            "FEAT_LSE",
            "FEAT_LSE2",
            "FEAT_LUT",
            "FEAT_MPAM",
            "FEAT_MTE",
            "FEAT_MTE2",
            "FEAT_NV",
            "FEAT_NV2",
            "FEAT_PAN",
            "FEAT_PAN2",
            "FEAT_PAuth",
            "FEAT_PAuth_LR",
            "FEAT_PMULL",
            "FEAT_PMUv3",
            "FEAT_RAS",
            "FEAT_RASv1p1",
            "FEAT_RASv2",
            "FEAT_RDM",
            "FEAT_SB",
            "FEAT_SEL2",
            "FEAT_SHA1",
            "FEAT_SHA256",
            "FEAT_SHA3",
            "FEAT_SHA512",
            "FEAT_SME",
            "FEAT_SME2",
            "FEAT_SME2p1",
            "FEAT_SME_B16B16",
            "FEAT_SME_F16F16",
            "FEAT_SME_F64F64",
            "FEAT_SME_F8F16",
            "FEAT_SME_F8F32",
            "FEAT_SME_I16I64",
            "FEAT_SME_LUTv2",
            "FEAT_SPECRES",
            "FEAT_SPECRES2",
            "FEAT_SVE_B16B16",
            "FEAT_TLBIOS",
            "FEAT_TLBIRANGE",
            "FEAT_TRF",
            "FEAT_UAO",
            "FEAT_VHE",
            "FEAT_WFxT",
            "FEAT_XS",
        ],
    },
];

/// The exception levels and granules every Apple CPU profile has.
const BASE: [(&str, &str); 10] = [
    ("FEAT_AA64", "AArch64"),
    ("FEAT_EL0", "EL0"),
    ("FEAT_EL1", "EL1"),
    ("FEAT_EL2", "EL2, run as a VHE host"),
    ("FEAT_AA64EL0", "EL0 is AArch64"),
    ("FEAT_AA64EL1", "EL1 is AArch64"),
    ("FEAT_AA64EL2", "EL2 is AArch64"),
    ("FEAT_TGran4K", "4 KiB stage-1 granule"),
    ("FEAT_TGran16K", "16 KiB granule, the one macOS uses"),
    ("FEAT_LittleEndEL0", "little-endian only"),
];

/// Choices the architecture leaves open within the Apple clang cap.
const CHOICES: [(&str, &str); 1] = [(
    "FEAT_MPAMv1p0",
    "FEAT_MPAM needs a version; v1.0 is the Armv8.4 base version",
)];

/// Every chip.
const ALL: &[&str] = &[];

/// Features a profile does not have, the chips it applies to (`ALL` for
/// every one) and the reason. Features implied only by these are excluded
/// with them.
const EXCLUDED: [(&str, &[&str], &str); 20] = [
    ("FEAT_EL3", ALL, "the profile has no EL3"),
    ("FEAT_AA64EL3", ALL, "the profile has no EL3"),
    ("FEAT_SEL2", ALL, "Secure EL2 needs EL3"),
    ("FEAT_AA32", ALL, "Apple cores are AArch64-only"),
    ("FEAT_AA32EL0", ALL, "Apple cores are AArch64-only"),
    ("FEAT_AA32EL1", ALL, "Apple cores are AArch64-only"),
    ("FEAT_AA32EL2", ALL, "Apple cores are AArch64-only"),
    ("FEAT_AA32EL3", ALL, "Apple cores are AArch64-only"),
    (
        "FEAT_PMUv3",
        ALL,
        "Apple's PMU is implementation-defined (Linux apple_m1_cpu_pmu)",
    ),
    ("FEAT_PMUv3p1", ALL, "no PMUv3"),
    ("FEAT_PMUv3p4", ALL, "no PMUv3"),
    ("FEAT_PMUv3p5", ALL, "no PMUv3"),
    (
        "FEAT_TRF",
        ALL,
        "no Arm trace unit (inference: SPTM, TXM and the 26A434 kernel touch no \
         trace register); clang lists TRF as an Armv8.4 default",
    ),
    ("FEAT_TRC_SR", ALL, "no Arm trace unit"),
    ("FEAT_ETMv4", ALL, "no Arm trace unit"),
    ("FEAT_ETE", ALL, "no Arm trace unit"),
    (
        "FEAT_NV",
        &["apple-m1", "apple-m2"],
        "Apple's Virtualization framework offers nested virtualization only on \
         M3 and later (VZGenericPlatformConfiguration.isNestedVirtualizationSupported)",
    ),
    ("FEAT_NV2", &["apple-m1", "apple-m2"], "no FEAT_NV"),
    ("FEAT_AMUv1", NO_AMU, NO_AMU_REASON),
    ("FEAT_AMUv1p1", NO_AMU, "no FEAT_AMUv1"),
];

/// The chips whose profile has no activity monitors.
const NO_AMU: &[&str] = &["apple-m1", "apple-m2", "apple-m3"];
const NO_AMU_REASON: &str = "no Arm activity monitors (inference, which a hardware reading \
    of ID_AA64PFR0_EL1.AMU can overturn): AARCHMRS makes FEAT_AMUv1 optional at every \
    version and Apple clang lists it only as an Armv8.4 default, Apple implements its own \
    IMPLEMENTATION DEFINED performance counters, the 26A434 kernelcache accesses no AMU \
    register, and Stela's ID_AA64PFR0_EL1.AMU already reads 0";

/// AARCHMRS constraints an Apple CPU profile does not meet, as rendered, the
/// chips it applies to and why. Any other violated constraint is an error.
const DEVIATIONS: [(&str, &[&str], &str); 19] = [
    ("(FEAT_SME ==> v9Ap2)", LATER, SME_WITHOUT_SVE),
    ("(FEAT_SME2 ==> v9Ap2)", LATER, SME_WITHOUT_SVE),
    ("(FEAT_SME_F64F64 ==> v9Ap2)", LATER, SME_WITHOUT_SVE),
    ("(FEAT_SME_I16I64 ==> v9Ap2)", LATER, SME_WITHOUT_SVE),
    ("(FEAT_SME2p1 ==> v9Ap2)", M5_ON, SME_WITHOUT_SVE),
    ("(FEAT_SME_F16F16 ==> v9Ap2)", M5_ON, SME_WITHOUT_SVE),
    ("(FEAT_SME_B16B16 ==> v9Ap2)", M5_ON, SME_WITHOUT_SVE),
    ("(FEAT_SVE_B16B16 ==> v9Ap2)", M5_ON, SME_WITHOUT_SVE),
    ("(FEAT_SME_LUTv2 ==> v9Ap2)", M6, SME_WITHOUT_SVE),
    ("(FEAT_SME_F8F16 ==> v9Ap2)", M6, SME_WITHOUT_SVE),
    ("(FEAT_SME_F8F32 ==> v9Ap2)", M6, SME_WITHOUT_SVE),
    ("(FEAT_LUT ==> v9Ap2)", M6, LATER_FEATURES),
    ("(FEAT_FAMINMAX ==> v9Ap2)", M6, LATER_FEATURES),
    ("(FEAT_FPMR ==> v9Ap2)", M6, LATER_FEATURES),
    ("(FEAT_FP8 ==> v9Ap2)", M6, LATER_FEATURES),
    ("(FEAT_CPA ==> v9Ap4)", M6, LATER_FEATURES),
    ("(FEAT_PAuth_LR ==> v9Ap4)", M6, LATER_FEATURES),
    ("(FEAT_RASv2 ==> v8Ap8)", M6, LATER_FEATURES),
    ("(FEAT_FGT2 ==> v8Ap8)", M6, LATER_FEATURES),
];

const M6: &[&str] = &["apple-m6"];
const LATER_FEATURES: &str = "Apple clang enables these later-version features on a \
    core that has neither FEAT_MOPS (Armv8.8-A) nor FEAT_SVE2 (Armv9.0-A)";

/// The chips from M5 on.
const M5_ON: &[&str] = &["apple-m5", "apple-m6"];

/// The chips from M4 on, which have SME.
const LATER: &[&str] = &["apple-m4", "apple-m5", "apple-m6"];
const SME_WITHOUT_SVE: &str = "Apple implements SME on an Armv8.7-A core: Apple clang \
    enables FEAT_SME but not FEAT_SVE, and Armv9.0-A requires FEAT_SVE2";

#[derive(Args)]
pub struct Sysregs {
    /// A directory holding Arm's 2026-06 downloads
    /// `AARCHMRS_OPENSOURCE_A_profile_FAT-2026-06.tar.gz` and
    /// `SysReg_xml_A_profile-2026-06.tar.gz`.
    #[arg(long)]
    aarchmrs: PathBuf,
}

impl Sysregs {
    pub fn run(&self) -> Result<()> {
        let directory = tempfile::tempdir()?;
        extract(
            &self.aarchmrs.join(ARCHIVE),
            (ARCHIVE_BYTES, ARCHIVE_SHA256, ARCHIVE_URI),
            directory.path(),
            &MEMBERS,
        )?;
        extract(
            &self.aarchmrs.join(resets::ARCHIVE),
            (resets::BYTES, resets::SHA256, resets::URI),
            directory.path(),
            &[resets::DIRECTORY],
        )?;
        let read = |name: &str| -> Result<Value> {
            Ok(serde_json::from_slice(&fs::read(
                directory.path().join(name),
            )?)?)
        };
        let registers = read("Registers.json")?;
        let profiles = profiles(&read("Features.json")?)?;
        let applicable = applicable(&profiles, &registers)?;
        let resets_directory = directory.path().join(resets::DIRECTORY);
        let facts = resets::read(&resets_directory, &profiles.union)?;
        let chip_facts: Vec<resets::Facts> = profiles
            .chips
            .iter()
            .map(|(_, chip)| resets::read(&resets_directory, chip))
            .collect::<Result<_>>()?;
        let generated = root().join(access::GENERATED);
        fs::write(
            &generated,
            access::generate(
                &registers,
                &profiles,
                &applicable,
                &facts,
                &chip_facts,
                &resets_directory,
            )?,
        )?;
        let status = Command::new("rustfmt")
            .args(["--edition", "2024"])
            .arg(&generated)
            .status()?;
        ensure!(status.success(), "rustfmt failed on {}", access::GENERATED);
        println!("wrote {}", access::GENERATED);
        Ok(())
    }
}

/// Check `archive` against its pinned size and SHA-256 and extract `members`
/// into `into`.
fn extract(
    archive: &Path,
    (bytes, sha256, uri): (usize, &str, &str),
    into: &Path,
    members: &[&str],
) -> Result<()> {
    let data = fs::read(archive).with_context(|| format!("cannot read {}", archive.display()))?;
    ensure!(
        data.len() == bytes && stela_runtime::sha256(&data) == sha256,
        "{} is not the pinned {RELEASE} download ({uri})",
        archive.display()
    );
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .args(members)
        .status()?;
    ensure!(status.success(), "cannot extract {members:?}");
    Ok(())
}

/// The names of the AArch64 System registers and System instructions some
/// chip's profile has.
fn applicable(profiles: &Profiles, registers: &Value) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for register in registers
        .as_array()
        .context("Registers.json is not a list")?
    {
        if register["state"] != "AArch64"
            || !matches!(
                register["_type"].as_str(),
                Some("Register" | "RegisterArray")
            )
        {
            continue;
        }
        let present = profiles
            .chips
            .iter()
            .any(|(_, chip)| chip.truth(&register["condition"]) != Truth::False);
        if !present {
            continue;
        }
        ensure!(
            profiles.union.truth(&register["condition"]) != Truth::False,
            "a chip has {}, which the union profile lacks",
            register["name"]
        );
        let name = register["name"].as_str().context("register without name")?;
        names.insert(name.to_owned());
    }
    Ok(names)
}

/// The platform's CPU profiles, each closed as [`chip_profile`] describes,
/// and their union, in which a feature only some chips have varies.
pub struct Profiles {
    pub union: Profile,
    pub chips: Vec<(&'static str, Profile)>,
}

fn applies(chips: &[&str], chip: &str) -> bool {
    chips.is_empty() || chips.contains(&chip)
}

fn profiles(features: &Value) -> Result<Profiles> {
    let parameters: BTreeSet<String> = features["parameters"]
        .as_array()
        .context("Features.json has no parameters")?
        .iter()
        .filter(|parameter| parameter["_type"] == "Parameters.Boolean")
        .filter_map(|parameter| parameter["name"].as_str().map(str::to_owned))
        .collect();
    let mut constraints: Vec<&Value> = features["constraints"]
        .as_array()
        .map(|list| list.iter().collect())
        .unwrap_or_default();
    for parameter in features["parameters"].as_array().into_iter().flatten() {
        constraints.extend(parameter["constraints"].as_array().into_iter().flatten());
    }
    for (name, _) in BASE.iter().chain(&CHOICES) {
        ensure!(
            parameters.contains(*name),
            "{name} is not an AARCHMRS feature"
        );
    }
    for (name, _, _) in &EXCLUDED {
        ensure!(
            parameters.contains(*name),
            "{name} is not an AARCHMRS feature"
        );
    }
    let mut chips = Vec::new();
    let mut used = BTreeSet::new();
    for chip in &CHIPS {
        let (profile, _, deviations) = chip_profile(&parameters, &constraints, chip)?;
        used.extend(deviations);
        chips.push((chip.name, profile));
    }
    for (constraint, _, _) in &DEVIATIONS {
        ensure!(
            used.contains(*constraint),
            "deviation {constraint} is not violated by any chip"
        );
    }
    let features: BTreeSet<String> = chips
        .iter()
        .flat_map(|(_, profile)| profile.features.iter().cloned())
        .collect();
    let varying = features
        .iter()
        .filter(|feature| {
            !chips
                .iter()
                .all(|(_, profile)| profile.features.contains(*feature))
        })
        .cloned()
        .collect();
    let union = Profile {
        parameters,
        features,
        varying,
        highest_el: 2,
    };
    Ok(Profiles { union, chips })
}

/// Whether `name` is an architecture version parameter such as `v8Ap6`.
fn is_version(name: &str) -> bool {
    name.strip_prefix("v8Ap")
        .or_else(|| name.strip_prefix("v9Ap"))
        .is_some_and(|minor| !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit()))
}

/// One chip's profile: its Apple clang cap, its architecture version and
/// the base, closed under the AARCHMRS feature implications, minus its
/// exclusions. It must meet every AARCHMRS constraint except its recorded
/// deviations, which are returned with the implied features.
fn chip_profile(
    parameters: &BTreeSet<String>,
    constraints: &[&Value],
    chip: &Chip,
) -> Result<(Profile, BTreeSet<String>, Vec<String>)> {
    let excluded: BTreeSet<&str> = EXCLUDED
        .iter()
        .filter(|(_, chips, _)| applies(chips, chip.name))
        .map(|(name, _, _)| *name)
        .collect();
    for name in chip.cap.iter().copied().chain([chip.version]) {
        ensure!(
            parameters.contains(name),
            "{name} of {} is not an AARCHMRS feature",
            chip.name
        );
    }
    let mut features: BTreeSet<String> = chip
        .cap
        .iter()
        .copied()
        .chain([chip.version])
        .chain(BASE.iter().map(|(name, _)| *name))
        .chain(CHOICES.iter().map(|(name, _)| *name))
        .filter(|name| !excluded.contains(name))
        .map(str::to_owned)
        .collect();
    let mut implied = BTreeSet::new();
    loop {
        let profile = Profile {
            parameters: parameters.clone(),
            features: features.clone(),
            highest_el: 2,
            ..Profile::default()
        };
        let mut added = false;
        for constraint in constraints {
            if constraint["op"] != "==>" || constraint["right"]["_type"] != "AST.Identifier" {
                continue;
            }
            let Some(consequent) = constraint["right"]["value"].as_str() else {
                continue;
            };
            // Versions follow the declared one: a feature that needs a later
            // version is a deviation, not a version change.
            let version_chain = !is_version(consequent)
                || constraint["left"]["value"].as_str().is_some_and(is_version);
            if !parameters.contains(consequent)
                || features.contains(consequent)
                || !version_chain
                || profile.truth(&constraint["left"]) != Truth::True
            {
                continue;
            }
            ensure!(
                !excluded.contains(consequent),
                "{} implies excluded {consequent}: {}",
                chip.name,
                render(constraint)
            );
            features.insert(consequent.to_owned());
            implied.insert(consequent.to_owned());
            added = true;
        }
        if !added {
            break;
        }
    }
    let profile = Profile {
        parameters: parameters.clone(),
        features,
        highest_el: 2,
        ..Profile::default()
    };
    let mut deviations = Vec::new();
    let mut violated = Vec::new();
    for constraint in constraints {
        if profile.truth(constraint) != Truth::False {
            continue;
        }
        let text = render(constraint);
        if DEVIATIONS
            .iter()
            .any(|(known, chips, _)| *known == text && applies(chips, chip.name))
        {
            deviations.push(text);
        } else {
            violated.push(text);
        }
    }
    if !violated.is_empty() {
        bail!(
            "{} violates AARCHMRS constraints:\n{}",
            chip.name,
            violated.join("\n")
        );
    }
    Ok((profile, implied, deviations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// SPSR_abt's AArch64 shape: RES0 without AArch32 EL1, else the AArch32
    /// layout.
    pub(super) fn banked_spsr() -> Value {
        let aa32el1 = json!({"_type": "AST.Function", "name": "IsFeatureImplemented",
                             "arguments": [{"_type": "AST.Identifier", "value": "FEAT_AA32EL1"}]});
        json!({"fieldsets": [
            {"condition": {"_type": "AST.UnaryOp", "op": "!", "expr": aa32el1},
             "values": [{"_type": "Fields.Reserved", "value": "RES0",
                         "rangeset": [{"start": 0, "width": 64}]}]},
            {"condition": {"_type": "AST.Bool", "value": true},
             "values": [{"_type": "Fields.Field", "name": "N",
                         "rangeset": [{"start": 31, "width": 1}]}]},
        ]})
    }

    fn identifier(name: &str) -> Value {
        json!({"_type": "AST.Identifier", "value": name})
    }

    fn implies(left: &str, right: &str) -> Value {
        json!({"_type": "AST.BinaryOp", "op": "==>", "left": identifier(left),
               "right": identifier(right)})
    }

    fn feature(name: &str) -> Value {
        json!({"_type": "AST.Function", "name": "IsFeatureImplemented",
               "arguments": [identifier(name)]})
    }

    #[test]
    fn chip_version_gates_feature_reporting() {
        let parameters: BTreeSet<String> = [
            "v8Ap6",
            "v8Ap7",
            "v9Ap2",
            "FEAT_SME",
            "FEAT_WFxT",
            "FEAT_ECV",
        ]
        .into_iter()
        .chain(BASE.iter().map(|(name, _)| *name))
        .chain(CHOICES.iter().map(|(name, _)| *name))
        .map(String::from)
        .collect();
        let constraints = [
            implies("v8Ap7", "v8Ap6"),
            implies("v8Ap7", "FEAT_WFxT"),
            implies("v8Ap6", "FEAT_ECV"),
            implies("FEAT_SME", "v9Ap2"),
        ];
        let constraints: Vec<&Value> = constraints.iter().collect();
        let chip = |name: &'static str, cap: &'static [&'static str]| Chip {
            name,
            version: "v8Ap7",
            cap,
        };
        // The version chain and its mandatory features are implied.
        let (profile, implied, deviations) =
            chip_profile(&parameters, &constraints, &chip("apple-m3", &[])).unwrap();
        assert!(implied.contains("v8Ap6") && implied.contains("FEAT_WFxT"));
        assert!(implied.contains("FEAT_ECV") && deviations.is_empty());
        assert!(!profile.features.contains("v9Ap2"));
        // A feature that needs a later version does not raise the version:
        // the violated constraint is an error unless it is a recorded
        // deviation for the chip.
        let error = chip_profile(&parameters, &constraints, &chip("apple-m3", &["FEAT_SME"]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("(FEAT_SME ==> v9Ap2)"), "{error}");
        let (profile, _, deviations) =
            chip_profile(&parameters, &constraints, &chip("apple-m4", &["FEAT_SME"])).unwrap();
        assert_eq!(deviations, ["(FEAT_SME ==> v9Ap2)"]);
        assert!(!profile.features.contains("v9Ap2"));
    }

    #[test]
    fn version_parameters_are_recognized() {
        assert!(is_version("v8Ap7") && is_version("v9Ap4") && is_version("v8Ap10"));
        assert!(!is_version("v8Ap") && !is_version("FEAT_V8") && !is_version("v7Ap1"));
    }

    #[test]
    fn registers_apply_when_a_chip_has_them() {
        let profile = |features: &[&str]| Profile {
            parameters: ["FEAT_A", "FEAT_B"].map(String::from).into(),
            features: features.iter().map(|f| String::from(*f)).collect(),
            highest_el: 2,
            varying: Default::default(),
        };
        let profiles = Profiles {
            union: Profile {
                varying: ["FEAT_A".to_owned()].into(),
                ..profile(&["FEAT_A"])
            },
            chips: vec![
                ("apple-m1", profile(&[])),
                ("apple-m2", profile(&["FEAT_A"])),
            ],
        };
        let register = |name: &str, condition: Value| json!({"_type": "Register", "state": "AArch64", "name": name, "condition": condition});
        let registers = json!([
            register("A_EL1", feature("FEAT_A")),
            register("B_EL1", feature("FEAT_B")),
            register("C_EL1", json!({"_type": "AST.Bool", "value": true})),
            {"_type": "Register", "state": "AArch32", "name": "D", "condition": true},
        ]);
        let names = applicable(&profiles, &registers).unwrap();
        assert_eq!(names.into_iter().collect::<Vec<_>>(), ["A_EL1", "C_EL1"]);
    }

    #[test]
    fn caps_name_only_features() {
        for chip in &CHIPS {
            assert!(chip.cap.iter().all(|name| name.starts_with("FEAT_")));
        }
    }
}
