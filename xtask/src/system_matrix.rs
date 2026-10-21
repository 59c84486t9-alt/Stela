//! The system platform requirement matrix: every architectural AArch64 System
//! register, field, System instruction, exception class, feature and
//! system-semantic instruction form that the declared Apple CPU profiles
//! requires, derived from Arm's machine-readable specification (AARCHMRS).
//!
//! `cargo xtask system-matrix --archive PATH` regenerates the facts from the
//! pinned archive; `cargo xtask progress` merges the status registry into the
//! matrix and the README. The facts are committed, so checks need no archive.
use crate::tools::root;
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use expression::{Profile, Truth, render};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

mod access;
pub mod assess;
mod checks;
mod codegen;
mod expression;
mod fold;
pub(crate) mod resets;
pub mod runs;

pub const MATRIX: &str = "isa/a64-system-requirements.json";
pub const REGISTRY: &str = "isa/system-platform-registry.json";
const APPLE_PROFILES: &str = "isa/apple-codegen-profiles.json";
const CHECKLIST: &str = "isa/a64-documented-checklist.json";

const RELEASE: &str = "2026-06";
const ARCHIVE_URI: &str = "https://developer.arm.com/-/cdn-downloads/permalink/\
    Exploration-Tools-OS-Machine-Readable-Data/AARCHMRS_BSD/\
    AARCHMRS_OPENSOURCE_A_profile_FAT-2026-06.tar.gz";
const ARCHIVE_SHA256: &str = "fe458c521745cc2d07244c416106add69ae8faa12fa3da8aad34fa76ab29399a";
const ARCHIVE_BYTES: usize = 5_696_585;
const MEMBERS: [&str; 2] = ["Registers.json", "Features.json"];

/// An Apple CPU of the platform: Apple clang's name for it and its Arm
/// architecture version, with the evidence for the version.
pub struct Chip {
    pub name: &'static str,
    version: &'static str,
    evidence: &'static str,
}

/// The Apple CPUs whose Macs the platform profiles cover. Each one's feature
/// cap is its Apple clang export (`isa/apple-codegen-profiles.json`).
pub const CHIPS: [Chip; 6] = [
    Chip {
        name: "apple-m1",
        version: "v8Ap5",
        evidence: "Apple clang -mcpu=apple-m1 defines __ARM_ARCH_8_5__",
    },
    Chip {
        name: "apple-m2",
        version: "v8Ap6",
        evidence: "Apple clang -mcpu=apple-m2 defines __ARM_ARCH_8_6__",
    },
    Chip {
        name: "apple-m3",
        version: "v8Ap6",
        evidence: "Apple clang -mcpu=apple-m3 defines __ARM_ARCH_8_6__",
    },
    Chip {
        name: "apple-m4",
        version: "v8Ap7",
        evidence: "Apple clang -mcpu=apple-m4 defines __ARM_ARCH_8_7__",
    },
    Chip {
        name: "apple-m5",
        version: "v8Ap7",
        evidence: "FEAT_CSSC and FEAT_HBC need Armv8.7-A, and without FEAT_MOPS the \
                   CPU is not Armv8.8-A",
    },
    Chip {
        name: "apple-m6",
        version: "v8Ap7",
        evidence: "FEAT_CSSC and FEAT_HBC need Armv8.7-A, and without FEAT_MOPS the \
                   CPU is not Armv8.8-A",
    },
];

/// The primary CPU family; the platform variant is M1 Pro J314sAP.
pub const DEFAULT_CHIP: &str = "apple-m1";
/// Historical no-chip registry entries were qualified on M2. Changing the
/// primary platform must never transfer that evidence to another family.
pub const REGISTRY_BASE_CHIP: &str = "apple-m2";

fn set_primary_profile(profile: &mut Value) -> Result<()> {
    let profile = profile
        .as_object_mut()
        .context("profile is not an object")?;
    profile.insert("default".into(), DEFAULT_CHIP.into());
    profile.insert("registry_base_chip".into(), REGISTRY_BASE_CHIP.into());
    profile.insert(
        "primary_platform".into(),
        json!({
            "model": "MacBookPro18,3",
            "board": "J314sAP",
            "soc": "T6000",
            "variant": "M1 Pro",
            "cpu_family": DEFAULT_CHIP,
        }),
    );
    Ok(())
}

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

/// A64 mnemonics whose semantics belong to the system platform: exception
/// generation and return, hints and waits, barriers, System register and
/// System instruction access, exclusive monitors and unprivileged accesses.
const SYSTEM_MNEMONICS: [&str; 65] = [
    "BRK", "SVC", "HLT", "HVC", "SMC", "DCPS1", "DCPS2", "DCPS3", "DRPS", "ERET", "ERETAA",
    "ERETAB", "UDF", "BTI", "ESB", "TSB", "HINT", "NOP", "YIELD", "WFE", "WFI", "WFET", "WFIT",
    "SEV", "SEVL", "DGH", "CSDB", "PSB", "SB", "ISB", "DSB", "DMB", "CLREX", "MSR", "MRS", "SYS",
    "SYSL", "SYSP", "MRRS", "MSRR", "LDTR", "LDTRB", "LDTRH", "LDTRSB", "LDTRSH", "LDTRSW", "STTR",
    "STTRB", "STTRH", "LDXR", "LDXRB", "LDXRH", "LDXP", "LDAXR", "LDAXRB", "LDAXRH", "LDAXP",
    "STXR", "STXRB", "STXRH", "STXP", "STLXR", "STLXRB", "STLXRH", "STLXP",
];

#[derive(Args)]
pub struct SystemMatrix {
    /// The pinned AARCHMRS archive (`AARCHMRS_OPENSOURCE_A_profile_FAT-2026-06.tar.gz`).
    #[arg(long)]
    archive: PathBuf,
    /// The pinned System register XML archive
    /// (`SysReg_xml_A_profile-2026-06.tar.gz`), the source of reset values.
    #[arg(long)]
    sysreg: PathBuf,
    /// The pinned A64 instruction XML archive
    /// (`ISA_A64_xml_A_profile-2026-06.tar.gz`, the checklist's source), the
    /// source of each form's access checks.
    #[arg(long)]
    isa: PathBuf,
}

impl SystemMatrix {
    pub fn run(&self) -> Result<()> {
        let bytes = fs::read(&self.archive)
            .with_context(|| format!("cannot read {}", self.archive.display()))?;
        ensure!(
            bytes.len() == ARCHIVE_BYTES && stela_runtime::sha256(&bytes) == ARCHIVE_SHA256,
            "{} is not the pinned AARCHMRS {RELEASE} archive",
            self.archive.display()
        );
        let directory = tempfile::tempdir()?;
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&self.archive)
            .arg("-C")
            .arg(directory.path())
            .args(MEMBERS)
            .status()?;
        ensure!(status.success(), "cannot extract {MEMBERS:?}");
        let bytes = fs::read(&self.sysreg)
            .with_context(|| format!("cannot read {}", self.sysreg.display()))?;
        ensure!(
            bytes.len() == resets::BYTES && stela_runtime::sha256(&bytes) == resets::SHA256,
            "{} is not the pinned {} archive ({})",
            self.sysreg.display(),
            resets::DIRECTORY,
            resets::URI
        );
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&self.sysreg)
            .arg("-C")
            .arg(directory.path())
            .arg(resets::DIRECTORY)
            .status()?;
        ensure!(status.success(), "cannot extract {}", resets::DIRECTORY);
        let (matrix, registers, profiles) = generate(directory.path())?;
        let profile = &profiles.union;
        let resets_directory = directory.path().join(resets::DIRECTORY);
        let facts = resets::read(&resets_directory, profile)?;
        let chip_facts: Vec<resets::Facts> = profiles
            .chips
            .iter()
            .map(|(_, chip)| resets::read(&resets_directory, chip))
            .collect::<Result<_>>()?;
        let previous = fs::read_to_string(root().join(MATRIX)).unwrap_or_default();
        let text = assess::render(&matrix, &assess::registry()?, &runs::read()?, &previous)?;
        fs::write(root().join(MATRIX), text)?;
        println!("wrote {MATRIX}");
        let applicable: BTreeSet<String> = matrix
            .rows
            .values()
            .filter(|row| matches!(row["kind"].as_str(), Some("register" | "instruction")))
            .filter_map(|row| row["name"].as_str().map(str::to_owned))
            .collect();
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
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&self.isa)
            .arg("-C")
            .arg(directory.path())
            .arg(format!("{}/", checks::DIRECTORY))
            .status()?;
        ensure!(status.success(), "cannot extract {}", checks::DIRECTORY);
        let checklist: Value = serde_json::from_str(&fs::read_to_string(root().join(CHECKLIST))?)?;
        let generated = root().join(checks::GENERATED);
        fs::write(
            &generated,
            checks::render(
                &directory.path().join(checks::DIRECTORY),
                &checklist,
                &profiles.chips,
            )?,
        )?;
        println!("wrote {}", checks::GENERATED);
        Ok(())
    }
}

/// The matrix facts: header and rows keyed by id.
pub struct Matrix {
    pub header: Map<String, Value>,
    pub rows: BTreeMap<String, Value>,
}

fn generate(directory: &Path) -> Result<(Matrix, Value, Profiles)> {
    let read = |name: &str| -> Result<(Value, String)> {
        let bytes = fs::read(directory.join(name))?;
        let digest = stela_runtime::sha256(&bytes);
        Ok((serde_json::from_slice(&bytes)?, digest))
    };
    let (registers, registers_sha256) = read("Registers.json")?;
    let (features, features_sha256) = read("Features.json")?;
    let (profiles, decisions) = profiles(&features)?;
    let mut rows = requirement_rows(&profiles.union, &registers)?;
    let chips: Vec<(&str, BTreeMap<String, Value>)> = profiles
        .chips
        .iter()
        .map(|(name, profile)| {
            let rows = requirement_rows(profile, &registers)?;
            Ok((
                *name,
                rows.into_values().map(|row| (key(&row), row)).collect(),
            ))
        })
        .collect::<Result<_>>()?;
    let union_keys: BTreeSet<String> = rows.values().map(key).collect();
    for (name, chip_rows) in &chips {
        if let Some(missing) = chip_rows.keys().find(|key| !union_keys.contains(*key)) {
            bail!("{name} has {missing}, which the union profile lacks");
        }
    }
    rows.retain(|_, row| {
        let key = key(row);
        let present: Vec<(&str, &Value)> = chips
            .iter()
            .filter_map(|(name, chip_rows)| chip_rows.get(&key).map(|chip_row| (*name, chip_row)))
            .collect();
        if present.is_empty() {
            return false;
        }
        if row.get("applicability").is_some() {
            let everywhere = present
                .iter()
                .all(|(_, chip_row)| chip_row["applicability"] == "profile");
            row["applicability"] = applicability(if everywhere {
                Truth::True
            } else {
                Truth::Dynamic
            })
            .into();
        }
        if present.len() < chips.len() {
            row["chips"] = present
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
                .into();
        }
        true
    });
    let mut header = Map::new();
    header.insert("schema_version".into(), 1.into());
    header.insert("kind".into(), "system_platform_requirement_matrix".into());
    header.insert(
        "version".into(),
        format!("arm-aarchmrs-{RELEASE}-v1").into(),
    );
    header.insert(
        "source".into(),
        json!({
            "publisher": "Arm Limited",
            "release": RELEASE,
            "uri": ARCHIVE_URI,
            "archive_sha256": ARCHIVE_SHA256,
            "archive_bytes": ARCHIVE_BYTES,
            "files_sha256": {"Registers.json": registers_sha256,
                             "Features.json": features_sha256},
        }),
    );
    header.insert(
        "unit".into(),
        "One row per applicable AArch64 System register, register field, System \
         register or System instruction accessor encoding, ESR_EL2 exception class, \
         profile feature, and system-semantic A64 encoding form."
            .into(),
    );
    header.insert(
        "applicability".into(),
        "A row's AARCHMRS condition is evaluated against each chip's profile: a row \
         exists when it holds on some chip, and `chips` lists them unless it holds on \
         every chip. `profile` rows always exist on their chips; `dynamic` rows exist \
         under a run-time control or an ID field value."
            .into(),
    );
    header.insert("profile".into(), decisions);
    Ok((Matrix { header, rows }, registers, profiles))
}

/// The requirement rows of `profile`, keyed by id.
fn requirement_rows(profile: &Profile, registers: &Value) -> Result<BTreeMap<String, Value>> {
    let mut rows = BTreeMap::new();
    let mut insert = |row: Value| -> Result<()> {
        let id = row["id"].as_str().context("row without id")?.to_owned();
        ensure!(rows.insert(id.clone(), row).is_none(), "duplicate row {id}");
        Ok(())
    };
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
        let applicability = profile.truth(&register["condition"]);
        if applicability == Truth::False {
            continue;
        }
        let name = register["name"].as_str().context("register without name")?;
        for row in register_rows(profile, register, name, applicability)? {
            insert(row)?;
        }
    }
    for row in exception_rows(profile, registers)? {
        insert(row)?;
    }
    for feature in &profile.features {
        if !feature.starts_with("FEAT_") {
            continue;
        }
        insert(
            json!({"id": format!("feature:{feature}"), "kind": "feature",
                      "name": feature}),
        )?;
    }
    for row in form_rows(profile)? {
        insert(row)?;
    }
    Ok(rows)
}

/// What identifies a row across profiles: a field by its register, name and
/// bits, since its id carries the bits only when the name repeats.
fn key(row: &Value) -> String {
    if row["kind"] == "field" {
        format!(
            "field:{}.{}@{}",
            row["register"].as_str().unwrap_or("?"),
            row["name"].as_str().unwrap_or("?"),
            row["bits"].as_str().unwrap_or("?")
        )
    } else {
        row["id"].as_str().unwrap_or("?").to_owned()
    }
}

/// The platform's CPU profiles, each closed as [`chip_profile`] describes,
/// and their union, in which a feature only some chips have varies.
pub struct Profiles {
    pub union: Profile,
    pub chips: Vec<(&'static str, Profile)>,
    /// Each chip's Apple clang cap, before the base and the implications.
    pub caps: Vec<Vec<String>>,
}

fn applies(chips: &[&str], chip: &str) -> bool {
    chips.is_empty() || chips.contains(&chip)
}

fn profiles(features: &Value) -> Result<(Profiles, Value)> {
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
    let apple = serde_json::from_str::<Value>(&fs::read_to_string(root().join(APPLE_PROFILES))?)?;
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
    let mut caps = Vec::new();
    let mut decisions = Vec::new();
    let mut used = BTreeSet::new();
    for chip in &CHIPS {
        let cap: Vec<String> = apple["profiles"][chip.name]["architectural_features"]
            .as_array()
            .with_context(|| format!("no {} profile", chip.name))?
            .iter()
            .filter_map(|feature| feature.as_str().map(str::to_owned))
            .collect();
        let (profile, implied, deviations) = chip_profile(&parameters, &constraints, chip, &cap)?;
        used.extend(deviations.iter().cloned());
        let deviations: Vec<Value> = deviations
            .iter()
            .map(|text| {
                let reason = DEVIATIONS
                    .iter()
                    .find(|(known, _, _)| known == text)
                    .map_or("", |(_, _, reason)| *reason);
                json!({"constraint": text, "reason": reason})
            })
            .collect();
        let excluded: Vec<Value> = EXCLUDED
            .iter()
            .filter(|(_, chips, _)| applies(chips, chip.name))
            .map(|(name, _, reason)| json!({"feature": name, "reason": reason}))
            .collect();
        decisions.push(json!({
            "chip": chip.name,
            "cap": format!("{APPLE_PROFILES} {} architectural_features", chip.name),
            "version": chip.version,
            "version_evidence": chip.evidence,
            "excluded": excluded,
            "deviations": deviations,
            "implied": implied.iter().collect::<Vec<_>>(),
            "features": profile.features.iter().collect::<Vec<_>>(),
        }));
        chips.push((chip.name, profile));
        caps.push(cap);
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
    let named = |list: &[(&str, &str)]| -> Value {
        list.iter()
            .map(|(name, reason)| json!({"feature": name, "reason": reason}))
            .collect()
    };
    let mut decisions = json!({
        "default": DEFAULT_CHIP,
        "exception_levels": "EL0, EL1 and EL2 with VHE; no EL3, no Secure state",
        "base": named(&BASE),
        "choices": named(&CHOICES),
        "varying": union.varying.iter().collect::<Vec<_>>(),
        "chips": decisions,
    });
    set_primary_profile(&mut decisions)?;
    Ok((Profiles { union, chips, caps }, decisions))
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
    cap: &[String],
) -> Result<(Profile, BTreeSet<String>, Vec<String>)> {
    let excluded: BTreeSet<&str> = EXCLUDED
        .iter()
        .filter(|(_, chips, _)| applies(chips, chip.name))
        .map(|(name, _, _)| *name)
        .collect();
    for name in cap.iter().map(String::as_str).chain([chip.version]) {
        ensure!(
            parameters.contains(name),
            "{name} of {} is not an AARCHMRS feature",
            chip.name
        );
    }
    let mut features: BTreeSet<String> = cap
        .iter()
        .map(String::as_str)
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

fn applicability(truth: Truth) -> &'static str {
    match truth {
        Truth::True => "profile",
        _ => "dynamic",
    }
}

fn condition_text(node: &Value) -> Value {
    if node["_type"] == "AST.Bool" && node["value"] == true {
        Value::Null
    } else {
        render(node).into()
    }
}

/// Bits `'0101'` as a number, or the AARCHMRS text for an indexed encoding.
fn encoding_field(value: &Value) -> String {
    let text = value["value"].as_str().unwrap_or("?");
    let bits = text.trim_matches('\'');
    if !bits.is_empty() && bits.bytes().all(|b| b == b'0' || b == b'1') {
        u64::from_str_radix(bits, 2)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| text.to_owned())
    } else {
        text.replace('\'', "")
    }
}

fn register_rows(
    profile: &Profile,
    register: &Value,
    name: &str,
    applicability_truth: Truth,
) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    let system_instruction = name.contains(' ');
    let instances = register["indexes"]
        .as_array()
        .map(|ranges| {
            ranges
                .iter()
                .map(|range| range["width"].as_u64().unwrap_or(0))
                .sum::<u64>()
        })
        .filter(|count| *count > 0);
    let mut encodings = Vec::new();
    for accessor in register["accessors"].as_array().into_iter().flatten() {
        let truth = profile.truth(&accessor["condition"]);
        if truth == Truth::False {
            continue;
        }
        let truth = if truth == Truth::Dynamic || applicability_truth == Truth::Dynamic {
            Truth::Dynamic
        } else {
            Truth::True
        };
        let instruction = match accessor["name"].as_str().unwrap_or("?") {
            "A64.MRS" => "MRS",
            "A64.MSRregister" => "MSR",
            "A64.MSRimmediate" => "MSR(imm)",
            "A64.MRRS" => "MRRS",
            "A64.MSRRregister" => "MSRR",
            other => other.trim_start_matches("A64."),
        };
        for encoding in accessor["encoding"].as_array().into_iter().flatten() {
            let asm = encoding["asmvalue"].as_str().unwrap_or(name);
            let fields = &encoding["encodings"];
            let text = ["op0", "op1", "CRn", "CRm", "op2"]
                .iter()
                .filter(|key| !fields[**key].is_null())
                .map(|key| format!("{key}={}", encoding_field(&fields[*key])))
                .collect::<Vec<_>>()
                .join(" ");
            // An encoding that reaches another register (a VHE redirection)
            // is its own requirement.
            let target = if system_instruction || unindexed(asm) == unindexed(name) {
                String::new()
            } else {
                format!(" -> {name}")
            };
            let id = format!("access:{instruction} {asm}{target}");
            if let Some(existing) = rows.iter_mut().find(|row: &&mut Value| row["id"] == id) {
                if truth == Truth::True {
                    existing["applicability"] = "profile".into();
                }
                continue;
            }
            encodings.push(Value::String(format!("{instruction} {asm}")));
            rows.push(json!({
                "id": id,
                "kind": "access",
                "name": format!("{instruction} {asm}"),
                "register": name,
                "encoding": text,
                "condition": condition_text(&accessor["condition"]),
                "applicability": applicability(truth),
            }));
        }
    }
    if !system_instruction {
        // Layouts are ordered alternatives: the first one the profile holds
        // is the register's layout, and the later ones never apply.
        let mut fields = Vec::new();
        for fieldset in register["fieldsets"].as_array().into_iter().flatten() {
            let truth = profile.truth(&fieldset["condition"]);
            if truth != Truth::False {
                collect_fields(profile, &fieldset["values"], 0, truth, &mut fields);
            }
            if truth == Truth::True {
                break;
            }
        }
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for field in &fields {
            *seen.entry(field.name.clone()).or_default() += 1;
        }
        let mut emitted = BTreeSet::new();
        for field in fields {
            let id = if seen[&field.name] > 1 {
                format!("field:{name}.{}@{}", field.name, field.bits)
            } else {
                format!("field:{name}.{}", field.name)
            };
            if !emitted.insert(id.clone()) {
                continue;
            }
            rows.push(json!({
                "id": id,
                "kind": "field",
                "name": field.name,
                "register": name,
                "bits": field.bits,
                "type": field.kind,
                "condition": field.condition,
                "applicability": applicability(field.truth),
            }));
        }
    }
    rows.push(json!({
        "id": format!("{}:{name}", if system_instruction { "instruction" } else { "register" }),
        "kind": if system_instruction { "instruction" } else { "register" },
        "name": name,
        "instances": instances,
        "accessors": encodings,
        "condition": condition_text(&register["condition"]),
        "applicability": applicability(applicability_truth),
    }));
    Ok(rows)
}

/// A name without its array index variable (`DBGBVR<m>_EL1` -> `DBGBVR_EL1`).
fn unindexed(name: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in name.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

struct Field {
    name: String,
    bits: String,
    kind: String,
    condition: Value,
    truth: Truth,
}

fn collect_fields(
    profile: &Profile,
    values: &Value,
    offset: u64,
    truth: Truth,
    out: &mut Vec<Field>,
) {
    for value in values.as_array().into_iter().flatten() {
        let kind = value["_type"].as_str().unwrap_or("?");
        if kind == "Fields.ConditionalField" {
            // Variants are relative to the conditional field's own range.
            let start = value["rangeset"][0]["start"].as_u64().unwrap_or(0) + offset;
            for variant in value["fields"].as_array().into_iter().flatten() {
                let variant_truth = profile.truth(&variant["condition"]);
                if variant_truth == Truth::False {
                    continue;
                }
                let combined = if truth == Truth::True && variant_truth == Truth::True {
                    Truth::True
                } else {
                    Truth::Dynamic
                };
                let before = out.len();
                collect_fields(
                    profile,
                    &Value::Array(vec![variant["field"].clone()]),
                    start,
                    combined,
                    out,
                );
                for field in &mut out[before..] {
                    if field.condition.is_null() {
                        field.condition = condition_text(&variant["condition"]);
                    }
                }
            }
            continue;
        }
        let bits = value["rangeset"]
            .as_array()
            .map(|ranges| {
                ranges
                    .iter()
                    .map(|range| {
                        let start = range["start"].as_u64().unwrap_or(0) + offset;
                        let width = range["width"].as_u64().unwrap_or(1);
                        if width == 1 {
                            start.to_string()
                        } else {
                            format!("{}:{start}", start + width - 1)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let short = kind.trim_start_matches("Fields.");
        let name = match value["name"].as_str() {
            Some(name) => name.to_owned(),
            None => match value["value"].as_str() {
                Some(text) => text.to_owned(),
                None => short.to_owned(),
            },
        };
        out.push(Field {
            name,
            bits,
            kind: short.to_owned(),
            condition: Value::Null,
            truth,
        });
    }
}

/// One row per ESR_EL2.EC value the profile can report.
fn exception_rows(profile: &Profile, registers: &Value) -> Result<Vec<Value>> {
    let esr = registers
        .as_array()
        .into_iter()
        .flatten()
        .find(|register| register["state"] == "AArch64" && register["name"] == "ESR_EL2")
        .context("no ESR_EL2")?;
    let mut fields = Vec::new();
    find_field(&esr["fieldsets"], "EC", &mut fields);
    let field = fields.first().context("ESR_EL2 has no EC field")?;
    let mut rows = Vec::new();
    collect_values(profile, &field["values"]["values"], Truth::True, &mut rows);
    Ok(rows)
}

fn find_field<'a>(node: &'a Value, name: &str, out: &mut Vec<&'a Value>) {
    match node {
        Value::Object(map) => {
            if map.get("_type").and_then(Value::as_str) == Some("Fields.Field")
                && map.get("name").and_then(Value::as_str) == Some(name)
            {
                out.push(node);
            }
            for value in map.values() {
                find_field(value, name, out);
            }
        }
        Value::Array(list) => list.iter().for_each(|value| find_field(value, name, out)),
        _ => {}
    }
}

fn collect_values(profile: &Profile, values: &Value, truth: Truth, out: &mut Vec<Value>) {
    for value in values.as_array().into_iter().flatten() {
        if value["_type"] == "Values.ConditionalValue" {
            let inner = profile.truth(&value["condition"]);
            if inner != Truth::False {
                let combined = if truth == Truth::True && inner == Truth::True {
                    Truth::True
                } else {
                    Truth::Dynamic
                };
                collect_values(profile, &value["values"]["values"], combined, out);
            }
            continue;
        }
        let bits = value["value"].as_str().unwrap_or("").trim_matches('\'');
        let Ok(class) = u8::from_str_radix(bits, 2) else {
            continue;
        };
        let meaning = value["links"]["ISS"]
            .as_str()
            .or_else(|| value["meaning"].as_str())
            .unwrap_or("")
            .split('_')
            .filter(|word| !word.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        out.push(json!({
            "id": format!("exception:EC {class:#04x}"),
            "kind": "exception",
            "name": meaning,
            "applicability": applicability(truth),
        }));
    }
}

/// The system-semantic forms of the Arm A64 checklist that the profile has.
fn form_rows(profile: &Profile) -> Result<Vec<Value>> {
    let checklist: Value = serde_json::from_str(&fs::read_to_string(root().join(CHECKLIST))?)?;
    let mut rows = Vec::new();
    for form in checklist["forms"]
        .as_array()
        .context("checklist has no forms")?
    {
        let mnemonic = form["mnemonic"].as_str().unwrap_or("");
        if !SYSTEM_MNEMONICS.contains(&mnemonic) {
            continue;
        }
        let present = form["features"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|feature| feature["feature"].as_str())
            .all(|feature| profile.features.contains(feature));
        if !present {
            continue;
        }
        let id = form["id"].as_str().context("form without id")?;
        rows.push(json!({
            "id": format!("form:{id}"),
            "kind": "form",
            "name": mnemonic,
            "encoding": format!("{}/{}", form["encoding_value"].as_str().unwrap_or("?"),
                                form["encoding_mask"].as_str().unwrap_or("?")),
        }));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn layouts_are_ordered_alternatives() {
        let profile = |features: &[&str]| Profile {
            parameters: ["FEAT_AA32EL1"].map(String::from).into(),
            features: features.iter().map(|f| String::from(*f)).collect(),
            highest_el: 2,
            varying: Default::default(),
        };
        let fields = |profile: &Profile| -> Vec<String> {
            register_rows(profile, &banked_spsr(), "SPSR_abt", Truth::True)
                .unwrap()
                .iter()
                .filter(|row| row["kind"] == "field")
                .map(|row| row["id"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(fields(&profile(&[])), ["field:SPSR_abt.RES0"]);
        assert_eq!(fields(&profile(&["FEAT_AA32EL1"])), ["field:SPSR_abt.N"]);
    }

    fn identifier(name: &str) -> Value {
        json!({"_type": "AST.Identifier", "value": name})
    }

    fn implies(left: &str, right: &str) -> Value {
        json!({"_type": "AST.BinaryOp", "op": "==>", "left": identifier(left),
               "right": identifier(right)})
    }

    #[test]
    fn a_chip_keeps_its_declared_version_and_reports_later_version_features() {
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
        let chip = |name: &'static str| Chip {
            name,
            version: "v8Ap7",
            evidence: "",
        };
        // The version chain and its mandatory features are implied.
        let (profile, implied, deviations) =
            chip_profile(&parameters, &constraints, &chip("apple-m3"), &[]).unwrap();
        assert!(implied.contains("v8Ap6") && implied.contains("FEAT_WFxT"));
        assert!(implied.contains("FEAT_ECV") && deviations.is_empty());
        assert!(!profile.features.contains("v9Ap2"));
        // A feature that needs a later version does not raise the version:
        // the violated constraint is an error unless it is a recorded
        // deviation for the chip.
        let sme = ["FEAT_SME".to_owned()];
        let error = chip_profile(&parameters, &constraints, &chip("apple-m3"), &sme)
            .unwrap_err()
            .to_string();
        assert!(error.contains("(FEAT_SME ==> v9Ap2)"), "{error}");
        let (profile, _, deviations) =
            chip_profile(&parameters, &constraints, &chip("apple-m4"), &sme).unwrap();
        assert_eq!(deviations, ["(FEAT_SME ==> v9Ap2)"]);
        assert!(!profile.features.contains("v9Ap2"));
    }

    #[test]
    fn version_parameters_are_recognized() {
        assert!(is_version("v8Ap7") && is_version("v9Ap4") && is_version("v8Ap10"));
        assert!(!is_version("v8Ap") && !is_version("FEAT_V8") && !is_version("v7Ap1"));
    }

    #[test]
    fn rows_match_across_profiles_by_register_name_and_bits() {
        let field = json!({"id": "field:R.F@3:0", "kind": "field", "register": "R",
                           "name": "F", "bits": "3:0"});
        let same = json!({"id": "field:R.F", "kind": "field", "register": "R",
                          "name": "F", "bits": "3:0"});
        assert_eq!(key(&field), key(&same));
        assert_eq!(
            key(&json!({"id": "register:R", "kind": "register"})),
            "register:R"
        );
    }
}
